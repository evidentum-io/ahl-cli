//! Deterministic test support: a mirror and a witness built over the published `ahl-core`
//! conformance corpus.
//!
//! This module exists because design note §5 states a mandatory invariant — cold, warm and
//! adversarially poisoned caches produce identical verdicts and exit codes — and then states
//! why it must be evaluated against a **fixed recorded transcript** rather than a live
//! endpoint. A fixture that answers deterministically is therefore part of the crate, not of
//! the test harness, and `src/bin/gen_fixtures.rs` uses it to record the transcripts the
//! integration tests replay.
//!
//! Everything here is derived from committed constants: the corpus statements, the published
//! test key seeds, and fixed timestamps. There is no clock read and no randomness, so two runs
//! produce byte-identical material.
//!
//! **Test material only.** Every key this module uses is a published constant of the AHL
//! conformance corpus. Nothing here is suitable for production key handling.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ahl_core::receipt::TrustPolicy;
use ahl_core::TestKey;
use atl_core::core::merkle::{compute_root, Hash};
use serde_json::{json, Value};

use crate::anchored::{establish, Anchored, Mirror};
use crate::cache::CheckpointIdentity;
use crate::checkpoint::{Checkpoint, SigningForm, TEST_LOG_PROFILE};
use crate::enumerate::LeafForm;
use crate::error::CliResult;
use crate::net::{FetchFailure, Fetcher, Request, Response};
use crate::policy::{ConfiguredProfile, Endpoints, LoadedPolicy, LocalLimits, NetworkLimits};

/// The mirror base URL the fixture answers on.
pub const MIRROR: &str = "https://mirror.example";
/// The witness base URL the fixture answers on.
pub const WITNESS: &str = "https://witness.example";
/// A fixed instant, so nothing in the fixture reads a clock.
pub const FIXED_TIME: &str = "2026-08-16T12:00:00Z";

/// The tree sizes the fixture publishes checkpoints at.
///
/// The smallest is here so that a checkpoint the tests ground results on has an authenticated
/// predecessor: adaptor §6.6 requires that relationship and the client never assumes it away,
/// because "the mirror served nothing earlier" is a server label rather than evidence about
/// what the deployment published. A run grounded on the smallest member is therefore
/// `unverifiable` — the deliberate refusal of the §5.2.2 item 3 carve-out, pinned by
/// `the_genuinely_first_published_member_is_refused_and_the_refusal_is_deliberate` so that it
/// stays a decision rather than an artefact of which sizes this list happens to carry.
pub const CHECKPOINT_SIZES: [u64; 8] = [4, 8, 13, 20, 28, 32, 38, 41];

/// One recorded exchange, in the shape [`crate::transcript`] replays.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    url: String,
    request_body: Option<String>,
    status: u16,
    body: Vec<u8>,
}

/// A deterministic mirror and witness over the conformance corpus.
#[derive(Debug)]
pub struct MirrorFixture {
    /// The trust policy matching the corpus.
    pub policy: LoadedPolicy,
    /// Canonical entry bytes, dense from entry index 0.
    entries: Vec<Vec<u8>>,
    /// The corpus log-signing key.
    /// The log's checkpoint-signing keys, in the order the corpus adopts them.
    ///
    /// A fixed pair rather than a vector: the corpus adopts exactly two, and every read of the
    /// first one is then in range by type rather than by convention.
    log_keys: [TestKey; 2],
    /// Sign every checkpoint with the outgoing key, ignoring the rotation.
    outgoing_log_key: bool,
    /// A key the corpus manifests never declare, for the "foreign key" fixture.
    foreign_key: TestKey,
    /// The producer key the corpus publishes, which signs every statement the builders append.
    producer: TestKey,
    /// The attacker and mis-filed keys the forged key-transition fixture stages, and the
    /// attacker key the forged-manifest fixture signs with. Resolved once, at construction, so
    /// a builder never has to decide what to do about a key it cannot build.
    forged_transition: (TestKey, TestKey),
    /// The attacker key the forged-manifest fixture signs with.
    forged_manifest_key: TestKey,
    /// Witness keys by name.
    witness_keys: BTreeMap<&'static str, TestKey>,
    /// Publish a second, diverging checkpoint at this size.
    equivocate_at: Option<u64>,
    /// Serialize the diverging member **before** the honest one, while giving it a later
    /// `checkpoint_time`, so array order and series order disagree.
    equivocate_first: bool,
    /// Republish the checkpoint at this size unchanged, with a later `checkpoint_time`.
    republish_at: Option<u64>,
    /// An entry was appended beyond the corpus, so the resulting total is published too.
    appended: bool,
    /// Serve only the members of the published series at or above this size, as a mirror that
    /// withholds the earlier ones does.
    series_from: Option<u64>,
    /// Publish a second, diverging member at this size, signed by a key no manifest version
    /// this corpus authorizes declares.
    foreign_divergence_at: Option<u64>,
    /// The `key_id` the checkpoint at the appended size names, where that must differ from the
    /// key that actually signs it.
    appended_key_id: Option<String>,
    /// Sign the checkpoint at this size with a key the manifest does not declare.
    foreign_key_at: Option<u64>,
    /// Serve different bytes for this entry index.
    tampered: Option<usize>,
    /// The corpus this fixture was built from, so a later read of it needs no second lookup and
    /// cannot land on a different corpus than the one the fixture's material came from.
    corpus: PathBuf,

    recorded: Mutex<Vec<Recorded>>,
}

/// A published test key seed, read from the corpus.
///
/// `None` where the seed file is absent or is not 64 hex digits. The absence is reported to
/// the caller rather than papered over with a substitute key: a fixture signing with a key the
/// corpus never published would make every signature test pass against the wrong material.
fn seed(path: &Path, name: &'static str) -> Option<TestKey> {
    let hex = std::fs::read_to_string(path.join("keys").join(format!("{name}.seed"))).ok()?;
    TestKey::from_seed_hex(name, hex.trim()).ok()
}

/// A key built from a constant seed byte, for the roles the corpus deliberately does not
/// publish: an attacker's key, and a key no manifest version declares.
fn synthetic(name: &'static str, byte: &str) -> Option<TestKey> {
    TestKey::from_seed_hex(name, &byte.repeat(32)).ok()
}

impl MirrorFixture {
    /// Where [`Self::conformance`] looks for the `ahl-core` conformance corpus.
    ///
    /// **No relative path is ever tried.** An installed package has no sibling working tree,
    /// so assuming one would make this succeed on the author's machine and nowhere else.
    ///
    /// Outside the crate's own test build — that is, in the shipped library and in
    /// `src/bin/gen_fixtures.rs` — the corpus is whatever `AHL_CORE_TEST_DATA` names, and
    /// nothing else. Under `cfg(test)` it is located from the `ahl-core` package `cargo`
    /// actually resolved, which is correct for a registry dependency and for an outside
    /// contributor holding no second checkout; that lookup runs `cargo metadata`, so it is
    /// compiled into test code only and nothing shipped spawns a subprocess.
    ///
    /// # Errors
    ///
    /// Where `AHL_CORE_TEST_DATA` is unset or does not name an existing directory, and — under
    /// `cfg(test)` — where the resolved `ahl-core` carries no corpus. The message says what to
    /// set.
    pub fn corpus_root() -> Result<PathBuf, String> {
        #[cfg(test)]
        {
            crate::test_corpus::locate()
        }
        #[cfg(not(test))]
        {
            let Some(named) = std::env::var_os("AHL_CORE_TEST_DATA") else {
                return Err("`AHL_CORE_TEST_DATA` is not set; it must name the `test_data/` \
                            directory of the `ahl-core` conformance corpus"
                    .to_owned());
            };
            let root = PathBuf::from(named);
            if root.is_dir() {
                Ok(root)
            } else {
                Err(format!(
                    "`AHL_CORE_TEST_DATA` is set to `{}`, which is not a directory; it must name \
                     the `test_data/` directory of the `ahl-core` conformance corpus",
                    root.display()
                ))
            }
        }
    }

    /// Build the fixture from the conformance corpus [`Self::corpus_root`] names.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::corpus_root`] reports, or a statement that the corpus found publishes
    /// none of the key seeds this fixture signs with; see [`Self::from_corpus`].
    pub fn conformance() -> Result<Self, String> {
        let root = Self::corpus_root()?;
        Self::from_corpus(&root).ok_or_else(|| {
            format!("`{}` publishes none of the key seeds the fixture signs with", root.display())
        })
    }

    /// Build the fixture from a corpus at `root`.
    ///
    /// `None` where a key seed the fixture needs is absent or unusable. Every signature this
    /// fixture produces is made with a published corpus key, so a missing seed is reported
    /// rather than substituted: a fixture that quietly signed with something else would make
    /// the tests grounded on it assert against material no corpus published.
    #[must_use]
    pub fn from_corpus(root: &Path) -> Option<Self> {
        let mut statements: Vec<(u64, Vec<u8>)> = Vec::new();
        if let Ok(dir) = std::fs::read_dir(root.join("vectors/statements")) {
            let mut files: Vec<PathBuf> = dir
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            files.sort();
            for file in files {
                let Ok(bytes) = std::fs::read(&file) else { continue };
                let Ok(value) = serde_json::from_slice::<Value>(&bytes) else { continue };
                let (Some(index), Some(envelope)) =
                    (value.get("entry_index").and_then(Value::as_u64), value.get("envelope"))
                else {
                    continue;
                };
                statements.push((index, ahl_core::jcs(envelope)));
            }
        }
        statements.sort_by_key(|(index, _)| *index);
        let entries = statements.into_iter().map(|(_, bytes)| bytes).collect();

        Some(Self {
            policy: corpus_policy(root),
            corpus: root.to_path_buf(),
            entries,
            log_keys: [seed(root, "log-1")?, seed(root, "log-2")?],
            outgoing_log_key: false,
            foreign_key: synthetic("foreign", "7f")?,
            producer: seed(root, "producer-1")?,
            forged_transition: (synthetic("attacker", "7d")?, synthetic("fake", "7c")?),
            forged_manifest_key: synthetic("attacker", "7e")?,
            witness_keys: BTreeMap::from([
                ("witness-1", seed(root, "witness-1")?),
                ("witness-2", seed(root, "witness-2")?),
            ]),
            equivocate_at: None,
            equivocate_first: false,
            republish_at: None,
            appended: false,
            series_from: None,
            foreign_divergence_at: None,
            appended_key_id: None,
            foreign_key_at: None,
            tampered: None,
            recorded: Mutex::new(Vec::new()),
        })
    }

    /// Publish a second, diverging checkpoint at `tree_size`.
    #[must_use]
    pub const fn with_equivocation_at(mut self, tree_size: u64) -> Self {
        self.equivocate_at = Some(tree_size);
        self
    }

    /// Publish the diverging member at `tree_size` **first in the served array**, while
    /// giving it a later `checkpoint_time` than the honest one.
    ///
    /// Array order and series order then disagree, which is the whole point: core §7.3 orders
    /// a series by `(tree_size, checkpoint_time)`, so a client that takes whichever member the
    /// mirror serialized first is letting the server choose. Here the server's choice is the
    /// branch whose root nothing recomputes.
    #[must_use]
    pub const fn with_equivocation_first_at(mut self, tree_size: u64) -> Self {
        self.equivocate_at = Some(tree_size);
        self.equivocate_first = true;
        self
    }

    /// Republish the checkpoint at `tree_size` unchanged, with a later `checkpoint_time`.
    ///
    /// A quiet log MUST keep publishing at its declared cadence with `tree_size` unchanged
    /// (core §7.3, adaptor §16 obligation 4), so this is what an honest idle deployment looks
    /// like — and the republished member is a genuine later member of the series.
    #[must_use]
    pub const fn with_republish_at(mut self, tree_size: u64) -> Self {
        self.republish_at = Some(tree_size);
        self
    }

    /// Anchor a correctly signed statement whose `type` core §2.3 does not define.
    ///
    /// Signed by the corpus producer key, so it passes every test that makes an anchored
    /// object an AHL statement; what a verifier cannot do is read what it means.
    #[must_use]
    pub fn with_unknown_statement_type(mut self) -> Self {
        let producer = self.producer.clone();
        let manifest = self
            .entries
            .iter()
            .rev()
            .find_map(|bytes| {
                let value: Value = serde_json::from_slice(bytes).ok()?;
                (value.get("payload")?.get("type")?.as_str()? == "manifest")
                    .then(|| ahl_core::sha256_hex(bytes))
            })
            .unwrap_or_default();
        let statement = ahl_core::envelope(
            json!({ "type": "attestation", "manifest": manifest, "dataset": "customers" }),
            &producer,
        );
        self.entries.push(ahl_core::jcs(&statement));
        self.appended = true;
        self
    }

    /// Serve only the members of the series at or above `tree_size`.
    ///
    /// This is a mirror withholding history the deployment did publish. Nothing about the
    /// response says so — which is the point: a short series answer is a server label, and
    /// adaptor §10.3 defines no authenticated completeness proof over published history, so a
    /// withheld predecessor is indistinguishable from an absent one.
    #[must_use]
    pub const fn with_series_from(mut self, tree_size: u64) -> Self {
        self.series_from = Some(tree_size);
        self
    }

    /// Publish a second, diverging member at `tree_size`, signed by a key **no manifest
    /// version this corpus authorizes declares**.
    ///
    /// From the client's side this is exactly the shape of a second branch whose own manifest
    /// chain authorizes its own log key: the signature does not resolve under this corpus's
    /// chain, and this run cannot ask the mirror for the entries behind the other root, because
    /// the request shape of adaptor §10.3 names a range and a tree size and never a root.
    #[must_use]
    pub const fn with_foreign_divergence_at(mut self, tree_size: u64) -> Self {
        self.foreign_divergence_at = Some(tree_size);
        self
    }

    /// Anchor a `key` transition whose binding is forged, then a successor manifest that only
    /// that forged binding can authorize.
    ///
    /// The shape of the attack, in three entries:
    ///
    /// 1. a producer key in force signs a `key` add carrying `{key_id: SHA-256(K_fake),
    ///    pubkey: attacker_pubkey}` — a well-formed statement from an authorized signer whose
    ///    only defect is that the id is not derived from the key beside it;
    /// 2. the attacker signs a successor manifest naming `SHA-256(K_fake)` as its signing key
    ///    id. A verifier that took the binding on trust resolves that name to the attacker's
    ///    public key, and the signature verifies — so §7.4.1 test 2 passes and the manifest
    ///    joins the chain;
    /// 3. that manifest names a log key, and the checkpoint over it is signed by that key.
    ///
    /// Every test of adaptor §7.4.1 passes. What stops it is core §2.3.6 and adaptor §7.2:
    /// the id is recomputed from the key and the mismatch refused, at step 1.
    #[must_use]
    pub fn with_forged_key_transition(mut self) -> Self {
        let producer = self.producer.clone();
        let (attacker, fake) = self.forged_transition.clone();

        // 1. The forged binding, signed by a key genuinely in force.
        let transition = ahl_core::envelope(
            json!({
                "type": "key",
                "action": "add",
                "key": { "key_id": fake.key_id(), "pubkey": attacker.pubkey() },
            }),
            &producer,
        );
        self.entries.push(ahl_core::jcs(&transition));

        // 2. A successor manifest signed by the attacker under the borrowed name. Assembled by
        //    hand because the envelope helper always names the key that signed.
        let predecessor = self
            .entries
            .iter()
            .rev()
            .find_map(|bytes| {
                let value: Value = serde_json::from_slice(bytes).ok()?;
                (value.get("payload")?.get("type")?.as_str()? == "manifest")
                    .then(|| ahl_core::sha256_hex(bytes))
            })
            .unwrap_or_default();
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": predecessor,
            "keys": [ attacker.producer_key_object() ],
            "log": {
                "log_id": self.log_id(),
                "operator": "log-operator-1",
                "adaptor": {
                    "id": TEST_LOG_PROFILE,
                    "hash": format!("sha256:{}", hex::encode([0u8; 32])),
                },
                "checkpoint_cadence": "PT1H",
                "cadence_epoch": self.genesis_cadence_epoch(),
                "witness_grace_period": "PT15M",
                "keys": [ self.foreign_key.key_object(0) ],
            },
        });
        let signature = attacker.sign(&ahl_core::jcs(&payload));
        let manifest = json!({
            "payload": payload,
            "signatures": [ { "key_id": fake.key_id(), "sig": signature } ],
        });
        self.entries.push(ahl_core::jcs(&manifest));

        self.appended = true;
        // 3. The checkpoint over the forged chain, signed by the log key it names.
        self.foreign_key_at = Some(self.appended_tree_size());
        self
    }

    /// Anchor an authorized manifest version whose `log` object is built by `alter`, and
    /// publish a checkpoint over it.
    ///
    /// The version links correctly to the one active before it and is signed by a producer key
    /// in force at its entry index, so every test of adaptor §7.4.1 passes: what the fixture
    /// varies is the `log` object itself.
    fn with_appended_manifest(mut self, alter: impl FnOnce(&mut Value)) -> Self {
        let producer = self.producer.clone();
        let predecessor = self.governing_manifest_entry_id();
        let mut log = json!({
            "log_id": self.log_id(),
            "operator": "log-operator-1",
            "adaptor": {
                "id": TEST_LOG_PROFILE,
                "hash": format!("sha256:{}", hex::encode([0u8; 32])),
            },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": self.genesis_cadence_epoch(),
            "witness_grace_period": "PT15M",
            "keys": [ self.log_keys[0].key_object(0) ],
        });
        alter(&mut log);
        let manifest = ahl_core::envelope(
            json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": predecessor,
                "keys": [ producer.producer_key_object() ],
                "log": log,
            }),
            &producer,
        );
        self.entries.push(ahl_core::jcs(&manifest));
        self.appended = true;
        self
    }

    /// Anchor an authorized manifest version declaring a log key that is **not yet active** at
    /// the checkpoint it governs, and publish a checkpoint signed by that key.
    ///
    /// Declaring a key is not the same as it being in force. `valid_from_index` is an entry
    /// index; a checkpoint of size `n` commits `[0, n)`, so a key activating at an index the
    /// checkpoint does not commit has not been adopted yet (design note §2 rule 4).
    #[must_use]
    pub fn with_future_activated_log_key(self) -> Self {
        let key = self.log_keys[0].key_object(u64::MAX);
        self.with_appended_manifest(move |log| log["keys"] = json!([key]))
    }

    /// Anchor an authorized manifest version whose log key object files one party's public key
    /// under another party's `key_id`, and publish a checkpoint naming that id.
    ///
    /// Adaptor §7.2: "A verifier MUST recompute a key id from the public key it is given and
    /// MUST reject a mismatch"; §6.5 step 4 repeats it at the point of use.
    #[must_use]
    pub fn with_mismatched_log_key_id(mut self) -> Self {
        let borrowed_id = self.foreign_key.key_id();
        let object = json!({
            "key_id": borrowed_id,
            "pubkey": self.log_keys[0].pubkey(),
            "valid_from_index": 0,
        });
        self.appended_key_id = Some(borrowed_id);
        self.with_appended_manifest(move |log| log["keys"] = json!([object]))
    }

    /// Anchor an authorized manifest version that moves `cadence_epoch`, and publish a
    /// checkpoint signed by the log key only that version declares.
    ///
    /// Core §7.3 and adaptor §7.3.2: the epoch is declared once, by the genesis manifest, and
    /// repeated unchanged by every later version. A movable epoch would let an operator
    /// re-anchor the series after the fact and erase an interval it failed to cover.
    #[must_use]
    pub fn with_moved_cadence_epoch(mut self) -> Self {
        let key = self.foreign_key.key_object(0);
        self.foreign_key_at = Some(self.appended_tree_size().saturating_add(1));
        self.with_appended_manifest(move |log| {
            log["cadence_epoch"] = json!("2026-08-16T12:30:00Z");
            log["keys"] = json!([key]);
        })
    }

    /// The `cadence_epoch` the corpus genesis manifest anchored, read rather than restated.
    fn genesis_cadence_epoch(&self) -> String {
        self.entries
            .first()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .and_then(|value| {
                value.get("payload")?.get("log")?.get("cadence_epoch")?.as_str().map(str::to_owned)
            })
            .unwrap_or_default()
    }

    /// The tree size whose checkpoint commits the appended statement, if one was appended.
    #[must_use]
    pub fn appended_tree_size(&self) -> u64 {
        u64::try_from(self.entries.len()).unwrap_or(u64::MAX)
    }

    /// Sign the checkpoint at `tree_size` with a key no manifest version declares.
    #[must_use]
    pub const fn with_foreign_log_key(mut self, tree_size: u64) -> Self {
        self.foreign_key_at = Some(tree_size);
        self
    }

    /// Sign every checkpoint with the log's OUTGOING key, as a log that rotated its
    /// checkpoint-signing key and then kept signing with the old one would.
    ///
    /// Distinct from [`Self::with_foreign_log_key`], which signs with a key no manifest version
    /// ever declared. This key IS declared by the corpus — by the version active before the
    /// rotation — so it exercises I-D §7.5.1 4f rather than "unknown key": keys resolve from the
    /// manifest version active for THE CHECKPOINT BEING VERIFIED, and a retired one does not
    /// authenticate a checkpoint the version after it governs. A verifier resolving the key by
    /// any other index would accept this.
    #[must_use]
    pub const fn with_outgoing_log_key(mut self) -> Self {
        self.outgoing_log_key = true;
        self
    }

    /// Serve different bytes for the entry at `index`, so root recomputation fails.
    #[must_use]
    pub const fn with_tampered_entry(mut self, index: usize) -> Self {
        self.tampered = Some(index);
        self
    }

    /// Append a **forged later manifest** naming attacker log keys, and sign the newest
    /// checkpoint with one of them.
    ///
    /// This is the attack adaptor §7.4.1 exists to forbid, staged exactly as it would arrive:
    /// the tree recomputes, the genuine pinned genesis manifest is in it, the forged manifest
    /// is anchored at a real index with a real inclusion proof, and it even links correctly to
    /// the manifest version active before it — so the *only* thing standing between an
    /// attacker and a checkpoint that authenticates is test 2, the producer signature.
    #[must_use]
    pub fn with_forged_manifest(mut self) -> Self {
        let attacker = self.forged_manifest_key.clone();
        let predecessor = self
            .entries
            .iter()
            .rev()
            .find_map(|bytes| {
                let value: Value = serde_json::from_slice(bytes).ok()?;
                (value.get("payload")?.get("type")?.as_str()? == "manifest")
                    .then(|| ahl_core::sha256_hex(bytes))
            })
            .unwrap_or_default();
        let forged = ahl_core::envelope(
            json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": predecessor,
                "keys": [ attacker.producer_key_object() ],
                "log": {
                    "log_id": self.log_id(),
                    "operator": "log-operator-1",
                    "adaptor": { "id": TEST_LOG_PROFILE, "hash": format!("sha256:{}", "00".repeat(32)) },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-08-16T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    // The whole point: attacker-controlled checkpoint-signing keys.
                    "keys": [ self.foreign_key.key_object(0) ],
                },
            }),
            &attacker,
        );
        self.entries.push(ahl_core::jcs(&forged));
        self.appended = true;
        // The checkpoint over the forged manifest is signed by the key that manifest declares:
        // that is what makes the attack complete, and what an unauthenticated chain would
        // resolve and accept.
        self.foreign_key_at = Some(self.forged_tree_size());
        self
    }

    /// The largest published tree size.
    #[must_use]
    pub fn newest_tree_size(&self) -> u64 {
        self.published_sizes().into_iter().max().unwrap_or(0)
    }

    fn published_sizes(&self) -> Vec<u64> {
        let total = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let mut sizes: Vec<u64> =
            CHECKPOINT_SIZES.into_iter().filter(|size| *size <= total).collect();
        // The whole corpus is always a published size, appended entries or not. Pinning the set
        // to a constant alone would silently stop covering the corpus's own tail every time the
        // corpus grew, and a test grounded on the newest checkpoint would quietly ground itself
        // somewhere older instead.
        if !sizes.contains(&total) {
            sizes.push(total);
        }
        if let Some(from) = self.series_from {
            sizes.retain(|size| *size >= from);
        }
        sizes
    }

    /// The corpus entries as parsed envelopes, in entry-index order.
    ///
    /// The index into the returned vector IS the entry index, which is what every governance
    /// and closure walk keys on.
    #[must_use]
    pub fn corpus_entries(&self) -> Vec<Value> {
        self.entries.iter().filter_map(|bytes| serde_json::from_slice(bytes).ok()).collect()
    }

    /// The trust policy this fixture's corpus is anchored to.
    #[must_use]
    pub const fn trust_policy(&self) -> &ahl_core::receipt::TrustPolicy {
        &self.policy.trust
    }

    /// The entry id of the manifest version that GOVERNS at the end of the corpus.
    ///
    /// §7.4.1 test 3 links a manifest to the version active immediately before it, not to
    /// whatever manifest was anchored last: the corpus deliberately carries manifest entries
    /// that do not verify, and one of those is anchored after the last governing version. A
    /// fixture linking to the last manifest by position would anchor a version that no walk
    /// accepts, and every checkpoint it was meant to govern would quietly keep its old key set
    /// — a fixture that appears to test a rotation and tests nothing.
    fn governing_manifest_entry_id(&self) -> String {
        let entries: Vec<(u64, Value)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, bytes)| {
                Some((u64::try_from(index).ok()?, serde_json::from_slice(bytes).ok()?))
            })
            .collect();
        let governing = crate::governance::Governance::resolve(&entries, &self.policy.trust)
            .ok()
            .and_then(|(governance, _)| governance.manifest_indexes().last().copied());
        governing
            .and_then(|index| self.entries.get(usize::try_from(index).ok()?))
            .map(|bytes| ahl_core::sha256_hex(bytes))
            .unwrap_or_default()
    }

    /// The tree size whose checkpoint the forged manifest would govern, if one was appended.
    #[must_use]
    pub fn forged_tree_size(&self) -> u64 {
        u64::try_from(self.entries.len()).unwrap_or(u64::MAX)
    }

    fn entry_bytes(&self, index: usize) -> Vec<u8> {
        if self.tampered == Some(index) {
            ahl_core::jcs(&json!({ "payload": { "type": "ingestion" }, "signatures": [] }))
        } else {
            self.entries.get(index).cloned().unwrap_or_default()
        }
    }

    fn leaf_hashes(&self, upto: u64) -> Vec<Hash> {
        (0..usize::try_from(upto).unwrap_or(usize::MAX))
            .map(|index| LeafForm::Direct.leaf_hash(&self.entry_bytes(index)))
            .collect()
    }

    /// The root the log **committed**, always over the honest entries.
    ///
    /// `with_tampered_entry` changes what the mirror *serves*, never what the log signed —
    /// which is the whole point: a checkpoint that commits one tree while the mirror serves
    /// another is exactly the substitution root recomputation exists to catch.
    fn root_at(&self, tree_size: u64) -> String {
        let hashes: Vec<Hash> = (0..usize::try_from(tree_size).unwrap_or(usize::MAX))
            .map(|index| {
                LeafForm::Direct.leaf_hash(self.entries.get(index).map_or(&[][..], Vec::as_slice))
            })
            .collect();
        ahl_core::hash_hex(&compute_root(&hashes))
    }

    /// The log key the manifest version governing a checkpoint of `tree_size` declares.
    ///
    /// A log rotates its checkpoint-signing key by anchoring a new manifest version, and the
    /// corpus does exactly that. Signing every published checkpoint with the genesis key would
    /// make the fixture a log that announces a rotation and never performs one — and every
    /// client test grounded past the rotation would then be asserting against material no
    /// conformant log would serve.
    fn log_key_for(&self, tree_size: u64) -> &TestKey {
        if self.outgoing_log_key {
            return &self.log_keys[0];
        }
        let entries: Vec<(u64, Value)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, bytes)| {
                Some((u64::try_from(index).ok()?, serde_json::from_slice(bytes).ok()?))
            })
            .collect();
        let active = crate::governance::Governance::resolve(&entries, &self.policy.trust)
            .ok()
            .and_then(|(governance, _)| governance.log_keys_for(tree_size).ok())
            .unwrap_or_default();
        self.log_keys
            .iter()
            .find(|candidate| active.contains_key(&candidate.key_id()))
            .unwrap_or(&self.log_keys[0])
    }

    fn log_id(&self) -> String {
        // Read from the genesis manifest rather than restated, so the fixture cannot drift.
        self.entries
            .first()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .and_then(|value| {
                let log = value.get("payload")?.get("log")?;
                log.get("log_id").or_else(|| log.get("id"))?.as_str().map(str::to_owned)
            })
            .unwrap_or_default()
    }

    fn checkpoint(&self, tree_size: u64, root: &str, time: &str, foreign: bool) -> Checkpoint {
        let key = if foreign { &self.foreign_key } else { self.log_key_for(tree_size) };
        let mut checkpoint = Checkpoint {
            log_id: self.log_id(),
            tree_size,
            root_hash: root.to_owned(),
            checkpoint_time: time.to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        if let Some(borrowed) =
            self.appended_key_id.as_ref().filter(|_| tree_size == self.appended_tree_size())
        {
            // Named before signing: the id is inside the JCS bytes the log signs, so a
            // checkpoint that names one key and is signed by another has to be built this way.
            checkpoint.key_id.clone_from(borrowed);
        }
        if let Ok(bytes) = checkpoint.signing_bytes(SigningForm::CanonicalJson) {
            checkpoint.signature = key.sign(&bytes);
        }
        checkpoint
    }

    /// The checkpoint series this fixture publishes.
    #[must_use]
    pub fn series(&self) -> Vec<Checkpoint> {
        let mut series: Vec<Checkpoint> = self
            .published_sizes()
            .into_iter()
            .map(|size| {
                let root = self.root_at(size);
                self.checkpoint(size, &root, FIXED_TIME, self.foreign_key_at == Some(size))
            })
            .collect();
        if let Some(size) = self.equivocate_at {
            // A second, validly signed checkpoint at one size with a different root: no
            // append-only tree has two roots at one size. Its `checkpoint_time` is later, so
            // the honest member governs under the series order of core §7.3 — and where
            // `equivocate_first` is set it is nevertheless serialized first, so array order
            // and series order disagree.
            let divergent = format!("sha256:{}", hex::encode([0xee_u8; 32]));
            let member = self.checkpoint(size, &divergent, "2026-08-16T13:00:00Z", false);
            if self.equivocate_first {
                series.insert(0, member);
            } else {
                series.push(member);
            }
        }
        if let Some(size) = self.foreign_divergence_at {
            // A second root at one size, signed by a key this corpus's manifest chain does not
            // declare — the shape a second branch has when seen from the first one.
            let divergent = format!("sha256:{}", hex::encode([0xdd_u8; 32]));
            series.push(self.checkpoint(size, &divergent, "2026-08-16T13:00:00Z", true));
        }
        if let Some(size) = self.republish_at {
            // A quiet log restating one tree: same size, same root, later time — and
            // serialized **first**, so array order and series order disagree. Core §7.3 makes
            // the earliest `checkpoint_time` govern where a selection lands on a size carrying
            // several members; taking whichever came first in the array would let the server
            // decide which of its own publications a result is reported against.
            let root = self.root_at(size);
            series.insert(0, self.checkpoint(size, &root, "2026-08-16T13:00:00Z", false));
        }
        series
    }

    /// The witness key active for a checkpoint of size `tree_size` under the corpus manifests.
    fn witness_for(&self, tree_size: u64) -> (&'static str, &TestKey) {
        // Manifest v2 is anchored at entry 25 and rotates the witness set in full, so it
        // governs every checkpoint whose `tree_size` exceeds 25.
        let name = if tree_size > 25 { "witness-2" } else { "witness-1" };
        (name, self.witness_keys.get(name).unwrap_or(&self.log_keys[0]))
    }

    /// A cosigned checkpoint, as the witness publishes it.
    #[must_use]
    pub fn cosigned(&self, tree_size: u64) -> Value {
        let root = self.root_at(tree_size);
        let checkpoint = self.checkpoint(tree_size, &root, FIXED_TIME, false);
        let (witness_id, key) = self.witness_for(tree_size);
        let value = serde_json::to_value(&checkpoint).unwrap_or(Value::Null);
        // Adaptor §11.1 cosigns the six members of §6.2; the projection is what keeps the
        // preimage independent of anything else a checkpoint carries. Every checkpoint this
        // fixture builds projects; one that did not would yield a cosignature over no bytes,
        // which fails in the test that uses it rather than aborting the library.
        let bytes = ahl_core::CosignedCheckpoint::project(&value)
            .map(|cosigned| ahl_core::cosignature_bytes(&cosigned, witness_id))
            .unwrap_or_default();
        json!({
            "checkpoint": checkpoint,
            "witness_id": witness_id,
            "key_id": key.key_id(),
            "cosignature": key.sign(&bytes),
            "cosigned_at": FIXED_TIME,
        })
    }

    /// Establish an anchored view at `tree_size` through the real pipeline.
    ///
    /// # Errors
    ///
    /// Whatever [`establish`] reports.
    pub fn establish(&self, tree_size: u64) -> CliResult<Anchored> {
        let mirror =
            Mirror::new(self, MIRROR, TEST_LOG_PROFILE, NetworkLimits::default())?.with_chunk(5);
        establish(&mirror, &self.policy, tree_size)
    }

    /// `(dataset, record)` of the corpus record retracted at entries 22, 23, 28, 29 and 31.
    #[must_use]
    pub fn record_f(&self) -> (String, String) {
        self.record_named("22-retraction-f-authorized")
    }

    /// `(dataset, record)` of a corpus record no trigger names.
    #[must_use]
    pub fn record_b(&self) -> (String, String) {
        self.record_named("02-ingestion-customers-b")
    }

    /// `(dataset, record)` of the record the correction at entry 6 names.
    #[must_use]
    pub fn record_a(&self) -> (String, String) {
        self.record_named("06-correction-a-to-a2")
    }

    /// Read from the corpus this fixture was built from, never from a fresh lookup: the names
    /// a caller gets back must come from the same material the fixture signs over.
    fn record_named(&self, file: &str) -> (String, String) {
        let path = self.corpus.join("vectors/statements").join(format!("{file}.json"));
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| {
                let payload = value.get("envelope")?.get("payload")?;
                Some((
                    payload.get("dataset")?.as_str()?.to_owned(),
                    payload.get("record")?.as_str()?.to_owned(),
                ))
            })
            .unwrap_or_default()
    }

    /// The recorded exchanges, as a [`crate::transcript`] document.
    #[must_use]
    pub fn transcript(&self) -> Value {
        let mut exchanges: Vec<Value> = self
            .recorded
            .lock()
            .map(|recorded| {
                recorded
                    .iter()
                    .map(|exchange| {
                        json!({
                            "method": exchange.method,
                            "url": exchange.url,
                            "request_body": exchange.request_body,
                            "status": exchange.status,
                            "body_base64": base64_of(&exchange.body),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Sorted and deduplicated so two runs record byte-identical transcripts.
        exchanges.sort_by_key(std::string::ToString::to_string);
        exchanges.dedup();
        json!({
            "description": "recorded from `ahl-cli`'s deterministic conformance fixture",
            "exchanges": exchanges,
        })
    }

    fn record(&self, request: &Request, response: &Response) {
        if let Ok(mut recorded) = self.recorded.lock() {
            recorded.push(Recorded {
                method: request.method.as_str().to_owned(),
                url: request.url.clone(),
                request_body: request
                    .body
                    .as_ref()
                    .map(|body| String::from_utf8_lossy(body).into_owned()),
                status: response.status,
                body: response.body.clone(),
            });
        }
    }

    fn answer(&self, request: &Request) -> Response {
        let path = request.url.strip_prefix(MIRROR).unwrap_or("");
        let witness_path = request.url.strip_prefix(WITNESS).unwrap_or("");

        if path == "/v1/checkpoints" {
            return ok(&self.series());
        }
        if path == "/v1/range" {
            return self.range(request);
        }
        if let Some(query) = path.strip_prefix("/v1/consistency?") {
            return self.consistency(query);
        }
        if let Some(entry_id) = path.strip_prefix("/v1/entries/") {
            return self.entry(entry_id);
        }
        if witness_path.starts_with("/v1/logs/") && witness_path.ends_with("/checkpoints") {
            let history: Vec<Value> =
                self.published_sizes().into_iter().map(|size| self.cosigned(size)).collect();
            return ok(&history);
        }
        if witness_path.starts_with("/v1/logs/") && witness_path.ends_with("/checkpoint") {
            return ok(&self.cosigned(self.newest_tree_size()));
        }
        if witness_path.starts_with("/v1/logs/") && witness_path.ends_with("/refusals") {
            return ok(&Vec::<Value>::new());
        }
        Response { status: 404, body: b"{\"error\":\"no such route\"}".to_vec() }
    }

    fn range(&self, request: &Request) -> Response {
        let Some(body) =
            request.body.as_ref().and_then(|body| serde_json::from_slice::<Value>(body).ok())
        else {
            return Response { status: 400, body: b"{}".to_vec() };
        };
        let (Some(tree_size), Some(from), Some(to)) = (
            body.get("tree_size").and_then(Value::as_u64),
            body.get("from_index").and_then(Value::as_u64),
            body.get("to_index").and_then(Value::as_u64),
        ) else {
            return Response { status: 400, body: b"{}".to_vec() };
        };
        let hashes = self.leaf_hashes(tree_size);
        let Ok(proof) = ahl_core::range_proof::generate(&hashes, from, to) else {
            return Response { status: 400, body: b"{}".to_vec() };
        };
        let entries: Vec<Value> = (from..to)
            .map(|index| {
                let bytes = self.entry_bytes(usize::try_from(index).unwrap_or(usize::MAX));
                json!({
                    "entry_index": index,
                    "envelope": serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
                })
            })
            .collect();
        let root = self.root_at(tree_size);
        ok(&json!({
            "range": { "from_index": from, "to_index": to },
            "entries": entries,
            "range_proof": { "adaptor_form": ahl_core::range_proof::encode(&proof) },
            "checkpoint": self.checkpoint(
                tree_size,
                &root,
                FIXED_TIME,
                self.foreign_key_at == Some(tree_size),
            ),
        }))
    }

    fn consistency(&self, query: &str) -> Response {
        let mut from = 0_u64;
        let mut to = 0_u64;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("from", value)) => from = value.parse().unwrap_or(0),
                Some(("to", value)) => to = value.parse().unwrap_or(0),
                _ => {}
            }
        }
        let hashes = self.leaf_hashes(to);
        let Ok(proof) =
            atl_core::core::merkle::generate_consistency_proof(from, to, |level, at| {
                if level == 0 {
                    hashes.get(usize::try_from(at).ok()?).copied()
                } else {
                    None
                }
            })
        else {
            return Response { status: 400, body: b"{}".to_vec() };
        };
        ok(&json!({
            "from": from,
            "to": to,
            "consistency_path": proof
                .path
                .iter()
                .map(ahl_core::hash_hex)
                .collect::<Vec<_>>(),
        }))
    }

    fn entry(&self, entry_id: &str) -> Response {
        for index in 0..self.entries.len() {
            let bytes = self.entry_bytes(index);
            if ahl_core::sha256_hex(&bytes) == entry_id {
                return Response { status: 200, body: bytes };
            }
        }
        Response { status: 404, body: b"{\"status\":\"absent\"}".to_vec() }
    }
}

fn ok<T: serde::Serialize>(value: &T) -> Response {
    Response { status: 200, body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()) }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl Fetcher for MirrorFixture {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        let response = self.answer(request);
        self.record(request, &response);
        Ok(response)
    }
}

/// The trust policy the conformance corpus's own `receipts/index.json` declares.
#[must_use]
pub fn corpus_policy(root: &Path) -> LoadedPolicy {
    let index: Value = std::fs::read(root.join("receipts/index.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let block = index.get("policy").cloned().unwrap_or(Value::Null);
    let declared =
        block.get("adaptor_profiles").and_then(|profiles| profiles.get(TEST_LOG_PROFILE));
    let hash = declared
        .and_then(|profile| profile.get("hash"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // Capabilities come from what the corpus declares, never from a hard-coded guess: they are
    // a property of the pinned profile document, and pinning them here would make this fixture
    // silently disagree with the corpus the moment the document gains a capability.
    let capabilities = declared
        .and_then(|profile| profile.get("capabilities"))
        .map(|caps| ahl_core::receipt::AdaptorCapabilities {
            checkpoint_raw: caps.get("checkpoint_raw").and_then(Value::as_bool).unwrap_or(false),
            consistency_proofs: caps
                .get("consistency_proofs")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
        .unwrap_or_default();

    let dataset_keys = std::fs::read_to_string(root.join("keys/dataset_customers.key"))
        .ok()
        .and_then(|text| hex::decode(text.trim()).ok())
        .map(|key| BTreeMap::from([("customers".to_owned(), key)]))
        .unwrap_or_default();

    LoadedPolicy {
        trust: TrustPolicy {
            genesis_entry_id: block
                .get("genesis_entry_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            genesis_key_ids: block
                .get("genesis_key_ids")
                .and_then(Value::as_array)
                .map(|ids| ids.iter().filter_map(|id| id.as_str().map(str::to_owned)).collect()),
            // The held document is installed at the point of use; see `policy::load`.
            adaptor_profiles: BTreeMap::new(),
            dataset_keys,
            trusted_witness_keys: BTreeMap::new(),
            limits: ahl_core::receipt::Limits::default(),
        },
        profiles: BTreeMap::from([(
            TEST_LOG_PROFILE.to_owned(),
            ConfiguredProfile { hash, path: root.join("adaptor/ahl-test-log-v1.md"), capabilities },
        )]),
        endpoints: Endpoints { mirror: Some(MIRROR.to_owned()), witness: Some(WITNESS.to_owned()) },
        network: NetworkLimits::default(),
        local: LocalLimits::default(),
    }
}

/// The corpus's committed tree material, as the root-to-leaves map a closure needs.
///
/// Adaptor profile §9 makes the complete leaf material of every committed tree corpus material
/// that a deployment MUST publish, but neither the profile nor `ahl-mirror` defines an
/// interface for serving it, so a client is handed it out of band. The conformance corpus
/// publishes it as merkle vectors; this assembles them into the map the CLI accepts.
#[must_use]
pub fn tree_material(root: &Path) -> Value {
    let dir = root.join("vectors/merkle");
    let mut material = serde_json::Map::new();
    for (file, root_member) in [
        ("batch-tree.json", "outputs_root"),
        ("wide-outputs-tree.json", "outputs_root"),
        ("input-set-tree.json", "input_set_root"),
        ("disposition-tree.json", "affected_root"),
        ("challenge-disposition-tree.json", "affected_root"),
    ] {
        let Ok(bytes) = std::fs::read(dir.join(file)) else { continue };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else { continue };
        let (Some(anchored_root), Some(leaves)) =
            (value.get(root_member).and_then(Value::as_str), value.get("leaves"))
        else {
            continue;
        };
        material.insert(anchored_root.to_owned(), leaves.clone());
    }
    Value::Object(material)
}

/// The longest PREFIX of the corpus statements a closure can be answered over, copied into a
/// fresh directory.
///
/// A closure collects every committed tree root the corpus references **before** traversal
/// begins, so that missing material is named rather than discovered halfway through. The
/// conformance corpus deliberately contains a derivation whose committed tree the corpus
/// publishes only inside the negative receipt vectors built on it, and a walk over the whole
/// directory is therefore `unverifiable` for want of that material — correctly, and for a
/// reason unrelated to what a topology-mode test is exercising.
///
/// A PREFIX rather than a subset, and the difference is not cosmetic: closure traversal keys on
/// the entry index, so a corpus with a hole in it cannot be walked without inventing one. Taking
/// everything before the first statement whose roots [`tree_material`] does not carry keeps the
/// sequence dense. The rule is the material, never a file name, so a corpus that later publishes
/// those roots extends the prefix here with no edit.
#[cfg(test)]
#[must_use]
pub(crate) fn statements_with_published_tree_material(dir: &Path) -> PathBuf {
    statements_with_published_tree_material_in(&crate::test_corpus::corpus_dir(), dir)
}

/// The longest prefix of `root`'s statements a closure can be answered over, copied into
/// `dir`; see [`tree_material`] for what "published material" means here.
///
/// The corpus is the caller's to name. An integration test is a separate crate, linking this
/// one without `cfg(test)`, so it locates the corpus for itself — from the `ahl-core` package
/// `cargo` resolved — and passes it here rather than having one chosen behind its back.
#[must_use]
pub fn statements_with_published_tree_material_in(root: &Path, dir: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let out = dir.join(format!("statements.{}.{unique}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);

    let material = tree_material(root);
    let published = |value: &Value| -> bool {
        let Some(payload) = value.get("envelope").and_then(|e| e.get("payload")) else {
            return true;
        };
        tree_material_reaches(payload, &material)
    };

    let Ok(entries) = std::fs::read_dir(root.join("vectors/statements")) else { return out };
    let mut files: Vec<PathBuf> =
        entries.filter_map(|entry| entry.ok().map(|entry| entry.path())).collect();
    files.sort();
    for file in files {
        if file.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&file) else { continue };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else { continue };
        if !published(&value) {
            break;
        }
        if let Some(name) = file.file_name() {
            let _ = std::fs::write(out.join(name), &bytes);
        }
    }
    out
}

/// Every committed tree root reachable from `value`, at any depth.
///
/// A root is any member whose name ends in `_root` — `outputs_root`, `affected_root`,
/// `input_set_root` — read off the whole subtree rather than off a fixed list of members, so a
/// commitment a later revision adds is followed here without an edit.
fn committed_roots(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(members) => {
            for (name, member) in members {
                if name.ends_with("_root") {
                    if let Some(hash) = member.as_str() {
                        out.insert(hash.to_owned());
                    }
                }
                committed_roots(member, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                committed_roots(item, out);
            }
        }
        _ => {}
    }
}

/// Whether `material` publishes every committed tree a closure over `payload` would open,
/// **transitively**.
///
/// Following only the roots named in the payload is not enough, and the gap is not theoretical:
/// a batch derivation's `outputs_root` opens a tree whose leaves each carry their own `inputs`,
/// and a leaf's `inputs` may itself be a wide-input commitment `{input_set_root,
/// input_set_count}` that the closure opens in turn. A selector that stopped at the payload
/// would hand a topology test a corpus that fails halfway through the walk, for want of
/// material, on a statement it believed it had checked.
fn tree_material_reaches(payload: &Value, material: &Value) -> bool {
    let mut pending = BTreeSet::new();
    committed_roots(payload, &mut pending);
    let mut seen: BTreeSet<String> = BTreeSet::new();

    while let Some(root) = pending.pop_first() {
        if !seen.insert(root.clone()) {
            continue;
        }
        let Some(leaves) = material.get(&root) else { return false };
        committed_roots(leaves, &mut pending);
    }
    true
}

/// Write [`tree_material`] into `dir` and return the path.
///
/// The file name is unique per call: callers routinely pass a shared temporary directory, and
/// two tests running in parallel writing one name is how a reader ends up seeing a
/// half-written file.
#[cfg(test)]
#[must_use]
pub(crate) fn tree_material_file(dir: &Path) -> PathBuf {
    tree_material_file_in(&crate::test_corpus::corpus_dir(), dir)
}

/// Write [`tree_material`] for the corpus at `root` into `dir` and return the path.
///
/// The file name is unique per call, and the corpus is the caller's to name — see
/// [`statements_with_published_tree_material_in`] for why.
#[must_use]
pub fn tree_material_file_in(root: &Path, dir: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("tree-material.{}.{unique}.json", std::process::id()));
    let bytes = serde_json::to_vec(&tree_material(root)).unwrap_or_else(|_| b"{}".to_vec());
    let _ = std::fs::write(&path, bytes);
    path
}

/// The identity of the fixture's checkpoint at `tree_size`, for cache-key construction.
#[must_use]
pub fn identity_at(fixture: &MirrorFixture, tree_size: u64) -> CheckpointIdentity {
    CheckpointIdentity {
        log_id: fixture.log_id(),
        tree_size,
        root_hash: fixture.root_at(tree_size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_selector_follows_every_committed_tree_the_closure_would_open() {
        // The closure opens a batch derivation's `outputs_root`, and then each leaf's `inputs`
        // — which may itself be a wide-input commitment naming another tree. A selector that
        // read only the payload's own roots would pass a statement whose closure fails halfway
        // through the walk for want of material.
        let nested = format!("sha256:{}", "11".repeat(32));
        let outputs = format!("sha256:{}", "22".repeat(32));
        let material = json!({
            outputs.as_str(): [
                { "dataset": "d", "record": "sha256:aa",
                  "inputs": { "input_set_root": nested.as_str(), "input_set_count": 2 } },
            ],
            nested.as_str(): [ { "dataset": "d", "record": "sha256:bb" } ],
        });

        // Nothing committed at all: nothing to publish.
        assert!(tree_material_reaches(&json!({ "type": "ingestion" }), &material));

        // A root named in the payload and not published.
        let unpublished = format!("sha256:{}", "33".repeat(32));
        assert!(!tree_material_reaches(
            &json!({ "inputs": { "input_set_root": unpublished, "input_set_count": 1 } }),
            &material
        ));

        // A published outputs tree whose LEAF names an input set — the transitive case.
        let payload = json!({ "outputs_root": outputs.as_str(), "outputs_count": 1 });
        assert!(tree_material_reaches(&payload, &material));
        let without_nested = json!({ outputs.as_str(): material[&outputs].clone() });
        assert!(
            !tree_material_reaches(&payload, &without_nested),
            "a root reachable only through another tree's leaves is still required"
        );
    }

    #[test]
    fn the_selected_corpus_keeps_the_wide_input_derivation_and_drops_the_unpublished_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let selected = statements_with_published_tree_material(dir.path());
        let names: Vec<String> = std::fs::read_dir(&selected)
            .expect("selected corpus")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|name| name.contains("derivation-batch-wide-inputs")),
            "a wide-input derivation whose input-set tree IS published stays: {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.contains("defective-input-sets")),
            "the statement whose committed tree the corpus does not publish is dropped: {names:?}"
        );
        // A dense prefix, so the walk can key on the entry index: everything from the first
        // unpublished statement on is left out too, whatever its own material.
        let mut indexes: Vec<usize> =
            names.iter().filter_map(|name| name.split('-').next()?.parse().ok()).collect();
        indexes.sort_unstable();
        assert!(
            indexes.iter().enumerate().all(|(at, index)| at == *index),
            "the selection is a dense prefix: {indexes:?}"
        );
    }

    #[test]
    fn the_fixture_loads_the_whole_conformance_corpus() {
        // Counted from the corpus rather than pinned to a number: what this asserts is that
        // every published statement is loaded and that the newest checkpoint covers all of
        // them, and a corpus that grows must not turn either into a failure.
        let published =
            std::fs::read_dir(crate::test_corpus::corpus_dir().join("vectors/statements"))
                .expect("statement vectors")
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count();
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        assert!(published >= 30, "the corpus should carry 30+ statements, got {published}");
        assert_eq!(fixture.entries.len(), published, "every published statement is loaded");
        assert!(fixture.log_id().starts_with("sha256:"));
        assert_eq!(
            fixture.newest_tree_size(),
            u64::try_from(published).expect("small test corpus"),
            "the newest published checkpoint covers the whole corpus"
        );
    }

    #[test]
    fn the_published_series_is_deterministic() {
        let first = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with")
            .series();
        let second = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with")
            .series();
        assert_eq!(first, second);
        // The constant sizes that fit the corpus, plus the corpus's own size where it is not
        // already one of them.
        let total = u64::try_from(
            MirrorFixture::conformance()
                .expect("the conformance corpus publishes the key seeds the fixture signs with")
                .entries
                .len(),
        )
        .expect("small");
        let mut expected: Vec<u64> =
            CHECKPOINT_SIZES.into_iter().filter(|size| *size <= total).collect();
        if !expected.contains(&total) {
            expected.push(total);
        }
        assert_eq!(first.len(), expected.len());
    }

    #[test]
    fn an_equivocating_fixture_publishes_two_roots_at_one_size() {
        let series = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with")
            .with_equivocation_at(13)
            .series();
        assert_eq!(crate::checkpoint::equivocation_floor(&series), Some(13));
    }

    #[test]
    fn the_fixture_records_a_replayable_transcript() {
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        let _ = fixture.establish(8).expect("established");
        let transcript = fixture.transcript();
        let replay = crate::transcript::TranscriptFetcher::from_slice(
            &serde_json::to_vec(&transcript).expect("serialize"),
        )
        .expect("parses");
        assert!(!replay.is_empty());
    }

    #[test]
    fn the_named_corpus_records_resolve() {
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        for (dataset, record) in [fixture.record_a(), fixture.record_b(), fixture.record_f()] {
            assert_eq!(dataset, "customers");
            assert!(record.starts_with("hmac-sha256:"), "{record}");
        }
    }

    #[test]
    fn unknown_routes_answer_with_a_status_rather_than_inventing_a_body() {
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        let response =
            fixture.fetch(&Request::get(format!("{MIRROR}/v1/nothing"))).expect("fixture answers");
        assert_eq!(response.status, 404);
    }

    #[test]
    fn the_witness_key_rotates_with_the_manifest_version_governing_the_checkpoint() {
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        assert_eq!(fixture.witness_for(20).0, "witness-1");
        assert_eq!(fixture.witness_for(26).0, "witness-2");
        assert_eq!(fixture.cosigned(26)["witness_id"], json!("witness-2"));
    }

    #[test]
    fn a_tampered_entry_changes_the_served_bytes_but_never_the_committed_root() {
        let clean = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        let tampered = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with")
            .with_tampered_entry(3);
        // The log signed one tree; the mirror serves another. That mismatch is the whole
        // scenario, so the committed root must stay put while the bytes change.
        assert_eq!(clean.root_at(8), tampered.root_at(8));
        assert_ne!(clean.entry_bytes(3), tampered.entry_bytes(3));
        assert_ne!(clean.leaf_hashes(8), tampered.leaf_hashes(8));
    }

    #[test]
    fn entry_retrieval_is_content_addressed_and_absence_is_a_status() {
        let fixture = MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        let entry_id = ahl_core::sha256_hex(&fixture.entry_bytes(1));
        let response = fixture.entry(&entry_id);
        assert_eq!(response.status, 200);
        assert_eq!(ahl_core::sha256_hex(&response.body), entry_id);
        assert_eq!(fixture.entry(&format!("sha256:{}", "aa".repeat(32))).status, 404);
    }

    #[test]
    fn the_corpus_policy_carries_the_published_anchor_and_dataset_key() {
        let policy = corpus_policy(&crate::test_corpus::corpus_dir());
        assert!(policy.trust.genesis_entry_id.starts_with("sha256:"));
        assert_eq!(
            policy.trust.genesis_key_ids.as_ref().map(std::collections::BTreeSet::len),
            Some(1)
        );
        assert_eq!(policy.trust.dataset_keys["customers"].len(), 32);
        assert_eq!(
            identity_at(
                &MirrorFixture::conformance().expect(
                    "the conformance corpus publishes the key seeds the fixture signs with"
                ),
                8
            )
            .tree_size,
            8
        );
    }
}
