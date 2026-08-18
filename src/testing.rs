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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ahl_core::receipt::{AdaptorProfile, TrustPolicy};
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
pub const CHECKPOINT_SIZES: [u64; 5] = [8, 13, 20, 28, 32];

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
    log_key: TestKey,
    /// A key the corpus manifests never declare, for the "foreign key" fixture.
    foreign_key: TestKey,
    /// Witness keys by name.
    witness_keys: BTreeMap<&'static str, TestKey>,
    /// Publish a second, diverging checkpoint at this size.
    equivocate_at: Option<u64>,
    /// Sign the checkpoint at this size with a key the manifest does not declare.
    foreign_key_at: Option<u64>,
    /// Serve different bytes for this entry index.
    tampered: Option<usize>,
    recorded: Mutex<Vec<Recorded>>,
}

fn seed(path: &Path, name: &'static str) -> TestKey {
    let hex = std::fs::read_to_string(path.join("keys").join(format!("{name}.seed")))
        .unwrap_or_else(|_| "00".repeat(32));
    TestKey::from_seed_hex(name, hex.trim()).unwrap_or_else(|_| {
        TestKey::from_seed_hex(name, &"00".repeat(32)).unwrap_or_else(|_| {
            // Unreachable for a 32-byte constant; the fallback keeps this helper total.
            TestKey::from_seed_hex(name, &"01".repeat(32)).unwrap_or_else(|_| unreachable())
        })
    })
}

fn unreachable() -> TestKey {
    // `TestKey::from_seed_hex` accepts any 64 hex digits, so this is genuinely unreachable;
    // the crate denies `panic!`, so the total function returns a fixed key instead.
    #[allow(clippy::expect_used)]
    TestKey::from_seed_hex("fallback", &"02".repeat(32)).expect("64 hex digits")
}

impl MirrorFixture {
    /// The path of the sibling `ahl-core` conformance corpus this repository is developed
    /// against.
    #[must_use]
    pub fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ahl-core/test_data")
    }

    /// Build the fixture from the conformance corpus.
    #[must_use]
    pub fn conformance() -> Self {
        Self::from_corpus(&Self::corpus_root())
    }

    /// Build the fixture from a corpus at `root`.
    #[must_use]
    pub fn from_corpus(root: &Path) -> Self {
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

        Self {
            policy: corpus_policy(root),
            entries,
            log_key: seed(root, "log-1"),
            foreign_key: TestKey::from_seed_hex("foreign", &"7f".repeat(32))
                .unwrap_or_else(|_| unreachable()),
            witness_keys: BTreeMap::from([
                ("witness-1", seed(root, "witness-1")),
                ("witness-2", seed(root, "witness-2")),
            ]),
            equivocate_at: None,
            foreign_key_at: None,
            tampered: None,
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Publish a second, diverging checkpoint at `tree_size`.
    #[must_use]
    pub const fn with_equivocation_at(mut self, tree_size: u64) -> Self {
        self.equivocate_at = Some(tree_size);
        self
    }

    /// Sign the checkpoint at `tree_size` with a key no manifest version declares.
    #[must_use]
    pub const fn with_foreign_log_key(mut self, tree_size: u64) -> Self {
        self.foreign_key_at = Some(tree_size);
        self
    }

    /// Serve different bytes for the entry at `index`, so root recomputation fails.
    #[must_use]
    pub const fn with_tampered_entry(mut self, index: usize) -> Self {
        self.tampered = Some(index);
        self
    }

    /// The largest published tree size.
    #[must_use]
    pub fn newest_tree_size(&self) -> u64 {
        self.published_sizes().into_iter().max().unwrap_or(0)
    }

    fn published_sizes(&self) -> Vec<u64> {
        let total = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        CHECKPOINT_SIZES.into_iter().filter(|size| *size <= total).collect()
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
        let key = if foreign { &self.foreign_key } else { &self.log_key };
        let mut checkpoint = Checkpoint {
            log_id: self.log_id(),
            tree_size,
            root_hash: root.to_owned(),
            checkpoint_time: time.to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
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
            // append-only tree has two roots at one size.
            let divergent = format!("sha256:{}", hex::encode([0xee_u8; 32]));
            series.push(self.checkpoint(size, &divergent, "2026-08-16T13:00:00Z", false));
        }
        series
    }

    /// The witness key active for a checkpoint of size `tree_size` under the corpus manifests.
    fn witness_for(&self, tree_size: u64) -> (&'static str, &TestKey) {
        // Manifest v2 is anchored at entry 25 and rotates the witness set in full, so it
        // governs every checkpoint whose `tree_size` exceeds 25.
        let name = if tree_size > 25 { "witness-2" } else { "witness-1" };
        (name, self.witness_keys.get(name).unwrap_or(&self.log_key))
    }

    /// A cosigned checkpoint, as the witness publishes it.
    #[must_use]
    pub fn cosigned(&self, tree_size: u64) -> Value {
        let root = self.root_at(tree_size);
        let checkpoint = self.checkpoint(tree_size, &root, FIXED_TIME, false);
        let (witness_id, key) = self.witness_for(tree_size);
        let value = serde_json::to_value(&checkpoint).unwrap_or(Value::Null);
        json!({
            "checkpoint": checkpoint,
            "witness_id": witness_id,
            "key_id": key.key_id(),
            "cosignature": key.sign(&ahl_core::cosignature_bytes(&value, witness_id)),
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
        Self::record_named("22-retraction-f-authorized")
    }

    /// `(dataset, record)` of a corpus record no trigger names.
    #[must_use]
    pub fn record_b(&self) -> (String, String) {
        Self::record_named("02-ingestion-customers-b")
    }

    /// `(dataset, record)` of the record the correction at entry 6 names.
    #[must_use]
    pub fn record_a(&self) -> (String, String) {
        Self::record_named("06-correction-a-to-a2")
    }

    fn record_named(file: &str) -> (String, String) {
        let path = Self::corpus_root().join("vectors/statements").join(format!("{file}.json"));
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
    let hash = block
        .get("adaptor_profiles")
        .and_then(|profiles| profiles.get(TEST_LOG_PROFILE))
        .and_then(|profile| profile.get("hash"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

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
                .map(|ids| ids.iter().filter_map(|id| id.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
            adaptor_profiles: BTreeMap::from([(
                TEST_LOG_PROFILE.to_owned(),
                AdaptorProfile::minimal(hash.clone()),
            )]),
            dataset_keys,
            trusted_witness_key_ids: std::collections::BTreeSet::new(),
            limits: ahl_core::receipt::Limits::default(),
        },
        profiles: BTreeMap::from([(
            TEST_LOG_PROFILE.to_owned(),
            ConfiguredProfile {
                hash,
                path: root.join("adaptor/ahl-test-log-v1.md"),
                capabilities: ahl_core::receipt::AdaptorCapabilities::default(),
            },
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

/// Write [`tree_material`] into `dir` and return the path.
#[must_use]
pub fn tree_material_file(dir: &Path) -> PathBuf {
    let path = dir.join("tree-material.json");
    let bytes = serde_json::to_vec(&tree_material(&MirrorFixture::corpus_root()))
        .unwrap_or_else(|_| b"{}".to_vec());
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
    fn the_fixture_loads_the_whole_conformance_corpus() {
        let fixture = MirrorFixture::conformance();
        assert_eq!(fixture.entries.len(), 32, "the toy corpus is 32 entries");
        assert!(fixture.log_id().starts_with("sha256:"));
        assert_eq!(fixture.newest_tree_size(), 32);
    }

    #[test]
    fn the_published_series_is_deterministic() {
        let first = MirrorFixture::conformance().series();
        let second = MirrorFixture::conformance().series();
        assert_eq!(first, second);
        assert_eq!(first.len(), CHECKPOINT_SIZES.len());
    }

    #[test]
    fn an_equivocating_fixture_publishes_two_roots_at_one_size() {
        let series = MirrorFixture::conformance().with_equivocation_at(13).series();
        assert_eq!(crate::checkpoint::equivocation_floor(&series), Some(13));
    }

    #[test]
    fn the_fixture_records_a_replayable_transcript() {
        let fixture = MirrorFixture::conformance();
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
        let fixture = MirrorFixture::conformance();
        for (dataset, record) in [fixture.record_a(), fixture.record_b(), fixture.record_f()] {
            assert_eq!(dataset, "customers");
            assert!(record.starts_with("hmac-sha256:"), "{record}");
        }
    }

    #[test]
    fn unknown_routes_answer_with_a_status_rather_than_inventing_a_body() {
        let fixture = MirrorFixture::conformance();
        let response =
            fixture.fetch(&Request::get(format!("{MIRROR}/v1/nothing"))).expect("fixture answers");
        assert_eq!(response.status, 404);
    }

    #[test]
    fn the_witness_key_rotates_with_the_manifest_version_governing_the_checkpoint() {
        let fixture = MirrorFixture::conformance();
        assert_eq!(fixture.witness_for(20).0, "witness-1");
        assert_eq!(fixture.witness_for(26).0, "witness-2");
        assert!(fixture.cosigned(26)["witness_id"] == json!("witness-2"));
    }

    #[test]
    fn a_tampered_entry_changes_the_served_bytes_but_never_the_committed_root() {
        let clean = MirrorFixture::conformance();
        let tampered = MirrorFixture::conformance().with_tampered_entry(3);
        // The log signed one tree; the mirror serves another. That mismatch is the whole
        // scenario, so the committed root must stay put while the bytes change.
        assert_eq!(clean.root_at(8), tampered.root_at(8));
        assert_ne!(clean.entry_bytes(3), tampered.entry_bytes(3));
        assert_ne!(clean.leaf_hashes(8), tampered.leaf_hashes(8));
    }

    #[test]
    fn entry_retrieval_is_content_addressed_and_absence_is_a_status() {
        let fixture = MirrorFixture::conformance();
        let entry_id = ahl_core::sha256_hex(&fixture.entry_bytes(1));
        let response = fixture.entry(&entry_id);
        assert_eq!(response.status, 200);
        assert_eq!(ahl_core::sha256_hex(&response.body), entry_id);
        assert_eq!(fixture.entry(&format!("sha256:{}", "aa".repeat(32))).status, 404);
    }

    #[test]
    fn the_corpus_policy_carries_the_published_anchor_and_dataset_key() {
        let policy = corpus_policy(&MirrorFixture::corpus_root());
        assert!(policy.trust.genesis_entry_id.starts_with("sha256:"));
        assert_eq!(policy.trust.genesis_key_ids.len(), 1);
        assert_eq!(policy.trust.dataset_keys["customers"].len(), 32);
        assert_eq!(identity_at(&MirrorFixture::conformance(), 8).tree_size, 8);
    }
}
