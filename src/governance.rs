//! Governance resolved from anchored entries, independently of any receipt.
//!
//! `ahl-core` resolves governance inside `verify_receipt`, from the chain a receipt carries.
//! A client that must resolve it from a **live enumeration** — which `closure` and
//! `reconstruct` do — needs the same rules over a different input, and `ahl-core` does not
//! expose them, so they are re-derived here against the same normative text.
//!
//! The rules, and why each one is not optional:
//!
//! * **Governance statements are not self-authorizing** (core spec §7.3, adaptor §7.4.1).
//!   Anchoring proves bytes existed at a position; it never makes an unverified governance
//!   statement effective. A party able to submit entries can place a well-formed object
//!   claiming to be a manifest at a real index with a real inclusion proof, and a verifier
//!   that resolved keys from it would accept checkpoints signed by keys the corpus never
//!   adopted.
//! * **The genesis anchor comes from local policy**, never from the log.
//! * **A manifest's `keys` array is a snapshot, not a set of add events** (core spec §7.2): it
//!   discards the prior snapshot, and later `key` statements modify it in entry order until
//!   the next manifest version. A key a later manifest omits is gone.
//! * **The manifest version governing a checkpoint is selected by `tree_size`** — the manifest
//!   statement with the greatest entry index smaller than that `tree_size` (core spec §7.3,
//!   receipt format §2.2). Resolving by the *subject entry's* index is wrong in both
//!   directions: it rejects a legitimate rotation between the entry and the checkpoint, and it
//!   admits a retired key on a later checkpoint.
//!
//! # Governance is not self-authorizing, and this is where that is enforced
//!
//! Adaptor §7.4.1 is explicit that an implementation built from the profile alone could
//! otherwise "resolve keys from any anchored entry whose payload says `"type": "manifest"`. It
//! MUST NOT." An anchored `manifest` or `key` statement counts as governance only if **all**
//! of the following hold:
//!
//! 1. it is anchored at a known entry index, proven by inclusion under a checkpoint — which is
//!    established before [`Governance::resolve`] is reached, by the range proof and the root
//!    recomputation of [`crate::enumerate`];
//! 2. its **producer signature verifies under the key set in force at its own entry index**,
//!    every signature entry resolving to an active key and verifying;
//! 3. for a non-genesis manifest, its `predecessor` links by entry id to the manifest version
//!    **active immediately before it** — not merely to some earlier manifest in the log;
//! 4. for the genesis manifest, its entry id and initial key fingerprints match the verifier's
//!    **locally configured** trust anchor, which is never taken from the log.
//!
//! Test 2 is why [`Governance::resolve`] builds the chain **incrementally**. Collecting every
//! `manifest`-shaped payload first and checking signatures afterwards inverts the dependency:
//! a hostile mirror can then serve a recomputable tree containing the genuine pinned genesis
//! manifest *plus a forged later manifest naming attacker log keys*, and a checkpoint signed
//! by those keys authenticates. On a log without submission controls anyone who can reach the
//! endpoint can place such an entry at a real index with a real inclusion proof.
//!
//! A statement that fails is **ignored for key resolution and reported**, never fatal: adaptor
//! §7.4.1 says such an entry "is not a fork of the corpus and does not need to be reconciled
//! with the real chain". Only a genesis that does not match configured policy is fatal, because
//! then there is no trust anchor at all.
//!
//! # `log.log_id`
//!
//! Core §7.2/§7.3 and adaptor §7.3 name the manifest log-object member `log_id`, and every
//! member of that object is REQUIRED. This module requires that spelling: the value is
//! load-bearing for the check that a checkpoint belongs to the corpus's bound Data Tree
//! (adaptor §3, §6.2), so its absence is not a reportable irregularity but a check that cannot
//! be performed. Members this build never consults — `cadence_epoch`, `operator` — are
//! reported through [`Governance::log_object_findings`] instead, because reporting is all a
//! verifier can honestly do about a field no rule of its own depends on.
//!
use std::collections::{BTreeMap, BTreeSet};

use ahl_core::entry_id;
use ahl_core::receipt::TrustPolicy;
use serde_json::Value;

use crate::duration::parse_time_only_duration;
use crate::error::{CliError, CliResult};
use crate::report::Finding;

/// A producer key-set transition, ordered by the entry index that anchored it.
#[derive(Debug, Clone)]
struct KeyEvent {
    entry_index: u64,
    key_id: String,
    pubkey: String,
    added: bool,
}

/// The governance state derived from a set of anchored entries.
#[derive(Debug, Clone, Default)]
pub struct Governance {
    /// Manifest payloads, ascending by entry index.
    manifests: Vec<(u64, Value)>,
    /// Producer key transitions, ascending by entry index.
    events: Vec<KeyEvent>,
}

fn payload_of(envelope: &Value) -> CliResult<&Value> {
    envelope.get("payload").filter(|p| p.is_object()).ok_or_else(|| CliError::Malformed {
        what: "entry",
        detail: "carries no `payload` object".to_owned(),
    })
}

impl Governance {
    /// Collect governance statements after **structural validation only**.
    ///
    /// No producer signature is checked and no trust anchor is consulted, so the result is
    /// **not** an authenticated key set and must never be used to authenticate anything. It
    /// exists for topology mode, where nothing is evidence and the point is to describe an
    /// operator-supplied file rather than to believe it. Authenticated callers use
    /// [`Self::resolve`].
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] naming the structural rule that failed.
    pub fn structural_only(entries: &[(u64, Value)]) -> CliResult<Self> {
        let mut manifests: Vec<(u64, Value)> = Vec::new();
        let mut events: Vec<KeyEvent> = Vec::new();
        let mut previous_manifest_entry_id: Option<String> = None;
        let mut previous_index: Option<u64> = None;

        for (index, envelope) in entries {
            if previous_index.is_some_and(|previous| previous >= *index) {
                return Err(CliError::RuleFired(
                    "entries must ascend by entry index; the entry index is AHL's only \
                     ordering primitive"
                        .to_owned(),
                ));
            }
            previous_index = Some(*index);

            let payload = payload_of(envelope)?;
            let Some(kind) = payload.get("type").and_then(Value::as_str) else {
                return Err(CliError::RuleFired(format!(
                    "entry at index {index} carries no statement type"
                )));
            };
            match kind {
                "manifest" => {
                    let predecessor = payload.get("predecessor").and_then(Value::as_str);
                    match (&previous_manifest_entry_id, predecessor) {
                        (None, Some(_)) => {
                            return Err(CliError::RuleFired(
                                "the genesis manifest must carry no predecessor reference"
                                    .to_owned(),
                            ))
                        }
                        (Some(_), None) => {
                            return Err(CliError::RuleFired(
                                "a non-genesis manifest must reference its predecessor".to_owned(),
                            ))
                        }
                        // By *entry* id: signature identity matters for chain links (§2.3.5),
                        // and it must be the version active immediately before, not merely
                        // some earlier manifest in the log (adaptor §7.4.1 rule 3).
                        (Some(want), Some(got)) if want != got => {
                            return Err(CliError::RuleFired(format!(
                                "manifest at entry index {index} references `{got}`, but the \
                                 version active immediately before it is `{want}`"
                            )))
                        }
                        _ => {}
                    }
                    previous_manifest_entry_id = Some(entry_id(envelope));
                    manifests.push((*index, payload.clone()));
                }
                "key" => events.push(read_key_event(*index, payload).map_err(|detail| {
                    CliError::RuleFired(format!(
                        "`key` statement at entry index {index} is unusable: {detail}"
                    ))
                })?),
                _ => {}
            }
        }

        if manifests.is_empty() {
            return Err(CliError::RuleFired(
                "no manifest statement is anchored; a corpus always contains at least its \
                 genesis manifest"
                    .to_owned(),
            ));
        }
        Ok(Self { manifests, events })
    }

    /// Resolve governance **incrementally**, per adaptor §7.4.1.
    ///
    /// Walks `entries` in ascending entry-index order. The first manifest is the genesis and
    /// is tested against locally configured policy; every later `manifest` or `key` statement
    /// must verify under the key set the chain has already established *before* it can
    /// contribute anything to that key set. A statement that fails any of §7.4.1's tests is
    /// ignored for key resolution and reported in the returned findings.
    ///
    /// Returns the resolved state and the findings raised while resolving it.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when there is no usable trust anchor at all: entries out of
    /// order, no manifest, or a genesis that does not match configured policy. Everything else
    /// is a finding, because a forged governance statement is not a fork of the corpus and
    /// does not need to be reconciled with the real chain.
    pub fn resolve(
        entries: &[(u64, Value)],
        policy: &TrustPolicy,
    ) -> CliResult<(Self, Vec<Finding>)> {
        let mut resolved = Self::default();
        let mut findings = Vec::new();
        let mut previous_index: Option<u64> = None;
        let mut previous_manifest_entry_id: Option<String> = None;

        for (index, envelope) in entries {
            if previous_index.is_some_and(|previous| previous >= *index) {
                return Err(CliError::RuleFired(
                    "entries must ascend by entry index; the entry index is AHL's only \
                     ordering primitive"
                        .to_owned(),
                ));
            }
            previous_index = Some(*index);

            let payload = payload_of(envelope)?;
            let kind = payload.get("type").and_then(Value::as_str).unwrap_or_default();
            if !matches!(kind, "manifest" | "key") {
                continue;
            }

            // --- the genesis manifest: §7.4.1 test 4 ---------------------------------
            if resolved.manifests.is_empty() {
                if kind != "manifest" {
                    findings.push(Finding::new(
                        "governance-statement-not-authorized",
                        format!(
                            "the `key` statement at entry index {index} precedes any manifest \
                             version, so no key set is in force to authorize it; it is ignored \
                             for key resolution"
                        ),
                    ));
                    continue;
                }
                resolved.accept_genesis(*index, envelope, payload, policy)?;
                previous_manifest_entry_id = Some(entry_id(envelope));
                continue;
            }

            // --- §7.4.1 test 2: verified under the key set the chain already established --
            //
            // `resolved` holds only statements already accepted, so `producer_keys_at` is the
            // key set in force at this index under the chain BEFORE it. This is the ordering
            // the whole module exists to get right.
            if !resolved.envelope_verifies_at(envelope, *index).unwrap_or(false) {
                findings.push(Finding::new(
                    "governance-statement-not-authorized",
                    format!(
                        "the `{kind}` statement at entry index {index} does not verify under \
                         the key set in force at that index; anchoring proves bytes existed at \
                         a position and never makes an unverified governance statement \
                         effective (adaptor §7.4.1)"
                    ),
                ));
                continue;
            }

            match kind {
                "manifest" => {
                    // --- §7.4.1 test 3: the predecessor link ---------------------------
                    let declared = payload.get("predecessor").and_then(Value::as_str);
                    let expected = previous_manifest_entry_id.as_deref();
                    if declared != expected {
                        findings.push(Finding::new(
                            "governance-statement-not-authorized",
                            format!(
                                "the manifest at entry index {index} references predecessor \
                                 `{}`, but the version active immediately before it is `{}`; it \
                                 is ignored for key resolution",
                                declared.unwrap_or("<absent>"),
                                expected.unwrap_or("<none>")
                            ),
                        ));
                        continue;
                    }
                    previous_manifest_entry_id = Some(entry_id(envelope));
                    resolved.manifests.push((*index, payload.clone()));
                }
                _ => match read_key_event(*index, payload) {
                    Ok(event) => resolved.events.push(event),
                    Err(detail) => findings.push(Finding::new(
                        "governance-statement-not-authorized",
                        format!("the `key` statement at entry index {index} is unusable: {detail}"),
                    )),
                },
            }
        }

        if resolved.manifests.is_empty() {
            return Err(CliError::RuleFired(
                "no manifest statement authorized by the configured trust anchor is anchored; \
                 a corpus always contains at least its genesis manifest"
                    .to_owned(),
            ));
        }
        findings.sort();
        findings.dedup();
        Ok((resolved, findings))
    }

    /// §7.4.1 test 4, plus the genesis's own signature.
    ///
    /// The genesis manifest is the one statement validated by its own snapshot: there is no
    /// earlier key set to check it against, which is exactly why its entry id and key
    /// fingerprints have to come from **locally configured policy** rather than from the log.
    fn accept_genesis(
        &mut self,
        index: u64,
        envelope: &Value,
        payload: &Value,
        policy: &TrustPolicy,
    ) -> CliResult<()> {
        if index != 0 {
            return Err(CliError::RuleFired(format!(
                "the genesis manifest is anchored at entry index {index}; nothing can be \
                 governed before the corpus trust anchor, so it can only be at index 0"
            )));
        }
        if payload.get("predecessor").is_some() {
            return Err(CliError::RuleFired(
                "the genesis manifest must carry no predecessor reference".to_owned(),
            ));
        }
        let anchor = entry_id(envelope);
        if anchor != policy.genesis_entry_id {
            return Err(CliError::RuleFired(format!(
                "the anchored genesis manifest digests to {anchor}, local policy configures {}",
                policy.genesis_entry_id
            )));
        }
        let declared = manifest_key_ids(payload)?;
        if declared != policy.genesis_key_ids {
            return Err(CliError::RuleFired(
                "the genesis manifest's producer key fingerprints are not the configured ones"
                    .to_owned(),
            ));
        }

        // Provisionally in force so the genesis can be checked against its own snapshot.
        self.manifests.push((index, payload.clone()));
        if self.envelope_verifies_at(envelope, index).unwrap_or(false) {
            Ok(())
        } else {
            self.manifests.clear();
            Err(CliError::RuleFired(
                "the genesis manifest's own signature does not verify under the key set it \
                 declares"
                    .to_owned(),
            ))
        }
    }

    /// The manifest version whose snapshot is in force **at** `index` — the manifest with the
    /// greatest entry index smaller than `index`, falling back to genesis at index 0, which is
    /// the one statement validated under its own snapshot.
    fn snapshot_manifest(&self, index: u64) -> Option<(u64, &Value)> {
        self.manifests
            .iter()
            .rfind(|(at, _)| *at < index)
            .or_else(|| self.manifests.first())
            .map(|(at, payload)| (*at, payload))
    }

    /// The producer key set in force at `index`, as `key_id -> pubkey`.
    #[must_use]
    pub fn producer_keys_at(&self, index: u64) -> BTreeMap<String, String> {
        let mut keys = BTreeMap::new();
        let Some((snapshot_index, manifest)) = self.snapshot_manifest(index) else {
            return keys;
        };
        for (key_id, pubkey) in manifest_key_pairs(manifest) {
            keys.insert(key_id, pubkey);
        }
        for event in self
            .events
            .iter()
            .filter(|event| event.entry_index > snapshot_index && event.entry_index <= index)
        {
            if event.added {
                keys.insert(event.key_id.clone(), event.pubkey.clone());
            } else {
                keys.remove(&event.key_id);
            }
        }
        keys
    }

    /// The manifest version active **for a checkpoint** of size `tree_size`.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when no manifest version precedes that tree size.
    pub fn active_for(&self, tree_size: u64) -> CliResult<(u64, &Value)> {
        self.manifests
            .iter()
            .rfind(|(index, _)| *index < tree_size)
            .map(|(index, payload)| (*index, payload))
            .ok_or_else(|| {
                CliError::RuleFired(format!(
                    "no manifest version is active for a checkpoint of size {tree_size}"
                ))
            })
    }

    /// The log checkpoint-signing keys declared for a checkpoint of size `tree_size`.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when the active manifest carries no usable `log.keys`.
    pub fn log_keys_for(&self, tree_size: u64) -> CliResult<BTreeMap<String, String>> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        Ok(manifest_key_pairs(log).into_iter().collect())
    }

    /// The witness keys declared for a checkpoint of size `tree_size`, across every declared
    /// witness. Each manifest version's witness key objects replace the prior set in full.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when the active manifest cannot be resolved.
    pub fn witness_keys_for(&self, tree_size: u64) -> CliResult<BTreeMap<String, String>> {
        let (_, manifest) = self.active_for(tree_size)?;
        let mut keys = BTreeMap::new();
        for witness in manifest.get("witnesses").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            for (key_id, pubkey) in manifest_key_pairs(witness) {
                keys.insert(key_id, pubkey);
            }
        }
        Ok(keys)
    }

    /// The `log_id` the manifest version active for `tree_size` declares.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when neither spelling is present.
    pub fn log_id_for(&self, tree_size: u64) -> CliResult<String> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        log.get("log_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
            CliError::RuleFired(
                "the active manifest's `log` object declares no `log_id`; core spec §7.2/§7.3 \
                 and adaptor profile §7.3 name that member and make it REQUIRED, and its value \
                 is what binds a checkpoint to the corpus's Data Tree, so there is no check to \
                 perform without it"
                    .to_owned(),
            )
        })
    }

    /// `(checkpoint_cadence, witness_grace_period)` in nanoseconds, for `tree_size`.
    ///
    /// The values are taken from the manifest version **governing that checkpoint**, never
    /// from the newest version: a later version that relaxes cadence does not retroactively
    /// make an earlier stale interval fresh (core spec §3.3, adaptor §11.3).
    ///
    /// # Errors
    ///
    /// [`CliError::Malformed`] if either duration breaks the restricted grammar of §7.3.1,
    /// [`CliError::RuleFired`] if either is absent or if cadence is not greater than zero.
    pub fn cadence_and_grace_for(&self, tree_size: u64) -> CliResult<(u64, u64)> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        let cadence = parse_time_only_duration(
            "checkpoint_cadence",
            log.get("checkpoint_cadence").and_then(Value::as_str).ok_or_else(|| {
                CliError::RuleFired(
                    "the active manifest's `log` object declares no `checkpoint_cadence`"
                        .to_owned(),
                )
            })?,
        )?;
        if cadence == 0 {
            return Err(CliError::RuleFired(
                "`checkpoint_cadence` must be greater than zero; a zero cadence states an \
                 obligation no series can satisfy"
                    .to_owned(),
            ));
        }
        let grace = parse_time_only_duration(
            "witness_grace_period",
            log.get("witness_grace_period").and_then(Value::as_str).ok_or_else(|| {
                CliError::RuleFired(
                    "the active manifest's `log` object declares no `witness_grace_period`"
                        .to_owned(),
                )
            })?,
        )?;
        Ok((cadence, grace))
    }

    /// The dataset authority key ids declared for `dataset` at `index`, if the manifest
    /// declares one.
    ///
    /// Core spec §7.2 permits authority to be omitted only for datasets with no ingestion
    /// statements in corpus scope, so `None` is a real answer and not an error here; the
    /// caller decides what an ingestion into an authority-less dataset means.
    #[must_use]
    pub fn dataset_authority(&self, index: u64, dataset: &str) -> Option<BTreeSet<String>> {
        let (_, manifest) = self.snapshot_manifest(index)?;
        let authority = manifest.get("datasets")?.get(dataset)?.get("authority")?;
        Some(
            authority
                .get("key_ids")?
                .as_array()?
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect(),
        )
    }

    /// The commitment mode declared for `dataset` at `index`.
    #[must_use]
    pub fn dataset_commitment_mode(&self, index: u64, dataset: &str) -> Option<String> {
        let (_, manifest) = self.snapshot_manifest(index)?;
        manifest.get("datasets")?.get(dataset)?.get("commitment_mode")?.as_str().map(str::to_owned)
    }

    /// Verify every signature on `envelope` against the producer key set in force at `index`.
    ///
    /// Core spec §2.1: an envelope is valid only if **every** entry in its `signatures` array
    /// resolves to an active key and verifies. An envelope carrying a non-verifying entry is
    /// invalid regardless of how many other entries verify. Authorization is the separate,
    /// later test of §2.3.3.
    ///
    /// # Errors
    ///
    /// [`CliError::Malformed`] if the envelope shape is wrong or a resolved key cannot be
    /// decoded.
    pub fn envelope_verifies_at(&self, envelope: &Value, index: u64) -> CliResult<bool> {
        let keys = self.producer_keys_at(index);
        ahl_core::verify_envelope(envelope, |key_id| keys.get(key_id).cloned())
            .map_err(|source| CliError::Malformed { what: "envelope", detail: source.to_string() })
    }

    /// Findings about members of every manifest version's `log` object that **this build never
    /// consults**.
    ///
    /// Core §7.3 makes every member REQUIRED. Members a check of this crate depends on are
    /// enforced where that check runs — `log_id` in [`Self::log_id_for`], the two durations in
    /// [`Self::cadence_and_grace_for`] — because a missing value there is a check that cannot
    /// be performed. The rest are reported: a verifier that has no rule of its own depending
    /// on a field can honestly report its absence and nothing more.
    #[must_use]
    pub fn log_object_findings(&self) -> Vec<Finding> {
        let mut findings = BTreeSet::new();
        for (index, manifest) in &self.manifests {
            let Some(log) = manifest.get("log").filter(|value| value.is_object()) else {
                continue;
            };
            let missing: Vec<&str> = ["operator", "adaptor", "cadence_epoch"]
                .into_iter()
                .filter(|member| log.get(*member).is_none())
                .collect();
            if !missing.is_empty() {
                findings.insert(Finding::new(
                    "manifest-log-object-incomplete",
                    format!(
                        "the manifest at entry index {index} omits {} from its `log` object; \
                         core spec §7.3 makes every member REQUIRED, and no rule this build \
                         evaluates depends on the missing one",
                        missing.join(", ")
                    ),
                ));
            }
        }
        findings.into_iter().collect()
    }

    /// Entry indexes of the manifest versions in the chain, ascending.
    #[must_use]
    pub fn manifest_indexes(&self) -> Vec<u64> {
        self.manifests.iter().map(|(index, _)| *index).collect()
    }
}

/// Read a `key` statement's transition, or say why it is unusable.
fn read_key_event(index: u64, payload: &Value) -> Result<KeyEvent, String> {
    let key = payload
        .get("key")
        .filter(|value| value.is_object())
        .ok_or_else(|| "it carries no `key` object".to_owned())?;
    let added = match payload.get("action").and_then(Value::as_str) {
        Some("add") => true,
        Some("retire") => false,
        other => return Err(format!("unknown key action `{}`", other.unwrap_or("<absent>"))),
    };
    Ok(KeyEvent {
        entry_index: index,
        key_id: string_member(key, "key_id").map_err(|error| error.to_string())?,
        pubkey: string_member(key, "pubkey").map_err(|error| error.to_string())?,
        added,
    })
}

fn string_member(value: &Value, member: &str) -> CliResult<String> {
    value.get(member).and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
        CliError::RuleFired(format!("governance object carries no string `{member}`"))
    })
}

fn manifest_key_pairs(container: &Value) -> Vec<(String, String)> {
    container
        .get("keys")
        .and_then(Value::as_array)
        .map(|objects| {
            objects
                .iter()
                .filter_map(|object| {
                    Some((
                        object.get("key_id")?.as_str()?.to_owned(),
                        object.get("pubkey")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn manifest_key_ids(manifest: &Value) -> CliResult<BTreeSet<String>> {
    let keys = manifest.get("keys").and_then(Value::as_array).ok_or_else(|| {
        CliError::RuleFired("the genesis manifest carries no producer `keys` array".to_owned())
    })?;
    keys.iter()
        .map(|object| {
            object.get("key_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
                CliError::RuleFired("a producer key object carries no `key_id`".to_owned())
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ahl_core::TestKey;
    use serde_json::json;

    use super::*;

    fn producer(seed: u8) -> TestKey {
        TestKey::from_seed_hex("producer", &format!("{seed:02x}").repeat(32)).expect("seed")
    }

    fn genesis(log_id_member: &str) -> Value {
        let key = producer(1);
        let log_key = producer(3);
        ahl_core::envelope(
            json!({
                "type": "manifest",
                "producer": "producer-1",
                "keys": [ key.key_object(0) ],
                "datasets": {
                    "customers": {
                        "commitment_mode": "keyed",
                        "authority": { "producer": "producer-1", "key_ids": [key.key_id()] },
                    },
                },
                "log": {
                    log_id_member: "sha256:aa",
                    "operator": "op",
                    "adaptor": { "id": "ahl-test-log-v1", "hash": "sha256:bb" },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    "keys": [ log_key.key_object(0) ],
                },
                "witnesses": [ { "witness_id": "w1", "keys": [ producer(4).key_object(0) ] } ],
            }),
            &key,
        )
    }

    fn chain(log_id_member: &str) -> Vec<(u64, Value)> {
        vec![(0, genesis(log_id_member))]
    }

    #[test]
    fn a_missing_required_log_member_is_reported_not_adjudicated() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ key.key_object(0) ],
                "log": { "id": "sha256:aa", "checkpoint_cadence": "PT1H",
                         "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        let governance = Governance::structural_only(&[(0, envelope)]).expect("chain");
        let findings = governance.log_object_findings();
        assert!(findings.iter().any(|f| f.code == "manifest-log-object-incomplete"));
        assert!(findings.iter().any(|f| f.detail.contains("cadence_epoch")));
    }

    #[test]
    fn a_non_genesis_manifest_must_link_to_the_version_active_immediately_before_it() {
        let key = producer(1);
        let first = genesis("log_id");
        let good = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ key.key_object(0) ],
                "log": { "log_id": "sha256:aa", "checkpoint_cadence": "PT1H",
                         "cadence_epoch": "2026-01-01T00:00:00Z", "operator": "op",
                         "adaptor": {}, "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        assert!(Governance::structural_only(&[(0, first.clone()), (5, good)]).is_ok());

        let wrong = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": format!("sha256:{}", "77".repeat(32)),
                "keys": [ key.key_object(0) ],
                "log": {},
            }),
            &key,
        );
        let error =
            Governance::structural_only(&[(0, first), (5, wrong)]).expect_err("wrong predecessor");
        assert!(error.to_string().contains("active immediately before"), "{error}");
    }

    #[test]
    fn a_genesis_manifest_carrying_a_predecessor_is_refused() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({ "type": "manifest", "predecessor": "sha256:aa", "keys": [], "log": {} }),
            &key,
        );
        let error = Governance::structural_only(&[(0, envelope)]).expect_err("genesis predecessor");
        assert!(error.to_string().contains("no predecessor"), "{error}");
    }

    #[test]
    fn a_non_genesis_manifest_without_a_predecessor_is_refused() {
        let key = producer(1);
        let second = ahl_core::envelope(json!({ "type": "manifest", "keys": [], "log": {} }), &key);
        let error = Governance::structural_only(&[(0, genesis("log_id")), (5, second)])
            .expect_err("no predecessor");
        assert!(error.to_string().contains("must reference its predecessor"), "{error}");
    }

    #[test]
    fn a_manifest_keys_array_is_a_snapshot_that_discards_the_prior_one() {
        let first_key = producer(1);
        let second_key = producer(2);
        let first = genesis("log_id");
        let rotation = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ second_key.key_object(5) ],
                "log": { "log_id": "sha256:aa", "keys": [] },
            }),
            &first_key,
        );
        let entries = vec![(0, first), (5, rotation)];
        let governance = Governance::structural_only(&entries).expect("chain");

        // Before the rotation the first key is in force; after it, only the second.
        assert!(governance.producer_keys_at(3).contains_key(&first_key.key_id()));
        let after = governance.producer_keys_at(6);
        assert!(after.contains_key(&second_key.key_id()));
        assert!(
            !after.contains_key(&first_key.key_id()),
            "a key a later manifest omits is gone, not merged"
        );
    }

    #[test]
    fn key_statements_modify_the_snapshot_in_entry_order() {
        let first_key = producer(1);
        let added = producer(2);
        let first = genesis("log_id");
        let add = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": added.key_object(3) }),
            &first_key,
        );
        let retire = ahl_core::envelope(
            json!({ "type": "key", "action": "retire", "key": added.key_object(3) }),
            &first_key,
        );
        let entries = vec![(0, first), (3, add), (7, retire)];
        let governance = Governance::structural_only(&entries).expect("chain");

        assert!(!governance.producer_keys_at(2).contains_key(&added.key_id()));
        assert!(governance.producer_keys_at(4).contains_key(&added.key_id()));
        assert!(!governance.producer_keys_at(8).contains_key(&added.key_id()));
    }

    #[test]
    fn an_unknown_key_action_is_refused() {
        let key = producer(1);
        let bad = ahl_core::envelope(
            json!({ "type": "key", "action": "borrow", "key": key.key_object(1) }),
            &key,
        );
        assert!(Governance::structural_only(&[(0, genesis("log_id")), (1, bad)]).is_err());
    }

    #[test]
    fn the_manifest_governing_a_checkpoint_is_selected_by_tree_size() {
        let key = producer(1);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ key.key_object(0) ],
                "log": { "log_id": "sha256:cc", "checkpoint_cadence": "PT2H",
                         "witness_grace_period": "PT1M", "keys": [] },
            }),
            &key,
        );
        let entries = vec![(0, first), (5, second)];
        let governance = Governance::structural_only(&entries).expect("chain");

        // tree_size 5 commits [0, 5), so index 5 is NOT yet committed and genesis governs.
        assert_eq!(governance.log_id_for(5).expect("log id"), "sha256:aa");
        assert_eq!(governance.log_id_for(6).expect("log id"), "sha256:cc");
        assert_eq!(governance.cadence_and_grace_for(6).expect("durations").0, 7_200_000_000_000);
        assert!(governance.active_for(0).is_err());
    }

    #[test]
    fn a_prohibited_duration_component_is_rejected_rather_than_approximated() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ key.key_object(0) ],
                "log": { "log_id": "sha256:aa", "checkpoint_cadence": "P1Y",
                         "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        let governance = Governance::structural_only(&[(0, envelope)]).expect("chain");
        let error = governance.cadence_and_grace_for(1).expect_err("prohibited component");
        assert!(error.to_string().contains("prohibited"), "{error}");
    }

    #[test]
    fn a_zero_cadence_is_refused() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ key.key_object(0) ],
                "log": { "log_id": "sha256:aa", "checkpoint_cadence": "PT0S",
                         "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        let governance = Governance::structural_only(&[(0, envelope)]).expect("chain");
        assert!(governance.cadence_and_grace_for(1).is_err());
    }

    #[test]
    fn log_and_witness_keys_come_from_the_active_manifest_version() {
        let entries = chain("log_id");
        let governance = Governance::structural_only(&entries).expect("chain");
        assert!(governance.log_keys_for(1).expect("log keys").contains_key(&producer(3).key_id()));
        assert!(governance
            .witness_keys_for(1)
            .expect("witness keys")
            .contains_key(&producer(4).key_id()));
    }

    #[test]
    fn dataset_authority_and_commitment_mode_are_read_from_the_snapshot() {
        let entries = chain("log_id");
        let governance = Governance::structural_only(&entries).expect("chain");
        let authority = governance.dataset_authority(1, "customers").expect("declared");
        assert!(authority.contains(&producer(1).key_id()));
        assert_eq!(governance.dataset_commitment_mode(1, "customers").as_deref(), Some("keyed"));
        assert!(governance.dataset_authority(1, "absent").is_none());
    }

    #[test]
    fn envelope_signatures_are_verified_against_the_key_set_at_their_index() {
        let key = producer(1);
        let stranger = producer(9);
        let entries = chain("log_id");
        let governance = Governance::structural_only(&entries).expect("chain");

        let good = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(governance.envelope_verifies_at(&good, 1).expect("well-formed"));
        let bad = ahl_core::envelope(json!({ "type": "ingestion" }), &stranger);
        assert!(!governance.envelope_verifies_at(&bad, 1).expect("well-formed"));
    }

    #[test]
    fn entries_must_ascend_and_a_corpus_must_carry_a_manifest() {
        let entries = vec![(5, genesis("log_id")), (1, genesis("log_id"))];
        assert!(Governance::structural_only(&entries).is_err());

        let key = producer(1);
        let ingestion = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(Governance::structural_only(&[(0, ingestion)]).is_err());
    }

    #[test]
    fn a_typeless_or_payloadless_entry_is_refused() {
        assert!(Governance::structural_only(&[(0, json!({ "signatures": [] }))]).is_err());
        assert!(Governance::structural_only(&[(0, json!({ "payload": { "a": 1 } }))]).is_err());
    }

    // -- adaptor §7.4.1: governance is not self-authorizing ---------------------------

    fn policy_for(entries: &[(u64, Value)], key: &TestKey) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: BTreeSet::from([key.key_id()]),
            ..TrustPolicy::default()
        }
    }

    /// A manifest a hostile party anchored: well-formed, at a real index, signed by a key the
    /// corpus never adopted, naming attacker log keys.
    fn forged_manifest(predecessor: &Value, attacker: &TestKey, log_key: &TestKey) -> Value {
        ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(predecessor),
                "keys": [ attacker.key_object(0) ],
                "log": {
                    "log_id": "sha256:aa",
                    "operator": "op",
                    "adaptor": { "id": "ahl-test-log-v1", "hash": "sha256:bb" },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    "keys": [ log_key.key_object(0) ],
                },
            }),
            attacker,
        )
    }

    #[test]
    fn a_forged_later_manifest_never_contributes_to_the_resolved_key_set() {
        // The blocker this module was rewritten for. A hostile mirror serves a recomputable
        // tree containing the genuine pinned genesis manifest PLUS a forged later manifest
        // naming attacker log keys. If the chain were collected first and checked afterwards,
        // a checkpoint signed by those keys would authenticate.
        let honest = producer(1);
        let attacker = producer(9);
        let attacker_log_key = producer(8);
        let first = genesis("log_id");
        let forged = forged_manifest(&first, &attacker, &attacker_log_key);
        let entries = vec![(0, first), (5, forged)];

        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");

        assert_eq!(
            resolved.manifest_indexes(),
            vec![0],
            "the forged manifest must not join the chain"
        );
        assert!(findings.iter().any(|f| f.code == "governance-statement-not-authorized"));
        // And the attacker's log key is not resolvable for any checkpoint.
        let log_keys = resolved.log_keys_for(9).expect("genesis governs");
        assert!(!log_keys.contains_key(&attacker_log_key.key_id()));
        assert!(log_keys.contains_key(&producer(3).key_id()), "the genuine log key still is");
    }

    #[test]
    fn a_forged_key_statement_never_adds_a_producer_key() {
        let honest = producer(1);
        let attacker = producer(9);
        let first = genesis("log_id");
        let forged = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": attacker.key_object(3) }),
            &attacker,
        );
        let entries = vec![(0, first), (3, forged)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert!(!resolved.producer_keys_at(4).contains_key(&attacker.key_id()));
        assert!(findings.iter().any(|f| f.code == "governance-statement-not-authorized"));
    }

    #[test]
    fn a_key_statement_before_any_manifest_is_not_governance() {
        let honest = producer(1);
        let attacker = producer(9);
        let early = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": attacker.key_object(0) }),
            &attacker,
        );
        let first = genesis("log_id");
        let entries = vec![(0, early), (1, first.clone())];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&first),
            genesis_key_ids: BTreeSet::from([honest.key_id()]),
            ..TrustPolicy::default()
        };
        // The genesis is not at index 0 here, so there is no usable anchor at all.
        assert!(Governance::resolve(&entries, &policy).is_err());
    }

    #[test]
    fn a_genuine_rotation_signed_by_the_key_set_before_it_is_accepted() {
        // The other direction: the incremental rule must not reject an honest chain.
        let honest = producer(1);
        let rotated = producer(2);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ rotated.key_object(5) ],
                "log": {
                    "log_id": "sha256:cc",
                    "operator": "op",
                    "adaptor": { "id": "ahl-test-log-v1", "hash": "sha256:bb" },
                    "checkpoint_cadence": "PT2H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    "keys": [ producer(3).key_object(0) ],
                },
            }),
            &honest,
        );
        let entries = vec![(0, first), (5, second)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0, 5]);
        assert!(findings.iter().all(|f| f.code != "governance-statement-not-authorized"));
        assert_eq!(resolved.log_id_for(6).expect("log id"), "sha256:cc");
        // And after the rotation the old producer key is gone.
        assert!(!resolved.producer_keys_at(6).contains_key(&honest.key_id()));
    }

    #[test]
    fn a_manifest_linking_past_the_active_version_is_ignored_for_key_resolution() {
        let honest = producer(1);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ honest.key_object(0) ],
                "log": { "log_id": "sha256:cc", "keys": [] },
            }),
            &honest,
        );
        // Links to genesis rather than to the version active immediately before it.
        let third = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ honest.key_object(0) ],
                "log": { "log_id": "sha256:dd", "keys": [] },
            }),
            &honest,
        );
        let entries = vec![(0, first), (5, second), (9, third)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0, 5]);
        assert!(findings.iter().any(|f| f.detail.contains("active immediately before")));
    }

    #[test]
    fn a_genesis_that_is_not_the_configured_anchor_is_fatal_not_a_finding() {
        let honest = producer(1);
        let entries = vec![(0, genesis("log_id"))];
        let mut policy = policy_for(&entries, &honest);
        policy.genesis_entry_id = format!("sha256:{}", "99".repeat(32));
        let error = Governance::resolve(&entries, &policy).expect_err("no trust anchor");
        assert!(error.to_string().contains("local policy configures"), "{error}");

        let mut policy = policy_for(&entries, &honest);
        policy.genesis_key_ids = BTreeSet::from([format!("sha256:{}", "88".repeat(32))]);
        assert!(Governance::resolve(&entries, &policy).is_err());
    }

    #[test]
    fn a_genesis_whose_own_signature_does_not_verify_is_fatal() {
        let honest = producer(1);
        let stranger = producer(9);
        // Declares the honest key set but is signed by someone else.
        let forged = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.key_object(0) ],
                "log": { "log_id": "sha256:aa", "keys": [] },
            }),
            &stranger,
        );
        let entries = vec![(0, forged)];
        let policy = policy_for(&entries, &honest);
        let error = Governance::resolve(&entries, &policy).expect_err("self-signature");
        assert!(error.to_string().contains("own signature"), "{error}");
    }

    #[test]
    fn the_resolved_chain_is_never_the_structural_one() {
        // A regression guard for the inversion itself: the structural walk accepts the forged
        // manifest (it checks no signatures, by design and by name), the resolved one does not.
        let honest = producer(1);
        let attacker = producer(9);
        let first = genesis("log_id");
        let forged = forged_manifest(&first, &attacker, &producer(8));
        let entries = vec![(0, first), (5, forged)];

        let structural = Governance::structural_only(&entries).expect("structurally fine");
        assert_eq!(structural.manifest_indexes(), vec![0, 5]);

        let (resolved, _) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0]);
        assert_ne!(structural.manifest_indexes(), resolved.manifest_indexes());
    }

    #[test]
    fn a_log_object_without_the_specification_spelling_has_no_check_to_perform() {
        let entries = vec![(0, genesis("id"))];
        let governance = Governance::structural_only(&entries).expect("structurally fine");
        let error = governance.log_id_for(1).expect_err("no log_id");
        assert!(error.to_string().contains("REQUIRED"), "{error}");
        assert!(error.to_string().contains("no check to perform"), "{error}");

        // The specification spelling resolves.
        let entries = vec![(0, genesis("log_id"))];
        let governance = Governance::structural_only(&entries).expect("structurally fine");
        assert_eq!(governance.log_id_for(1).expect("log id"), "sha256:aa");
    }
}
