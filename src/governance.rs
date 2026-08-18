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
//! # A recorded disagreement between the frozen sources and their implementations
//!
//! Core spec §7.2/§7.3 and adaptor profile §7.3 name the manifest log-object member
//! **`log_id`**, and `ahl-mirror` and `ahl-witness` both read that spelling. `ahl-core` reads
//! **`log.id`**, and every manifest in the `ahl-core` conformance corpus carries `id`. Both
//! spellings are therefore accepted here, `log_id` first; where only `id` is present a
//! [`Finding`](crate::report::Finding) with code `manifest-log-id-legacy-spelling` is raised so
//! the disagreement is reported rather than smoothed over. The same applies to the members
//! core §7.3 makes REQUIRED that the corpus omits — see [`Governance::log_object_findings`].

use std::collections::{BTreeMap, BTreeSet};

use ahl_core::receipt::TrustPolicy;
use ahl_core::entry_id;
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
    /// Collect and structurally validate the governance statements among `entries`.
    ///
    /// `entries` is `(entry_index, envelope)` in ascending index order; it may be a full
    /// enumeration or a receipt's governance chain. Every statement that is neither a
    /// `manifest` nor a `key` is skipped, because a full enumeration legitimately contains
    /// them.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] naming the chain rule that failed.
    pub fn from_entries(entries: &[(u64, Value)]) -> CliResult<Self> {
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
                                "a non-genesis manifest must reference its predecessor"
                                    .to_owned(),
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
                "key" => {
                    let key = payload.get("key").filter(|k| k.is_object()).ok_or_else(|| {
                        CliError::RuleFired(format!(
                            "`key` statement at entry index {index} carries no `key` object"
                        ))
                    })?;
                    let added = match payload.get("action").and_then(Value::as_str) {
                        Some("add") => true,
                        Some("retire") => false,
                        other => {
                            return Err(CliError::RuleFired(format!(
                                "unknown key action `{}` at entry index {index}",
                                other.unwrap_or("<absent>")
                            )))
                        }
                    };
                    events.push(KeyEvent {
                        entry_index: *index,
                        key_id: string_member(key, "key_id")?,
                        pubkey: string_member(key, "pubkey")?,
                        added,
                    });
                }
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

    /// Compare the genesis anchor against **locally configured policy**.
    ///
    /// A receipt or a log carries a genesis anchor so it is self-describing; policy decides
    /// whether that anchor is the right one. Nothing here is ever defaulted from the artifact.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] if the genesis manifest is not at index 0, its entry id is not
    /// the configured anchor, or its key fingerprints are not the configured ones.
    pub fn check_genesis(&self, entries: &[(u64, Value)], policy: &TrustPolicy) -> CliResult<()> {
        let (index, _) = self.manifests.first().ok_or_else(|| {
            CliError::RuleFired("no genesis manifest is anchored".to_owned())
        })?;
        if *index != 0 {
            return Err(CliError::RuleFired(format!(
                "the genesis manifest must be anchored at entry index 0, found it at {index}"
            )));
        }
        let genesis_envelope = entries
            .iter()
            .find(|(at, _)| *at == 0)
            .map(|(_, envelope)| envelope)
            .ok_or_else(|| {
                CliError::RuleFired("entry index 0 is not present in the material".to_owned())
            })?;
        let anchor = entry_id(genesis_envelope);
        if anchor != policy.genesis_entry_id {
            return Err(CliError::RuleFired(format!(
                "the anchored genesis manifest digests to {anchor}, local policy configures {}",
                policy.genesis_entry_id
            )));
        }
        let declared: BTreeSet<String> = self
            .manifests
            .first()
            .map(|(_, payload)| manifest_key_ids(payload))
            .transpose()?
            .unwrap_or_default();
        if declared != policy.genesis_key_ids {
            return Err(CliError::RuleFired(
                "the genesis manifest's producer key fingerprints are not the configured ones"
                    .to_owned(),
            ));
        }
        Ok(())
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
        log.get("log_id")
            .or_else(|| log.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                CliError::RuleFired(
                    "the active manifest's `log` object names no log id".to_owned(),
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
        manifest
            .get("datasets")?
            .get(dataset)?
            .get("commitment_mode")?
            .as_str()
            .map(str::to_owned)
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
        ahl_core::verify_envelope(envelope, |key_id| keys.get(key_id).cloned()).map_err(|source| {
            CliError::Malformed { what: "envelope", detail: source.to_string() }
        })
    }

    /// Findings about every manifest version's `log` object, reported rather than adjudicated.
    ///
    /// Core spec §7.3 makes every member of the `log` object REQUIRED and names it `log_id`,
    /// while the `ahl-core` conformance corpus spells it `id` and omits `cadence_epoch`.
    /// Rejecting those manifests would reject the frozen corpus; accepting them silently would
    /// hide a live disagreement between the specification and its reference vectors. They are
    /// therefore reported as findings, which never change an outcome.
    #[must_use]
    pub fn log_object_findings(&self) -> Vec<Finding> {
        let mut findings = BTreeSet::new();
        for (index, manifest) in &self.manifests {
            let Some(log) = manifest.get("log").filter(|value| value.is_object()) else {
                continue;
            };
            if log.get("log_id").is_none() && log.get("id").is_some() {
                findings.insert(Finding::new(
                    "manifest-log-id-legacy-spelling",
                    format!(
                        "the manifest at entry index {index} names the log `log.id`; core spec \
                         §7.2/§7.3 and adaptor profile §7.3 name it `log.log_id`"
                    ),
                ));
            }
            let missing: Vec<&str> = ["operator", "adaptor", "checkpoint_cadence", "cadence_epoch",
                "witness_grace_period", "keys"]
                .into_iter()
                .filter(|member| log.get(*member).is_none())
                .collect();
            if !missing.is_empty() {
                findings.insert(Finding::new(
                    "manifest-log-object-incomplete",
                    format!(
                        "the manifest at entry index {index} omits {} from its `log` object; \
                         core spec §7.3 makes every member REQUIRED",
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

    fn policy_for(entries: &[(u64, Value)]) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: BTreeSet::from([producer(1).key_id()]),
            ..TrustPolicy::default()
        }
    }

    #[test]
    fn a_genesis_only_chain_resolves_and_matches_configured_policy() {
        let entries = chain("log_id");
        let governance = Governance::from_entries(&entries).expect("chain resolves");
        governance.check_genesis(&entries, &policy_for(&entries)).expect("anchor matches");
        assert_eq!(governance.manifest_indexes(), vec![0]);
        assert_eq!(governance.log_id_for(1).expect("log id"), "sha256:aa");
        assert_eq!(
            governance.cadence_and_grace_for(1).expect("durations"),
            (3_600_000_000_000, 900_000_000_000)
        );
    }

    #[test]
    fn a_mismatched_genesis_anchor_is_never_defaulted_from_the_artifact() {
        let entries = chain("log_id");
        let governance = Governance::from_entries(&entries).expect("chain resolves");
        let mut policy = policy_for(&entries);
        policy.genesis_entry_id = format!("sha256:{}", "99".repeat(32));
        let error = governance.check_genesis(&entries, &policy).expect_err("anchor mismatch");
        assert!(error.to_string().contains("local policy configures"), "{error}");

        let mut policy = policy_for(&entries);
        policy.genesis_key_ids = BTreeSet::from([format!("sha256:{}", "88".repeat(32))]);
        assert!(governance.check_genesis(&entries, &policy).is_err());
    }

    #[test]
    fn the_legacy_log_id_spelling_is_accepted_and_reported_as_a_finding() {
        let entries = chain("id");
        let governance = Governance::from_entries(&entries).expect("chain resolves");
        assert_eq!(governance.log_id_for(1).expect("log id"), "sha256:aa");
        let findings = governance.log_object_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "manifest-log-id-legacy-spelling");

        assert!(Governance::from_entries(&chain("log_id"))
            .expect("chain")
            .log_object_findings()
            .is_empty());
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
        let governance = Governance::from_entries(&[(0, envelope)]).expect("chain");
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
        assert!(Governance::from_entries(&[(0, first.clone()), (5, good)]).is_ok());

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
            Governance::from_entries(&[(0, first), (5, wrong)]).expect_err("wrong predecessor");
        assert!(error.to_string().contains("active immediately before"), "{error}");
    }

    #[test]
    fn a_genesis_manifest_carrying_a_predecessor_is_refused() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({ "type": "manifest", "predecessor": "sha256:aa", "keys": [], "log": {} }),
            &key,
        );
        let error = Governance::from_entries(&[(0, envelope)]).expect_err("genesis predecessor");
        assert!(error.to_string().contains("no predecessor"), "{error}");
    }

    #[test]
    fn a_non_genesis_manifest_without_a_predecessor_is_refused() {
        let key = producer(1);
        let second =
            ahl_core::envelope(json!({ "type": "manifest", "keys": [], "log": {} }), &key);
        let error = Governance::from_entries(&[(0, genesis("log_id")), (5, second)])
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
        let governance = Governance::from_entries(&entries).expect("chain");

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
        let governance = Governance::from_entries(&entries).expect("chain");

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
        assert!(Governance::from_entries(&[(0, genesis("log_id")), (1, bad)]).is_err());
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
        let governance = Governance::from_entries(&entries).expect("chain");

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
        let governance = Governance::from_entries(&[(0, envelope)]).expect("chain");
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
        let governance = Governance::from_entries(&[(0, envelope)]).expect("chain");
        assert!(governance.cadence_and_grace_for(1).is_err());
    }

    #[test]
    fn log_and_witness_keys_come_from_the_active_manifest_version() {
        let entries = chain("log_id");
        let governance = Governance::from_entries(&entries).expect("chain");
        assert!(governance.log_keys_for(1).expect("log keys").contains_key(&producer(3).key_id()));
        assert!(governance
            .witness_keys_for(1)
            .expect("witness keys")
            .contains_key(&producer(4).key_id()));
    }

    #[test]
    fn dataset_authority_and_commitment_mode_are_read_from_the_snapshot() {
        let entries = chain("log_id");
        let governance = Governance::from_entries(&entries).expect("chain");
        let authority = governance.dataset_authority(1, "customers").expect("declared");
        assert!(authority.contains(&producer(1).key_id()));
        assert_eq!(
            governance.dataset_commitment_mode(1, "customers").as_deref(),
            Some("keyed")
        );
        assert!(governance.dataset_authority(1, "absent").is_none());
    }

    #[test]
    fn envelope_signatures_are_verified_against_the_key_set_at_their_index() {
        let key = producer(1);
        let stranger = producer(9);
        let entries = chain("log_id");
        let governance = Governance::from_entries(&entries).expect("chain");

        let good = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(governance.envelope_verifies_at(&good, 1).expect("well-formed"));
        let bad = ahl_core::envelope(json!({ "type": "ingestion" }), &stranger);
        assert!(!governance.envelope_verifies_at(&bad, 1).expect("well-formed"));
    }

    #[test]
    fn entries_must_ascend_and_a_corpus_must_carry_a_manifest() {
        let entries = vec![(5, genesis("log_id")), (1, genesis("log_id"))];
        assert!(Governance::from_entries(&entries).is_err());

        let key = producer(1);
        let ingestion = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(Governance::from_entries(&[(0, ingestion)]).is_err());
    }

    #[test]
    fn a_typeless_or_payloadless_entry_is_refused() {
        assert!(Governance::from_entries(&[(0, json!({ "signatures": [] }))]).is_err());
        assert!(Governance::from_entries(&[(0, json!({ "payload": { "a": 1 } }))]).is_err());
    }
}
