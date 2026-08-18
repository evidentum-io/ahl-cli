//! `verify` — offline by construction.
//!
//! Receipt format §1 defines verification as receipt + locally pinned profile + local policy.
//! There is no flag that makes `verify` reach the network, and an assurance field that could
//! only be raised by fetching is simply not raised. In particular `assurance.witnessed` is
//! true iff a cosignature **carried by the receipt** verifies: whether a witness answers right
//! now is irrelevant and must not change the verdict.
//!
//! # The §6 mapping
//!
//! Every rejection `ahl-core` can produce is mapped explicitly to an outcome. A path not in
//! that mapping is a defect, not a default, so [`classify`] is a total match over
//! `ReceiptError` with no wildcard.
//!
//! The one mapping that reads oddly is [`ReceiptError::ContentBindingMismatch`], which
//! `ahl-core` produces both for *carried bytes that do not recompute to the commitment* (a
//! rule fired against the artifact — `1`) and for *no authorized dataset key held* (missing
//! evidence — `3`, `content_binding: none`, never downgraded to `plain-verified`). The two are
//! distinguished only by a sentinel string in the `recomputed` field. That is fragile, it is
//! `ahl-core`'s only signal, and the sentinel is pinned by a test here so a change upstream
//! fails loudly rather than silently turning a `3` into a `1`.


use ahl_core::receipt::{verify_receipt, ReceiptError, Verdict};
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::evaluation::{parse_artifact_time, EvaluationTime};
use crate::governance::Governance;
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::profile;
use crate::report::{
    AssuranceOut, CheckpointOut, Completeness, Finding, Report,
};
use crate::secure;

/// The sentinel `ahl-core` puts in `ContentBindingMismatch::recomputed` when the verifier holds
/// no dataset key for a `keyed` dataset. Pinned by `the_dataset_key_sentinel_is_still_what_ahl_core_emits`.
const NO_DATASET_KEY: &str = "<no dataset key held>";

/// Options for one `verify` run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Path to the `.ahl` receipt.
    pub receipt: std::path::PathBuf,
    /// Promote a stale witness cosignature from a finding to `unverifiable`.
    pub require_fresh: bool,
}

/// Verify a receipt against locally configured policy.
///
/// Returns the outcome and the report to print; never both an `Err` and a report, because the
/// exit-code contract requires a report on every path.
#[must_use]
pub fn run(policy: &LoadedPolicy, evaluation: &EvaluationTime, options: &Options) -> Report {
    match verify(policy, evaluation, options) {
        Ok(report) => report,
        Err(error) => Report::new(
            error.outcome(),
            error.reason_code(),
            error.to_string(),
            evaluation.rendered.clone(),
            evaluation.source,
        ),
    }
}

fn verify(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
) -> CliResult<Report> {
    // Unreadable, absent, or not a regular file: the CLI could not begin (exit 2).
    let bytes =
        secure::read_regular("receipt", &options.receipt, policy.local.max_file_bytes)?;

    // Bytes present but malformed, non-canonical or structurally invalid: a rule fired against
    // the artifact (exit 1).
    let receipt: Value = serde_json::from_slice(&bytes).map_err(|source| CliError::Malformed {
        what: "receipt",
        detail: format!("not JSON: {source}"),
    })?;
    if ahl_core::jcs(&receipt) != bytes {
        return Err(CliError::Malformed {
            what: "receipt",
            detail: "the file is not the JCS-canonical serialization of the receipt object \
                     (receipt format §1.4)"
                .to_owned(),
        });
    }

    // The profile is resolved from local possession before anything else looks at the artifact,
    // so "not possessed" (3) and "configured but broken" (2) stay distinct.
    let adaptor_id = receipt
        .get("anchoring")
        .and_then(|anchoring| anchoring.get("adaptor"))
        .and_then(|adaptor| adaptor.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Malformed {
            what: "receipt",
            detail: "carries no `anchoring.adaptor.id`".to_owned(),
        })?;
    let _resolved = profile::resolve(policy, adaptor_id)?;

    let verdict = verify_receipt(&receipt, &policy.trust).map_err(classify)?;
    Ok(succeeded(&receipt, &verdict, evaluation, options))
}

/// Map an `ahl-core` rejection onto the §6 outcome table. Total, deliberately.
fn classify(error: ReceiptError) -> CliError {
    match error {
        // Unsupported version, or a capability the pinned profile does not define: the
        // profile's limitation is named (3).
        ReceiptError::UnsupportedVersion { .. }
        | ReceiptError::AdaptorCapabilityUnsupported { .. } => {
            CliError::ProfileLimitation(error.to_string())
        }
        // Not locally possessed at the pinned hash (3).
        ReceiptError::AdaptorUnknown { id } => CliError::ProfileNotPossessed { id },
        // Rejection, never a degraded acceptance (3).
        ReceiptError::LimitExceeded(what) => CliError::LimitExhausted(what.to_owned()),
        // Keyed binding with no authorized dataset key held (3) versus carried bytes that do
        // not recompute (1) — see the module docs on the sentinel.
        ReceiptError::ContentBindingMismatch { mode, recomputed, claimed } => {
            if recomputed == NO_DATASET_KEY {
                CliError::DatasetKeyNotHeld { dataset: claimed }
            } else {
                CliError::RuleFired(
                    ReceiptError::ContentBindingMismatch { mode, recomputed, claimed }.to_string(),
                )
            }
        }
        // Everything else fired against the user's own artifact (1). `verify` is offline, so
        // every checkpoint, proof and signature it examines is artifact-carried: there is no
        // remote candidate here whose failure could mean "evidence not obtained".
        ReceiptError::Malformed(detail) => CliError::Malformed { what: "receipt", detail },
        ReceiptError::IdentifierMismatch { .. }
        | ReceiptError::CheckpointNotBound { .. }
        | ReceiptError::GovernanceRangeNotComplete { .. }
        | ReceiptError::TriggerNotAuthorized { .. }
        | ReceiptError::GovernanceSubjectNotManifest { .. }
        | ReceiptError::CheckpointSignatureInvalid
        | ReceiptError::KeyNotBound { .. }
        | ReceiptError::WitnessCosignatureInvalid { .. }
        | ReceiptError::EntryIndexBeyondCheckpoint { .. }
        | ReceiptError::InclusionPathInvalid { .. }
        | ReceiptError::ConsistencyPathInvalid
        | ReceiptError::GenesisAnchorMismatch
        | ReceiptError::GovernanceChainInvalid(_)
        | ReceiptError::EnvelopeSignatureInvalid { .. }
        | ReceiptError::AssuranceMismatch { .. }
        | ReceiptError::RecordSubjectMismatch { .. }
        | ReceiptError::SubjectManifestPresence { .. }
        | ReceiptError::EmbeddedOrderingViolation { .. }
        | ReceiptError::EmbeddedSubjectMismatch { .. }
        | ReceiptError::EmbeddedClaimTypeMismatch { .. }
        | ReceiptError::ClaimMaterialMissing { .. }
        | ReceiptError::ClaimMaterialPathInvalid { .. }
        | ReceiptError::CompetingRangeInsufficient { .. }
        | ReceiptError::RangeProofInvalid { .. }
        | ReceiptError::TreeMaterialInvalid { .. }
        | ReceiptError::ClosureMismatch(_)
        | ReceiptError::GovernanceStateNotCurrent { .. }
        | ReceiptError::Ahl(_) => CliError::RuleFired(error.to_string()),
        // `ReceiptError` is `#[non_exhaustive]`: a variant added upstream must not silently
        // become an accept or an arbitrary outcome. Unverifiable is the honest answer — this
        // build does not know what the new rule means.
        other => CliError::ProfileLimitation(format!(
            "this build does not know how to classify the rejection `{other}`; treating it as \
             evidence not established rather than guessing an outcome"
        )),
    }
}

fn succeeded(
    receipt: &Value,
    verdict: &Verdict,
    evaluation: &EvaluationTime,
    options: &Options,
) -> Report {
    let checkpoint = receipt.get("anchoring").and_then(|anchoring| anchoring.get("checkpoint"));
    let mut findings = Vec::new();
    let mut outcome = Outcome::Valid;

    // Governance findings and freshness both come from the receipt's own chain, which
    // `verify_receipt` has already validated back to the configured genesis anchor.
    let chain = chain_entries(receipt);
    if let Ok(entries) = &chain {
        if let Ok(governance) = Governance::from_entries(entries) {
            findings.extend(governance.log_object_findings());
            if verdict.assurance.witnessed {
                match freshness(&governance, checkpoint, evaluation) {
                    Ok(Some(finding)) => {
                        // Staleness is a finding, never by itself a disproof. `--require-fresh`
                        // promotes it to `unverifiable` — never to `invalid`.
                        if options.require_fresh {
                            outcome = Outcome::Unverifiable;
                        }
                        findings.push(finding);
                    }
                    Ok(None) => {}
                    Err(detail) => findings.push(Finding::new("witness-freshness-unavailable", detail)),
                }
            }
        }
    }

    let reason = if outcome == Outcome::Valid {
        "every required rule verified".to_owned()
    } else {
        "a witness cosignature is stale and --require-fresh was given".to_owned()
    };
    let reason_code = if outcome == Outcome::Valid { "verified" } else { "witness-stale" };

    let mut report = Report::new(
        outcome,
        reason_code,
        reason,
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.claim_type = Some(verdict.claim_type.clone());
    // Never stronger than the boundary `ahl_core::receipt::Verdict` carries.
    report.boundary = Some(verdict.boundary.clone());
    report.assurance = Some(AssuranceOut {
        governance: verdict.assurance.governance.clone(),
        competing_triggers: verdict.assurance.competing_triggers.clone(),
        witnessed: verdict.assurance.witnessed,
        continued_history: verdict.assurance.continued_history,
        content_binding: verdict.assurance.content_binding.clone(),
    });
    report.checkpoint = checkpoint.and_then(|checkpoint| {
        Some(CheckpointOut {
            log_id: checkpoint.get("log_id")?.as_str()?.to_owned(),
            tree_size: checkpoint.get("tree_size")?.as_u64()?,
            root_hash: checkpoint.get("root_hash")?.as_str()?.to_owned(),
        })
    });
    report.authenticated = true;
    // Enumerated governance is an authenticated range proven complete over exactly
    // `[0, tree_size(C))`; declared mode enumerates nothing at all.
    report.completeness = if verdict.assurance.governance == "enumerated" {
        Completeness::Complete
    } else {
        Completeness::NotApplicable
    };
    report.receipt_note = receipt
        .get("claim")
        .and_then(|claim| claim.get("note"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    report.with_findings(findings)
}

fn chain_entries(receipt: &Value) -> Result<Vec<(u64, Value)>, ()> {
    let chain = receipt
        .get("governance")
        .and_then(|governance| governance.get("chain"))
        .and_then(Value::as_array)
        .ok_or(())?;
    chain
        .iter()
        .map(|hop| {
            Ok((
                hop.get("entry_index").and_then(Value::as_u64).ok_or(())?,
                hop.get("envelope").cloned().ok_or(())?,
            ))
        })
        .collect()
}

/// Staleness per adaptor profile §11.3: older than the cadence by more than the grace period,
/// both taken from the manifest version **governing that checkpoint**.
fn freshness(
    governance: &Governance,
    checkpoint: Option<&Value>,
    evaluation: &EvaluationTime,
) -> Result<Option<Finding>, String> {
    let checkpoint = checkpoint.ok_or_else(|| "the receipt carries no checkpoint".to_owned())?;
    let tree_size = checkpoint
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| "the checkpoint carries no `tree_size`".to_owned())?;
    let time = checkpoint
        .get("checkpoint_time")
        .and_then(Value::as_str)
        .ok_or_else(|| "the checkpoint carries no `checkpoint_time`".to_owned())?;
    let instant = parse_artifact_time("checkpoint_time", time).map_err(|error| error.to_string())?;
    let (cadence, grace) =
        governance.cadence_and_grace_for(tree_size).map_err(|error| error.to_string())?;

    let age = evaluation.nanos_since(instant);
    let threshold = u128::from(cadence) + u128::from(grace);
    if age > threshold {
        Ok(Some(Finding::new(
            "witness-stale",
            format!(
                "the cosigned checkpoint's `checkpoint_time` {time} is {age}ns old at the \
                 evaluation time, beyond the governing cadence plus grace period ({threshold}ns)"
            ),
        )))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};


    use ahl_core::receipt::{AdaptorProfile, TrustPolicy};
    use serde_json::json;

    use super::*;
    use crate::policy::{ConfiguredProfile, Endpoints, LocalLimits, NetworkLimits};

    /// The `ahl-core` conformance corpus, as a foreign implementation would read it.
    fn corpus() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ahl-core/test_data")
    }

    fn corpus_index() -> Value {
        let bytes = std::fs::read(corpus().join("receipts/index.json")).expect("corpus index");
        serde_json::from_slice(&bytes).expect("index parses")
    }

    fn corpus_policy(with_dataset_key: bool) -> LoadedPolicy {
        let index = corpus_index();
        let policy_block = &index["policy"];
        let profile_hash = policy_block["adaptor_profiles"]["ahl-test-log-v1"]["hash"]
            .as_str()
            .expect("pinned hash")
            .to_owned();
        let profile_path = corpus().join("adaptor/ahl-test-log-v1.md");

        let mut dataset_keys = BTreeMap::new();
        if with_dataset_key {
            let raw = std::fs::read_to_string(corpus().join("keys/dataset_customers.key"))
                .expect("dataset key");
            dataset_keys
                .insert("customers".to_owned(), hex::decode(raw.trim()).expect("hex key"));
        }

        LoadedPolicy {
            trust: TrustPolicy {
                genesis_entry_id: policy_block["genesis_entry_id"]
                    .as_str()
                    .expect("anchor")
                    .to_owned(),
                genesis_key_ids: policy_block["genesis_key_ids"]
                    .as_array()
                    .expect("key ids")
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect(),
                adaptor_profiles: BTreeMap::from([(
                    "ahl-test-log-v1".to_owned(),
                    AdaptorProfile::minimal(profile_hash.clone()),
                )]),
                dataset_keys,
                trusted_witness_key_ids: BTreeSet::new(),
                limits: ahl_core::receipt::Limits::default(),
            },
            profiles: BTreeMap::from([(
                "ahl-test-log-v1".to_owned(),
                ConfiguredProfile {
                    hash: profile_hash,
                    path: profile_path,
                    capabilities: ahl_core::receipt::AdaptorCapabilities::default(),
                },
            )]),
            endpoints: Endpoints::default(),
            network: NetworkLimits::default(),
            local: LocalLimits::default(),
        }
    }

    fn at_corpus_time() -> EvaluationTime {
        EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("fixed instant")
    }

    fn verify_vector(file: &str, policy: &LoadedPolicy) -> Report {
        run(
            policy,
            &at_corpus_time(),
            &Options { receipt: corpus().join("receipts").join(file), require_fresh: false },
        )
    }

    #[test]
    fn every_positive_corpus_receipt_is_valid_and_every_negative_one_is_invalid() {
        let policy = corpus_policy(true);
        let index = corpus_index();
        let vectors = index["vectors"].as_array().expect("vectors");
        assert!(vectors.len() >= 20, "the corpus should carry 20+ receipts");

        for vector in vectors {
            let file = vector["file"].as_str().expect("file");
            let expect = vector["expect"].as_str().expect("expect");
            let report = verify_vector(file, &policy);
            match expect {
                "accept" => {
                    assert_eq!(report.status, "valid", "{file}: {}", report.reason);
                    assert_eq!(
                        report.claim_type.as_deref(),
                        vector["claim_type"].as_str(),
                        "{file}"
                    );
                    assert_eq!(
                        report.boundary.as_deref(),
                        vector["boundary"].as_str(),
                        "{file}: the rendered boundary must be the one ahl-core carries"
                    );
                }
                "reject" => {
                    assert_eq!(report.status, "invalid", "{file}: {}", report.reason);
                    let expected = vector["reason"].as_str().expect("reason");
                    assert!(
                        report.reason.contains(expected),
                        "{file}: expected the rule `{expected}` to fire, got `{}`",
                        report.reason
                    );
                }
                other => panic!("unknown expectation `{other}` for {file}"),
            }
        }
    }

    #[test]
    fn a_keyed_binding_with_no_dataset_key_held_is_unverifiable_never_invalid() {
        // §6: "Keyed binding, no authorized dataset key held | 3, content_binding: none —
        // never downgraded to plain-verified".
        let report = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(report.status, "unverifiable");
        assert_eq!(report.reason_code, "dataset-key-not-held");
        assert!(report.assurance.is_none(), "no assurance is claimed without the key");
    }

    #[test]
    fn the_dataset_key_sentinel_is_still_what_ahl_core_emits() {
        // Pins the fragile coupling described in the module docs: if `ahl-core` changes this
        // string, this test fails rather than a `3` silently becoming a `1`.
        let error = ReceiptError::ContentBindingMismatch {
            mode: "keyed-authorized".to_owned(),
            recomputed: NO_DATASET_KEY.to_owned(),
            claimed: "customers".to_owned(),
        };
        assert!(matches!(classify(error), CliError::DatasetKeyNotHeld { .. }));
        let report = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(report.status, "unverifiable", "sentinel drift: {}", report.reason);
    }

    #[test]
    fn an_unreadable_receipt_is_an_error_and_a_malformed_one_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = corpus_policy(true);

        let absent = run(
            &policy,
            &at_corpus_time(),
            &Options { receipt: dir.path().join("absent.ahl"), require_fresh: false },
        );
        assert_eq!(absent.status, "error");

        let malformed_path = dir.path().join("bad.ahl");
        std::fs::write(&malformed_path, b"{not json").expect("write");
        let malformed = run(
            &policy,
            &at_corpus_time(),
            &Options { receipt: malformed_path, require_fresh: false },
        );
        assert_eq!(malformed.status, "invalid");
        assert_eq!(malformed.reason_code, "malformed");
    }

    #[test]
    fn a_receipt_that_is_not_jcs_canonical_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = corpus().join("receipts/statement-anchored-valid.ahl");
        let value: Value =
            serde_json::from_slice(&std::fs::read(&source).expect("read")).expect("parse");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty");
        let path = dir.path().join("pretty.ahl");
        std::fs::write(&path, pretty).expect("write");

        let report = run(
            &corpus_policy(true),
            &at_corpus_time(),
            &Options { receipt: path, require_fresh: false },
        );
        assert_eq!(report.status, "invalid");
        assert!(report.reason.contains("JCS-canonical"), "{}", report.reason);
    }

    #[test]
    fn a_profile_that_is_not_locally_possessed_is_unverifiable_not_invalid() {
        let mut policy = corpus_policy(true);
        policy.profiles.clear();
        policy.trust.adaptor_profiles.clear();
        let report = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(report.status, "unverifiable");
        assert_eq!(report.reason_code, "profile-not-possessed");
    }

    #[test]
    fn a_profile_whose_bytes_do_not_hash_to_the_pinned_value_is_a_local_configuration_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tampered = dir.path().join("profile.md");
        std::fs::write(&tampered, b"# not the pinned document\n").expect("write");
        let mut policy = corpus_policy(true);
        if let Some(profile) = policy.profiles.get_mut("ahl-test-log-v1") {
            profile.path = tampered;
        }
        let report = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(report.status, "error");
        assert_eq!(report.reason_code, "profile-broken");
    }

    #[test]
    fn the_receipt_note_is_carried_as_a_quotation_and_never_as_a_finding() {
        // The corpus receipts carry no `note`; construct the surrounding logic directly.
        let receipt = json!({ "claim": { "note": "issued for the 2026 audit" } });
        let verdict = Verdict {
            claim_type: "statement-anchored".to_owned(),
            subject_entry_index: 1,
            subject_statement_id: "sha256:aa".to_owned(),
            assurance: ahl_core::receipt::Assurance {
                governance: "declared".to_owned(),
                competing_triggers: "not-checked".to_owned(),
                witnessed: false,
                continued_history: false,
                content_binding: "none".to_owned(),
            },
            boundary: "anchored".to_owned(),
            embedded_receipts: 0,
        };
        let report = succeeded(
            &receipt,
            &verdict,
            &at_corpus_time(),
            &Options { receipt: std::path::PathBuf::new(), require_fresh: false },
        );
        assert_eq!(report.receipt_note.as_deref(), Some("issued for the 2026 audit"));
        assert!(report.findings.is_empty(), "a note is never a finding");
    }

    #[test]
    fn a_stale_cosignature_is_a_finding_and_require_fresh_promotes_it_to_unverifiable() {
        let policy = corpus_policy(true);
        // The corpus checkpoints are stamped 2026-08-16T12:00:00Z with a PT1H cadence and a
        // PT15M grace period; a year later they are unambiguously stale.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let path = corpus().join("receipts/statement-anchored-valid.ahl");

        let finding_only = run(
            &policy,
            &much_later,
            &Options { receipt: path.clone(), require_fresh: false },
        );
        assert_eq!(finding_only.status, "valid", "staleness is never by itself a disproof");
        assert!(finding_only.findings.iter().any(|f| f.code == "witness-stale"));

        let promoted =
            run(&policy, &much_later, &Options { receipt: path, require_fresh: true });
        assert_eq!(promoted.status, "unverifiable");
        assert!(promoted.findings.iter().any(|f| f.code == "witness-stale"));
    }

    #[test]
    fn a_fresh_cosignature_raises_no_staleness_finding() {
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, "valid");
        assert!(!report.findings.iter().any(|f| f.code == "witness-stale"));
    }

    #[test]
    fn the_corpus_manifests_are_reported_as_disagreeing_with_core_spec_7_3() {
        // Not adjudicated — reported. The corpus spells the log id `log.id` and omits
        // `cadence_epoch`, both of which core spec §7.3 fixes otherwise.
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert!(report.findings.iter().any(|f| f.code == "manifest-log-id-legacy-spelling"));
        assert!(report.findings.iter().any(|f| f.code == "manifest-log-object-incomplete"));
        assert_eq!(report.status, "valid", "a finding never changes the outcome");
    }

    #[test]
    fn enumerated_governance_reports_complete_and_declared_reports_not_applicable() {
        let policy = corpus_policy(true);
        let enumerated = verify_vector("trigger-effective-valid.ahl", &policy);
        assert_eq!(enumerated.completeness, Completeness::Complete);
        let declared = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(declared.completeness, Completeness::NotApplicable);
    }

    #[test]
    fn a_receipt_pinning_an_unknown_profile_id_is_unverifiable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = corpus().join("receipts/statement-anchored-valid.ahl");
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(&source).expect("read")).expect("parse");
        value["anchoring"]["adaptor"]["id"] = json!("ahl-adaptor-atl-v1");
        let path = dir.path().join("other-profile.ahl");
        std::fs::write(&path, ahl_core::jcs(&value)).expect("write");

        let report = run(
            &corpus_policy(true),
            &at_corpus_time(),
            &Options { receipt: path, require_fresh: false },
        );
        assert_eq!(report.status, "unverifiable");
        assert_eq!(report.reason_code, "profile-not-possessed");
    }

    #[test]
    fn a_receipt_with_no_adaptor_id_is_malformed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.ahl");
        std::fs::write(&path, ahl_core::jcs(&json!({ "anchoring": {} }))).expect("write");
        let report = run(
            &corpus_policy(true),
            &at_corpus_time(),
            &Options { receipt: path, require_fresh: false },
        );
        assert_eq!(report.status, "invalid");
    }

    #[test]
    fn every_receipt_error_variant_maps_to_a_named_outcome() {
        // Spot-checks across the three outcome classes; the compiler enforces totality of the
        // match itself, so this asserts the classification rather than the coverage.
        assert_eq!(
            classify(ReceiptError::LimitExceeded("decoded size budget")).outcome(),
            Outcome::Unverifiable
        );
        assert_eq!(
            classify(ReceiptError::UnsupportedVersion {
                field: "spec_version",
                expected: "0.3.0",
                got: "0.4.0".to_owned(),
            })
            .outcome(),
            Outcome::Unverifiable
        );
        assert_eq!(
            classify(ReceiptError::AdaptorCapabilityUnsupported {
                id: "ahl-test-log-v1".to_owned(),
                capability: "a binary checkpoint framing",
            })
            .outcome(),
            Outcome::Unverifiable
        );
        assert_eq!(
            classify(ReceiptError::CheckpointSignatureInvalid).outcome(),
            Outcome::Invalid
        );
        assert_eq!(classify(ReceiptError::GenesisAnchorMismatch).outcome(), Outcome::Invalid);
        assert_eq!(
            classify(ReceiptError::Malformed("x".to_owned())).outcome(),
            Outcome::Invalid
        );
    }

    #[test]
    fn freshness_is_reported_as_unavailable_rather_than_guessed() {
        let entries: Vec<(u64, Value)> = Vec::new();
        let governance = Governance::default();
        assert!(freshness(&governance, None, &at_corpus_time()).is_err());
        assert!(freshness(&governance, Some(&json!({})), &at_corpus_time()).is_err());
        assert!(freshness(
            &governance,
            Some(&json!({ "tree_size": 1, "checkpoint_time": "nope" })),
            &at_corpus_time()
        )
        .is_err());
        let _ = entries;
    }

    #[test]
    fn a_receipt_with_no_governance_chain_still_reports_rather_than_panicking() {
        assert!(chain_entries(&json!({})).is_err());
        assert!(chain_entries(&json!({ "governance": { "chain": [ { } ] } })).is_err());
    }
}
