//! `verify` — offline by construction.
//!
//! Receipt format §1 defines verification as receipt + locally pinned profile + local policy.
//! There is no flag that makes `verify` reach the network, and an assurance field that could
//! only be raised by fetching is simply not raised. In particular `assurance.witnessed` is
//! true iff a cosignature **carried by the receipt** verifies: whether a witness answers right
//! now is irrelevant and must not change the verdict.
//!
//! # Outcomes
//!
//! The core returns the I-D §7.7 result model: a completed run reaches exactly one of
//! `verified`, `invalid` and `unverifiable`, together with one finding per required assertion,
//! and a run that does not complete reaches none of them. This command maps that model onto
//! the §6 exit-code contract and adds nothing to it:
//!
//! | §7.7 result | Outcome | Exit |
//! |---|---|---|
//! | `verified` | [`Outcome::Valid`] | `0` |
//! | `invalid` | [`Outcome::Invalid`] | `1` |
//! | `unverifiable` | [`Outcome::Unverifiable`] | `3` |
//! | no result — the run did not complete | [`Outcome::Error`] | `2` |
//!
//! Which of `invalid` and `unverifiable` a rejection produces is decided by the core, from the
//! rule that fired, and is never re-derived here: a verifier-local condition reported as
//! `invalid` would let two verifiers make contradictory statements about one artifact, and a
//! second classifier over the same rejections is how the two implementations come to disagree.
//!
//! The rows of §6 this command still decides are the ones that fire **before** the core is
//! entered, over material the core never sees: an unreadable receipt (`2`), bytes that are not
//! the JCS-canonical serialization (`1`), a receipt naming no adaptor profile (`1`), a profile
//! local policy does not hold (`3`), and a profile whose held bytes do not hash to the pinned
//! value (`2`). The last of these is the one place this crate and the core would answer
//! differently — the core reads a pinned digest disagreeing with the held document as
//! `invalid` — and §6 governs because the check runs against local configuration, before any
//! artifact has been adjudicated.

use ahl_core::receipt::{
    verify_receipt_report, Outcome as CoreOutcome, Report as CoreReport, Verdict,
};
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::evaluation::{parse_artifact_time, EvaluationTime};
use crate::governance::Governance;
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::profile;
use crate::report::{AssertionOut, AssuranceOut, CheckpointOut, Completeness, Finding, Report};
use crate::secure;

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
    let bytes = secure::read_regular("receipt", &options.receipt, policy.local.max_file_bytes)?;

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
    let pinned = adaptor_id(&receipt).map_err(|()| CliError::Malformed {
        what: "receipt",
        detail: "carries no `anchoring.adaptor.id`".to_owned(),
    })?;
    let resolved = profile::resolve(policy, &pinned)?;
    // The core recomputes the profile digest over the document it HOLDS, so it is handed the
    // bytes this run read and hashed rather than a value asserted about them. The clone is
    // what carries them; its own dataset-key bytes are wiped when it is dropped.
    let mut held = policy.clone();
    if let Some(capabilities) = policy.profiles.get(&pinned).map(|entry| entry.capabilities) {
        held.trust.adaptor_profiles.insert(pinned.clone(), resolved.as_core(capabilities));
    }
    let policy = &held;

    // A run that does not complete produces no result at all: it says nothing about the
    // receipt, so it is reported as the local failure it is (`2`) and never as one of the
    // three values.
    let core = verify_receipt_report(&receipt, &policy.trust)
        .map_err(|failure| CliError::ExecutionFailed(failure.detail))?;

    match (core.result, core.verdict.as_ref()) {
        (CoreOutcome::Verified, Some(verdict)) => {
            Ok(succeeded(&receipt, &core, verdict, evaluation, options, policy))
        }
        // A boundary is rendered for `verified` and for nothing else, so a result carrying
        // none is a rejection whatever else it carries.
        _ => Ok(rejected(&receipt, &core, evaluation)),
    }
}

/// The §7.7 findings, in the order the verification algorithm reaches them.
fn assertions(core: &CoreReport) -> Vec<AssertionOut> {
    core.findings
        .iter()
        .map(|finding| AssertionOut {
            assertion: finding.assertion.name().to_owned(),
            outcome: finding.outcome.name().to_owned(),
            receipt_path: finding.receipt_path.clone(),
            detail: finding.detail.clone(),
        })
        .collect()
}

/// The assurance block the receipt carries, read without interpretation.
///
/// I-D §7.7 forbids expressing a result by rewriting these members, so they are copied across
/// on every outcome and what the run established about each of them is reported separately, in
/// the assertions.
fn carried_assurance(receipt: &Value) -> Option<AssuranceOut> {
    let assurance = receipt.get("claim")?.get("assurance")?;
    let string =
        |member: &str| assurance.get(member).and_then(Value::as_str).unwrap_or_default().to_owned();
    Some(AssuranceOut {
        governance: string("governance"),
        competing_triggers: string("competing_triggers"),
        witnessed: assurance.get("witnessed").and_then(Value::as_bool).unwrap_or(false),
        continued_history: assurance
            .get("continued_history")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        content_binding: string("content_binding"),
        canonicalization_namespace: assurance
            .get("canonicalization_namespace")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// The finding that decided a non-`verified` result: the first `invalid` one, since `invalid`
/// dominates, and otherwise the first `unverifiable` one.
///
/// Findings arrive ordered by receipt path and then by the order the §7.5 algorithm reaches
/// them, so "first" is the earliest assertion that produced the result rather than an arbitrary
/// one, and a finding is never presented as though it were the result.
fn dominating(core: &CoreReport) -> Option<&ahl_core::receipt::Finding> {
    core.findings
        .iter()
        .find(|finding| finding.outcome == CoreOutcome::Invalid)
        .or_else(|| core.findings.iter().find(|f| f.outcome == CoreOutcome::Unverifiable))
}

/// Render a non-`verified` result: the §6 outcome, the assertion that produced it, and the
/// assurance the receipt claimed.
///
/// No boundary is rendered — §7.7 permits only `verified` to be "rendered in words that assert
/// the property" — and the assurance block is reproduced as carried rather than rewritten to
/// express the result.
fn rejected(receipt: &Value, core: &CoreReport, evaluation: &EvaluationTime) -> Report {
    let outcome = match core.result {
        CoreOutcome::Invalid => Outcome::Invalid,
        // `Verified` cannot reach here: it is handled above, and a report carrying no verdict
        // is not one. Mapping it alongside `Unverifiable` keeps the match total without
        // inventing an outcome for a state the core does not produce.
        CoreOutcome::Unverifiable | CoreOutcome::Verified => Outcome::Unverifiable,
    };
    let deciding = dominating(core);
    let reason_code =
        deciding.map_or_else(|| core.result.name().to_owned(), |f| f.assertion.name().to_owned());
    let reason = deciding
        .and_then(|finding| finding.detail.clone())
        .unwrap_or_else(|| format!("the receipt is {}", core.result));

    let mut report =
        Report::new(outcome, reason_code, reason, evaluation.rendered.clone(), evaluation.source);
    report.claim_type = receipt
        .get("claim")
        .and_then(|claim| claim.get("type"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    report.assurance = carried_assurance(receipt);
    report.assertions = Some(assertions(core));
    report
}

fn adaptor_id(receipt: &Value) -> Result<String, ()> {
    receipt
        .get("anchoring")
        .and_then(|anchoring| anchoring.get("adaptor"))
        .and_then(|adaptor| adaptor.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(())
}

fn succeeded(
    receipt: &Value,
    core: &CoreReport,
    verdict: &Verdict,
    evaluation: &EvaluationTime,
    options: &Options,
    policy: &LoadedPolicy,
) -> Report {
    let checkpoint = receipt.get("anchoring").and_then(|anchoring| anchoring.get("checkpoint"));
    let mut findings = Vec::new();
    let mut outcome = Outcome::Valid;

    // Governance findings and freshness both come from the receipt's own chain, which
    // `verify_receipt` has already validated back to the configured genesis anchor.
    let chain = chain_entries(receipt);
    if let Ok(entries) = &chain {
        // `verify_receipt` has already validated this chain from the configured genesis
        // anchor; resolving it again here is what supplies the cadence and grace period the
        // freshness check needs, and it uses the same §7.4.1 rules rather than a weaker walk.
        if let Ok((governance, _)) = Governance::resolve(entries, &policy.trust) {
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
                    Err(detail) => {
                        findings.push(Finding::new("witness-freshness-unavailable", detail));
                    }
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

    let mut report =
        Report::new(outcome, reason_code, reason, evaluation.rendered.clone(), evaluation.source);
    report.claim_type = Some(verdict.claim_type.clone());
    // Never stronger than the boundary `ahl_core::receipt::Verdict` carries.
    report.boundary = Some(verdict.boundary.clone());
    report.assurance = Some(AssuranceOut {
        governance: verdict.assurance.governance.clone(),
        competing_triggers: verdict.assurance.competing_triggers.clone(),
        witnessed: verdict.assurance.witnessed,
        continued_history: verdict.assurance.continued_history,
        content_binding: verdict.assurance.content_binding.clone(),
        canonicalization_namespace: verdict.assurance.canonicalization_namespace.clone(),
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
    report.assertions = Some(assertions(core));
    report.with_findings(findings)
}

/// `(entry_index, envelope)` pairs, as the governance resolver takes them.
type ChainEntries = Vec<(u64, Value)>;

fn chain_entries(receipt: &Value) -> Result<ChainEntries, ()> {
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
    let instant =
        parse_artifact_time("checkpoint_time", time).map_err(|error| error.to_string())?;
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
    use std::collections::BTreeMap;

    use ahl_core::receipt::TrustPolicy;
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
        // Declared by the corpus, never hard-coded: a capability is a property of the pinned
        // profile document.
        let declared = &policy_block["adaptor_profiles"]["ahl-test-log-v1"]["capabilities"];
        let capabilities = ahl_core::receipt::AdaptorCapabilities {
            checkpoint_raw: declared["checkpoint_raw"].as_bool().unwrap_or(false),
            consistency_proofs: declared["consistency_proofs"].as_bool().unwrap_or(false),
        };
        let profile_path = corpus().join("adaptor/ahl-test-log-v1.md");

        let mut dataset_keys = BTreeMap::new();
        if with_dataset_key {
            let raw = std::fs::read_to_string(corpus().join("keys/dataset_customers.key"))
                .expect("dataset key");
            dataset_keys.insert("customers".to_owned(), hex::decode(raw.trim()).expect("hex key"));
        }

        LoadedPolicy {
            trust: TrustPolicy {
                genesis_entry_id: policy_block["genesis_entry_id"]
                    .as_str()
                    .expect("anchor")
                    .to_owned(),
                genesis_key_ids: Some(
                    policy_block["genesis_key_ids"]
                        .as_array()
                        .expect("key ids")
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect(),
                ),
                // Empty exactly as `policy::load` leaves it: the held document is installed
                // from the resolution, at the point of use.
                adaptor_profiles: BTreeMap::new(),
                dataset_keys,
                trusted_witness_keys: BTreeMap::new(),
                limits: ahl_core::receipt::Limits::default(),
            },
            profiles: BTreeMap::from([(
                "ahl-test-log-v1".to_owned(),
                ConfiguredProfile { hash: profile_hash, path: profile_path, capabilities },
            )]),
            endpoints: Endpoints::default(),
            network: NetworkLimits::default(),
            local: LocalLimits::default(),
        }
    }

    fn at_corpus_time() -> EvaluationTime {
        EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("fixed instant")
    }

    /// Collapse runs of whitespace, so a comparison is on the words rather than on the layout.
    ///
    /// The corpus's `index.json` records the expected boundary for
    /// `statement-anchored-continued-history.ahl` with a run of spaces where its generator
    /// wrapped the line, while `ahl_core::receipt::Verdict::boundary` renders a single space.
    /// The words are identical and the rule under test is that the CLI never renders anything
    /// **stronger** than that struct carries, so the comparison is on the words. The
    /// discrepancy is reported upstream rather than smoothed over silently.
    fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn verify_vector(file: &str, policy: &LoadedPolicy) -> Report {
        run(
            policy,
            &at_corpus_time(),
            &Options { receipt: corpus().join("receipts").join(file), require_fresh: false },
        )
    }

    #[test]
    fn every_corpus_receipt_reaches_the_result_and_the_finding_the_corpus_declares() {
        // The corpus index states the §7.7 result a conformant verifier must reach and, for a
        // non-`verified` vector, the required assertion whose finding produced it. Both are
        // asserted, so neither the result nor the assertion it came from can drift.
        let policy = corpus_policy(true);
        let index = corpus_index();
        let vectors = index["vectors"].as_array().expect("vectors");
        assert!(vectors.len() >= 20, "the corpus should carry 20+ receipts");

        for vector in vectors {
            let file = vector["file"].as_str().expect("file");
            let expect = vector["expect"].as_str().expect("expect");
            let report = verify_vector(file, &policy);
            let status = match expect {
                "verified" => "valid",
                "invalid" => "invalid",
                "unverifiable" => "unverifiable",
                other => panic!("unknown expectation `{other}` for {file}"),
            };
            assert_eq!(report.status, status, "{file}: {}", report.reason);

            if expect == "verified" {
                assert_eq!(report.claim_type.as_deref(), vector["claim_type"].as_str(), "{file}");
                // The verdict is rendered from `ahl_core::receipt::Verdict` and is never
                // stronger than the boundary that struct carries.
                assert_eq!(
                    words(report.boundary.as_deref().unwrap_or_default()),
                    words(vector["boundary"].as_str().unwrap_or_default()),
                    "{file}: the rendered boundary must be the one ahl-core carries"
                );
                continue;
            }

            assert!(report.boundary.is_none(), "{file}: only `verified` renders a boundary");
            let expected = vector["reason"].as_str().expect("reason");
            assert!(
                report.reason.contains(expected),
                "{file}: expected the rule `{expected}` to fire, got `{}`",
                report.reason
            );
            let assertion = vector["finding"].as_str().expect("finding");
            let assertions = report.assertions.as_ref().expect("the findings are reported");
            assert!(
                assertions
                    .iter()
                    .any(|entry| entry.assertion == assertion && entry.outcome == expect),
                "{file}: `{assertion}` is not reported as `{expect}`: {assertions:?}"
            );
        }
    }

    #[test]
    fn a_keyed_binding_with_no_dataset_key_held_is_unverifiable_never_invalid() {
        // §7.7's own worked example: the content binding is a required assertion, the verifier
        // is not authorized to hold the key, and the result is `unverifiable` — a capability
        // gap the verifier has, never a defect it has shown in the artifact. Its report "MUST
        // show the anchoring and introduction findings as `verified` and the content-binding
        // finding as `unverifiable`".
        let report = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(report.status, "unverifiable", "{}", report.reason);
        assert_eq!(report.reason_code, "content-binding");
        assert!(report.boundary.is_none(), "a boundary is rendered for `verified` alone");

        let assertions = report.assertions.as_ref().expect("the findings are reported");
        let outcome_of = |name: &str| {
            assertions
                .iter()
                .find(|entry| entry.assertion == name && entry.receipt_path.is_empty())
                .map(|entry| entry.outcome.clone())
        };
        assert_eq!(outcome_of("content-binding").as_deref(), Some("unverifiable"));
        assert_eq!(outcome_of("anchoring").as_deref(), Some("verified"));
        assert_eq!(outcome_of("claim-material").as_deref(), Some("verified"));

        // The assurance block is reproduced AS CARRIED. §7.7: "a content binding the verifier
        // cannot compute MUST NOT be re-rendered as `content_binding: \"none\"`, which would
        // convert an unevaluated claim into a weaker verified one."
        let assurance = report.assurance.as_ref().expect("the carried block is reproduced");
        assert_eq!(assurance.content_binding, "keyed-authorized");
        assert_ne!(assurance.content_binding, "none");
        assert_eq!(assurance.canonicalization_namespace.as_deref(), Some("public"));
        assert!(report.to_text().contains("content_binding: keyed-authorized"));
    }
    #[test]
    fn a_run_that_reaches_no_result_is_a_local_failure_and_never_one_of_the_three_values() {
        // §7.7: a run that does not complete "says nothing about the receipt and MUST NOT be
        // rendered as any of the three values".
        let error = CliError::ExecutionFailed("the run stopped".to_owned());
        assert_eq!(error.outcome(), Outcome::Error);
        assert_eq!(error.outcome().exit_code(), 2);
        assert_eq!(error.reason_code(), "execution-failed");
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
        // The note is informative: it is attributed to the receipt and never rendered as
        // something the run established.
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, "valid", "{}", report.reason);
        let note = report.receipt_note.as_deref().expect("the corpus receipt carries a note");
        assert!(!note.is_empty());
        assert!(
            !report.findings.iter().any(|finding| finding.detail == note),
            "a note is never a finding"
        );
        assert!(report.to_text().contains("the receipt says (informative, not a finding)"));
    }

    #[test]
    fn a_stale_cosignature_is_a_finding_and_require_fresh_promotes_it_to_unverifiable() {
        let policy = corpus_policy(true);
        // The corpus checkpoints are stamped 2026-08-16T12:00:00Z with a PT1H cadence and a
        // PT15M grace period; a year later they are unambiguously stale.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let path = corpus().join("receipts/statement-anchored-valid.ahl");

        let finding_only =
            run(&policy, &much_later, &Options { receipt: path.clone(), require_fresh: false });
        assert_eq!(finding_only.status, "valid", "staleness is never by itself a disproof");
        assert!(finding_only.findings.iter().any(|f| f.code == "witness-stale"));

        let promoted = run(&policy, &much_later, &Options { receipt: path, require_fresh: true });
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
    fn the_regenerated_corpus_manifests_carry_the_specification_log_object() {
        // The corpus previously spelled the log id `log.id` and omitted `cadence_epoch`, and
        // this crate reported both. It now follows core §7.3, so there is nothing to report —
        // and the `log_id` spelling is required rather than aliased, which is what makes the
        // vectors below resolve at all.
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert!(
            !report.findings.iter().any(|f| f.code == "manifest-log-object-incomplete"),
            "unexpected log-object findings: {:?}",
            report.findings
        );
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
    fn each_of_the_three_results_maps_to_its_exit_code_and_never_to_another() {
        // §7.7's three values, exercised end to end so the mapping is asserted over what the
        // core actually returns rather than over a table restated here. A local failure that
        // reaches no result at all is the fourth outcome and is covered by
        // `an_unreadable_receipt_is_an_error_and_a_malformed_one_is_invalid`.
        let policy = corpus_policy(true);
        let verified = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(verified.status, "valid");
        assert_eq!(Outcome::Valid.exit_code(), 0);

        let invalid = verify_vector("overclaim-must-fail.ahl", &policy);
        assert_eq!(invalid.status, "invalid", "{}", invalid.reason);
        assert_eq!(Outcome::Invalid.exit_code(), 1);

        let unverifiable = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(unverifiable.status, "unverifiable", "{}", unverifiable.reason);
        assert_eq!(Outcome::Unverifiable.exit_code(), 3);
        assert_ne!(unverifiable.status, invalid.status, "never rendered as the other");
    }
    #[test]
    fn a_receipt_carrying_a_verifying_consistency_path_is_valid() {
        let report =
            verify_vector("statement-anchored-continued-history.ahl", &corpus_policy(true));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert_eq!(
            report.assurance.as_ref().map(|assurance| assurance.continued_history),
            Some(true)
        );
    }
    #[test]
    fn an_invalid_result_prints_the_assertion_table_and_never_a_boundary() {
        let report = verify_vector("overclaim-must-fail.ahl", &corpus_policy(true));
        assert_eq!(report.status, "invalid", "{}", report.reason);
        assert!(report.boundary.is_none());
        let text = report.to_text();
        assert!(!text.contains("boundary:"), "{text}");
        assert!(text.contains("assertions:"), "{text}");
        assert!(text.contains("cross-field: invalid"), "{text}");
        // The assurance the receipt claimed is still shown, so a reader can see what was
        // asserted beside what the run established about it.
        assert!(text.contains("assurance:"), "{text}");
    }

    #[test]
    fn a_consistency_path_that_does_not_verify_is_invalid_on_the_anchoring_assertion() {
        // The core evaluates the carried consistency path, so which of `invalid` and
        // `unverifiable` its failure produces is its answer and not one re-derived here. The
        // corpus vector pairs the two checkpoints the path does not open.
        let report = verify_vector(
            "statement-anchored-continued-history-wrong-pair-must-fail.ahl",
            &corpus_policy(true),
        );
        assert_eq!(report.status, "invalid", "{}", report.reason);
        assert_eq!(report.reason_code, "anchoring");
        assert!(report.boundary.is_none(), "a boundary is rendered for `verified` alone");
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
