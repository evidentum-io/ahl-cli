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
//! | §7.7 result | `status` | `outcome`, where no overlay applied | Exit |
//! |---|---|---|---|
//! | `verified` | `valid` | `valid` | `0` |
//! | `invalid` | `invalid` | `invalid` | `1` |
//! | `unverifiable` | `unverifiable` | `unverifiable` | `3` |
//! | no result — the run did not complete | `null` | `error` | `2` |
//!
//! `error` is a value of `outcome` alone. §7.7 has three values and a non-completing run
//! reaches none of them, so reporting one as a `status` would invent the model's fourth.
//!
//! Which of `invalid` and `unverifiable` a rejection produces is decided by the core, from the
//! rule that fired, and is never re-derived here: a verifier-local condition reported as
//! `invalid` would let two verifiers make contradictory statements about one artifact, and a
//! second classifier over the same rejections is how the two implementations come to disagree.
//!
//! Which finding the report LEADS with is the core's answer for the same reason
//! ([`CoreReport::dominating`]): the cause, never an assertion that merely inherited another's
//! gap. The distinction is load-bearing where a budget runs out — every assertion the run could
//! not reach then rests on it, and §7.8's "MUST report WHICH budget was exhausted and the value
//! that was in force" is satisfied only by the one that ran out.
//!
//! # The one CLI policy overlay
//!
//! `assertions[]` carries the core's required assertions and nothing else: §7.7 enumerates
//! them "exactly", and a verifier-local condition among them would be this crate asserting
//! something about the receipt that another conformant verifier would not.
//!
//! `policy_overlays[]` is where a locally configured condition goes, and this build has one:
//! `witness-freshness`, present only where `--require-fresh` is given and a carried cosignature
//! is older than the cadence plus the grace period the governing manifest declares. Freshness
//! is a property of the run's evaluation time, not of the receipt, so the core neither has it
//! nor could. It produces `unverifiable` and **never** `invalid` — a stale cosignature
//! disproves nothing — and without the flag it is not an overlay at all, only a `findings[]`
//! entry (`witness-stale`).
//!
//! **`status` and `outcome` are two answers, not one.** `status` is the RECEIPT's result — the
//! §7.7 reduction of `assertions[]` — and no local policy rewrites it. `outcome` is THIS RUN's
//! decision: `status`, then promoted from `valid` to `unverifiable` by any overlay, and the
//! exit code follows it. A receipt whose every required assertion verified therefore reports
//! `status: valid` beside `outcome: unverifiable` and exits `3`, rather than having a condition
//! of this run presented as though it were the receipt's result.
//!
//! An overlay is evaluated on every completed run and reported whatever the receipt's result
//! was — but only over material this run established. On a rejected receipt the freshness
//! overlay is emitted only where the receipt carries a cosignature at all and its own
//! `witnesses` and `checkpoint-authentication` assertions verified: a receipt may carry
//! `witnessed: true` beside a cosignature that does not verify, and an overlay speaking of "the
//! cosigned checkpoint" would then assert what the result denies. It can only ever move
//! `valid`: a demonstrated defect outranks a condition of this
//! run, so an overlay beside an `invalid` receipt is informative and changes nothing. The
//! headline describes `outcome` and follows the same precedence — the core's `dominating()`
//! finding wherever the core result is not `verified`, and otherwise the first overlay.
//!
//! A boundary is rendered where the FINAL status is `valid` and nowhere else. Carrying the
//! core's boundary under a status the overlay moved would present words that assert the
//! property beside a result that does not, which is what §7.7 forbids for the other two values.
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
    verify_receipt_report, Assertion, Finding as CoreFinding, Outcome as CoreOutcome, ReceiptError,
    Report as CoreReport, Verdict, RECEIPT_VERSION, SPEC_VERSION,
};
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::evaluation::{parse_artifact_time, EvaluationTime};
use crate::governance::Governance;
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::profile;
use crate::report::{
    AssertionOut, AssuranceOut, CheckpointOut, Completeness, Finding, InformativeOut,
    PolicyOverlayOut, Report,
};
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
        Err(error) => {
            let mut report = Report::over_receipt(
                error.outcome(),
                error.reason_code(),
                error.to_string(),
                evaluation.rendered.clone(),
                evaluation.source,
            );
            report.assertions = settled_before_the_core(&error).map(|assertion| {
                vec![AssertionOut {
                    assertion: assertion.name().to_owned(),
                    outcome: error.outcome().as_result_value().unwrap_or_default().to_owned(),
                    receipt_path: Vec::new(),
                    detail: Some(error.to_string()),
                    // Its own check produced it: nothing was skipped for want of a
                    // prerequisite, because nothing before it had run.
                    rests_on: None,
                }]
            });
            // A run that settled an assertion inspected no carried envelopes beyond the one
            // that stopped it, so its void-entry list is empty rather than absent: `null` is
            // for a run that reported no assertions at all.
            report.informative = report.assertions.as_ref().map(|_| Vec::new());
            report
        }
    }
}

/// The §7.7 assertion a rejection the CLI reached BEFORE the core settled, where there is one.
///
/// §7.7 requires a verifier to "report the findings alongside" the result, and these runs
/// completed: they reached one of the three values over the receipt's own bytes, and the
/// assertion each belongs to is the one the core would have filed it under. Reporting the
/// result without it would leave a consumer holding a status it cannot attribute — and would
/// make the CLI's own rows the one place `assertions[]` goes silent.
///
/// `None` where the run reached no result at all: an unreadable file, an unusable policy, a
/// broken local configuration. §7.7 scopes those out of the model entirely — they say nothing
/// about the receipt — so they carry no assertion rather than an invented one.
const fn settled_before_the_core(error: &CliError) -> Option<Assertion> {
    match error {
        // The container schema and identifier checks of §7.5 step 1: bytes that are not JSON,
        // are not the JCS serialization, or name no adaptor profile at all.
        CliError::Malformed { .. } => Some(Assertion::Structure),
        // §7.5 step 2, resolved from local possession before the core is entered.
        CliError::ProfileNotPossessed { .. } => Some(Assertion::AdaptorProfile),
        _ => None,
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
    // I-D §7.5 step 1: "Read `ahl_receipt_version` and act on it BEFORE ANY OTHER CHECK,
    // including schema validation", and §7.1 follows a version this build does not implement
    // with no further processing. The order is not a matter of taste. A receipt issued under
    // rules this build does not implement would otherwise be adjudicated against the rules of a
    // revision it never claimed — refused for non-canonical bytes, or for naming no adaptor
    // profile — and reported `invalid` for a capability gap, which is the contradiction §7.7
    // exists to forbid. The JCS check and the profile resolution keep their order behind it.
    if let Some(report) = unsupported_version(&receipt, evaluation) {
        return Ok(report);
    }

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
        _ => Ok(rejected(&receipt, &core, evaluation, options, policy)),
    }
}

/// The locally configured conditions this run applied, and the findings the same checks raised.
///
/// Evaluated on every completed run, not only on an accepted one, so `policy_overlays[]` says
/// what this verifier's own policy found rather than only what it was able to act on. Where the
/// receipt's own result is already something other than `valid` an overlay changes nothing —
/// `Report::apply_policy_overlays` moves only `valid` — and it is reported because a holder
/// deciding what to fix is better served by both facts than by one.
///
/// `established` is the caller's answer to "did this run establish the cosignature a freshness
/// overlay would speak of". It is not read from the carried assurance on a rejected receipt: a
/// receipt is free to carry `witnessed: true` beside a cosignature that does not verify, and an
/// overlay whose detail begins "the cosigned checkpoint's `checkpoint_time`" would then assert
/// something this run refuted. See [`cosignature_established`].
fn policy_overlays(
    receipt: &Value,
    established: bool,
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
) -> (Vec<PolicyOverlayOut>, Vec<Finding>) {
    let mut overlays = Vec::new();
    let mut findings = Vec::new();
    if !established {
        return (overlays, findings);
    }

    // Resolving the chain again here is what supplies the cadence and the grace period the
    // freshness check needs, under the same §7.4.1 rules rather than a weaker walk.
    let Ok(entries) = chain_entries(receipt) else { return (overlays, findings) };
    let Ok((governance, _)) = Governance::resolve(&entries, &policy.trust) else {
        return (overlays, findings);
    };
    let checkpoint = receipt.get("anchoring").and_then(|anchoring| anchoring.get("checkpoint"));

    match freshness(&governance, checkpoint, evaluation) {
        Ok(Some(finding)) => {
            // Staleness is a finding, never by itself a disproof. `--require-fresh` makes it a
            // POLICY OVERLAY of this run — `unverifiable`, never `invalid` — reported in its
            // own field rather than among the receipt's required assertions, which §7.7
            // enumerates exactly.
            if options.require_fresh {
                overlays.push(PolicyOverlayOut {
                    overlay: FRESHNESS.to_owned(),
                    outcome: CoreOutcome::Unverifiable.name().to_owned(),
                    detail: finding.detail.clone(),
                });
            }
            findings.push(finding);
        }
        Ok(None) => {}
        Err(detail) => findings.push(Finding::new("witness-freshness-unavailable", detail)),
    }
    (overlays, findings)
}

/// Whether this run established the cosignature a freshness overlay would speak of.
///
/// Nothing here is read from `claim.assurance`: a receipt is free to carry `witnessed: true`
/// beside a cosignature that does not verify, or beside none at all, and taking that claim at
/// its word would put "the cosigned checkpoint's `checkpoint_time` is …" in a report over a
/// cosignature this very run refuted. Freshness is a statement about a cosignature; where none
/// was established there is no statement to make.
///
/// Three conditions, each answering a different question, all about the receipt's own material —
/// an embedded receipt's cosignatures say nothing about this one's checkpoint:
///
/// * `anchoring.witnesses[]` is carried and non-empty — there is a cosignature to speak OF.
///   This is the one that holds below L3, where §3.3 requires no cosignature at all and the
///   `witnesses` assertion therefore verifies over a receipt carrying none;
/// * the `witnesses` assertion verified — the cosignatures that were named check out, and where
///   the level requires one, one exists;
/// * the `checkpoint-authentication` assertion verified — the checkpoint they cosigned
///   authenticates in its own right, so `checkpoint_time` is a member of an object this run
///   accepted.
///
/// The aggregate `cross-field` assertion is deliberately NOT among them. It carries every §7.6
/// rule, not only the one about `witnessed`, so requiring it would withhold a true and useful
/// overlay from every receipt whose cross-field defect lies somewhere else — a mismatched
/// subject, an embedded ordering violation — none of which says anything about whether the
/// cosignature verified. The carried-array condition closes the case §7.6 would have closed
/// here, and closes only that case.
fn cosignature_established(receipt: &Value, assertions: &[AssertionOut]) -> bool {
    let carried = receipt
        .get("anchoring")
        .and_then(|anchoring| anchoring.get("witnesses"))
        .and_then(Value::as_array)
        .is_some_and(|witnesses| !witnesses.is_empty());
    let verified = |name: &str| {
        assertions.iter().any(|entry| {
            entry.assertion == name
                && entry.receipt_path.is_empty()
                && entry.outcome == CoreOutcome::Verified.name()
        })
    };
    carried
        && verified(Assertion::Witnesses.name())
        && verified(Assertion::CheckpointAuthentication.name())
}

/// The `(reason_code, reason)` a core finding leads a report with: its assertion's stable name,
/// and the rule it rendered.
fn headline(finding: Option<&CoreFinding>) -> Option<(String, String)> {
    let finding = finding?;
    Some((
        finding.assertion.name().to_owned(),
        finding.detail.clone().unwrap_or_else(|| finding.assertion.name().to_owned()),
    ))
}

/// The one policy overlay this build applies: whether the cosignature the result rests on is
/// fresh at the run's evaluation time. See the module header for why it is not a §7.7 assertion
/// and why it can never be `invalid`.
const FRESHNESS: &str = "witness-freshness";

/// The version result of I-D §7.5 step 1, where either container version is one this build does
/// not implement.
///
/// Only a version that is CARRIED, is a string, and differs from the implemented one stops the
/// run here. An absent or non-string member is a structural defect of the container — decided
/// from the receipt's own bytes, `invalid` on the `structure` assertion — so it falls through to
/// the steps below rather than being promoted to a capability gap.
///
/// The report carries the version assertion and nothing else: §7.5 step 1 follows an
/// unimplemented version with "no further processing", so no claim type, no assurance block and
/// no boundary is read off bytes this build has stated it cannot interpret.
fn unsupported_version(receipt: &Value, evaluation: &EvaluationTime) -> Option<Report> {
    // Sequentially, in the core's own order, and stopping at the first member that is not a
    // carried string. Scanning past such a member to reach a later one would report `versions`
    // and `unverifiable` over a receipt whose FIRST version member the core never got past —
    // material §7.7's first bullet makes `invalid`, decidable from the receipt's own bytes.
    // A preflight that answered `unverifiable` there would state a capability gap where the
    // core states a defect, which is the disagreement between two verifiers §7.7 forbids.
    let mut mismatch = None;
    for (field, expected) in
        [("ahl_receipt_version", RECEIPT_VERSION), ("spec_version", SPEC_VERSION)]
    {
        // `?` here is the stop: a member that is not a carried string ends the preflight for
        // the whole receipt, and the core decides it.
        let got = receipt.get(field).and_then(Value::as_str)?;
        if got != expected {
            mismatch = Some((field, expected, got.to_owned()));
            break;
        }
    }
    let (field, expected, got) = mismatch?;

    // The core's own wording, so a consumer reads the same reason whichever of the two reached
    // the version first.
    let detail = ReceiptError::UnsupportedVersion { field, expected, got }.to_string();
    let mut report = Report::over_receipt(
        Outcome::Unverifiable,
        Assertion::Versions.name(),
        detail.clone(),
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.assertions = Some(vec![AssertionOut {
        assertion: Assertion::Versions.name().to_owned(),
        outcome: CoreOutcome::Unverifiable.name().to_owned(),
        receipt_path: Vec::new(),
        detail: Some(detail),
        // Its own check produced it: the version read is what stopped the run.
        rests_on: None,
    }]);
    report.informative = Some(Vec::new());
    Some(report)
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
            rests_on: finding.rests_on.map(|assertion| assertion.name().to_owned()),
        })
        .collect()
}

/// The void entries the run inspected, in the order it inspected them (I-D §7.5.1 4d).
///
/// Copied across verbatim and kept apart from the assertions: they are informative, and a
/// verifier that folded them into `assertions[]` would give every one of them an outcome the
/// model does not assign and a place in a reduction the model keeps them out of.
fn informative(core: &CoreReport) -> Vec<InformativeOut> {
    core.informative
        .iter()
        .map(|item| InformativeOut {
            entry_index: item.entry_index,
            reason: item.reason.name().to_owned(),
            receipt_path: item.receipt_path.clone(),
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

/// Render a non-`verified` result: the §6 outcome, the assertion that produced it, and the
/// assurance the receipt claimed.
///
/// No boundary is rendered — §7.7 permits only `verified` to be "rendered in words that assert
/// the property" — and the assurance block is reproduced as carried rather than rewritten to
/// express the result.
fn rejected(
    receipt: &Value,
    core: &CoreReport,
    evaluation: &EvaluationTime,
    options: &Options,
    policy: &LoadedPolicy,
) -> Report {
    let outcome = match core.result {
        CoreOutcome::Invalid => Outcome::Invalid,
        // `Verified` cannot reach here: it is handled above, and a report carrying no verdict
        // is not one. Mapping it alongside `Unverifiable` keeps the match total without
        // inventing an outcome for a state the core does not produce.
        CoreOutcome::Unverifiable | CoreOutcome::Verified => Outcome::Unverifiable,
    };
    // The CAUSE, from the core, not the first non-`verified` finding in report order: where a
    // budget ran out, every assertion the run could not reach inherits the gap, and leading
    // with one of those would name the symptom while the fact §7.8 requires — which budget, and
    // the value in force — sits on a finding further down.
    let (reason_code, reason) = headline(core.dominating()).unwrap_or_else(|| {
        (core.result.name().to_owned(), format!("the receipt is {}", core.result))
    });

    let mut report = Report::over_receipt(
        outcome,
        reason_code,
        reason,
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.claim_type = receipt
        .get("claim")
        .and_then(|claim| claim.get("type"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    report.assurance = carried_assurance(receipt);
    let assertions = assertions(core);
    // Reported, and unable to change anything: the receipt's own result is not `valid`, so
    // `apply_policy_overlays` leaves `outcome` where `status` put it. Emitted at all only where
    // this run established the cosignature it would speak of.
    let established = cosignature_established(receipt, &assertions);
    report.assertions = Some(assertions);
    report.informative = Some(informative(core));
    let (overlays, findings) = policy_overlays(receipt, established, policy, evaluation, options);
    report.policy_overlays = overlays;
    report.apply_policy_overlays();
    report.with_findings(findings)
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
    let assertions = assertions(core);
    // The core reached `verified`, so every assertion `cosignature_established` looks for holds;
    // the carried `witnessed` is the verified value and is what decides whether there is a
    // cosignature to be fresh about at all.
    let (overlays, mut findings) =
        policy_overlays(receipt, verdict.assurance.witnessed, policy, evaluation, options);

    // The chain the freshness check resolved also carries the §7.3 schema findings, and those
    // are reported for an accepted receipt because there is a result for them to qualify.
    if let Ok(entries) = chain_entries(receipt) {
        if let Ok((governance, _)) = Governance::resolve(&entries, &policy.trust) {
            findings.extend(governance.log_object_findings());
        }
    }

    // `status` is the receipt's own result and this arm is the `verified` one, so it is `Valid`
    // here whatever local policy says; `outcome` is decided from it below, by
    // `Report::apply_policy_overlays`.
    let outcome = Outcome::Valid;

    // The headline describes `outcome`. The core's cause outranks the overlay: a receipt that
    // also failed a required assertion failed it for a reason its holder must be told first,
    // while freshness is a condition of this run. `dominating()` is `None` on this arm, so the
    // overlay leads where it fired; the ordering is written out because an overlay silently
    // outranking a core cause is what the split exists to prevent.
    let (reason_code, reason) = headline(core.dominating())
        .or_else(|| {
            let overlay = overlays.first()?;
            Some((overlay.overlay.clone(), overlay.detail.clone()))
        })
        .unwrap_or_else(|| ("verified".to_owned(), "every required rule verified".to_owned()));

    let mut report = Report::over_receipt(
        outcome,
        reason_code,
        reason,
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.claim_type = Some(verdict.claim_type.clone());
    // Only `verified` may be rendered in words that assert the property, and never more
    // strongly than the boundary `ahl_core::receipt::Verdict` carries. This arm has the
    // receipt's own result at `valid`; `apply_policy_overlays` below takes the boundary away
    // again where a locally configured condition moves the run's decision off it.
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
    report.assertions = Some(assertions);
    report.informative = Some(informative(core));
    report.policy_overlays = overlays;
    report.apply_policy_overlays();
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
            assert_eq!(report.status, Some(status), "{file}: {}", report.reason);

            // Void entries are counted, never adjudicated: the corpus states how many each
            // vector carries, and a vector that carries some still reaches the result its
            // `expect` names — a void entry is not a defect of the receipt that revealed it.
            let void = vector["informative"].as_u64().unwrap_or(0);
            let reported = report.informative.as_ref().expect("void entries are reported");
            assert_eq!(
                u64::try_from(reported.len()).expect("small count"),
                void,
                "{file}: {reported:?}"
            );
            for item in reported {
                assert!(
                    ["signature-invalid", "key-not-active"].contains(&item.reason.as_str()),
                    "{file}: unknown void reason `{}`",
                    item.reason
                );
            }

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
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
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
    fn an_unsupported_version_stops_the_run_before_any_other_check() {
        // §7.5 step 1 reads the version "BEFORE ANY OTHER CHECK, including schema validation",
        // and §7.1 follows an unimplemented one with no further processing. Each receipt below
        // breaks a rule that would otherwise be reached first and reported `invalid`.
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = corpus_policy(true);
        let source: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");

        let run_over = |name: &str, value: &Value, canonical: bool| {
            let path = dir.path().join(name);
            let bytes = if canonical {
                ahl_core::jcs(value)
            } else {
                serde_json::to_vec_pretty(value).expect("pretty")
            };
            std::fs::write(&path, bytes).expect("write");
            run(&policy, &at_corpus_time(), &Options { receipt: path, require_fresh: false })
        };

        // The version alone.
        let mut old_version = source;
        old_version["spec_version"] = json!("0.3.0");
        let report = run_over("v.ahl", &old_version, true);
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(report.reason_code, "versions");

        // The version, on bytes that are not the JCS serialization.
        let report = run_over("v-noncanonical.ahl", &old_version, false);
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(report.reason_code, "versions");

        // The version, on a receipt naming no adaptor profile.
        let mut no_adaptor = old_version;
        no_adaptor["anchoring"]["adaptor"] = json!({});
        let report = run_over("v-no-adaptor.ahl", &no_adaptor, true);
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(report.reason_code, "versions");
        assert!(report.reason.contains("0.3.0"), "the carried value is named: {}", report.reason);

        // Nothing is read off bytes this build has said it cannot interpret.
        assert!(report.boundary.is_none());
        assert!(report.assurance.is_none());
        assert!(report.claim_type.is_none());
        let assertions = report.assertions.as_ref().expect("the version finding is reported");
        assert_eq!(assertions.len(), 1, "no further processing: {assertions:?}");
        assert_eq!(assertions[0].assertion, "versions");
        assert_eq!(assertions[0].outcome, "unverifiable");
    }

    #[test]
    fn the_preflight_reads_the_version_members_in_order_and_stops_at_the_first_defect() {
        // §7.5 step 1 reads `ahl_receipt_version` first, and the core stops there. A preflight
        // that scanned past a malformed first member to reach an old `spec_version` would
        // answer `unverifiable` where the core answers `invalid` on `structure` — two verifiers
        // making contradictory statements about one artifact.
        let dir = tempfile::tempdir().expect("tempdir");
        let source: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");

        for broken in [None, Some(json!(2)), Some(Value::Null)] {
            let mut value = source.clone();
            match broken.clone() {
                None => {
                    value.as_object_mut().expect("object").remove("ahl_receipt_version");
                }
                Some(member) => value["ahl_receipt_version"] = member,
            }
            // An old second member the preflight must NOT reach past the defective first one.
            value["spec_version"] = json!("0.3.0");
            let path = dir.path().join("first-member.ahl");
            std::fs::write(&path, ahl_core::jcs(&value)).expect("write");
            let report = run(
                &corpus_policy(true),
                &at_corpus_time(),
                &Options { receipt: path, require_fresh: false },
            );
            assert_eq!(
                report.status,
                Some("invalid"),
                "{broken:?}: the core decides the malformed first member: {}",
                report.reason
            );
        }

        // And a carried string that simply is not the implemented one still stops the run.
        let mut value = source;
        value["ahl_receipt_version"] = json!("1");
        let path = dir.path().join("old-first-member.ahl");
        std::fs::write(&path, ahl_core::jcs(&value)).expect("write");
        let report = run(
            &corpus_policy(true),
            &at_corpus_time(),
            &Options { receipt: path, require_fresh: false },
        );
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(report.reason_code, "versions");
        assert!(report.reason.contains("ahl_receipt_version"), "{}", report.reason);
    }

    #[test]
    fn a_version_member_that_is_absent_or_not_a_string_is_a_structural_defect_not_a_gap() {
        // The short circuit is for a version this build does not implement, never for one the
        // container does not carry: that is decidable from the bytes, and the core decides it.
        let dir = tempfile::tempdir().expect("tempdir");
        let source: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");
        for broken in [json!(2), Value::Null] {
            let mut value = source.clone();
            value["spec_version"] = broken;
            let path = dir.path().join("x.ahl");
            std::fs::write(&path, ahl_core::jcs(&value)).expect("write");
            let report = run(
                &corpus_policy(true),
                &at_corpus_time(),
                &Options { receipt: path, require_fresh: false },
            );
            assert_eq!(report.status, Some("invalid"), "{}", report.reason);
        }
    }

    #[test]
    fn a_completed_pre_core_result_reports_the_assertion_it_settled() {
        // §7.7: "A verifier MUST report the findings alongside it." These runs reached one of
        // the three values over the receipt's own bytes, so each names the assertion the core
        // would have filed it under — the CLI's own rows are not where `assertions[]` goes
        // silent.
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = corpus_policy(true);
        let source: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");

        let sole = |report: &Report| -> (String, String) {
            let assertions = report.assertions.as_ref().expect("the assertion is reported");
            assert_eq!(assertions.len(), 1, "{assertions:?}");
            assert!(assertions[0].receipt_path.is_empty());
            assert!(assertions[0].rests_on.is_none(), "nothing ran before it to rest on");
            assert!(assertions[0].detail.is_some());
            (assertions[0].assertion.clone(), assertions[0].outcome.clone())
        };

        // Bytes that are not JSON at all: structural, and `invalid`.
        let path = dir.path().join("broken.ahl");
        std::fs::write(&path, b"{not json").expect("write");
        let report =
            run(&policy, &at_corpus_time(), &Options { receipt: path, require_fresh: false });
        assert_eq!(report.status, Some("invalid"));
        assert_eq!(sole(&report), ("structure".to_owned(), "invalid".to_owned()));

        // Bytes that are JSON but not the JCS serialization.
        let path = dir.path().join("pretty.ahl");
        std::fs::write(&path, serde_json::to_vec_pretty(&source).expect("pretty")).expect("write");
        let report =
            run(&policy, &at_corpus_time(), &Options { receipt: path, require_fresh: false });
        assert_eq!(report.status, Some("invalid"));
        assert_eq!(sole(&report), ("structure".to_owned(), "invalid".to_owned()));

        // A profile local policy does not hold: `unverifiable`, on the profile assertion.
        let mut without = corpus_policy(true);
        without.profiles.clear();
        without.trust.adaptor_profiles.clear();
        let report = verify_vector("statement-anchored-valid.ahl", &without);
        assert_eq!(report.status, Some("unverifiable"));
        assert_eq!(sole(&report), ("adaptor-profile".to_owned(), "unverifiable".to_owned()));

        // And a run that reached no result at all reports none: it is not a receipt report.
        let report = run(
            &policy,
            &at_corpus_time(),
            &Options { receipt: dir.path().join("absent.ahl"), require_fresh: false },
        );
        assert_eq!(report.outcome, "error");
        assert!(report.assertions.is_none(), "a local failure carries no §7.7 value");
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
        assert_eq!(absent.outcome, "error");

        let malformed_path = dir.path().join("bad.ahl");
        std::fs::write(&malformed_path, b"{not json").expect("write");
        let malformed = run(
            &policy,
            &at_corpus_time(),
            &Options { receipt: malformed_path, require_fresh: false },
        );
        assert_eq!(malformed.status, Some("invalid"));
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
        assert_eq!(report.status, Some("invalid"));
        assert!(report.reason.contains("JCS-canonical"), "{}", report.reason);
    }

    #[test]
    fn a_profile_that_is_not_locally_possessed_is_unverifiable_not_invalid() {
        let mut policy = corpus_policy(true);
        policy.profiles.clear();
        policy.trust.adaptor_profiles.clear();
        let report = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(report.status, Some("unverifiable"));
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
        assert_eq!(report.outcome, "error");
        assert_eq!(report.reason_code, "profile-broken");
    }

    #[test]
    fn the_receipt_note_is_carried_as_a_quotation_and_never_as_a_finding() {
        // The note is informative: it is attributed to the receipt and never rendered as
        // something the run established.
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, Some("valid"), "{}", report.reason);
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
        assert_eq!(finding_only.status, Some("valid"), "staleness is never by itself a disproof");
        assert!(finding_only.findings.iter().any(|f| f.code == "witness-stale"));

        assert!(finding_only.boundary.is_some(), "a valid result renders the boundary");
        let assertions = finding_only.assertions.as_ref().expect("assertions");
        assert!(
            assertions.iter().all(|entry| entry.outcome == "verified"),
            "without the flag nothing overlays the core's set: {assertions:?}"
        );
        assert_eq!(Some(reduction(assertions)), finding_only.status);
        assert!(
            finding_only.policy_overlays.is_empty(),
            "without the flag freshness is a finding, not an overlay"
        );
        assert_eq!(Some(finding_only.outcome), finding_only.status, "no overlay, no difference");
        assert!(!finding_only.to_text().contains("receipt result:"));

        let promoted = run(&policy, &much_later, &Options { receipt: path, require_fresh: true });
        // The receipt's own result is untouched; the run's decision carries the overlay, and
        // the exit code follows the decision.
        assert_eq!(promoted.status, Some("valid"), "local policy never rewrites the §7.7 result");
        assert_eq!(promoted.outcome, "unverifiable");
        assert!(promoted.findings.iter().any(|f| f.code == "witness-stale"));
        // A boundary asserts the property in words, so it is rendered where the FINAL status is
        // `valid` and nowhere else — never carried over from a core result the overlay moved.
        assert!(promoted.boundary.is_none(), "no boundary under a non-valid status");
        assert!(!promoted.to_text().contains("boundary:"), "{}", promoted.to_text());

        // §7.7 enumerates the required assertions exactly, and freshness is not among them:
        // the core's set is untouched and the overlay is reported in its own field.
        let assertions = promoted.assertions.as_ref().expect("assertions");
        assert!(
            assertions.iter().all(|entry| entry.outcome == "verified"),
            "the core's required assertions are untouched by an overlay: {assertions:?}"
        );
        assert!(
            !assertions.iter().any(|entry| entry.assertion == FRESHNESS),
            "an overlay is never a §7.7 assertion: {assertions:?}"
        );
        assert_eq!(reduction(assertions), "valid", "the reduction alone is still `valid`");

        let overlay =
            promoted.policy_overlays.first().expect("the overlay is reported in its own field");
        assert_eq!(overlay.overlay, FRESHNESS);
        assert_eq!(overlay.outcome, "unverifiable", "an overlay never yields `invalid`");
        assert!(
            overlay.detail.contains("ns old at the evaluation time"),
            "the age is named: {}",
            overlay.detail
        );
        assert!(
            overlay.detail.contains("grace period"),
            "the grace period is named: {}",
            overlay.detail
        );
        // `status` is the reduction of the assertions and stays there; `outcome` is what the
        // overlay moved, and the text spells the difference out on its own line.
        assert_eq!(Some(reduction(assertions)), promoted.status);
        assert_eq!(promoted.reason_code, FRESHNESS, "the headline describes `outcome`");
        let text = promoted.to_text();
        assert!(text.starts_with("outcome: unverifiable\n"), "{text}");
        assert!(
            text.contains("receipt result: valid; policy: unverifiable (witness-freshness)"),
            "{text}"
        );
        assert!(text.contains("policy overlays:"), "{text}");
    }

    /// The §7.7 reduction over a reported assertion set, in the CLI's own status vocabulary.
    ///
    /// An embedded receipt's content binding is never a required assertion of the receipt that
    /// embeds it, so it is outside the reduction at every non-empty path.
    fn reduction(assertions: &[AssertionOut]) -> &'static str {
        let counts = |entry: &&AssertionOut| {
            entry.assertion != "content-binding" || entry.receipt_path.is_empty()
        };
        let has =
            |outcome: &str| assertions.iter().filter(counts).any(|entry| entry.outcome == outcome);
        if has("invalid") {
            "invalid"
        } else if has("unverifiable") {
            "unverifiable"
        } else {
            "valid"
        }
    }

    #[test]
    fn the_headline_is_the_cause_and_never_an_assertion_that_inherited_the_gap() {
        // An exhausted budget leaves every assertion the run could not reach resting on it. The
        // reader needs the budget and the value in force (§7.8), which sit on the cause; a
        // headline taken from report order would name a derived finding instead.
        let mut policy = corpus_policy(true);
        policy.trust.limits.max_work_units = 3;
        let report = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(report.reason_code, "resource-limits");
        assert!(report.reason.contains("verification work units"), "{}", report.reason);
        assert!(report.reason.contains('3'), "the value in force: {}", report.reason);

        // The derived findings are reported beside it, each naming what it rests on as a value
        // rather than only in prose.
        let assertions = report.assertions.as_ref().expect("assertions");
        let cause = assertions
            .iter()
            .find(|entry| entry.assertion == "resource-limits")
            .expect("the cause is reported");
        assert!(cause.rests_on.is_none(), "a cause inherits nothing");
        assert!(
            assertions.iter().any(|entry| entry.rests_on.as_deref() == Some("resource-limits")),
            "the derived findings name the cause: {assertions:?}"
        );
    }

    #[test]
    fn the_freshness_overlay_never_displaces_a_core_cause() {
        // The overlay is a condition of this run; a receipt that also failed a required
        // assertion failed it for a reason its holder must be told first. The corpus policy
        // withholds the dataset key, so the core reaches `unverifiable` on its own, and
        // `--require-fresh` is given over an evaluation time at which the cosignature is stale.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let report = run(
            &corpus_policy(false),
            &much_later,
            &Options {
                receipt: corpus().join("receipts/record-ingested-valid.ahl"),
                require_fresh: true,
            },
        );
        assert_eq!(report.status, Some("unverifiable"), "{}", report.reason);
        assert_eq!(
            report.reason_code, "content-binding",
            "the core's cause leads, not the CLI overlay: {}",
            report.reason
        );
    }

    #[test]
    fn an_overlay_beside_a_rejected_receipt_is_reported_and_changes_nothing() {
        // A condition of this run is worth reporting whatever the receipt's own result was, and
        // it can never move a result that was not `valid`: a demonstrated defect outranks it.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let report = run(
            &corpus_policy(true),
            &much_later,
            &Options {
                // A vector whose defect is in its claim material: the cosignature, the
                // checkpoint under it and the §7.6 rules all verify, so the overlay has
                // something established to speak of.
                receipt: corpus().join("receipts/record-derived-wrong-path-must-fail.ahl"),
                require_fresh: true,
            },
        );
        assert_eq!(report.status, Some("invalid"), "{}", report.reason);
        assert_eq!(report.outcome, "invalid", "an overlay never weakens an `invalid`");
        assert_eq!(report.reason_code, "claim-material", "the core's cause still leads");
        assert!(
            report.policy_overlays.iter().any(|overlay| overlay.overlay == FRESHNESS),
            "the overlay is still listed: {:?}",
            report.policy_overlays
        );
        assert!(!report.to_text().contains("receipt result:"), "nothing to disambiguate");
    }

    #[test]
    fn a_void_entry_is_counted_and_never_moves_the_result() {
        // I-D §7.5.1 4d: a non-verifying envelope the receipt does not rest on is VOID —
        // excluded, never effective, never traversed, and it does not affect the result. The
        // corpus carries vectors that verify WITH void entries in them, which is the whole
        // point: a log anchors opaque bytes and validates none, so were a void entry a defect
        // of every later receipt, any party able to anchor one envelope could disable every
        // enumerated claim of that log from that index on.
        let policy = corpus_policy(true);
        let index = corpus_index();
        let mut checked = 0;
        for vector in index["vectors"].as_array().expect("vectors") {
            let Some(void) = vector["informative"].as_u64() else { continue };
            assert!(void > 0, "the corpus only records the member where there are void entries");
            let file = vector["file"].as_str().expect("file");
            let report = verify_vector(file, &policy);
            let reported = report.informative.as_ref().expect("void entries are reported");
            assert_eq!(u64::try_from(reported.len()).expect("small"), void, "{file}");

            if vector["expect"] == "verified" {
                assert_eq!(report.status, Some("valid"), "{file}: {}", report.reason);
                assert_eq!(report.outcome, "valid", "{file}");
                assert_eq!(report.reason_code, "verified", "{file}: a void entry never leads");
                assert!(report.boundary.is_some(), "{file}: a verified receipt keeps its boundary");
            }
            // Never a finding, whatever the result: the two lists do not overlap.
            let assertions = report.assertions.as_ref().expect("assertions");
            assert!(
                assertions.iter().all(|entry| entry.assertion != "void-entry"),
                "{file}: a void entry is not an assertion: {assertions:?}"
            );
            checked += 1;
        }
        assert!(checked >= 3, "the corpus should carry vectors with void entries, got {checked}");
    }

    #[test]
    fn the_text_surface_lists_void_entries_under_their_own_heading() {
        let policy = corpus_policy(true);
        let index = corpus_index();
        let file = index["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|vector| vector["expect"] == "verified" && vector["informative"].is_number())
            .and_then(|vector| vector["file"].as_str())
            .expect("a verified vector carrying void entries");
        let report = verify_vector(file, &policy);
        let text = report.to_text();
        assert!(text.starts_with("outcome: valid\n"), "{file}: {text}");
        assert!(text.contains("void entries:\n"), "{file}: {text}");
        assert!(text.contains("entry index "), "{file}: {text}");
        assert!(!text.contains("findings:"), "{file}: a void entry is not a finding: {text}");
    }

    #[test]
    fn a_freshness_overlay_is_never_emitted_over_a_cosignature_this_run_refuted() {
        // A receipt is free to carry `witnessed: true` beside a cosignature that does not
        // verify. Taking that claim at its word would put "the cosigned checkpoint's
        // `checkpoint_time` is …" in a report over a cosignature this very run refuted — a
        // diagnostic asserting what the result denies.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut forged: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");
        assert_eq!(
            forged["claim"]["assurance"]["witnessed"],
            json!(true),
            "the vector claims a witnessed checkpoint, and keeps claiming it"
        );
        forged["anchoring"]["witnesses"][0]["cosignature"] =
            json!(format!("base64:{}==", "A".repeat(86)));
        let path = dir.path().join("forged-witness.ahl");
        std::fs::write(&path, ahl_core::jcs(&forged)).expect("write");

        // A year past the cadence, so the carried `checkpoint_time` is unambiguously old.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let report =
            run(&corpus_policy(true), &much_later, &Options { receipt: path, require_fresh: true });
        assert_eq!(report.status, Some("invalid"), "{}", report.reason);
        assert_eq!(report.outcome, "invalid", "an overlay never weakens an `invalid`");
        let assertions = report.assertions.as_ref().expect("assertions");
        assert!(
            assertions
                .iter()
                .any(|entry| entry.assertion == "witnesses" && entry.outcome == "invalid"),
            "the cosignature is what failed: {assertions:?}"
        );
        assert!(
            report.policy_overlays.is_empty(),
            "nothing about the cosignature was established: {:?}",
            report.policy_overlays
        );
        assert!(
            !report.findings.iter().any(|finding| finding.code == "witness-stale"),
            "the finding comes from the same check and is withheld with it: {:?}",
            report.findings
        );
        assert!(!report.to_text().contains("cosigned checkpoint"), "{}", report.to_text());
    }

    #[test]
    fn a_cross_field_defect_unrelated_to_the_witness_does_not_withhold_the_overlay() {
        // The gate asks whether the cosignature was established, not whether the receipt is
        // otherwise sound. Requiring the aggregate `cross-field` assertion would withhold a true
        // overlay from every receipt whose cross-field defect lies somewhere else entirely,
        // which says nothing about whether the cosignature verified.
        let much_later = EvaluationTime::resolve(Some("2027-08-16T12:00:00Z")).expect("instant");
        let report = run(
            &corpus_policy(true),
            &much_later,
            &Options {
                // `governance` overstated in the assurance block: `cross-field` is `invalid`,
                // the cosignature and the checkpoint under it are untouched.
                receipt: corpus().join("receipts/overclaim-must-fail.ahl"),
                require_fresh: true,
            },
        );
        assert_eq!(report.status, Some("invalid"), "{}", report.reason);
        let assertions = report.assertions.as_ref().expect("assertions");
        assert!(
            assertions
                .iter()
                .any(|entry| entry.assertion == "cross-field" && entry.outcome == "invalid"),
            "this vector's defect is a cross-field one: {assertions:?}"
        );
        for established in ["witnesses", "checkpoint-authentication"] {
            assert!(
                assertions
                    .iter()
                    .any(|entry| entry.assertion == established && entry.outcome == "verified"),
                "`{established}` verified, so the cosignature stands: {assertions:?}"
            );
        }
        assert!(
            report.policy_overlays.iter().any(|overlay| overlay.overlay == FRESHNESS),
            "the overlay is emitted over an established cosignature: {:?}",
            report.policy_overlays
        );
        assert_eq!(report.outcome, "invalid", "and still changes nothing");
    }

    #[test]
    fn a_receipt_carrying_no_cosignature_gets_no_freshness_overlay() {
        // Below L3 no cosignature is REQUIRED, so `witnesses` verifies over a receipt that
        // carries none — and there is then nothing for a freshness overlay to speak of. The
        // carried-array condition is what closes that case; the assertions alone would not.
        let assertions: Vec<AssertionOut> = ["witnesses", "checkpoint-authentication"]
            .into_iter()
            .map(|assertion| AssertionOut {
                assertion: assertion.to_owned(),
                outcome: CoreOutcome::Verified.name().to_owned(),
                receipt_path: Vec::new(),
                detail: None,
                rests_on: None,
            })
            .collect();
        // Both assertions verified, and `witnessed` claimed — but no cosignature is carried.
        let receipt = json!({
            "claim": { "assurance": { "witnessed": true } },
            "anchoring": { "witnesses": [] },
        });
        assert!(!cosignature_established(&receipt, &assertions));

        // The member absent entirely answers the same way.
        let receipt = json!({ "claim": { "assurance": { "witnessed": true } }, "anchoring": {} });
        assert!(!cosignature_established(&receipt, &assertions));

        // One carried cosignature, with both assertions verified, is what opens the gate.
        let receipt = json!({ "anchoring": { "witnesses": [ { "key_id": "sha256:aa" } ] } });
        assert!(cosignature_established(&receipt, &assertions));
    }

    #[test]
    fn the_status_is_the_reduction_of_the_reported_assertions_over_the_whole_corpus() {
        // Design note §6: `status` is the reduction of the assertions reported beside it. A
        // status a consumer cannot derive from the set it is shown is a status it cannot act on.
        let policy = corpus_policy(true);
        let index = corpus_index();
        for vector in index["vectors"].as_array().expect("vectors") {
            let file = vector["file"].as_str().expect("file");
            let report = verify_vector(file, &policy);
            let assertions = report.assertions.as_ref().expect("assertions are always reported");
            assert_eq!(Some(reduction(assertions)), report.status, "{file}: {}", report.reason);
        }

        // And with the one capability gap the corpus policy can withhold.
        let report = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(Some(reduction(report.assertions.as_ref().expect("assertions"))), report.status);
    }

    #[test]
    fn a_fresh_cosignature_raises_no_staleness_finding() {
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, Some("valid"));
        assert!(!report.findings.iter().any(|f| f.code == "witness-stale"));
    }

    #[test]
    fn the_regenerated_corpus_manifests_carry_the_specification_log_object() {
        // The corpus previously spelled the log id `log.id` and omitted `cadence_epoch`, and
        // this crate reported both. It now follows core §7.3, so there is nothing to report —
        // and the `log_id` spelling is required rather than aliased, which is what makes the
        // vectors below resolve at all.
        let report = verify_vector("statement-anchored-valid.ahl", &corpus_policy(true));
        assert_eq!(report.status, Some("valid"), "{}", report.reason);
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
        assert_eq!(report.status, Some("unverifiable"));
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
        assert_eq!(report.status, Some("invalid"));
    }

    #[test]
    fn each_of_the_three_results_maps_to_its_exit_code_and_never_to_another() {
        // §7.7's three values, exercised end to end so the mapping is asserted over what the
        // core actually returns rather than over a table restated here. A local failure that
        // reaches no result at all is the fourth outcome and is covered by
        // `an_unreadable_receipt_is_an_error_and_a_malformed_one_is_invalid`.
        let policy = corpus_policy(true);
        let verified = verify_vector("statement-anchored-valid.ahl", &policy);
        assert_eq!(verified.status, Some("valid"));
        assert_eq!(Outcome::Valid.exit_code(), 0);

        let invalid = verify_vector("overclaim-must-fail.ahl", &policy);
        assert_eq!(invalid.status, Some("invalid"), "{}", invalid.reason);
        assert_eq!(Outcome::Invalid.exit_code(), 1);

        let unverifiable = verify_vector("record-ingested-valid.ahl", &corpus_policy(false));
        assert_eq!(unverifiable.status, Some("unverifiable"), "{}", unverifiable.reason);
        assert_eq!(Outcome::Unverifiable.exit_code(), 3);
        assert_ne!(unverifiable.status, invalid.status, "never rendered as the other");
    }
    #[test]
    fn a_receipt_carrying_a_verifying_consistency_path_is_valid() {
        let report =
            verify_vector("statement-anchored-continued-history.ahl", &corpus_policy(true));
        assert_eq!(report.status, Some("valid"), "{}", report.reason);
        assert_eq!(
            report.assurance.as_ref().map(|assurance| assurance.continued_history),
            Some(true)
        );
    }
    #[test]
    fn an_invalid_result_prints_the_assertion_table_and_never_a_boundary() {
        let report = verify_vector("overclaim-must-fail.ahl", &corpus_policy(true));
        assert_eq!(report.status, Some("invalid"), "{}", report.reason);
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
        assert_eq!(report.status, Some("invalid"), "{}", report.reason);
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
