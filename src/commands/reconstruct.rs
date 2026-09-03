//! `reconstruct` — "as known at `C`, about `T`", and nothing more.
//!
//! Parameterized by an as-of checkpoint `C` (the knowledge boundary: statements with entry
//! index `< tree_size(C)`) and a valid time `T` (the domain time asked about). Corrections
//! anchored beyond `C` are invisible at `C` by construction; re-running at a later checkpoint
//! shows knowledge evolution.
//!
//! # What it requires beyond `closure`
//!
//! `C` must be **witnessed**, and consistency must be verified from `C` forward. Where a mode
//! requires a witnessed checkpoint, an unreachable witness makes the operation *unverifiable*
//! — it is never silently downlevelled to a weaker success.
//!
//! # Where this is deliberately weaker than core §4, and why the gap is stated
//!
//! Core §4 requires consistency to *the latest* witnessed checkpoint. **That is not observable
//! from untrusted input.** A hostile or merely lagging witness can serve an older valid
//! cosigned checkpoint or omit history, and neither core §3.3 nor adaptor §11 defines an
//! authenticated completeness proof over a witness's checkpoint history. This command
//! therefore verifies consistency to *the newest witnessed checkpoint this run obtained*, and
//! labels it exactly that way (`continued_history_bound: run-observed`). It never renders that
//! as the global latest.
//!
//! # What it returns, stated as a boundary
//!
//! v0.1 returns the **evidenced assertion set** and nothing more. *Reproducible
//! reconstruction* — the optional manifest-declared property requiring retention and retrieval
//! of referenced artifacts and canonical input/output bytes — is **out of scope for v0.1**, and
//! the result says so rather than leaving the reader to assume it. Core §4 fixes the rule a
//! later version must follow: erasure of any required content *terminates* the property for
//! the affected records, and the result must report it as terminated. Silent degradation to a
//! weaker answer is prohibited, so the v0.1 behaviour is to name the property as **not
//! evaluated** — never to imply it holds.

use ahl_core::bitemporal::{Scope, ValidTime};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::anchored::{self, Anchored, Mirror};
use crate::checkpoint::{consistency_verifies, Checkpoint};
use crate::error::{CliError, CliResult};
use crate::evaluation::{parse_artifact_time, EvaluationTime};
use crate::net::Fetcher;
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::report::{CheckpointOut, Completeness, Finding, ObservationBound, RecordOut, Report};
use crate::witness;

/// Options for one `reconstruct` run.
#[derive(Debug, Clone)]
pub struct Options {
    /// The dataset the record belongs to.
    pub dataset: String,
    /// The record commitment.
    pub record: String,
    /// The domain time asked about, RFC 3339.
    pub valid_time: String,
    /// The as-of checkpoint, by `tree_size`. Explicit, never inferred.
    pub checkpoint: Option<u64>,
}

/// One anchored statement, named by the two identifiers that matter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatementRefOut {
    /// Its position in the log — AHL's only ordering primitive.
    pub entry_index: u64,
    /// Its statement id.
    pub statement_id: String,
    /// Its statement type.
    pub statement_type: String,
}

/// The evidenced assertion set, as of `C`, about `T`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconstructionOut {
    /// The record asked about.
    pub record: RecordOut,
    /// The domain time asked about.
    pub valid_time: String,
    /// The knowledge boundary: statements with entry index below this are visible.
    pub as_of_tree_size: u64,
    /// The `ingestion` or `derivation` that introduced the record, if one is committed.
    pub introduction: Option<StatementRefOut>,
    /// Derivations naming the record as an input, ascending by entry index.
    pub consumers: Vec<StatementRefOut>,
    /// Effective triggers naming the record whose scope covers `T`, ascending.
    pub effective_triggers: Vec<StatementRefOut>,
    /// The trigger that governs at `C` — among conflicting effective triggers, the greatest
    /// entry index governs.
    pub governing_trigger: Option<StatementRefOut>,
    /// `as-asserted`, `retracted` or `corrected`.
    pub status: &'static str,
    /// Where a correction governs, the commitment it names as the replacement.
    pub replacement: Option<String>,
    /// Always `not-evaluated` in v0.1 — named, never implied to hold.
    pub reproducible_reconstruction: &'static str,
}

/// Run `reconstruct`.
#[must_use]
pub fn run<F: Fetcher>(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
    fetcher: Option<&F>,
) -> Report {
    reconstruct(policy, evaluation, options, fetcher).unwrap_or_else(|error| {
        Report::new(
            error.outcome(),
            error.reason_code(),
            error.to_string(),
            evaluation.rendered.clone(),
            evaluation.source,
        )
    })
}

fn reconstruct<F: Fetcher>(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
    fetcher: Option<&F>,
) -> CliResult<Report> {
    let tree_size = options.checkpoint.ok_or_else(|| {
        CliError::Usage(
            "`reconstruct` needs `--checkpoint <tree_size>`: the as-of checkpoint is the \
             knowledge boundary and is chosen explicitly, never inferred"
                .to_owned(),
        )
    })?;
    let asked_about = parse_artifact_time("--valid-time", &options.valid_time)?;

    let base = policy.endpoints.mirror.as_deref().ok_or_else(|| {
        CliError::Usage("`reconstruct` needs a mirror: configure `[endpoints] mirror`".to_owned())
    })?;
    let witness_base = policy.endpoints.witness.as_deref().ok_or_else(|| {
        CliError::Usage(
            "`reconstruct` needs a witness: core spec §4 fixes the as-of checkpoint as a \
             witnessed one, and an unwitnessed reconstruction is not a weaker success"
                .to_owned(),
        )
    })?;
    let fetcher = fetcher.ok_or_else(|| {
        CliError::Usage("`reconstruct` needs a network or a recorded transcript".to_owned())
    })?;

    let profile_id = crate::profile::resolve_all(policy)?
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| CliError::ProfileNotPossessed { id: "<none configured>".to_owned() })?;
    let mirror = Mirror::new(fetcher, base, &profile_id, policy.network)?;
    let anchored = anchored::establish(&mirror, policy, tree_size)?;

    let mut findings = anchored.findings.clone();
    findings.extend(witnessed(fetcher, witness_base, &anchored, &mirror, policy)?);

    let reconstruction = assemble(&anchored, options, asked_about)?;
    findings.sort();
    findings.dedup();

    let mut report = Report::new(
        Outcome::Valid,
        "reconstructed",
        format!(
            "the evidenced assertion set for `{}`/`{}` as known at tree_size {tree_size}, about \
             {}. Reproducible reconstruction is out of scope in v0.1 and was not evaluated",
            options.dataset, options.record, options.valid_time
        ),
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.authenticated = true;
    report.completeness = Completeness::Complete;
    report.checkpoint = Some(CheckpointOut::of(&anchored.checkpoint));
    report.series_usable_bound = Some(ObservationBound::RunObserved);
    report.continued_history_bound = Some(ObservationBound::RunObserved);
    report.reconstruction = Some(reconstruction);
    Ok(report.with_findings(findings))
}

/// Establish that `C` is witnessed, and verify consistency from `C` forward to the newest
/// witnessed checkpoint **this run obtained**.
///
/// The cosigned *history* is read rather than the witness's single newest checkpoint, because
/// the question here is "is `C` witnessed?", and an endpoint that answers "here is the newest"
/// answers a different one. The newest member is then used for the forward-consistency step,
/// and — because the witness key set for a checkpoint is resolved from the manifest version
/// governing **its** `tree_size`, which may be anchored beyond `C` — a second view is
/// established at that member before its cosignature is checked. Resolving a later
/// checkpoint's witness key from `C`'s governance would validate a cosignature under a key set
/// the corpus had already replaced.
// The §11 witness checks in the order they must run: `C` is witnessed, then the forward
// consistency step, then the second view a later checkpoint's own governance requires. The
// order is the content, so it stays in one place.
#[allow(clippy::too_many_lines)]
fn witnessed<F: Fetcher>(
    fetcher: &F,
    witness_base: &str,
    anchored: &Anchored,
    mirror: &Mirror<'_, F>,
    policy: &LoadedPolicy,
) -> CliResult<Vec<Finding>> {
    let url = format!(
        "{}/v1/logs/{}/checkpoints",
        witness_base.trim_end_matches('/'),
        anchored.checkpoint.log_id
    );
    // Never cached: a valid old cosigned checkpoint is a replay of "what is newest?".
    let response = fetcher
        .fetch(&crate::net::Request::get(url))
        .map_err(crate::net::FetchFailure::into_cli_error)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the witness answered {} and no cosigned history was obtained; reconstruction \
             requires a witnessed checkpoint and is never downlevelled to a weaker success",
            response.status
        )));
    }
    let history: Vec<Value> = serde_json::from_slice(&response.body).map_err(|source| {
        CliError::EvidenceMissing(format!("the witness did not answer with JSON: {source}"))
    })?;

    // --- `C` itself must be witnessed -------------------------------------------------
    let keys_for_c = anchored
        .governance
        .witness_keys_for(anchored.checkpoint.tree_size)
        .map_err(|error| CliError::EvidenceMissing(error.to_string()))?;
    let trusted_for_c = with_locally_trusted(&keys_for_c, policy);
    let mut witnessed_c = false;
    for cosigned in &history {
        let Some(value) = cosigned.get("checkpoint") else { continue };
        let Ok(checkpoint) = Checkpoint::from_value(value) else { continue };
        if !checkpoint.matches_identity(&anchored.checkpoint.identity()) {
            continue;
        }
        if witness::cosignature_holds(&checkpoint, cosigned, &trusted_for_c)? {
            witnessed_c = true;
            break;
        }
    }
    if !witnessed_c {
        return Err(CliError::EvidenceMissing(format!(
            "no witness cosignature this run obtained verifies over the as-of checkpoint at \
             tree_size {}; core spec §4 fixes the as-of checkpoint as a witnessed one, and an \
             unwitnessed reconstruction is not a weaker success",
            anchored.checkpoint.tree_size
        )));
    }

    // --- consistency forward, to the newest member this run obtained -------------------
    let newest = history
        .iter()
        .filter_map(|cosigned| Checkpoint::from_value(cosigned.get("checkpoint")?).ok())
        .max_by_key(|checkpoint| checkpoint.tree_size)
        .ok_or_else(|| {
            CliError::EvidenceMissing("the witness published no cosigned checkpoint".to_owned())
        })?;

    if newest.tree_size > anchored.checkpoint.tree_size {
        // The witness key set for `newest` is resolved from the manifest version governing
        // *its* tree size, which may be anchored beyond `C`, so `newest` gets its own view.
        let later = anchored::establish(mirror, policy, newest.tree_size)?;
        let keys = later
            .governance
            .witness_keys_for(newest.tree_size)
            .map_err(|error| CliError::EvidenceMissing(error.to_string()))?;
        let trusted = with_locally_trusted(&keys, policy);
        let cosigned = history
            .iter()
            .find(|cosigned| {
                cosigned
                    .get("checkpoint")
                    .and_then(|value| Checkpoint::from_value(value).ok())
                    .is_some_and(|checkpoint| checkpoint.matches_identity(&newest.identity()))
            })
            .ok_or_else(|| {
                CliError::EvidenceMissing("the newest cosigned member vanished".to_owned())
            })?;
        if !witness::cosignature_holds(&newest, cosigned, &trusted)? {
            return Err(CliError::EvidenceMissing(
                "the newest cosigned checkpoint this run obtained does not verify under the \
                 witness key set the manifest version governing it declares"
                    .to_owned(),
            ));
        }
        let path = mirror.consistency_path(anchored.checkpoint.tree_size, newest.tree_size)?;
        if !consistency_verifies(&anchored.checkpoint, &newest, &path)? {
            return Err(CliError::EvidenceMissing(format!(
                "consistency from the as-of checkpoint at tree_size {} to the newest witnessed \
                 checkpoint at {} does not verify",
                anchored.checkpoint.tree_size, newest.tree_size
            )));
        }
    }

    Ok(vec![
        Finding::new(
            "continued-history-run-observed",
            format!(
                "consistency was verified to the newest witnessed checkpoint this run obtained \
                 (tree_size {}); no authenticated completeness proof over a witness's \
                 checkpoint history is defined in the frozen sources, so this is not a claim \
                 that it is the global latest",
                newest.tree_size
            ),
        ),
        Finding::new(
            "reproducible-reconstruction-not-evaluated",
            "reproducible reconstruction is an optional manifest-declared property requiring \
             retention and retrieval of referenced artifacts and canonical input and output \
             bytes; v0.1 does not evaluate it, and this result neither claims nor implies that \
             it holds",
        ),
    ])
}

/// Local policy may add witness keys it already trusts (receipt format §2.2) — and only for
/// witnesses: nothing else may be sourced from policy.
fn with_locally_trusted(
    declared: &std::collections::BTreeMap<String, String>,
    policy: &LoadedPolicy,
) -> std::collections::BTreeMap<String, String> {
    let mut trusted = declared.clone();
    for key_id in policy.trust.trusted_witness_keys.keys() {
        if let Some(pubkey) = declared.get(key_id) {
            trusted.insert(key_id.clone(), pubkey.clone());
        }
    }
    trusted
}

fn statement_ref(index: u64, envelope: &Value) -> Option<StatementRefOut> {
    Some(StatementRefOut {
        entry_index: index,
        statement_id: ahl_core::statement_id(envelope).ok()?,
        statement_type: envelope.get("payload")?.get("type")?.as_str()?.to_owned(),
    })
}

/// Assemble the evidenced assertion set from the enumerated statements.
fn assemble(
    anchored: &Anchored,
    options: &Options,
    asked_about: OffsetDateTime,
) -> CliResult<ReconstructionOut> {
    let (dataset, record) = (options.dataset.as_str(), options.record.as_str());
    let mut introduction = None;
    let mut consumers = Vec::new();
    let mut effective_triggers = Vec::new();
    let mut governing: Option<(u64, Value)> = None;

    for (index, envelope) in anchored.statements.iter() {
        let Some(payload) = envelope.get("payload") else { continue };
        match payload.get("type").and_then(Value::as_str) {
            Some("ingestion")
                if introduction.is_none()
                    && payload.get("dataset").and_then(Value::as_str) == Some(dataset)
                    && payload.get("record").and_then(Value::as_str) == Some(record) =>
            {
                introduction = statement_ref(index, envelope);
            }
            Some("derivation") => {
                let outputs = payload.get("outputs").and_then(Value::as_array);
                if outputs.is_some_and(|outputs| {
                    outputs.iter().any(|output| {
                        output.get("dataset").and_then(Value::as_str) == Some(dataset)
                            && output.get("record").and_then(Value::as_str) == Some(record)
                    })
                }) && introduction.is_none()
                {
                    introduction = statement_ref(index, envelope);
                }
                if payload.get("inputs").and_then(Value::as_array).is_some_and(|inputs| {
                    inputs.iter().any(|input| {
                        input.get("dataset").and_then(Value::as_str) == Some(dataset)
                            && input.get("record").and_then(Value::as_str) == Some(record)
                    })
                }) {
                    consumers.extend(statement_ref(index, envelope));
                }
            }
            Some("retraction" | "correction") => {
                if payload.get("dataset").and_then(Value::as_str) != Some(dataset)
                    || payload.get("record").and_then(Value::as_str) != Some(record)
                {
                    continue;
                }
                // Only triggers whose scope covers T apply at T (core §4 step 2).
                let Ok(scope) = Scope::from_payload(payload) else { continue };
                if !scope.covers(ValidTime::Point(asked_about)) {
                    continue;
                }
                // Effectiveness still requires authority; `governing_trigger` runs the full
                // §2.3.3 test over the same enumerated range.
                effective_triggers.extend(statement_ref(index, envelope));
                if governing.as_ref().is_none_or(|(at, _)| index > *at) {
                    governing = Some((index, envelope.clone()));
                }
            }
            _ => {}
        }
    }

    // Among conflicting effective triggers committed by C, the greatest entry index governs —
    // but only among *authorized* ones, so the authority test decides the final answer.
    let authorized = anchored::governing_trigger(anchored, dataset, record).ok();
    let governing_ref = governing.as_ref().and_then(|(index, envelope)| {
        let authorized = authorized.as_ref()?;
        (authorized.entry_index == *index).then(|| statement_ref(*index, envelope))?
    });

    let (status, replacement) = governing_ref.as_ref().map_or(("as-asserted", None), |reference| {
        let payload = anchored.statements.payload(reference.entry_index);
        match reference.statement_type.as_str() {
            "retraction" => ("retracted", None),
            "correction" => (
                "corrected",
                payload
                    .and_then(|payload| payload.get("replacement"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ),
            _ => ("as-asserted", None),
        }
    });

    if introduction.is_none() {
        return Err(CliError::EvidenceMissing(format!(
            "no anchored `ingestion` or `derivation` introduces `{dataset}`/`{record}` in \
             [0, {}); there is nothing to reconstruct at this checkpoint",
            anchored.checkpoint.tree_size
        )));
    }

    Ok(ReconstructionOut {
        record: RecordOut { dataset: dataset.to_owned(), record: record.to_owned() },
        valid_time: options.valid_time.clone(),
        as_of_tree_size: anchored.checkpoint.tree_size,
        introduction,
        consumers,
        effective_triggers,
        governing_trigger: governing_ref,
        status,
        replacement,
        reproducible_reconstruction: "not-evaluated",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MirrorFixture;

    fn at_corpus_time() -> EvaluationTime {
        EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("fixed instant")
    }

    fn options(fixture: &MirrorFixture, tree_size: u64) -> Options {
        let (dataset, record) = fixture.record_a();
        Options {
            dataset,
            record,
            valid_time: "2026-08-16T12:00:00Z".to_owned(),
            checkpoint: Some(tree_size),
        }
    }

    fn run_with(fixture: &MirrorFixture, options: &Options) -> Report {
        run(&fixture.policy, &at_corpus_time(), options, Some(fixture))
    }

    #[test]
    fn a_witnessed_reconstruction_is_valid_and_bounded_by_what_this_run_observed() {
        let fixture = MirrorFixture::conformance();
        let report = run_with(&fixture, &options(&fixture, 32));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert_eq!(report.continued_history_bound, Some(ObservationBound::RunObserved));
        assert_eq!(report.series_usable_bound, Some(ObservationBound::RunObserved));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "continued-history-run-observed"));
    }

    #[test]
    fn the_result_never_claims_the_latest_witnessed_checkpoint() {
        let fixture = MirrorFixture::conformance();
        let report = run_with(&fixture, &options(&fixture, 32));
        let json = report.to_json().expect("serializes").to_lowercase();
        assert!(!json.contains("latest witnessed"), "{json}");
        assert!(json.contains("run-observed"));
    }

    #[test]
    fn reproducible_reconstruction_is_named_as_not_evaluated_never_implied_to_hold() {
        let fixture = MirrorFixture::conformance();
        let report = run_with(&fixture, &options(&fixture, 32));
        let reconstruction = report.reconstruction.as_ref().expect("reconstructed");
        assert_eq!(reconstruction.reproducible_reconstruction, "not-evaluated");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "reproducible-reconstruction-not-evaluated"));
        assert!(report.reason.contains("was not evaluated"), "{}", report.reason);
    }

    #[test]
    fn knowledge_evolves_with_the_as_of_checkpoint() {
        let fixture = MirrorFixture::conformance();
        // At tree_size 8 the correction at entry 6 governs the record; further along the log a
        // second correction and then a retraction supersede it.
        let early = run_with(&fixture, &options(&fixture, 8));
        assert_eq!(early.status, "valid", "{}", early.reason);
        let late = run_with(&fixture, &options(&fixture, 32));
        let early_governing = early
            .reconstruction
            .as_ref()
            .and_then(|reconstruction| reconstruction.governing_trigger.as_ref())
            .map(|trigger| trigger.entry_index);
        let late_governing = late
            .reconstruction
            .as_ref()
            .and_then(|reconstruction| reconstruction.governing_trigger.as_ref())
            .map(|trigger| trigger.entry_index);
        assert_eq!(early_governing, Some(6));
        assert_eq!(late_governing, Some(18));
        assert_eq!(
            early.reconstruction.as_ref().map(|reconstruction| reconstruction.status),
            Some("corrected")
        );
        assert_eq!(
            late.reconstruction.as_ref().map(|reconstruction| reconstruction.status),
            Some("retracted")
        );
    }

    #[test]
    fn a_record_with_no_effective_trigger_reconstructs_as_asserted() {
        let fixture = MirrorFixture::conformance();
        let (dataset, record) = fixture.record_b();
        let report = run_with(
            &fixture,
            &Options {
                dataset,
                record,
                valid_time: "2026-08-16T12:00:00Z".to_owned(),
                checkpoint: Some(32),
            },
        );
        assert_eq!(report.status, "valid", "{}", report.reason);
        let reconstruction = report.reconstruction.expect("reconstructed");
        assert_eq!(reconstruction.status, "as-asserted");
        assert!(reconstruction.governing_trigger.is_none());
        assert!(reconstruction.introduction.is_some());
    }

    #[test]
    fn an_unreachable_witness_makes_reconstruction_unverifiable_never_a_weaker_success() {
        let mut fixture = MirrorFixture::conformance();
        fixture.policy.endpoints.witness = Some("https://witness.unreachable".to_owned());
        let report = run_with(&fixture, &options(&fixture, 32));
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("never downlevelled"), "{}", report.reason);
    }

    #[test]
    fn a_missing_witness_endpoint_is_a_usage_error_not_a_silent_downgrade() {
        let mut fixture = MirrorFixture::conformance();
        fixture.policy.endpoints.witness = None;
        let report = run_with(&fixture, &options(&fixture, 32));
        assert_eq!(report.status, "error");
        assert!(report.reason.contains("not a weaker success"), "{}", report.reason);
    }

    #[test]
    fn the_as_of_checkpoint_is_explicit_and_the_valid_time_is_rfc_3339() {
        let fixture = MirrorFixture::conformance();
        let mut options = options(&fixture, 32);
        options.checkpoint = None;
        let report = run_with(&fixture, &options);
        assert_eq!(report.status, "error");
        assert!(report.reason.contains("never inferred"), "{}", report.reason);

        let mut options = self::options(&fixture, 32);
        options.valid_time = "yesterday".to_owned();
        let report = run_with(&fixture, &options);
        assert_eq!(report.status, "invalid", "a bad artifact time is a rule against the input");
    }

    #[test]
    fn a_record_that_was_never_introduced_has_nothing_to_reconstruct() {
        let fixture = MirrorFixture::conformance();
        let report = run_with(
            &fixture,
            &Options {
                dataset: "customers".to_owned(),
                record: "sha256:deadbeef".to_owned(),
                valid_time: "2026-08-16T12:00:00Z".to_owned(),
                checkpoint: Some(32),
            },
        );
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("nothing to reconstruct"), "{}", report.reason);
    }

    #[test]
    fn a_non_retroactive_trigger_outside_the_asked_time_does_not_govern() {
        // Entry 17 retracts record C with `retroactive: false` from a boundary instant; asked
        // about an earlier valid time the trigger's scope does not cover it.
        let fixture = MirrorFixture::conformance();
        let vector: Value = serde_json::from_slice(
            &std::fs::read(
                MirrorFixture::corpus_root()
                    .join("vectors/closure/non-retroactive-retraction.json"),
            )
            .expect("vector"),
        )
        .expect("parses");
        let dataset = vector["trigger"]["dataset"].as_str().unwrap_or_default().to_owned();
        let record = vector["trigger"]["record"].as_str().unwrap_or_default().to_owned();
        let effective_from =
            vector["trigger"]["scope"]["effective_from"].as_str().unwrap_or_default().to_owned();

        let at_boundary = run_with(
            &fixture,
            &Options {
                dataset: dataset.clone(),
                record: record.clone(),
                valid_time: effective_from,
                checkpoint: Some(32),
            },
        );
        assert_eq!(
            at_boundary.reconstruction.as_ref().map(|reconstruction| reconstruction.status),
            Some("retracted")
        );

        let before = run_with(
            &fixture,
            &Options {
                dataset,
                record,
                valid_time: "2020-01-01T00:00:00Z".to_owned(),
                checkpoint: Some(32),
            },
        );
        assert_eq!(
            before.reconstruction.as_ref().map(|reconstruction| reconstruction.status),
            Some("as-asserted"),
            "a non-retroactive trigger does not reach back before its effective instant"
        );
    }
}
