//! `closure` — two explicitly separated modes, and the boundary between them is the point.
//!
//! # Topology mode (`--unauthenticated`)
//!
//! Input is a local corpus, output is labelled `authenticated: false`, and the command **exits
//! unverifiable, never `0`**, regardless of result. It exists for development against test
//! vectors.
//!
//! Its result is emitted under a distinct field name, `topology_affected` — never `affected`,
//! and never `affected_is_partial`. A hostile corpus can *add* forged edges as easily as omit
//! real ones, so the result is not a subset of the true closure and must not be describable as
//! a partial one. Nothing this mode prints ever says *complete*.
//!
//! Rule violations found while walking such a corpus are **findings, not verdicts**: nothing
//! there is evidence, so nothing can be disproved, and adjudicating it would imply the CLI had
//! established something it explicitly refuses to establish. Only a failure to read or parse
//! the input at all is a local-environment failure, because that happens before any walking
//! begins.
//!
//! # Authenticated mode (default)
//!
//! The result is AHL-backed only when every element of [`crate::anchored`] is established, in
//! order, plus trigger effectiveness and the tree material the closure needs. Failure of any
//! of them yields *unverifiable* with the missing element named — not a partial answer wearing
//! a complete answer's clothes.

use std::path::PathBuf;

use ahl_core::closure::{affected_set, TreeMaterial};
use ahl_core::AhlError;
use serde_json::Value;

use crate::anchored::{self, Anchored, Mirror, Statements};
use crate::corpus;
use crate::error::{CliError, CliResult};
use crate::evaluation::EvaluationTime;
use crate::net::Fetcher;
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::report::{CheckpointOut, Completeness, Finding, ObservationBound, RecordOut, Report};

/// How the operator named the trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerRef {
    /// By statement id — `sha256:<hex>` over `JCS(payload)`.
    StatementId(String),
    /// By entry index, AHL's only ordering primitive.
    EntryIndex(u64),
}

impl TriggerRef {
    /// Resolve against a **verified** statement view.
    ///
    /// A position voided for carrying a non-verifying signature, or for repeating a statement
    /// id a smaller entry index already governs, is not selectable: it is not a statement, so
    /// there is no closure to compute of it.
    fn resolve(&self, statements: &Statements) -> CliResult<u64> {
        match self {
            Self::EntryIndex(index) => match statements.statement_type(*index) {
                Some("not-a-statement") | None => Err(CliError::EvidenceMissing(format!(
                    "entry index {index} is not a statement this checkpoint commits: it is \
                         beyond the checkpoint, or it was voided for a signature that does not \
                         verify or for repeating a statement id a smaller index governs"
                ))),
                Some(_) => Ok(*index),
            },
            Self::StatementId(wanted) => statements
                .iter()
                .find(|(_, envelope)| {
                    ahl_core::statement_id(envelope).is_ok_and(|id| &id == wanted)
                })
                .map(|(index, _)| index)
                .ok_or_else(|| {
                    CliError::EvidenceMissing(format!(
                        "no verified statement in the material has statement id `{wanted}`"
                    ))
                }),
        }
    }

    /// Resolve against an unauthenticated corpus, where nothing is evidence and the operator's
    /// own file is all there is.
    fn resolve_topology(&self, entries: &[(u64, Value)]) -> CliResult<u64> {
        match self {
            Self::EntryIndex(index) => {
                entries.iter().any(|(at, _)| at == index).then_some(*index).ok_or_else(|| {
                    CliError::TopologyMode(format!(
                        "no entry at index {index} is present in the corpus"
                    ))
                })
            }
            Self::StatementId(wanted) => entries
                .iter()
                .find(|(_, envelope)| {
                    ahl_core::statement_id(envelope).is_ok_and(|id| &id == wanted)
                })
                .map(|(index, _)| *index)
                .ok_or_else(|| {
                    CliError::TopologyMode(format!(
                        "no entry in the corpus has statement id `{wanted}`"
                    ))
                }),
        }
    }
}

/// Options for one `closure` run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Which trigger to compute the closure of.
    pub trigger: TriggerRef,
    /// Topology mode: a local corpus, no authentication, never `0`.
    pub unauthenticated: bool,
    /// The local corpus, in topology mode.
    pub corpus: Option<PathBuf>,
    /// Committed tree material, untrusted until validated against its anchored root.
    pub tree_material: Option<PathBuf>,
    /// The checkpoint to evaluate at, by `tree_size`. Explicit, never inferred.
    pub checkpoint: Option<u64>,
}

/// Run `closure`.
#[must_use]
pub fn run<F: Fetcher>(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
    fetcher: Option<&F>,
) -> Report {
    let result = if options.unauthenticated {
        topology(policy, evaluation, options)
    } else {
        authenticated(policy, evaluation, options, fetcher)
    };
    result.unwrap_or_else(|error| {
        Report::new(
            error.outcome(),
            error.reason_code(),
            error.to_string(),
            evaluation.rendered.clone(),
            evaluation.source,
        )
    })
}

fn tree_material(policy: &LoadedPolicy, options: &Options) -> CliResult<TreeMaterial> {
    options.tree_material.as_ref().map_or_else(
        || Ok(TreeMaterial::new()),
        |path| corpus::load_tree_material(path, policy.local),
    )
}

/// Map a closure failure onto the outcome the mode calls for.
fn closure_failure(source: &AhlError, mode: Outcome) -> CliError {
    let detail = match source {
        AhlError::MissingTreeMaterial(root) => format!(
            "the committed tree material for `{root}` was not supplied; closure recomputation \
             must not depend on producer cooperation (core spec §3.5), so the material is \
             named rather than assumed"
        ),
        other => format!("the closure could not be computed: {other}"),
    };
    match mode {
        Outcome::Invalid => CliError::RuleFired(detail),
        _ => CliError::EvidenceMissing(detail),
    }
}

// ---------------------------------------------------------------------------
// Topology mode
// ---------------------------------------------------------------------------

fn topology(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
) -> CliResult<Report> {
    let path = options.corpus.as_ref().ok_or_else(|| {
        CliError::Usage(
            "`--unauthenticated` needs `--corpus <path>`: topology mode walks a local corpus"
                .to_owned(),
        )
    })?;

    // §6's one stated exception, and the boundary inside it: a failure to read **or parse**
    // the file at all is a local-environment failure (exit `2`), because it happens before any
    // walking begins. From the first line of the walk onwards, everything found is a finding
    // and the outcome is fixed at `3` — including a corpus riddled with violations.
    let loaded = corpus::load(path, policy.local)?;
    let mut findings = corpus::walk(&loaded);

    let envelopes = loaded.dense_envelopes()?;
    let trigger_index = options.trigger.resolve_topology(&loaded.entries)?;
    let trees = tree_material(policy, options)?;

    let closure = affected_set(
        &envelopes,
        &trees,
        usize::try_from(trigger_index).unwrap_or(usize::MAX),
        envelopes.len(),
    )
    .map_err(|source| closure_failure(&source, Outcome::Unverifiable))?;

    findings.push(Finding::new(
        "topology-mode",
        "nothing in this result is authenticated: the corpus is an unauthenticated file the \
         operator supplied, its edges are not proven to be the log's, and forged edges are as \
         reachable as omitted ones",
    ));
    findings.sort();
    findings.dedup();

    // The outcome is fixed at unverifiable whatever the walk found: adjudicating an
    // unauthenticated corpus would imply the CLI had established something it refuses to.
    let mut report = Report::new(
        Outcome::Unverifiable,
        "topology-mode",
        format!(
            "topology over an unauthenticated corpus of {} entries; this is neither an affected \
             set nor a subset of one",
            envelopes.len()
        ),
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.authenticated = false;
    report.completeness = Completeness::NotApplicable;
    report.topology_affected = Some(records(closure.affected.into_iter()));
    Ok(report.with_findings(findings))
}

// ---------------------------------------------------------------------------
// Authenticated mode
// ---------------------------------------------------------------------------

fn authenticated<F: Fetcher>(
    policy: &LoadedPolicy,
    evaluation: &EvaluationTime,
    options: &Options,
    fetcher: Option<&F>,
) -> CliResult<Report> {
    let anchored = establish_view(policy, options, fetcher)?;
    let trigger_index = options.trigger.resolve(&anchored.statements)?;

    // Trigger effectiveness per receipt format §3: not merely that *a* trigger is anchored,
    // but that **this** trigger governs at C.
    let (dataset, record) = trigger_record(&anchored, trigger_index)?;
    let governing = anchored::governing_trigger(&anchored, &dataset, &record)?;
    if governing.entry_index != trigger_index {
        return Err(CliError::EvidenceMissing(format!(
            "the trigger at entry index {trigger_index} does not govern `{dataset}`/`{record}` \
             at this checkpoint: the trigger at entry index {} does, and among effective \
             triggers the greatest entry index governs",
            governing.entry_index
        )));
    }

    let trees = tree_material(policy, options)?;
    let through = usize::try_from(anchored.checkpoint.tree_size).unwrap_or(usize::MAX);
    let closure = affected_set(
        anchored.statements.envelopes(),
        &trees,
        usize::try_from(trigger_index).unwrap_or(usize::MAX),
        through,
    )
    .map_err(|source| closure_failure(&source, Outcome::Unverifiable))?;

    let mut findings = anchored.findings.clone();
    findings.extend(governing.findings);
    findings.sort();
    findings.dedup();

    let mut report = Report::new(
        Outcome::Valid,
        "closure-computed",
        format!(
            "the affected set of the trigger at entry index {trigger_index}, recomputed from \
             the authenticated enumeration of [0, {})",
            anchored.checkpoint.tree_size
        ),
        evaluation.rendered.clone(),
        evaluation.source,
    );
    report.authenticated = true;
    report.completeness = Completeness::Complete;
    report.checkpoint = Some(CheckpointOut::of(&anchored.checkpoint));
    // Never "series-usable" unqualified: usability is claimed as of what this run observed.
    report.series_usable_bound = Some(ObservationBound::RunObserved);
    report.affected = Some(records(closure.affected.into_iter()));
    Ok(report.with_findings(findings))
}

fn establish_view<F: Fetcher>(
    policy: &LoadedPolicy,
    options: &Options,
    fetcher: Option<&F>,
) -> CliResult<Anchored> {
    let tree_size = options.checkpoint.ok_or_else(|| {
        CliError::Usage(
            "authenticated mode needs `--checkpoint <tree_size>`: the checkpoint is chosen \
             explicitly and is never inferred. Use `--unauthenticated` for topology over a \
             local corpus"
                .to_owned(),
        )
    })?;
    let base = policy.endpoints.mirror.as_deref().ok_or_else(|| {
        CliError::Usage(
            "authenticated mode needs a mirror: configure `[endpoints] mirror` or pass \
             `--mirror`"
                .to_owned(),
        )
    })?;
    let fetcher = fetcher.ok_or_else(|| {
        CliError::Usage("authenticated mode needs a network or a recorded transcript".to_owned())
    })?;
    let profile_id = crate::profile::resolve_all(policy)?
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| CliError::ProfileNotPossessed { id: "<none configured>".to_owned() })?;
    let mirror = Mirror::new(fetcher, base, &profile_id, policy.network)?;
    anchored::establish(&mirror, policy, tree_size)
}

fn trigger_record(anchored: &Anchored, index: u64) -> CliResult<(String, String)> {
    let envelope = anchored.statements.get(index).ok_or_else(|| {
        CliError::EvidenceMissing(format!(
            "entry index {index} is not committed by this checkpoint"
        ))
    })?;
    let payload = envelope.get("payload").ok_or_else(|| {
        CliError::EvidenceMissing(format!("the entry at index {index} carries no payload"))
    })?;
    match payload.get("type").and_then(Value::as_str) {
        Some("retraction" | "correction") => {}
        other => {
            return Err(CliError::EvidenceMissing(format!(
                "the entry at index {index} is a `{}`, not a trigger; a closure is computed of \
                 a retraction or a correction",
                other.unwrap_or("<not a statement>")
            )))
        }
    }
    Ok((
        payload
            .get("dataset")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::EvidenceMissing("the trigger names no dataset".to_owned()))?
            .to_owned(),
        payload
            .get("record")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::EvidenceMissing("the trigger names no record".to_owned()))?
            .to_owned(),
    ))
}

fn records(pairs: impl Iterator<Item = (String, String)>) -> Vec<RecordOut> {
    let mut out: Vec<RecordOut> =
        pairs.map(|(dataset, record)| RecordOut { dataset, record }).collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MirrorFixture;

    fn corpus_dir() -> PathBuf {
        crate::testing::statements_with_published_tree_material(&std::env::temp_dir())
    }

    fn at_corpus_time() -> EvaluationTime {
        EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("fixed instant")
    }

    fn tree_material_file() -> PathBuf {
        crate::testing::tree_material_file(&std::env::temp_dir())
    }

    fn topology_options(trigger: TriggerRef) -> Options {
        Options {
            trigger,
            unauthenticated: true,
            corpus: Some(corpus_dir()),
            tree_material: Some(tree_material_file()),
            checkpoint: None,
        }
    }

    fn policy() -> LoadedPolicy {
        MirrorFixture::conformance().policy
    }

    fn run_topology(options: &Options) -> Report {
        run::<MirrorFixture>(&policy(), &at_corpus_time(), options, None)
    }

    #[test]
    fn topology_mode_never_returns_valid_however_clean_the_corpus_is() {
        let report = run_topology(&topology_options(TriggerRef::EntryIndex(6)));
        assert_eq!(report.status, "unverifiable");
        assert!(!report.authenticated);
        assert!(report.topology_affected.is_some());
        assert!(report.affected.is_none(), "the two results never share a field name");
    }

    #[test]
    fn topology_mode_never_prints_the_word_complete() {
        let report = run_topology(&topology_options(TriggerRef::EntryIndex(6)));
        let json = report.to_json().expect("serializes").to_lowercase();
        let text = report.to_text().to_lowercase();
        assert!(!json.contains("\"complete\""), "{json}");
        assert!(!text.contains("completeness: complete"), "{text}");
        assert!(!json.contains("partial"), "the result is not a partial closure either");
    }

    #[test]
    fn topology_mode_reports_rule_violations_as_findings_and_keeps_the_outcome() {
        let report = run_topology(&topology_options(TriggerRef::EntryIndex(6)));
        // The conformance corpus deliberately carries entries whose signatures do not verify.
        assert!(report.findings.iter().any(|f| f.code == "signature-does-not-verify"));
        assert!(report.findings.iter().any(|f| f.code == "topology-mode"));
        assert_eq!(report.status, "unverifiable", "a finding never changes the outcome");
    }

    #[test]
    fn the_topology_result_matches_the_published_closure_vector() {
        // Topology mode has no checkpoint, so it walks the whole corpus — which is exactly the
        // post-`D` enlargement the corpus documents: the derivation at entry 27 consumes an
        // already-affected descendant, so the set at the end of the log is larger than the set
        // at the propagation's declared checkpoint. The published vector for that reading is
        // `descendant-enlargement-past-declared-checkpoint`, and matching it rather than the
        // `toy-corpus` vector is the point: closure is not stable across checkpoints.
        let vector: Value = serde_json::from_slice(
            &std::fs::read(
                MirrorFixture::corpus_root()
                    .join("vectors/closure/descendant-enlargement-past-declared-checkpoint.json"),
            )
            .expect("vector"),
        )
        .expect("parses");
        let trigger_index = vector["trigger"]["entry_index"].as_u64().expect("index");
        let expected: Vec<RecordOut> = vector["expected_affected"]
            .as_array()
            .expect("array")
            .iter()
            .map(|item| RecordOut {
                dataset: item["dataset"].as_str().unwrap_or_default().to_owned(),
                record: item["record"].as_str().unwrap_or_default().to_owned(),
            })
            .collect();

        let report = run_topology(&topology_options(TriggerRef::EntryIndex(trigger_index)));
        assert_eq!(report.topology_affected.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn a_trigger_can_be_named_by_statement_id_as_well_as_by_entry_index() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(MirrorFixture::corpus_root().join("vectors/closure/toy-corpus.json"))
                .expect("vector"),
        )
        .expect("parses");
        let statement_id = vector["trigger"]["statement_id"].as_str().expect("id").to_owned();
        let by_id = run_topology(&topology_options(TriggerRef::StatementId(statement_id)));
        let by_index = run_topology(&topology_options(TriggerRef::EntryIndex(
            vector["trigger"]["entry_index"].as_u64().expect("index"),
        )));
        assert_eq!(by_id.topology_affected, by_index.topology_affected);
    }

    #[test]
    fn an_unknown_trigger_reference_is_reported_rather_than_guessed() {
        let report = run_topology(&topology_options(TriggerRef::EntryIndex(9999)));
        assert_eq!(report.status, "unverifiable");
        let report =
            run_topology(&topology_options(TriggerRef::StatementId("sha256:nope".to_owned())));
        assert_eq!(report.status, "unverifiable");
    }

    #[test]
    fn topology_mode_without_a_corpus_is_a_usage_error_before_anything_is_read() {
        let mut options = topology_options(TriggerRef::EntryIndex(6));
        options.corpus = None;
        let report = run_topology(&options);
        assert_eq!(report.status, "error");
        assert_eq!(report.reason_code, "usage");
    }

    #[test]
    fn the_boundary_between_unparseable_input_and_a_walked_corpus_with_violations() {
        // The boundary the reviewer asked for, in all three positions. It is asserted on the
        // *reason code* as well as the status, because two different failures can share an
        // exit code and only one of them is the one under test.
        let dir = tempfile::tempdir().expect("tempdir");

        // (a) cannot be opened at all — local-environment failure, before any walking.
        let mut options = topology_options(TriggerRef::EntryIndex(0));
        options.corpus = Some(dir.path().join("absent.json"));
        let report = run_topology(&options);
        assert_eq!(report.status, "error");
        assert_eq!(report.reason_code, "input-unreadable");

        // (b) opens but does not parse — still before any walking, so still `2`.
        let path = dir.path().join("corpus.json");
        std::fs::write(&path, b"{ this is not json").expect("write");
        options.corpus = Some(path);
        let report = run_topology(&options);
        assert_eq!(report.status, "error", "a parse failure happens before any walking begins");
        assert_eq!(report.reason_code, "input-unparseable");

        // (c) parses, and the walk finds violations — findings, not verdicts, outcome `3`.
        let report = run_topology(&topology_options(TriggerRef::EntryIndex(6)));
        assert_eq!(report.status, "unverifiable");
        assert_eq!(report.reason_code, "topology-mode");
        assert!(!report.findings.is_empty(), "violations are reported in full");
    }

    #[test]
    fn missing_tree_material_is_named_rather_than_assumed() {
        let mut options = topology_options(TriggerRef::EntryIndex(12));
        options.tree_material = None;
        let report = run_topology(&options);
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("was not supplied"), "{}", report.reason);
    }

    // -- authenticated mode -------------------------------------------------------------

    fn authenticated_options(trigger: TriggerRef, tree_size: u64) -> Options {
        Options {
            trigger,
            unauthenticated: false,
            corpus: None,
            tree_material: Some(tree_material_file()),
            checkpoint: Some(tree_size),
        }
    }

    fn run_authenticated(fixture: &MirrorFixture, options: &Options) -> Report {
        run(&fixture.policy, &at_corpus_time(), options, Some(fixture))
    }

    #[test]
    fn an_authenticated_closure_is_valid_and_labelled_run_observed() {
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 8));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert!(report.authenticated);
        assert_eq!(report.completeness, Completeness::Complete);
        assert_eq!(report.series_usable_bound, Some(ObservationBound::RunObserved));
        assert!(report.affected.is_some());
        assert!(report.topology_affected.is_none());
        assert_eq!(report.checkpoint.as_ref().map(|checkpoint| checkpoint.tree_size), Some(8));
    }

    #[test]
    fn the_authenticated_result_matches_the_published_closure_vector() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(MirrorFixture::corpus_root().join("vectors/closure/toy-corpus.json"))
                .expect("vector"),
        )
        .expect("parses");
        let expected: Vec<RecordOut> = vector["expected_affected"]
            .as_array()
            .expect("array")
            .iter()
            .map(|item| RecordOut {
                dataset: item["dataset"].as_str().unwrap_or_default().to_owned(),
                record: item["record"].as_str().unwrap_or_default().to_owned(),
            })
            .collect();
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 8));
        assert_eq!(report.affected.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn a_trigger_a_later_one_supersedes_does_not_govern() {
        // Entry 6 corrects record A; entry 12 corrects it again and supersedes entry 6. At a
        // checkpoint committing both, entry 6 no longer governs, and the CLI refuses rather
        // than computing a closure from the older trigger.
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 13));
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("does not govern"), "{}", report.reason);
        assert!(report.reason.contains("entry index 12"), "{}", report.reason);

        // Further along the log a retraction of the same record supersedes both corrections,
        // and the governing index moves again.
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(12), 20));
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("entry index 18"), "{}", report.reason);
    }

    #[test]
    fn a_challenge_never_governs_and_is_surfaced() {
        // Entry 23 retracts record F under a key that is not the dataset authority.
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(23), 32));
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("does not govern"), "{}", report.reason);
    }

    #[test]
    fn authenticated_mode_needs_an_explicit_checkpoint_and_a_mirror() {
        let fixture = MirrorFixture::conformance();
        let mut options = authenticated_options(TriggerRef::EntryIndex(6), 8);
        options.checkpoint = None;
        let report = run_authenticated(&fixture, &options);
        assert_eq!(report.status, "error");
        assert!(report.reason.contains("never inferred"), "{}", report.reason);

        let mut fixture = MirrorFixture::conformance();
        fixture.policy.endpoints.mirror = None;
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 8));
        assert_eq!(report.status, "error");
    }

    #[test]
    fn an_equivocating_series_at_the_checkpoint_is_invalid_not_unverifiable() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(8);
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 8));
        assert_eq!(report.status, "invalid");
        assert_eq!(report.reason_code, "equivocation-at-or-beyond-floor");
    }

    #[test]
    fn a_divergence_above_the_grounding_checkpoint_is_carried_as_a_finding() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(20);
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(6), 8));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert!(report.findings.iter().any(|f| f.code == "divergence-below-floor"));
    }

    #[test]
    fn an_entry_that_is_not_a_statement_is_excluded_and_reported() {
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(29), 32));
        assert_eq!(report.status, "valid", "{}", report.reason);
        assert!(report.findings.iter().any(|f| f.code == "entry-is-not-a-statement"));
    }

    #[test]
    fn an_entry_that_is_not_a_trigger_is_refused_by_name() {
        let fixture = MirrorFixture::conformance();
        let report =
            run_authenticated(&fixture, &authenticated_options(TriggerRef::EntryIndex(1), 8));
        assert_eq!(report.status, "unverifiable");
        assert!(report.reason.contains("not a trigger"), "{}", report.reason);
    }
}
