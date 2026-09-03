//! The stable result schema, and the two surfaces it is rendered on.
//!
//! `--json` writes this schema to **stdout**; diagnostics, progress and colour go to
//! **stderr**, so a consumer can pipe one without the other. The field set is fixed in v0.1
//! and every field is always present, `null` where it does not apply — a consumer that reads
//! `completeness` should not have to distinguish "absent" from "not applicable".
//!
//! Two exceptions to "always present", both required by §6: `affected` and
//! `topology_affected` appear only on `closure`, and **never together**. A complete result and
//! an unauthenticated one never share a field name, because a hostile corpus can *add* forged
//! edges as easily as omit real ones — the topology result is not a subset of the true
//! closure, so it must not be describable as a partial one.
//!
//! # `status`, in two steps
//!
//! `status` is the I-D §7.7 reduction of `assertions[]` — `invalid` if any required assertion
//! is `invalid`, otherwise `unverifiable` if any is `unverifiable`, otherwise `valid` — and
//! **then** promoted to `unverifiable` by any entry in `policy_overlays[]`. The two steps are
//! separate because the two lists answer different questions: `assertions[]` is what the
//! receipt requires, decided identically by every conformant verifier, while an overlay is a
//! condition this operator configured. Folding an overlay into `assertions[]` would put a
//! verifier-local condition among the receipt's required assertions, which §7.7 enumerates
//! exactly; leaving it out of the status would report `valid` for a run whose own policy was
//! not satisfied.
//!
//! An overlay can only ever promote, and only to `unverifiable`: it never turns `invalid` into
//! something weaker, and it never produces `invalid` itself.
//!
//! # Determinism
//!
//! Key order is the declaration order of these structs, and every printed set is ordered
//! lexicographically by a stated field: affected sets by `(dataset, record)`, findings by
//! `(code, detail)`, key ids as strings. Given the same inputs, the same policy and the same
//! `--evaluation-time`, stdout is byte-identical.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::Serialize;

use crate::outcome::Outcome;

/// Whether the evaluation time came from the clock or from `--evaluation-time`.
///
/// Always reported, so an overridden result can never be read as a current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimeSource {
    /// Read from the system clock at the start of the run.
    Clock,
    /// Supplied by `--evaluation-time`.
    Override,
}

/// Enumeration completeness, as §6 names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Completeness {
    /// The required range was enumerated and proven.
    Complete,
    /// A limit was hit, subranges did not tile, or a proof was missing.
    Incomplete,
    /// This command establishes nothing about enumeration.
    NotApplicable,
}

/// A bound that is honest about what one run observed.
///
/// The frozen sources define no authenticated completeness proof over any history a server
/// publishes, so a client cannot establish that a checkpoint is the latest, nor that no
/// successor exists. Rather than overclaim, the CLI labels what it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationBound {
    /// Established only as of what this run observed.
    RunObserved,
}

/// One finding: a stable machine code plus detail. Never a verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    /// Stable code, e.g. `witness-stale`, `divergence-below-floor`.
    pub code: String,
    /// Human-readable detail.
    pub detail: String,
}

impl Finding {
    /// Build a finding.
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into() }
    }
}

/// The assurance block, AS THE RECEIPT CARRIES IT (I-D §7.3).
///
/// Never rewritten to express a result. I-D §7.7: "No result may be represented by rewriting
/// the receipt's assurance fields: in particular a content binding the verifier cannot compute
/// MUST NOT be re-rendered as `content_binding: \"none\"`, which would convert an unevaluated
/// claim into a weaker verified one." What the run established about each of these is in
/// [`Report::assertions`]; the block itself says what was claimed, on every outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssuranceOut {
    /// `declared` or `enumerated`. These are different results and never collapse to one glyph.
    pub governance: String,
    /// `not-checked` or `enumerated`.
    pub competing_triggers: String,
    /// At least one cosignature **carried by the receipt** verified.
    pub witnessed: bool,
    /// A later checkpoint plus a consistency proof verified.
    pub continued_history: bool,
    /// `none`, `plain-verified` or `keyed-authorized`.
    pub content_binding: String,
    /// `public` or `private-use`, present exactly where `content_binding` is not `none`
    /// (I-D §7.3): the namespace the dataset's canonicalization identifier is drawn from.
    pub canonicalization_namespace: Option<String>,
}

/// One required assertion of the receipt, with the outcome the run reached for it (I-D §7.7).
///
/// §7.7 requires the findings to be reported alongside the scalar result, "because the result
/// alone does not say which assertion produced it, and a reader cannot act on `unverifiable`
/// without knowing what was missing". A finding is never a result: the receipt still has
/// exactly one, in [`Report::status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertionOut {
    /// The assertion's stable name, as `ahl-core` spells it: `anchoring`, `governance`,
    /// `content-binding`, and the rest.
    pub assertion: String,
    /// `verified`, `invalid` or `unverifiable` — the same three values as the result, with the
    /// same meanings.
    pub outcome: String,
    /// Where the assertion lives: empty for the receipt itself, otherwise the claim-material
    /// member names of the embedded receipts leading to it, outermost first.
    pub receipt_path: Vec<String>,
    /// For an outcome other than `verified`, what produced it.
    pub detail: Option<String>,
    /// The assertion whose gap this one inherits, where it has one.
    ///
    /// `null` means the finding is what its own check produced — the rule that fired, the
    /// budget that ran out, the capability that was missing — and is therefore a **cause**. A
    /// name means the check was not run because that other assertion was `unverifiable`. The
    /// headline in `reason_code` is always a cause, so this is what lets a consumer reproduce
    /// the choice from the list rather than parse it out of prose.
    pub rests_on: Option<String>,
}

/// One locally configured policy condition this run applied on top of the receipt's own
/// required assertions.
///
/// I-D §7.7 fixes the required assertions of a receipt "exactly", and freshness is not among
/// them: it is a property of the run's evaluation time rather than of the artifact, so it
/// cannot be a §7.7 finding and does not belong in [`Report::assertions`]. It is reported here
/// instead, in its own field, so a consumer can tell what the receipt asserted from what this
/// verifier's own policy added.
///
/// An overlay yields [`Self::outcome`] `unverifiable` and nothing else. It is verifier-local by
/// construction, and a verifier-local condition reported as `invalid` would let two verifiers
/// make contradictory statements about one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyOverlayOut {
    /// Stable code for the condition, e.g. `witness-freshness`.
    pub overlay: String,
    /// Always `unverifiable`: an overlay never disproves anything.
    pub outcome: String,
    /// What the condition found.
    pub detail: String,
}

/// The checkpoint a result is grounded on, by identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointOut {
    /// `log_id`.
    pub log_id: String,
    /// Number of entries committed.
    pub tree_size: u64,
    /// Root hash.
    pub root_hash: String,
}

impl CheckpointOut {
    /// The identity fields of a checkpoint, which is all a result is grounded on.
    #[must_use]
    pub fn of(checkpoint: &crate::checkpoint::Checkpoint) -> Self {
        Self {
            log_id: checkpoint.log_id.clone(),
            tree_size: checkpoint.tree_size,
            root_hash: checkpoint.root_hash.clone(),
        }
    }
}

/// A `(dataset, record)` pair, the only identity closure traversal uses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RecordOut {
    /// Dataset id.
    pub dataset: String,
    /// Record commitment.
    pub record: String,
}

/// The result document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// One of `valid`, `invalid`, `error`, `unverifiable`. Never `invalid` for a `3`.
    pub status: &'static str,
    /// Stable machine string naming the class of result.
    pub reason_code: String,
    /// Human-readable reason.
    pub reason: String,
    /// The proven claim type, where one applies.
    pub claim_type: Option<String>,
    /// The rendered boundary. Never stronger than the boundary `ahl-core` carries.
    pub boundary: Option<String>,
    /// The assurance block as the receipt carries it, on every outcome.
    pub assurance: Option<AssuranceOut>,
    /// The checkpoint this result is grounded on.
    pub checkpoint: Option<CheckpointOut>,
    /// Whether the result rests on authenticated evidence at all.
    pub authenticated: bool,
    /// Enumeration completeness.
    pub completeness: Completeness,
    /// The instant freshness was evaluated at.
    pub evaluation_time: String,
    /// Where that instant came from.
    pub evaluation_time_source: TimeSource,
    /// How far series usability was established, where it was.
    pub series_usable_bound: Option<ObservationBound>,
    /// How far continued history was established, where it was.
    pub continued_history_bound: Option<ObservationBound>,
    /// Findings, ordered by `(code, detail)`. Reported in full, never suppressed.
    pub findings: Vec<Finding>,
    /// One entry per required assertion of the verified receipt, in the order the verification
    /// algorithm reaches them, **as the core reports them and nothing else**. `null` for a
    /// command that verifies no receipt, and for a local failure that reached no result.
    pub assertions: Option<Vec<AssertionOut>>,
    /// Locally configured conditions this run applied on top of those. Empty where none did.
    pub policy_overlays: Vec<PolicyOverlayOut>,
    /// The receipt's informative `note`, quoted. Never a finding, never normative.
    pub receipt_note: Option<String>,
    /// The authenticated affected set. Present only on an authenticated `closure`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected: Option<Vec<RecordOut>>,
    /// The topology-mode result. Present only on `closure --unauthenticated`, and deliberately
    /// **not** named `affected`: an unauthenticated corpus can add forged edges as easily as
    /// omit real ones, so this is not a subset of the true closure and is never a partial one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology_affected: Option<Vec<RecordOut>>,
    /// The evidenced assertion set. Present only on `reconstruct`.
    ///
    /// §6 fixes the top-level field set for the verdict surface and does not name a member for
    /// a reconstruction result, which the command nevertheless has to return. It is added
    /// here on the same footing as `affected` and `topology_affected` — present only for the
    /// command that produces it — and the addition is recorded in the crate README rather than
    /// made silently.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstruction: Option<crate::commands::reconstruct::ReconstructionOut>,
}

impl Report {
    /// A report carrying nothing but an outcome and its reason.
    #[must_use]
    pub fn new(
        outcome: Outcome,
        reason_code: impl Into<String>,
        reason: impl Into<String>,
        evaluation_time: String,
        evaluation_time_source: TimeSource,
    ) -> Self {
        Self {
            status: outcome.as_str(),
            reason_code: reason_code.into(),
            reason: reason.into(),
            claim_type: None,
            boundary: None,
            assurance: None,
            checkpoint: None,
            authenticated: false,
            completeness: Completeness::NotApplicable,
            evaluation_time,
            evaluation_time_source,
            series_usable_bound: None,
            continued_history_bound: None,
            findings: Vec::new(),
            assertions: None,
            policy_overlays: Vec::new(),
            receipt_note: None,
            affected: None,
            topology_affected: None,
            reconstruction: None,
        }
    }

    /// Add findings, keeping them ordered and duplicate-free.
    #[must_use]
    pub fn with_findings(mut self, findings: impl IntoIterator<Item = Finding>) -> Self {
        let mut set: BTreeSet<Finding> = self.findings.into_iter().collect();
        set.extend(findings);
        self.findings = set.into_iter().collect();
        self
    }

    /// Serialize to the stable JSON form, with a trailing newline.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::Internal`] if serialization fails, which for this closed set
    /// of types cannot happen for any input the CLI constructs.
    pub fn to_json(&self) -> crate::error::CliResult<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|source| crate::error::CliError::Internal(source.to_string()))?;
        text.push('\n');
        Ok(text)
    }

    /// Render the human-readable form.
    ///
    /// `inspect` never reaches this function: it prints no verdict, no checkmark and no
    /// "looks valid", so it has its own surface entirely.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "status: {}", self.status);
        let _ = writeln!(out, "reason: [{}] {}", self.reason_code, self.reason);
        if let Some(claim_type) = &self.claim_type {
            let _ = writeln!(out, "claim type: {claim_type}");
        }
        if let Some(boundary) = &self.boundary {
            let _ = writeln!(out, "boundary: {boundary}");
        }
        if let Some(assurance) = &self.assurance {
            // Assurance fields print in full: `governance: declared` and
            // `governance: enumerated` are different results and never collapse to one glyph.
            out.push_str("assurance:\n");
            let _ = writeln!(out, "  governance: {}", assurance.governance);
            let _ = writeln!(out, "  competing_triggers: {}", assurance.competing_triggers);
            let _ = writeln!(out, "  witnessed: {}", assurance.witnessed);
            let _ = writeln!(out, "  continued_history: {}", assurance.continued_history);
            let _ = writeln!(out, "  content_binding: {}", assurance.content_binding);
            if let Some(namespace) = &assurance.canonicalization_namespace {
                let _ = writeln!(out, "  canonicalization_namespace: {namespace}");
            }
        }
        if let Some(checkpoint) = &self.checkpoint {
            let _ = writeln!(
                out,
                "checkpoint: log_id={} tree_size={} root_hash={}",
                checkpoint.log_id, checkpoint.tree_size, checkpoint.root_hash
            );
        }
        let _ = writeln!(out, "authenticated: {}", self.authenticated);
        let _ = writeln!(out, "completeness: {}", completeness_str(self.completeness));
        let _ = writeln!(
            out,
            "evaluation time: {} (source: {})",
            self.evaluation_time,
            match self.evaluation_time_source {
                TimeSource::Clock => "clock",
                TimeSource::Override => "override",
            }
        );
        if let Some(bound) = self.series_usable_bound {
            let _ = writeln!(out, "series usable bound: {}", bound_str(bound));
        }
        if let Some(bound) = self.continued_history_bound {
            let _ = writeln!(out, "continued history bound: {}", bound_str(bound));
        }
        if let Some(note) = &self.receipt_note {
            // Attributed to the receipt, never presented as a finding.
            let _ = writeln!(out, "the receipt says (informative, not a finding): \"{note}\"");
        }
        if !self.findings.is_empty() {
            out.push_str("findings:\n");
            for finding in &self.findings {
                let _ = writeln!(out, "  [{}] {}", finding.code, finding.detail);
            }
        }
        if !self.policy_overlays.is_empty() {
            out.push_str("policy overlays:\n");
            for overlay in &self.policy_overlays {
                let _ = writeln!(
                    out,
                    "  {}: {} — {}",
                    overlay.overlay, overlay.outcome, overlay.detail
                );
            }
        }
        if let Some(assertions) = &self.assertions {
            if !assertions.is_empty() {
                out.push_str("assertions:\n");
                for assertion in assertions {
                    let mut name = assertion.receipt_path.join("/");
                    if !name.is_empty() {
                        name.push('/');
                    }
                    name.push_str(&assertion.assertion);
                    match &assertion.detail {
                        Some(detail) => {
                            let _ = writeln!(out, "  {name}: {} — {detail}", assertion.outcome);
                        }
                        None => {
                            let _ = writeln!(out, "  {name}: {}", assertion.outcome);
                        }
                    }
                }
            }
        }
        if let Some(affected) = &self.affected {
            let _ = writeln!(out, "affected ({}):", affected.len());
            for record in affected {
                let _ = writeln!(out, "  {} {}", record.dataset, record.record);
            }
        }
        if let Some(topology) = &self.topology_affected {
            let _ = writeln!(out, "topology affected ({}), unauthenticated:", topology.len());
            for record in topology {
                let _ = writeln!(out, "  {} {}", record.dataset, record.record);
            }
        }
        out
    }
}

const fn completeness_str(value: Completeness) -> &'static str {
    match value {
        Completeness::Complete => "complete",
        Completeness::Incomplete => "incomplete",
        Completeness::NotApplicable => "not-applicable",
    }
}

const fn bound_str(value: ObservationBound) -> &'static str {
    match value {
        ObservationBound::RunObserved => "run-observed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report::new(
            Outcome::Valid,
            "verified",
            "every required rule verified",
            "2026-08-17T00:00:00Z".to_owned(),
            TimeSource::Override,
        )
    }

    #[test]
    fn the_json_field_order_is_the_declaration_order_and_is_stable() {
        let json = report().to_json().expect("serializes");
        let order: Vec<&str> = [
            "\"status\"",
            "\"reason_code\"",
            "\"reason\"",
            "\"claim_type\"",
            "\"boundary\"",
            "\"assurance\"",
            "\"checkpoint\"",
            "\"authenticated\"",
            "\"completeness\"",
            "\"evaluation_time\"",
            "\"evaluation_time_source\"",
            "\"series_usable_bound\"",
            "\"continued_history_bound\"",
            "\"findings\"",
            "\"assertions\"",
            "\"policy_overlays\"",
            "\"receipt_note\"",
        ]
        .into_iter()
        .collect();
        let mut last = 0;
        for field in order {
            let at = json.find(field).unwrap_or_else(|| panic!("{field} missing from {json}"));
            assert!(at > last, "{field} out of order");
            last = at;
        }
        assert_eq!(json, report().to_json().expect("serializes"));
    }

    #[test]
    fn a_complete_result_and_an_unauthenticated_one_never_share_a_field_name() {
        let mut authenticated = report();
        authenticated.affected =
            Some(vec![RecordOut { dataset: "d".to_owned(), record: "sha256:aa".to_owned() }]);
        let json = authenticated.to_json().expect("serializes");
        assert!(json.contains("\"affected\""));
        assert!(!json.contains("topology_affected"));

        let mut topology = report();
        topology.topology_affected =
            Some(vec![RecordOut { dataset: "d".to_owned(), record: "sha256:aa".to_owned() }]);
        let json = topology.to_json().expect("serializes");
        assert!(json.contains("\"topology_affected\""));
        assert!(
            !json.contains("\"affected\""),
            "the unauthenticated result must not be filed under the complete one's name"
        );
    }

    #[test]
    fn findings_are_ordered_and_deduplicated() {
        let report = report().with_findings([
            Finding::new("witness-stale", "b"),
            Finding::new("divergence-below-floor", "a"),
            Finding::new("witness-stale", "b"),
        ]);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].code, "divergence-below-floor");
        assert_eq!(report.findings[1].code, "witness-stale");
    }

    #[test]
    fn unverifiable_is_never_rendered_as_invalid_on_either_surface() {
        let report = Report::new(
            Outcome::Unverifiable,
            "evidence-missing",
            "the mirror did not answer",
            "2026-08-17T00:00:00Z".to_owned(),
            TimeSource::Clock,
        );
        let text = report.to_text();
        let json = report.to_json().expect("serializes");
        assert!(text.contains("status: unverifiable"));
        assert!(!text.to_lowercase().contains("invalid"));
        assert!(json.contains("\"status\": \"unverifiable\""));
        assert!(!json.contains("invalid"));
    }

    #[test]
    fn assurance_prints_in_full_and_never_collapses_to_one_glyph() {
        let mut report = report();
        report.assurance = Some(AssuranceOut {
            governance: "enumerated".to_owned(),
            competing_triggers: "enumerated".to_owned(),
            witnessed: true,
            continued_history: false,
            content_binding: "keyed-authorized".to_owned(),
            canonicalization_namespace: Some("public".to_owned()),
        });
        let text = report.to_text();
        for expected in [
            "governance: enumerated",
            "competing_triggers: enumerated",
            "witnessed: true",
            "continued_history: false",
            "content_binding: keyed-authorized",
            "canonicalization_namespace: public",
        ] {
            assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
        }
    }

    #[test]
    fn the_receipt_note_is_quoted_and_attributed_never_reported_as_a_finding() {
        let mut report = report();
        report.receipt_note = Some("issued for the 2026 audit".to_owned());
        let text = report.to_text();
        assert!(text.contains("the receipt says (informative, not a finding)"));
        assert!(!text.contains("findings:"));
    }

    #[test]
    fn the_evaluation_time_source_is_always_rendered() {
        assert!(report().to_text().contains("source: override"));
        let mut clock = report();
        clock.evaluation_time_source = TimeSource::Clock;
        assert!(clock.to_text().contains("source: clock"));
    }

    #[test]
    fn every_rendered_bound_and_completeness_value_has_a_spelling() {
        let mut report = report();
        report.completeness = Completeness::Incomplete;
        report.series_usable_bound = Some(ObservationBound::RunObserved);
        report.continued_history_bound = Some(ObservationBound::RunObserved);
        report.checkpoint = Some(CheckpointOut {
            log_id: "sha256:aa".to_owned(),
            tree_size: 8,
            root_hash: "sha256:bb".to_owned(),
        });
        report.claim_type = Some("trigger-effective".to_owned());
        report.boundary = Some("the trigger governs at C".to_owned());
        report.topology_affected = Some(Vec::new());
        let text = report.to_text();
        assert!(text.contains("completeness: incomplete"));
        assert!(text.contains("series usable bound: run-observed"));
        assert!(text.contains("continued history bound: run-observed"));
        assert!(text.contains("tree_size=8"));
        assert!(text.contains("claim type: trigger-effective"));
        assert!(text.contains("boundary: the trigger governs at C"));
        assert!(text.contains("topology affected (0)"));

        let mut complete = report;
        complete.completeness = Completeness::Complete;
        complete.topology_affected = None;
        complete.affected =
            Some(vec![RecordOut { dataset: "scores".to_owned(), record: "sha256:cc".to_owned() }]);
        let text = complete.to_text();
        assert!(text.contains("completeness: complete"));
        assert!(text.contains("affected (1)"));
        assert!(text.contains("scores sha256:cc"));
    }

    #[test]
    fn the_assertion_table_renders_every_entry_under_its_receipt_path() {
        let mut report = report();
        report.assertions = Some(vec![
            AssertionOut {
                assertion: "anchoring".to_owned(),
                outcome: "verified".to_owned(),
                receipt_path: Vec::new(),
                detail: None,
                rests_on: None,
            },
            AssertionOut {
                assertion: "content-binding".to_owned(),
                outcome: "unverifiable".to_owned(),
                receipt_path: vec!["introduction".to_owned()],
                detail: Some("no dataset key is held".to_owned()),
                rests_on: None,
            },
        ]);
        let text = report.to_text();
        assert!(text.contains("anchoring: verified"), "{text}");
        assert!(
            text.contains("introduction/content-binding: unverifiable — no dataset key is held"),
            "{text}"
        );
        let json = report.to_json().expect("serializes");
        assert!(json.contains("\"receipt_path\""), "{json}");
    }

    #[test]
    fn a_command_that_verifies_no_receipt_reports_no_assertions_rather_than_an_empty_set() {
        let json = report().to_json().expect("serializes");
        assert!(json.contains("\"assertions\": null"), "{json}");
        assert!(!report().to_text().contains("assertions:"));
    }

    #[test]
    fn findings_render_with_their_codes() {
        let text = report()
            .with_findings([Finding::new("witness-stale", "older than the grace period")])
            .to_text();
        assert!(text.contains("[witness-stale] older than the grace period"));
    }
}
