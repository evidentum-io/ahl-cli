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
//! # Determinism
//!
//! Key order is the declaration order of these structs, and every printed set is ordered
//! lexicographically by a stated field: affected sets by `(dataset, record)`, findings by
//! `(code, detail)`, key ids as strings. Given the same inputs, the same policy and the same
//! `--evaluation-time`, stdout is byte-identical.

use std::collections::BTreeSet;

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

/// The verified assurance block (receipt format §2.1).
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
    /// The verified assurance block.
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
            receipt_note: None,
            affected: None,
            topology_affected: None,
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
        out.push_str(&format!("status: {}\n", self.status));
        out.push_str(&format!("reason: [{}] {}\n", self.reason_code, self.reason));
        if let Some(claim_type) = &self.claim_type {
            out.push_str(&format!("claim type: {claim_type}\n"));
        }
        if let Some(boundary) = &self.boundary {
            out.push_str(&format!("boundary: {boundary}\n"));
        }
        if let Some(assurance) = &self.assurance {
            // Assurance fields print in full: `governance: declared` and
            // `governance: enumerated` are different results and never collapse to one glyph.
            out.push_str("assurance:\n");
            out.push_str(&format!("  governance: {}\n", assurance.governance));
            out.push_str(&format!("  competing_triggers: {}\n", assurance.competing_triggers));
            out.push_str(&format!("  witnessed: {}\n", assurance.witnessed));
            out.push_str(&format!("  continued_history: {}\n", assurance.continued_history));
            out.push_str(&format!("  content_binding: {}\n", assurance.content_binding));
        }
        if let Some(checkpoint) = &self.checkpoint {
            out.push_str(&format!(
                "checkpoint: log_id={} tree_size={} root_hash={}\n",
                checkpoint.log_id, checkpoint.tree_size, checkpoint.root_hash
            ));
        }
        out.push_str(&format!("authenticated: {}\n", self.authenticated));
        out.push_str(&format!("completeness: {}\n", completeness_str(self.completeness)));
        out.push_str(&format!(
            "evaluation time: {} (source: {})\n",
            self.evaluation_time,
            match self.evaluation_time_source {
                TimeSource::Clock => "clock",
                TimeSource::Override => "override",
            }
        ));
        if let Some(bound) = self.series_usable_bound {
            out.push_str(&format!("series usable bound: {}\n", bound_str(bound)));
        }
        if let Some(bound) = self.continued_history_bound {
            out.push_str(&format!("continued history bound: {}\n", bound_str(bound)));
        }
        if let Some(note) = &self.receipt_note {
            // Attributed to the receipt, never presented as a finding.
            out.push_str(&format!("the receipt says (informative, not a finding): \"{note}\"\n"));
        }
        if !self.findings.is_empty() {
            out.push_str("findings:\n");
            for finding in &self.findings {
                out.push_str(&format!("  [{}] {}\n", finding.code, finding.detail));
            }
        }
        if let Some(affected) = &self.affected {
            out.push_str(&format!("affected ({}):\n", affected.len()));
            for record in affected {
                out.push_str(&format!("  {} {}\n", record.dataset, record.record));
            }
        }
        if let Some(topology) = &self.topology_affected {
            out.push_str(&format!("topology affected ({}), unauthenticated:\n", topology.len()));
            for record in topology {
                out.push_str(&format!("  {} {}\n", record.dataset, record.record));
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
        });
        let text = report.to_text();
        for expected in [
            "governance: enumerated",
            "competing_triggers: enumerated",
            "witnessed: true",
            "continued_history: false",
            "content_binding: keyed-authorized",
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
        complete.affected = Some(vec![RecordOut {
            dataset: "scores".to_owned(),
            record: "sha256:cc".to_owned(),
        }]);
        let text = complete.to_text();
        assert!(text.contains("completeness: complete"));
        assert!(text.contains("affected (1)"));
        assert!(text.contains("scores sha256:cc"));
    }

    #[test]
    fn findings_render_with_their_codes() {
        let text = report()
            .with_findings([Finding::new("witness-stale", "older than the grace period")])
            .to_text();
        assert!(text.contains("[witness-stale] older than the grace period"));
    }
}
