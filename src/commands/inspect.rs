//! `inspect` — a structural dump, and **no verdict**.
//!
//! No verdict, no checkmark, no "looks valid". Every value this command prints is labelled as
//! *declared by the receipt*, because that is all it is: `inspect` verifies nothing, so an
//! assurance block it prints is the receipt's own claim about itself and not a finding of any
//! kind. A reader who wants a verdict runs `verify`.
//!
//! The one thing `inspect` does check is that the bytes parse and are JCS-canonical, because a
//! dump of something that is not a receipt would be a dump of nothing.
//!
//! Its exit code is `0` when a dump was produced, `1` when the bytes are present but are not a
//! canonical receipt object, and `2` when the file could not be read at all. `0` here means
//! "the dump was produced" and never "the receipt is valid" — the output carries no verdict
//! field for a consumer to misread.

use serde::Serialize;
use serde_json::Value;
use std::fmt::Write as _;

use crate::error::{CliError, CliResult};
use crate::outcome::Outcome;
use crate::policy::LoadedPolicy;
use crate::secure;

/// Options for one `inspect` run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Path to the `.ahl` receipt.
    pub receipt: std::path::PathBuf,
}

/// One embedded receipt, dumped recursively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbeddedDump {
    /// Where in the claim material it sits.
    pub slot: String,
    /// The claim type it declares.
    pub declared_claim_type: Option<String>,
    /// Its subject entry index, as declared.
    pub declared_entry_index: Option<u64>,
    /// Receipts embedded inside it.
    pub embedded: Vec<Self>,
}

/// The structural dump. Deliberately carries no `status`, no boundary and no verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dump {
    /// A standing reminder in the document itself.
    pub disclaimer: &'static str,
    /// Size of the file on disk.
    pub file_bytes: usize,
    /// Whether the bytes are the JCS-canonical serialization of the parsed object.
    pub jcs_canonical: bool,
    /// `ahl_receipt_version`, as declared.
    pub declared_receipt_version: Option<String>,
    /// `spec_version`, as declared.
    pub declared_spec_version: Option<String>,
    /// `claim.type`, as declared.
    pub declared_claim_type: Option<String>,
    /// `claim.assurance`, verbatim and unverified.
    pub declared_assurance: Option<Value>,
    /// `claim.note`, quoted; informative, never normative.
    pub declared_note: Option<String>,
    /// The subject block, as declared.
    pub declared_subject: Option<Value>,
    /// The subject envelope's statement type, as declared.
    pub declared_statement_type: Option<String>,
    /// The pinned adaptor `{id, hash}`, as declared.
    pub declared_adaptor: Option<Value>,
    /// The checkpoint identity, as declared.
    pub declared_checkpoint: Option<Value>,
    /// Witness ids carrying a cosignature, as declared, in lexicographic order.
    pub declared_witness_ids: Vec<String>,
    /// Governance chain entry indexes, as declared, ascending.
    pub declared_governance_indexes: Vec<u64>,
    /// `governance.currency.mode`, as declared.
    pub declared_currency_mode: Option<String>,
    /// `governance.genesis_entry_id`, as declared. Not compared against policy here.
    pub declared_genesis_entry_id: Option<String>,
    /// Top-level member names of `claim_material`, in lexicographic order.
    pub claim_material_members: Vec<String>,
    /// Embedded receipts, recursively.
    pub embedded: Vec<EmbeddedDump>,
    /// External anchor types carried, in lexicographic order.
    pub declared_anchor_types: Vec<String>,
}

const DISCLAIMER: &str = "structural dump only: nothing here is verified, and no field of this \
                          document is a verdict. Run `ahl-cli verify` for a verdict.";

/// Produce the dump, or the outcome that stopped it.
///
/// # Errors
///
/// [`CliError::Open`] if the file cannot be read (`2`); [`CliError::Malformed`] if the bytes
/// are not a canonical receipt object (`1`).
pub fn run(policy: &LoadedPolicy, options: &Options) -> CliResult<Dump> {
    let bytes = secure::read_regular("receipt", &options.receipt, policy.local.max_file_bytes)?;
    let receipt: Value = serde_json::from_slice(&bytes).map_err(|source| CliError::Malformed {
        what: "receipt",
        detail: format!("not JSON: {source}"),
    })?;
    if !receipt.is_object() {
        return Err(CliError::Malformed {
            what: "receipt",
            detail: "the top level is not a JSON object".to_owned(),
        });
    }
    let jcs_canonical = ahl_core::jcs(&receipt) == bytes;

    Ok(Dump {
        disclaimer: DISCLAIMER,
        file_bytes: bytes.len(),
        jcs_canonical,
        declared_receipt_version: text(&receipt, &["ahl_receipt_version"]),
        declared_spec_version: text(&receipt, &["spec_version"]),
        declared_claim_type: text(&receipt, &["claim", "type"]),
        declared_assurance: at(&receipt, &["claim", "assurance"]).cloned(),
        declared_note: text(&receipt, &["claim", "note"]),
        declared_subject: at(&receipt, &["subject"]).cloned(),
        declared_statement_type: text(&receipt, &["envelope", "payload", "type"]),
        declared_adaptor: at(&receipt, &["anchoring", "adaptor"]).cloned(),
        declared_checkpoint: at(&receipt, &["anchoring", "checkpoint"]).map(identity_only),
        declared_witness_ids: sorted_strings(&receipt, &["anchoring", "witnesses"], "witness_id"),
        declared_governance_indexes: governance_indexes(&receipt),
        declared_currency_mode: text(&receipt, &["governance", "currency", "mode"]),
        declared_genesis_entry_id: text(&receipt, &["governance", "genesis_entry_id"]),
        claim_material_members: members(&receipt, &["claim_material"]),
        embedded: embedded_receipts(at(&receipt, &["claim_material"])),
        declared_anchor_types: sorted_strings(&receipt, &["anchors"], "type"),
    })
}

/// The outcome an inspection produced. `0` means the dump exists, never that it is valid.
#[must_use]
pub const fn outcome_of(result: &CliResult<Dump>) -> Outcome {
    match result {
        Ok(_) => Outcome::Valid,
        Err(error) => error.outcome(),
    }
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for member in path {
        current = current.get(*member)?;
    }
    Some(current)
}

fn text(value: &Value, path: &[&str]) -> Option<String> {
    at(value, path)?.as_str().map(str::to_owned)
}

/// A checkpoint is reduced to its identity fields, because those are what a claim binds on
/// (§7): matching is on `{log_id, tree_size, root_hash}`, never on byte-identity.
fn identity_only(checkpoint: &Value) -> Value {
    serde_json::json!({
        "log_id": checkpoint.get("log_id"),
        "tree_size": checkpoint.get("tree_size"),
        "root_hash": checkpoint.get("root_hash"),
        "checkpoint_time": checkpoint.get("checkpoint_time"),
    })
}

fn sorted_strings(value: &Value, path: &[&str], member: &str) -> Vec<String> {
    let mut out: Vec<String> = at(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().filter_map(|item| item.get(member)?.as_str().map(str::to_owned)).collect()
        })
        .unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

fn governance_indexes(receipt: &Value) -> Vec<u64> {
    let mut out: Vec<u64> = at(receipt, &["governance", "chain"])
        .and_then(Value::as_array)
        .map(|hops| hops.iter().filter_map(|hop| hop.get("entry_index")?.as_u64()).collect())
        .unwrap_or_default();
    out.sort_unstable();
    out
}

fn members(value: &Value, path: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = at(value, path)
        .and_then(Value::as_object)
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// Walk claim material for embedded receipts. An embedded receipt is recognised structurally —
/// an object carrying `ahl_receipt_version` — so a dump never depends on knowing the registry.
fn embedded_receipts(material: Option<&Value>) -> Vec<EmbeddedDump> {
    let Some(Value::Object(object)) = material else { return Vec::new() };
    let mut out: Vec<EmbeddedDump> = object
        .iter()
        .filter(|(_, value)| value.get("ahl_receipt_version").is_some())
        .map(|(slot, value)| EmbeddedDump {
            slot: slot.clone(),
            declared_claim_type: text(value, &["claim", "type"]),
            declared_entry_index: at(value, &["subject", "entry_index"]).and_then(Value::as_u64),
            embedded: embedded_receipts(at(value, &["claim_material"])),
        })
        .collect();
    out.sort_by(|a, b| a.slot.cmp(&b.slot));
    out
}

impl Dump {
    /// Serialize to the stable JSON form, with a trailing newline.
    ///
    /// # Errors
    ///
    /// [`CliError::Internal`] if serialization fails.
    pub fn to_json(&self) -> CliResult<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|source| CliError::Internal(source.to_string()))?;
        text.push('\n');
        Ok(text)
    }

    /// Render the human-readable dump.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{DISCLAIMER}\n");
        let _ = writeln!(out, "file bytes: {}", self.file_bytes);
        let _ = writeln!(out, "JCS-canonical: {}", self.jcs_canonical);
        for (label, value) in [
            ("declared receipt version", &self.declared_receipt_version),
            ("declared spec version", &self.declared_spec_version),
            ("declared claim type", &self.declared_claim_type),
            ("declared statement type", &self.declared_statement_type),
            ("declared currency mode", &self.declared_currency_mode),
            ("declared genesis entry id", &self.declared_genesis_entry_id),
        ] {
            let _ = writeln!(out, "{label}: {}", value.as_deref().unwrap_or("<absent>"));
        }
        if let Some(assurance) = &self.declared_assurance {
            let _ = writeln!(out, "declared assurance (unverified): {assurance}");
        }
        if let Some(checkpoint) = &self.declared_checkpoint {
            let _ = writeln!(out, "declared checkpoint: {checkpoint}");
        }
        if let Some(note) = &self.declared_note {
            let _ = writeln!(out, "the receipt says (informative, not normative): \"{note}\"");
        }
        let _ = writeln!(out, "declared witness ids: {:?}", self.declared_witness_ids);
        let _ = writeln!(
            out,
            "declared governance chain indexes: {:?}",
            self.declared_governance_indexes
        );
        let _ = writeln!(out, "claim material members: {:?}", self.claim_material_members);
        let _ = writeln!(out, "declared anchor types: {:?}", self.declared_anchor_types);
        render_embedded(&mut out, &self.embedded, 0);
        out
    }
}

fn render_embedded(out: &mut String, embedded: &[EmbeddedDump], depth: usize) {
    for item in embedded {
        let _ = writeln!(
            out,
            "{:indent$}embedded `{}`: declared claim type {}, declared entry index {}",
            "",
            item.slot,
            item.declared_claim_type.as_deref().unwrap_or("<absent>"),
            item.declared_entry_index.map_or_else(|| "<absent>".to_owned(), |i| i.to_string()),
            // Depth follows the embedding nesting of the receipt under inspection, which is
            // attacker-chosen. Both are saturating: an absurd depth widens the indent no
            // further instead of wrapping it to zero.
            indent = depth.saturating_mul(2),
        );
        render_embedded(out, &item.embedded, depth.saturating_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Endpoints, LocalLimits, NetworkLimits};

    fn corpus() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ahl-core/test_data")
    }

    fn policy() -> LoadedPolicy {
        LoadedPolicy {
            trust: ahl_core::receipt::TrustPolicy::default(),
            profiles: std::collections::BTreeMap::new(),
            endpoints: Endpoints::default(),
            network: NetworkLimits::default(),
            local: LocalLimits::default(),
        }
    }

    fn dump(file: &str) -> Dump {
        run(&policy(), &Options { receipt: corpus().join("receipts").join(file) })
            .expect("dump produced")
    }

    #[test]
    fn a_dump_carries_no_verdict_on_either_surface() {
        let dump = dump("statement-anchored-valid.ahl");
        let json = dump.to_json().expect("serializes");
        let text = dump.to_text();
        for forbidden in ["\"status\"", "\"valid\"", "\"boundary\"", "looks valid", "✓"] {
            assert!(!json.contains(forbidden), "dump carries `{forbidden}`:\n{json}");
        }
        for forbidden in ["status:", "boundary:", "looks valid", "✓"] {
            assert!(!text.contains(forbidden), "dump carries `{forbidden}`:\n{text}");
        }
        assert!(text.starts_with("structural dump only"));
    }

    #[test]
    fn every_printed_value_is_labelled_as_declared() {
        let dump = dump("trigger-effective-valid.ahl");
        let json = dump.to_json().expect("serializes");
        assert!(json.contains("\"declared_claim_type\": \"trigger-effective\""));
        assert!(json.contains("\"declared_currency_mode\": \"enumerated\""));
        assert!(json.contains("\"jcs_canonical\": true"));
    }

    #[test]
    fn embedded_receipts_are_walked_recursively_and_ordered() {
        let dump = dump("disposition-effective-valid.ahl");
        assert!(!dump.embedded.is_empty(), "this vector embeds receipts");
        let slots: Vec<&str> = dump.embedded.iter().map(|e| e.slot.as_str()).collect();
        let mut sorted = slots.clone();
        sorted.sort_unstable();
        assert_eq!(slots, sorted, "embedded receipts are printed in slot order");
        assert!(
            dump.embedded.iter().any(|e| !e.embedded.is_empty()),
            "this vector nests receipts two deep"
        );
        assert!(dump.to_text().contains("embedded `trigger`"));
    }

    #[test]
    fn the_checkpoint_is_reduced_to_its_identity_fields() {
        let dump = dump("statement-anchored-valid.ahl");
        let checkpoint = dump.declared_checkpoint.expect("declared");
        assert!(checkpoint.get("log_id").is_some());
        assert!(checkpoint.get("tree_size").is_some());
        assert!(checkpoint.get("root_hash").is_some());
        assert!(
            checkpoint.get("signature").is_none(),
            "identity fields only; a signature is not an identity field"
        );
    }

    #[test]
    fn witness_ids_and_governance_indexes_are_ordered() {
        let dump = dump("propagation-complete-valid.ahl");
        let mut witnesses = dump.declared_witness_ids.clone();
        witnesses.sort_unstable();
        assert_eq!(dump.declared_witness_ids, witnesses);
        let mut indexes = dump.declared_governance_indexes.clone();
        indexes.sort_unstable();
        assert_eq!(dump.declared_governance_indexes, indexes);
        assert!(!dump.declared_governance_indexes.is_empty());
    }

    #[test]
    fn an_unreadable_file_is_an_error_and_a_non_object_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = run(&policy(), &Options { receipt: dir.path().join("absent.ahl") });
        assert_eq!(outcome_of(&absent), Outcome::Error);

        let path = dir.path().join("array.ahl");
        std::fs::write(&path, b"[]").expect("write");
        let array = run(&policy(), &Options { receipt: path });
        assert_eq!(outcome_of(&array), Outcome::Invalid);

        let path = dir.path().join("bad.ahl");
        std::fs::write(&path, b"{oops").expect("write");
        let bad = run(&policy(), &Options { receipt: path });
        assert_eq!(outcome_of(&bad), Outcome::Invalid);
    }

    #[test]
    fn a_non_canonical_but_parseable_receipt_still_dumps_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let value: Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("read"),
        )
        .expect("parse");
        let path = dir.path().join("pretty.ahl");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("pretty")).expect("write");
        let dump = run(&policy(), &Options { receipt: path }).expect("dump produced");
        assert!(!dump.jcs_canonical);
        assert!(dump.to_text().contains("JCS-canonical: false"));
    }

    #[test]
    fn a_dump_of_an_almost_empty_object_reports_absences_rather_than_guessing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.ahl");
        std::fs::write(&path, b"{}").expect("write");
        let dump = run(&policy(), &Options { receipt: path }).expect("dump produced");
        assert!(dump.declared_claim_type.is_none());
        assert!(dump.declared_witness_ids.is_empty());
        assert!(dump.claim_material_members.is_empty());
        assert!(dump.to_text().contains("declared claim type: <absent>"));
        assert!(dump.to_json().expect("serializes").contains("\"embedded\": []"));
    }

    #[test]
    fn a_note_is_quoted_and_attributed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("note.ahl");
        std::fs::write(&path, br#"{"claim":{"note":"informative"}}"#).expect("write");
        let dump = run(&policy(), &Options { receipt: path }).expect("dump produced");
        assert!(dump.to_text().contains("the receipt says (informative, not normative)"));
    }
}
