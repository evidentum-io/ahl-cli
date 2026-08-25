//! Local corpus loading, and the walk that produces **findings, not verdicts**.
//!
//! `ahl_core::closure::affected_set` computes graph topology over envelopes handed to it. It
//! does not authenticate a corpus, verify signatures or governance, prove positions, or
//! establish that the corpus is complete. A hostile local corpus therefore manufactures a
//! plausible affected set — which is why a local corpus is only ever the input to *topology
//! mode*, and why topology mode never returns `valid`.
//!
//! In topology mode nothing is evidence, so nothing can be disproved: a corpus is an
//! unauthenticated file the operator handed over, and adjudicating it would imply the CLI had
//! established something it explicitly refuses to establish. Rule violations found while
//! walking such a corpus are therefore **findings, reported in full and never silently
//! skipped**, with the outcome fixed at `unverifiable`. Only a failure to read or parse the
//! input at all is a local-environment failure, because that happens before any walking begins.
//!
//! Loading is bounded — file count, per-file bytes and total entries — so a hostile file
//! cannot exhaust memory where a hostile server cannot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ahl_core::closure::TreeMaterial;
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::governance::Governance;
use crate::policy::LocalLimits;
use crate::report::Finding;
use crate::secure;

/// The seven statement types (core spec §2.2).
pub const STATEMENT_TYPES: [&str; 7] =
    ["ingestion", "derivation", "retraction", "correction", "propagation", "manifest", "key"];

/// A loaded corpus: entries in ascending entry-index order.
#[derive(Debug, Clone, Default)]
pub struct Corpus {
    /// `(entry_index, envelope)`, ascending and duplicate-free after loading.
    pub entries: Vec<(u64, Value)>,
    /// Findings raised while loading, before any walk.
    pub findings: Vec<Finding>,
}

impl Corpus {
    /// The envelopes in entry-index order, dense from index 0, as `ahl-core`'s closure
    /// functions expect (the position in the slice *is* the entry index).
    ///
    /// # Errors
    ///
    /// [`CliError::TopologyMode`] if the corpus is not dense from 0 — `ahl-core` keys on slice
    /// position, so a sparse corpus would silently shift every index.
    pub fn dense_envelopes(&self) -> CliResult<Vec<Value>> {
        let mut out = Vec::with_capacity(self.entries.len());
        for (expected, (index, envelope)) in self.entries.iter().enumerate() {
            if *index != expected as u64 {
                return Err(CliError::TopologyMode(format!(
                    "the corpus is not dense from entry index 0: position {expected} carries \
                     index {index}. Closure traversal keys on the entry index, so a corpus with \
                     a hole cannot be walked without inventing one"
                )));
            }
            out.push(envelope.clone());
        }
        Ok(out)
    }
}

/// Read a corpus from a directory of per-entry JSON files, or from one JSON file holding an
/// array of them.
///
/// Each element is `{ "entry_index": n, "envelope": { ... } }`; extra members (the `entry_id`
/// and `statement_id` the AHL conformance corpus carries) are ignored, because a filename and
/// a carried identifier are both untrusted labels.
///
/// # Errors
///
/// [`CliError::Open`] if the path cannot be read and [`CliError::Unparseable`] if it does not
/// parse — both local-environment failures before any walking begins;
/// [`CliError::LimitExhausted`] on a bound.
pub fn load(path: &Path, limits: LocalLimits) -> CliResult<Corpus> {
    let mut raw: Vec<Value> = Vec::new();
    if path.is_dir() {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)
            .map_err(|source| CliError::Open {
                what: "corpus directory",
                path: path.display().to_string(),
                detail: source.to_string(),
            })?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        // Sorted so a directory listing order cannot change the result.
        files.sort();
        if files.len() > limits.max_corpus_entries {
            return Err(CliError::LimitExhausted(format!(
                "the corpus directory holds {} files, beyond the configured maximum of {}",
                files.len(),
                limits.max_corpus_entries
            )));
        }
        for file in files {
            let bytes = secure::read_regular("corpus entry", &file, limits.max_file_bytes)?;
            raw.push(parse("corpus entry", &file.display().to_string(), &bytes)?);
        }
    } else {
        let bytes = secure::read_regular("corpus", path, limits.max_file_bytes)?;
        let value = parse("corpus", &path.display().to_string(), &bytes)?;
        match value {
            Value::Array(items) => raw = items,
            other => raw.push(other),
        }
    }

    if raw.len() > limits.max_corpus_entries {
        return Err(CliError::LimitExhausted(format!(
            "the corpus holds {} entries, beyond the configured maximum of {}",
            raw.len(),
            limits.max_corpus_entries
        )));
    }

    let mut findings = Vec::new();
    let mut entries: Vec<(u64, Value)> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for (position, item) in raw.into_iter().enumerate() {
        let Some(index) = item.get("entry_index").and_then(Value::as_u64) else {
            findings.push(Finding::new(
                "corpus-entry-unindexed",
                format!("the element at position {position} carries no `entry_index`"),
            ));
            continue;
        };
        let Some(envelope) = item.get("envelope").filter(|value| value.is_object()) else {
            findings.push(Finding::new(
                "corpus-entry-unenveloped",
                format!("the entry at index {index} carries no `envelope` object"),
            ));
            continue;
        };
        if !seen.insert(index) {
            findings.push(Finding::new(
                "corpus-duplicate-entry-index",
                format!(
                    "entry index {index} appears more than once; the entry index is an \
                     immutable position and cannot be occupied twice"
                ),
            ));
            continue;
        }
        entries.push((index, envelope.clone()));
    }
    entries.sort_by_key(|(index, _)| *index);
    Ok(Corpus { entries, findings })
}

/// A parse failure happens **before any walking begins**, so it is a local-environment
/// failure (exit `2`), not a finding about the operator's corpus. Everything the walk finds
/// afterwards is a finding and leaves the outcome at `3`.
fn parse(what: &'static str, label: &str, bytes: &[u8]) -> CliResult<Value> {
    serde_json::from_slice(bytes).map_err(|source| CliError::Unparseable {
        what,
        path: label.to_owned(),
        detail: format!("does not parse as JSON: {source}"),
    })
}

/// Read committed tree material: a map from anchored root to its claimed leaf set.
///
/// The values are **untrusted**. They become usable only through `ahl-core`'s
/// `ValidatedLeafSet`, which checks them against the anchored root, the committed count and the
/// ordering rule before any edge is read from them.
///
/// # Errors
///
/// [`CliError::Open`] if the file cannot be read; [`CliError::Unparseable`] if it does not
/// parse into a root-to-leaves map.
pub fn load_tree_material(path: &Path, limits: LocalLimits) -> CliResult<TreeMaterial> {
    let bytes = secure::read_regular("tree material", path, limits.max_file_bytes)?;
    let value: Value = parse("tree material", &path.display().to_string(), &bytes)?;
    let object = value.as_object().ok_or_else(|| CliError::Unparseable {
        what: "tree material",
        path: path.display().to_string(),
        detail: "must be a JSON object mapping each anchored root to its leaf set".to_owned(),
    })?;
    let mut material = BTreeMap::new();
    for (root, leaves) in object {
        let leaves = leaves.as_array().ok_or_else(|| CliError::Unparseable {
            what: "tree material",
            path: path.display().to_string(),
            detail: format!("the material for `{root}` is not an array"),
        })?;
        material.insert(root.clone(), leaves.clone());
    }
    Ok(material)
}

/// Walk a corpus and report every rule violation as a finding.
///
/// Nothing here adjudicates: the corpus is unauthenticated input, so a violation found in it
/// says something about the file the operator handed over and nothing about the log.
#[must_use]
// One pass over one corpus, raising every finding it can. Splitting the per-statement checks
// out would hide that they are exhaustive over one entry, which is the property that matters:
// a violation is never skipped because an earlier one fired.
#[allow(clippy::too_many_lines)]
pub fn walk(corpus: &Corpus) -> Vec<Finding> {
    let mut findings = corpus.findings.clone();
    let mut statement_ids: BTreeMap<String, u64> = BTreeMap::new();

    // Governance may or may not be resolvable from an unauthenticated corpus. A defect in one
    // entry never ends the collection — it is excluded and reported, and every later entry is
    // still walked — so the two cases below are the only ones that leave no key set at all to
    // resolve a signature against, and each is reported in as many words.
    let governance = Governance::structural_only(&corpus.entries);
    // Taken unconditionally: a walk that reached a limit still reports what it found before
    // reaching it. A corpus whose only manifest was excluded for breaking the predecessor rule
    // has to say *that*, not merely that no chain remained — the general answer alone would
    // suppress the specific one the walk already established.
    findings.extend(governance.findings.iter().cloned());
    match &governance.chain {
        Ok(chain) => {
            // The manifest side of the same duty. A key object that cannot be read is left out
            // of the key set — reading it leniently would quietly shrink the set a signature
            // resolves against — so topology mode has to be told, and this is the only caller
            // that builds a structural chain. `resolve` rejects such a manifest outright, so on
            // an authenticated chain there is nothing here to say.
            findings.extend(chain.log_object_findings());
        }
        Err(error) => findings.push(Finding::new(
            "corpus-governance-unresolvable",
            format!(
                "producer signatures were not checked because the corpus's governance chain \
                 does not resolve: {error}"
            ),
        )),
    }

    for (index, envelope) in &corpus.entries {
        let Some(payload) = envelope.get("payload").filter(|value| value.is_object()) else {
            findings.push(Finding::new(
                "statement-unenveloped",
                format!("the entry at index {index} carries no `payload` object"),
            ));
            continue;
        };

        match ahl_core::statement_id(envelope) {
            Ok(statement_id) => {
                if let Some(first) = statement_ids.insert(statement_id.clone(), *index) {
                    findings.push(Finding::new(
                        "statement-id-not-unique",
                        format!(
                            "entry {index} repeats the statement id first anchored at {first}; \
                             core spec §2.1 makes the one with the smallest entry index govern \
                             and voids later ones"
                        ),
                    ));
                }
            }
            Err(source) => findings.push(Finding::new(
                "statement-id-unavailable",
                format!("entry {index} has no computable statement id: {source}"),
            )),
        }

        let kind = payload.get("type").and_then(Value::as_str).unwrap_or_default();
        if !STATEMENT_TYPES.contains(&kind) {
            // Never skipped, never inert.
            findings.push(Finding::new(
                "unknown-statement-type",
                format!(
                    "entry {index} declares statement type `{kind}`, which is not one of the seven"
                ),
            ));
        }

        let carries_manifest = payload.get("manifest").is_some();
        if kind == "manifest" && carries_manifest {
            findings.push(Finding::new(
                "manifest-statement-carries-manifest-member",
                format!(
                    "entry {index} is a manifest statement and must carry no `manifest` member"
                ),
            ));
        } else if kind != "manifest" && !carries_manifest && STATEMENT_TYPES.contains(&kind) {
            findings.push(Finding::new(
                "statement-unbound-to-manifest",
                format!("entry {index} declares no `manifest` version (core spec §2.2)"),
            ));
        }

        if matches!(kind, "retraction" | "correction") && payload.get("scope").is_none() {
            findings.push(Finding::new(
                "trigger-without-scope",
                format!(
                    "entry {index} is a trigger with no `scope`; scopeless triggers are malformed"
                ),
            ));
        }
        if kind == "correction" && payload.get("replacement").is_none() {
            findings.push(Finding::new(
                "correction-without-replacement",
                format!("entry {index} is a correction naming no `replacement`"),
            ));
        }
        if kind == "derivation" {
            findings.extend(derivation_findings(*index, payload));
        }

        match envelope.get("signatures").and_then(Value::as_array) {
            None => findings.push(Finding::new(
                "statement-unsigned",
                format!(
                    "entry {index} carries no signatures; unsigned objects are not AHL statements"
                ),
            )),
            Some(signatures) if signatures.is_empty() => findings.push(Finding::new(
                "statement-unsigned",
                format!(
                    "entry {index} carries no signatures; unsigned objects are not AHL statements"
                ),
            )),
            Some(_) => {
                if let Ok(chain) = &governance.chain {
                    match chain.envelope_verifies_at(envelope, *index) {
                        Ok(true) => {}
                        Ok(false) => findings.push(Finding::new(
                            "signature-does-not-verify",
                            format!(
                                "entry {index} carries a signature that does not resolve to a \
                                 key active at that index, or does not verify"
                            ),
                        )),
                        Err(source) => findings.push(Finding::new(
                            "signature-unreadable",
                            format!("entry {index}: {source}"),
                        )),
                    }
                }
            }
        }
    }

    findings.sort();
    findings.dedup();
    findings
}

fn derivation_findings(index: u64, payload: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let batched = payload.get("outputs_root").is_some();
    if !batched {
        match payload.get("outputs").and_then(Value::as_array) {
            None => findings.push(Finding::new(
                "derivation-without-outputs",
                format!(
                    "entry {index} is a derivation carrying neither `outputs` nor `outputs_root`"
                ),
            )),
            Some(outputs) => {
                for (position, output) in outputs.iter().enumerate() {
                    if output.get("record").and_then(Value::as_str).is_none() {
                        findings.push(Finding::new(
                            "derivation-output-without-record",
                            format!("entry {index}, output {position}, names no `record`"),
                        ));
                    }
                }
            }
        }
    }
    if let Some(inputs) = payload.get("inputs").and_then(Value::as_array) {
        for (position, input) in inputs.iter().enumerate() {
            if input.get("record").and_then(Value::as_str).is_none() {
                findings.push(Finding::new(
                    "derivation-input-without-record",
                    format!(
                        "entry {index}, input {position}, names no `record`; closure traversal \
                         uses `(dataset, record)` only, so an input without one cannot be \
                         reached by any trigger"
                    ),
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use ahl_core::TestKey;
    use serde_json::json;

    use super::*;

    fn corpus_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ahl-core/test_data/vectors/statements")
    }

    fn limits() -> LocalLimits {
        LocalLimits::default()
    }

    #[test]
    fn the_conformance_corpus_loads_dense_and_in_entry_index_order() {
        let corpus = load(&corpus_dir(), limits()).expect("loads");
        assert!(corpus.entries.len() >= 25, "the toy corpus carries 25+ entries");
        let indexes: Vec<u64> = corpus.entries.iter().map(|(index, _)| *index).collect();
        let mut sorted = indexes.clone();
        sorted.sort_unstable();
        assert_eq!(indexes, sorted);
        assert_eq!(corpus.dense_envelopes().expect("dense").len(), corpus.entries.len());
    }

    #[test]
    fn a_single_file_holding_an_array_loads_the_same_way() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corpus = load(&corpus_dir(), limits()).expect("loads");
        let array: Vec<Value> = corpus
            .entries
            .iter()
            .map(|(index, envelope)| json!({ "entry_index": index, "envelope": envelope }))
            .collect();
        let path = dir.path().join("corpus.json");
        std::fs::write(&path, serde_json::to_vec(&array).expect("serialize")).expect("write");
        let from_file = load(&path, limits()).expect("loads");
        assert_eq!(from_file.entries, corpus.entries);
    }

    #[test]
    fn walking_the_conformance_corpus_reports_exactly_its_deliberate_violations() {
        let corpus = load(&corpus_dir(), limits()).expect("loads");
        let findings = walk(&corpus);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code.as_str()).collect();

        // Entries 28 and 29 exist precisely to carry signatures that do not verify, so the
        // negative receipt vectors have something to trip on. A walk that did not surface them
        // would be skipping violations.
        assert!(codes.contains("signature-does-not-verify"));

        // The corpus previously anchored three envelopes over one payload, which core §2.1
        // makes a duplicate-statement-id violation. It has since been regenerated to give each
        // a distinct payload, so the rule has nothing to fire on here; it is pinned instead by
        // `a_repeated_statement_id_is_reported_with_the_index_that_governs` over a fixture this
        // crate controls, which is where a normative rule belongs.
        assert!(
            !codes.contains("statement-id-not-unique"),
            "the regenerated corpus should carry no duplicate statement ids: {findings:?}"
        );

        assert_eq!(
            codes,
            BTreeSet::from(["signature-does-not-verify"]),
            "unexpected findings: {findings:?}"
        );
    }

    fn producer() -> TestKey {
        TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed")
    }

    fn genesis() -> Value {
        let key = producer();
        json!({
            "entry_index": 0,
            "envelope": ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "producer": "producer-1",
                    "keys": [ key.key_object(0) ],
                    "log": { "log_id": "sha256:aa", "keys": [] },
                }),
                &key,
            ),
        })
    }

    fn corpus_of(items: &[Value]) -> Corpus {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, serde_json::to_vec(items).expect("serialize")).expect("write");
        load(&path, limits()).expect("loads")
    }

    #[test]
    fn a_defect_in_the_governance_chain_never_silences_the_entries_after_it() {
        // Design note §6 fixes topology mode's whole contract: rule violations found while
        // walking are findings, reported **in full** and never suppressed, with the outcome at
        // `3`. A defect that ended the collection would take every later check down with it,
        // and the list of violations is the one thing this mode exists to produce — a shorter
        // list is not a safer answer, it is a wrong one.
        //
        // The corpus is the smallest shape that shows it. Entry 1 carries a `key` add whose
        // `key_id` does not recompute from the `pubkey` beside it: it must never join a key set
        // (core §2.3.6, adaptor §7.2), so it is excluded — and its exclusion must not hide the
        // ordinary signature violation sitting at entry 2.
        let key = producer();
        let attacker = TestKey::from_seed_hex("attacker", &"7d".repeat(32)).expect("seed");
        let fake = TestKey::from_seed_hex("fake", &"7c".repeat(32)).expect("seed");
        let stranger = TestKey::from_seed_hex("stranger", &"09".repeat(32)).expect("seed");

        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({
                    "type": "key",
                    "action": "add",
                    "manifest": "sha256:aa",
                    "key": { "key_id": fake.key_id(), "pubkey": attacker.pubkey() },
                }), &key) }),
            json!({ "entry_index": 2, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa", "dataset": "d",
                        "record": "sha256:bb" }), &stranger) }),
        ]);

        let findings = walk(&corpus);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code.as_str()).collect();

        // The forged binding is excluded, and said so.
        assert!(codes.contains("governance-element-excluded"), "{findings:?}");
        assert!(
            findings.iter().any(|f| f.detail.contains("recomputes to")),
            "the exclusion must name why the binding was refused: {findings:?}"
        );
        // And the attacker's key never reached the key set through it.
        let governance = Governance::structural_only(&corpus.entries).chain.expect("chain");
        assert!(!governance.producer_keys_at(2).contains_key(&fake.key_id()));
        assert!(!governance.producer_keys_at(2).contains_key(&attacker.key_id()));

        // The violation *after* it is still reported — the whole point.
        assert!(
            codes.contains("signature-does-not-verify"),
            "entry 2's signature violation disappeared behind the excluded element: {findings:?}"
        );
        assert!(
            !codes.contains("corpus-governance-unresolvable"),
            "one bad element must not make the chain unresolvable: {findings:?}"
        );
    }

    #[test]
    fn the_reason_the_chain_emptied_is_reported_beside_the_fact_that_it_did() {
        // The terminal path. This corpus's only manifest sits at index 0 and carries a
        // `predecessor` the genesis manifest must not have (core §2.3.5, adaptor §7.4.1). It is
        // excluded and reported — and then nothing is left to be a chain, which is one of the
        // two limits this walk still stops at.
        //
        // Both answers have to reach the report. Returning only the general one would replace
        // an established violation with "the chain does not resolve", which is the same
        // suppression §6 forbids, just moved to the last line: the walk *knows* why no manifest
        // remained, and the operator is the one who needs to be told.
        let key = producer();
        let corpus = corpus_of(&[json!({
            "entry_index": 0,
            "envelope": ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "producer": "producer-1",
                    "predecessor": format!("sha256:{}", "aa".repeat(32)),
                    "keys": [ key.key_object(0) ],
                    "log": { "log_id": "sha256:aa", "keys": [] },
                }),
                &key,
            ),
        })]);

        let findings = walk(&corpus);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains("governance-element-excluded"),
            "the defect that emptied the chain must be reported: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("no predecessor reference")),
            "and it must name the rule that fired: {findings:?}"
        );
        assert!(
            codes.contains("corpus-governance-unresolvable"),
            "alongside the fact that no chain remained: {findings:?}"
        );
    }

    #[test]
    fn a_broken_manifest_key_object_is_reported_without_silencing_the_entries_after_it() {
        // The symmetric case. A manifest key object that cannot be read is left out of the key
        // set — reading it leniently would quietly shrink the set a signature resolves against
        // — but the structural walk does not stop there either, so entry 2's signature
        // violation is still enumerated.
        let key = producer();
        let stranger = TestKey::from_seed_hex("stranger", &"09".repeat(32)).expect("seed");
        let broken = json!({
            "entry_index": 0,
            "envelope": ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "producer": "producer-1",
                    "keys": [ key.key_object(0) ],
                    "log": { "log_id": "sha256:aa",
                             "keys": [ { "key_id": "sha256:aa", "pubkey": "base64:zzz" } ] },
                }),
                &key,
            ),
        });
        let corpus = corpus_of(&[
            broken,
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa", "dataset": "d",
                        "record": "sha256:aa" }), &key) }),
            json!({ "entry_index": 2, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa", "dataset": "d",
                        "record": "sha256:bb" }), &stranger) }),
        ]);

        let findings = walk(&corpus);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains("manifest-log-object-incomplete"), "{findings:?}");
        assert!(codes.contains("signature-does-not-verify"), "{findings:?}");
        assert!(!codes.contains("corpus-governance-unresolvable"), "{findings:?}");
        // Entry 1 is signed by a key the manifest really does declare, so it is not reported.
        assert!(
            findings
                .iter()
                .all(|f| !(f.code == "signature-does-not-verify" && f.detail.contains("entry 1 "))),
            "{findings:?}"
        );
    }

    #[test]
    fn every_rule_violation_in_a_hostile_corpus_is_reported_and_none_is_skipped() {
        let key = producer();
        let stranger = TestKey::from_seed_hex("stranger", &"09".repeat(32)).expect("seed");
        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({ "type": "attestation", "manifest": "sha256:aa" }), &key) }),
            json!({ "entry_index": 2, "envelope": ahl_core::envelope(
                json!({ "type": "retraction", "manifest": "sha256:aa",
                        "dataset": "d", "record": "sha256:bb" }), &key) }),
            json!({ "entry_index": 3, "envelope": ahl_core::envelope(
                json!({ "type": "correction", "manifest": "sha256:aa", "dataset": "d",
                        "record": "sha256:bb",
                        "scope": { "effective_from": "2026-01-01T00:00:00Z", "retroactive": true } }),
                &key) }),
            json!({ "entry_index": 4, "envelope": ahl_core::envelope(
                json!({ "type": "derivation", "manifest": "sha256:aa",
                        "inputs": [ { "dataset": "d" } ] }), &key) }),
            json!({ "entry_index": 5, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "dataset": "d", "record": "sha256:cc" }), &key) }),
            json!({ "entry_index": 6, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa", "dataset": "d",
                        "record": "sha256:dd" }), &stranger) }),
            json!({ "entry_index": 7, "envelope": json!({
                "payload": { "type": "ingestion", "manifest": "sha256:aa" },
                "signatures": [] }) }),
        ]);

        let findings = walk(&corpus);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        for expected in [
            "unknown-statement-type",
            "trigger-without-scope",
            "correction-without-replacement",
            "derivation-without-outputs",
            "derivation-input-without-record",
            "statement-unbound-to-manifest",
            "signature-does-not-verify",
            "statement-unsigned",
        ] {
            assert!(codes.contains(expected), "missing `{expected}` in {codes:?}");
        }
    }

    #[test]
    fn findings_are_ordered_and_duplicate_free() {
        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({ "type": "attestation", "manifest": "sha256:aa" }), &producer()) }),
            json!({ "entry_index": 2, "envelope": ahl_core::envelope(
                json!({ "type": "attestation", "manifest": "sha256:aa" }), &producer()) }),
        ]);
        let findings = walk(&corpus);
        let mut sorted = findings.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(findings, sorted);
    }

    #[test]
    fn a_duplicate_entry_index_is_reported_rather_than_silently_overwriting() {
        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa" }), &producer()) }),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa" }), &producer()) }),
        ]);
        assert!(corpus.findings.iter().any(|f| f.code == "corpus-duplicate-entry-index"));
        assert_eq!(corpus.entries.len(), 2);
    }

    #[test]
    fn a_repeated_statement_id_is_reported_with_the_index_that_governs() {
        let key = producer();
        let payload = json!({ "type": "ingestion", "manifest": "sha256:aa", "dataset": "d",
                              "record": "sha256:bb" });
        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 1, "envelope": ahl_core::envelope(payload.clone(), &key) }),
            json!({ "entry_index": 2, "envelope": ahl_core::envelope(payload, &key) }),
        ]);
        let findings = walk(&corpus);
        let finding = findings
            .iter()
            .find(|f| f.code == "statement-id-not-unique")
            .expect("duplicate statement id");
        assert!(finding.detail.contains("smallest entry index"), "{}", finding.detail);
    }

    #[test]
    fn an_unresolvable_governance_chain_is_reported_rather_than_skipping_signature_checks() {
        let corpus = corpus_of(&[json!({
            "entry_index": 0,
            "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa" }), &producer()),
        })]);
        let findings = walk(&corpus);
        assert!(findings.iter().any(|f| f.code == "corpus-governance-unresolvable"));
    }

    #[test]
    fn malformed_elements_are_reported_rather_than_dropped_silently() {
        let corpus = corpus_of(&[
            json!({ "envelope": { "payload": {} } }),
            json!({ "entry_index": 1 }),
            json!({ "entry_index": 2, "envelope": "not an object" }),
        ]);
        let codes: BTreeSet<&str> = corpus.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains("corpus-entry-unindexed"));
        assert!(codes.contains("corpus-entry-unenveloped"));
        assert!(corpus.entries.is_empty());
    }

    #[test]
    fn a_sparse_corpus_is_refused_rather_than_walked_with_invented_indexes() {
        let corpus = corpus_of(&[
            genesis(),
            json!({ "entry_index": 7, "envelope": ahl_core::envelope(
                json!({ "type": "ingestion", "manifest": "sha256:aa" }), &producer()) }),
        ]);
        let error = corpus.dense_envelopes().expect_err("sparse");
        assert!(error.to_string().contains("not dense"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn loading_is_bounded_by_entry_count_and_by_file_size() {
        let limits = LocalLimits { max_corpus_entries: 2, max_file_bytes: 1 << 20 };
        let error = load(&corpus_dir(), limits).expect_err("too many files");
        assert!(error.to_string().contains("maximum"), "{error}");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, b"[]").expect("write");
        let tiny = LocalLimits { max_corpus_entries: 10, max_file_bytes: 1 };
        assert!(load(&path, tiny).is_err());
    }

    #[test]
    fn an_unparseable_corpus_is_reported_before_any_walking_begins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.json");
        std::fs::write(&path, b"{oops").expect("write");
        let error = load(&path, limits()).expect_err("unparseable");
        assert!(error.to_string().contains("does not parse"), "{error}");
        assert_eq!(
            error.outcome(),
            crate::outcome::Outcome::Error,
            "a parse failure happens before any walking begins"
        );
    }

    #[test]
    fn an_absent_corpus_path_is_an_open_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = load(&dir.path().join("absent.json"), limits()).expect_err("absent");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Error);
    }

    #[test]
    fn tree_material_loads_as_an_untrusted_root_to_leaves_map() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trees.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "sha256:aa": [ { "dataset": "d", "record": "sha256:bb" } ],
            }))
            .expect("serialize"),
        )
        .expect("write");
        let material = load_tree_material(&path, limits()).expect("loads");
        assert_eq!(material["sha256:aa"].len(), 1);

        std::fs::write(&path, b"[]").expect("write");
        assert!(load_tree_material(&path, limits()).is_err());
        std::fs::write(&path, br#"{"sha256:aa": 7}"#).expect("write");
        assert!(load_tree_material(&path, limits()).is_err());
    }

    #[test]
    fn a_single_object_input_is_read_as_a_one_entry_corpus() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("one.json");
        std::fs::write(&path, serde_json::to_vec(&genesis()).expect("serialize")).expect("write");
        assert_eq!(load(&path, limits()).expect("loads").entries.len(), 1);
    }
}
