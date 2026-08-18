//! Establishing an AHL-backed view of a log, in the order the design note fixes.
//!
//! `closure` and `reconstruct` are AHL-backed only when **all** of the following are
//! established, and the CLI refuses to produce a result otherwise:
//!
//! 1. a fixed checkpoint `C`, chosen explicitly, **authenticated**: a signed object whose
//!    signature resolves through the governing manifest version, selected by `tree_size`;
//! 2. full authenticated enumeration of `[0, tree_size(C))`, the range proof verified and
//!    `C`'s root **recomputed** from the enumerated leaves;
//! 3. the neighbouring consistency relationships of adaptor §6.6 — predecessor, and successor
//!    where one exists;
//! 4. only now is `C` classified **series-usable**, and only as `run-observed`;
//! 5. every envelope's signature resolving to a key active at its entry index, under the
//!    manifest version governing that index, plus the governance checks of core §2.1–§2.3;
//! 6. trigger effectiveness, where the command needs a trigger;
//! 7. all tree material the closure needs, verified rather than assumed.
//!
//! # Steps 1 and 2 are a joint fixed point, not a sequence
//!
//! Written as a sequence, step 1 precedes step 2. In practice it cannot: authenticating `C`
//! needs the log key from the manifest version governing `tree_size(C)`, that manifest is an
//! entry in the log, and trusting entries needs `C`'s root. The two are mutually dependent.
//!
//! This implementation therefore establishes them as a **joint fixed point** and says so:
//! candidate entries are fetched under the candidate `C`, the range proofs and the recomputed
//! root tie those entries to `C.root_hash`, the governance chain inside them is validated from
//! the **locally configured** genesis anchor, and only a chain that both opens `C`'s root and
//! anchors to configured policy can supply the key that then validates `C`'s signature. All
//! three hold simultaneously or the result is unverifiable. Nothing is trusted on the way
//! round: the entries are content-addressed against `C`'s root, and the anchor comes from
//! policy rather than from the log. This is recorded as an ambiguity in the frozen sources
//! rather than presented as a reading of them.
//!
//! # `run-observed`, and why nothing stronger is claimed
//!
//! The frozen sources define no authenticated completeness proof over *any* history a server
//! publishes. A mirror can withhold a successor and make an older `C` look newest; a witness
//! can serve an older valid cosigned checkpoint. So the CLI never claims unconditional series
//! usability or "the latest witnessed checkpoint" — it claims usability *as of what this run
//! observed*, and labels it that way.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::cache;
use crate::checkpoint::{consistency_verifies, equivocation_floor, Checkpoint, SigningForm};
use crate::enumerate::{Enumerator, LeafForm};
use crate::error::{CliError, CliResult};
use crate::governance::Governance;
use crate::net::{FetchFailure, Fetcher, Request};
use crate::policy::{LoadedPolicy, NetworkLimits};
use crate::report::Finding;

/// How wide one subrange request is, unless a caller narrows it.
pub const DEFAULT_CHUNK: u64 = 512;

/// An established view: a series-usable checkpoint, its complete entry set, and its governance.
#[derive(Debug)]
pub struct Anchored {
    /// The selected checkpoint, authenticated and series-usable as of this run.
    pub checkpoint: Checkpoint,
    /// The complete enumerated entry set of `[0, tree_size(C))`, ascending.
    pub entries: Vec<(u64, Value)>,
    /// The same set as a dense array for traversal, with every entry whose signature does not
    /// verify replaced by a neutral placeholder.
    ///
    /// Core spec §2.1 makes an object whose signatures do not all verify **not an AHL
    /// statement**, and adaptor §7.4.1 spells out the consequence for a permissionless log:
    /// anyone who can reach the submission endpoint can place a well-formed object at a real
    /// index with a real inclusion proof, and a verifier must ignore it rather than treat the
    /// whole log as compromised. Such entries are therefore excluded from traversal and
    /// reported in `findings` — never silently dropped, and never allowed to shift an entry
    /// index, which is why a placeholder occupies the position rather than the entry vanishing.
    pub statements: Vec<Value>,
    /// The governance state resolved from those entries.
    pub governance: Governance,
    /// Findings raised while establishing the view.
    pub findings: Vec<Finding>,
}

/// The client half of a mirror conversation.
#[derive(Debug)]
pub struct Mirror<'a, F: Fetcher> {
    fetcher: &'a F,
    base: String,
    signing_form: SigningForm,
    leaf_form: LeafForm,
    limits: NetworkLimits,
    chunk: u64,
}

impl<'a, F: Fetcher> Mirror<'a, F> {
    /// Bind a client to `base` under the pinned adaptor profile.
    ///
    /// # Errors
    ///
    /// [`CliError::ProfileLimitation`] if this build implements neither the checkpoint signing
    /// form nor the leaf construction of `profile_id`.
    pub fn new(
        fetcher: &'a F,
        base: &str,
        profile_id: &str,
        limits: NetworkLimits,
    ) -> CliResult<Self> {
        Ok(Self {
            fetcher,
            base: base.trim_end_matches('/').to_owned(),
            signing_form: SigningForm::for_profile(profile_id)?,
            leaf_form: LeafForm::for_profile(profile_id)?,
            limits,
            chunk: DEFAULT_CHUNK,
        })
    }

    /// Narrow the subrange width, for tests and for constrained deployments.
    #[must_use]
    pub const fn with_chunk(mut self, chunk: u64) -> Self {
        self.chunk = chunk;
        self
    }

    fn get(&self, path: &str) -> CliResult<Value> {
        // Never cached: see `series` and `checkpoint_at` for the two reasons.
        let response = self
            .fetcher
            .fetch(&Request::get(format!("{}{path}", self.base)))
            .map_err(FetchFailure::into_cli_error)?;
        if response.status != 200 {
            return Err(CliError::EvidenceMissing(format!(
                "the mirror answered {} for `{path}`; a status is an operational failure, never \
                 refusal evidence",
                response.status
            )));
        }
        serde_json::from_slice(&response.body).map_err(|source| {
            CliError::EvidenceMissing(format!("`{path}` did not answer with JSON: {source}"))
        })
    }

    /// The checkpoint series as this run observed it.
    ///
    /// Never served from cache: "what does the log publish now?" answered from a cache is
    /// "what did the log publish then", and a valid old answer is a replay.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the mirror does not answer usably.
    pub fn series(&self) -> CliResult<Vec<Checkpoint>> {
        let value = self.get("/v1/checkpoints")?;
        let members = value.as_array().ok_or_else(|| {
            CliError::EvidenceMissing("the checkpoint series is not an array".to_owned())
        })?;
        members.iter().map(Checkpoint::from_value).collect()
    }

    /// A consistency proof between two sizes, as this mirror serves it.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the mirror does not answer usably.
    pub fn consistency_path(&self, from: u64, to: u64) -> CliResult<Vec<String>> {
        let value = self.get(&format!("/v1/consistency?from={from}&to={to}"))?;
        value
            .get("consistency_path")
            .and_then(Value::as_array)
            .map(|path| path.iter().filter_map(|hash| hash.as_str().map(str::to_owned)).collect())
            .ok_or_else(|| {
                CliError::EvidenceMissing(format!(
                    "the mirror served no `consistency_path` for {from}→{to}"
                ))
            })
    }

    /// Retrieve one entry's bytes by AHL entry id, content-checked against the id requested
    /// (adaptor §10.1.1 verifier duty 1).
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the bytes are absent or do not digest to the id.
    pub fn entry_by_id(
        &self,
        entry_id: &str,
        identity: &cache::CheckpointIdentity,
    ) -> CliResult<Value> {
        let request = Request::get(format!("{}/v1/entries/{entry_id}", self.base));
        let key = cache::request_key(identity, &request);
        let response =
            self.fetcher.fetch(&request.cached_under(key)).map_err(FetchFailure::into_cli_error)?;
        if response.status != 200 {
            // Absence is a fact about the interface, not about the corpus: it is never read as
            // evidence that no such entry was ever anchored.
            return Err(CliError::EvidenceMissing(format!(
                "the mirror does not hold entry `{entry_id}` (status {}); absence is \
                 unavailability, never a negative result about the corpus",
                response.status
            )));
        }
        if ahl_core::sha256_hex(&response.body) != entry_id {
            return Err(CliError::EvidenceMissing(format!(
                "the bytes served for `{entry_id}` do not digest to it; retrieval is \
                 self-checking and a substitution is detected here"
            )));
        }
        serde_json::from_slice(&response.body).map_err(|source| {
            CliError::EvidenceMissing(format!("entry `{entry_id}` is not JSON: {source}"))
        })
    }
}

/// Establish an AHL-backed view at `tree_size`.
///
/// # Errors
///
/// [`CliError::EquivocationAtOrBeyondFloor`] when the result would be grounded at or beyond a
/// confirmed divergence — positive proof of misbehaviour, not absence of evidence.
/// [`CliError::EvidenceMissing`] for every other failure to establish the view: a hostile or
/// merely broken server disproves nothing about the user's artifact.
pub fn establish<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    policy: &LoadedPolicy,
    tree_size: u64,
) -> CliResult<Anchored> {
    let mut findings = Vec::new();

    // --- the observed series, and divergence over EVERY authenticated member -----------
    let series = mirror.series()?;
    let selected =
        series.iter().find(|member| member.tree_size == tree_size).cloned().ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "the mirror published no checkpoint at tree_size {tree_size}; checkpoint \
                 selection is explicit and is never inferred"
            ))
        })?;

    // --- steps 1 and 2, as a joint fixed point ---------------------------------------
    let enumerator = Enumerator::new(
        mirror.fetcher,
        &mirror.base,
        mirror.leaf_form,
        mirror.limits,
        mirror.chunk,
    );
    let entries = enumerator.enumerate_and_recompute(&selected)?;

    let governance = Governance::from_entries(&entries).map_err(remote_candidate)?;
    governance.check_genesis(&entries, &policy.trust).map_err(remote_candidate)?;
    findings.extend(governance.log_object_findings());

    let declared_log_id = governance.log_id_for(tree_size).map_err(remote_candidate)?;
    if declared_log_id != selected.log_id {
        return Err(CliError::EvidenceMissing(format!(
            "the checkpoint names log `{}` but the manifest version governing tree_size \
             {tree_size} declares `{declared_log_id}`",
            selected.log_id
        )));
    }
    let log_keys = governance.log_keys_for(tree_size).map_err(remote_candidate)?;
    if !selected.signature_verifies(mirror.signing_form, &log_keys)? {
        return Err(CliError::EvidenceMissing(
            "the selected checkpoint's log signature does not verify under the key set the \
             governing manifest version declares"
                .to_owned(),
        ));
    }

    // --- divergence: authentication is enough to condemn ------------------------------
    // Every member that authenticates counts, series-usable or not: divergence is visible from
    // checkpoint metadata alone, and requiring usability first would let a deployment defer
    // detection indefinitely by never recomputing the branch it dislikes (adaptor §6.6.1).
    let mut authenticated = Vec::new();
    for member in &series {
        let Ok(keys) = governance.log_keys_for(member.tree_size) else { continue };
        if member.signature_verifies(mirror.signing_form, &keys).unwrap_or(false) {
            authenticated.push(member.clone());
        }
    }
    if let Some(floor) = equivocation_floor(&authenticated) {
        if tree_size >= floor {
            // Positive proof of misbehaviour, and a branch is never chosen.
            return Err(CliError::EquivocationAtOrBeyondFloor { floor });
        }
        findings.push(Finding::new(
            "divergence-below-floor",
            format!(
                "the checkpoint series equivocates from tree_size {floor}; this result is \
                 grounded strictly below that floor and members below a divergence remain \
                 usable, so the divergence is carried rather than adjudicated"
            ),
        ));
    }

    // --- step 3: neighbouring consistency --------------------------------------------
    findings.extend(check_neighbours(mirror, &authenticated, &selected)?);

    // --- step 5: every envelope's signature, under the manifest governing its index ----
    let mut statements = Vec::with_capacity(entries.len());
    for (index, envelope) in &entries {
        let verifies = governance.envelope_verifies_at(envelope, *index).unwrap_or(false);
        if verifies {
            statements.push(envelope.clone());
        } else {
            findings.push(Finding::new(
                "entry-is-not-a-statement",
                format!(
                    "the entry at entry index {index} carries a signature that does not resolve \
                     to a key active at that index, or does not verify; core spec §2.1 makes it \
                     not an AHL statement, so it is excluded from traversal and reported rather \
                     than being treated as evidence"
                ),
            ));
            statements.push(json!({ "payload": { "type": "not-a-statement" } }));
        }
    }

    findings.sort();
    findings.dedup();
    Ok(Anchored { checkpoint: selected, entries, statements, governance, findings })
}

/// A failure while reading remote material is missing evidence, never a disproved artifact.
fn remote_candidate(error: CliError) -> CliError {
    match error.outcome() {
        crate::outcome::Outcome::Invalid => CliError::EvidenceMissing(format!(
            "the material the mirror served is unusable: {error}"
        )),
        _ => error,
    }
}

/// Verify the §6.6 neighbour relationships: predecessor, and successor where one exists.
fn check_neighbours<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    authenticated: &[Checkpoint],
    selected: &Checkpoint,
) -> CliResult<Vec<Finding>> {
    let mut findings = Vec::new();

    let predecessor = authenticated
        .iter()
        .filter(|member| member.tree_size < selected.tree_size)
        .max_by_key(|member| member.tree_size);
    let successor = authenticated
        .iter()
        .filter(|member| member.tree_size > selected.tree_size)
        .min_by_key(|member| member.tree_size);

    match predecessor {
        Some(previous) => {
            let path = mirror.consistency_path(previous.tree_size, selected.tree_size)?;
            if !consistency_verifies(previous, selected, &path)? {
                return Err(CliError::EvidenceMissing(format!(
                    "consistency from the preceding series member at tree_size {} to {} does \
                     not verify",
                    previous.tree_size, selected.tree_size
                )));
            }
        }
        // Adaptor §6.6 requires the predecessor relationship for series-usability but §5.2.2
        // item 3 lets an operator first publish at a size larger than the genesis checkpoint,
        // so the earliest published member has no predecessor and the two rules cannot both be
        // satisfied for it. Refusing outright would make the earliest member — and therefore
        // the whole series — permanently unusable, so the gap is named and carried instead of
        // being decided silently in either direction. See the crate README, "Ambiguities".
        None => findings.push(Finding::new(
            "series-predecessor-unpublished",
            format!(
                "no authenticated series member precedes tree_size {}, so the predecessor \
                 relationship adaptor §6.6 requires could not be verified; §5.2.2 item 3 \
                 permits an operator to publish no earlier member, and the two rules are not \
                 reconciled in the frozen sources",
                selected.tree_size
            ),
        )),
    }

    match successor {
        Some(next) => {
            let path = mirror.consistency_path(selected.tree_size, next.tree_size)?;
            if !consistency_verifies(selected, next, &path)? {
                return Err(CliError::EvidenceMissing(format!(
                    "consistency from tree_size {} to the following series member at {} does \
                     not verify",
                    selected.tree_size, next.tree_size
                )));
            }
        }
        // "Where one exists" is not decidable against an untrusted mirror: no authenticated
        // completeness proof over checkpoint-series history is defined, so a mirror can
        // withhold a successor and make an older C look newest.
        None => findings.push(Finding::new(
            "series-successor-not-observed",
            format!(
                "this run observed no series member after tree_size {}; that a successor does \
                 not exist is not establishable against an untrusted mirror, so series \
                 usability is claimed only as of what this run observed",
                selected.tree_size
            ),
        )),
    }
    Ok(findings)
}

/// Which trigger governs a record at `C`, established over the whole enumerated range.
///
/// Not merely that *a* trigger is anchored, in scope and signed by an authorized key, but that
/// **this** trigger governs: all competing triggers are enumerated over the required range,
/// **every** candidate envelope signature is verified *before* authority is compared — an
/// invalid signature never governs — and the governing trigger is the one with the greatest
/// entry index. Without this, a hostile corpus makes the CLI compute a closure from an older
/// trigger a later one supersedes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoverningTrigger {
    /// Entry index of the trigger that governs.
    pub entry_index: u64,
    /// Its statement id.
    pub statement_id: String,
    /// The record it names.
    pub record: (String, String),
    /// Competing triggers that were enumerated and rejected, with the reason.
    pub findings: Vec<Finding>,
}

/// Establish the governing trigger for `record` at the anchored view.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] when no effective trigger exists for the record, or when the
/// record was never introduced at all.
pub fn governing_trigger(
    anchored: &Anchored,
    dataset: &str,
    record: &str,
) -> CliResult<GoverningTrigger> {
    let introduction = introduction_index(anchored, dataset, record).ok_or_else(|| {
        CliError::EvidenceMissing(format!(
            "no anchored `ingestion` or `derivation` introduces `{dataset}`/`{record}` in \
             [0, {}); authority cannot predate the introduction that creates it",
            anchored.checkpoint.tree_size
        ))
    })?;

    let mut findings = Vec::new();
    let mut governing: Option<(u64, String)> = None;

    for (index, envelope) in &anchored.entries {
        let Some(payload) = envelope.get("payload") else { continue };
        let kind = payload.get("type").and_then(Value::as_str).unwrap_or_default();
        if !matches!(kind, "retraction" | "correction") {
            continue;
        }
        if payload.get("dataset").and_then(Value::as_str) != Some(dataset)
            || payload.get("record").and_then(Value::as_str) != Some(record)
        {
            continue;
        }

        // A trigger anchored before the record's introduction is never effective.
        if *index < introduction {
            findings.push(Finding::new(
                "trigger-predates-introduction",
                format!(
                    "the trigger at entry index {index} precedes the record's introduction at \
                     {introduction} and is never effective"
                ),
            ));
            continue;
        }

        // Every candidate's signature is verified BEFORE authority is compared.
        if !anchored.governance.envelope_verifies_at(envelope, *index).unwrap_or(false) {
            findings.push(Finding::new(
                "trigger-signature-does-not-verify",
                format!(
                    "the candidate trigger at entry index {index} carries a signature that does \
                     not verify; an invalid signature never governs"
                ),
            ));
            continue;
        }

        let signers = signer_key_ids(envelope);
        let authority = authority_for(anchored, dataset, introduction, *index);
        if signers.is_disjoint(&authority) {
            // Triggers from other keys anchor as challenges: surfaced, never traversed.
            findings.push(Finding::new(
                "trigger-anchored-as-challenge",
                format!(
                    "the trigger at entry index {index} is not signed by the record's \
                     authority and anchors as a challenge; challenges are never traversed"
                ),
            ));
            continue;
        }

        let statement_id = ahl_core::statement_id(envelope).map_err(|source| {
            CliError::EvidenceMissing(format!("entry {index} has no statement id: {source}"))
        })?;
        // Among effective triggers for one record, the greatest entry index governs.
        if governing.as_ref().is_none_or(|(at, _)| *index > *at) {
            governing = Some((*index, statement_id));
        }
    }

    let (entry_index, statement_id) = governing.ok_or_else(|| {
        CliError::EvidenceMissing(format!(
            "no effective trigger for `{dataset}`/`{record}` is anchored in [0, {})",
            anchored.checkpoint.tree_size
        ))
    })?;
    findings.sort();
    findings.dedup();
    Ok(GoverningTrigger {
        entry_index,
        statement_id,
        record: (dataset.to_owned(), record.to_owned()),
        findings,
    })
}

/// The entry index at which `(dataset, record)` is introduced, if it is.
#[must_use]
pub fn introduction_index(anchored: &Anchored, dataset: &str, record: &str) -> Option<u64> {
    anchored.entries.iter().find_map(|(index, envelope)| {
        let payload = envelope.get("payload")?;
        match payload.get("type")?.as_str()? {
            "ingestion" => (payload.get("dataset")?.as_str()? == dataset
                && payload.get("record")?.as_str()? == record)
                .then_some(*index),
            "derivation" => payload
                .get("outputs")?
                .as_array()?
                .iter()
                .any(|output| {
                    output.get("dataset").and_then(Value::as_str) == Some(dataset)
                        && output.get("record").and_then(Value::as_str) == Some(record)
                })
                .then_some(*index),
            _ => None,
        }
    })
}

/// The key set entitled to trigger `(dataset, record)`.
///
/// For an **ingested** record it is the dataset authority the manifest declares. For a
/// **derived** record it is the introducing producer's key set **as of the trigger's entry
/// index** — not the introduction index, so a key rotation between the two applies.
fn authority_for(
    anchored: &Anchored,
    dataset: &str,
    introduction: u64,
    trigger_index: u64,
) -> BTreeSet<String> {
    let introduced_by_ingestion = anchored
        .entries
        .iter()
        .find(|(index, _)| *index == introduction)
        .and_then(|(_, envelope)| envelope.get("payload")?.get("type")?.as_str())
        == Some("ingestion");

    if introduced_by_ingestion {
        anchored.governance.dataset_authority(trigger_index, dataset).unwrap_or_default()
    } else {
        anchored.governance.producer_keys_at(trigger_index).keys().cloned().collect()
    }
}

fn signer_key_ids(envelope: &Value) -> BTreeSet<String> {
    envelope
        .get("signatures")
        .and_then(Value::as_array)
        .map(|signatures| {
            signatures
                .iter()
                .filter_map(|signature| signature.get("key_id")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Every committed tree root the enumerated entries reference, so missing material can be
/// named rather than discovered mid-traversal.
#[must_use]
pub fn required_tree_roots(entries: &[(u64, Value)]) -> BTreeMap<String, u64> {
    let mut roots = BTreeMap::new();
    for (_, envelope) in entries {
        let Some(payload) = envelope.get("payload") else { continue };
        if let (Some(root), Some(count)) = (
            payload.get("outputs_root").and_then(Value::as_str),
            payload.get("outputs_count").and_then(Value::as_u64),
        ) {
            roots.insert(root.to_owned(), count);
        }
        if let (Some(root), Some(count)) = (
            payload.get("affected_root").and_then(Value::as_str),
            payload.get("affected_count").and_then(Value::as_u64),
        ) {
            roots.insert(root.to_owned(), count);
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MirrorFixture;

    #[test]
    fn a_view_is_established_only_when_every_step_holds() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        assert_eq!(anchored.checkpoint.tree_size, 8);
        assert_eq!(anchored.entries.len(), 8);
        assert_eq!(anchored.governance.manifest_indexes(), vec![0]);
    }

    #[test]
    fn a_checkpoint_the_mirror_never_published_is_never_inferred() {
        let fixture = MirrorFixture::conformance();
        let error = fixture.establish(7).expect_err("unpublished size");
        assert!(error.to_string().contains("never inferred"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_genesis_anchor_that_is_not_the_configured_one_is_missing_evidence_not_a_verdict() {
        let mut fixture = MirrorFixture::conformance();
        fixture.policy.trust.genesis_entry_id = format!("sha256:{}", "99".repeat(32));
        let error = fixture.establish(8).expect_err("wrong anchor");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn the_predecessor_relationship_is_verified_and_a_missing_one_is_named() {
        let fixture = MirrorFixture::conformance();
        // tree_size 8 is the earliest published member of the fixture's series.
        let anchored = fixture.establish(8).expect("established");
        assert!(anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-predecessor-unpublished"));

        // tree_size 13 has both a predecessor and a successor, so neither gap is reported.
        let anchored = fixture.establish(13).expect("established");
        assert!(!anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-predecessor-unpublished"));
        assert!(!anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-successor-not-observed"));
    }

    #[test]
    fn the_newest_observed_member_is_labelled_run_observed_rather_than_latest() {
        let fixture = MirrorFixture::conformance();
        let newest = fixture.newest_tree_size();
        let anchored = fixture.establish(newest).expect("established");
        assert!(anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-successor-not-observed"));
    }

    #[test]
    fn a_result_grounded_at_or_beyond_an_equivocation_floor_is_positive_proof_of_misbehaviour() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(13);
        let error = fixture.establish(13).expect_err("at the floor");
        assert!(matches!(error, CliError::EquivocationAtOrBeyondFloor { floor: 13 }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid);
    }

    #[test]
    fn a_result_grounded_below_the_floor_keeps_its_outcome_and_carries_the_divergence() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(13);
        let anchored = fixture.establish(8).expect("below the floor");
        assert!(anchored.findings.iter().any(|finding| finding.code == "divergence-below-floor"));
    }

    #[test]
    fn a_checkpoint_signed_by_a_key_the_manifest_does_not_declare_does_not_authenticate() {
        let fixture = MirrorFixture::conformance().with_foreign_log_key(8);
        let error = fixture.establish(8).expect_err("foreign key");
        assert!(error.to_string().contains("does not verify"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_tampered_entry_breaks_the_root_recomputation() {
        let fixture = MirrorFixture::conformance().with_tampered_entry(3);
        let error = fixture.establish(8).expect_err("tampered");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn the_governing_trigger_is_the_greatest_entry_index_among_effective_ones() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(fixture.newest_tree_size()).expect("established");
        let (dataset, record) = fixture.record_f();
        let governing = governing_trigger(&anchored, &dataset, &record).expect("governs");
        // Entry 22 is the authorized retraction; entry 23 is a challenge by a non-authority
        // key, 28 and 29 carry non-verifying signatures, and 31 is co-signed by the authority.
        assert_eq!(governing.entry_index, 31);
        let codes: BTreeSet<&str> =
            governing.findings.iter().map(|finding| finding.code.as_str()).collect();
        assert!(codes.contains("trigger-anchored-as-challenge"));
        assert!(codes.contains("trigger-signature-does-not-verify"));
    }

    #[test]
    fn a_record_that_was_never_introduced_has_no_authority_to_trigger_it() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        let error = governing_trigger(&anchored, "customers", "sha256:deadbeef")
            .expect_err("never introduced");
        assert!(error.to_string().contains("authority cannot predate"), "{error}");
    }

    #[test]
    fn a_record_with_no_effective_trigger_is_reported_as_such() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        let (dataset, record) = fixture.record_b();
        let error = governing_trigger(&anchored, &dataset, &record).expect_err("no trigger");
        assert!(error.to_string().contains("no effective trigger"), "{error}");
    }

    #[test]
    fn required_tree_roots_are_collected_before_traversal_begins() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(fixture.newest_tree_size()).expect("established");
        let roots = required_tree_roots(&anchored.entries);
        assert!(!roots.is_empty(), "the corpus commits batch and disposition trees");
        assert!(roots.values().all(|count| *count > 0));
    }
}
