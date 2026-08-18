//! Client-driven authenticated enumeration.
//!
//! Chunking is the **client's** decision, not the server's. Where a range is too large for one
//! request the CLI asks for deterministic adjacent subranges under one fixed, already-selected
//! checkpoint, verifies each subrange proof *before* concatenation **against the locally
//! selected `C.root_hash`**, and requires the subranges to tile `[from, to)` exactly.
//!
//! There is no cursor. A server-supplied continuation token is not evidence, and the adaptor
//! profile defines no pagination protocol to borrow one from, so the next request is computed
//! from the previous one's declared bounds and nothing the server said.
//!
//! A response whose declared checkpoint does not match the selected
//! `{log_id, tree_size, root_hash}` is rejected — but matching is on those **identity fields**,
//! not byte-identity of the checkpoint object: a quiet log may legitimately publish several
//! signed checkpoints at one size with the same root, and rejecting those would break honest
//! deployments.
//!
//! Every failure here is [`crate::error::CliError::EvidenceMissing`] or
//! [`crate::error::CliError::LimitExhausted`], never a rule fired against the user's artifact:
//! a hostile server returning one bogus object disproves nothing about the user's receipt or
//! corpus. Only the user's own artifact can be *disproved*.

use ahl_core::range_proof;
use atl_core::core::merkle::{compute_root, Hash};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::cache;
use crate::checkpoint::{Checkpoint, ATL_PROFILE, TEST_LOG_PROFILE};
use crate::error::{CliError, CliResult};
use crate::net::{Fetcher, Request};
use crate::policy::NetworkLimits;

/// The fixed ATL adaptor metadata digest of adaptor profile §4.2 — the JCS form of
/// `{"ahl_adaptor":"ahl-adaptor-atl-v1"}`.
const ATL_METADATA_HASH: [u8; 32] = [
    0xbb, 0x4f, 0x98, 0x46, 0x1f, 0x06, 0x2d, 0x89, 0x79, 0x80, 0xc9, 0x05, 0x0f, 0x8f, 0x85, 0x9c,
    0x3b, 0x83, 0xc8, 0x44, 0x86, 0xc5, 0xe6, 0x85, 0x72, 0x62, 0xf6, 0xdf, 0xa9, 0x74, 0x68, 0xa4,
];

/// How the log tree's leaf hash is built from the entry bytes.
///
/// The asymmetry is deliberate and adaptor-defined: the ATL profile hashes the *entry id* into
/// a two-digest leaf because ATL builds that tree, while the corpus test profile hashes the
/// entry bytes directly. An implementation must not apply one construction to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafForm {
    /// `SHA-256(0x00 || JCS(envelope))` — `ahl-test-log-v1` §2.1.
    Direct,
    /// `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)` — `ahl-adaptor-atl-v1` §4.2.
    AtlPayloadMetadata,
}

impl LeafForm {
    /// Select the construction the pinned profile defines.
    ///
    /// # Errors
    ///
    /// [`CliError::ProfileLimitation`] for a profile this build does not implement.
    pub fn for_profile(profile_id: &str) -> CliResult<Self> {
        match profile_id {
            TEST_LOG_PROFILE => Ok(Self::Direct),
            ATL_PROFILE => Ok(Self::AtlPayloadMetadata),
            other => Err(CliError::ProfileLimitation(format!(
                "this build implements no log-tree leaf construction for adaptor profile \
                 `{other}`; the construction is adaptor-defined and is never guessed"
            ))),
        }
    }

    /// The log-tree leaf hash of one entry's canonical bytes.
    #[must_use]
    pub fn leaf_hash(self, entry_bytes: &[u8]) -> Hash {
        match self {
            Self::Direct => ahl_core::leaf_hash(entry_bytes),
            Self::AtlPayloadMetadata => {
                let payload_hash = Sha256::digest(entry_bytes);
                let mut hasher = Sha256::new();
                hasher.update([ahl_core::LEAF_PREFIX]);
                hasher.update(payload_hash);
                hasher.update(ATL_METADATA_HASH);
                hasher.finalize().into()
            }
        }
    }
}

/// An enumeration client bound to one mirror.
#[derive(Debug)]
pub struct Enumerator<'a, F: Fetcher> {
    fetcher: &'a F,
    mirror: &'a str,
    leaf_form: LeafForm,
    limits: NetworkLimits,
    chunk: u64,
}

impl<'a, F: Fetcher> Enumerator<'a, F> {
    /// Build an enumerator. `chunk` is the client's own subrange width; a zero is corrected to
    /// one so a caller cannot accidentally request empty ranges forever.
    #[must_use]
    pub fn new(
        fetcher: &'a F,
        mirror: &'a str,
        leaf_form: LeafForm,
        limits: NetworkLimits,
        chunk: u64,
    ) -> Self {
        Self { fetcher, mirror, leaf_form, limits, chunk: chunk.max(1) }
    }

    /// Enumerate `[from, to)` under `selected`, in deterministic adjacent subranges.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when a subrange does not verify, does not tile, or names a
    /// different checkpoint; [`CliError::LimitExhausted`] when a network limit is reached.
    pub fn enumerate(
        &self,
        selected: &Checkpoint,
        from: u64,
        to: u64,
    ) -> CliResult<Vec<(u64, Value)>> {
        if from >= to || to > selected.tree_size {
            return Err(CliError::EvidenceMissing(format!(
                "range [{from}, {to}) is empty or is not committed by a checkpoint of size {}",
                selected.tree_size
            )));
        }
        let width = to - from;
        if width > self.limits.max_entries {
            return Err(CliError::LimitExhausted(format!(
                "enumerating {width} entries exceeds the configured maximum of {}",
                self.limits.max_entries
            )));
        }

        let mut collected: Vec<(u64, Value)> = Vec::new();
        let mut cursor = from;
        let mut requests: u32 = 0;
        while cursor < to {
            requests = requests.saturating_add(1);
            if requests > self.limits.max_subrange_requests {
                return Err(CliError::LimitExhausted(format!(
                    "enumeration needs more than the configured maximum of {} subrange requests",
                    self.limits.max_subrange_requests
                )));
            }
            // Deterministic and computed locally: the next bound comes from the previous one,
            // never from a continuation token the server chose.
            let end = cursor.saturating_add(self.chunk).min(to);
            let subrange = self.fetch_subrange(selected, cursor, end)?;

            // Each subrange is verified BEFORE concatenation, so a bad chunk never enters the
            // accumulated material.
            if subrange.first().map(|(index, _)| *index) != Some(cursor) {
                return Err(CliError::EvidenceMissing(format!(
                    "subrange starting at {cursor} does not begin there"
                )));
            }
            collected.extend(subrange);
            cursor = end;
        }

        // The subranges must tile `[from, to)` exactly: no gap, no overlap, no reordering.
        if collected.len() as u64 != width {
            return Err(CliError::EvidenceMissing(format!(
                "the subranges carry {} entries but [{from}, {to}) is {width} wide; they do not \
                 tile the requested range",
                collected.len()
            )));
        }
        for (offset, (index, _)) in collected.iter().enumerate() {
            let expected = from + offset as u64;
            if *index != expected {
                return Err(CliError::EvidenceMissing(format!(
                    "the subranges do not tile [{from}, {to}): position {offset} carries entry \
                     index {index}, expected {expected}"
                )));
            }
        }
        Ok(collected)
    }

    fn fetch_subrange(
        &self,
        selected: &Checkpoint,
        from: u64,
        to: u64,
    ) -> CliResult<Vec<(u64, Value)>> {
        let body = serde_json::to_vec(&serde_json::json!({
            "tree_size": selected.tree_size,
            "from_index": from,
            "to_index": to,
        }))
        .map_err(|source| CliError::Internal(format!("cannot build a range request: {source}")))?;
        let url = format!("{}/v1/range", self.mirror.trim_end_matches('/'));
        let request = Request::post(url, body);
        // The cache key binds the locally selected checkpoint identity, so material from the
        // wrong branch of an equivocating log can never be served for this request.
        let key = cache::request_key(&selected.identity(), &request);
        let request = request.cached_under(key);

        // Verification is handed to `fetch_revalidating`, so a cached answer that passes the
        // cache's own integrity check and is nevertheless the wrong answer is evicted and
        // refetched exactly once, then reported. A digest check on stored bytes cannot catch
        // that; only these proof checks can, which is why they are what drives the eviction.
        crate::net::fetch_revalidating(self.fetcher, &request, |response| {
            if response.status != 200 {
                return Err(CliError::EvidenceMissing(format!(
                    "the mirror answered {} for range [{from}, {to}); a status is an \
                     operational failure, never refusal evidence",
                    response.status
                )));
            }
            let value: Value = serde_json::from_slice(&response.body).map_err(|source| {
                CliError::EvidenceMissing(format!("range response is not JSON: {source}"))
            })?;
            verify_range_response(&value, selected, self.leaf_form, from, to)
        })
    }

    /// Enumerate `[0, tree_size)` and **recompute** the checkpoint's root from the result.
    ///
    /// This is what promotes a checkpoint from authenticated to series-usable on its own
    /// contents (core spec §7.3 item 1, adaptor §6.6): the response covering the whole range is
    /// itself the material that promotes it, so the first full enumeration and the promotion
    /// are one operation.
    ///
    /// # Errors
    ///
    /// As [`Self::enumerate`], plus [`CliError::EvidenceMissing`] when the recomputed root
    /// differs from the one the checkpoint commits.
    pub fn enumerate_and_recompute(&self, selected: &Checkpoint) -> CliResult<Vec<(u64, Value)>> {
        let entries = self.enumerate(selected, 0, selected.tree_size)?;
        let recomputed = recompute_root(self.leaf_form, &entries);
        let committed = ahl_core::parse_hash_hex(&selected.root_hash).map_err(|source| {
            CliError::EvidenceMissing(format!("checkpoint `root_hash` is unreadable: {source}"))
        })?;
        if recomputed != committed {
            return Err(CliError::EvidenceMissing(format!(
                "the root recomputed from the enumerated entries is {}, the checkpoint commits \
                 {}; the checkpoint describes a tree this material is not",
                ahl_core::hash_hex(&recomputed),
                selected.root_hash
            )));
        }
        Ok(entries)
    }
}

/// Recompute a log-tree root from enumerated entries, in entry-index order.
#[must_use]
pub fn recompute_root(form: LeafForm, entries: &[(u64, Value)]) -> Hash {
    let hashes: Vec<Hash> =
        entries.iter().map(|(_, envelope)| form.leaf_hash(&ahl_core::jcs(envelope))).collect();
    compute_root(&hashes)
}

/// Verify one range response against the **locally selected** checkpoint.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] naming which of the §10.4 checks failed.
pub fn verify_range_response(
    response: &Value,
    selected: &Checkpoint,
    form: LeafForm,
    from: u64,
    to: u64,
) -> CliResult<Vec<(u64, Value)>> {
    let missing = |detail: String| CliError::EvidenceMissing(detail);

    // Identity fields only. A quiet log may publish several signed checkpoints at one size
    // with one root; those are the same checkpoint for every purpose a claim binds on.
    let declared = response
        .get("checkpoint")
        .ok_or_else(|| missing("range response names no checkpoint".to_owned()))?;
    let declared = Checkpoint::from_value(declared)?;
    if !declared.matches_identity(&selected.identity()) {
        return Err(missing(format!(
            "the range response declares checkpoint {{log_id: {}, tree_size: {}, root_hash: \
             {}}}, which is not the locally selected {{log_id: {}, tree_size: {}, root_hash: \
             {}}}",
            declared.log_id,
            declared.tree_size,
            declared.root_hash,
            selected.log_id,
            selected.tree_size,
            selected.root_hash
        )));
    }

    let range = response
        .get("range")
        .ok_or_else(|| missing("range response carries no `range`".to_owned()))?;
    let declared_from = range.get("from_index").and_then(Value::as_u64);
    let declared_to = range.get("to_index").and_then(Value::as_u64);
    if declared_from != Some(from) || declared_to != Some(to) {
        return Err(missing(format!(
            "the range response declares [{declared_from:?}, {declared_to:?}) but [{from}, \
             {to}) was requested"
        )));
    }

    let entries = response
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| missing("range response carries no `entries` array".to_owned()))?;
    let width = to - from;
    if entries.len() as u64 != width {
        return Err(missing(format!(
            "the range response carries {} entries for a range {width} wide",
            entries.len()
        )));
    }

    let mut collected = Vec::with_capacity(entries.len());
    for (offset, entry) in entries.iter().enumerate() {
        let claimed = entry.get("entry_index").and_then(Value::as_u64);
        let expected = from + offset as u64;
        if claimed != Some(expected) {
            return Err(missing(format!(
                "entry {offset} claims index {claimed:?}, expected {expected}"
            )));
        }
        let envelope = entry
            .get("envelope")
            .filter(|value| value.is_object())
            .ok_or_else(|| missing(format!("entry {offset} carries no `envelope` object")))?;
        collected.push((expected, envelope.clone()));
    }

    let adaptor_form = response
        .get("range_proof")
        .and_then(|proof| proof.get("adaptor_form"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            missing("range response carries no `range_proof.adaptor_form`".to_owned())
        })?;
    let proof = range_proof::decode(adaptor_form)
        .map_err(|source| missing(format!("range proof is unreadable: {source}")))?;
    if proof.tree_size != selected.tree_size || proof.from_index != from || proof.to_index != to {
        return Err(missing(format!(
            "the proof covers [{}, {}) of a size-{} tree; [{from}, {to}) of a size-{} tree was \
             requested",
            proof.from_index, proof.to_index, proof.tree_size, selected.tree_size
        )));
    }

    // Verified against the LOCALLY SELECTED root, never against the checkpoint carried inside
    // the response.
    let root = ahl_core::parse_hash_hex(&selected.root_hash)
        .map_err(|source| missing(format!("selected `root_hash` is unreadable: {source}")))?;
    let leaf_hashes: Vec<Hash> =
        collected.iter().map(|(_, envelope)| form.leaf_hash(&ahl_core::jcs(envelope))).collect();
    if !range_proof::verify(&proof, &leaf_hashes, &root)
        .map_err(|source| missing(format!("range proof did not run: {source}")))?
    {
        return Err(missing(
            "the range proof does not open the locally selected checkpoint root".to_owned(),
        ));
    }
    Ok(collected)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::net::{FetchFailure, Response};

    fn envelope(n: u8) -> Value {
        json!({ "payload": { "type": "ingestion", "n": n }, "signatures": [] })
    }

    fn corpus(size: usize) -> Vec<Value> {
        (0..size).map(|n| envelope(u8::try_from(n).unwrap_or(0))).collect()
    }

    fn root_of(form: LeafForm, entries: &[Value]) -> String {
        let hashes: Vec<Hash> =
            entries.iter().map(|envelope| form.leaf_hash(&ahl_core::jcs(envelope))).collect();
        ahl_core::hash_hex(&compute_root(&hashes))
    }

    fn checkpoint(form: LeafForm, entries: &[Value]) -> Checkpoint {
        Checkpoint {
            log_id: format!("sha256:{}", "11".repeat(32)),
            tree_size: entries.len() as u64,
            root_hash: root_of(form, entries),
            checkpoint_time: "2026-08-16T12:00:00Z".to_owned(),
            key_id: format!("sha256:{}", "22".repeat(32)),
            signature: "base64:AA==".to_owned(),
        }
    }

    fn range_response(form: LeafForm, entries: &[Value], from: u64, to: u64) -> Value {
        let checkpoint = checkpoint(form, entries);
        let hashes: Vec<Hash> =
            entries.iter().map(|envelope| form.leaf_hash(&ahl_core::jcs(envelope))).collect();
        let proof = range_proof::generate(&hashes, from, to).expect("proof");
        json!({
            "range": { "from_index": from, "to_index": to },
            "entries": entries[usize::try_from(from).unwrap_or(usize::MAX)
                ..usize::try_from(to).unwrap_or(usize::MAX)]
                .iter()
                .enumerate()
                .map(|(offset, envelope)| json!({
                    "entry_index": from + offset as u64,
                    "envelope": envelope,
                }))
                .collect::<Vec<_>>(),
            "range_proof": { "adaptor_form": range_proof::encode(&proof) },
            "checkpoint": checkpoint,
        })
    }

    /// A mirror that answers range requests honestly, recording what it was asked.
    #[derive(Debug)]
    struct Mirror {
        entries: Vec<Value>,
        form: LeafForm,
        asked: Mutex<Vec<(u64, u64)>>,
    }

    impl Mirror {
        fn new(form: LeafForm, size: usize) -> Self {
            Self { entries: corpus(size), form, asked: Mutex::new(Vec::new()) }
        }
        fn asked(&self) -> Vec<(u64, u64)> {
            self.asked.lock().map(|asked| asked.clone()).unwrap_or_default()
        }
    }

    impl Fetcher for Mirror {
        fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
            let body: Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).expect("json");
            let from = body["from_index"].as_u64().expect("from");
            let to = body["to_index"].as_u64().expect("to");
            if let Ok(mut asked) = self.asked.lock() {
                asked.push((from, to));
            }
            let response = range_response(self.form, &self.entries, from, to);
            Ok(Response { status: 200, body: serde_json::to_vec(&response).expect("serialize") })
        }
    }

    fn limits() -> NetworkLimits {
        NetworkLimits::default()
    }

    #[test]
    fn the_two_leaf_constructions_are_different_and_are_never_interchanged() {
        let bytes = ahl_core::jcs(&envelope(1));
        assert_ne!(
            LeafForm::Direct.leaf_hash(&bytes),
            LeafForm::AtlPayloadMetadata.leaf_hash(&bytes)
        );
        assert_eq!(LeafForm::for_profile(TEST_LOG_PROFILE).expect("known"), LeafForm::Direct);
        assert_eq!(
            LeafForm::for_profile(ATL_PROFILE).expect("known"),
            LeafForm::AtlPayloadMetadata
        );
        assert!(LeafForm::for_profile("ahl-adaptor-ct-v1").is_err());
    }

    #[test]
    fn the_pinned_atl_metadata_digest_is_the_one_the_profile_states() {
        // Adaptor profile §4.2 pins the digest of the 36-byte JCS form of
        // `{"ahl_adaptor":"ahl-adaptor-atl-v1"}`; recompute it rather than trust the constant.
        let canonical = ahl_core::jcs(&json!({ "ahl_adaptor": "ahl-adaptor-atl-v1" }));
        assert_eq!(canonical.len(), 36);
        assert_eq!(
            ahl_core::sha256_hex(&canonical),
            "sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4"
        );
        assert_eq!(Sha256::digest(&canonical).as_slice(), ATL_METADATA_HASH);
    }

    #[test]
    fn a_full_enumeration_recomputes_the_root_and_promotes_the_checkpoint() {
        for form in [LeafForm::Direct, LeafForm::AtlPayloadMetadata] {
            let mirror = Mirror::new(form, 13);
            let selected = checkpoint(form, &mirror.entries);
            let enumerator = Enumerator::new(&mirror, "https://m", form, limits(), 5);
            let entries = enumerator.enumerate_and_recompute(&selected).expect("enumerated");
            assert_eq!(entries.len(), 13);
            assert_eq!(
                recompute_root(form, &entries),
                ahl_core::parse_hash_hex(&selected.root_hash).expect("root")
            );
        }
    }

    #[test]
    fn chunking_is_client_driven_deterministic_and_adjacent() {
        let mirror = Mirror::new(LeafForm::Direct, 13);
        let selected = checkpoint(LeafForm::Direct, &mirror.entries);
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits(), 5);
        enumerator.enumerate(&selected, 0, 13).expect("enumerated");
        assert_eq!(mirror.asked(), vec![(0, 5), (5, 10), (10, 13)]);
    }

    #[test]
    fn a_response_declaring_a_different_checkpoint_identity_is_rejected() {
        let entries = corpus(8);
        let selected = checkpoint(LeafForm::Direct, &entries);
        let response = range_response(LeafForm::Direct, &entries, 0, 8);

        let mut wrong_root = selected.clone();
        wrong_root.root_hash = format!("sha256:{}", "ee".repeat(32));
        let error = verify_range_response(&response, &wrong_root, LeafForm::Direct, 0, 8)
            .expect_err("root");
        assert!(error.to_string().contains("locally selected"), "{error}");

        let mut wrong_log = selected;
        wrong_log.log_id = format!("sha256:{}", "ff".repeat(32));
        assert!(verify_range_response(&response, &wrong_log, LeafForm::Direct, 0, 8).is_err());
    }

    #[test]
    fn a_republished_checkpoint_with_the_same_identity_is_accepted() {
        // The identity match is on three fields, not byte-identity: an honest quiet log that
        // restated the same tree at a later time must not be rejected.
        let entries = corpus(8);
        let selected = checkpoint(LeafForm::Direct, &entries);
        let mut response = range_response(LeafForm::Direct, &entries, 0, 8);
        response["checkpoint"]["checkpoint_time"] = json!("2026-08-16T13:00:00Z");
        response["checkpoint"]["signature"] = json!("base64:BB==");
        assert!(verify_range_response(&response, &selected, LeafForm::Direct, 0, 8).is_ok());
    }

    #[test]
    fn a_substituted_entry_breaks_the_proof_against_the_selected_root() {
        let entries = corpus(8);
        let selected = checkpoint(LeafForm::Direct, &entries);
        let mut response = range_response(LeafForm::Direct, &entries, 0, 8);
        response["entries"][3]["envelope"] = envelope(0xff);
        let error = verify_range_response(&response, &selected, LeafForm::Direct, 0, 8)
            .expect_err("substitution");
        assert!(error.to_string().contains("does not open"), "{error}");
    }

    #[test]
    fn a_response_whose_indexes_or_width_disagree_is_rejected() {
        let entries = corpus(8);
        let selected = checkpoint(LeafForm::Direct, &entries);

        let mut renumbered = range_response(LeafForm::Direct, &entries, 0, 8);
        renumbered["entries"][2]["entry_index"] = json!(99);
        assert!(verify_range_response(&renumbered, &selected, LeafForm::Direct, 0, 8).is_err());

        let mut short = range_response(LeafForm::Direct, &entries, 0, 8);
        short["entries"].as_array_mut().expect("array").pop();
        assert!(verify_range_response(&short, &selected, LeafForm::Direct, 0, 8).is_err());

        let mut wrong_range = range_response(LeafForm::Direct, &entries, 0, 8);
        wrong_range["range"]["to_index"] = json!(7);
        assert!(verify_range_response(&wrong_range, &selected, LeafForm::Direct, 0, 8).is_err());
    }

    #[test]
    fn a_proof_for_another_range_or_tree_size_is_rejected() {
        let entries = corpus(8);
        let selected = checkpoint(LeafForm::Direct, &entries);
        let mut response = range_response(LeafForm::Direct, &entries, 0, 8);
        let other = range_response(LeafForm::Direct, &entries, 2, 5);
        response["range_proof"] = other["range_proof"].clone();
        let error = verify_range_response(&response, &selected, LeafForm::Direct, 0, 8)
            .expect_err("wrong proof");
        assert!(error.to_string().contains("the proof covers"), "{error}");
    }

    #[test]
    fn structurally_incomplete_responses_are_missing_evidence() {
        let entries = corpus(4);
        let selected = checkpoint(LeafForm::Direct, &entries);
        for response in [
            json!({}),
            json!({ "checkpoint": checkpoint(LeafForm::Direct, &entries) }),
            json!({ "checkpoint": checkpoint(LeafForm::Direct, &entries),
                    "range": { "from_index": 0, "to_index": 4 } }),
            json!({ "checkpoint": checkpoint(LeafForm::Direct, &entries),
                    "range": { "from_index": 0, "to_index": 4 },
                    "entries": [ { "entry_index": 0 } ] }),
        ] {
            let error = verify_range_response(&response, &selected, LeafForm::Direct, 0, 4)
                .expect_err("incomplete");
            assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
        }
    }

    /// A mirror that answers with a subrange other than the one requested — the "does not
    /// tile" case, seen from the client side.
    #[derive(Debug)]
    struct ShiftingMirror {
        entries: Vec<Value>,
    }

    impl Fetcher for ShiftingMirror {
        fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
            let body: Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).expect("json");
            let from = body["from_index"].as_u64().expect("from");
            let to = body["to_index"].as_u64().expect("to");
            // Answer the *next* subrange along, with a perfectly valid proof for it.
            let shift = (to - from).min(self.entries.len() as u64 - to);
            let response =
                range_response(LeafForm::Direct, &self.entries, from + shift, to + shift);
            Ok(Response { status: 200, body: serde_json::to_vec(&response).expect("serialize") })
        }
    }

    #[test]
    fn subranges_that_do_not_tile_the_request_are_refused() {
        let mirror = ShiftingMirror { entries: corpus(12) };
        let selected = checkpoint(LeafForm::Direct, &mirror.entries);
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits(), 4);
        let error = enumerator.enumerate(&selected, 0, 12).expect_err("shifted");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn an_enumeration_needing_too_many_subranges_exhausts_the_named_limit() {
        let mirror = Mirror::new(LeafForm::Direct, 20);
        let selected = checkpoint(LeafForm::Direct, &mirror.entries);
        let limits = NetworkLimits { max_subrange_requests: 2, ..limits() };
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits, 4);
        let error = enumerator.enumerate(&selected, 0, 20).expect_err("too many");
        assert!(error.to_string().contains("subrange requests"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn an_enumeration_wider_than_the_entry_limit_is_refused_before_any_request() {
        let mirror = Mirror::new(LeafForm::Direct, 20);
        let selected = checkpoint(LeafForm::Direct, &mirror.entries);
        let limits = NetworkLimits { max_entries: 4, ..limits() };
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits, 4);
        assert!(enumerator.enumerate(&selected, 0, 20).is_err());
        assert!(mirror.asked().is_empty(), "the limit must fire before any request");
    }

    #[test]
    fn an_empty_or_out_of_range_request_is_refused() {
        let mirror = Mirror::new(LeafForm::Direct, 8);
        let selected = checkpoint(LeafForm::Direct, &mirror.entries);
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits(), 4);
        assert!(enumerator.enumerate(&selected, 4, 4).is_err());
        assert!(enumerator.enumerate(&selected, 0, 9).is_err());
    }

    #[test]
    fn a_root_that_does_not_recompute_reports_which_tree_the_material_is_not() {
        let mirror = Mirror::new(LeafForm::Direct, 8);
        let mut selected = checkpoint(LeafForm::Direct, &mirror.entries);
        // The proof still verifies against the real root, so force the mismatch at the last
        // step by claiming a root the mirror's own material does not build.
        selected.root_hash = root_of(LeafForm::AtlPayloadMetadata, &mirror.entries);
        let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits(), 8);
        let error = enumerator.enumerate_and_recompute(&selected).expect_err("mismatch");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    /// A mirror that answers every request with an operational failure.
    #[derive(Debug)]
    struct BrokenMirror(u16);

    impl Fetcher for BrokenMirror {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            Ok(Response { status: self.0, body: b"{\"reason\":\"invented\"}".to_vec() })
        }
    }

    #[test]
    fn a_mirror_status_is_an_operational_failure_never_refusal_evidence() {
        let entries = corpus(4);
        let selected = checkpoint(LeafForm::Direct, &entries);
        for status in [404, 500] {
            let mirror = BrokenMirror(status);
            let enumerator = Enumerator::new(&mirror, "https://m", LeafForm::Direct, limits(), 4);
            let error = enumerator.enumerate(&selected, 0, 4).expect_err("broken mirror");
            assert!(error.to_string().contains("never refusal evidence"), "{error}");
            assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
        }
    }

    #[derive(Debug)]
    struct GarbageMirror;

    impl Fetcher for GarbageMirror {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            Ok(Response { status: 200, body: b"not json".to_vec() })
        }
    }

    #[test]
    fn a_malformed_mirror_response_is_missing_evidence_not_a_disproved_artifact() {
        let entries = corpus(4);
        let selected = checkpoint(LeafForm::Direct, &entries);
        let enumerator =
            Enumerator::new(&GarbageMirror, "https://m", LeafForm::Direct, limits(), 4);
        let error = enumerator.enumerate(&selected, 0, 4).expect_err("garbage");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }
}
