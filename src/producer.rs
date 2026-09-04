//! Producer-side assembly: submit an entry to the log, publish it, collect cosignatures,
//! enumerate the prefix, and put an Evidence Receipt together from what came back.
//!
//! This is the half of the stack the client did not have. `verify` reads a receipt somebody
//! else assembled; nothing here decided how that receipt got its shape, and every integrator
//! wrote their own — which is exactly how canonicalization and binding drift enter a protocol.
//!
//! # What this module does not do
//!
//! It is **not** a verifier and must never be read as one. It checks only what assembly needs
//! and no more: a path computed against the wrong tree is not a path, so the root recomputed
//! from the enumerated prefix is compared with the checkpoint's before any path is derived from
//! it. Everything else — the signatures, the governance walk, the claim-type rules, the
//! outcome — belongs to `verify`, which is the judge. A receipt this module produced and
//! `verify` rejects is a finding about the producer, and that is the point of having both.
//!
//! # Trust
//!
//! Every server here is an address, not an authority (design note §2). The log's answer is
//! checked against the bytes submitted, the mirror's enumeration is checked against the
//! checkpoint the log signed, and a cosignature is carried only where the governing manifest
//! declares the witness that issued it.

use std::collections::BTreeMap;

use ahl_core::{
    entry_id, hash_hex, inclusion_proof, jcs, leaf_hash, log_leaf_bytes_for, parse_hash_hex,
    proof_path_hex, sha256_hex, statement_id, tree_root,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::checkpoint::ATL_PROFILE;
use crate::error::{CliError, CliResult};
use crate::net::{FetchFailure, Fetcher, Request, Response};

/// The receipt container revision this build assembles.
const RECEIPT_VERSION: &str = "2";
/// The specification revision this build assembles for.
const SPEC_VERSION: &str = "0.4.0";

/// The fixed ATL metadata object of adaptor §4.2, and nothing else.
///
/// Pinning it is what keeps a log leaf a pure function of the entry: ATL metadata is
/// operator-supplied and no AHL signature covers it, so an entry whose metadata carried AHL
/// data would have a leaf depending on bytes outside the signed envelope.
fn atl_metadata() -> Value {
    json!({ "ahl_adaptor": ATL_PROFILE })
}

/// `base64:` family string over `bytes`.
fn base64(bytes: &[u8]) -> String {
    format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Where the three services are. Addresses, never authorities.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The ATL log accepting submissions.
    pub log: String,
    /// The mirror serving retrieval, enumeration and checkpoints.
    pub mirror: String,
    /// Every witness this producer submits checkpoints to, by base URL.
    pub witnesses: Vec<String>,
}

/// An entry's position in the log and the checkpoint the log served with it.
#[derive(Debug, Clone)]
pub struct LogPosition {
    /// The ATL identifier the log assigned, where this run submitted the entry.
    ///
    /// It is the log's own retrieval key and is not an AHL identifier: adaptor §10.1.1 is
    /// explicit that resolving an AHL entry id to an ATL identifier and fetching the ATL
    /// receipt yields a digest of the envelope and no envelope. It is carried so the ATL
    /// Evidence Receipt can be fetched again and reconciled, never as a substitute for the
    /// entry id.
    pub atl_entry_id: Option<String>,
    /// The AHL entry index — the ATL leaf index of adaptor §5.1.
    pub entry_index: u64,
    /// The AHL checkpoint object of adaptor §6.2, signed by the log.
    pub checkpoint: Value,
    /// `anchoring.checkpoint.raw` — the 98-byte framing of §6.4.
    pub raw: String,
    /// The inclusion path the log served, leaf to root.
    pub inclusion_path: Vec<String>,
}

/// `tree_size` of a checkpoint object.
fn tree_size(checkpoint: &Value) -> CliResult<u64> {
    checkpoint.get("tree_size").and_then(Value::as_u64).ok_or_else(|| {
        CliError::EvidenceMissing("the checkpoint carries no `tree_size`".to_owned())
    })
}

/// A JSON body, or a reason the response is unusable.
fn json_body(response: &Response, what: &str) -> CliResult<Value> {
    serde_json::from_slice(&response.body).map_err(|source| {
        CliError::EvidenceMissing(format!("{what} did not answer JSON: {source}"))
    })
}

/// Perform one request, or convert the transport failure into an outcome.
fn fetch<F: Fetcher>(fetcher: &F, request: &Request) -> CliResult<Response> {
    fetcher.fetch(request).map_err(FetchFailure::into_cli_error)
}

/// The object map of a JSON value, so a member can be set without indexing.
///
/// The crate denies `clippy::indexing_slicing`, and `Value`'s index operator panics on a
/// non-object; this is the same edit with the failure surfaced instead.
///
/// # Errors
///
/// [`CliError::Internal`] where the value is not a JSON object.
pub fn object_mut(value: &mut Value) -> CliResult<&mut serde_json::Map<String, Value>> {
    value.as_object_mut().ok_or_else(|| CliError::Internal("a JSON object was expected".to_owned()))
}

/// Set one member of a JSON object.
///
/// # Errors
///
/// [`CliError::Internal`] where the value is not a JSON object.
pub fn set(value: &mut Value, member: &str, member_value: Value) -> CliResult<()> {
    object_mut(value)?.insert(member.to_owned(), member_value);
    Ok(())
}

/// Serialize a request body, or report the internal failure that made it impossible.
fn body(value: &Value) -> CliResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|source| CliError::Internal(format!("cannot build a request body: {source}")))
}

/// Map an ATL Evidence Receipt's checkpoint onto the AHL checkpoint object of adaptor §6.2.
///
/// The rendering of `checkpoint_time` is normative and not cosmetic (§6.3): a verifier
/// reassembles the 98-byte blob from the parsed object, so a value that lost precision
/// reassembles different bytes and the log signature fails over them.
fn ahl_checkpoint(atl: &Value) -> CliResult<Value> {
    let field = |name: &str| -> CliResult<Value> {
        atl.get(name).cloned().ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "the log's checkpoint carries no `{name}`; adaptor §6.2 maps it field by field"
            ))
        })
    };
    let nanos = atl.get("timestamp").and_then(Value::as_u64).ok_or_else(|| {
        CliError::EvidenceMissing(
            "the log's checkpoint carries no nanosecond `timestamp`".to_owned(),
        )
    })?;
    Ok(json!({
        "log_id": field("origin")?,
        "tree_size": field("tree_size")?,
        "root_hash": field("root_hash")?,
        "checkpoint_time": ahl_core::atl_checkpoint_time(nanos),
        "key_id": field("key_id")?,
        "signature": field("signature")?,
    }))
}

/// Submit an entry to the ATL log and read back its position under a signed checkpoint.
///
/// The entry travels as the ATL **payload**: adaptor §4.1 makes `JCS(envelope)` the anchored
/// bytes, and §4.2 makes their digest the ATL payload hash, so the AHL entry id and the ATL
/// payload hash are the same value. The log's answer is checked against that value rather than
/// taken on trust.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the log refuses, answers unusably, or answers about an
/// entry other than the one submitted.
pub fn anchor<F: Fetcher>(fetcher: &F, log: &str, envelope: &Value) -> CliResult<LogPosition> {
    let entry = sha256_hex(&jcs(envelope));
    let (atl_entry_id, submitted_index) = submit(fetcher, log, envelope, &entry)?;
    let mut position = retrieve(fetcher, log, &atl_entry_id, &entry)?;
    // The two answers describe the same append and must agree on where it landed. They are
    // separately signed objects from separately handled requests, so a disagreement is the log
    // contradicting itself rather than a transient.
    if position.entry_index != submitted_index {
        return Err(CliError::EvidenceMissing(format!(
            "the log placed the entry at index {submitted_index} when it accepted it and at \
             index {} when asked for its receipt",
            position.entry_index
        )));
    }
    position.atl_entry_id = Some(atl_entry_id);
    Ok(position)
}

/// `POST /v1/anchor` — submit the entry, and read back the identifier and index the log assigned.
///
/// The entry travels as the ATL **payload**: adaptor §4.1 makes `JCS(envelope)` the anchored
/// bytes, and §4.2 makes their digest the ATL payload hash, so the AHL entry id and the ATL
/// payload hash are the same value. The log's answer is checked against that value rather than
/// taken on trust.
fn submit<F: Fetcher>(
    fetcher: &F,
    log: &str,
    envelope: &Value,
    entry: &str,
) -> CliResult<(String, u64)> {
    let request = Request::post(
        format!("{}/v1/anchor", log.trim_end_matches('/')),
        body(&json!({ "payload": envelope, "metadata": atl_metadata() }))?,
    );
    let response = fetch(fetcher, &request)?;
    if response.status != 201 {
        return Err(CliError::EvidenceMissing(format!(
            "the log answered {} to a submission: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )));
    }
    let receipt = json_body(&response, "the log")?;
    check_entry_block(&receipt, entry)?;
    let atl_entry_id = receipt
        .pointer("/entry/id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::EvidenceMissing(
                "the log's submission answer carries no `entry.id`, so its Evidence Receipt \
                 cannot be retrieved"
                    .to_owned(),
            )
        })?
        .to_owned();
    let index = receipt.pointer("/proof/leaf_index").and_then(Value::as_u64).ok_or_else(|| {
        CliError::EvidenceMissing("the log's submission answer carries no `leaf_index`".to_owned())
    })?;
    Ok((atl_entry_id, index))
}

/// `GET /v1/anchor/:id` — the ATL Evidence Receipt, and the promotion evidence it carries.
///
/// This is the interface adaptor §10.1 names for retrieval by ATL identifier, and what it
/// returns is exactly what the mirror's promote step needs: the leaf index, a checkpoint in ATL
/// form, and an inclusion proof. Using the retrieved receipt rather than the submission answer
/// is deliberate — the submission answer is a courtesy, the receipt is the log's published
/// evidence, and a deployment where the two disagree is one this refuses to build on.
///
/// Note the consequence of the log minting checkpoints per request: the checkpoint here is a
/// **different signed object** from the one the submission answered with, over the same tree.
/// That is the log's behaviour, not a fault of this code, and it is why the receipt carries the
/// retrieved checkpoint alone rather than mixing the two.
fn retrieve<F: Fetcher>(
    fetcher: &F,
    log: &str,
    atl_entry_id: &str,
    entry: &str,
) -> CliResult<LogPosition> {
    let request = Request::get(format!("{}/v1/anchor/{atl_entry_id}", log.trim_end_matches('/')));
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the log answered {} for the Evidence Receipt of `{atl_entry_id}`",
            response.status
        )));
    }
    let receipt = json_body(&response, "the log")?;
    check_entry_block(&receipt, entry)?;
    let proof = receipt.get("proof").ok_or_else(|| {
        CliError::EvidenceMissing("the log's Evidence Receipt carries no `proof`".to_owned())
    })?;
    let entry_index = proof.get("leaf_index").and_then(Value::as_u64).ok_or_else(|| {
        CliError::EvidenceMissing("the log's Evidence Receipt carries no `leaf_index`".to_owned())
    })?;
    let checkpoint = ahl_checkpoint(proof.get("checkpoint").unwrap_or(&Value::Null))?;
    let raw = checkpoint_raw(&checkpoint)?;
    let inclusion_path = string_array(proof.get("inclusion_path"), "the log's inclusion path")?;
    Ok(LogPosition { atl_entry_id: None, entry_index, checkpoint, raw, inclusion_path })
}

/// The `entry` block of an ATL Evidence Receipt must describe the entry that was submitted.
///
/// Both digests are load-bearing. The payload hash is the AHL entry id (§4.2), so a receipt
/// naming another is a receipt about another entry. The metadata digest is the constant this
/// profile pins, and "an entry whose ATL metadata is anything else is not an AHL entry under
/// this profile" — an entry the log accepted under different metadata has a leaf that does not
/// reconstruct from the envelope, however valid it is as an ATL entry.
fn check_entry_block(receipt: &Value, entry: &str) -> CliResult<()> {
    let payload_hash = receipt.pointer("/entry/payload_hash").and_then(Value::as_str);
    if payload_hash != Some(entry) {
        return Err(CliError::EvidenceMissing(format!(
            "the log names payload hash {payload_hash:?}, the submitted entry digests to \
             `{entry}`; adaptor §4.2 makes those the same value"
        )));
    }
    let metadata_hash = receipt.pointer("/entry/metadata_hash").and_then(Value::as_str);
    let pinned = sha256_hex(&jcs(&atl_metadata()));
    if metadata_hash != Some(pinned.as_str()) {
        return Err(CliError::EvidenceMissing(format!(
            "the log recorded ATL metadata digest {metadata_hash:?}; adaptor §4.2 fixes it at \
             `{pinned}`, and an entry carrying anything else is not an AHL entry under this \
             profile"
        )));
    }
    Ok(())
}

/// Read a JSON array of `sha256:<hex>` family strings, rejecting anything else outright.
///
/// Adaptor §8.2 admits that serialization and nothing else, so a proof carrying an element
/// outside the grammar is unusable rather than partly readable.
fn string_array(value: Option<&Value>, what: &str) -> CliResult<Vec<String>> {
    let array = value.and_then(Value::as_array).ok_or_else(|| {
        CliError::EvidenceMissing(format!("{what} is not an array of family strings"))
    })?;
    array
        .iter()
        .map(|element| {
            let text = element.as_str().ok_or_else(|| {
                CliError::EvidenceMissing(format!("an element of {what} is not a string"))
            })?;
            parse_hash_hex(text).map_err(|source| {
                CliError::EvidenceMissing(format!(
                    "an element of {what} is not a `sha256:<hex>` family string: {source}"
                ))
            })?;
            Ok(text.to_owned())
        })
        .collect()
}

/// The entry index the mirror already holds this entry at, if it holds it at all.
///
/// Absence is a fact about the interface and never evidence that the entry was not anchored
/// (adaptor §10.1.1), so a miss means "submit it", not "it does not exist".
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror answers unusably, or serves bytes that do not
/// digest to the id requested.
pub fn published_index<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    entry: &str,
) -> CliResult<Option<u64>> {
    let request = Request::get(format!(
        "{}/v1/entries/{entry}?encoding=base64",
        mirror.trim_end_matches('/')
    ));
    let response = fetch(fetcher, &request)?;
    if response.status == 404 {
        return Ok(None);
    }
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} for entry `{entry}`",
            response.status
        )));
    }
    let value = json_body(&response, "the mirror")?;
    let carried = value.get("envelope").and_then(Value::as_str).ok_or_else(|| {
        CliError::EvidenceMissing("the mirror served no `envelope` member".to_owned())
    })?;
    let bytes = decode_base64(carried)?;
    if sha256_hex(&bytes) != entry {
        return Err(CliError::EvidenceMissing(format!(
            "the bytes the mirror served for `{entry}` do not digest to it; retrieval is \
             self-checking and a substitution is detected here"
        )));
    }
    Ok(value.get("entry_index").and_then(Value::as_u64))
}

/// Decode a `base64:` family string.
fn decode_base64(value: &str) -> CliResult<Vec<u8>> {
    let encoded = value.strip_prefix("base64:").ok_or_else(|| {
        CliError::EvidenceMissing(format!("`{value}` is not a `base64:` family string"))
    })?;
    base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|source| {
        CliError::EvidenceMissing(format!("a `base64:` value is unusable: {source}"))
    })
}

/// Stage an entry's canonical bytes at the mirror.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror refuses the bytes.
pub fn stage<F: Fetcher>(fetcher: &F, mirror: &str, envelope: &Value) -> CliResult<()> {
    let bytes = jcs(envelope);
    let request = Request::post(
        format!("{}/v1/entries/stage", mirror.trim_end_matches('/')),
        body(&json!({
            "entry_id": entry_id(envelope),
            "envelope_base64": base64(&bytes),
            "atl_metadata": atl_metadata(),
        }))?,
    );
    let response = fetch(fetcher, &request)?;
    if response.status == 200 || response.status == 201 {
        Ok(())
    } else {
        Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} to a stage request: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )))
    }
}

/// Ingest a checkpoint at the mirror, promoting the entry the log just placed under it.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror refuses the checkpoint or the promotion.
pub fn ingest_checkpoint<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    position: &LogPosition,
    entry: &str,
) -> CliResult<()> {
    let request = Request::post(
        format!("{}/v1/checkpoints", mirror.trim_end_matches('/')),
        body(&json!({
            "checkpoint": position.checkpoint,
            "raw": position.raw,
            "entries_to_promote": [ {
                "entry_id": entry,
                "leaf_index": position.entry_index,
                "inclusion_path": position.inclusion_path,
            } ],
        }))?,
    );
    let response = fetch(fetcher, &request)?;
    if response.status == 201 {
        Ok(())
    } else {
        Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} to a checkpoint ingest: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )))
    }
}

/// Submit a checkpoint to one witness with the entry prefix it commits, and read the
/// cosignature back.
///
/// The whole prefix travels rather than a consistency proof: this profile's witness derives the
/// proof itself, which is why adaptor §11.2.4 removes `missing-consistency-proof` — a
/// proof-fed witness has no checkable evidence that a proof was withheld.
///
/// A refusal (HTTP 409) is not an error here: it is signed evidence about the log, returned to
/// the caller to report rather than to swallow.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the witness answers unusably.
pub fn cosign<F: Fetcher>(
    fetcher: &F,
    witness: &str,
    log_id: &str,
    position: &LogPosition,
    prefix: &[Value],
) -> CliResult<Value> {
    let entries: Vec<String> = prefix.iter().map(|entry| base64(&jcs(entry))).collect();
    let request = Request::post(
        format!("{}/v1/logs/{log_id}/witness", witness.trim_end_matches('/')),
        body(&json!({
            "checkpoint": position.checkpoint,
            "raw": position.raw,
            "entries": entries,
        }))?,
    );
    let response = fetch(fetcher, &request)?;
    match response.status {
        201 | 409 => json_body(&response, "the witness"),
        status => Err(CliError::EvidenceMissing(format!(
            "the witness answered {status}: {}",
            String::from_utf8_lossy(&response.body)
        ))),
    }
}

/// The newest checkpoint the mirror publishes, as this run observed it.
///
/// Never cached and never treated as authoritative about what is newest: "the mirror served
/// nothing later" is a server label, and design note §2 rule 3 makes server labels evidence of
/// nothing. It is used here only to place an entry the log already anchored, and every path
/// derived from it is recomputed against the enumerated prefix.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror publishes no checkpoint or answers unusably.
pub fn newest_checkpoint<F: Fetcher>(fetcher: &F, mirror: &str) -> CliResult<Value> {
    let request = Request::get(format!("{}/v1/checkpoints", mirror.trim_end_matches('/')));
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} for its checkpoint series",
            response.status
        )));
    }
    let value = json_body(&response, "the mirror")?;
    let members = value.as_array().ok_or_else(|| {
        CliError::EvidenceMissing("the checkpoint series is not an array".to_owned())
    })?;
    members
        .iter()
        .max_by_key(|member| member.get("tree_size").and_then(Value::as_u64).unwrap_or(0))
        .map(strip_state)
        .ok_or_else(|| CliError::EvidenceMissing("the mirror publishes no checkpoint".to_owned()))
}

/// One checkpoint the mirror publishes at a named tree size.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror holds no member at that size.
pub fn signed_checkpoint_at<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    tree_size: u64,
) -> CliResult<Value> {
    let request =
        Request::get(format!("{}/v1/checkpoints/{tree_size}", mirror.trim_end_matches('/')));
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} for the checkpoint at tree size {tree_size}",
            response.status
        )));
    }
    Ok(strip_state(&json_body(&response, "the mirror")?))
}

/// A checkpoint object with any server-side annotation removed.
///
/// The mirror reports its own view of a member's state alongside the signed fields. That view
/// is a server label: it is not covered by the log's signature and has no place in a receipt.
fn strip_state(member: &Value) -> Value {
    let mut checkpoint = member.clone();
    if let Some(object) = checkpoint.as_object_mut() {
        object.remove("state");
    }
    checkpoint
}

/// The 98-byte framing of a checkpoint object (adaptor §6.4).
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the object does not reassemble into the blob.
pub fn checkpoint_raw(checkpoint: &Value) -> CliResult<String> {
    Ok(base64(&ahl_core::atl_checkpoint_blob_from_json(checkpoint).map_err(|source| {
        CliError::EvidenceMissing(format!("the checkpoint does not reassemble: {source}"))
    })?))
}

/// The mirror's enumeration of `[0, tree_size)` under a named checkpoint.
#[derive(Debug, Clone)]
pub struct Prefix {
    /// The §4.2 inline enumeration form a receipt carries.
    pub material: Value,
    /// The carried envelopes, in entry-index order from 0.
    pub entries: Vec<Value>,
}

/// Enumerate `[0, to_index)` at the mirror under the checkpoint of size `tree_size`.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror refuses, answers unusably, or answers with a
/// range other than the one requested.
pub fn enumerate<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    tree_size: u64,
    to_index: u64,
) -> CliResult<Prefix> {
    let request = Request::post(
        format!("{}/v1/range", mirror.trim_end_matches('/')),
        body(&json!({ "tree_size": tree_size, "from_index": 0, "to_index": to_index }))?,
    );
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} to a range request for [0, {to_index}) under tree size \
             {tree_size}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )));
    }
    let value = json_body(&response, "the mirror")?;
    let carried = value.get("entries").and_then(Value::as_array).ok_or_else(|| {
        CliError::EvidenceMissing("the range response carries no `entries` array".to_owned())
    })?;
    let mut entries = Vec::with_capacity(carried.len());
    for (position, element) in carried.iter().enumerate() {
        let index = element.get("entry_index").and_then(Value::as_u64);
        if index != u64::try_from(position).ok() {
            return Err(CliError::EvidenceMissing(format!(
                "the range response carries entry index {index:?} at position {position}; \
                 adaptor §10.4 requires the indices to be exactly `i, i+1, ...` in order"
            )));
        }
        let envelope = element.get("envelope").cloned().ok_or_else(|| {
            CliError::EvidenceMissing(format!("range element {position} carries no `envelope`"))
        })?;
        entries.push(envelope);
    }
    let material = json!({
        "range": value.get("range").cloned().unwrap_or(Value::Null),
        "entries": value.get("entries").cloned().unwrap_or(Value::Null),
        "range_proof": value.get("range_proof").cloned().unwrap_or(Value::Null),
    });
    Ok(Prefix { material, entries })
}

/// The log-tree leaf preimages of a prefix, under the ATL leaf construction of adaptor §4.2.
fn leaves(entries: &[Value]) -> CliResult<Vec<Vec<u8>>> {
    entries
        .iter()
        .map(|envelope| {
            log_leaf_bytes_for(envelope, ATL_PROFILE).map_err(|source| {
                CliError::EvidenceMissing(format!(
                    "an enumerated entry is not an envelope: {source}"
                ))
            })
        })
        .collect()
}

/// The material one receipt is assembled from, after the prefix has been checked against the
/// checkpoint it is served under.
///
/// # Why the checkpoint is carried exactly as cosigned
///
/// Adaptor §6.4 permits `anchoring.checkpoint.raw`, and §11.1 makes the cosigned bytes
/// `JCS({"checkpoint": <the signed checkpoint object>, "witness_id": ...})`. Read literally
/// those two clauses interact and neither says so: a witness shown the six mapped members of
/// §6.2 cosigned *those* bytes, so a producer that afterwards added `raw` changed the preimage
/// and the cosignature stopped verifying over the object the receipt carried. That is not a
/// hypothetical — it is what this pilot hit first, on every receipt it issued.
///
/// `ahl_core::CosignedCheckpoint::project` now settles it in the direction §11.1 should have
/// stated all along: the preimage is the six members, and `raw` is dropped rather than signed.
/// Carrying the framing is therefore possible again. This build still does not, for one reason
/// only — a receipt is safest when its checkpoint object is byte-identical to the one a witness
/// was actually shown, and nothing in this pilot needs the convenience §6.4 offers. Revisiting
/// that is a decision to take deliberately, not a default to drift into.
pub struct Assembly {
    /// The checkpoint the receipt is anchored under, exactly as the witnesses cosigned it.
    checkpoint: Value,
    /// Cosignatures the governing manifest's witness set accounts for.
    cosignatures: Vec<Value>,
    /// Cosignatures by witnesses an earlier manifest version declared, for rotation proofs.
    outgoing_cosignatures: BTreeMap<String, Value>,
    /// The entries the checkpoint commits, in index order.
    entries: Vec<Value>,
    /// Their leaf preimages.
    leaf_bytes: Vec<Vec<u8>>,
    /// The §4.2 enumeration material, carried only in enumerated mode.
    material: Value,
}

impl Assembly {
    /// Build from a checkpoint and the prefix enumerated under it.
    ///
    /// The recomputed root is compared with the one the checkpoint commits **before** any path
    /// is derived from these leaves. That is not a verification step standing in for `verify`:
    /// a path computed in the wrong tree is not a path, and emitting one would put a receipt
    /// into the world whose geometry never held.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the enumeration does not cover the checkpoint, or
    /// where the root it recomputes to is not the one the checkpoint commits.
    pub fn new(
        checkpoint: Value,
        prefix: Prefix,
        cosignatures: Vec<Value>,
        outgoing_cosignatures: BTreeMap<String, Value>,
    ) -> CliResult<Self> {
        let size = tree_size(&checkpoint)?;
        let carried = u64::try_from(prefix.entries.len()).unwrap_or(u64::MAX);
        if carried != size {
            return Err(CliError::EvidenceMissing(format!(
                "the enumeration carries {carried} entries, the checkpoint commits {size}"
            )));
        }
        let leaf_bytes = leaves(&prefix.entries)?;
        let recomputed = tree_root(&leaf_bytes);
        let committed = checkpoint.get("root_hash").and_then(Value::as_str).ok_or_else(|| {
            CliError::EvidenceMissing("the checkpoint carries no `root_hash`".to_owned())
        })?;
        if hash_hex(&recomputed) != committed {
            return Err(CliError::EvidenceMissing(format!(
                "the root recomputed from the enumerated prefix is {}, the checkpoint commits \
                 {committed}; the checkpoint describes a tree this material is not",
                hash_hex(&recomputed)
            )));
        }
        Ok(Self {
            checkpoint,
            cosignatures,
            outgoing_cosignatures,
            entries: prefix.entries,
            leaf_bytes,
            material: prefix.material,
        })
    }

    /// The entry at `index`, as the enumeration carried it.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the prefix does not reach that index.
    pub fn entry(&self, index: u64) -> CliResult<&Value> {
        usize::try_from(index).ok().and_then(|at| self.entries.get(at)).ok_or_else(|| {
            CliError::EvidenceMissing(format!("the enumerated prefix does not reach entry {index}"))
        })
    }

    /// Require the entry at `index` to be the one whose bytes the caller handed over.
    ///
    /// The index a mirror reports for an entry is a **server label** (design note §2 rule 3) and
    /// proves nothing; a mirror that answered with a neighbour's index would otherwise have a
    /// receipt assembled about a different statement, signed and anchored and entirely genuine,
    /// and about the wrong thing. The enumerated prefix has already been checked against the
    /// root the log signed, so this comparison is against material the checkpoint commits.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the prefix does not reach the index, or where the
    /// entry there is a different entry.
    pub fn require_subject(&self, index: u64, entry: &str) -> CliResult<()> {
        let found = entry_id(self.entry(index)?);
        if found == entry {
            Ok(())
        } else {
            Err(CliError::EvidenceMissing(format!(
                "the mirror places entry `{entry}` at index {index}, but the entry the \
                 checkpoint commits there is `{found}`; an index is a server label and is never \
                 evidence of position"
            )))
        }
    }

    /// The inclusion path of `index` under this assembly's checkpoint, computed locally.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the index is outside the tree.
    pub fn inclusion_path(&self, index: u64) -> CliResult<Vec<String>> {
        let at = usize::try_from(index).map_err(|_| {
            CliError::EvidenceMissing(format!("entry index {index} is not addressable"))
        })?;
        let proof = inclusion_proof(&self.leaf_bytes, at).map_err(|source| {
            CliError::EvidenceMissing(format!("no inclusion path for entry {index}: {source}"))
        })?;
        Ok(proof_path_hex(&proof))
    }

    /// The `tree_size` of the checkpoint this assembly is anchored under.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the checkpoint is unreadable.
    pub fn size(&self) -> CliResult<u64> {
        tree_size(&self.checkpoint)
    }

    /// The checkpoint this assembly is anchored under, without its binary framing.
    #[must_use]
    pub const fn checkpoint(&self) -> &Value {
        &self.checkpoint
    }

    /// The leaf hash of one carried entry, for a caller cross-checking geometry.
    #[must_use]
    pub fn leaf(&self, index: usize) -> Option<String> {
        self.leaf_bytes.get(index).map(|bytes| hash_hex(&leaf_hash(bytes)))
    }
}

/// One producer key in force at some entry index, with the governance statement that put it
/// there — the binding a receipt's `keys.producer[]` entry must name (receipt format §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundKey {
    /// `base64:` public key.
    pub pubkey: String,
    /// Entry index of the manifest or `key` statement that put the key in force.
    pub bound_at: u64,
}

/// A governance view over an enumerated prefix: which manifests it carries, which is active
/// where, and which producer keys are in force at a given index.
pub struct Governance<'a> {
    /// `(entry_index, payload)` for every manifest statement in the prefix, in order.
    manifests: Vec<(u64, &'a Value)>,
    /// `(entry_index, key payload)` for every `key` statement in the prefix, in order.
    events: Vec<(u64, &'a Value)>,
}

/// The payload of an envelope, where it has one.
fn payload(envelope: &Value) -> Option<&Value> {
    envelope.get("payload").filter(|value| value.is_object())
}

impl<'a> Governance<'a> {
    /// Read the governance statements out of an enumerated prefix.
    ///
    /// Nothing here authorizes anything: it collects what the range carries so the receipt can
    /// present it, and adaptor §7.4.1 is emphatic that anchoring never makes an unverified
    /// governance statement effective. The verifier decides which of these count.
    #[must_use]
    pub fn read(entries: &'a [Value]) -> Self {
        let mut manifests = Vec::new();
        let mut events = Vec::new();
        for (position, envelope) in entries.iter().enumerate() {
            let Some(payload) = payload(envelope) else { continue };
            let Ok(index) = u64::try_from(position) else { continue };
            match payload.get("type").and_then(Value::as_str) {
                Some("manifest") => manifests.push((index, payload)),
                Some("key") => events.push((index, payload)),
                _ => {}
            }
        }
        Self { manifests, events }
    }

    /// The manifest payload anchored at `index`.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the prefix carries no manifest there.
    pub fn manifest_at(&self, index: u64) -> CliResult<&'a Value> {
        self.manifests
            .iter()
            .find(|(at, _)| *at == index)
            .map(|(_, manifest)| *manifest)
            .ok_or_else(|| {
                CliError::EvidenceMissing(format!(
                    "the enumerated prefix carries no manifest at entry {index}"
                ))
            })
    }

    /// Entry indices of every manifest the prefix carries, in order.
    #[must_use]
    pub fn manifest_indices(&self) -> Vec<u64> {
        self.manifests.iter().map(|(index, _)| *index).collect()
    }

    /// The manifest version **active for a checkpoint** of size `tree_size` (I-D §7.1): the
    /// manifest with the greatest entry index strictly smaller than that size.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the prefix carries no manifest below that size.
    pub fn active_for_checkpoint(&self, tree_size: u64) -> CliResult<(u64, &'a Value)> {
        self.manifests.iter().rfind(|(index, _)| *index < tree_size).copied().ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "no manifest version is anchored below tree size {tree_size}"
            ))
        })
    }

    /// The manifest whose producer-key snapshot is in force *at* `index` (I-D §2.2): the
    /// greatest manifest index smaller than `index`, falling back to genesis at index 0.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where the prefix carries no manifest at all.
    pub fn snapshot_at(&self, index: u64) -> CliResult<(u64, &'a Value)> {
        self.manifests
            .iter()
            .rfind(|(at, _)| *at < index)
            .or_else(|| self.manifests.first())
            .copied()
            .ok_or_else(|| {
                CliError::EvidenceMissing("the enumerated prefix carries no manifest".to_owned())
            })
    }

    /// The producer keys in force at `index`, each with the governance statement that put it
    /// there — the binding a receipt's `keys.producer[]` entry must name (receipt format §2.2).
    ///
    /// `enumerated` decides whether `key` statements are seen at all: I-D §7.4 puts producer-key
    /// transitions in enumeration material alone, so a declared-mode receipt sees the manifest
    /// snapshot and nothing else.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] where no manifest governs that index.
    pub fn producer_keys_at(
        &self,
        index: u64,
        enumerated: bool,
    ) -> CliResult<BTreeMap<String, BoundKey>> {
        let (snapshot_index, manifest) = self.snapshot_at(index)?;
        let mut keys = BTreeMap::new();
        for object in manifest.get("keys").and_then(Value::as_array).into_iter().flatten() {
            let (Some(key_id), Some(pubkey)) = (
                object.get("key_id").and_then(Value::as_str),
                object.get("pubkey").and_then(Value::as_str),
            ) else {
                continue;
            };
            keys.insert(
                key_id.to_owned(),
                BoundKey { pubkey: pubkey.to_owned(), bound_at: snapshot_index },
            );
        }
        if !enumerated {
            return Ok(keys);
        }
        for (at, event) in &self.events {
            if *at <= snapshot_index || *at > index {
                continue;
            }
            let object = event.get("key");
            let (Some(key_id), Some(pubkey)) = (
                object.and_then(|key| key.get("key_id")).and_then(Value::as_str),
                object.and_then(|key| key.get("pubkey")).and_then(Value::as_str),
            ) else {
                continue;
            };
            if event.get("action").and_then(Value::as_str) == Some("add") {
                keys.insert(
                    key_id.to_owned(),
                    BoundKey { pubkey: pubkey.to_owned(), bound_at: *at },
                );
            } else {
                keys.remove(key_id);
            }
        }
        Ok(keys)
    }

    /// The manifest versions in the carried chain that rotate the log or witness key set.
    ///
    /// I-D §7.1 requires one `governance.rotation_proofs[]` element per such version, in
    /// ascending order, and requires the member to be ABSENT where the chain rotates neither
    /// set — never present as an empty array.
    #[must_use]
    pub fn rotations(&self, carried: &[u64]) -> Vec<Rotation> {
        let mut rotations = Vec::new();
        let mut previous: Option<(u64, &Value)> = None;
        for (index, manifest) in &self.manifests {
            if let Some((outgoing_entry_index, outgoing)) = previous {
                let log_keys_changed =
                    outgoing.pointer("/log/keys") != manifest.pointer("/log/keys");
                let witnesses_changed = outgoing.get("witnesses") != manifest.get("witnesses");
                if (log_keys_changed || witnesses_changed) && carried.contains(index) {
                    rotations.push(Rotation {
                        manifest_entry_index: *index,
                        outgoing_entry_index,
                        log_keys_changed,
                    });
                }
            }
            previous = Some((*index, manifest));
        }
        rotations
    }
}

/// A governance-key rotation the carried chain contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// Entry index of the manifest version that rotates.
    pub manifest_entry_index: u64,
    /// Entry index of the version active immediately before it — the outgoing state.
    pub outgoing_entry_index: u64,
    /// Whether the LOG checkpoint-signing key set changed, as opposed to the witness set alone.
    pub log_keys_changed: bool,
}

impl Rotation {
    /// Whether this build can assemble a rotation proof for it.
    ///
    /// I-D §7.1 requires a rotation proof's checkpoint to verify under the **outgoing** key set.
    /// Where only the witness set rotated, the log key is unchanged and the receipt's own
    /// anchoring checkpoint satisfies that; what differs is which witness cosigned it, and both
    /// cosignatures are obtainable.
    ///
    /// Where the LOG key set rotated, the proof needs a checkpoint signed by the **retired** key
    /// over a tree size the **incoming** manifest version governs. Nothing in this stack can
    /// supply one: `ahl-mirror` and `ahl-witness` both resolve a checkpoint's log key from the
    /// governance state at the end of its committed prefix, which is the incoming version, so
    /// both refuse such a checkpoint — and the published `atl-server` reads its signing key once
    /// at start-up and has no rotation path at all. Rather than emit a proof built from the
    /// anchoring checkpoint, which is signed by the *incoming* key and would fail verification
    /// for a reason that names the wrong thing, this build says what it cannot do.
    ///
    /// # Errors
    ///
    /// [`CliError::ProfileLimitation`] naming the rotation and why it is not assembled here.
    pub fn check_supported(&self) -> CliResult<()> {
        if !self.log_keys_changed {
            return Ok(());
        }
        Err(CliError::ProfileLimitation(format!(
            "the manifest version at entry {} rotates the LOG checkpoint-signing key set, and \
             this build assembles no rotation proof for that: I-D §7.1 requires the proof's \
             checkpoint to verify under the OUTGOING key set, and no interface in this \
             deployment serves a checkpoint signed by a retired log key over a tree size the \
             incoming manifest version governs",
            self.manifest_entry_index
        )))
    }
}

/// A `keys` block entry (receipt format §2.2).
fn key_entry(key_id: &str, pubkey: &str, witness_id: Option<&str>, binding: u64) -> Value {
    let mut entry = json!({
        "key_id": key_id,
        "pubkey": pubkey,
        "source": "manifest-chain",
        "binding": { "entry_index": binding },
    });
    if let Some(id) = witness_id {
        if let Some(map) = entry.as_object_mut() {
            map.insert("witness_id".to_owned(), json!(id));
        }
    }
    entry
}

/// Add a `keys` entry unless the block already carries the identical one.
///
/// One physical key legitimately appears more than once under different bindings — a rotation
/// whose outgoing log key is the incoming one produces exactly that — but a byte-identical
/// repeat is not a second binding.
fn push_key(block: &mut Vec<Value>, entry: Value) {
    if !block.contains(&entry) {
        block.push(entry);
    }
}

/// The `keys.log[]` and `keys.witness[]` entries a manifest version declares, bound to it.
fn manifest_key_entries(manifest: &Value, index: u64) -> (Vec<Value>, Vec<Value>) {
    let mut log = Vec::new();
    for object in manifest.pointer("/log/keys").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(key_id), Some(pubkey)) = (
            object.get("key_id").and_then(Value::as_str),
            object.get("pubkey").and_then(Value::as_str),
        ) {
            push_key(&mut log, key_entry(key_id, pubkey, None, index));
        }
    }
    let mut witness = Vec::new();
    for declared in manifest.get("witnesses").and_then(Value::as_array).into_iter().flatten() {
        let witness_id = declared.get("witness_id").and_then(Value::as_str);
        for object in declared.get("keys").and_then(Value::as_array).into_iter().flatten() {
            if let (Some(key_id), Some(pubkey)) = (
                object.get("key_id").and_then(Value::as_str),
                object.get("pubkey").and_then(Value::as_str),
            ) {
                push_key(&mut witness, key_entry(key_id, pubkey, witness_id, index));
            }
        }
    }
    (log, witness)
}

/// Which witness identities and key ids a manifest version declares.
fn declared_witnesses(manifest: &Value) -> BTreeMap<String, Vec<String>> {
    let mut declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for witness in manifest.get("witnesses").and_then(Value::as_array).into_iter().flatten() {
        let Some(witness_id) = witness.get("witness_id").and_then(Value::as_str) else { continue };
        let keys = witness
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|object| object.get("key_id").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .collect();
        declared.insert(witness_id.to_owned(), keys);
    }
    declared
}

/// Turn a witness's cosigned answer into an `anchoring.witnesses[]` element.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the answer is a refusal or is missing a member.
pub fn cosignature_entry(cosigned: &Value) -> CliResult<Value> {
    if cosigned.get("status").and_then(Value::as_str) == Some("refused") {
        return Err(CliError::EvidenceMissing(format!(
            "the witness refused to cosign, reason `{}`; a refusal is signed evidence about the \
             log and is never folded into a receipt as assurance",
            cosigned.get("reason").and_then(Value::as_str).unwrap_or("unstated")
        )));
    }
    let member = |name: &str| -> CliResult<Value> {
        cosigned.get(name).cloned().ok_or_else(|| {
            CliError::EvidenceMissing(format!("the witness's answer carries no `{name}`"))
        })
    };
    Ok(json!({
        "witness_id": member("witness_id")?,
        "key_id": member("key_id")?,
        "cosignature": member("cosignature")?,
        "cosigned_at": member("cosigned_at")?,
    }))
}

/// What a claim type asks of governance and of competing-trigger evidence.
///
/// Receipt format §3: `-effective` and `-complete` types REQUIRE `governance: "enumerated"`,
/// and `trigger-effective` additionally establishes the governing trigger by enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimShape {
    /// `declared` or `enumerated`.
    pub governance: &'static str,
    /// `not-checked` or `enumerated`.
    pub competing_triggers: &'static str,
    /// Whether `record_subject` is required.
    pub record_subject: bool,
}

/// The registry row for a claim type, or a report that this build does not assemble it.
///
/// # Errors
///
/// [`CliError::Usage`] naming the types this build assembles.
pub fn claim_shape(claim_type: &str) -> CliResult<ClaimShape> {
    let shape = |governance, competing_triggers, record_subject| {
        Ok(ClaimShape { governance, competing_triggers, record_subject })
    };
    match claim_type {
        "statement-anchored" => shape("declared", "not-checked", false),
        "record-ingested" | "record-derived" | "trigger-declared" | "disposition-declared" => {
            shape("declared", "not-checked", true)
        }
        "trigger-effective" => shape("enumerated", "enumerated", true),
        "disposition-effective" => shape("enumerated", "not-checked", true),
        // Receipt format §3 subject rule: `record_subject` is REQUIRED for `record-*`,
        // `trigger-*` and `disposition-*` types only, and MUST be absent for the other two. A
        // `propagation-complete` receipt is about an affected SET rather than one record, and
        // `governance-state` targets an index through `claim_material.target_index`.
        "propagation-complete" | "governance-state" => shape("enumerated", "not-checked", false),
        other => Err(CliError::Usage(format!(
            "`{other}` is not a claim type this build assembles; receipt format §3 registers \
             `statement-anchored`, `record-ingested`, `record-derived`, `trigger-declared`, \
             `trigger-effective`, `disposition-declared`, `disposition-effective`, \
             `propagation-complete` and `governance-state`"
        ))),
    }
}

/// Everything the caller decides about the claim, as opposed to what the log decided.
pub struct Claim {
    /// The registry id.
    pub claim_type: String,
    /// `record_subject`, where the type requires one.
    pub record_subject: Option<(String, String)>,
    /// `claim.assurance.content_binding`, and the evidence that goes with it.
    pub content: Option<ContentBinding>,
    /// The type-specific `claim_material`, less anything derived from the log.
    pub material: Value,
    /// The informative note.
    pub note: String,
}

/// Record bytes carried for a content binding, with the descriptor that interprets them.
pub struct ContentBinding {
    /// The bytes AS RECEIVED, which the verifier canonicalizes itself.
    pub bytes: Vec<u8>,
    /// The dataset's canonicalization identifier.
    pub canonicalization: String,
    /// The media type, where the descriptor requires one.
    pub media_type: Option<String>,
    /// `plain-verified` or `keyed-authorized`.
    pub binding: &'static str,
}

/// Assemble one Evidence Receipt.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the material the claim needs is not in the prefix, and
/// [`CliError::Usage`] where the caller asked for a claim type this build does not assemble.
#[allow(clippy::too_many_lines)] // One receipt, member by member; splitting it hides the order.
pub fn assemble(
    assembly: &Assembly,
    subject_index: u64,
    claim: &Claim,
    adaptor_hash_from_manifest: bool,
) -> CliResult<Value> {
    let shape = claim_shape(&claim.claim_type)?;
    let enumerated = shape.governance == "enumerated";
    let size = assembly.size()?;
    let governance = Governance::read(&assembly.entries);
    let (active_index, active) = governance.active_for_checkpoint(size)?;

    let subject = assembly.entry(subject_index)?.clone();
    let subject_payload = payload(&subject).ok_or_else(|| {
        CliError::EvidenceMissing(format!("entry {subject_index} is not an envelope"))
    })?;
    let mut subject_block = json!({
        "statement_id": statement_id(&subject).map_err(|source| CliError::EvidenceMissing(
            format!("the subject envelope has no statement id: {source}")
        ))?,
        "entry_id": entry_id(&subject),
        "entry_index": subject_index,
    });
    // A manifest statement declares no manifest version; everything else must (I-D §2.2).
    if subject_payload.get("type").and_then(Value::as_str) != Some("manifest") {
        let declared = subject_payload.get("manifest").cloned().ok_or_else(|| {
            CliError::EvidenceMissing(
                "the subject payload declares no `manifest` version".to_owned(),
            )
        })?;
        set(&mut subject_block, "manifest", declared)?;
    }

    // The chain carries every manifest the prefix holds below the checkpoint. In enumerated
    // mode I-D §7.5.1 4c requires exactly that; in declared mode it is the chain from genesis
    // the producer declares, and carrying the whole of it is the honest reading.
    let carried: Vec<u64> =
        governance.manifest_indices().into_iter().filter(|index| *index < size).collect();
    let mut chain = Vec::with_capacity(carried.len());
    for index in &carried {
        chain.push(json!({
            "envelope": assembly.entry(*index)?,
            "entry_index": index,
            "inclusion_path": assembly.inclusion_path(*index)?,
        }));
    }

    let (mut log_keys, mut witness_keys) = manifest_key_entries(active, active_index);
    let mut producer_keys = Vec::new();
    for (key_id, bound) in governance.producer_keys_at(subject_index, enumerated)? {
        push_key(&mut producer_keys, key_entry(&key_id, &bound.pubkey, None, bound.bound_at));
    }

    // `anchoring.adaptor` names the pair the ACTIVE manifest's own `log.adaptor` pins, so a
    // receipt anchored under a checkpoint one version governs carries that version's pin.
    let adaptor = if adaptor_hash_from_manifest {
        active.pointer("/log/adaptor").cloned().ok_or_else(|| {
            CliError::EvidenceMissing(
                "the active manifest's `log` object pins no adaptor profile".to_owned(),
            )
        })?
    } else {
        json!({ "id": ATL_PROFILE, "hash": Value::Null })
    };

    let mut assurance = json!({
        "governance": shape.governance,
        "competing_triggers": shape.competing_triggers,
        "witnessed": !assembly.cosignatures.is_empty(),
        "continued_history": false,
        "content_binding": claim.content.as_ref().map_or("none", |content| content.binding),
    });
    if let Some(content) = &claim.content {
        // I-D §7.3: the member is REQUIRED where `content_binding` is not `none` and absent
        // otherwise, and is `private-use` exactly where the identifier begins `x-`.
        let namespace =
            if content.canonicalization.starts_with("x-") { "private-use" } else { "public" };
        set(&mut assurance, "canonicalization_namespace", json!(namespace))?;
    }
    let mut claim_block = json!({
        "type": claim.claim_type,
        "assurance": assurance,
        "note": claim.note,
    });
    if let Some((dataset, record)) = &claim.record_subject {
        set(&mut claim_block, "record_subject", json!({ "dataset": dataset, "record": record }))?;
    } else if shape.record_subject {
        return Err(CliError::Usage(format!(
            "claim type `{}` requires a record subject; supply `--dataset` and `--record`",
            claim.claim_type
        )));
    }
    if claim.record_subject.is_some() && !shape.record_subject {
        return Err(CliError::Usage(format!(
            "claim type `{}` carries no record subject (receipt format §3 subject rule); a \
             subject here would narrow a claim the type does not narrow",
            claim.claim_type
        )));
    }

    let mut material = claim.material.clone();
    if let Some(content) = &claim.content {
        set(&mut material, "record_bytes", json!(base64(&content.bytes)))?;
        set(&mut material, "canonicalization", json!(content.canonicalization))?;
        if let Some(media_type) = &content.media_type {
            set(&mut material, "media_type", json!(media_type))?;
        }
    }

    let genesis = assembly.entry(0)?;
    let mut governance_block = json!({
        "genesis_entry_id": entry_id(genesis),
        "chain": chain,
        "currency": {
            "mode": shape.governance,
            "material": if enumerated { assembly.material.clone() } else { json!({}) },
        },
    });
    let receipt_skeleton = json!({
        "ahl_receipt_version": RECEIPT_VERSION,
        "spec_version": SPEC_VERSION,
        "claim": claim_block,
        "subject": subject_block,
        "envelope": subject,
        "anchoring": {
            "adaptor": adaptor,
            "checkpoint": assembly.checkpoint.clone(),
            "inclusion_path": assembly.inclusion_path(subject_index)?,
            "witnesses": assembly.cosignatures,
        },
        "claim_material": material,
    });
    let mut receipt = receipt_skeleton;

    // I-D §7.1: `rotation_proofs` is present if and only if the carried chain contains a
    // governance-key rotation, one element per rotation in ascending order, and the outgoing
    // key set is listed in `keys` bound to the predecessor version.
    let rotations = governance.rotations(&carried);
    if !rotations.is_empty() {
        let mut proofs = Vec::with_capacity(rotations.len());
        for rotation in &rotations {
            rotation.check_supported()?;
            let index = &rotation.manifest_entry_index;
            let outgoing_index = rotation.outgoing_entry_index;
            let outgoing_manifest = governance.manifest_at(outgoing_index)?;
            let (outgoing_log, outgoing_witness) =
                manifest_key_entries(outgoing_manifest, outgoing_index);
            for entry in outgoing_log {
                push_key(&mut log_keys, entry);
            }
            for entry in outgoing_witness {
                push_key(&mut witness_keys, entry);
            }
            // The rotation-proof checkpoint verifies under the OUTGOING key set, so its
            // cosignature must come from a witness that version declared.
            let mut witnesses = Vec::new();
            for witness_id in declared_witnesses(outgoing_manifest).keys() {
                if let Some(cosigned) = assembly.outgoing_cosignatures.get(witness_id) {
                    witnesses.push(cosigned.clone());
                }
            }
            if witnesses.is_empty() {
                return Err(CliError::EvidenceMissing(format!(
                    "the rotation at entry {index} needs a cosignature from a witness the \
                     outgoing manifest version at entry {outgoing_index} declares, and none was \
                     obtained"
                )));
            }
            proofs.push(json!({
                "manifest_entry_index": index,
                "checkpoint": assembly.checkpoint.clone(),
                "inclusion_path": assembly.inclusion_path(*index)?,
                "witnesses": witnesses,
            }));
        }
        set(&mut governance_block, "rotation_proofs", json!(proofs))?;
    }
    set(&mut receipt, "governance", governance_block)?;
    let mut keys = json!({ "producer": producer_keys });
    set(&mut keys, "log", json!(log_keys))?;
    set(&mut keys, "witness", json!(witness_keys))?;
    set(&mut receipt, "keys", keys)?;
    Ok(receipt)
}

/// Keep only the cosignatures a manifest version's witness set accounts for, and index the rest
/// by witness id so a rotation proof can find an outgoing one.
///
/// A cosignature by a witness the governing version does not declare raises no assurance
/// (adaptor §11.1), so it is not carried in `anchoring.witnesses[]`; it may still be exactly
/// what a rotation proof needs, which is why it is kept rather than discarded.
#[must_use]
pub fn split_cosignatures(
    cosignatures: Vec<Value>,
    active: &Value,
) -> (Vec<Value>, BTreeMap<String, Value>) {
    let declared = declared_witnesses(active);
    let mut carried = Vec::new();
    let mut others = BTreeMap::new();
    for entry in cosignatures {
        let witness_id = entry.get("witness_id").and_then(Value::as_str).unwrap_or_default();
        let key_id = entry.get("key_id").and_then(Value::as_str).unwrap_or_default();
        let accounted =
            declared.get(witness_id).is_some_and(|keys| keys.iter().any(|id| id == key_id));
        if accounted {
            carried.push(entry);
        } else {
            others.insert(witness_id.to_owned(), entry);
        }
    }
    (carried, others)
}

/// Leaves of the committed tree with this root, from the producer's tree material.
///
/// The material is shaped as the receipt member it becomes: `{ "<root>": { "leaves": [ ... ] } }`.
fn tree_leaves<'a>(trees: &'a Value, root: &str) -> CliResult<&'a Vec<Value>> {
    trees.get(root).and_then(|tree| tree.get("leaves")).and_then(Value::as_array).ok_or_else(|| {
        CliError::Usage(format!(
            "the tree material holds no leaves for root `{root}`; committed tree material is \
             corpus material and a claim over it cannot be assembled without it"
        ))
    })
}

/// The index of the leaf naming `record`, and the path opening it.
///
/// These trees are AHL constructs, so they use the plain leaf hashing of adaptor §9 —
/// `SHA-256(0x00 || JCS(leaf))` — and never the two-digest log-leaf construction of §4.2.
fn leaf_position(leaves: &[Value], record: &str) -> CliResult<(usize, Vec<String>)> {
    let at = leaves
        .iter()
        .position(|leaf| leaf.get("record").and_then(Value::as_str) == Some(record))
        .ok_or_else(|| CliError::Usage(format!("no committed leaf names record `{record}`")))?;
    let bytes: Vec<Vec<u8>> = leaves.iter().map(jcs).collect();
    let proof = inclusion_proof(&bytes, at).map_err(|source| {
        CliError::EvidenceMissing(format!("no path opens leaf {at}: {source}"))
    })?;
    Ok((at, proof_path_hex(&proof)))
}

/// The claim material a producer's committed trees supply for the leaf-bearing claim types.
///
/// `record-derived` opens the batch output tree at the output's leaf and, where that leaf
/// carries the wide-input form, opens the input-set tree at every member — I-D §7.2 makes
/// `input_members` prove the listed inputs and **no others**, so a partial list is not a
/// smaller claim but a false one. `disposition-*` opens the propagation's affected tree.
///
/// # Errors
///
/// [`CliError::Usage`] where the material does not hold a tree the subject commits, or holds no
/// leaf for the record the claim is about.
pub fn leaf_material(
    claim_type: &str,
    subject_payload: &Value,
    trees: &Value,
    record: &str,
    dataset: &str,
) -> CliResult<Value> {
    match claim_type {
        "record-derived" => {
            let Some(root) = subject_payload.get("outputs_root").and_then(Value::as_str) else {
                // An unbatched derivation commits its outputs inline, so there is no tree to
                // open and the claim material is the output alone.
                return Ok(json!({ "output": { "dataset": dataset, "record": record } }));
            };
            let leaves = tree_leaves(trees, root)?;
            let (at, path) = leaf_position(leaves, record)?;
            let leaf = leaves.get(at).cloned().unwrap_or(Value::Null);
            let mut material = json!({
                "output": { "dataset": dataset, "record": record },
                "batch_leaf": leaf,
                "leaf_index": at,
                "leaf_path": path,
            });
            let inputs = leaves.get(at).and_then(|leaf| leaf.get("inputs"));
            if let Some(input_root) =
                inputs.and_then(|inputs| inputs.get("input_set_root")).and_then(Value::as_str)
            {
                let input_leaves = tree_leaves(trees, input_root)?;
                let bytes: Vec<Vec<u8>> = input_leaves.iter().map(jcs).collect();
                let mut members = Vec::with_capacity(input_leaves.len());
                for (at, input) in input_leaves.iter().enumerate() {
                    let proof = inclusion_proof(&bytes, at).map_err(|source| {
                        CliError::EvidenceMissing(format!("no path opens input {at}: {source}"))
                    })?;
                    members.push(json!({
                        "input": input,
                        "input_index": at,
                        "input_path": proof_path_hex(&proof),
                    }));
                }
                set(&mut material, "input_members", json!(members))?;
            }
            Ok(material)
        }
        "disposition-declared" | "disposition-effective" => {
            let root =
                subject_payload.get("affected_root").and_then(Value::as_str).ok_or_else(|| {
                    CliError::Usage("the subject propagation commits no affected tree".to_owned())
                })?;
            let leaves = tree_leaves(trees, root)?;
            let (at, path) = leaf_position(leaves, record)?;
            Ok(json!({
                "disposition_leaf": leaves.get(at).cloned().unwrap_or(Value::Null),
                "leaf_index": at,
                "leaf_path": path,
            }))
        }
        _ => Ok(json!({})),
    }
}

#[cfg(test)]
#[allow(
    // A test asserts; an assertion that fires IS the failure report here.
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;

    fn manifest(log_key: &str, witness_id: &str, witness_key: &str) -> Value {
        json!({
            "type": "manifest",
            "keys": [ { "key_id": "sha256:p1", "pubkey": "base64:p1" } ],
            "log": { "keys": [ { "key_id": log_key, "pubkey": "base64:l", "valid_from_index": 0 } ] },
            "witnesses": [ {
                "witness_id": witness_id,
                "keys": [ { "key_id": witness_key, "pubkey": "base64:w", "valid_from_index": 0 } ],
            } ],
        })
    }

    fn envelope(payload: &Value) -> Value {
        json!({ "payload": payload, "signatures": [] })
    }

    #[test]
    fn the_metadata_object_digests_to_the_constant_the_profile_pins() {
        // Adaptor §4.2 states the digest as a constant; recompute it rather than trust it.
        assert_eq!(
            sha256_hex(&jcs(&atl_metadata())),
            "sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4"
        );
    }

    #[test]
    fn a_rotation_is_a_change_of_the_log_or_witness_key_objects_and_nothing_else() {
        let entries = vec![
            envelope(&manifest("sha256:l1", "w1", "sha256:k1")),
            envelope(&json!({ "type": "ingestion" })),
            // Same key sets restated: not a rotation.
            envelope(&manifest("sha256:l1", "w1", "sha256:k1")),
            // A different witness key: a rotation of the witness set.
            envelope(&manifest("sha256:l1", "w2", "sha256:k2")),
        ];
        let governance = Governance::read(&entries);
        assert_eq!(governance.manifest_indices(), vec![0, 2, 3]);
        assert_eq!(
            governance.rotations(&[0, 2, 3]),
            vec![Rotation {
                manifest_entry_index: 3,
                outgoing_entry_index: 2,
                log_keys_changed: false,
            }]
        );
        // A rotation whose manifest the chain does not carry produces no element, because the
        // receipt's own chain is what §7.1 conditions the member on.
        assert!(governance.rotations(&[0, 2]).is_empty());
    }

    #[test]
    fn a_log_key_rotation_is_refused_rather_than_assembled_from_the_wrong_checkpoint() {
        let entries = vec![
            envelope(&manifest("sha256:l1", "w1", "sha256:k1")),
            envelope(&manifest("sha256:l2", "w1", "sha256:k1")),
        ];
        let governance = Governance::read(&entries);
        let rotations = governance.rotations(&[0, 1]);
        assert_eq!(
            rotations,
            vec![Rotation {
                manifest_entry_index: 1,
                outgoing_entry_index: 0,
                log_keys_changed: true,
            }]
        );
        let error = rotations[0].check_supported().expect_err("no proof is assembled for it");
        assert!(error.to_string().contains("OUTGOING key set"), "{error}");
        // A witness-set rotation over an unchanged log key is assembled as before.
        Rotation { manifest_entry_index: 1, outgoing_entry_index: 0, log_keys_changed: false }
            .check_supported()
            .expect("a witness rotation needs no retired log key");
    }

    #[test]
    fn declared_mode_sees_no_key_transitions_and_enumerated_mode_sees_them() {
        let entries = vec![
            envelope(&manifest("sha256:l1", "w1", "sha256:k1")),
            envelope(&json!({
                "type": "key",
                "action": "add",
                "key": { "key_id": "sha256:p2", "pubkey": "base64:p2" },
            })),
            envelope(&json!({ "type": "ingestion" })),
        ];
        let governance = Governance::read(&entries);
        let declared = governance.producer_keys_at(2, false).unwrap();
        assert_eq!(declared.keys().collect::<Vec<_>>(), vec!["sha256:p1"]);
        let enumerated = governance.producer_keys_at(2, true).unwrap();
        assert_eq!(enumerated.keys().collect::<Vec<_>>(), vec!["sha256:p1", "sha256:p2"]);
        assert_eq!(
            enumerated.get("sha256:p2"),
            Some(&BoundKey { pubkey: "base64:p2".to_owned(), bound_at: 1 })
        );
    }

    #[test]
    fn a_cosignature_by_an_undeclared_witness_is_never_carried_as_assurance() {
        let active = manifest("sha256:l1", "w2", "sha256:k2");
        let cosignatures = vec![
            json!({ "witness_id": "w1", "key_id": "sha256:k1" }),
            json!({ "witness_id": "w2", "key_id": "sha256:k2" }),
        ];
        let (carried, others) = split_cosignatures(cosignatures, &active);
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0]["witness_id"], json!("w2"));
        assert!(others.contains_key("w1"));
    }

    #[test]
    fn a_refusal_is_reported_rather_than_folded_into_a_receipt() {
        let refusal = json!({ "status": "refused", "reason": "size-regression" });
        let error = cosignature_entry(&refusal).expect_err("a refusal is not a cosignature");
        assert!(error.to_string().contains("size-regression"), "{error}");
    }

    /// A two-entry assembly over a genuine root, for the subject-binding tests.
    fn assembly_of(entries: Vec<Value>) -> Assembly {
        let leaf_bytes: Vec<Vec<u8>> = entries
            .iter()
            .map(|envelope| log_leaf_bytes_for(envelope, ATL_PROFILE).expect("an envelope"))
            .collect();
        let checkpoint = json!({
            "tree_size": entries.len(),
            "root_hash": hash_hex(&tree_root(&leaf_bytes)),
        });
        Assembly::new(
            checkpoint,
            Prefix { material: json!({}), entries },
            Vec::new(),
            BTreeMap::new(),
        )
        .expect("the prefix recomputes the root")
    }

    #[test]
    fn a_server_supplied_index_is_never_taken_as_evidence_of_position() {
        let first = envelope(&json!({ "type": "ingestion", "record": "a" }));
        let second = envelope(&json!({ "type": "ingestion", "record": "b" }));
        let wanted = entry_id(&first);
        let assembly = assembly_of(vec![first, second]);

        assembly.require_subject(0, &wanted).expect("the entry is where the mirror said");
        // The same entry id, an index the mirror could have answered with instead.
        let error = assembly.require_subject(1, &wanted).expect_err("a neighbour is not the entry");
        assert!(error.to_string().contains("never evidence of position"), "{error}");
        // An index the checkpoint does not commit at all.
        assert!(assembly.require_subject(9, &wanted).is_err());
    }

    #[test]
    fn an_unregistered_claim_type_is_a_usage_error_naming_the_registry() {
        let error = claim_shape("record-invented").expect_err("not a registry id");
        assert!(error.to_string().contains("statement-anchored"), "{error}");
    }
}
