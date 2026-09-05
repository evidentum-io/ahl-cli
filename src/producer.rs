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

use std::collections::{BTreeMap, BTreeSet};

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
    // The receipt must be about the entry that was asked for. Nothing else in the exchange
    // establishes that: the identifier lives in the URL, and a log that answered with a
    // different entry's receipt — by defect or by design — would otherwise have its checkpoint,
    // its index and its inclusion proof taken as evidence about ours. The payload-hash check
    // below is not a substitute, because it is the same digest a substituted receipt would be
    // rejected on only if the substitution changed it; this catches the identifier itself.
    let named = receipt.pointer("/entry/id").and_then(Value::as_str);
    if named != Some(atl_entry_id) {
        return Err(CliError::EvidenceMissing(format!(
            "the Evidence Receipt served for `{atl_entry_id}` is about entry {named:?}"
        )));
    }
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
/// # `rotation_for`
///
/// Where the checkpoint being submitted is rotation-anchoring material (I-D §7.1's transition
/// exception), the rotating manifest's entry index is named. Naming NARROWS NOTHING — the
/// witness discovers every rotation the checkpoint qualifies for either way — so what it buys
/// is the report: a named rotation the checkpoint does not in fact anchor comes back as a
/// refusal saying why, instead of a cosignature that quietly anchors nothing.
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
    rotation_for: Option<u64>,
) -> CliResult<Value> {
    let entries: Vec<String> = prefix.iter().map(|entry| base64(&jcs(entry))).collect();
    let mut submission = json!({
        "checkpoint": position.checkpoint,
        "raw": position.raw,
        "entries": entries,
    });
    if let Some(index) = rotation_for {
        set(&mut submission, "rotation_for", json!(index))?;
    }
    let request = Request::post(
        format!("{}/v1/logs/{log_id}/witness", witness.trim_end_matches('/')),
        body(&submission)?,
    );
    let response = fetch(fetcher, &request)?;
    match response.status {
        201 | 409 => json_body(&response, "the witness"),
        status => Err(CliError::EvidenceMissing(format!(
            "the witness answered {status} to a checkpoint submission{}: {}",
            rotation_for
                .map_or_else(String::new, |index| format!(" naming the rotation at entry {index}")),
            String::from_utf8_lossy(&response.body)
        ))),
    }
}

/// The rotating-manifest entry indexes a server reported the submitted checkpoint anchors.
///
/// Both `POST /v1/checkpoints` and `POST /v1/logs/{log_id}/witness` answer with
/// `rotation_anchors[]`, always present and empty where the checkpoint anchors nothing. It is a
/// list because one checkpoint under an unchanged log key can anchor several witness-set
/// rotations at once.
#[must_use]
pub fn rotation_anchors(answer: &Value) -> Vec<u64> {
    answer
        .get("rotation_anchors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect()
}

/// Offer a checkpoint to the mirror as rotation-anchoring material for one rotation.
///
/// A second submission of a checkpoint the mirror already holds, carrying nothing but the
/// object and the name: the mirror's ingest is idempotent for an identical checkpoint, and the
/// ordinary ingest happens before the prefix is enumerated, which is the only place the
/// rotations are known. What this call adds is the naming — and with it the mirror's refusal
/// where the checkpoint does not in fact anchor the rotation named.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror refuses the offer or answers unusably.
pub fn offer_rotation_anchor<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    checkpoint: &Value,
    manifest_entry_index: u64,
) -> CliResult<Vec<u64>> {
    let request = Request::post(
        format!("{}/v1/checkpoints", mirror.trim_end_matches('/')),
        body(&json!({ "checkpoint": checkpoint, "rotation_for": manifest_entry_index }))?,
    );
    let response = fetch(fetcher, &request)?;
    if response.status != 201 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} to a checkpoint offered as rotation-anchoring material for \
             the rotation at entry {manifest_entry_index}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )));
    }
    Ok(rotation_anchors(&json_body(&response, "the mirror")?))
}

/// The mirror's `governance.rotation_proofs[]` element for the rotation at
/// `manifest_entry_index`.
///
/// Three of the element's four members come from here — `manifest_entry_index`, the
/// rotation-anchoring `checkpoint`, and the `inclusion_path` opening the rotating manifest to
/// THAT checkpoint's root. `witnesses` is served empty and is filled from
/// [`rotation_cosignatures`]: a mirror does not cosign, so an empty array is the only honest
/// value it has.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror serves no anchor for that rotation, naming
/// the index and the route, or answers unusably.
pub fn rotation_proof<F: Fetcher>(
    fetcher: &F,
    mirror: &str,
    manifest_entry_index: u64,
) -> CliResult<Value> {
    let route = format!("/v1/rotation-proofs/{manifest_entry_index}");
    let request = Request::get(format!("{}{route}", mirror.trim_end_matches('/')));
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered {} for the rotation at entry {manifest_entry_index}: `GET \
             {route}` serves no rotation-anchoring checkpoint for it, and I-D §7.1 makes the \
             element material a receipt MUST carry — a receipt without it is not a smaller \
             claim but an inadmissible one",
            response.status
        )));
    }
    json_body(&response, "the mirror")
}

/// One witness's cosignatures over the rotation-anchoring checkpoint for
/// `manifest_entry_index`, in the `anchoring.witnesses[]` shape.
///
/// The answer carries the `checkpoint` those cosignatures are over, which is what makes the
/// pairing checkable without a second request.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the witness holds none, naming the index and the route,
/// or answers unusably.
pub fn rotation_cosignatures<F: Fetcher>(
    fetcher: &F,
    witness: &str,
    log_id: &str,
    manifest_entry_index: u64,
) -> CliResult<Value> {
    let route = format!("/v1/logs/{log_id}/rotation-cosignatures/{manifest_entry_index}");
    let request = Request::get(format!("{}{route}", witness.trim_end_matches('/')));
    let response = fetch(fetcher, &request)?;
    if response.status != 200 {
        return Err(CliError::EvidenceMissing(format!(
            "the witness answered {} for the rotation at entry {manifest_entry_index}: `GET \
             {route}` serves no cosignature over a rotation-anchoring checkpoint for it",
            response.status
        )));
    }
    json_body(&response, "the witness")
}

/// Compose one `governance.rotation_proofs[]` element from the mirror's element and the
/// cosignatures every configured witness serves for the same rotation.
///
/// The join is the whole composition and nothing is edited into it: the three members the
/// mirror serves are carried through unchanged, and `witnesses` becomes the concatenation of
/// what the witnesses served. The one thing that is CHECKED is the pairing — a cosignature is
/// over one checkpoint, and an element whose `checkpoint` is a different one is not the element
/// those cosignatures attest. Both sides serve the earliest qualifying anchor, so they agree in
/// a healthy deployment; where they do not, the material is not joined into something that
/// looks whole.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the mirror's element is not the shape it must be, where
/// a witness answered about another rotation or over another checkpoint, or where the join
/// leaves no cosignature at all.
pub fn compose_rotation_proof(
    manifest_entry_index: u64,
    element: &Value,
    served: &[Value],
) -> CliResult<Value> {
    let missing = |what: &str| {
        CliError::EvidenceMissing(format!(
            "the rotation proof served for entry {manifest_entry_index} carries no `{what}`"
        ))
    };
    let served_index = element.get("manifest_entry_index").and_then(Value::as_u64);
    if served_index != Some(manifest_entry_index) {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror answered `GET /v1/rotation-proofs/{manifest_entry_index}` with an \
             element for {served_index:?}; I-D §7.1 makes `manifest_entry_index` the rotating \
             manifest's own entry index"
        )));
    }
    let checkpoint = element
        .get("checkpoint")
        .filter(|value| value.is_object())
        .ok_or_else(|| missing("checkpoint"))?;
    let inclusion_path = element
        .get("inclusion_path")
        .filter(|value| value.is_array())
        .ok_or_else(|| missing("inclusion_path"))?;

    let mut witnesses: Vec<Value> = Vec::new();
    for answer in served {
        if answer.get("manifest_entry_index").and_then(Value::as_u64) != Some(manifest_entry_index)
        {
            return Err(CliError::EvidenceMissing(format!(
                "a witness answered about another rotation than the one at entry \
                 {manifest_entry_index}"
            )));
        }
        let cosigned_over = answer.get("checkpoint").ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "the witness's answer for the rotation at entry {manifest_entry_index} carries \
                 no `checkpoint`, so nothing says which checkpoint it cosigned"
            ))
        })?;
        if cosigned_over != checkpoint {
            return Err(CliError::EvidenceMissing(format!(
                "the mirror and a witness serve different rotation-anchoring checkpoints for \
                 the rotation at entry {manifest_entry_index}: a cosignature is over ONE \
                 checkpoint, and joining these halves would carry cosignatures that do not \
                 attest the checkpoint the element names"
            )));
        }
        for cosignature in answer.get("witnesses").and_then(Value::as_array).into_iter().flatten() {
            if !witnesses.contains(cosignature) {
                witnesses.push(cosignature.clone());
            }
        }
    }
    if witnesses.is_empty() {
        return Err(CliError::EvidenceMissing(format!(
            "no witness served a cosignature over the rotation-anchoring checkpoint for the \
             rotation at entry {manifest_entry_index}"
        )));
    }
    Ok(json!({
        "manifest_entry_index": manifest_entry_index,
        "checkpoint": checkpoint,
        "inclusion_path": inclusion_path,
        "witnesses": witnesses,
    }))
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
    pub fn new(checkpoint: Value, prefix: Prefix, cosignatures: Vec<Value>) -> CliResult<Self> {
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

    /// Entry indices of the manifests a receipt anchored under a checkpoint of `tree_size`
    /// carries in `governance.chain[]`.
    ///
    /// Shared with [`assemble`] rather than recomputed beside it: the rotations a receipt owes a
    /// proof for are the rotations of the chain AS CARRIED (I-D §7.1), so a caller that fetched
    /// proofs against one chain and a receipt assembled against another would carry an element
    /// count the verifier does not expect.
    #[must_use]
    pub fn carried_indices(&self, tree_size: u64) -> Vec<u64> {
        self.manifest_indices().into_iter().filter(|index| *index < tree_size).collect()
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
                let log_keys_changed = log_key_set(outgoing) != log_key_set(manifest);
                let witnesses_changed = witness_key_set(outgoing) != witness_key_set(manifest);
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

/// One `log.keys[]` object as it is compared: `(key_id, pubkey, valid_from_index)`.
type LogKeyObject = (String, String, Option<u64>);

/// One `witnesses[].keys[]` object as it is compared, carrying the witness identity it belongs
/// to: `(witness_id, key_id, pubkey, valid_from_index)`.
type WitnessKeyObject = (String, String, String, Option<u64>);

/// The `log.keys[]` objects a manifest version declares, as a SET.
///
/// A set and not the array, because I-D §7.1 makes a rotation a difference between the key
/// OBJECTS: a version restating the same keys in another order rotates nothing, and the
/// verifier compares them the same way. A producer comparing the arrays would demand an element
/// for a rotation the verifier does not see, and the receipt would be refused for carrying one
/// element too many.
fn log_key_set(manifest: &Value) -> BTreeSet<LogKeyObject> {
    manifest
        .pointer("/log/keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|object| {
            Some((
                object.get("key_id").and_then(Value::as_str)?.to_owned(),
                object.get("pubkey").and_then(Value::as_str)?.to_owned(),
                object.get("valid_from_index").and_then(Value::as_u64),
            ))
        })
        .collect()
}

/// The `witnesses[].keys[]` objects a manifest version declares, as a SET, each carrying the
/// witness identity it belongs to.
fn witness_key_set(manifest: &Value) -> BTreeSet<WitnessKeyObject> {
    let mut set = BTreeSet::new();
    for witness in manifest.get("witnesses").and_then(Value::as_array).into_iter().flatten() {
        let Some(witness_id) = witness.get("witness_id").and_then(Value::as_str) else { continue };
        for object in witness.get("keys").and_then(Value::as_array).into_iter().flatten() {
            let (Some(key_id), Some(pubkey)) = (
                object.get("key_id").and_then(Value::as_str),
                object.get("pubkey").and_then(Value::as_str),
            ) else {
                continue;
            };
            set.insert((
                witness_id.to_owned(),
                key_id.to_owned(),
                pubkey.to_owned(),
                object.get("valid_from_index").and_then(Value::as_u64),
            ));
        }
    }
    set
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
    /// Whether `checkpoint` is ROTATION-ANCHORING material for this rotation, under the
    /// transition exception of I-D §7.1.
    ///
    /// Two conditions, and they are the two the mirror and the witness apply when they decide
    /// what a submission anchors: the checkpoint's `tree_size` is GREATER than the rotating
    /// manifest's entry index, and it is signed by a key of the **outgoing** log key set — the
    /// key being retired, never the one being installed.
    ///
    /// The signature itself is not checked here and must not be: `issue` verifies no signature
    /// (that is `verify`'s job), so this reads the `key_id` the checkpoint names and stops. It
    /// is therefore a necessary condition rather than the whole test, which is exactly what it
    /// is used for — deciding which rotation to NAME on a submission. The server applies the
    /// full test and refuses a name that does not hold.
    #[must_use]
    pub fn anchored_by(&self, checkpoint: &Value, outgoing_manifest: &Value) -> bool {
        let Some(tree_size) = checkpoint.get("tree_size").and_then(Value::as_u64) else {
            return false;
        };
        if tree_size <= self.manifest_entry_index {
            return false;
        }
        let Some(key_id) = checkpoint.get("key_id").and_then(Value::as_str) else { return false };
        log_key_set(outgoing_manifest).iter().any(|(declared, _, _)| declared == key_id)
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
/// `rotation_proofs` maps a rotating manifest's entry index to the element composed for it by
/// [`compose_rotation_proof`]. Assembly does not fetch: the caller obtained the halves from the
/// mirror and the witnesses and joined them, and what happens here is the last two steps I-D
/// §7.1 puts on the producer — filtering the cosignatures down to the witnesses the OUTGOING
/// version declares, and listing the outgoing keys in `keys` bound to that predecessor version.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] where the material the claim needs is not in the prefix or no
/// element was composed for a rotation the chain carries, and [`CliError::Usage`] where the
/// caller asked for a claim type this build does not assemble.
#[allow(clippy::too_many_lines)] // One receipt, member by member; splitting it hides the order.
pub fn assemble(
    assembly: &Assembly,
    subject_index: u64,
    claim: &Claim,
    rotation_proofs: &BTreeMap<u64, Value>,
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
    let carried: Vec<u64> = governance.carried_indices(size);
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
    // receipt anchored under a checkpoint one version governs carries that version's pin. It is
    // never assembled from a constant here: the pin is a governance fact, and a receipt that
    // named a profile its own corpus had not adopted would be claiming verification rules the
    // issuing corpus never declared (adaptor §14).
    let adaptor = active.pointer("/log/adaptor").cloned().ok_or_else(|| {
        CliError::EvidenceMissing(
            "the active manifest's `log` object pins no adaptor profile".to_owned(),
        )
    })?;

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
            let index = rotation.manifest_entry_index;
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
            let element = rotation_proofs.get(&index).ok_or_else(|| {
                CliError::EvidenceMissing(format!(
                    "the chain rotates the governance key set at entry {index} and no rotation \
                     proof was composed for it; `GET /v1/rotation-proofs/{index}` at the mirror \
                     and `GET /v1/logs/<log_id>/rotation-cosignatures/{index}` at each witness \
                     are what supply the element, and I-D §7.1 makes it material the receipt \
                     MUST carry"
                ))
            })?;
            // The rotation-proof checkpoint verifies under the OUTGOING key set, so only a
            // cosignature by a witness that version declared attests the handover. One by any
            // other witness is not wrong, it is simply not this evidence, and carrying it would
            // pad the element with material no rule reads.
            let declared = declared_witnesses(outgoing_manifest);
            let witnesses: Vec<Value> = element
                .get("witnesses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|cosigned| {
                    let witness_id =
                        cosigned.get("witness_id").and_then(Value::as_str).unwrap_or_default();
                    let key_id = cosigned.get("key_id").and_then(Value::as_str).unwrap_or_default();
                    declared.get(witness_id).is_some_and(|keys| keys.iter().any(|id| id == key_id))
                })
                .cloned()
                .collect();
            if witnesses.is_empty() {
                return Err(CliError::EvidenceMissing(format!(
                    "the rotation at entry {index} needs a cosignature from a witness the \
                     outgoing manifest version at entry {outgoing_index} declares, and none was \
                     obtained"
                )));
            }
            let mut element = element.clone();
            set(&mut element, "witnesses", json!(witnesses))?;
            proofs.push(element);
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

/// Keep only the cosignatures a manifest version's witness set accounts for.
///
/// A cosignature by a witness the governing version does not declare raises no assurance
/// (adaptor §11.1), so it is not carried in `anchoring.witnesses[]`. It is not the material a
/// rotation proof needs either: a rotation proof's cosignatures are over the ROTATION-ANCHORING
/// checkpoint, which the witness serves from its own rotation-cosignature route, and are not
/// whatever happened to arrive alongside this run's anchoring checkpoint.
#[must_use]
pub fn accounted_cosignatures(cosignatures: Vec<Value>, active: &Value) -> Vec<Value> {
    let declared = declared_witnesses(active);
    cosignatures
        .into_iter()
        .filter(|entry| {
            let witness_id = entry.get("witness_id").and_then(Value::as_str).unwrap_or_default();
            let key_id = entry.get("key_id").and_then(Value::as_str).unwrap_or_default();
            declared.get(witness_id).is_some_and(|keys| keys.iter().any(|id| id == key_id))
        })
        .collect()
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
    fn only_a_checkpoint_under_the_retired_log_key_anchors_a_log_key_rotation() {
        let outgoing = manifest("sha256:l1", "w1", "sha256:k1");
        let entries =
            vec![envelope(&outgoing), envelope(&manifest("sha256:l2", "w1", "sha256:k1"))];
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
        let rotation = rotations[0];
        let anchor =
            |tree_size: u64, key_id: &str| json!({ "tree_size": tree_size, "key_id": key_id });

        // The transition exception, both halves of it: past the rotating index, under the key
        // being retired.
        assert!(rotation.anchored_by(&anchor(2, "sha256:l1"), &outgoing));
        // The INCOMING key is exactly the key an attacker installs, so it anchors nothing.
        assert!(!rotation.anchored_by(&anchor(2, "sha256:l2"), &outgoing));
        // At or below the rotating index the outgoing state IS the active state, and §7.1 asks
        // for a tree size GREATER than it.
        assert!(!rotation.anchored_by(&anchor(1, "sha256:l1"), &outgoing));
        // Nothing is read out of a checkpoint that names neither.
        assert!(!rotation.anchored_by(&json!({ "tree_size": 2 }), &outgoing));
        assert!(!rotation.anchored_by(&json!({ "key_id": "sha256:l1" }), &outgoing));
    }

    #[test]
    fn key_objects_are_compared_as_sets_so_a_restatement_rotates_nothing() {
        // Two log keys, declared in the other order by the second version: I-D §7.1 compares
        // key OBJECTS, and the core's own comparison is a set, so this is not a rotation. A
        // producer that read the arrays positionally would carry an element the verifier then
        // refuses as one too many.
        let a = json!({ "key_id": "sha256:l1", "pubkey": "base64:a", "valid_from_index": 0 });
        let b = json!({ "key_id": "sha256:l2", "pubkey": "base64:b", "valid_from_index": 0 });
        let two_keys = |keys: Value| {
            json!({
                "type": "manifest",
                "log": { "keys": keys },
                "witnesses": [ { "witness_id": "w1", "keys": [
                    { "key_id": "sha256:k1", "pubkey": "base64:w", "valid_from_index": 0 },
                ] } ],
            })
        };
        let entries = vec![
            envelope(&two_keys(json!([a.clone(), b.clone()]))),
            envelope(&two_keys(json!([&b, &a]))),
        ];
        assert!(Governance::read(&entries).rotations(&[0, 1]).is_empty());

        // A different `valid_from_index` on the same key IS a difference of the key objects,
        // and the verifier reads it as a rotation, so this one does too.
        let mut moved = a.clone();
        moved["valid_from_index"] = json!(3);
        let entries =
            vec![envelope(&two_keys(json!([&a, &b]))), envelope(&two_keys(json!([moved, b])))];
        assert_eq!(Governance::read(&entries).rotations(&[0, 1]).len(), 1);
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
        let carried = accounted_cosignatures(cosignatures, &active);
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0]["witness_id"], json!("w2"));
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
        Assembly::new(checkpoint, Prefix { material: json!({}), entries }, Vec::new())
            .expect("the prefix recomputes the root")
    }

    /// A log that answers every `GET` with one fixed receipt.
    #[derive(Debug)]
    struct OneReceipt(Value);

    impl Fetcher for OneReceipt {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            Ok(Response { status: 200, body: serde_json::to_vec(&self.0).unwrap_or_default() })
        }
    }

    #[test]
    fn an_evidence_receipt_about_another_entry_is_refused() {
        let envelope = envelope(&json!({ "type": "ingestion", "record": "a" }));
        let entry = entry_id(&envelope);
        // Impeccable in every respect except the one that matters: it is somebody else's.
        let receipt = json!({
            "entry": {
                "id": "11111111-1111-4111-8111-111111111111",
                "payload_hash": entry,
                "metadata_hash": sha256_hex(&jcs(&atl_metadata())),
            },
            "proof": {
                "leaf_index": 0,
                "inclusion_path": [],
                "checkpoint": {
                    "origin": "sha256:00",
                    "tree_size": 1,
                    "root_hash": "sha256:00",
                    "timestamp": 1_786_881_600_123_456_789_u64,
                    "key_id": "sha256:00",
                    "signature": "base64:00",
                },
            },
        });
        let fetcher = OneReceipt(receipt);
        let error = retrieve(
            &fetcher,
            "https://log.example",
            "22222222-2222-4222-8222-222222222222",
            &entry,
        )
        .expect_err("a receipt about another entry is not evidence about this one");
        assert!(error.to_string().contains("is about entry"), "{error}");
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

    // ------------------------------------------------------------------
    // The scripted deployment: assembly against a log, mirror and witness
    // that answer from an in-memory tree rather than from a socket.
    // ------------------------------------------------------------------

    use crate::scripted;

    /// An assembly over a scripted deployment's own tree, with the cosignatures it obtained.
    fn assembly_over(stack: &scripted::Stack, cosignatures: Vec<Value>) -> Assembly {
        let size = stack.size();
        Assembly::new(
            stack.checkpoint(),
            Prefix {
                material: json!({ "range": { "from_index": 0, "to_index": size } }),
                entries: stack.entries.clone(),
            },
            cosignatures,
        )
        .expect("the enumerated prefix recomputes the root the checkpoint commits")
    }

    /// The default scripted assembly, carrying the one cosignature its witness issues.
    fn scripted_assembly() -> Assembly {
        let stack = scripted::Stack::new();
        assembly_over(&stack, vec![scripted::cosignature()])
    }

    /// `assemble` over a chain that rotates nothing, so no element is composed for it.
    fn assembled(assembly: &Assembly, subject_index: u64, claim: &Claim) -> CliResult<Value> {
        assemble(assembly, subject_index, claim, &BTreeMap::new())
    }

    /// The rotation proofs a scripted deployment serves for every rotation its corpus carries,
    /// composed exactly as `issue` composes them.
    fn scripted_rotation_proofs(stack: &scripted::Stack) -> CliResult<BTreeMap<u64, Value>> {
        let governance = Governance::read(&stack.entries);
        let mut proofs = BTreeMap::new();
        for rotation in governance.rotations(&governance.carried_indices(stack.size())) {
            let index = rotation.manifest_entry_index;
            let element = rotation_proof(stack, scripted::MIRROR, index)?;
            let served =
                rotation_cosignatures(stack, scripted::WITNESS, &scripted::log_id(), index)?;
            proofs.insert(index, compose_rotation_proof(index, &element, &[served])?);
        }
        Ok(proofs)
    }

    fn claim_of(claim_type: &str, record_subject: Option<(&str, &str)>) -> Claim {
        Claim {
            claim_type: claim_type.to_owned(),
            record_subject: record_subject
                .map(|(dataset, record)| (dataset.to_owned(), record.to_owned())),
            content: None,
            material: json!({}),
            note: "assembled by a scripted deployment".to_owned(),
        }
    }

    #[test]
    fn the_log_is_asked_twice_and_the_two_answers_must_place_the_entry_together() {
        let stack = scripted::Stack::new();
        let envelope = stack.envelope_at(scripted::APPENDED);
        let position = anchor(&stack, scripted::LOG, &envelope).expect("a scripted anchor");
        assert_eq!(position.entry_index, scripted::APPENDED);
        assert_eq!(position.atl_entry_id.as_deref(), Some(scripted::ATL_ENTRY_ID));
        assert_eq!(position.inclusion_path, stack.inclusion_path(scripted::APPENDED));
        assert_eq!(position.checkpoint.get("log_id"), Some(&json!(scripted::log_id())));
        // `raw` reassembles from the mapped object, which is the §6.4 framing.
        assert!(position.raw.starts_with("base64:"));

        let contradicting = scripted::Stack::new().with_disagreeing_index();
        let error = anchor(&contradicting, scripted::LOG, &envelope)
            .expect_err("a log that contradicts itself about where an entry landed");
        assert!(error.to_string().contains("when it accepted it"), "{error}");
    }

    #[test]
    fn a_submission_the_log_refuses_or_answers_unusably_is_reported_as_such() {
        let envelope = scripted::envelope(scripted::statement("ingestion", json!({})));
        let entry = entry_id(&envelope);

        let refused = scripted::Canned::raw(503, "unavailable");
        let error = submit(&refused, scripted::LOG, &envelope, &entry).expect_err("a refusal");
        assert!(error.to_string().contains("answered 503 to a submission"), "{error}");

        let garbage = scripted::Canned::raw(201, "not json");
        let error = submit(&garbage, scripted::LOG, &envelope, &entry).expect_err("not JSON");
        assert!(error.to_string().contains("did not answer JSON"), "{error}");

        let other_entry = scripted::Canned::json(
            201,
            &json!({ "entry": { "payload_hash": "sha256:00", "metadata_hash": "sha256:00" } }),
        );
        let error =
            submit(&other_entry, scripted::LOG, &envelope, &entry).expect_err("another entry");
        assert!(error.to_string().contains("names payload hash"), "{error}");

        let other_metadata = scripted::Canned::json(
            201,
            &json!({ "entry": { "payload_hash": entry, "metadata_hash": "sha256:00" } }),
        );
        let error = submit(&other_metadata, scripted::LOG, &envelope, &entry)
            .expect_err("metadata outside the profile");
        assert!(error.to_string().contains("recorded ATL metadata digest"), "{error}");

        let entry_block =
            json!({ "payload_hash": entry, "metadata_hash": scripted::metadata_hash() });
        let no_id = scripted::Canned::json(201, &json!({ "entry": entry_block }));
        let error = submit(&no_id, scripted::LOG, &envelope, &entry).expect_err("no `entry.id`");
        assert!(error.to_string().contains("carries no `entry.id`"), "{error}");

        let no_index = scripted::Canned::json(
            201,
            &json!({ "entry": { "id": "x", "payload_hash": entry,
                                "metadata_hash": scripted::metadata_hash() } }),
        );
        let error =
            submit(&no_index, scripted::LOG, &envelope, &entry).expect_err("no `leaf_index`");
        assert!(error.to_string().contains("carries no `leaf_index`"), "{error}");
    }

    /// An ATL Evidence Receipt about `entry`, with `proof` replaced by the caller's.
    fn atl_receipt_with(entry: &str, proof: &Value) -> Value {
        json!({
            "entry": {
                "id": scripted::ATL_ENTRY_ID,
                "payload_hash": entry,
                "metadata_hash": scripted::metadata_hash(),
            },
            "proof": proof,
        })
    }

    #[test]
    fn an_evidence_receipt_missing_what_a_position_is_made_of_is_refused() {
        let envelope = scripted::envelope(scripted::statement("ingestion", json!({})));
        let entry = entry_id(&envelope);
        let fetch = |receipt: Value| {
            retrieve(
                &scripted::Canned::json(200, &receipt),
                scripted::LOG,
                scripted::ATL_ENTRY_ID,
                &entry,
            )
        };

        let error = retrieve(
            &scripted::Canned::raw(404, "absent"),
            scripted::LOG,
            scripted::ATL_ENTRY_ID,
            &entry,
        )
        .expect_err("a 404");
        assert!(error.to_string().contains("answered 404 for the Evidence Receipt"), "{error}");

        let no_proof = json!({
            "entry": { "id": scripted::ATL_ENTRY_ID, "payload_hash": entry,
                       "metadata_hash": scripted::metadata_hash() },
        });
        let error = fetch(no_proof).expect_err("no proof");
        assert!(error.to_string().contains("carries no `proof`"), "{error}");

        let error = fetch(atl_receipt_with(&entry, &json!({}))).expect_err("no leaf index");
        assert!(error.to_string().contains("carries no `leaf_index`"), "{error}");

        let error = fetch(atl_receipt_with(&entry, &json!({ "leaf_index": 0 })))
            .expect_err("no checkpoint at all");
        assert!(error.to_string().contains("nanosecond `timestamp`"), "{error}");

        let error = fetch(atl_receipt_with(
            &entry,
            &json!({ "leaf_index": 0, "checkpoint": { "timestamp": 1_u64 } }),
        ))
        .expect_err("a checkpoint the §6.2 mapping cannot be built from");
        assert!(error.to_string().contains("carries no `origin`"), "{error}");
    }

    #[test]
    fn an_inclusion_path_outside_the_family_string_grammar_is_unusable() {
        let envelope = scripted::envelope(scripted::statement("ingestion", json!({})));
        let entry = entry_id(&envelope);
        let stack = scripted::Stack::new();
        let checkpoint = stack.atl_checkpoint(1);
        let fetch = |path: Value| {
            retrieve(
                &scripted::Canned::json(
                    200,
                    &atl_receipt_with(
                        &entry,
                        &json!({ "leaf_index": 0, "checkpoint": checkpoint,
                                 "inclusion_path": path }),
                    ),
                ),
                scripted::LOG,
                scripted::ATL_ENTRY_ID,
                &entry,
            )
        };

        let error = fetch(json!("not an array")).expect_err("not an array");
        assert!(error.to_string().contains("is not an array of family strings"), "{error}");
        let error = fetch(json!([7])).expect_err("not a string");
        assert!(error.to_string().contains("is not a string"), "{error}");
        let error = fetch(json!(["sha256:zz"])).expect_err("not a family string");
        assert!(error.to_string().contains("family string"), "{error}");
        // The grammar admits exactly this, and the position it describes comes back intact.
        let good = format!("sha256:{}", "11".repeat(32));
        let position = fetch(json!([good])).expect("a well-formed path");
        assert_eq!(position.inclusion_path, vec![good]);
    }

    #[test]
    fn retrieval_is_content_addressed_and_says_so_when_the_bytes_do_not_match() {
        let published = scripted::Stack::new().already_published();
        let entry = entry_id(&published.envelope_at(scripted::TRIGGER));
        assert_eq!(
            published_index(&published, scripted::MIRROR, &entry).expect("a published entry"),
            Some(scripted::TRIGGER)
        );
        // Absence is unavailability, never a negative result.
        let absent = scripted::Stack::new();
        assert_eq!(published_index(&absent, scripted::MIRROR, &entry).expect("a miss"), None);

        let broken = scripted::Canned::raw(500, "");
        let error = published_index(&broken, scripted::MIRROR, &entry).expect_err("a 500");
        assert!(error.to_string().contains("answered 500 for entry"), "{error}");

        let no_member = scripted::Canned::json(200, &json!({ "entry_index": 0 }));
        let error = published_index(&no_member, scripted::MIRROR, &entry).expect_err("no member");
        assert!(error.to_string().contains("served no `envelope` member"), "{error}");

        let unprefixed = scripted::Canned::json(200, &json!({ "envelope": "raw" }));
        let error = published_index(&unprefixed, scripted::MIRROR, &entry).expect_err("no prefix");
        assert!(error.to_string().contains("is not a `base64:` family string"), "{error}");

        let unusable = scripted::Canned::json(200, &json!({ "envelope": "base64:!!!" }));
        let error = published_index(&unusable, scripted::MIRROR, &entry).expect_err("bad base64");
        assert!(error.to_string().contains("is unusable"), "{error}");

        let substituted =
            scripted::Canned::json(200, &json!({ "envelope": "base64:c29tZXRoaW5nIGVsc2U=" }));
        let error =
            published_index(&substituted, scripted::MIRROR, &entry).expect_err("other bytes");
        assert!(error.to_string().contains("do not digest to it"), "{error}");
    }

    #[test]
    fn a_transport_failure_becomes_the_outcome_carrying_error_rather_than_a_verdict() {
        let error = published_index(&scripted::Unreachable, scripted::MIRROR, "sha256:00")
            .expect_err("nothing answered");
        assert!(error.to_string().contains("answers nothing"), "{error}");
    }

    #[test]
    fn staging_and_promotion_are_accepted_on_the_statuses_the_mirror_uses() {
        let stack = scripted::Stack::new();
        let envelope = stack.envelope_at(scripted::APPENDED);
        stage(&stack, scripted::MIRROR, &envelope).expect("the mirror accepts the bytes");
        stage(&scripted::Canned::json(200, &json!({})), scripted::MIRROR, &envelope)
            .expect("200 is an accepted stage too");
        let error =
            stage(&scripted::Canned::raw(422, "no"), scripted::MIRROR, &envelope).expect_err("422");
        assert!(error.to_string().contains("to a stage request"), "{error}");

        let position = anchor(&stack, scripted::LOG, &envelope).expect("a position");
        let entry = entry_id(&envelope);
        ingest_checkpoint(&stack, scripted::MIRROR, &position, &entry).expect("promotion");
        let error = ingest_checkpoint(
            &scripted::Canned::raw(409, "no"),
            scripted::MIRROR,
            &position,
            &entry,
        )
        .expect_err("409");
        assert!(error.to_string().contains("to a checkpoint ingest"), "{error}");
    }

    #[test]
    fn a_witness_refusal_comes_back_to_the_caller_rather_than_being_swallowed() {
        let stack = scripted::Stack::new();
        let envelope = stack.envelope_at(scripted::APPENDED);
        let position = anchor(&stack, scripted::LOG, &envelope).expect("a position");
        let answer =
            cosign(&stack, scripted::WITNESS, &scripted::log_id(), &position, &stack.entries, None)
                .expect("a cosignature");
        assert_eq!(answer.get("witness_id"), Some(&json!(scripted::WITNESS_ID)));

        let refusing = scripted::Stack::new().with_refusing_witness();
        let refusal = cosign(
            &refusing,
            scripted::WITNESS,
            &scripted::log_id(),
            &position,
            &refusing.entries,
            None,
        )
        .expect("a 409 is an answer, not a transport failure");
        assert_eq!(refusal.get("status"), Some(&json!("refused")));

        let error = cosign(
            &scripted::Canned::raw(500, "boom"),
            scripted::WITNESS,
            &scripted::log_id(),
            &position,
            &[],
            None,
        )
        .expect_err("a 500");
        assert!(error.to_string().contains("the witness answered 500"), "{error}");
    }

    #[test]
    fn the_newest_published_checkpoint_is_selected_by_size_and_stripped_of_server_labels() {
        let stack = scripted::Stack::new();
        let newest = newest_checkpoint(&stack, scripted::MIRROR).expect("a series");
        assert_eq!(newest.get("tree_size"), Some(&json!(stack.size())));
        assert!(newest.get("state").is_none(), "a server's view of its own member is not signed");

        let at_three = signed_checkpoint_at(&stack, scripted::MIRROR, 3).expect("a member");
        assert_eq!(at_three.get("tree_size"), Some(&json!(3)));

        let error = newest_checkpoint(&scripted::Canned::raw(500, ""), scripted::MIRROR)
            .expect_err("a 500");
        assert!(error.to_string().contains("for its checkpoint series"), "{error}");
        let error = newest_checkpoint(&scripted::Canned::json(200, &json!({})), scripted::MIRROR)
            .expect_err("not an array");
        assert!(error.to_string().contains("is not an array"), "{error}");
        let error = newest_checkpoint(&scripted::Canned::json(200, &json!([])), scripted::MIRROR)
            .expect_err("empty");
        assert!(error.to_string().contains("publishes no checkpoint"), "{error}");
        let error = signed_checkpoint_at(&scripted::Canned::raw(404, ""), scripted::MIRROR, 9)
            .expect_err("no member at that size");
        assert!(error.to_string().contains("for the checkpoint at tree size 9"), "{error}");
    }

    #[test]
    fn a_checkpoint_that_does_not_reassemble_into_the_binary_framing_is_refused() {
        let stack = scripted::Stack::new();
        checkpoint_raw(&stack.checkpoint()).expect("the mapped object reassembles");
        let error = checkpoint_raw(&json!({ "tree_size": 1 })).expect_err("nothing to frame");
        assert!(error.to_string().contains("does not reassemble"), "{error}");
    }

    #[test]
    fn an_enumeration_is_taken_only_where_it_is_the_range_that_was_asked_for() {
        let stack = scripted::Stack::new();
        let size = stack.size();
        let prefix = enumerate(&stack, scripted::MIRROR, size, size).expect("the whole prefix");
        assert_eq!(prefix.entries.len(), stack.entries.len());
        assert_eq!(prefix.material.pointer("/range/to_index"), Some(&json!(size)));

        let error = enumerate(&scripted::Canned::raw(500, "no"), scripted::MIRROR, 1, 1)
            .expect_err("a 500");
        assert!(error.to_string().contains("to a range request"), "{error}");
        let error = enumerate(&scripted::Canned::json(200, &json!({})), scripted::MIRROR, 1, 1)
            .expect_err("no entries");
        assert!(error.to_string().contains("carries no `entries` array"), "{error}");
        let out_of_order = scripted::Canned::json(
            200,
            &json!({ "entries": [ { "entry_index": 3, "envelope": {} } ] }),
        );
        let error =
            enumerate(&out_of_order, scripted::MIRROR, 1, 1).expect_err("indices out of order");
        assert!(error.to_string().contains("in order"), "{error}");
        let no_envelope =
            scripted::Canned::json(200, &json!({ "entries": [ { "entry_index": 0 } ] }));
        let error = enumerate(&no_envelope, scripted::MIRROR, 1, 1).expect_err("no envelope");
        assert!(error.to_string().contains("carries no `envelope`"), "{error}");
        // A response carrying none of the three enumeration members still yields a prefix; the
        // members are what the receipt would carry, and their absence is the verifier's finding.
        let bare = enumerate(
            &scripted::Canned::json(200, &json!({ "entries": [] })),
            scripted::MIRROR,
            0,
            0,
        )
        .expect("an empty prefix");
        assert_eq!(bare.material.get("range_proof"), Some(&Value::Null));
    }

    #[test]
    fn an_assembly_is_refused_where_the_prefix_is_not_the_tree_the_checkpoint_describes() {
        let stack = scripted::Stack::new();
        let prefix = || Prefix { material: json!({}), entries: stack.entries.clone() };
        // The assembly itself is never wanted here, only whether one was refused.
        let build = |checkpoint: Value| Assembly::new(checkpoint, prefix(), Vec::new()).map(|_| ());

        let error = build(json!({ "root_hash": "sha256:00" })).expect_err("no tree size");
        assert!(error.to_string().contains("carries no `tree_size`"), "{error}");
        let error = build(json!({ "tree_size": 99, "root_hash": "sha256:00" }))
            .expect_err("a size the enumeration does not cover");
        assert!(error.to_string().contains("the checkpoint commits 99"), "{error}");
        let error =
            build(json!({ "tree_size": stack.size() })).expect_err("nothing to compare against");
        assert!(error.to_string().contains("carries no `root_hash`"), "{error}");
        let error = build(json!({ "tree_size": stack.size(), "root_hash": "sha256:00" }))
            .expect_err("another tree");
        assert!(error.to_string().contains("a tree this material is not"), "{error}");
    }

    #[test]
    fn an_assembly_exposes_the_geometry_it_checked_and_refuses_what_is_outside_it() {
        let assembly = scripted_assembly();
        let stack = scripted::Stack::new();
        assert_eq!(assembly.size().expect("a size"), stack.size());
        assert_eq!(assembly.checkpoint().get("log_id"), Some(&json!(scripted::log_id())));
        assert_eq!(
            assembly.inclusion_path(scripted::TRIGGER).expect("a path"),
            stack.inclusion_path(scripted::TRIGGER)
        );
        assert!(assembly.leaf(0).is_some());
        assert!(assembly.leaf(99).is_none(), "a leaf outside the prefix is not invented");
        let error = assembly.inclusion_path(99).expect_err("outside the tree");
        assert!(error.to_string().contains("no inclusion path for entry 99"), "{error}");
        let error = assembly.entry(99).expect_err("outside the prefix");
        assert!(error.to_string().contains("does not reach entry 99"), "{error}");
    }

    #[test]
    fn governance_is_read_out_of_the_prefix_and_never_invented_where_it_is_absent() {
        let entries = vec![
            envelope(&manifest("sha256:l1", "w1", "sha256:k1")),
            envelope(&json!({
                "type": "key",
                "action": "add",
                "key": { "key_id": "sha256:p2", "pubkey": "base64:p2" },
            })),
            // Neither a key id nor a pubkey: nothing to bind, so nothing is bound.
            envelope(&json!({ "type": "key", "action": "add", "key": {} })),
            envelope(&json!({
                "type": "key",
                "action": "remove",
                "key": { "key_id": "sha256:p1", "pubkey": "base64:p1" },
            })),
            envelope(&json!({ "type": "ingestion" })),
        ];
        let governance = Governance::read(&entries);
        governance.manifest_at(0).expect("the genesis manifest");
        let error = governance.manifest_at(4).expect_err("no manifest there");
        assert!(error.to_string().contains("no manifest at entry 4"), "{error}");
        let error = governance.active_for_checkpoint(0).expect_err("nothing below size 0");
        assert!(error.to_string().contains("below tree size 0"), "{error}");
        assert_eq!(governance.active_for_checkpoint(5).expect("the genesis version").0, 0);
        // A removal at entry 3 is seen in enumerated mode and not in declared mode.
        let enumerated = governance.producer_keys_at(4, true).unwrap();
        assert_eq!(enumerated.keys().collect::<Vec<_>>(), vec!["sha256:p2"]);
        let declared = governance.producer_keys_at(4, false).unwrap();
        assert_eq!(declared.keys().collect::<Vec<_>>(), vec!["sha256:p1"]);
        // A transition anchored after the index asked about has not happened yet there.
        let earlier = governance.producer_keys_at(2, true).unwrap();
        assert_eq!(earlier.keys().collect::<Vec<_>>(), vec!["sha256:p1", "sha256:p2"]);
        // Index 0 has no manifest strictly below it, so the snapshot falls back to genesis.
        assert_eq!(governance.snapshot_at(0).expect("genesis").0, 0);

        let nothing = Governance::read(&[]);
        let error = nothing.snapshot_at(3).expect_err("no manifest at all");
        assert!(error.to_string().contains("carries no manifest"), "{error}");
    }

    #[test]
    fn a_manifest_key_object_missing_half_of_a_binding_binds_nothing() {
        let manifest = json!({
            "type": "manifest",
            "keys": [ { "key_id": "sha256:p1" } ],
            "log": { "keys": [ { "pubkey": "base64:l" } ] },
            "witnesses": [ { "keys": [ { "key_id": "sha256:k1", "pubkey": "base64:w" } ] } ],
        });
        let entries = vec![envelope(&manifest)];
        let governance = Governance::read(&entries);
        assert!(governance.producer_keys_at(0, false).unwrap().is_empty());
        let (log, witness) = manifest_key_entries(&manifest, 0);
        assert!(log.is_empty(), "a log key object with no id binds nothing");
        assert_eq!(witness.len(), 1);
        assert!(
            witness[0].get("witness_id").is_none(),
            "the key is listed; the identity it belongs to is the manifest's to state"
        );
        assert!(
            declared_witnesses(&manifest).is_empty(),
            "and an unnamed witness accounts for no cosignature"
        );
    }

    #[test]
    fn a_witness_answer_missing_a_member_is_not_folded_into_a_receipt_either() {
        let error = cosignature_entry(&json!({ "witness_id": "w1" }))
            .expect_err("an answer that carries no key id");
        assert!(error.to_string().contains("carries no `key_id`"), "{error}");
        let entry = cosignature_entry(&json!({
            "witness_id": "w1",
            "key_id": "sha256:k1",
            "cosignature": "base64:c",
            "cosigned_at": "2026-08-16T12:00:00Z",
        }))
        .expect("a complete answer");
        assert_eq!(entry.get("witness_id"), Some(&json!("w1")));
    }

    #[test]
    fn a_json_edit_on_something_that_is_not_an_object_is_an_internal_error_not_a_panic() {
        let mut scalar = json!(7);
        let error = set(&mut scalar, "member", json!(1)).expect_err("not an object");
        assert!(error.to_string().contains("a JSON object was expected"), "{error}");
        assert!(object_mut(&mut scalar).is_err());
    }

    #[test]
    fn every_registered_claim_type_declares_the_governance_mode_its_row_fixes() {
        for declared in
            ["record-ingested", "record-derived", "trigger-declared", "disposition-declared"]
        {
            let shape = claim_shape(declared).expect("a registered type");
            assert_eq!(shape.governance, "declared");
            assert!(shape.record_subject);
        }
        assert_eq!(claim_shape("statement-anchored").unwrap().governance, "declared");
        assert!(!claim_shape("statement-anchored").unwrap().record_subject);
        let effective = claim_shape("trigger-effective").unwrap();
        assert_eq!(effective.governance, "enumerated");
        assert_eq!(effective.competing_triggers, "enumerated");
        assert_eq!(claim_shape("disposition-effective").unwrap().competing_triggers, "not-checked");
        for setwide in ["propagation-complete", "governance-state"] {
            let shape = claim_shape(setwide).expect("a registered type");
            assert_eq!(shape.governance, "enumerated");
            assert!(!shape.record_subject, "these two narrow to no single record");
        }
    }

    #[test]
    fn a_declared_mode_receipt_carries_the_chain_and_no_enumeration_material() {
        let assembly = scripted_assembly();
        let receipt =
            assembled(&assembly, scripted::APPENDED, &claim_of("statement-anchored", None))
                .expect("a statement-anchored receipt");

        assert_eq!(receipt.get("ahl_receipt_version"), Some(&json!("2")));
        assert_eq!(receipt.get("spec_version"), Some(&json!("0.4.0")));
        assert_eq!(receipt.pointer("/claim/assurance/governance"), Some(&json!("declared")));
        assert_eq!(receipt.pointer("/claim/assurance/witnessed"), Some(&json!(true)));
        assert_eq!(receipt.pointer("/claim/assurance/content_binding"), Some(&json!("none")));
        assert!(
            receipt.pointer("/claim/assurance/canonicalization_namespace").is_none(),
            "the member is absent exactly where there is no content binding"
        );
        assert_eq!(receipt.pointer("/governance/currency/mode"), Some(&json!("declared")));
        assert_eq!(receipt.pointer("/governance/currency/material"), Some(&json!({})));
        assert!(
            receipt.pointer("/governance/rotation_proofs").is_none(),
            "the member is absent where the chain rotates nothing"
        );
        assert_eq!(receipt.pointer("/subject/entry_index"), Some(&json!(scripted::APPENDED)));
        assert_eq!(receipt.pointer("/subject/manifest"), Some(&json!(scripted::MANIFEST_VERSION)));
        assert_eq!(
            receipt.pointer("/anchoring/adaptor/id"),
            Some(&json!(crate::checkpoint::ATL_PROFILE)),
            "the pin is a governance fact, taken from the active manifest version"
        );
        assert_eq!(
            receipt.pointer("/anchoring/witnesses").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        assert_eq!(receipt.pointer("/keys/log/0/key_id"), Some(&json!(scripted::LOG_KEY)));
        assert_eq!(
            receipt.pointer("/keys/witness/0/witness_id"),
            Some(&json!(scripted::WITNESS_ID))
        );
        assert_eq!(
            receipt.pointer("/keys/producer/0/key_id"),
            Some(&json!(scripted::PRODUCER_KEY))
        );
        assert_eq!(receipt.pointer("/governance/chain/0/entry_index"), Some(&json!(0)));
    }

    #[test]
    fn an_enumerated_mode_receipt_carries_the_material_the_currency_mode_names() {
        let assembly = scripted_assembly();
        let receipt = assembled(&assembly, scripted::APPENDED, &claim_of("governance-state", None))
            .expect("a governance-state receipt");
        assert_eq!(receipt.pointer("/claim/assurance/governance"), Some(&json!("enumerated")));
        assert_eq!(
            receipt.pointer("/governance/currency/material/range/to_index"),
            Some(&json!(6))
        );

        let trigger = assembled(
            &assembly,
            scripted::TRIGGER,
            &claim_of("trigger-effective", Some((scripted::DATASET, scripted::RECORD))),
        )
        .expect("a trigger-effective receipt");
        assert_eq!(
            trigger.pointer("/claim/assurance/competing_triggers"),
            Some(&json!("enumerated"))
        );
        assert_eq!(trigger.pointer("/claim/record_subject/record"), Some(&json!(scripted::RECORD)));
    }

    #[test]
    fn the_subject_rule_of_the_registry_is_enforced_in_both_directions() {
        let assembly = scripted_assembly();
        let error = assembled(&assembly, scripted::INGESTION, &claim_of("record-ingested", None))
            .expect_err("a type that requires a record subject");
        assert!(error.to_string().contains("requires a record subject"), "{error}");

        let error = assembled(
            &assembly,
            scripted::APPENDED,
            &claim_of("statement-anchored", Some((scripted::DATASET, scripted::RECORD))),
        )
        .expect_err("a type that carries none");
        assert!(error.to_string().contains("carries no record subject"), "{error}");

        let error = assembled(&assembly, scripted::APPENDED, &claim_of("record-invented", None))
            .expect_err("not a registry id");
        assert!(error.to_string().contains("is not a claim type this build assembles"), "{error}");
    }

    #[test]
    fn content_binding_evidence_travels_with_the_descriptor_that_interprets_it() {
        let assembly = scripted_assembly();
        let with_content = |canonicalization: &str| Claim {
            content: Some(ContentBinding {
                bytes: b"{\"a\":1}".to_vec(),
                canonicalization: canonicalization.to_owned(),
                media_type: Some("application/json".to_owned()),
                binding: "plain-verified",
            }),
            ..claim_of("record-ingested", Some((scripted::DATASET, scripted::RECORD)))
        };

        let public =
            assembled(&assembly, scripted::INGESTION, &with_content("jcs")).expect("public");
        assert_eq!(
            public.pointer("/claim/assurance/content_binding"),
            Some(&json!("plain-verified"))
        );
        assert_eq!(
            public.pointer("/claim/assurance/canonicalization_namespace"),
            Some(&json!("public"))
        );
        assert_eq!(public.pointer("/claim_material/media_type"), Some(&json!("application/json")));
        assert_eq!(
            public.pointer("/claim_material/record_bytes"),
            Some(&json!("base64:eyJhIjoxfQ=="))
        );

        let private = assembled(&assembly, scripted::INGESTION, &with_content("x-house-style"))
            .expect("private use");
        assert_eq!(
            private.pointer("/claim/assurance/canonicalization_namespace"),
            Some(&json!("private-use"))
        );
    }

    #[test]
    fn a_manifest_subject_declares_no_manifest_version_and_every_other_subject_must() {
        let assembly = scripted_assembly();
        let receipt = assembled(&assembly, 0, &claim_of("statement-anchored", None))
            .expect("a manifest is anchorable like anything else");
        assert!(
            receipt.pointer("/subject/manifest").is_none(),
            "a manifest statement declares no manifest version"
        );

        let mut undeclared = scripted::corpus();
        undeclared.push(scripted::envelope(json!({ "type": "ingestion" })));
        let stack = scripted::Stack::over(undeclared, 6);
        let assembly = assembly_over(&stack, Vec::new());
        let error = assembled(&assembly, 6, &claim_of("statement-anchored", None))
            .expect_err("no manifest version declared");
        assert!(error.to_string().contains("declares no `manifest` version"), "{error}");
    }

    #[test]
    fn an_entry_that_is_not_an_envelope_cannot_be_a_subject() {
        let entries = vec![scripted::genesis(), json!({ "payload": "not an object" })];
        let stack = scripted::Stack::over(entries, 1);
        let assembly = assembly_over(&stack, Vec::new());
        let error = assembled(&assembly, 1, &claim_of("statement-anchored", None))
            .expect_err("not an envelope");
        assert!(error.to_string().contains("is not an envelope"), "{error}");
    }

    #[test]
    fn a_manifest_version_pinning_no_adaptor_profile_assembles_nothing() {
        let mut without_pin =
            scripted::manifest(scripted::WITNESS_ID, scripted::WITNESS_KEY, scripted::LOG_KEY);
        if let Some(log) = without_pin.get_mut("log").and_then(Value::as_object_mut) {
            log.remove("adaptor");
        }
        let entries = vec![
            scripted::envelope(without_pin),
            scripted::envelope(scripted::statement("ingestion", json!({}))),
        ];
        let stack = scripted::Stack::over(entries, 1);
        let assembly = assembly_over(&stack, Vec::new());
        let error = assembled(&assembly, 1, &claim_of("statement-anchored", None))
            .expect_err("no adaptor pin");
        assert!(error.to_string().contains("pins no adaptor profile"), "{error}");
    }

    /// A corpus whose second manifest version rotates the named key set.
    fn rotating_corpus(log_key: &str, witness_id: &str, witness_key: &str) -> Vec<Value> {
        vec![
            scripted::genesis(),
            scripted::envelope(scripted::statement("ingestion", json!({}))),
            scripted::envelope(scripted::manifest(witness_id, witness_key, log_key)),
            scripted::envelope(scripted::statement("ingestion", json!({}))),
        ]
    }

    #[test]
    fn a_witness_set_rotation_carries_the_element_the_two_interfaces_serve() {
        let entries =
            rotating_corpus(scripted::LOG_KEY, scripted::WITNESS_ID_2, scripted::WITNESS_KEY_2);
        let stack = scripted::Stack::over(entries, 3);
        let proofs = scripted_rotation_proofs(&stack).expect("both halves are served");
        assert_eq!(proofs.keys().copied().collect::<Vec<_>>(), vec![2]);

        // The cosignature this run's own anchoring checkpoint carries is the INCOMING witness's
        // and belongs in `anchoring.witnesses[]`; the rotation proof's comes from the witness's
        // rotation-cosignature route and is the OUTGOING witness's.
        let incoming = json!({
            "witness_id": scripted::WITNESS_ID_2,
            "key_id": scripted::WITNESS_KEY_2,
            "cosignature": "base64:aW4=",
            "cosigned_at": scripted::TIME,
        });
        let assembly = assembly_over(&stack, vec![incoming]);
        let receipt = assemble(&assembly, 3, &claim_of("statement-anchored", None), &proofs)
            .expect("a rotation both interfaces serve");
        let carried = receipt
            .pointer("/governance/rotation_proofs")
            .and_then(Value::as_array)
            .expect("one element per rotation");
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].get("manifest_entry_index"), Some(&json!(2)));
        assert_eq!(
            carried[0].pointer("/witnesses/0/witness_id"),
            Some(&json!(scripted::WITNESS_ID)),
            "the proof's checkpoint verifies under the outgoing key set"
        );
        // The element's checkpoint is the ROTATION anchor the mirror serves, not the receipt's
        // own anchoring checkpoint over the whole tree.
        assert_eq!(carried[0].pointer("/checkpoint/tree_size"), Some(&json!(3)));
        assert_eq!(receipt.pointer("/anchoring/checkpoint/tree_size"), Some(&json!(4)));
        // Both versions' witness keys are listed, each bound to the version that declared it.
        let witness_keys = receipt.pointer("/keys/witness").and_then(Value::as_array).unwrap();
        assert_eq!(witness_keys.len(), 2);
        assert_eq!(witness_keys[1].pointer("/binding/entry_index"), Some(&json!(0)));
    }

    #[test]
    fn a_log_key_rotation_carries_a_proof_under_the_retired_key() {
        let rotated_log_key =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let entries = rotating_corpus(rotated_log_key, scripted::WITNESS_ID, scripted::WITNESS_KEY);
        let stack = scripted::Stack::over(entries, 3);
        let proofs = scripted_rotation_proofs(&stack).expect("both halves are served");
        let assembly = assembly_over(&stack, vec![scripted::cosignature()]);
        let receipt = assemble(&assembly, 3, &claim_of("statement-anchored", None), &proofs)
            .expect("the mirror serves the anchor a retired log key signed");
        let carried = receipt
            .pointer("/governance/rotation_proofs")
            .and_then(Value::as_array)
            .expect("one element per rotation");
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].get("manifest_entry_index"), Some(&json!(2)));
        assert_eq!(
            carried[0].pointer("/checkpoint/key_id"),
            Some(&json!(scripted::LOG_KEY)),
            "a checkpoint signed by the INCOMING key does not attest the transition"
        );
        // Both log keys are listed, the retired one bound to the version it was drawn from.
        let log_keys = receipt.pointer("/keys/log").and_then(Value::as_array).unwrap();
        assert_eq!(log_keys.len(), 2);
        assert_eq!(log_keys[0].get("key_id"), Some(&json!(rotated_log_key)));
        assert_eq!(log_keys[1].get("key_id"), Some(&json!(scripted::LOG_KEY)));
        assert_eq!(log_keys[1].pointer("/binding/entry_index"), Some(&json!(0)));
    }

    #[test]
    fn adjacent_rotations_carry_one_element_each_in_ascending_order() {
        let third_witness = "witness-3";
        let third_key = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let entries = vec![
            scripted::genesis(),
            scripted::envelope(scripted::manifest(
                scripted::WITNESS_ID_2,
                scripted::WITNESS_KEY_2,
                scripted::LOG_KEY,
            )),
            scripted::envelope(scripted::manifest(third_witness, third_key, scripted::LOG_KEY)),
            scripted::envelope(scripted::statement("ingestion", json!({}))),
        ];
        let stack = scripted::Stack::over(entries, 3);
        let proofs = scripted_rotation_proofs(&stack).expect("both halves are served for each");
        assert_eq!(proofs.keys().copied().collect::<Vec<_>>(), vec![1, 2]);

        let cosignature = json!({
            "witness_id": third_witness,
            "key_id": third_key,
            "cosignature": "base64:aW4=",
            "cosigned_at": scripted::TIME,
        });
        let assembly = assembly_over(&stack, vec![cosignature]);
        let receipt = assemble(&assembly, 3, &claim_of("statement-anchored", None), &proofs)
            .expect("two rotations, two elements");
        let carried = receipt
            .pointer("/governance/rotation_proofs")
            .and_then(Value::as_array)
            .expect("one element per rotation");
        assert_eq!(carried.len(), 2);
        assert_eq!(carried[0].get("manifest_entry_index"), Some(&json!(1)));
        assert_eq!(carried[1].get("manifest_entry_index"), Some(&json!(2)));
        // Each element is cosigned by the witness the version PRECEDING it declared, so the
        // second rotation's proof is not signed by the identity the first one installed's
        // successor but by that identity itself.
        assert_eq!(
            carried[0].pointer("/witnesses/0/witness_id"),
            Some(&json!(scripted::WITNESS_ID))
        );
        assert_eq!(
            carried[1].pointer("/witnesses/0/witness_id"),
            Some(&json!(scripted::WITNESS_ID_2))
        );
        // Three versions' witness keys, each bound to the version that declared it.
        let witness_keys = receipt.pointer("/keys/witness").and_then(Value::as_array).unwrap();
        assert_eq!(witness_keys.len(), 3);
    }

    #[test]
    fn a_rotation_with_no_served_anchor_is_refused_rather_than_assembled_without_the_proof() {
        let entries =
            rotating_corpus(scripted::LOG_KEY, scripted::WITNESS_ID_2, scripted::WITNESS_KEY_2);
        let stack = scripted::Stack::over(entries, 3).without_anchor_for(2);
        let error = scripted_rotation_proofs(&stack).expect_err("no anchor is served for it");
        let text = error.to_string();
        assert!(text.contains("entry 2"), "{text}");
        assert!(text.contains("GET /v1/rotation-proofs/2"), "{text}");

        // And assembly itself refuses rather than emitting a receipt without the element.
        let assembly = assembly_over(&stack, vec![scripted::cosignature()]);
        let error = assemble(&assembly, 3, &claim_of("statement-anchored", None), &BTreeMap::new())
            .expect_err("the element is material the receipt MUST carry");
        assert!(error.to_string().contains("no rotation proof was composed"), "{error}");
    }

    #[test]
    fn halves_over_different_checkpoints_are_not_joined_into_something_that_looks_whole() {
        let entries =
            rotating_corpus(scripted::LOG_KEY, scripted::WITNESS_ID_2, scripted::WITNESS_KEY_2);
        let stack = scripted::Stack::over(entries, 3).with_rotation_checkpoint_mismatch();
        let error = scripted_rotation_proofs(&stack)
            .expect_err("the cosignatures are over another checkpoint");
        assert!(error.to_string().contains("different rotation-anchoring checkpoints"), "{error}");
    }

    #[test]
    fn a_composed_element_carries_the_four_members_the_published_vector_carries() {
        // The oracle is the corpus, not this crate's own idea of the shape: I-D §7.1 closes the
        // element to four members and `ahl-core` rejects a fifth, so the element assembled here
        // is compared with the one the published log-key-rotation vector carries.
        let vector = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ahl-core/test_data/receipts/statement-anchored-log-key-rotation.ahl");
        let bytes = std::fs::read(&vector).expect("the published rotation vector");
        let published: Value = serde_json::from_slice(&bytes).expect("a JSON receipt");
        let published = published
            .pointer("/governance/rotation_proofs/0")
            .and_then(Value::as_object)
            .expect("the vector carries a rotation proof");

        let entries =
            rotating_corpus(scripted::LOG_KEY, scripted::WITNESS_ID_2, scripted::WITNESS_KEY_2);
        let stack = scripted::Stack::over(entries, 3);
        let proofs = scripted_rotation_proofs(&stack).expect("both halves are served");
        let composed = proofs.get(&2).and_then(Value::as_object).expect("one element");

        assert_eq!(
            composed.keys().collect::<Vec<_>>(),
            published.keys().collect::<Vec<_>>(),
            "the element's member set is the vector's"
        );
        for member in ["checkpoint", "witnesses"] {
            let ours = composed.get(member).expect("a member");
            let theirs = published.get(member).expect("a member");
            assert_eq!(
                ours.as_object().map(|object| object.keys().collect::<Vec<_>>()),
                theirs.as_object().map(|object| object.keys().collect::<Vec<_>>()),
                "`{member}` carries the vector's members"
            );
            assert_eq!(
                ours.as_array().map(Vec::len).map(|_| ()),
                theirs.as_array().map(Vec::len).map(|_| ()),
                "`{member}` is the same kind of value"
            );
        }
        let cosignature = composed.get("witnesses").and_then(|value| value.get(0));
        let their_cosignature = published.get("witnesses").and_then(|value| value.get(0));
        assert_eq!(
            cosignature.and_then(Value::as_object).map(|object| object.keys().collect::<Vec<_>>()),
            their_cosignature
                .and_then(Value::as_object)
                .map(|object| object.keys().collect::<Vec<_>>()),
            "a cosignature carries the four members `anchoring.witnesses[]` carries"
        );
    }

    #[test]
    fn a_cosignature_is_kept_only_where_the_governing_version_declares_it() {
        let active =
            scripted::manifest(scripted::WITNESS_ID_2, scripted::WITNESS_KEY_2, scripted::LOG_KEY);
        let incoming = json!({
            "witness_id": scripted::WITNESS_ID_2,
            "key_id": scripted::WITNESS_KEY_2,
        });
        let carried = accounted_cosignatures(vec![scripted::cosignature(), incoming], &active);
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].get("witness_id"), Some(&json!(scripted::WITNESS_ID_2)));
    }

    #[test]
    fn a_batch_derivation_opens_its_output_leaf_and_every_listed_input() {
        let trees = scripted::tree_material();
        let subject =
            scripted::statement("derivation", json!({ "outputs_root": scripted::OUTPUTS_ROOT }));
        let material =
            leaf_material("record-derived", &subject, &trees, scripted::RECORD, scripted::DATASET)
                .expect("the batch tree the subject commits");
        assert_eq!(material.pointer("/output/record"), Some(&json!(scripted::RECORD)));
        assert_eq!(material.get("leaf_index"), Some(&json!(1)));
        assert!(material.get("leaf_path").and_then(Value::as_array).is_some());
        let members = material.get("input_members").and_then(Value::as_array).expect("the inputs");
        assert_eq!(members.len(), 2, "§7.2 proves the listed inputs and no others");
        assert_eq!(members[1].get("input_index"), Some(&json!(1)));

        // A leaf carrying no wide-input form opens no input-set tree.
        let narrow = leaf_material(
            "record-derived",
            &subject,
            &trees,
            scripted::RECORD_2,
            scripted::DATASET,
        )
        .expect("a leaf without inputs");
        assert!(narrow.get("input_members").is_none());
    }

    #[test]
    fn an_unbatched_derivation_commits_its_output_inline_and_opens_no_tree() {
        let material = leaf_material(
            "record-derived",
            &scripted::statement("derivation", json!({})),
            &json!({}),
            scripted::RECORD,
            scripted::DATASET,
        )
        .expect("no tree to open");
        assert_eq!(
            material,
            json!({ "output": { "dataset": scripted::DATASET, "record": scripted::RECORD } })
        );
    }

    #[test]
    fn a_disposition_opens_the_propagation_s_affected_tree_and_says_so_when_it_cannot() {
        let trees = scripted::tree_material();
        let subject =
            scripted::statement("propagation", json!({ "affected_root": scripted::AFFECTED_ROOT }));
        for claim_type in ["disposition-declared", "disposition-effective"] {
            let material =
                leaf_material(claim_type, &subject, &trees, scripted::RECORD, scripted::DATASET)
                    .expect("the affected tree");
            assert_eq!(material.get("leaf_index"), Some(&json!(0)));
            assert!(material.get("disposition_leaf").is_some());
        }

        let error = leaf_material(
            "disposition-declared",
            &scripted::statement("propagation", json!({})),
            &trees,
            scripted::RECORD,
            scripted::DATASET,
        )
        .expect_err("nothing to open");
        assert!(error.to_string().contains("commits no affected tree"), "{error}");

        let error = leaf_material(
            "disposition-declared",
            &subject,
            &json!({}),
            scripted::RECORD,
            scripted::DATASET,
        )
        .expect_err("material the producer did not supply");
        assert!(error.to_string().contains("holds no leaves for root"), "{error}");

        let error =
            leaf_material("disposition-declared", &subject, &trees, "sha256:ff", scripted::DATASET)
                .expect_err("no leaf names that record");
        assert!(error.to_string().contains("no committed leaf names record"), "{error}");

        // A claim type with no leaf-bearing material asks the trees for nothing.
        assert_eq!(
            leaf_material(
                "statement-anchored",
                &subject,
                &trees,
                scripted::RECORD,
                scripted::DATASET
            )
            .expect("nothing to open"),
            json!({})
        );
    }
}
