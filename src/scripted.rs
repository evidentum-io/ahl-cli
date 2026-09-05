//! A scripted log, mirror and witness over one in-memory tree.
//!
//! [`crate::producer`] and [`crate::commands::issue`] are the half of the client that talks to a
//! live deployment, and the end-to-end harness that drives them needs `atl-server`,
//! `ahl-mirror` and `ahl-witness` running. This module answers the same routes from committed
//! constants instead, so the assembly paths are exercised without a socket and without a clock.
//!
//! **Test material only, and deliberately unsigned.** Assembly verifies no signature — that is
//! `verify`'s job, and the division is the point of having both — so the key ids and signature
//! strings here are labels. A fixture that signed them would be testing the wrong module, and a
//! test that needed a real signature would belong to `verify`.

use ahl_core::{
    atl_checkpoint_time, entry_id, hash_hex, inclusion_proof, jcs, log_leaf_bytes_for,
    proof_path_hex, sha256_hex, tree_root,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::checkpoint::ATL_PROFILE;
use crate::net::{FetchFailure, Fetcher, Method, Request, Response};
use crate::producer::{Governance, Rotation};

/// Base URL the scripted log answers on.
pub const LOG: &str = "https://log.example";
/// Base URL the scripted mirror answers on.
pub const MIRROR: &str = "https://mirror.example";
/// Base URL the scripted witness answers on.
pub const WITNESS: &str = "https://witness.example";

/// The ATL identifier the scripted log assigns to every submission.
pub const ATL_ENTRY_ID: &str = "11111111-1111-4111-8111-111111111111";
/// The nanosecond stamp every scripted checkpoint carries.
pub const TIMESTAMP_NS: u64 = 1_786_881_600_123_456_789;
/// A fixed domain time, so nothing here reads a clock.
pub const TIME: &str = "2026-08-16T12:00:00Z";

/// The witness the genesis manifest declares.
pub const WITNESS_ID: &str = "witness-1";
/// Its key id.
pub const WITNESS_KEY: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
/// The witness a second manifest version rotates in.
pub const WITNESS_ID_2: &str = "witness-2";
/// Its key id.
pub const WITNESS_KEY_2: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
/// The log's checkpoint-signing key id.
pub const LOG_KEY: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
/// The producer key the genesis manifest declares.
pub const PRODUCER_KEY: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";
/// The adaptor-profile document digest the manifests pin.
pub const ADAPTOR_HASH: &str =
    "sha256:6666666666666666666666666666666666666666666666666666666666666666";
/// The manifest version every statement declares.
pub const MANIFEST_VERSION: &str =
    "sha256:7777777777777777777777777777777777777777777777777777777777777777";
/// The batch output tree a derivation commits.
pub const OUTPUTS_ROOT: &str =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";
/// The input-set tree that batch's leaf commits.
pub const INPUT_SET_ROOT: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
/// The affected tree a propagation commits.
pub const AFFECTED_ROOT: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The dataset every scripted statement is about.
pub const DATASET: &str = "customers";
/// The record the subject statements name.
pub const RECORD: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000a1";
/// A second record, so a claim can be about one that is not the first leaf.
pub const RECORD_2: &str =
    "sha256:00000000000000000000000000000000000000000000000000000000000000a2";

/// Entry index of the ingestion the default subject is.
pub const INGESTION: u64 = 1;
/// Entry index of the derivation.
pub const DERIVATION: u64 = 2;
/// Entry index of the trigger.
pub const TRIGGER: u64 = 3;
/// Entry index of the propagation.
pub const PROPAGATION: u64 = 4;
/// Entry index of the entry a fresh run anchors.
pub const APPENDED: u64 = 5;

/// The AHL `log_id` the scripted deployment is bound to.
#[must_use]
pub fn log_id() -> String {
    sha256_hex(b"scripted-log")
}

/// The fixed ATL metadata digest of adaptor §4.2, recomputed here rather than imported.
#[must_use]
pub fn metadata_hash() -> String {
    sha256_hex(&jcs(&json!({ "ahl_adaptor": ATL_PROFILE })))
}

/// A `base64:` family string.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Wrap a payload in the envelope shape the log anchors.
#[must_use]
pub fn envelope(payload: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("payload".to_owned(), payload);
    map.insert("signatures".to_owned(), json!([]));
    Value::Object(map)
}

/// A statement payload carrying the common members of I-D §2.2.
#[must_use]
pub fn statement(kind: &str, extra: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("ahl_version".to_owned(), json!("0.4"));
    map.insert("type".to_owned(), json!(kind));
    map.insert("producer".to_owned(), json!("producer-1"));
    map.insert("manifest".to_owned(), json!(MANIFEST_VERSION));
    map.insert("valid_time".to_owned(), json!(TIME));
    map.insert("issued_at".to_owned(), json!(TIME));
    if let Value::Object(extra) = extra {
        map.extend(extra);
    }
    Value::Object(map)
}

/// A manifest payload declaring one log key and one witness.
#[must_use]
pub fn manifest(witness_id: &str, witness_key: &str, log_key: &str) -> Value {
    json!({
        "ahl_version": "0.4",
        "type": "manifest",
        "producer": "producer-1",
        "valid_time": TIME,
        "issued_at": TIME,
        "level": "L3",
        "keys": [ { "key_id": PRODUCER_KEY, "pubkey": "base64:cHJvZHVjZXItMQ==" } ],
        "log": {
            "log_id": log_id(),
            "operator": "scripted-operator",
            "adaptor": { "id": ATL_PROFILE, "hash": ADAPTOR_HASH },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": TIME,
            "witness_grace_period": "PT15M",
            "keys": [ { "key_id": log_key, "pubkey": "base64:bG9n", "valid_from_index": 0 } ],
        },
        "witnesses": [ {
            "witness_id": witness_id,
            "keys": [ { "key_id": witness_key, "pubkey": "base64:d2l0", "valid_from_index": 0 } ],
        } ],
    })
}

/// The genesis manifest of the scripted corpus.
#[must_use]
pub fn genesis() -> Value {
    envelope(manifest(WITNESS_ID, WITNESS_KEY, LOG_KEY))
}

/// The corpus the scripted mirror enumerates: one manifest version and one statement of every
/// shape the claim-type registry needs a subject for.
#[must_use]
pub fn corpus() -> Vec<Value> {
    vec![
        genesis(),
        envelope(statement("ingestion", json!({ "dataset": DATASET, "record": RECORD }))),
        envelope(statement(
            "derivation",
            json!({
                "dataset": DATASET,
                "record": RECORD,
                "pipeline": "scripted-pipeline-v1",
                "outputs_root": OUTPUTS_ROOT,
            }),
        )),
        envelope(statement(
            "trigger",
            json!({ "dataset": DATASET, "record": RECORD, "action": "erasure" }),
        )),
        envelope(statement(
            "propagation",
            json!({
                "affected_root": AFFECTED_ROOT,
                "corpus_checkpoint": { "tree_size": 3 },
            }),
        )),
        envelope(statement("ingestion", json!({ "dataset": DATASET, "record": RECORD_2 }))),
    ]
}

/// The committed tree material the producer holds for the scripted corpus.
#[must_use]
pub fn tree_material() -> Value {
    json!({
        OUTPUTS_ROOT: { "leaves": [
            { "record": RECORD_2, "dataset": DATASET },
            { "record": RECORD, "dataset": DATASET, "inputs": { "input_set_root": INPUT_SET_ROOT } },
        ] },
        INPUT_SET_ROOT: { "leaves": [
            { "record": RECORD, "dataset": DATASET },
            { "record": RECORD_2, "dataset": DATASET },
        ] },
        AFFECTED_ROOT: { "leaves": [
            { "record": RECORD, "dataset": DATASET, "disposition": "erased" },
        ] },
    })
}

/// The cosigned answer the scripted witness returns.
#[must_use]
pub fn cosignature() -> Value {
    json!({
        "witness_id": WITNESS_ID,
        "key_id": WITNESS_KEY,
        "cosignature": "base64:Y29zaWduYXR1cmU=",
        "cosigned_at": TIME,
    })
}

/// A way the scripted log is set to contradict itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discrepancy {
    /// None: every answer agrees with every other.
    None,
    /// The log serves an inclusion path the enumerated prefix does not recompute to.
    CrookedPath,
    /// The log names one index when it accepts the entry and another when asked afterwards.
    MovedIndex,
}

/// A deterministic log, mirror and witness over one in-memory tree.
#[derive(Debug)]
pub struct Stack {
    /// The entries, in index order; the position in this vector IS the entry index.
    pub entries: Vec<Value>,
    /// The entry a run is about.
    pub subject_index: u64,
    /// Whether the mirror already holds the subject, so no submission is made.
    pub published: bool,
    /// Answer every cosignature request with a refusal.
    pub refusing_witness: bool,
    /// Rotations neither the mirror nor the witness serves an anchor for, so a receipt that
    /// needs one is refused rather than assembled without it.
    pub unanchored: Vec<u64>,
    /// The witness serves its rotation cosignatures over a checkpoint other than the one the
    /// mirror's element carries, so the two halves do not pair.
    pub rotation_mismatch: bool,
    /// What the log is set to contradict itself about.
    pub discrepancy: Discrepancy,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// The default deployment: the scripted corpus, about the entry a fresh run anchors.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: corpus(),
            subject_index: APPENDED,
            published: false,
            refusing_witness: false,
            unanchored: Vec::new(),
            rotation_mismatch: false,
            discrepancy: Discrepancy::None,
        }
    }

    /// The same deployment, about another entry.
    #[must_use]
    pub const fn about(mut self, index: u64) -> Self {
        self.subject_index = index;
        self
    }

    /// The log serves an inclusion path the enumeration does not recompute to.
    #[must_use]
    pub const fn with_crooked_path(mut self) -> Self {
        self.discrepancy = Discrepancy::CrookedPath;
        self
    }

    /// The mirror already holds every entry, so a run finds the subject anchored.
    #[must_use]
    pub const fn already_published(mut self) -> Self {
        self.published = true;
        self
    }

    /// The witness refuses to cosign.
    #[must_use]
    pub const fn with_refusing_witness(mut self) -> Self {
        self.refusing_witness = true;
        self
    }

    /// The log places the entry at one index when it accepts it and at another afterwards.
    #[must_use]
    pub const fn with_disagreeing_index(mut self) -> Self {
        self.discrepancy = Discrepancy::MovedIndex;
        self
    }

    /// Neither server holds a rotation-anchoring checkpoint for the rotation at `index`.
    #[must_use]
    pub fn without_anchor_for(mut self, index: u64) -> Self {
        self.unanchored.push(index);
        self
    }

    /// The witness cosigns a different checkpoint from the one the mirror's element carries.
    #[must_use]
    pub const fn with_rotation_checkpoint_mismatch(mut self) -> Self {
        self.rotation_mismatch = true;
        self
    }

    /// A deployment over a caller-supplied corpus.
    #[must_use]
    pub fn over(entries: Vec<Value>, subject_index: u64) -> Self {
        Self { entries, subject_index, ..Self::new() }
    }

    /// The tree size the log commits.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.entries.len()).unwrap_or(u64::MAX)
    }

    /// The canonical bytes of the entry at `index` — what a producer holds in a file.
    #[must_use]
    pub fn entry_bytes(&self, index: u64) -> Vec<u8> {
        jcs(&self.envelope_at(index))
    }

    /// The entry at `index`, as the mirror serves it.
    #[must_use]
    pub fn envelope_at(&self, index: u64) -> Value {
        usize::try_from(index)
            .ok()
            .and_then(|at| self.entries.get(at))
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn leaf_bytes(&self, upto: u64) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .take(usize::try_from(upto).unwrap_or(usize::MAX))
            .map(|envelope| log_leaf_bytes_for(envelope, ATL_PROFILE).expect("a scripted envelope"))
            .collect()
    }

    fn root_at(&self, tree_size: u64) -> String {
        hash_hex(&tree_root(&self.leaf_bytes(tree_size)))
    }

    /// The inclusion path of `index` under the full tree, as the log serves it.
    #[must_use]
    pub fn inclusion_path(&self, index: u64) -> Vec<String> {
        let at = usize::try_from(index).unwrap_or(usize::MAX);
        let proof =
            inclusion_proof(&self.leaf_bytes(self.size()), at).expect("an index inside the tree");
        proof_path_hex(&proof)
    }

    /// The AHL checkpoint object of adaptor §6.2 at `tree_size`, as the mirror publishes it.
    #[must_use]
    pub fn checkpoint_at(&self, tree_size: u64) -> Value {
        json!({
            "log_id": log_id(),
            "tree_size": tree_size,
            "root_hash": self.root_at(tree_size),
            "checkpoint_time": atl_checkpoint_time(TIMESTAMP_NS),
            "key_id": LOG_KEY,
            "signature": "base64:c2lnbmF0dXJl",
        })
    }

    /// The checkpoint over the whole tree.
    #[must_use]
    pub fn checkpoint(&self) -> Value {
        self.checkpoint_at(self.size())
    }

    /// The same checkpoint in the ATL form the log's own Evidence Receipt carries.
    #[must_use]
    pub fn atl_checkpoint(&self, tree_size: u64) -> Value {
        json!({
            "origin": log_id(),
            "tree_size": tree_size,
            "root_hash": self.root_at(tree_size),
            "timestamp": TIMESTAMP_NS,
            "key_id": LOG_KEY,
            "signature": "base64:c2lnbmF0dXJl",
        })
    }

    /// The ATL Evidence Receipt the log answers with, for the subject entry.
    #[must_use]
    pub fn atl_receipt(&self, leaf_index: u64) -> Value {
        let path = if self.discrepancy == Discrepancy::CrookedPath {
            vec![format!("sha256:{}", "ab".repeat(32))]
        } else {
            self.inclusion_path(self.subject_index)
        };
        json!({
            "entry": {
                "id": ATL_ENTRY_ID,
                "payload_hash": entry_id(&self.envelope_at(self.subject_index)),
                "metadata_hash": metadata_hash(),
            },
            "proof": {
                "leaf_index": leaf_index,
                "inclusion_path": path,
                "checkpoint": self.atl_checkpoint(self.size()),
            },
        })
    }

    fn entry_answer(&self, wanted: &str) -> Response {
        if !self.published {
            return not_found();
        }
        for (position, envelope) in self.entries.iter().enumerate() {
            let bytes = jcs(envelope);
            if sha256_hex(&bytes) == wanted {
                return ok(&json!({ "entry_index": position, "envelope": base64(&bytes) }));
            }
        }
        not_found()
    }

    fn series(&self) -> Vec<Value> {
        // Two members, out of size order and each carrying the mirror's own view of its state,
        // so selecting the newest is a comparison rather than a read of the last element and
        // the server annotation is something `strip_state` has to remove.
        let mut newest = self.checkpoint();
        let mut older = self.checkpoint_at(self.size().saturating_sub(2));
        for member in [&mut newest, &mut older] {
            if let Some(object) = member.as_object_mut() {
                object.insert("state".to_owned(), json!("published"));
            }
        }
        vec![older, newest]
    }

    fn range_answer(&self, request: &Request) -> Response {
        let Some(body) =
            request.body.as_ref().and_then(|body| serde_json::from_slice::<Value>(body).ok())
        else {
            return bad_request();
        };
        let (Some(tree_size), Some(from), Some(to)) = (
            body.get("tree_size").and_then(Value::as_u64),
            body.get("from_index").and_then(Value::as_u64),
            body.get("to_index").and_then(Value::as_u64),
        ) else {
            return bad_request();
        };
        let entries: Vec<Value> = (from..to)
            .map(|index| json!({ "entry_index": index, "envelope": self.envelope_at(index) }))
            .collect();
        ok(&json!({
            "range": { "from_index": from, "to_index": to },
            "entries": entries,
            "range_proof": { "adaptor_form": format!("scripted:{tree_size}:{from}:{to}") },
        }))
    }

    fn witness_answer(&self, request: &Request) -> Response {
        if self.refusing_witness {
            return Response {
                status: 409,
                body: serde_json::to_vec(
                    &json!({ "status": "refused", "reason": "size-regression" }),
                )
                .unwrap_or_default(),
            };
        }
        let Some(anchors) = self.named_anchors(request) else { return not_rotation_material() };
        let mut answer = cosignature();
        if let Some(object) = answer.as_object_mut() {
            object.insert("status".to_owned(), json!("cosigned"));
            object.insert("series_member".to_owned(), json!(true));
            object.insert("rotation_anchors".to_owned(), json!(anchors));
        }
        created(&answer)
    }

    /// Every governance-key rotation the scripted corpus carries.
    fn rotations(&self) -> Vec<Rotation> {
        let governance = Governance::read(&self.entries);
        let carried = governance.carried_indices(self.size());
        governance.rotations(&carried)
    }

    /// The rotations a checkpoint is rotation-anchoring material for, ascending.
    ///
    /// The same two conditions the mirror and the witness apply: a `tree_size` greater than the
    /// rotating manifest's entry index, and a signing key of the OUTGOING set.
    fn anchors_for(&self, checkpoint: &Value) -> Vec<u64> {
        let governance = Governance::read(&self.entries);
        self.rotations()
            .into_iter()
            .filter(|rotation| {
                governance
                    .manifest_at(rotation.outgoing_entry_index)
                    .is_ok_and(|outgoing| rotation.anchored_by(checkpoint, outgoing))
            })
            .map(|rotation| rotation.manifest_entry_index)
            .collect()
    }

    /// What a submission naming a rotation is answered with: the discovered anchors, or `None`
    /// where the name is not among them and the server refuses the submission.
    fn named_anchors(&self, request: &Request) -> Option<Vec<u64>> {
        let body = request
            .body
            .as_ref()
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .unwrap_or(Value::Null);
        let checkpoint = body.get("checkpoint").cloned().unwrap_or_else(|| self.checkpoint());
        let anchors = self.anchors_for(&checkpoint);
        match body.get("rotation_for").and_then(Value::as_u64) {
            Some(named) if !anchors.contains(&named) => None,
            _ => Some(anchors),
        }
    }

    /// The rotation-anchoring checkpoint the scripted deployment holds for a rotation: the
    /// smallest tree size that commits the rotating manifest.
    fn rotation_anchor(&self, index: u64) -> Option<Value> {
        if self.unanchored.contains(&index)
            || !self.rotations().iter().any(|rotation| rotation.manifest_entry_index == index)
        {
            return None;
        }
        let tree_size = index.checked_add(1)?;
        (tree_size <= self.size()).then(|| self.checkpoint_at(tree_size))
    }

    /// The mirror's half of the element: three members, and `witnesses` empty because a mirror
    /// does not cosign.
    fn rotation_proof_answer(&self, index: u64) -> Response {
        let Some(checkpoint) = self.rotation_anchor(index) else { return not_found() };
        let Some(tree_size) = index.checked_add(1) else { return not_found() };
        let at = usize::try_from(index).unwrap_or(usize::MAX);
        let Ok(proof) = inclusion_proof(&self.leaf_bytes(tree_size), at) else {
            return not_found();
        };
        ok(&json!({
            "manifest_entry_index": index,
            "checkpoint": checkpoint,
            "inclusion_path": proof_path_hex(&proof),
            "witnesses": [],
        }))
    }

    /// The witness's half: the cosignatures it holds over that anchor, in the
    /// `anchoring.witnesses[]` shape, alongside the checkpoint they are over.
    fn rotation_cosignature_answer(&self, index: u64) -> Response {
        let Some(checkpoint) = self.rotation_anchor(index) else { return not_found() };
        // The rotation-anchoring checkpoint verifies under the OUTGOING state, so the witness
        // that cosigned it is the one the version PRECEDING the rotating manifest declares.
        let governance = Governance::read(&self.entries);
        let Ok((_, outgoing)) = governance.snapshot_at(index) else { return not_found() };
        let declared = outgoing.pointer("/witnesses/0");
        let (Some(witness_id), Some(key_id)) = (
            declared.and_then(|witness| witness.get("witness_id")).cloned(),
            declared.and_then(|witness| witness.pointer("/keys/0/key_id")).cloned(),
        ) else {
            return not_found();
        };
        let served = if self.rotation_mismatch { self.checkpoint() } else { checkpoint };
        ok(&json!({
            "log_id": log_id(),
            "manifest_entry_index": index,
            "checkpoint": served,
            "witnesses": [ {
                "witness_id": witness_id,
                "key_id": key_id,
                "cosignature": "base64:cm90YXRpb24=",
                "cosigned_at": TIME,
            } ],
        }))
    }

    fn answer(&self, request: &Request) -> Response {
        let log = request.url.strip_prefix(LOG).unwrap_or("");
        let mirror = request.url.strip_prefix(MIRROR).unwrap_or("");
        let witness = request.url.strip_prefix(WITNESS).unwrap_or("");

        if log == "/v1/anchor" && request.method == Method::Post {
            // The submission answer names the index the log placed it at; where the deployment
            // is set to contradict itself, the retrieved receipt names another.
            let placed = if self.discrepancy == Discrepancy::MovedIndex {
                self.subject_index.wrapping_add(1)
            } else {
                self.subject_index
            };
            return created(&self.atl_receipt(placed));
        }
        if let Some(id) = log.strip_prefix("/v1/anchor/") {
            return if id == ATL_ENTRY_ID {
                ok(&self.atl_receipt(self.subject_index))
            } else {
                not_found()
            };
        }
        if mirror == "/v1/entries/stage" {
            return created(&json!({ "status": "staged" }));
        }
        if let Some(rest) = mirror.strip_prefix("/v1/entries/") {
            return self.entry_answer(rest.split('?').next().unwrap_or(rest));
        }
        if mirror == "/v1/checkpoints" {
            return if request.method == Method::Post {
                self.named_anchors(request).map_or_else(not_rotation_material, |anchors| {
                    created(&json!({ "series_member": true, "rotation_anchors": anchors }))
                })
            } else {
                ok(&self.series())
            };
        }
        if let Some(index) = mirror.strip_prefix("/v1/rotation-proofs/") {
            return index
                .parse::<u64>()
                .map_or_else(|_| bad_request(), |index| self.rotation_proof_answer(index));
        }
        if let Some(size) = mirror.strip_prefix("/v1/checkpoints/") {
            return size
                .parse::<u64>()
                .map_or_else(|_| bad_request(), |tree_size| ok(&self.checkpoint_at(tree_size)));
        }
        if mirror == "/v1/range" {
            return self.range_answer(request);
        }
        if witness.starts_with("/v1/logs/") && witness.ends_with("/witness") {
            return self.witness_answer(request);
        }
        if let Some(rest) = witness.strip_prefix("/v1/logs/") {
            if let Some((_, index)) = rest.split_once("/rotation-cosignatures/") {
                return index.parse::<u64>().map_or_else(
                    |_| bad_request(),
                    |index| self.rotation_cosignature_answer(index),
                );
            }
        }
        not_found()
    }
}

impl Fetcher for Stack {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        Ok(self.answer(request))
    }
}

/// A fetcher answering every request with one fixed status and body.
///
/// Every producer entry point but [`crate::producer::anchor`] makes exactly one request, so a
/// single canned answer is enough to drive each of their rejection paths.
#[derive(Debug)]
pub struct Canned {
    /// The status to answer with.
    pub status: u16,
    /// The body to answer with.
    pub body: Vec<u8>,
}

impl Canned {
    /// Answer with `status` and a JSON body.
    #[must_use]
    pub fn json(status: u16, body: &Value) -> Self {
        Self { status, body: serde_json::to_vec(body).unwrap_or_default() }
    }

    /// Answer with `status` and body bytes that are not JSON.
    #[must_use]
    pub fn raw(status: u16, body: &str) -> Self {
        Self { status, body: body.as_bytes().to_vec() }
    }
}

impl Fetcher for Canned {
    fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
        Ok(Response { status: self.status, body: self.body.clone() })
    }
}

/// A fetcher that never answers, so the transport-failure path is reached.
#[derive(Debug)]
pub struct Unreachable;

impl Fetcher for Unreachable {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        Err(FetchFailure::Unreachable {
            url: request.url.clone(),
            detail: "the scripted endpoint answers nothing".to_owned(),
        })
    }
}

fn ok<T: serde::Serialize>(value: &T) -> Response {
    Response { status: 200, body: serde_json::to_vec(value).unwrap_or_default() }
}

fn created<T: serde::Serialize>(value: &T) -> Response {
    Response { status: 201, body: serde_json::to_vec(value).unwrap_or_default() }
}

fn not_found() -> Response {
    Response { status: 404, body: br#"{"error":"no such route"}"#.to_vec() }
}

fn bad_request() -> Response {
    Response { status: 400, body: br#"{"error":"unusable request"}"#.to_vec() }
}

/// The refusal both servers answer a `rotation_for` naming a rotation the checkpoint does not
/// in fact anchor with.
fn not_rotation_material() -> Response {
    Response {
        status: 400,
        body: br#"{"error":"the checkpoint is not rotation-anchoring material for that manifest entry index"}"#
            .to_vec(),
    }
}
