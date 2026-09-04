//! The deployment the pilot runs against: keys, identifiers, statements, configurations.
//!
//! Everything here is the **producer's and operator's** side of the deployment, written out
//! by the harness rather than reused from the product. The ATL-form checkpoint conversion in
//! particular is done here a second time, on purpose: a harness that imported the client's own
//! conversion could not catch a fault in it.
//!
//! Key seeds are trivially repeating byte patterns, exactly as the published conformance
//! corpus does it, so nothing here can be mistaken for production key material.

// The deployment is described in one place; which parts of it a given test exercises is that
// test's business, and a scenario member with no caller today is not a defect.
#![allow(dead_code)]

use std::collections::BTreeMap;

use ahl_core::descriptor::CanonicalizationDescriptor;
use ahl_core::{
    atl_checkpoint_time, atl_log_id, commit_plain, entry_id, envelope, jcs, statement_id, TestKey,
    AHL_VERSION,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::stack::{http, Stack};

/// The ATL Data Tree this corpus is bound to, as 16 raw bytes.
///
/// Adaptor §7.1 derives the Origin ID as `SHA-256(uuid)` and the AHL `log_id` as
/// `"sha256:" || hex(Origin ID)`, so fixing the UUID fixes the log id before the log starts —
/// which is what lets the genesis manifest, the mirror configuration and the witness
/// configurations all be written against the same identifier without asking the log for it.
pub const TREE_UUID: [u8; 16] = [0x0A; 16];

/// The operator id the manifests declare.
pub const OPERATOR: &str = "pilot-log-operator";
/// Producer identity.
pub const PRODUCER: &str = "producer-1";
/// The first witness, declared by the genesis manifest.
pub const WITNESS_1: &str = "witness-1";
/// The second witness, which manifest version 2 rotates in.
pub const WITNESS_2: &str = "witness-2";
/// The adaptor profile this corpus pins.
pub const PROFILE_ID: &str = "ahl-adaptor-atl-v1";
/// Datasets.
pub const DS_CUSTOMERS: &str = "customers";
/// The derived dataset.
pub const DS_SCORES: &str = "scores";
/// The pipeline every derivation declares.
pub const PIPELINE: &str = "pilot-scoring-v1";
/// Canonicalization identifier every dataset declares.
pub const CANONICALIZATION: &str = "jcs";
/// Domain time for every statement. Statement times are domain facts and carry no relation to
/// the wall clock the log stamps its checkpoints with.
pub const T0: &str = "2026-08-16T12:00:00Z";

/// Every key the deployment declares.
pub struct Keys {
    /// The producer the genesis manifest declares.
    pub producer_1: TestKey,
    /// The producer a `key` statement adds.
    pub producer_2: TestKey,
    /// The log's checkpoint-signing key — the same 32-byte seed `atl-server` is started with.
    pub log: TestKey,
    /// The witness the genesis manifest declares.
    pub witness_1: TestKey,
    /// The witness manifest version 2 rotates in.
    pub witness_2: TestKey,
}

/// The 32-byte Ed25519 seed the log signs checkpoints with.
pub const LOG_SEED: [u8; 32] = [0x33; 32];
/// The witness seeds, as hex, because that is how `ahl-witness` is configured.
pub const WITNESS_1_SEED: &str = "0404040404040404040404040404040404040404040404040404040404040404";
/// Seed of the incoming witness.
pub const WITNESS_2_SEED: &str = "0606060606060606060606060606060606060606060606060606060606060606";
/// Producer seeds, written to key files for `ahl-cli emit`.
pub const PRODUCER_1_SEED: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
/// Seed of the producer a `key` statement adds.
pub const PRODUCER_2_SEED: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";

impl Keys {
    /// Load every key from its committed seed.
    pub fn load() -> Self {
        let key =
            |name: &str, seed: &str| TestKey::from_seed_hex(name, seed).expect("a 32-byte seed");
        Self {
            producer_1: key(PRODUCER, PRODUCER_1_SEED),
            producer_2: key("producer-2", PRODUCER_2_SEED),
            log: key("log-1", &hex::encode(LOG_SEED)),
            witness_1: key(WITNESS_1, WITNESS_1_SEED),
            witness_2: key(WITNESS_2, WITNESS_2_SEED),
        }
    }

    /// The witness a given manifest version declares, with the entry index it binds at.
    pub const fn witness_for(&self, manifest_index: u64) -> (&TestKey, &'static str) {
        if manifest_index == 0 {
            (&self.witness_1, WITNESS_1)
        } else {
            (&self.witness_2, WITNESS_2)
        }
    }
}

/// The AHL `log_id` of adaptor §7.1, derived from [`TREE_UUID`] and never asked of the log.
pub fn log_id() -> String {
    atl_log_id(&TREE_UUID)
}

/// [`TREE_UUID`] in the hyphenated form `atl-server` parses.
pub fn tree_uuid_string() -> String {
    let hex = hex::encode(TREE_UUID);
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// The canonicalization descriptor every dataset in this corpus declares.
pub fn descriptor() -> CanonicalizationDescriptor {
    CanonicalizationDescriptor::new(CANONICALIZATION, None).expect("a registered identifier")
}

/// A record: the bytes a producer holds and the commitment the log carries.
pub struct Record {
    /// The dataset the record belongs to.
    pub dataset: String,
    /// The commitment, `sha256:<hex>` under the `plain` mode of I-D §2.6.
    pub commitment: String,
    /// The canonical bytes the commitment is computed over.
    pub bytes: Vec<u8>,
}

/// Build a `plain`-mode record from a JSON document.
pub fn record(dataset: &str, document: &Value) -> Record {
    let bytes = jcs(document);
    let commitment = commit_plain(dataset, &descriptor().ddig(), &bytes).expect("a dataset id");
    Record { dataset: dataset.to_owned(), commitment, bytes }
}

/// Common payload members (I-D §2.2) merged with the type-specific ones.
pub fn payload(kind: &str, manifest: &str, producer: &str, extra: Value) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("ahl_version".to_owned(), json!(AHL_VERSION));
    map.insert("type".to_owned(), json!(kind));
    map.insert("producer".to_owned(), json!(producer));
    map.insert("manifest".to_owned(), json!(manifest));
    map.insert("valid_time".to_owned(), json!(T0));
    map.insert("issued_at".to_owned(), json!(T0));
    if let Value::Object(extra) = extra {
        map.extend(extra);
    }
    Value::Object(map)
}

/// A manifest payload, in the shape adaptor §7.3 fixes for an ATL binding.
///
/// `cadence_epoch` is a run-time value: the log stamps its checkpoints with the wall clock, and
/// adaptor §5.2.2 item 3 requires the earliest checkpoint committing the genesis manifest to
/// fall inside `[cadence_epoch, cadence_epoch + cadence]`. The epoch is declared once by the
/// genesis manifest and repeated verbatim by every later version (§7.3.2).
pub fn manifest(
    keys: &Keys,
    adaptor_hash: &str,
    entry_index: u64,
    cadence_epoch: &str,
    predecessor: Option<&str>,
) -> Value {
    let (witness_key, witness_id) = keys.witness_for(entry_index);
    // The producer snapshot: the genesis version knows one key, and version 2 carries the key
    // a `key` statement added, so the addition survives the snapshot rather than being
    // discarded by it (I-D §6.2).
    let producers = if entry_index == 0 {
        vec![keys.producer_1.producer_key_object()]
    } else {
        vec![keys.producer_1.producer_key_object(), keys.producer_2.producer_key_object()]
    };
    let mut payload = json!({
        "ahl_version": AHL_VERSION,
        "type": "manifest",
        "producer": PRODUCER,
        "valid_time": T0,
        "issued_at": T0,
        "level": "L3",
        "keys": producers,
        "log": {
            "log_id": log_id(),
            "operator": OPERATOR,
            "adaptor": { "id": PROFILE_ID, "hash": adaptor_hash },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": cadence_epoch,
            "witness_grace_period": "PT15M",
            // Repeated verbatim by every version: I-D §7.1 compares log key objects as a SET,
            // so re-declaring the same key at a new index would read as a rotation of the log
            // key set, which this deployment does not perform.
            "keys": [ keys.log.key_object(0) ],
        },
        "witnesses": [ {
            "witness_id": witness_id,
            "keys": [ witness_key.key_object(entry_index) ],
        } ],
        "datasets": {
            DS_CUSTOMERS: {
                "canonicalization": CANONICALIZATION,
                "commitment_mode": "plain",
                "key_access": "not-applicable",
                "authority": {
                    "producer": PRODUCER,
                    "key_ids": [ keys.producer_1.key_id() ],
                },
            },
            DS_SCORES: {
                "canonicalization": CANONICALIZATION,
                "commitment_mode": "plain",
                "key_access": "not-applicable",
            },
        },
        "pipelines": { "include": [ PIPELINE ], "exclude": [] },
        "windows": { "anchoring": "PT24H", "propagation": "P30D" },
        "retention": { "statements": "P10Y" },
        "properties": { "reproducible_reconstruction": false },
    });
    if let Some(entry) = predecessor {
        payload["predecessor"] = json!(entry);
    }
    payload
}

/// The mirror's configuration document.
pub fn mirror_config(genesis_entry_id: &str, keys: &Keys, store: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "log_id": log_id(),
        "genesis_manifest_entry_id": genesis_entry_id,
        "genesis_producer_keys": [ {
            "key_id": keys.producer_1.key_id(),
            "pubkey": keys.producer_1.pubkey(),
            "valid_from_index": 0,
        } ],
        "store_path": store,
    }))
    .expect("a serializable configuration")
}

/// One witness's configuration document.
pub fn witness_config(
    witness_id: &str,
    seed_hex: &str,
    genesis_entry_id: &str,
    keys: &Keys,
    store: &str,
) -> String {
    serde_json::to_string_pretty(&json!({
        "witness_id": witness_id,
        "signing_key_seed_hex": seed_hex,
        "store_path": store,
        "logs": [ {
            "log_id": log_id(),
            "genesis_manifest_entry_id": genesis_entry_id,
            "genesis_producer_keys": [ {
                "key_id": keys.producer_1.key_id(),
                "pubkey": keys.producer_1.pubkey(),
                "valid_from_index": 0,
            } ],
        } ],
    }))
    .expect("a serializable configuration")
}

/// The AHL checkpoint object of adaptor §6.2, built from an ATL Evidence Receipt's checkpoint.
///
/// A second implementation of the mapping the client also performs, kept here deliberately: a
/// harness that reused the client's conversion could not catch a fault in it.
pub fn ahl_checkpoint(atl: &Value) -> Value {
    let nanos = atl["timestamp"].as_u64().expect("a nanosecond timestamp");
    json!({
        "log_id": atl["origin"],
        "tree_size": atl["tree_size"],
        "root_hash": atl["root_hash"],
        "checkpoint_time": atl_checkpoint_time(nanos),
        "key_id": atl["key_id"],
        "signature": atl["signature"],
    })
}

/// `base64:` family string over `bytes`.
pub fn base64(bytes: &[u8]) -> String {
    format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Submit `envelope` to the ATL log and return its ATL Evidence Receipt.
///
/// The submitted ATL metadata is the fixed object of adaptor §4.2 and nothing else, so the
/// leaf the log builds is a pure function of the entry bytes.
pub fn anchor(stack: &Stack, envelope: &Value) -> Result<Value, String> {
    let body = serde_json::to_vec(&json!({
        "payload": envelope,
        "metadata": { "ahl_adaptor": PROFILE_ID },
    }))
    .expect("a serializable request");
    let (status, response) = http(&stack.log.base, "POST", "/v1/anchor", Some(&body))?;
    if status != 201 {
        return Err(format!(
            "the log answered {status} for an anchor request: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    serde_json::from_slice(&response)
        .map_err(|source| format!("the log's receipt is not JSON: {source}"))
}

/// Stage one entry's canonical bytes at the mirror.
pub fn stage(stack: &Stack, envelope: &Value) -> Result<(), String> {
    let bytes = jcs(envelope);
    let body = serde_json::to_vec(&json!({
        "entry_id": entry_id(envelope),
        "envelope_base64": base64(&bytes),
        "atl_metadata": { "ahl_adaptor": PROFILE_ID },
    }))
    .expect("a serializable request");
    let (status, response) = http(&stack.mirror.base, "POST", "/v1/entries/stage", Some(&body))?;
    if status == 200 || status == 201 {
        Ok(())
    } else {
        Err(format!(
            "the mirror answered {status} to a stage request: {}",
            String::from_utf8_lossy(&response)
        ))
    }
}

/// Ingest a checkpoint at the mirror, promoting the entries it commits that are not yet
/// promoted.
pub fn ingest_checkpoint(
    stack: &Stack,
    checkpoint: &Value,
    raw: &str,
    promotions: &[Value],
) -> Result<(), String> {
    let body = serde_json::to_vec(&json!({
        "checkpoint": checkpoint,
        "raw": raw,
        "entries_to_promote": promotions,
    }))
    .expect("a serializable request");
    let (status, response) = http(&stack.mirror.base, "POST", "/v1/checkpoints", Some(&body))?;
    if status == 201 {
        Ok(())
    } else {
        Err(format!(
            "the mirror answered {status} to a checkpoint ingest: {}",
            String::from_utf8_lossy(&response)
        ))
    }
}

/// Submit a checkpoint to one witness, with the complete entry prefix it commits, and return
/// the cosigned object it answers with.
///
/// The witness derives the consistency proof itself, which is why the whole prefix travels
/// rather than a proof: adaptor §11.2.4 removes `missing-consistency-proof` precisely because
/// a proof-fed witness cannot produce checkable evidence of a missing one.
pub fn cosign(
    stack: &Stack,
    witness_id: &str,
    checkpoint: &Value,
    raw: &str,
    prefix: &[Value],
) -> Result<Value, String> {
    let entries: Vec<String> = prefix.iter().map(|entry| base64(&jcs(entry))).collect();
    let body = serde_json::to_vec(&json!({
        "checkpoint": checkpoint,
        "raw": raw,
        "entries": entries,
    }))
    .expect("a serializable request");
    let path = format!("/v1/logs/{}/witness", log_id());
    let (status, response) = http(stack.witness(witness_id), "POST", &path, Some(&body))?;
    if status != 201 {
        return Err(format!(
            "witness `{witness_id}` answered {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    serde_json::from_slice(&response)
        .map_err(|source| format!("witness `{witness_id}` did not answer with JSON: {source}"))
}

/// The genesis manifest, signed, plus its identifiers.
pub struct Genesis {
    /// The signed envelope, anchored at entry index 0.
    pub envelope: Value,
    /// `entry_id` — the trust anchor a policy pins and the configurations name.
    pub entry_id: String,
    /// `statement_id` — what later statements name in their `manifest` member.
    pub statement_id: String,
    /// The `cadence_epoch` every manifest version repeats.
    pub cadence_epoch: String,
}

/// Build the genesis manifest against a cadence epoch taken from the clock.
pub fn genesis(keys: &Keys, adaptor_hash: &str, cadence_epoch: &str) -> Genesis {
    let envelope = envelope(manifest(keys, adaptor_hash, 0, cadence_epoch, None), &keys.producer_1);
    Genesis {
        entry_id: entry_id(&envelope),
        statement_id: statement_id(&envelope).expect("a well-formed envelope"),
        cadence_epoch: cadence_epoch.to_owned(),
        envelope,
    }
}

/// Anchor the genesis manifest and publish the resulting checkpoint to the mirror and to every
/// witness.
///
/// This is a deployment act rather than a receipt-issuing one: entry 0 is the trust anchor, and
/// nothing can be verified against the corpus until it exists. Everything after it goes through
/// the product's own `issue`.
pub fn bootstrap(stack: &Stack, genesis: &Genesis) -> Result<Value, String> {
    let receipt = anchor(stack, &genesis.envelope)?;
    let leaf_index = receipt["proof"]["leaf_index"].as_u64().unwrap_or(u64::MAX);
    if leaf_index != 0 {
        return Err(format!("the genesis manifest anchored at leaf index {leaf_index}, not 0"));
    }
    let checkpoint = ahl_checkpoint(&receipt["proof"]["checkpoint"]);
    if checkpoint["log_id"] != json!(log_id()) {
        return Err(format!(
            "the log's Origin ID is {}, the harness derived {} from the tree UUID it started \
             the log with; adaptor §7.1 makes the two the same value",
            checkpoint["log_id"],
            log_id()
        ));
    }
    let raw = base64(
        &ahl_core::atl_checkpoint_blob_from_json(&checkpoint)
            .map_err(|source| format!("the checkpoint does not reassemble: {source}"))?,
    );
    stage(stack, &genesis.envelope)?;
    ingest_checkpoint(
        stack,
        &checkpoint,
        &raw,
        &[json!({
            "entry_id": genesis.entry_id,
            "leaf_index": 0,
            "inclusion_path": receipt["proof"]["inclusion_path"],
        })],
    )?;
    for witness_id in [WITNESS_1, WITNESS_2] {
        cosign(stack, witness_id, &checkpoint, &raw, std::slice::from_ref(&genesis.envelope))?;
    }
    Ok(checkpoint)
}

/// Write the trust policy the pilot verifies under.
///
/// The profile digest is computed over the document at run time and pinned here. **This pin is
/// pilot-only.** Adaptor §14 makes release a precondition for pinning: until the document is
/// published as an immutable artifact its digest is not stable, and no production manifest may
/// pin it. A test policy over a scratch log is not a production manifest, and the pin is
/// recomputed on every run from the bytes actually held, so it can never go stale.
pub fn policy_file(
    dir: &std::path::Path,
    genesis: &Genesis,
    keys: &Keys,
    profile: &std::path::Path,
    profile_hash: &str,
    stack: &Stack,
) -> std::path::PathBuf {
    let text = format!(
        "# Generated by the AHL end-to-end pilot. The adaptor profile digest below is a\n\
         # PILOT-ONLY pin: adaptor §14 makes release a precondition for pinning a profile, and\n\
         # this document is unreleased. It is recomputed from the held bytes on every run, and\n\
         # this policy governs a scratch log rather than a production corpus.\n\
         [policy]\n\
         genesis_entry_id = \"{}\"\n\
         genesis_key_ids = [\"{}\"]\n\n\
         [policy.adaptor_profiles.{PROFILE_ID}]\n\
         hash = \"{profile_hash}\"\n\
         path = \"{}\"\n\
         checkpoint_raw = true\n\
         consistency_proofs = true\n\n\
         [endpoints]\n\
         mirror = \"{}\"\n\
         witness = \"{}\"\n",
        genesis.entry_id,
        keys.producer_1.key_id(),
        profile.display(),
        stack.mirror.base,
        stack.witness(WITNESS_1),
    );
    let path = dir.join("policy.toml");
    std::fs::write(&path, text).expect("write the policy");
    std::fs::set_permissions(&path, permissions(0o600)).expect("owner-only policy");
    path
}

/// Owner-only file permissions, as the design note §4 secure-open rules require.
pub fn permissions(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::Permissions::from_mode(mode)
}

/// Write a producer signing seed where `ahl-cli emit` can open it.
pub fn key_file(dir: &std::path::Path, name: &str, seed: &str) -> std::path::PathBuf {
    let path = dir.join(format!("{name}.seed"));
    std::fs::write(&path, format!("{seed}\n")).expect("write the seed");
    std::fs::set_permissions(&path, permissions(0o600)).expect("owner-only seed");
    path
}

/// The witness endpoints the pilot runs, by id.
pub fn witness_endpoints(stack: &Stack) -> BTreeMap<String, String> {
    stack.witnesses.iter().map(|(id, server)| (id.clone(), server.base.clone())).collect()
}
