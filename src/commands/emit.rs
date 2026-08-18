//! `emit` — a signed **candidate envelope**, never a conforming anchored statement.
//!
//! `emit` is retained against reviewer advice to cut it, because without it the open
//! self-hosted stack has no producer-side tool at all and every integrator writes bespoke
//! signing code — which is precisely how canonicalization drift enters a protocol. It is
//! constrained instead:
//!
//! * it performs the **locally decidable** checks only — statement-type schema, required
//!   members, canonicalization (JCS), and value grammars such as the restricted duration form;
//! * it **never adds a field the operator did not supply**, never signs an unknown statement
//!   type, and never defaults a missing required field;
//! * its output says, in the tool's own words, what it is not.
//!
//! The rules it cannot evaluate are log-position-dependent by nature, and are named in
//! [`NOT_EVALUATED`] rather than silently skipped: an introduction at a smaller entry index,
//! the active manifest binding, whether the signing key is active at the entry index the log
//! will assign, and trigger authority. A candidate envelope must never be presented as a
//! conforming statement, so every surface repeats it.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::duration::parse_time_only_duration;
use crate::error::{CliError, CliResult};
use crate::evaluation::parse_artifact_time;
use crate::install::{self, Force};
use crate::keys::{KeySource, SigningMaterial};
use crate::policy::LocalLimits;
use crate::secure;

/// What `emit` cannot evaluate, named in its own output.
pub const NOT_EVALUATED: [&str; 5] = [
    "that every consumed record is introduced by an anchored statement at a smaller entry index \
     (core spec §2.3.1)",
    "that the `manifest` this payload declares is the version active at the entry index the log \
     will assign (core spec §2.2)",
    "that the signing key is active at that entry index under the governing manifest version \
     (core spec §2.3.6)",
    "for a trigger, that the signing key is in the dataset authority key set active at the \
     trigger's entry index (core spec §2.3.3, §7.2)",
    "that no effective trigger for a consumed record is anchored at a smaller entry index \
     (core spec §2.3.2)",
];

const BOUNDARY: &str = "this is a signed CANDIDATE envelope, not a conforming anchored \
                        statement: every rule below is log-position-dependent and cannot be \
                        evaluated before the log assigns an entry index";

/// Options for one `emit` run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Path to the statement payload, as JSON.
    pub payload: std::path::PathBuf,
    /// Where the signing seed comes from.
    pub key: KeySource,
    /// Where to install the canonical envelope bytes, if anywhere.
    pub out: Option<std::path::PathBuf>,
    /// Whether an existing destination may be replaced.
    pub force: bool,
}

/// What `emit` produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Emitted {
    /// The standing statement of what this output is not.
    pub boundary: &'static str,
    /// The rules `emit` cannot evaluate.
    pub not_evaluated: Vec<&'static str>,
    /// The statement type signed.
    pub statement_type: String,
    /// `key_id` of the signing key, so the operator can confirm which key signed.
    pub key_id: String,
    /// Statement id — SHA-256 over `JCS(payload)`.
    pub statement_id: String,
    /// Entry id — SHA-256 over `JCS(envelope)`.
    pub entry_id: String,
    /// The signed envelope.
    pub envelope: Value,
    /// Where the canonical bytes were installed, if anywhere.
    pub written_to: Option<String>,
}

impl Emitted {
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

    /// Render the human-readable form.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{BOUNDARY}\n\n"));
        out.push_str(&format!("statement type: {}\n", self.statement_type));
        out.push_str(&format!("signed by key_id: {}\n", self.key_id));
        out.push_str(&format!("statement id: {}\n", self.statement_id));
        out.push_str(&format!("entry id: {}\n", self.entry_id));
        if let Some(path) = &self.written_to {
            out.push_str(&format!("canonical envelope bytes written to: {path}\n"));
        }
        out.push_str("\nnot evaluated by this tool:\n");
        for rule in &self.not_evaluated {
            out.push_str(&format!("  - {rule}\n"));
        }
        out
    }
}

/// Sign a candidate envelope.
///
/// # Errors
///
/// [`CliError::Open`] for an unreadable payload or key; [`CliError::Malformed`] for a payload
/// that breaks a locally decidable rule; [`CliError::Output`] if the destination exists or
/// cannot be written.
pub fn run(limits: LocalLimits, options: &Options) -> CliResult<Emitted> {
    let bytes = secure::read_regular("statement payload", &options.payload, limits.max_file_bytes)?;
    let payload: Value = serde_json::from_slice(&bytes).map_err(|source| CliError::Malformed {
        what: "statement payload",
        detail: format!("not JSON: {source}"),
    })?;
    let statement_type = check(&payload)?;

    // The signing key is opened only here. No verification command reaches this module.
    let material = SigningMaterial::load(&options.key)?;
    let envelope = material.envelope(payload);
    let canonical = ahl_core::jcs(&envelope);

    let written_to = match &options.out {
        Some(path) => {
            install::install(
                path,
                &canonical,
                if options.force { Force::Yes } else { Force::No },
            )?;
            Some(path.display().to_string())
        }
        None => None,
    };

    Ok(Emitted {
        boundary: BOUNDARY,
        not_evaluated: NOT_EVALUATED.to_vec(),
        statement_type,
        key_id: material.key_id(),
        statement_id: ahl_core::statement_id(&envelope).map_err(|source| CliError::Internal(
            format!("a freshly built envelope has no payload: {source}"),
        ))?,
        entry_id: ahl_core::entry_id(&envelope),
        envelope,
        written_to,
    })
}

/// The seven statement types (core spec §2.2). An unknown type is never signed.
const STATEMENT_TYPES: [&str; 7] =
    ["ingestion", "derivation", "retraction", "correction", "propagation", "manifest", "key"];

/// The `reason_code` registry of core spec §2.3.3.
const REASON_CODES: [&str; 6] =
    ["error", "fraud", "legal_obligation", "consent_withdrawn", "superseded", "other"];

fn malformed(detail: impl Into<String>) -> CliError {
    CliError::Malformed { what: "statement payload", detail: detail.into() }
}

fn require(payload: &Value, member: &str) -> CliResult<()> {
    if payload.get(member).is_some() {
        Ok(())
    } else {
        // Never defaulted: a missing required field is the operator's to supply.
        Err(malformed(format!("required member `{member}` is absent and is never defaulted")))
    }
}

fn require_string(payload: &Value, member: &str) -> CliResult<String> {
    payload
        .get(member)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| malformed(format!("required member `{member}` is absent or not a string")))
}

/// Run every locally decidable check, returning the statement type.
fn check(payload: &Value) -> CliResult<String> {
    if !payload.is_object() {
        return Err(malformed("the payload is not a JSON object"));
    }
    let statement_type = require_string(payload, "type")?;
    if !STATEMENT_TYPES.contains(&statement_type.as_str()) {
        return Err(malformed(format!(
            "`{statement_type}` is not one of the seven statement types; an unknown type is \
             never signed"
        )));
    }

    // Common members (core spec §2.2). `manifest` is absent only in manifest statements.
    let version = require_string(payload, "ahl_version")?;
    if version != ahl_core::AHL_VERSION {
        return Err(malformed(format!(
            "`ahl_version` is `{version}`; this build emits `{}` only",
            ahl_core::AHL_VERSION
        )));
    }
    require(payload, "producer")?;
    check_valid_time(payload)?;
    parse_artifact_time("issued_at", &require_string(payload, "issued_at")?)?;

    let declares_manifest = payload.get("manifest").is_some();
    if statement_type == "manifest" {
        if declares_manifest {
            return Err(malformed(
                "a manifest statement carries no `manifest` member; its predecessor lives in \
                 `predecessor` (core spec §2.3.5)",
            ));
        }
    } else if !declares_manifest {
        return Err(malformed(
            "`manifest` is REQUIRED for every statement except a manifest statement \
             (core spec §2.2)",
        ));
    }

    match statement_type.as_str() {
        "ingestion" => {
            require_string(payload, "dataset")?;
            require_commitment(payload, "record")?;
        }
        "derivation" => check_derivation(payload)?,
        "retraction" => check_trigger(payload, false)?,
        "correction" => check_trigger(payload, true)?,
        "propagation" => check_propagation(payload)?,
        "manifest" => check_manifest(payload)?,
        "key" => check_key(payload)?,
        // Unreachable: the type was checked against the registry above.
        other => return Err(malformed(format!("`{other}` has no local schema"))),
    }
    Ok(statement_type)
}

fn check_valid_time(payload: &Value) -> CliResult<()> {
    let valid_time = payload
        .get("valid_time")
        .ok_or_else(|| malformed("required member `valid_time` is absent"))?;
    match valid_time {
        Value::String(point) => {
            parse_artifact_time("valid_time", point)?;
        }
        Value::Object(interval) => {
            let from = interval
                .get("from")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed("`valid_time.from` is absent or not a string"))?;
            parse_artifact_time("valid_time.from", from)?;
            match interval.get("to") {
                None => return Err(malformed("`valid_time.to` is absent; use `null` for an open interval")),
                Some(Value::Null) => {}
                Some(Value::String(to)) => {
                    parse_artifact_time("valid_time.to", to)?;
                }
                Some(_) => return Err(malformed("`valid_time.to` is neither null nor a string")),
            }
        }
        _ => return Err(malformed("`valid_time` is neither an RFC 3339 string nor an interval")),
    }
    Ok(())
}

fn require_commitment(payload: &Value, member: &str) -> CliResult<String> {
    let value = require_string(payload, member)?;
    if ahl_core::tree::is_canonical_commitment(&value) {
        Ok(value)
    } else {
        Err(malformed(format!(
            "`{member}` is `{value}`, which is not a canonical commitment string \
             (`sha256:<64 lowercase hex>` or `hmac-sha256:<64 lowercase hex>`)"
        )))
    }
}

fn check_derivation(payload: &Value) -> CliResult<()> {
    require_string(payload, "pipeline")?;
    require(payload, "inputs")?;
    require(payload, "transform")?;
    // Either the inline output list or the §2.5 batch commitment, never both and never neither.
    let batched = payload.get("outputs_root").is_some();
    let inline = payload.get("outputs").is_some();
    match (batched, inline) {
        (true, true) => {
            return Err(malformed(
                "a batch derivation replaces `outputs` with `outputs_root`; carrying both is \
                 ambiguous (core spec §2.5)",
            ))
        }
        (false, false) => {
            return Err(malformed("a derivation carries either `outputs` or `outputs_root`"))
        }
        (true, false) => {
            require(payload, "outputs_count")?;
            let format = require_string(payload, "leaf_format")?;
            if format != "ahl-leaf-v2" {
                return Err(malformed(format!(
                    "`leaf_format` is `{format}`; core spec §2.5 fixes `ahl-leaf-v2`"
                )));
            }
        }
        (false, true) => {
            let outputs = payload
                .get("outputs")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("`outputs` is not an array"))?;
            if outputs.is_empty() {
                return Err(malformed("`outputs` is empty"));
            }
            for output in outputs {
                require_string(output, "dataset")?;
                require_commitment(output, "record")?;
            }
        }
    }
    let inputs = payload
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("`inputs` is not an array"))?;
    for input in inputs {
        require_string(input, "dataset")?;
        // Closure traversal uses `(dataset, record)` only, so `record` is REQUIRED on every
        // input object — that is what a trigger would name (core spec §2.3.2).
        require_commitment(input, "record")?;
    }
    Ok(())
}

fn check_trigger(payload: &Value, correction: bool) -> CliResult<()> {
    require_string(payload, "dataset")?;
    require_commitment(payload, "record")?;
    if correction {
        require_commitment(payload, "replacement")?;
    }
    let reason = require_string(payload, "reason_code")?;
    if !REASON_CODES.contains(&reason.as_str()) {
        return Err(malformed(format!(
            "`reason_code` is `{reason}`, which is not in the core spec §2.3.3 registry"
        )));
    }
    // `scope` is REQUIRED; scopeless triggers are malformed (core spec §2.3.3).
    let scope = payload
        .get("scope")
        .filter(|value| value.is_object())
        .ok_or_else(|| malformed("`scope` is REQUIRED; scopeless triggers are malformed"))?;
    parse_artifact_time("scope.effective_from", &require_string(scope, "effective_from")?)?;
    if scope.get("retroactive").and_then(Value::as_bool).is_none() {
        return Err(malformed("`scope.retroactive` is absent or not a boolean"));
    }
    Ok(())
}

fn check_propagation(payload: &Value) -> CliResult<()> {
    require_string(payload, "trigger")?;
    let checkpoint = payload
        .get("corpus_checkpoint")
        .filter(|value| value.is_object())
        .ok_or_else(|| malformed("`corpus_checkpoint` is REQUIRED and must be an object"))?;
    require_string(checkpoint, "log_id")?;
    require_string(checkpoint, "root_hash")?;
    if checkpoint.get("tree_size").and_then(Value::as_u64).is_none() {
        return Err(malformed("`corpus_checkpoint.tree_size` is absent or not an integer"));
    }
    require_string(payload, "affected_root")?;
    if payload.get("affected_count").and_then(Value::as_u64).is_none() {
        return Err(malformed("`affected_count` is absent or not an integer"));
    }
    if payload.get("complete_relative_to_manifest").and_then(Value::as_bool).is_none() {
        return Err(malformed(
            "`complete_relative_to_manifest` is absent or not a boolean",
        ));
    }
    Ok(())
}

fn check_manifest(payload: &Value) -> CliResult<()> {
    require(payload, "keys")?;
    require(payload, "datasets")?;
    require(payload, "pipelines")?;
    let log = payload
        .get("log")
        .filter(|value| value.is_object())
        .ok_or_else(|| malformed("`log` is REQUIRED and must be an object (core spec §7.3)"))?;

    // Core spec §7.3 makes every member of the `log` object REQUIRED, and names the log id
    // `log_id`. `emit` enforces the specification here: it is producing a new statement, so
    // there is no frozen corpus to accommodate, and a manifest emitted with the legacy
    // spelling would be malformed on the face of §7.3.
    for member in [
        "log_id",
        "operator",
        "adaptor",
        "checkpoint_cadence",
        "cadence_epoch",
        "witness_grace_period",
        "keys",
    ] {
        if log.get(member).is_none() {
            return Err(malformed(format!(
                "`log.{member}` is REQUIRED by core spec §7.3 and is never defaulted"
            )));
        }
    }
    let adaptor = log.get("adaptor").filter(|value| value.is_object()).ok_or_else(|| {
        malformed("`log.adaptor` must be the object `{id, hash}` (core spec §7.2)")
    })?;
    require_string(adaptor, "id")?;
    require_string(adaptor, "hash")?;

    // The restricted duration grammar: `Y`, or `M` in the date part, is rejected rather than
    // approximated, and fractional seconds are capped at nine digits.
    let cadence = parse_time_only_duration(
        "checkpoint_cadence",
        log.get("checkpoint_cadence").and_then(Value::as_str).unwrap_or_default(),
    )?;
    if cadence == 0 {
        return Err(malformed("`log.checkpoint_cadence` must be greater than zero"));
    }
    parse_time_only_duration(
        "witness_grace_period",
        log.get("witness_grace_period").and_then(Value::as_str).unwrap_or_default(),
    )?;
    parse_artifact_time(
        "cadence_epoch",
        log.get("cadence_epoch").and_then(Value::as_str).unwrap_or_default(),
    )?;
    Ok(())
}

fn check_key(payload: &Value) -> CliResult<()> {
    let action = require_string(payload, "action")?;
    if action != "add" && action != "retire" {
        return Err(malformed(format!(
            "`action` is `{action}`; core spec §2.3.6 defines `add` and `retire`"
        )));
    }
    let key = payload
        .get("key")
        .filter(|value| value.is_object())
        .ok_or_else(|| malformed("`key` is REQUIRED and must be an object"))?;
    require_string(key, "key_id")?;
    require_string(key, "pubkey")?;
    require(key, "valid_from")?;
    Ok(())
}

/// Statement types this build will sign, for `--help` and documentation.
#[must_use]
pub fn supported_statement_types() -> BTreeSet<&'static str> {
    STATEMENT_TYPES.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::*;

    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn commitment(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn key_source(dir: &Path) -> KeySource {
        let path = dir.join("k.seed");
        std::fs::write(&path, SEED).expect("write seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        KeySource::File(path)
    }

    fn emit(dir: &Path, payload: &Value, out: Option<PathBuf>) -> CliResult<Emitted> {
        let path = dir.join("payload.json");
        std::fs::write(&path, serde_json::to_vec(payload).expect("serialize")).expect("write");
        run(
            LocalLimits::default(),
            &Options { payload: path, key: key_source(dir), out, force: false },
        )
    }

    fn ingestion() -> Value {
        json!({
            "ahl_version": "0.3",
            "type": "ingestion",
            "producer": "producer-1",
            "manifest": commitment(0x11),
            "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z",
            "dataset": "customers",
            "record": commitment(0x22),
        })
    }

    #[test]
    fn a_well_formed_ingestion_is_signed_and_verifies_under_its_own_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let emitted = emit(dir.path(), &ingestion(), None).expect("emitted");
        assert_eq!(emitted.statement_type, "ingestion");
        assert!(emitted.key_id.starts_with("sha256:"));
        assert_eq!(emitted.entry_id, ahl_core::entry_id(&emitted.envelope));

        let key = ahl_core::TestKey::from_seed_hex("k", SEED).expect("seed");
        assert!(ahl_core::verify_envelope(&emitted.envelope, |id| (id == key.key_id())
            .then(|| key.pubkey()))
        .expect("well-formed"));
    }

    #[test]
    fn the_output_says_what_it_is_not_on_every_surface() {
        let dir = tempfile::tempdir().expect("tempdir");
        let emitted = emit(dir.path(), &ingestion(), None).expect("emitted");
        for surface in [emitted.to_text(), emitted.to_json().expect("serializes")] {
            assert!(surface.contains("CANDIDATE"), "boundary missing:\n{surface}");
            assert!(surface.contains("not a conforming anchored statement"));
            assert!(surface.contains("entry index"), "the reason must be named");
        }
        assert_eq!(emitted.not_evaluated.len(), NOT_EVALUATED.len());
    }

    #[test]
    fn emit_never_adds_a_field_the_operator_did_not_supply() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = ingestion();
        let emitted = emit(dir.path(), &payload, None).expect("emitted");
        assert_eq!(emitted.envelope["payload"], payload);
    }

    #[test]
    fn an_unknown_statement_type_is_never_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = ingestion();
        payload["type"] = json!("attestation");
        let error = emit(dir.path(), &payload, None).expect_err("unknown type");
        assert!(error.to_string().contains("never signed"), "{error}");
    }

    #[test]
    fn each_required_ingestion_member_is_enforced_by_name_and_never_defaulted() {
        let dir = tempfile::tempdir().expect("tempdir");
        for member in
            ["ahl_version", "type", "producer", "manifest", "valid_time", "issued_at", "record"]
        {
            let mut payload = ingestion();
            payload.as_object_mut().expect("object").remove(member);
            assert!(
                emit(dir.path(), &payload, None).is_err(),
                "removing `{member}` must be refused"
            );
        }
    }

    #[test]
    fn a_manifest_statement_carries_no_manifest_member_and_others_must() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manifest = json!({
            "ahl_version": "0.3",
            "type": "manifest",
            "producer": "producer-1",
            "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z",
            "keys": [],
            "datasets": {},
            "pipelines": { "include": [], "exclude": [] },
            "log": {
                "log_id": commitment(0x33),
                "operator": "op",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": commitment(0x44) },
                "checkpoint_cadence": "PT1H",
                "cadence_epoch": "2026-08-16T00:00:00Z",
                "witness_grace_period": "PT15M",
                "keys": [],
            },
        });
        assert_eq!(
            emit(dir.path(), &manifest, None).expect("emitted").statement_type,
            "manifest"
        );
        manifest["manifest"] = json!(commitment(0x55));
        assert!(emit(dir.path(), &manifest, None).is_err());
    }

    #[test]
    fn a_manifest_log_object_is_held_to_core_spec_7_3_in_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = json!({
            "ahl_version": "0.3", "type": "manifest", "producer": "p",
            "valid_time": "2026-08-16T12:00:00Z", "issued_at": "2026-08-16T12:00:00Z",
            "keys": [], "datasets": {}, "pipelines": {},
            "log": {
                "log_id": commitment(0x33), "operator": "op",
                "adaptor": { "id": "a", "hash": commitment(0x44) },
                "checkpoint_cadence": "PT1H", "cadence_epoch": "2026-08-16T00:00:00Z",
                "witness_grace_period": "PT15M", "keys": [],
            },
        });
        for member in [
            "log_id",
            "operator",
            "adaptor",
            "checkpoint_cadence",
            "cadence_epoch",
            "witness_grace_period",
            "keys",
        ] {
            let mut payload = base.clone();
            payload["log"].as_object_mut().expect("object").remove(member);
            let error = emit(dir.path(), &payload, None).expect_err("required member");
            assert!(error.to_string().contains(member), "{error}");
        }
        // The legacy `log.id` spelling is not accepted when producing a new manifest.
        let mut legacy = base.clone();
        let log = legacy["log"].as_object_mut().expect("object");
        let value = log.remove("log_id").expect("present");
        log.insert("id".to_owned(), value);
        assert!(emit(dir.path(), &legacy, None).is_err());
    }

    #[test]
    fn prohibited_duration_components_are_rejected_rather_than_approximated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = json!({
            "ahl_version": "0.3", "type": "manifest", "producer": "p",
            "valid_time": "2026-08-16T12:00:00Z", "issued_at": "2026-08-16T12:00:00Z",
            "keys": [], "datasets": {}, "pipelines": {},
            "log": {
                "log_id": commitment(0x33), "operator": "op",
                "adaptor": { "id": "a", "hash": commitment(0x44) },
                "checkpoint_cadence": "PT1H", "cadence_epoch": "2026-08-16T00:00:00Z",
                "witness_grace_period": "PT15M", "keys": [],
            },
        });
        for (member, value) in [
            ("checkpoint_cadence", "P1Y"),
            ("checkpoint_cadence", "P1M"),
            ("checkpoint_cadence", "PT0S"),
            ("witness_grace_period", "PT0.0000000001S"),
        ] {
            let mut payload = base.clone();
            payload["log"][member] = json!(value);
            assert!(
                emit(dir.path(), &payload, None).is_err(),
                "`{member} = {value}` must be refused"
            );
        }
    }

    #[test]
    fn a_scopeless_trigger_is_malformed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = json!({
            "ahl_version": "0.3", "type": "retraction", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "dataset": "customers",
            "record": commitment(0x22), "reason_code": "error",
            "scope": { "effective_from": "2026-08-16T12:00:00Z", "retroactive": true },
        });
        assert_eq!(emit(dir.path(), &payload, None).expect("emitted").statement_type, "retraction");

        payload.as_object_mut().expect("object").remove("scope");
        let error = emit(dir.path(), &payload, None).expect_err("scopeless");
        assert!(error.to_string().contains("scopeless triggers are malformed"), "{error}");
    }

    #[test]
    fn an_unregistered_reason_code_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = json!({
            "ahl_version": "0.3", "type": "retraction", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "dataset": "customers",
            "record": commitment(0x22), "reason_code": "because",
            "scope": { "effective_from": "2026-08-16T12:00:00Z", "retroactive": true },
        });
        assert!(emit(dir.path(), &payload, None).is_err());
    }

    #[test]
    fn a_correction_must_name_its_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = json!({
            "ahl_version": "0.3", "type": "correction", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "dataset": "customers",
            "record": commitment(0x22), "replacement": commitment(0x23),
            "reason_code": "error",
            "scope": { "effective_from": "2026-08-16T12:00:00Z", "retroactive": false },
        });
        assert!(emit(dir.path(), &payload, None).is_ok());
        payload.as_object_mut().expect("object").remove("replacement");
        assert!(emit(dir.path(), &payload, None).is_err());
    }

    #[test]
    fn a_derivation_carries_either_outputs_or_a_batch_commitment_never_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = json!({
            "ahl_version": "0.3", "type": "derivation", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "pipeline": "scoring-v1",
            "inputs": [ { "dataset": "customers", "record": commitment(0x22) } ],
            "transform": { "code": { "digest": commitment(0x31), "type": "git_commit" } },
        });

        let mut inline = base.clone();
        inline["outputs"] = json!([ { "dataset": "scores", "record": commitment(0x41) } ]);
        assert!(emit(dir.path(), &inline, None).is_ok());

        let mut batch = base.clone();
        batch["outputs_root"] = json!(commitment(0x51));
        batch["outputs_count"] = json!(3);
        batch["leaf_format"] = json!("ahl-leaf-v2");
        assert!(emit(dir.path(), &batch, None).is_ok());

        let mut both = inline.clone();
        both["outputs_root"] = json!(commitment(0x51));
        assert!(emit(dir.path(), &both, None).is_err());

        assert!(emit(dir.path(), &base, None).is_err(), "neither form is refused");

        let mut wrong_leaf = batch;
        wrong_leaf["leaf_format"] = json!("ahl-leaf-v1");
        assert!(emit(dir.path(), &wrong_leaf, None).is_err());
    }

    #[test]
    fn every_derivation_input_names_the_record_a_trigger_would_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = json!({
            "ahl_version": "0.3", "type": "derivation", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "pipeline": "scoring-v1",
            "inputs": [ { "dataset": "customers" } ],
            "outputs": [ { "dataset": "scores", "record": commitment(0x41) } ],
            "transform": {},
        });
        let error = emit(dir.path(), &payload, None).expect_err("input without a record");
        assert!(error.to_string().contains("`record`"), "{error}");
    }

    #[test]
    fn non_canonical_commitment_strings_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = ingestion();
        payload["record"] = json!("sha256:aa");
        let error = emit(dir.path(), &payload, None).expect_err("short digest");
        assert!(error.to_string().contains("canonical commitment"), "{error}");
        payload["record"] = json!(format!("sha256:{}", "AA".repeat(32)));
        assert!(emit(dir.path(), &payload, None).is_err(), "uppercase hex is not canonical");
    }

    #[test]
    fn valid_time_accepts_a_point_or_an_interval_and_refuses_anything_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = ingestion();
        payload["valid_time"] = json!({ "from": "2026-08-16T12:00:00Z", "to": null });
        assert!(emit(dir.path(), &payload, None).is_ok());
        payload["valid_time"] = json!({ "from": "2026-08-16T12:00:00Z", "to": "2026-09-01T00:00:00Z" });
        assert!(emit(dir.path(), &payload, None).is_ok());

        for bad in [
            json!({ "from": "2026-08-16T12:00:00Z" }),
            json!({ "to": null }),
            json!({ "from": "yesterday", "to": null }),
            json!({ "from": "2026-08-16T12:00:00Z", "to": 7 }),
            json!(7),
            json!("yesterday"),
        ] {
            payload["valid_time"] = bad.clone();
            assert!(emit(dir.path(), &payload, None).is_err(), "`{bad}` must be refused");
        }
    }

    #[test]
    fn a_propagation_names_its_declared_checkpoint_in_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = json!({
            "ahl_version": "0.3", "type": "propagation", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "trigger": commitment(0x61),
            "corpus_checkpoint": { "log_id": commitment(0x71), "tree_size": 8,
                                   "root_hash": commitment(0x81) },
            "affected_root": commitment(0x91), "affected_count": 4,
            "complete_relative_to_manifest": true,
        });
        assert!(emit(dir.path(), &base, None).is_ok());
        for member in ["log_id", "tree_size", "root_hash"] {
            let mut payload = base.clone();
            payload["corpus_checkpoint"].as_object_mut().expect("object").remove(member);
            assert!(emit(dir.path(), &payload, None).is_err(), "`{member}` is required");
        }
        for member in ["trigger", "affected_root", "affected_count", "complete_relative_to_manifest"]
        {
            let mut payload = base.clone();
            payload.as_object_mut().expect("object").remove(member);
            assert!(emit(dir.path(), &payload, None).is_err(), "`{member}` is required");
        }
    }

    #[test]
    fn a_key_statement_names_a_registered_action_and_a_complete_key_object() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = json!({
            "ahl_version": "0.3", "type": "key", "producer": "p",
            "manifest": commitment(0x11), "valid_time": "2026-08-16T12:00:00Z",
            "issued_at": "2026-08-16T12:00:00Z", "action": "add",
            "key": { "key_id": commitment(0xa1), "pubkey": "base64:AAAA", "valid_from": 9 },
        });
        assert!(emit(dir.path(), &base, None).is_ok());
        let mut retire = base.clone();
        retire["action"] = json!("retire");
        assert!(emit(dir.path(), &retire, None).is_ok());
        let mut borrowed = base.clone();
        borrowed["action"] = json!("borrow");
        assert!(emit(dir.path(), &borrowed, None).is_err());
        for member in ["key_id", "pubkey", "valid_from"] {
            let mut payload = base.clone();
            payload["key"].as_object_mut().expect("object").remove(member);
            assert!(emit(dir.path(), &payload, None).is_err(), "`{member}` is required");
        }
    }

    #[test]
    fn output_is_installed_atomically_and_never_clobbers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("statement.json");
        let emitted =
            emit(dir.path(), &ingestion(), Some(out.clone())).expect("emitted");
        assert_eq!(emitted.written_to.as_deref(), Some(out.display().to_string().as_str()));
        // The file is exactly the canonical entry bytes: what the log anchors, nothing else.
        assert_eq!(std::fs::read(&out).expect("read"), ahl_core::jcs(&emitted.envelope));

        let error = emit(dir.path(), &ingestion(), Some(out)).expect_err("clobber refused");
        assert!(error.to_string().contains("--force"), "{error}");
    }

    #[test]
    fn a_payload_that_is_not_an_object_or_not_json_is_malformed() {
        let dir = tempfile::tempdir().expect("tempdir");
        for bytes in [b"[]".as_slice(), b"{oops".as_slice()] {
            let path = dir.path().join("p.json");
            std::fs::write(&path, bytes).expect("write");
            let result = run(
                LocalLimits::default(),
                &Options {
                    payload: path,
                    key: key_source(dir.path()),
                    out: None,
                    force: false,
                },
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn a_wrong_ahl_version_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut payload = ingestion();
        payload["ahl_version"] = json!("0.2");
        assert!(emit(dir.path(), &payload, None).is_err());
    }

    #[test]
    fn the_supported_type_list_is_the_seven_statement_types() {
        assert_eq!(supported_statement_types().len(), 7);
        assert!(supported_statement_types().contains("propagation"));
    }
}
