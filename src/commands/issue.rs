//! `issue` — assemble an AHL Evidence Receipt from a live log, mirror and witness set.
//!
//! The producer's verb. `emit` signs a candidate envelope, `issue` gets it anchored and turns
//! what the stack answers with into a receipt, and `verify` judges the result. The division is
//! deliberate and is stated in the output: **`issue` establishes nothing.** It performs the
//! checks assembly needs and no others, and a receipt it produced is not evidence of anything
//! until `verify` has read it under a policy.
//!
//! # Network
//!
//! Design note §7 applies unchanged: HTTPS only, no redirects, budgets counted after
//! decompression. Plain `http://` reaches a loopback peer only, and `issue` additionally
//! refuses it unless `--allow-insecure-loopback` says the operator meant it — the transport's
//! resolved-peer rule stops a plain-HTTP request from leaving the machine, while the flag stops
//! one from being made by accident.

use std::fmt::Write as _;
use std::net::ToSocketAddrs as _;
use std::path::{Path, PathBuf};

use ahl_core::{entry_id, jcs};
use serde::Serialize;
use serde_json::{json, Value};

use crate::error::{CliError, CliResult};
use crate::install::{self, Force};
use crate::net::Fetcher;
use crate::policy::LocalLimits;
use crate::producer::{self, set, Assembly, Claim, ContentBinding, Endpoints};
use crate::secure;

/// The standing statement of what this output is not.
const BOUNDARY: &str = "This is an assembled Evidence Receipt, not a verified one. `issue` \
                        performs only the checks assembly needs — that the log anchored the \
                        bytes submitted, and that the enumerated prefix recomputes the root the \
                        checkpoint commits. It evaluates no claim-type rule, no governance \
                        walk, and no signature beyond those. Run `ahl-cli verify` against a \
                        local policy before relying on this file.";

/// What `issue` was asked to do.
pub struct Options {
    /// The signed envelope, as `emit` wrote it.
    pub envelope: PathBuf,
    /// The claim type to assemble.
    pub claim: String,
    /// The subject record's dataset, where the claim type requires one.
    pub dataset: Option<String>,
    /// The subject record's commitment.
    pub record: Option<String>,
    /// Record bytes to carry as content-binding evidence.
    pub record_bytes: Option<PathBuf>,
    /// The dataset's canonicalization identifier, carried beside the bytes.
    pub canonicalization: Option<String>,
    /// The media type, where the descriptor requires one.
    pub media_type: Option<String>,
    /// An embedded introduction receipt.
    pub introduction: Option<PathBuf>,
    /// An embedded introduction receipt for a correction's replacement.
    pub replacement_introduction: Option<PathBuf>,
    /// An embedded trigger receipt.
    pub trigger: Option<PathBuf>,
    /// Committed tree material, as a root-to-leaves JSON map.
    pub tree_material: Option<PathBuf>,
    /// The entry index a `governance-state` claim is about.
    pub target_index: Option<u64>,
    /// The receipt's informative note.
    pub note: Option<String>,
    /// Permit plain HTTP to a loopback peer.
    pub allow_insecure_loopback: bool,
    /// Where to install the receipt.
    pub out: PathBuf,
    /// Replace an existing destination. Still a no-replace install.
    pub force: bool,
}

/// What one `issue` run produced.
#[derive(Debug, Serialize)]
pub struct Issued {
    /// The standing statement of what this output is not.
    pub boundary: &'static str,
    /// The claim type assembled.
    pub claim_type: String,
    /// The subject's entry index in the bound Data Tree.
    pub entry_index: u64,
    /// The ATL identifier the log assigned, where this run submitted the entry. The log's own
    /// retrieval key, never an AHL identifier (adaptor §10.1.1).
    pub atl_entry_id: Option<String>,
    /// Whether this run anchored the subject or found it already anchored.
    pub anchored_now: bool,
    /// The `log_id` the checkpoint carries.
    pub log_id: String,
    /// The checkpoint's tree size.
    pub tree_size: u64,
    /// Governance currency mode.
    pub governance: &'static str,
    /// Witness identities whose cosignatures the receipt carries.
    pub witnesses: Vec<String>,
    /// Where the receipt was installed.
    pub written_to: String,
}

impl Issued {
    /// Render the stable JSON form.
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
        let _ = writeln!(out, "{BOUNDARY}\n");
        let _ = writeln!(out, "claim type: {}", self.claim_type);
        let _ = writeln!(out, "governance: {}", self.governance);
        let _ = writeln!(out, "log id: {}", self.log_id);
        let _ = writeln!(
            out,
            "entry index: {} ({})",
            self.entry_index,
            if self.anchored_now { "anchored by this run" } else { "already anchored" }
        );
        if let Some(atl_entry_id) = &self.atl_entry_id {
            let _ = writeln!(out, "ATL entry id: {atl_entry_id}");
        }
        let _ = writeln!(out, "checkpoint tree size: {}", self.tree_size);
        let _ = writeln!(
            out,
            "witness cosignatures carried: {}",
            if self.witnesses.is_empty() { "none".to_owned() } else { self.witnesses.join(", ") }
        );
        let _ = writeln!(out, "receipt written to: {}", self.written_to);
        out
    }
}

/// Refuse a plain-HTTP endpoint the operator did not opt into, and one that is not loopback.
///
/// The transport checks the **resolved peer** per connection, which is what closes DNS
/// rebinding; this check exists for a different reason — so that reaching a plain-HTTP endpoint
/// is always a thing the operator asked for, never a default.
fn check_endpoint(url: &str, allow_loopback: bool) -> CliResult<()> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Ok(());
    };
    if !allow_loopback {
        return Err(CliError::Usage(format!(
            "`{url}` is plain HTTP; pass `--allow-insecure-loopback` to say so deliberately. It \
             is accepted for a loopback peer only, and never as a default"
        )));
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let with_port =
        if authority.contains(':') { authority.to_owned() } else { format!("{authority}:80") };
    let addresses = with_port
        .to_socket_addrs()
        .map_err(|source| CliError::Usage(format!("`{url}` does not resolve: {source}")))?;
    let mut any = false;
    for address in addresses {
        any = true;
        if !address.ip().is_loopback() {
            return Err(CliError::Usage(format!(
                "`{url}` resolves to {}, which is not loopback; `--allow-insecure-loopback` \
                 permits plain HTTP to a loopback peer and nothing else",
                address.ip()
            )));
        }
    }
    if any {
        Ok(())
    } else {
        Err(CliError::Usage(format!("`{url}` resolves to no address")))
    }
}

/// Read a `.ahl` receipt to embed, as the JSON object it is.
fn embedded(path: &Path, what: &'static str, limits: LocalLimits) -> CliResult<Value> {
    let bytes = secure::read_regular(what, path, limits.max_file_bytes)?;
    serde_json::from_slice(&bytes).map_err(|source| {
        CliError::Usage(format!("`{}` is not a receipt: {source}", path.display()))
    })
}

/// Build the type-specific `claim_material` from the files the caller supplied.
///
/// What comes from the LOG — enumeration ranges, the declared checkpoint, inclusion paths — is
/// filled in later from the published state; this is only the part a producer holds.
fn material(options: &Options, limits: LocalLimits) -> CliResult<Value> {
    let mut material = json!({});
    if let Some(path) = &options.introduction {
        set(&mut material, "introduction", embedded(path, "introduction receipt", limits)?)?;
    }
    if let Some(path) = &options.replacement_introduction {
        set(
            &mut material,
            "replacement_introduction",
            embedded(path, "replacement introduction receipt", limits)?,
        )?;
    }
    if let Some(path) = &options.trigger {
        set(&mut material, "trigger", embedded(path, "trigger receipt", limits)?)?;
    }
    if let Some(path) = &options.tree_material {
        let bytes = secure::read_regular("tree material", path, limits.max_file_bytes)?;
        let trees: Value = serde_json::from_slice(&bytes).map_err(|source| {
            CliError::Usage(format!("`{}` is not tree material: {source}", path.display()))
        })?;
        set(&mut material, "trees", trees)?;
    }
    if let Some(index) = options.target_index {
        set(&mut material, "target_index", json!(index))?;
    }
    Ok(material)
}

/// Assemble one receipt against a live stack.
///
/// # Errors
///
/// [`CliError::Usage`] for a request the CLI refuses to attempt, [`CliError::EvidenceMissing`]
/// where the stack did not supply what assembly needs, and [`CliError::Output`] where the
/// receipt could not be installed.
pub fn run<F: Fetcher>(
    fetcher: &F,
    limits: LocalLimits,
    endpoints: &Endpoints,
    options: &Options,
) -> CliResult<Issued> {
    let shape = producer::claim_shape(&options.claim)?;
    for url in std::iter::once(&endpoints.log)
        .chain(std::iter::once(&endpoints.mirror))
        .chain(endpoints.witnesses.iter())
    {
        check_endpoint(url, options.allow_insecure_loopback)?;
    }
    if endpoints.witnesses.is_empty() {
        return Err(CliError::Usage(
            "no witness endpoint is configured; a receipt carrying no cosignature raises no \
             assurance, and `issue` does not assemble one silently"
                .to_owned(),
        ));
    }

    let envelope = read_envelope(&options.envelope, limits)?;
    let entry = entry_id(&envelope);

    // Idempotent by construction: an entry the mirror already holds at a proven index is not
    // submitted again. Retrieval is content-addressed (adaptor §10.1.1), so this cannot resolve
    // to somebody else's entry, and absence is unavailability rather than a negative result.
    let (position, anchored_now) =
        if let Some(index) = producer::published_index(fetcher, &endpoints.mirror, &entry)? {
            (publish_existing(fetcher, endpoints, index)?, false)
        } else {
            let position = producer::anchor(fetcher, &endpoints.log, &envelope)?;
            producer::stage(fetcher, &endpoints.mirror, &envelope)?;
            producer::ingest_checkpoint(fetcher, &endpoints.mirror, &position, &entry)?;
            (position, true)
        };
    let size =
        position.checkpoint.get("tree_size").and_then(Value::as_u64).ok_or_else(|| {
            CliError::EvidenceMissing("the checkpoint has no tree size".to_owned())
        })?;
    let log_id = position
        .checkpoint
        .get("log_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::EvidenceMissing("the checkpoint has no log id".to_owned()))?
        .to_owned();

    let prefix = producer::enumerate(fetcher, &endpoints.mirror, size, size)?;
    let mut cosignatures = Vec::new();
    for witness in &endpoints.witnesses {
        let answer = producer::cosign(fetcher, witness, &log_id, &position, &prefix.entries)?;
        cosignatures.push(producer::cosignature_entry(&answer)?);
    }
    let governance = producer::Governance::read(&prefix.entries);
    let (_, active) = governance.active_for_checkpoint(size)?;
    let (carried, outgoing) = producer::split_cosignatures(cosignatures, active);
    let witnesses: Vec<String> = carried
        .iter()
        .filter_map(|entry| entry.get("witness_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();

    let assembly = Assembly::new(position.checkpoint.clone(), prefix, carried, outgoing)?;
    // The index came from the mirror. Now that the prefix has been checked against the root the
    // log signed, the entry at that index must be the one whose bytes were handed over — or the
    // receipt would be about a different statement.
    assembly.require_subject(position.entry_index, &entry)?;
    // Two sources, one geometry. The log served an inclusion proof with its Evidence Receipt;
    // the mirror served the entries. Recomputing the path from the mirror's enumeration and
    // comparing it with the log's proof is the one place those two independently obtained
    // bodies of material are made to agree, and a deployment where they do not is one this
    // refuses to issue a receipt against.
    if !position.inclusion_path.is_empty()
        && assembly.inclusion_path(position.entry_index)? != position.inclusion_path
    {
        return Err(CliError::EvidenceMissing(format!(
            "the inclusion path the log served for entry {} does not match the one recomputed \
             from the entries the mirror enumerated under the same checkpoint",
            position.entry_index
        )));
    }

    let content = content_binding(options, limits)?;
    let record_subject = record_subject(options)?;
    let claim = Claim {
        claim_type: options.claim.clone(),
        record_subject,
        content,
        material: complete_material(
            fetcher,
            endpoints,
            &assembly,
            position.entry_index,
            &options.claim,
            options,
            material(options, limits)?,
        )?,
        note: options.note.clone().unwrap_or_else(|| {
            format!(
                "Assembled by `ahl-cli issue` from a live {} deployment. No verification result \
                 attaches to assembly.",
                crate::checkpoint::ATL_PROFILE
            )
        }),
    };

    let receipt = producer::assemble(&assembly, position.entry_index, &claim)?;
    let canonical = jcs(&receipt);
    install::install(&options.out, &canonical, if options.force { Force::Yes } else { Force::No })?;

    Ok(Issued {
        boundary: BOUNDARY,
        claim_type: options.claim.clone(),
        entry_index: position.entry_index,
        atl_entry_id: position.atl_entry_id,
        anchored_now,
        log_id,
        tree_size: size,
        governance: shape.governance,
        witnesses,
        written_to: options.out.display().to_string(),
    })
}

/// Read the signed envelope `emit` wrote, insisting on the canonical bytes.
///
/// The anchored entry IS `JCS(envelope)` (adaptor §4.1), so a file that is not already canonical
/// would anchor a different entry from the one it appears to carry.
fn read_envelope(path: &Path, limits: LocalLimits) -> CliResult<Value> {
    let bytes = secure::read_regular("signed envelope", path, limits.max_file_bytes)?;
    let envelope: Value = serde_json::from_slice(&bytes).map_err(|source| {
        CliError::Usage(format!("`{}` is not an envelope: {source}", path.display()))
    })?;
    if jcs(&envelope) == bytes {
        Ok(envelope)
    } else {
        Err(CliError::Usage(format!(
            "`{}` is not JCS-canonical; the anchored entry is the canonical bytes, so anchoring \
             a re-serialization would anchor a different entry",
            path.display()
        )))
    }
}

/// The content-binding evidence the caller supplied, where they supplied any.
///
/// The two members travel together: bytes without a descriptor prove nothing, and a descriptor
/// without bytes describes nothing (I-D §7.2).
fn content_binding(options: &Options, limits: LocalLimits) -> CliResult<Option<ContentBinding>> {
    match (&options.record_bytes, &options.canonicalization) {
        (Some(path), Some(canonicalization)) => Ok(Some(ContentBinding {
            bytes: secure::read_regular("record bytes", path, limits.max_file_bytes)?,
            canonicalization: canonicalization.clone(),
            media_type: options.media_type.clone(),
            // The pilot's datasets commit in `plain` mode. A keyed dataset's commitment cannot
            // be recomputed without the dataset key, and this build does not hold one.
            binding: "plain-verified",
        })),
        (None, None) => Ok(None),
        _ => Err(CliError::Usage(
            "`--record-bytes` and `--canonicalization` are carried together: the bytes without a \
             descriptor prove nothing, and a descriptor without bytes describes nothing (I-D \
             §7.2)"
                .to_owned(),
        )),
    }
}

/// The record subject the caller named, where the claim type takes one.
fn record_subject(options: &Options) -> CliResult<Option<(String, String)>> {
    match (&options.dataset, &options.record) {
        (Some(dataset), Some(record)) => Ok(Some((dataset.clone(), record.clone()))),
        (None, None) => Ok(None),
        _ => Err(CliError::Usage(
            "`--dataset` and `--record` name one record subject and are given together".to_owned(),
        )),
    }
}

/// The published position of an entry already anchored, taken from the mirror's newest
/// checkpoint rather than from a fresh submission.
fn publish_existing<F: Fetcher>(
    fetcher: &F,
    endpoints: &Endpoints,
    entry_index: u64,
) -> CliResult<producer::LogPosition> {
    let checkpoint = producer::newest_checkpoint(fetcher, &endpoints.mirror)?;
    let size = checkpoint
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| CliError::EvidenceMissing("the checkpoint has no tree size".to_owned()))?;
    if entry_index >= size {
        return Err(CliError::EvidenceMissing(format!(
            "entry {entry_index} is not committed by the newest checkpoint the mirror publishes, \
             whose tree size is {size}"
        )));
    }
    let raw = producer::checkpoint_raw(&checkpoint)?;
    // The inclusion path is recomputed from the enumerated prefix during assembly; a path
    // carried here would be a second, unchecked copy of it.
    Ok(producer::LogPosition {
        atl_entry_id: None,
        entry_index,
        checkpoint,
        raw,
        inclusion_path: Vec::new(),
    })
}

/// Fill in the parts of `claim_material` that come from the published state rather than from
/// the producer's own files.
///
/// `trigger-effective` needs its competing-trigger range and the checkpoint it is bounded at;
/// `propagation-complete` needs the declared checkpoint D and the prefix `[0, tree_size(D))`.
/// Both are enumerations under the receipt's own checkpoint, so both come from the mirror.
fn complete_material<F: Fetcher>(
    fetcher: &F,
    endpoints: &Endpoints,
    assembly: &Assembly,
    subject_index: u64,
    claim_type: &str,
    options: &Options,
    mut material: Value,
) -> CliResult<Value> {
    let size = assembly.size()?;
    // What the producer's committed trees supply: the batch output leaf a `record-derived`
    // claim opens, and the disposition leaf a `disposition-*` claim opens. Both are keyed by
    // the record subject, so no flag names a leaf index a caller could get wrong.
    if let (Some(trees), Some((dataset, record))) =
        (material.get("trees").cloned(), record_subject(options)?)
    {
        let subject = assembly.entry(subject_index)?.clone();
        let payload = subject.get("payload").cloned().unwrap_or(Value::Null);
        let mut derived = producer::leaf_material(claim_type, &payload, &trees, &record, &dataset)?;
        let members: Vec<(String, Value)> = producer::object_mut(&mut derived)?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (member, value) in members {
            set(&mut material, &member, value)?;
        }
    }
    match claim_type {
        "trigger-effective" => {
            set(&mut material, "checkpoint_C", assembly.checkpoint().clone())?;
            let competing = json!({
                "corpus_range":
                    producer::enumerate(fetcher, &endpoints.mirror, size, size)?.material,
            });
            set(&mut material, "competing", competing)?;
        }
        "propagation-complete" => {
            let declared_size = assembly
                .entry(subject_index)?
                .pointer("/payload/corpus_checkpoint/tree_size")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    CliError::Usage(
                        "a `propagation-complete` subject declares a `corpus_checkpoint` with a \
                         tree size, and this one does not"
                            .to_owned(),
                    )
                })?;
            let declared =
                producer::signed_checkpoint_at(fetcher, &endpoints.mirror, declared_size)?;
            set(&mut material, "corpus_checkpoint", declared)?;
            let prefix =
                producer::enumerate(fetcher, &endpoints.mirror, size, declared_size)?.material;
            set(&mut material, "corpus_prefix", prefix)?;
        }
        _ => {}
    }
    Ok(material)
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

    #[test]
    fn plain_http_needs_the_flag_and_the_flag_does_not_reach_off_loopback() {
        let error = check_endpoint("http://127.0.0.1:8080", false).expect_err("no flag");
        assert!(error.to_string().contains("--allow-insecure-loopback"), "{error}");
        check_endpoint("http://127.0.0.1:8080", true).expect("a loopback peer");
        // IANA's example range: never loopback, and never connected to, because the refusal
        // happens on the resolved address before any socket is opened.
        let error = check_endpoint("http://93.184.215.14:80", true).expect_err("off loopback");
        assert!(error.to_string().contains("not loopback"), "{error}");
    }

    #[test]
    fn https_needs_no_flag() {
        check_endpoint("https://mirror.example", false).expect("HTTPS is the default");
    }

    // ------------------------------------------------------------------
    // The whole verb, against a scripted log, mirror and witness.
    // ------------------------------------------------------------------

    use crate::scripted;

    /// The three addresses a run is pointed at.
    fn endpoints() -> Endpoints {
        Endpoints {
            log: scripted::LOG.to_owned(),
            mirror: scripted::MIRROR.to_owned(),
            witnesses: vec![scripted::WITNESS.to_owned()],
        }
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("a writable working directory");
        path
    }

    /// A request with every optional input unset, so a test names only what it is about.
    fn options(dir: &Path, envelope: PathBuf, claim: &str) -> Options {
        Options {
            envelope,
            claim: claim.to_owned(),
            dataset: None,
            record: None,
            record_bytes: None,
            canonicalization: None,
            media_type: None,
            introduction: None,
            replacement_introduction: None,
            trigger: None,
            tree_material: None,
            target_index: None,
            note: None,
            allow_insecure_loopback: false,
            out: dir.join("receipt.ahl"),
            force: false,
        }
    }

    /// A run against `stack`, about the entry the stack is set to be about.
    fn issue_against(
        stack: &scripted::Stack,
        dir: &Path,
        claim: &str,
        adjust: impl FnOnce(&mut Options),
    ) -> CliResult<Issued> {
        let envelope = write(dir, "envelope.json", &stack.entry_bytes(stack.subject_index));
        let mut options = options(dir, envelope, claim);
        adjust(&mut options);
        run(stack, LocalLimits::default(), &endpoints(), &options)
    }

    /// The receipt one run installed, parsed back.
    fn installed(dir: &Path) -> Value {
        let bytes = std::fs::read(dir.join("receipt.ahl")).expect("an installed receipt");
        assert_eq!(jcs(&serde_json::from_slice::<Value>(&bytes).unwrap()), bytes, "canonical");
        serde_json::from_slice(&bytes).expect("a JSON receipt")
    }

    #[test]
    fn a_fresh_entry_is_anchored_staged_promoted_and_then_assembled() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new();
        let issued = issue_against(&stack, dir.path(), "statement-anchored", |_| {})
            .expect("the scripted deployment answers everything assembly needs");

        assert!(issued.anchored_now, "the mirror held nothing, so this run anchored it");
        assert_eq!(issued.entry_index, scripted::APPENDED);
        assert_eq!(issued.atl_entry_id.as_deref(), Some(scripted::ATL_ENTRY_ID));
        assert_eq!(issued.log_id, scripted::log_id());
        assert_eq!(issued.tree_size, stack.size());
        assert_eq!(issued.governance, "declared");
        assert_eq!(issued.witnesses, vec![scripted::WITNESS_ID.to_owned()]);
        assert!(issued.written_to.ends_with("receipt.ahl"));

        let receipt = installed(dir.path());
        assert_eq!(receipt.pointer("/claim/type"), Some(&json!("statement-anchored")));
        assert_eq!(receipt.pointer("/subject/entry_index"), Some(&json!(scripted::APPENDED)));
        assert_eq!(
            receipt.pointer("/anchoring/checkpoint/root_hash"),
            stack.checkpoint().get("root_hash")
        );
        assert!(
            receipt.pointer("/claim/note").and_then(Value::as_str).unwrap().contains("issue"),
            "the default note says where the receipt came from"
        );

        let text = issued.to_text();
        assert!(text.contains("not a verified one"), "{text}");
        assert!(text.contains("anchored by this run"), "{text}");
        assert!(text.contains("ATL entry id"), "{text}");
        assert!(text.contains(scripted::WITNESS_ID), "{text}");
        let rendered = issued.to_json().expect("a JSON report");
        assert!(rendered.contains("\"anchored_now\": true"), "{rendered}");
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn an_entry_the_mirror_already_holds_is_placed_rather_than_submitted_again() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::INGESTION);
        let issued = issue_against(&stack, dir.path(), "statement-anchored", |_| {})
            .expect("an already-anchored entry needs no second submission");

        assert!(!issued.anchored_now);
        assert_eq!(issued.entry_index, scripted::INGESTION);
        assert!(
            issued.atl_entry_id.is_none(),
            "no submission was made, so the log assigned no identifier in this run"
        );
        let text = issued.to_text();
        assert!(text.contains("already anchored"), "{text}");
        assert!(!text.contains("ATL entry id"), "{text}");
    }

    #[test]
    fn a_claim_type_the_build_does_not_assemble_is_refused_before_anything_is_fetched() {
        let dir = tempfile::tempdir().expect("a working directory");
        let envelope = write(dir.path(), "envelope.json", b"{}");
        let error = run(
            &scripted::Unreachable,
            LocalLimits::default(),
            &endpoints(),
            &options(dir.path(), envelope, "record-invented"),
        )
        .expect_err("not a registry id");
        assert!(error.to_string().contains("is not a claim type"), "{error}");
    }

    #[test]
    fn a_run_with_no_witness_endpoint_assembles_nothing_silently() {
        let dir = tempfile::tempdir().expect("a working directory");
        let envelope = write(dir.path(), "envelope.json", b"{}");
        let mut endpoints = endpoints();
        endpoints.witnesses.clear();
        let error = run(
            &scripted::Unreachable,
            LocalLimits::default(),
            &endpoints,
            &options(dir.path(), envelope, "statement-anchored"),
        )
        .expect_err("a receipt carrying no cosignature raises no assurance");
        assert!(error.to_string().contains("no witness endpoint is configured"), "{error}");
    }

    #[test]
    fn plain_http_is_refused_for_every_endpoint_the_run_would_reach() {
        let dir = tempfile::tempdir().expect("a working directory");
        let envelope = write(dir.path(), "envelope.json", b"{}");
        for endpoints in [
            Endpoints {
                log: "http://127.0.0.1:8080".to_owned(),
                mirror: scripted::MIRROR.to_owned(),
                witnesses: vec![scripted::WITNESS.to_owned()],
            },
            Endpoints {
                log: scripted::LOG.to_owned(),
                mirror: "http://127.0.0.1:8080".to_owned(),
                witnesses: vec![scripted::WITNESS.to_owned()],
            },
            Endpoints {
                log: scripted::LOG.to_owned(),
                mirror: scripted::MIRROR.to_owned(),
                witnesses: vec!["http://127.0.0.1:8080".to_owned()],
            },
        ] {
            let error = run(
                &scripted::Unreachable,
                LocalLimits::default(),
                &endpoints,
                &options(dir.path(), envelope.clone(), "statement-anchored"),
            )
            .expect_err("plain HTTP is never a default");
            assert!(error.to_string().contains("--allow-insecure-loopback"), "{error}");
        }
    }

    #[test]
    fn the_loopback_opt_in_is_checked_on_the_address_and_not_on_the_text() {
        // A path after the authority, and a default port where the URL names none: both are
        // the same loopback peer, and both are what the flag permits.
        check_endpoint("http://127.0.0.1/v1/anchor", true).expect("a loopback peer");
        check_endpoint("http://[::1]:8080", true).expect("loopback over IPv6 too");
        let error = check_endpoint("http://127.0.0.1:notaport", true).expect_err("no address");
        assert!(error.to_string().contains("does not resolve"), "{error}");
    }

    #[test]
    fn an_envelope_that_is_not_the_bytes_it_appears_to_carry_anchors_nothing() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new();

        let loose = write(dir.path(), "loose.json", b"{ \"payload\": {}, \"signatures\": [] }");
        let error = run(
            &stack,
            LocalLimits::default(),
            &endpoints(),
            &options(dir.path(), loose, "statement-anchored"),
        )
        .expect_err("a re-serialization anchors a different entry");
        assert!(error.to_string().contains("not JCS-canonical"), "{error}");

        let garbage = write(dir.path(), "garbage.json", b"not json");
        let error = run(
            &stack,
            LocalLimits::default(),
            &endpoints(),
            &options(dir.path(), garbage, "statement-anchored"),
        )
        .expect_err("not an envelope at all");
        assert!(error.to_string().contains("is not an envelope"), "{error}");
    }

    #[test]
    fn the_flags_that_name_one_thing_between_them_are_given_together() {
        let dir = tempfile::tempdir().expect("a working directory");
        let bytes = write(dir.path(), "record.json", b"{\"a\":1}");
        let stack = scripted::Stack::new().already_published().about(scripted::INGESTION);

        let error = issue_against(&stack, dir.path(), "record-ingested", |options| {
            options.record_bytes = Some(bytes.clone());
            options.dataset = Some(scripted::DATASET.to_owned());
            options.record = Some(scripted::RECORD.to_owned());
        })
        .expect_err("bytes without a descriptor prove nothing");
        assert!(error.to_string().contains("carried together"), "{error}");

        let error = issue_against(&stack, dir.path(), "record-ingested", |options| {
            options.canonicalization = Some("jcs".to_owned());
            options.dataset = Some(scripted::DATASET.to_owned());
            options.record = Some(scripted::RECORD.to_owned());
        })
        .expect_err("a descriptor without bytes describes nothing");
        assert!(error.to_string().contains("carried together"), "{error}");

        let error = issue_against(&stack, dir.path(), "record-ingested", |options| {
            options.dataset = Some(scripted::DATASET.to_owned());
        })
        .expect_err("half a record subject");
        assert!(error.to_string().contains("name one record subject"), "{error}");
    }

    #[test]
    fn a_witness_refusal_stops_the_run_rather_than_being_carried_as_assurance() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().with_refusing_witness();
        let error = issue_against(&stack, dir.path(), "statement-anchored", |_| {})
            .expect_err("a refusal is evidence about the log, not assurance about the entry");
        assert!(error.to_string().contains("refused to cosign"), "{error}");
    }

    #[test]
    fn the_two_bodies_of_material_are_made_to_agree_on_one_geometry() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().with_crooked_path();
        let error = issue_against(&stack, dir.path(), "statement-anchored", |_| {})
            .expect_err("the log's proof and the mirror's entries describe different trees");
        assert!(error.to_string().contains("does not match the one recomputed"), "{error}");
    }

    #[test]
    fn a_record_derived_receipt_opens_the_batch_tree_the_producer_committed() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::DERIVATION);
        let trees = write(
            dir.path(),
            "trees.json",
            &serde_json::to_vec(&scripted::tree_material()).unwrap(),
        );
        let bytes = write(dir.path(), "record.json", b"{\"a\":1}");
        issue_against(&stack, dir.path(), "record-derived", |options| {
            options.dataset = Some(scripted::DATASET.to_owned());
            options.record = Some(scripted::RECORD.to_owned());
            options.tree_material = Some(trees);
            options.record_bytes = Some(bytes);
            options.canonicalization = Some("jcs".to_owned());
            options.media_type = Some("application/json".to_owned());
            options.note = Some("a note the operator wrote".to_owned());
        })
        .expect("the producer's own tree material completes the claim");

        let receipt = installed(dir.path());
        assert_eq!(receipt.pointer("/claim/note"), Some(&json!("a note the operator wrote")));
        assert_eq!(receipt.pointer("/claim_material/leaf_index"), Some(&json!(1)));
        assert!(receipt.pointer("/claim_material/batch_leaf").is_some());
        assert_eq!(
            receipt
                .pointer("/claim_material/input_members")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            receipt.pointer("/claim_material/canonicalization"),
            Some(&json!("jcs")),
            "the descriptor travels with the bytes it interprets"
        );
    }

    #[test]
    fn a_trigger_effective_receipt_carries_the_competing_range_it_was_bounded_at() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::TRIGGER);
        let issued = issue_against(&stack, dir.path(), "trigger-effective", |options| {
            options.dataset = Some(scripted::DATASET.to_owned());
            options.record = Some(scripted::RECORD.to_owned());
        })
        .expect("an enumerated-mode claim over the published prefix");
        assert_eq!(issued.governance, "enumerated");

        let receipt = installed(dir.path());
        assert_eq!(
            receipt.pointer("/claim_material/checkpoint_C/tree_size"),
            Some(&json!(stack.size()))
        );
        assert_eq!(
            receipt.pointer("/claim_material/competing/corpus_range/range/to_index"),
            Some(&json!(stack.size()))
        );
    }

    #[test]
    fn a_propagation_complete_receipt_carries_the_declared_checkpoint_and_its_prefix() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::PROPAGATION);
        issue_against(&stack, dir.path(), "propagation-complete", |_| {})
            .expect("the declared checkpoint is a published member");

        let receipt = installed(dir.path());
        assert_eq!(receipt.pointer("/claim_material/corpus_checkpoint/tree_size"), Some(&json!(3)));
        assert_eq!(
            receipt.pointer("/claim_material/corpus_prefix/range/to_index"),
            Some(&json!(3)),
            "the prefix is `[0, tree_size(D))` of the checkpoint the subject declares"
        );
    }

    #[test]
    fn a_propagation_declaring_no_corpus_checkpoint_completes_nothing() {
        let dir = tempfile::tempdir().expect("a working directory");
        let mut entries = scripted::corpus();
        entries[usize::try_from(scripted::PROPAGATION).unwrap()] = scripted::envelope(
            scripted::statement("propagation", json!({ "affected_root": scripted::AFFECTED_ROOT })),
        );
        let stack = scripted::Stack::over(entries, scripted::PROPAGATION).already_published();
        let error = issue_against(&stack, dir.path(), "propagation-complete", |_| {})
            .expect_err("there is no declared checkpoint to fetch");
        assert!(error.to_string().contains("declares a `corpus_checkpoint`"), "{error}");
    }

    #[test]
    fn the_embedded_receipts_and_the_target_index_reach_the_claim_material() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::INGESTION);
        let embed = |name: &str| write(dir.path(), name, br#"{"ahl_receipt_version":"2"}"#);
        let introduction = embed("introduction.ahl");
        let replacement = embed("replacement.ahl");
        let trigger = embed("trigger.ahl");

        issue_against(&stack, dir.path(), "governance-state", |options| {
            options.introduction = Some(introduction);
            options.replacement_introduction = Some(replacement);
            options.trigger = Some(trigger);
            options.target_index = Some(scripted::INGESTION);
        })
        .expect("every embedded receipt is carried as the object it is");

        let receipt = installed(dir.path());
        for member in ["introduction", "replacement_introduction", "trigger"] {
            assert_eq!(
                receipt.pointer(&format!("/claim_material/{member}/ahl_receipt_version")),
                Some(&json!("2")),
                "{member}"
            );
        }
        assert_eq!(
            receipt.pointer("/claim_material/target_index"),
            Some(&json!(scripted::INGESTION))
        );
    }

    #[test]
    fn a_file_that_is_not_the_artifact_it_is_passed_as_is_named_as_such() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::INGESTION);
        let junk = write(dir.path(), "junk.json", b"[not json");

        let error = issue_against(&stack, dir.path(), "governance-state", |options| {
            options.introduction = Some(junk.clone());
        })
        .expect_err("not a receipt");
        assert!(error.to_string().contains("is not a receipt"), "{error}");

        let error = issue_against(&stack, dir.path(), "governance-state", |options| {
            options.replacement_introduction = Some(junk.clone());
        })
        .expect_err("a replacement's introduction is read the same way");
        assert!(error.to_string().contains("is not a receipt"), "{error}");

        let error = issue_against(&stack, dir.path(), "governance-state", |options| {
            options.tree_material = Some(junk.clone());
        })
        .expect_err("not tree material");
        assert!(error.to_string().contains("is not tree material"), "{error}");

        let error = issue_against(&stack, dir.path(), "governance-state", |options| {
            options.introduction = Some(dir.path().join("absent.ahl"));
        })
        .expect_err("nothing is there");
        assert!(error.to_string().contains("introduction receipt"), "{error}");
    }

    #[test]
    fn a_receipt_is_installed_without_clobbering_unless_the_operator_says_otherwise() {
        let dir = tempfile::tempdir().expect("a working directory");
        let stack = scripted::Stack::new().already_published().about(scripted::INGESTION);
        issue_against(&stack, dir.path(), "statement-anchored", |_| {}).expect("the first run");
        let error = issue_against(&stack, dir.path(), "statement-anchored", |_| {})
            .expect_err("the destination is occupied");
        assert!(error.to_string().contains("receipt.ahl"), "{error}");
        issue_against(&stack, dir.path(), "statement-anchored", |options| options.force = true)
            .expect("`--force` is still a no-replace install, into a freed name");
    }

    #[test]
    fn an_entry_the_newest_published_checkpoint_does_not_commit_is_not_placed_under_it() {
        let stack = scripted::Stack::new();
        let short = scripted::Canned::json(200, &json!([stack.checkpoint_at(1)]));
        let error = publish_existing(&short, &endpoints(), scripted::APPENDED)
            .expect_err("the checkpoint commits one entry, the mirror named the sixth");
        assert!(error.to_string().contains("is not committed by the newest checkpoint"), "{error}");

        let nameless = scripted::Canned::json(200, &json!([ { "log_id": scripted::log_id() } ]));
        let error = publish_existing(&nameless, &endpoints(), 0).expect_err("no tree size");
        assert!(error.to_string().contains("has no tree size"), "{error}");

        let position = publish_existing(&stack, &endpoints(), scripted::INGESTION)
            .expect("a position under the newest member");
        assert_eq!(position.entry_index, scripted::INGESTION);
        assert!(
            position.inclusion_path.is_empty(),
            "the path is recomputed during assembly rather than carried unchecked"
        );
    }
}
