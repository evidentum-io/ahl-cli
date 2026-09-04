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
    /// Base URL of the log accepting submissions.
    pub log: String,
    /// Extra witness base URLs, beyond the configured one.
    pub witness_endpoints: Vec<String>,
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

    let assembly = Assembly::new(
        position.checkpoint.clone(),
        position.raw.clone(),
        prefix,
        carried,
        outgoing,
    )?;

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

    let receipt = producer::assemble(&assembly, position.entry_index, &claim, true)?;
    let canonical = jcs(&receipt);
    install::install(&options.out, &canonical, if options.force { Force::Yes } else { Force::No })?;

    Ok(Issued {
        boundary: BOUNDARY,
        claim_type: options.claim.clone(),
        entry_index: position.entry_index,
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
    Ok(producer::LogPosition { entry_index, checkpoint, raw, inclusion_path: Vec::new() })
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
    mut material: Value,
) -> CliResult<Value> {
    let size = assembly.size()?;
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
}
