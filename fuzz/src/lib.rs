//! Shared fixtures for the `ahl-cli` fuzz targets.
//!
//! The fixture is built once per process and then read from memory, so a target reads no file
//! per input. Every accessor returns an `Option` rather than asserting: a fixture that failed
//! to build must not be reported as a crash in the code under test.
//!
//! The corpus behind the fixture is `test_data/` inside the resolved `ahl-core`, found at
//! process start rather than at build time — see [`test_corpus`]. Building it at compile time
//! would put a sibling working tree between this crate and its own compilation, which a
//! registry dependency does not provide and an outside contributor does not have. Where the
//! corpus cannot be found the reason is printed once and every accessor reports `None`.
//!
//! The one path that stays a path is the adaptor profile document. The client resolves a
//! pinned profile from local possession **at the point of use**, hashing the bytes that run
//! read, and that is the behaviour under test; the document is therefore named by an absolute
//! path in the fixture policy rather than held in it.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ahl_cli::evaluation::EvaluationTime;
use ahl_cli::policy::{LoadedPolicy, LocalLimits, NetworkLimits};
use serde_json::Value;

// Shared with the crate under test rather than copied, so the two can never disagree about
// where the corpus is.
#[path = "../../src/test_corpus.rs"]
mod test_corpus;

/// The published conformance corpus this client is tested against, or `None` with the reason
/// reported once on stderr.
///
/// A fuzz target that silently fuzzed nothing would be worse than one that stops, so the
/// failure is said out loud; it is not a panic, because a panic raised by the harness itself
/// would be reported as a finding against the code under test.
fn corpus() -> Option<&'static Path> {
    static CORPUS: OnceLock<Option<PathBuf>> = OnceLock::new();
    CORPUS
        .get_or_init(|| match test_corpus::locate() {
            Ok(path) => Some(path),
            Err(reason) => {
                eprintln!("ahl-cli-fuzz: {reason}");
                None
            }
        })
        .as_deref()
}

/// A corpus file's text, or `None` where the corpus or the file is unavailable.
fn corpus_text(relative: &str) -> Option<String> {
    std::fs::read_to_string(corpus()?.join(relative)).ok()
}

/// A fixed instant, so no target reads a clock and two runs of one input agree.
const FIXED_TIME: &str = "2026-08-16T12:00:00Z";

/// The mirror and witness base URLs the `response` target answers on.
pub const MIRROR: &str = "https://mirror.example";
/// The witness base URL the `response` target answers on.
pub const WITNESS: &str = "https://witness.example";

/// The adaptor profile the corpus pins, and the leaf and signing constructions it defines.
pub const PROFILE_ID: &str = "ahl-test-log-v1";

/// Limits tightened well below the defaults, so a single input cannot spend a long time inside
/// a run: 256 KiB per local file, 4 096 corpus entries, 64 KiB per response, 32 subrange
/// requests and 4 096 entries per enumeration.
fn network_limits() -> NetworkLimits {
    NetworkLimits {
        max_response_bytes: 64 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
        max_subrange_requests: 32,
        max_entries: 4096,
        wall_clock_seconds: 30,
    }
}

/// Local-file limits, tightened on the same reasoning as [`network_limits`].
#[must_use]
pub const fn local_limits() -> LocalLimits {
    LocalLimits { max_file_bytes: 256 * 1024, max_corpus_entries: 4096 }
}

fn parse(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn quoted(values: Option<&Vec<Value>>) -> String {
    values
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// The policy text the corpus index describes, in the TOML spelling an operator writes.
///
/// Built from `test_data/receipts/index.json` — never from any receipt — so the fixture and
/// the corpus cannot drift apart. The dataset key is carried as `hex` rather than as `file`,
/// so parsing this text opens nothing.
fn policy_text() -> Option<&'static str> {
    static TEXT: OnceLock<Option<String>> = OnceLock::new();
    TEXT.get_or_init(|| {
        let corpus = corpus()?.display().to_string();
        let index = parse(&corpus_text("receipts/index.json")?).unwrap_or(Value::Null);
        let dataset_key = corpus_text("keys/dataset_customers.key")?;
        let policy = index.get("policy").unwrap_or(&Value::Null).clone();
        let profile = policy.pointer("/adaptor_profiles/ahl-test-log-v1");

        Some(format!(
            "[policy]\n\
             genesis_entry_id = \"{genesis}\"\n\
             genesis_key_ids = [{key_ids}]\n\n\
             [policy.adaptor_profiles.{PROFILE_ID}]\n\
             hash = \"{hash}\"\n\
             path = \"{corpus}/adaptor/{PROFILE_ID}.md\"\n\
             checkpoint_raw = {raw}\n\
             consistency_proofs = {consistency}\n\n\
             [policy.dataset_keys.customers]\n\
             hex = \"{key}\"\n\n\
             [endpoints]\n\
             mirror = \"{MIRROR}\"\n\
             witness = \"{WITNESS}\"\n",
            genesis = policy.get("genesis_entry_id").and_then(Value::as_str).unwrap_or_default(),
            key_ids = quoted(policy.get("genesis_key_ids").and_then(Value::as_array)),
            hash = profile
                .and_then(|entry| entry.get("hash"))
                .and_then(Value::as_str)
                .unwrap_or_default(),
            raw = profile
                .and_then(|entry| entry.pointer("/capabilities/checkpoint_raw"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            consistency = profile
                .and_then(|entry| entry.pointer("/capabilities/consistency_proofs"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            key = dataset_key.trim(),
        ))
    })
    .as_deref()
}

/// The corpus trust policy, with the tightened limits of [`network_limits`].
///
/// Parsed through the client's own loader from [`policy_text`], so the fixture is exactly what
/// an operator's file would produce. A policy that cannot be built comes back as `None` and
/// the target returns rather than reporting a crash.
pub fn policy() -> Option<&'static LoadedPolicy> {
    static POLICY: OnceLock<Option<LoadedPolicy>> = OnceLock::new();
    POLICY
        .get_or_init(|| {
            let mut loaded = ahl_cli::policy::from_toml_str(policy_text()?, corpus()?).ok()?;
            loaded.network = network_limits();
            loaded.local = local_limits();
            Some(loaded)
        })
        .as_ref()
}

/// The fixed evaluation instant every target verifies at.
pub fn evaluation() -> Option<&'static EvaluationTime> {
    static TIME: OnceLock<Option<EvaluationTime>> = OnceLock::new();
    TIME.get_or_init(|| EvaluationTime::from_override(FIXED_TIME).ok()).as_ref()
}
