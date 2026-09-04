//! Shared fixtures for the `ahl-cli` fuzz targets.
//!
//! The policy text is baked in at build time with `include_str!`-style constants, so a target
//! builds its fixture once and reads no file per input. Every accessor returns an `Option`
//! rather than asserting: a fixture that failed to build must not be reported as a crash in
//! the code under test.
//!
//! The one path that does touch the filesystem is the adaptor profile document. The client
//! resolves a pinned profile from local possession **at the point of use**, hashing the bytes
//! that run read, and that is the behaviour under test; the document is therefore named by an
//! absolute path fixed at build time rather than held in the policy.

use std::sync::OnceLock;

use ahl_cli::evaluation::EvaluationTime;
use ahl_cli::policy::{LoadedPolicy, LocalLimits, NetworkLimits};
use serde_json::Value;

/// The published conformance corpus this client is tested against.
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ahl-core/test_data");

/// The corpus receipt index, which carries the trust anchor the corpus outcomes assume.
const RECEIPT_INDEX: &str = include_str!("../../../ahl-core/test_data/receipts/index.json");

/// The dataset HMAC key an authorized verifier holds for the `customers` dataset. Carried
/// inline as `hex` so the fixture policy names no key file.
const DATASET_KEY: &str = include_str!("../../../ahl-core/test_data/keys/dataset_customers.key");

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
fn policy_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| {
        let index = parse(RECEIPT_INDEX).unwrap_or(Value::Null);
        let policy = index.get("policy").unwrap_or(&Value::Null).clone();
        let profile = policy.pointer("/adaptor_profiles/ahl-test-log-v1");

        format!(
            "[policy]\n\
             genesis_entry_id = \"{genesis}\"\n\
             genesis_key_ids = [{key_ids}]\n\n\
             [policy.adaptor_profiles.{PROFILE_ID}]\n\
             hash = \"{hash}\"\n\
             path = \"{CORPUS}/adaptor/{PROFILE_ID}.md\"\n\
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
            key = DATASET_KEY.trim(),
        )
    })
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
            let mut loaded =
                ahl_cli::policy::from_toml_str(policy_text(), std::path::Path::new(CORPUS)).ok()?;
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
