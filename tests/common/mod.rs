//! Shared scaffolding for the integration tests: the built binary, a policy file, and the
//! recorded transcripts.
//!
//! Everything here drives `ahl-cli` as a **process**, exactly as a foreign consumer would.
//! Design note §9 requires every test vector to be exercised end-to-end through the built
//! binary and not only through the library, and an exit-code contract that is only ever
//! asserted in-process is not an exit-code contract.

// Shared by four integration-test binaries, each of which uses a different subset.
#![allow(dead_code)]
// Test code: an assertion, an index or an overflow that fires IS the failure report here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The `ahl-core` conformance corpus this repository is developed against.
pub fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ahl-core/test_data")
}

/// The recorded fixtures directory.
pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The result of one process run.
pub struct Run {
    /// The process exit code.
    pub code: i32,
    /// Everything written to stdout.
    pub stdout: String,
    /// Everything written to stderr.
    pub stderr: String,
}

impl Run {
    /// Both streams together, for assertions that only care that a reason was reported
    /// somewhere. A report goes to stdout; a failure that stopped the command before a report
    /// could be built goes to stderr.
    pub fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    /// The `--json` document, parsed.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error}):\n{}", self.stdout))
    }
}

/// Run the built binary.
pub fn ahl_cli(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_ahl-cli"))
        .args(args)
        .output()
        .expect("the built binary runs");
    Run {
        code: output.status.code().expect("the process exited normally"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// How a policy file should be written.
pub struct PolicySpec<'a> {
    /// Include the `customers` dataset key.
    pub dataset_key: bool,
    /// Include the adaptor profile entry.
    pub profile: bool,
    /// Point the profile at a document that does not hash to the pinned value.
    pub broken_profile: bool,
    /// Mode bits for the policy file itself.
    pub mode: u32,
    /// Endpoint URLs, if any.
    pub mirror: Option<&'a str>,
    /// Witness URL, if any.
    pub witness: Option<&'a str>,
    /// An optional `[limits.network]` body.
    pub network_limits: Option<&'a str>,
}

impl Default for PolicySpec<'_> {
    fn default() -> Self {
        Self {
            dataset_key: true,
            profile: true,
            broken_profile: false,
            mode: 0o600,
            mirror: None,
            witness: None,
            network_limits: None,
        }
    }
}

/// Write a policy file into `dir` and return its path.
pub fn policy(dir: &Path, spec: &PolicySpec<'_>) -> PathBuf {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("receipts/index.json")).expect("index"),
    )
    .expect("index parses");
    let block = &index["policy"];
    let hash = block["adaptor_profiles"]["ahl-test-log-v1"]["hash"].as_str().unwrap_or_default();
    let key_ids: Vec<String> = block["genesis_key_ids"]
        .as_array()
        .expect("key ids")
        .iter()
        .map(|id| format!("\"{}\"", id.as_str().unwrap_or_default()))
        .collect();

    let mut text = format!(
        "[policy]\ngenesis_entry_id = \"{}\"\ngenesis_key_ids = [{}]\n\n",
        block["genesis_entry_id"].as_str().unwrap_or_default(),
        key_ids.join(", ")
    );

    if spec.profile {
        let document = if spec.broken_profile {
            let tampered = dir.join("tampered-profile.md");
            std::fs::write(&tampered, b"# not the pinned document\n").expect("write");
            tampered
        } else {
            corpus().join("adaptor/ahl-test-log-v1.md")
        };
        // Capabilities come from what the corpus declares about the pinned document, never
        // from a hard-coded guess here.
        let capabilities = &block["adaptor_profiles"]["ahl-test-log-v1"]["capabilities"];
        let _ = write!(
            text,
            "[policy.adaptor_profiles.ahl-test-log-v1]\nhash = \"{hash}\"\npath = \"{}\"\n\
             checkpoint_raw = {}\nconsistency_proofs = {}\n\n",
            document.display(),
            capabilities["checkpoint_raw"].as_bool().unwrap_or(false),
            capabilities["consistency_proofs"].as_bool().unwrap_or(false),
        );
    }
    if spec.dataset_key {
        let key = dir.join("customers.key");
        std::fs::copy(corpus().join("keys/dataset_customers.key"), &key).expect("copy key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("mode");
        text.push_str("[policy.dataset_keys.customers]\nfile = \"customers.key\"\n\n");
    }
    if spec.mirror.is_some() || spec.witness.is_some() {
        text.push_str("[endpoints]\n");
        if let Some(mirror) = spec.mirror {
            let _ = writeln!(text, "mirror = \"{mirror}\"");
        }
        if let Some(witness) = spec.witness {
            let _ = writeln!(text, "witness = \"{witness}\"");
        }
        text.push('\n');
    }
    if let Some(limits) = spec.network_limits {
        let _ = writeln!(text, "[limits.network]\n{limits}");
    }

    let path = dir.join("policy.toml");
    std::fs::write(&path, text).expect("write policy");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(spec.mode)).expect("mode");
    path
}

/// A policy wired to the recorded fixture's endpoints.
pub fn networked_policy(dir: &Path) -> PathBuf {
    policy(
        dir,
        &PolicySpec {
            mirror: Some("https://mirror.example"),
            witness: Some("https://witness.example"),
            ..PolicySpec::default()
        },
    )
}

/// Rewrite a receipt through a mutation, keeping it JCS-canonical.
pub fn mutate_receipt(
    dir: &Path,
    name: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PathBuf {
    let mut value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("receipts").join(name)).expect("receipt"),
    )
    .expect("receipt parses");
    mutate(&mut value);
    let path = dir.join(name);
    std::fs::write(&path, ahl_core::jcs(&value)).expect("write receipt");
    path
}

/// Load a recorded transcript, apply a mutation, and write it into `dir`.
pub fn mutate_transcript(
    dir: &Path,
    source: &str,
    name: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PathBuf {
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures().join(source)).expect("transcript"))
            .expect("transcript parses");
    mutate(&mut value);
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(&value).expect("serialize")).expect("write");
    path
}

/// Decode an exchange body recorded as base64.
pub fn exchange_body(exchange: &serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    let encoded = exchange["body_base64"].as_str().unwrap_or_default();
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Re-encode a body into an exchange.
pub fn set_exchange_body(exchange: &mut serde_json::Value, body: &serde_json::Value) {
    use base64::Engine as _;
    let bytes = serde_json::to_vec(body).expect("serialize");
    exchange["body_base64"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes));
}

/// The largest `tree_size` the recorded transcript at `name` publishes.
///
/// Read from the recording rather than written down: the fixtures are regenerated from the
/// conformance corpus, so every size in them moves when the corpus grows. A test that names one
/// as a literal does not fail when the corpus changes — it silently grounds itself on an older
/// checkpoint, or on none, which is the kind of drift a recording exists to prevent.
pub fn newest_published_size(name: &str) -> u64 {
    let recorded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures().join(name)).expect("transcript"))
            .expect("transcript parses");
    let exchanges = recorded
        .get("exchanges")
        .and_then(serde_json::Value::as_array)
        .or_else(|| recorded.as_array())
        .expect("exchanges");
    exchanges
        .iter()
        .filter(|exchange| {
            exchange["url"].as_str().is_some_and(|url| url.ends_with("/v1/checkpoints"))
        })
        .filter_map(|exchange| {
            let body = exchange_body(exchange);
            let members = body
                .get("checkpoints")
                .and_then(serde_json::Value::as_array)
                .or_else(|| body.as_array())?
                .clone();
            members
                .iter()
                .filter_map(|member| {
                    member["tree_size"]
                        .as_u64()
                        .or_else(|| member["checkpoint"]["tree_size"].as_u64())
                })
                .max()
        })
        .max()
        .expect("the transcript publishes a checkpoint series")
}

/// A policy file for one receipt set, written from the set's own `index.json`.
///
/// The conformance corpus carries more than one toy log, and a trust policy names ONE published
/// genesis anchor, so a second set brings its own policy with it: its own anchor, its own
/// producer key fingerprints, and its own adaptor profile — a different id, a different held
/// document, different capabilities. Every member is read from the index rather than written
/// down here, so running a set through the binary exercises the CLI's profile plumbing over
/// whatever the corpus actually publishes.
pub fn policy_for_set(dir: &Path, set: &str) -> PathBuf {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join(set).join("index.json")).expect("index"),
    )
    .expect("index parses");
    let block = &index["policy"];
    let key_ids: Vec<String> = block["genesis_key_ids"]
        .as_array()
        .expect("key ids")
        .iter()
        .map(|id| format!("\"{}\"", id.as_str().unwrap_or_default()))
        .collect();

    let mut text = format!(
        "[policy]\ngenesis_entry_id = \"{}\"\ngenesis_key_ids = [{}]\n\n",
        block["genesis_entry_id"].as_str().unwrap_or_default(),
        key_ids.join(", ")
    );
    for (id, declared) in block["adaptor_profiles"].as_object().expect("adaptor profiles") {
        let document = declared["document"]
            .as_str()
            .map_or_else(|| format!("adaptor/{id}.md"), std::borrow::ToOwned::to_owned);
        let _ = write!(
            text,
            "[policy.adaptor_profiles.{id}]\nhash = \"{}\"\npath = \"{}\"\n\
             checkpoint_raw = {}\nconsistency_proofs = {}\n\n",
            declared["hash"].as_str().unwrap_or_default(),
            corpus().join(document).display(),
            declared["capabilities"]["checkpoint_raw"].as_bool().unwrap_or(false),
            declared["capabilities"]["consistency_proofs"].as_bool().unwrap_or(false),
        );
    }
    if block["dataset_keys"].get("customers").is_some() {
        let key = dir.join("customers.key");
        std::fs::copy(corpus().join("keys/dataset_customers.key"), &key).expect("copy key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("mode");
        text.push_str("[policy.dataset_keys.customers]\nfile = \"customers.key\"\n\n");
    }

    let path = dir.join(format!("policy-{}.toml", set.replace('/', "-")));
    std::fs::write(&path, text).expect("write policy");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    path
}
