//! The command surface, and the single place an outcome becomes an exit code.
//!
//! Five verbs, and the network is a flag on exactly two of them:
//!
//! | Command | Input | Output | Network |
//! |---|---|---|---|
//! | `verify` | `.ahl` receipt + policy | verdict with rendered boundary | **never** |
//! | `inspect` | `.ahl` receipt | structural dump, **no verdict** | never |
//! | `emit` | statement payload + signing key | signed candidate envelope | never |
//! | `closure` | corpus or log + trigger reference | affected set + authentication state | optional |
//! | `reconstruct` | corpus or log + checkpoint + valid time | projection + authentication state | optional |
//!
//! Retrieval is a flag on `closure` and `reconstruct` only, never a verb of its own: fetching
//! bytes nobody verifies is not a feature. `verify` is offline by construction — there is no
//! flag that makes it reach the network.
//!
//! `--json` writes the stable schema to **stdout**; diagnostics go to **stderr**, so a
//! consumer can pipe one without the other.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::cache::Cache;
use crate::commands::{closure, emit, inspect, reconstruct, verify};
use crate::error::{CliError, CliResult};
use crate::evaluation::EvaluationTime;
use crate::keys::KeySource;
use crate::net::{Budgeted, Fetcher, HttpFetcher};
use crate::outcome::Outcome;
use crate::policy::{self, LoadedPolicy};
use crate::transcript::TranscriptFetcher;

/// The open self-hosted client of the AHL stack.
#[derive(Debug, Parser)]
#[command(name = "ahl-cli", version, about, long_about = None)]
pub struct Cli {
    /// Path to the local trust policy (TOML). Owner-only, owned by the effective uid.
    #[arg(long, global = true)]
    pub policy: Option<PathBuf>,

    /// Write the stable JSON schema to stdout instead of the human-readable form.
    #[arg(long, global = true)]
    pub json: bool,

    /// Evaluate freshness at this instant instead of reading the clock. Never selects a
    /// checkpoint — that is `--checkpoint`, and one flag never does both jobs.
    #[arg(long, global = true, value_name = "RFC3339")]
    pub evaluation_time: Option<String>,

    /// Mirror base URL, overriding `[endpoints] mirror`. An address, never an authority.
    #[arg(long, global = true, value_name = "URL")]
    pub mirror: Option<String>,

    /// Witness base URL, overriding `[endpoints] witness`. An address, never an authority.
    #[arg(long, global = true, value_name = "URL")]
    pub witness: Option<String>,

    /// Replay a recorded network transcript instead of reaching the network.
    #[arg(long, global = true, value_name = "FILE")]
    pub transcript: Option<PathBuf>,

    /// Enable the two-layer cache under this directory.
    #[arg(long, global = true, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Byte quota for the cache's object store; least-recently-used objects are evicted.
    #[arg(long, global = true, default_value_t = 512 * 1024 * 1024)]
    pub cache_quota_bytes: u64,

    /// The verb.
    #[command(subcommand)]
    pub command: Command,
}

/// The five verbs.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify a `.ahl` Evidence Receipt offline against local policy.
    Verify {
        /// Path to the receipt.
        receipt: PathBuf,
        /// Promote a stale witness cosignature from a finding to `unverifiable`.
        #[arg(long)]
        require_fresh: bool,
    },
    /// Dump a receipt's structure. Prints no verdict.
    Inspect {
        /// Path to the receipt.
        receipt: PathBuf,
    },
    /// Sign a candidate envelope. Never a conforming anchored statement.
    Emit {
        /// Path to the statement payload, as JSON.
        payload: PathBuf,
        /// Where the signing seed comes from — a file or a named environment variable.
        #[command(flatten)]
        key: KeyArgs,
        /// Install the canonical envelope bytes here, atomically and without clobbering.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing destination. Still a no-replace install, never a silent
        /// overwrite.
        #[arg(long)]
        force: bool,
    },
    /// Compute the affected set of a trigger.
    Closure {
        /// The trigger's statement id.
        #[arg(long, conflicts_with = "trigger_index", required_unless_present = "trigger_index")]
        trigger: Option<String>,
        /// The trigger's entry index.
        #[arg(long)]
        trigger_index: Option<u64>,
        /// Topology mode over a local corpus. Never returns `0`.
        #[arg(long)]
        unauthenticated: bool,
        /// The local corpus: a directory of per-entry JSON files, or one JSON array.
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// Committed tree material, as a root-to-leaves JSON map.
        #[arg(long)]
        tree_material: Option<PathBuf>,
        /// The checkpoint to evaluate at, by `tree_size`. Explicit, never inferred.
        #[arg(long)]
        checkpoint: Option<u64>,
    },
    /// Reconstruct the evidenced assertion set for a record, as known at a checkpoint.
    Reconstruct {
        /// The dataset the record belongs to.
        #[arg(long)]
        dataset: String,
        /// The record commitment.
        #[arg(long)]
        record: String,
        /// The domain time asked about.
        #[arg(long, value_name = "RFC3339")]
        valid_time: String,
        /// The as-of checkpoint, by `tree_size`.
        #[arg(long)]
        checkpoint: Option<u64>,
    },
}

/// Where the signing seed comes from. Never a command-line argument: `argv` is world-readable
/// in `ps`.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct KeyArgs {
    /// A file holding one line of hex encoding a 32-byte Ed25519 seed.
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    /// The name of an environment variable holding that hex.
    #[arg(long, value_name = "NAME")]
    pub key_env: Option<String>,
}

impl KeyArgs {
    fn source(&self) -> CliResult<KeySource> {
        match (&self.key_file, &self.key_env) {
            (Some(path), None) => Ok(KeySource::File(path.clone())),
            (None, Some(name)) => Ok(KeySource::Env(name.clone())),
            _ => Err(CliError::Usage(
                "exactly one of `--key-file` or `--key-env` is required; key material is never \
                 taken from a command-line argument, because `argv` is world-readable in `ps`"
                    .to_owned(),
            )),
        }
    }
}

/// Parse `argv`, run the command, and return the outcome whose exit code the caller uses.
///
/// Output goes to `stdout`; diagnostics to `stderr`. Both are injected so the whole surface is
/// testable without a process.
pub fn run(
    argv: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Outcome {
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(error) => {
            // clap writes its own help and version text; both are usage, not a verdict.
            let _ = write!(stderr, "{error}");
            return if error.use_stderr() { Outcome::Error } else { Outcome::Valid };
        }
    };
    match dispatch(&cli, stdout) {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = writeln!(stderr, "ahl-cli: [{}] {error}", error.reason_code());
            error.outcome()
        }
    }
}

fn load_policy(cli: &Cli) -> CliResult<LoadedPolicy> {
    let path = cli.policy.as_ref().ok_or_else(|| {
        CliError::Usage(
            "`--policy <path>` is required: the trust anchor is operator-configured and is \
             never derived from the artifact under verification"
                .to_owned(),
        )
    })?;
    let mut policy = policy::load(path)?;
    // Endpoints are addresses, so a flag may override configuration without touching trust.
    if let Some(mirror) = &cli.mirror {
        policy.endpoints.mirror = Some(mirror.clone());
    }
    if let Some(witness) = &cli.witness {
        policy.endpoints.witness = Some(witness.clone());
    }
    Ok(policy)
}

/// Build the fetch chain: cache (outermost) → network budget → transport.
///
/// The cache sits outside the budget deliberately: a cache hit is not network traffic, and a
/// network budget bounds the network. It changes *what work happens*, never *what is accepted*
/// — every object is re-verified from its bytes on read.
fn fetch_chain(cli: &Cli, policy: &LoadedPolicy) -> CliResult<Box<dyn Fetcher>> {
    let transport: Box<dyn Fetcher> = match &cli.transcript {
        Some(path) => Box::new(TranscriptFetcher::load(path)?),
        None => Box::new(HttpFetcher::new(policy.network)),
    };
    let mut chain: Box<dyn Fetcher> = Box::new(Budgeted::new(transport, policy.network));
    if let Some(dir) = &cli.cache_dir {
        chain =
            Box::new(crate::cache::Caching::new(chain, Cache::open(dir, cli.cache_quota_bytes)?));
    }
    Ok(chain)
}

fn dispatch(cli: &Cli, stdout: &mut dyn Write) -> CliResult<Outcome> {
    let evaluation = EvaluationTime::resolve(cli.evaluation_time.as_deref())?;

    match &cli.command {
        Command::Verify { receipt, require_fresh } => {
            let policy = load_policy(cli)?;
            let report = verify::run(
                &policy,
                &evaluation,
                &verify::Options { receipt: receipt.clone(), require_fresh: *require_fresh },
            );
            emit_report(cli, stdout, &report)
        }
        Command::Inspect { receipt } => {
            let policy = load_policy(cli)?;
            let result = inspect::run(&policy, &inspect::Options { receipt: receipt.clone() });
            let outcome = inspect::outcome_of(&result);
            match result {
                Ok(dump) => {
                    let rendered = if cli.json { dump.to_json()? } else { dump.to_text() };
                    write_out(stdout, &rendered)?;
                    Ok(outcome)
                }
                Err(error) => Err(error),
            }
        }
        Command::Emit { payload, key, out, force } => {
            // `emit` needs no trust policy: it establishes nothing about a log. Local limits
            // come from policy where one is configured, and from the defaults otherwise.
            let limits = cli.policy.as_ref().map_or_else(
                || Ok(crate::policy::LocalLimits::default()),
                |_| load_policy(cli).map(|policy| policy.local),
            )?;
            let emitted = emit::run(
                limits,
                &emit::Options {
                    payload: payload.clone(),
                    key: key.source()?,
                    out: out.clone(),
                    force: *force,
                },
            )?;
            let rendered = if cli.json { emitted.to_json()? } else { emitted.to_text() };
            write_out(stdout, &rendered)?;
            Ok(Outcome::Valid)
        }
        Command::Closure {
            trigger,
            trigger_index,
            unauthenticated,
            corpus,
            tree_material,
            checkpoint,
        } => {
            let policy = load_policy(cli)?;
            let reference =
                match (trigger, trigger_index) {
                    (Some(id), None) => closure::TriggerRef::StatementId(id.clone()),
                    (None, Some(index)) => closure::TriggerRef::EntryIndex(*index),
                    _ => return Err(CliError::Usage(
                        "exactly one of `--trigger <statement-id>` or `--trigger-index <n>` is \
                         required"
                            .to_owned(),
                    )),
                };
            let options = closure::Options {
                trigger: reference,
                unauthenticated: *unauthenticated,
                corpus: corpus.clone(),
                tree_material: tree_material.clone(),
                checkpoint: *checkpoint,
            };
            let report = if *unauthenticated {
                closure::run::<Box<dyn Fetcher>>(&policy, &evaluation, &options, None)
            } else {
                let chain = fetch_chain(cli, &policy)?;
                closure::run(&policy, &evaluation, &options, Some(&chain))
            };
            emit_report(cli, stdout, &report)
        }
        Command::Reconstruct { dataset, record, valid_time, checkpoint } => {
            let policy = load_policy(cli)?;
            let chain = fetch_chain(cli, &policy)?;
            let report = reconstruct::run(
                &policy,
                &evaluation,
                &reconstruct::Options {
                    dataset: dataset.clone(),
                    record: record.clone(),
                    valid_time: valid_time.clone(),
                    checkpoint: *checkpoint,
                },
                Some(&chain),
            );
            emit_report(cli, stdout, &report)
        }
    }
}

fn emit_report(
    cli: &Cli,
    stdout: &mut dyn Write,
    report: &crate::report::Report,
) -> CliResult<Outcome> {
    let rendered = if cli.json { report.to_json()? } else { report.to_text() };
    write_out(stdout, &rendered)?;
    // The exit code follows `outcome`, the run's decision, not `status`, the receipt's own
    // result: a receipt that verified under a policy this run did not satisfy must not exit 0.
    Ok(match report.outcome {
        "valid" => Outcome::Valid,
        "invalid" => Outcome::Invalid,
        "unverifiable" => Outcome::Unverifiable,
        _ => Outcome::Error,
    })
}

fn write_out(stdout: &mut dyn Write, rendered: &str) -> CliResult<()> {
    stdout.write_all(rendered.as_bytes()).map_err(|source| CliError::Output {
        path: "<stdout>".to_owned(),
        detail: source.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;
    use crate::testing::MirrorFixture;

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("ahl-cli")).chain(args.iter().map(OsString::from)).collect()
    }

    struct Run {
        outcome: Outcome,
        stdout: String,
        stderr: String,
    }

    fn run_cli(args: &[&str]) -> Run {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = run(argv(args), &mut stdout, &mut stderr);
        Run {
            outcome,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }
    }

    fn corpus() -> PathBuf {
        MirrorFixture::corpus_root()
    }

    /// A policy file pointing at the conformance corpus, written owner-only.
    fn policy_file(dir: &Path) -> PathBuf {
        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(corpus().join("receipts/index.json")).expect("index"),
        )
        .expect("parses");
        let block = &index["policy"];
        let hash = block["adaptor_profiles"]["ahl-test-log-v1"]["hash"].as_str().unwrap_or("");
        let key_ids: Vec<String> = block["genesis_key_ids"]
            .as_array()
            .expect("key ids")
            .iter()
            .map(|id| format!("\"{}\"", id.as_str().unwrap_or_default()))
            .collect();

        let key_path = dir.join("customers.key");
        std::fs::copy(corpus().join("keys/dataset_customers.key"), &key_path).expect("copy key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");

        let text = format!(
            "[policy]\n\
             genesis_entry_id = \"{}\"\n\
             genesis_key_ids = [{}]\n\n\
             [policy.adaptor_profiles.ahl-test-log-v1]\n\
             hash = \"{hash}\"\n\
             path = \"{}\"\n\n\
             [policy.dataset_keys.customers]\n\
             file = \"customers.key\"\n",
            block["genesis_entry_id"].as_str().unwrap_or_default(),
            key_ids.join(", "),
            corpus().join("adaptor/ahl-test-log-v1.md").display(),
        );
        let path = dir.join("policy.toml");
        std::fs::write(&path, text).expect("write policy");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
        path
    }

    #[test]
    fn verify_of_a_valid_receipt_exits_zero_and_writes_only_to_stdout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let receipt = corpus().join("receipts/statement-anchored-valid.ahl");
        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "--evaluation-time",
            "2026-08-16T12:00:00Z",
            "verify",
            &receipt.display().to_string(),
        ]);
        assert_eq!(run.outcome, Outcome::Valid);
        assert_eq!(run.outcome.exit_code(), 0);
        assert!(run.stdout.contains("outcome: valid"));
        assert!(run.stderr.is_empty(), "diagnostics leaked into stdout: {}", run.stderr);
    }

    #[test]
    fn json_goes_to_stdout_and_diagnostics_go_to_stderr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "--json",
            "--evaluation-time",
            "2026-08-16T12:00:00Z",
            "verify",
            &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        ]);
        assert_eq!(run.outcome, Outcome::Valid);
        let parsed: serde_json::Value =
            serde_json::from_str(&run.stdout).expect("stdout is the JSON schema");
        assert_eq!(parsed["status"], "valid");
        assert!(run.stderr.is_empty());
    }

    #[test]
    fn a_negative_receipt_exits_one_and_a_missing_profile_exits_three() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "--evaluation-time",
            "2026-08-16T12:00:00Z",
            "verify",
            &corpus().join("receipts/overclaim-must-fail.ahl").display().to_string(),
        ]);
        assert_eq!(run.outcome.exit_code(), 1);

        // A policy with no profiles at all: not locally possessed, therefore unverifiable.
        let bare = dir.path().join("bare.toml");
        std::fs::write(
            &bare,
            format!(
                "[policy]\ngenesis_entry_id = \"sha256:{}\"\ngenesis_key_ids = [\"sha256:{}\"]\n",
                "aa".repeat(32),
                "bb".repeat(32)
            ),
        )
        .expect("write");
        std::fs::set_permissions(&bare, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let run = run_cli(&[
            "--policy",
            &bare.display().to_string(),
            "verify",
            &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        ]);
        assert_eq!(run.outcome.exit_code(), 3);
    }

    #[test]
    fn a_missing_policy_is_a_usage_error_before_any_artifact_is_read() {
        let run = run_cli(&["verify", "/nonexistent/receipt.ahl"]);
        assert_eq!(run.outcome.exit_code(), 2);
        assert!(run.stderr.contains("never derived from the artifact"), "{}", run.stderr);
        assert!(run.stdout.is_empty());
    }

    #[test]
    fn inspect_prints_no_verdict_and_still_exits_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "inspect",
            &corpus().join("receipts/trigger-effective-valid.ahl").display().to_string(),
        ]);
        assert_eq!(run.outcome, Outcome::Valid);
        assert!(run.stdout.starts_with("structural dump only"));
        assert!(!run.stdout.contains("status:"));
    }

    #[test]
    fn emit_needs_exactly_one_key_source_and_never_takes_one_from_argv() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = dir.path().join("payload.json");
        std::fs::write(
            &payload,
            serde_json::to_vec(&serde_json::json!({
                "ahl_version": "0.4", "type": "ingestion", "producer": "p",
                "manifest": format!("sha256:{}", "11".repeat(32)),
                "valid_time": "2026-08-16T12:00:00Z", "issued_at": "2026-08-16T12:00:00Z",
                "dataset": "customers", "record": format!("sha256:{}", "22".repeat(32)),
            }))
            .expect("serialize"),
        )
        .expect("write");
        let seed = dir.path().join("k.seed");
        std::fs::write(&seed, "01".repeat(32)).expect("write");
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).expect("mode");

        let run = run_cli(&[
            "emit",
            &payload.display().to_string(),
            "--key-file",
            &seed.display().to_string(),
        ]);
        assert_eq!(run.outcome, Outcome::Valid);
        assert!(run.stdout.contains("CANDIDATE"));

        // Neither source: clap refuses before anything is opened.
        let run = run_cli(&["emit", &payload.display().to_string()]);
        assert_eq!(run.outcome.exit_code(), 2);

        // There is no `--key`/`--seed` flag that would put material in `argv`.
        let run = run_cli(&["emit", &payload.display().to_string(), "--key", &"01".repeat(32)]);
        assert_eq!(run.outcome.exit_code(), 2);
    }

    #[test]
    fn closure_in_topology_mode_never_exits_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let trees = crate::testing::tree_material_file(dir.path());
        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "closure",
            "--unauthenticated",
            "--corpus",
            &crate::testing::statements_with_published_tree_material(dir.path())
                .display()
                .to_string(),
            "--tree-material",
            &trees.display().to_string(),
            "--trigger-index",
            "6",
        ]);
        assert_eq!(run.outcome.exit_code(), 3);
        assert!(run.stdout.contains("topology affected"));
    }

    #[test]
    fn closure_needs_exactly_one_trigger_reference() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_file(dir.path());
        let run = run_cli(&["--policy", &policy.display().to_string(), "closure"]);
        assert_eq!(run.outcome.exit_code(), 2);

        let run = run_cli(&[
            "--policy",
            &policy.display().to_string(),
            "closure",
            "--trigger",
            "sha256:aa",
            "--trigger-index",
            "1",
        ]);
        assert_eq!(run.outcome.exit_code(), 2);
    }

    #[test]
    fn an_unparseable_evaluation_time_is_a_usage_error() {
        let run = run_cli(&["--evaluation-time", "yesterday", "inspect", "/dev/null"]);
        assert_eq!(run.outcome.exit_code(), 2);
    }

    #[test]
    fn help_and_version_are_usage_not_verdicts() {
        let run = run_cli(&["--help"]);
        assert_eq!(run.outcome, Outcome::Valid, "help is not a failure");
        assert!(run.stderr.contains("verify"));
        let run = run_cli(&["--version"]);
        assert_eq!(run.outcome, Outcome::Valid);
    }

    #[test]
    fn an_unknown_verb_is_a_usage_error() {
        let run = run_cli(&["prove-everything"]);
        assert_eq!(run.outcome.exit_code(), 2);
    }

    #[test]
    fn verify_has_no_flag_that_reaches_the_network() {
        // The whole surface is enumerated here rather than asserted informally: a future flag
        // named anything like these on `verify` would fail this test.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _ = run(argv(&["verify", "--help"]), &mut stdout, &mut stderr);
        let help =
            String::from_utf8_lossy(&stdout).into_owned() + &String::from_utf8_lossy(&stderr);
        assert!(help.contains("--require-fresh"));
        for forbidden in ["--fetch", "--online", "--refresh-witness", "--insecure"] {
            assert!(!help.contains(forbidden), "`verify` must not offer `{forbidden}`");
        }
    }

    #[test]
    fn there_is_no_insecure_flag_anywhere() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _ = run(argv(&["--help"]), &mut stdout, &mut stderr);
        let help =
            String::from_utf8_lossy(&stdout).into_owned() + &String::from_utf8_lossy(&stderr);
        assert!(!help.contains("insecure"));
    }
}
