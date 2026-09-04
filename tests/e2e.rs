//! The AHL end-to-end pilot: real log, real mirror, real witnesses, real receipts.
//!
//! # Running it
//!
//! ```text
//! AHL_E2E=1 cargo +stable test -p ahl-cli --test e2e -- --nocapture --test-threads=1
//! ```
//!
//! Without `AHL_E2E=1` every test here returns immediately, so `cargo test` stays offline and
//! self-contained. The pilot is excluded from the default run because it starts three server
//! processes and compiles three sibling checkouts.
//!
//! # What it needs
//!
//! * `cargo` and a Rust toolchain able to build the three server crates.
//! * The sibling checkouts `../ahl-mirror`, `../ahl-witness` and
//!   `../../evidentum.io/atl-server`, each buildable with `cargo build --release`. The first
//!   build of `atl-server` needs network access, because its `atl-core` dependency comes from
//!   crates.io.
//! * The adaptor profile document `../docs-md/ahl-adaptor-atl-v1.md`. It is read at run time
//!   and never committed to this crate; the pilot skips with a message naming the path when it
//!   is absent.
//! * Four free loopback ports, and permission to spawn processes.
//!
//! # What it never touches
//!
//! The `atl-server` checkout carries an operator's own `atl.db` and `signing.key`. The harness
//! starts the server with a **cleared environment** plus `ATL_DATABASE_PATH` and
//! `ATL_SIGNING_KEY_PATH` pointing into a scratch directory that is removed when the run ends,
//! so neither file is read or written even if the developer's shell exports `ATL_*`.

// Test code: an assertion, an index or an overflow that fires IS the failure report here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::multiple_crate_versions
)]

// `tests/e2e.rs` is the crate root of this test binary, so its child modules would otherwise
// resolve beside it in `tests/`. The harness lives in its own directory instead.
#[path = "e2e/scenario.rs"]
mod scenario;
#[path = "e2e/stack.rs"]
mod stack;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Whether the pilot runs at all. Absent the flag, every test returns without doing anything.
fn enabled() -> bool {
    std::env::var("AHL_E2E").ok().as_deref() == Some("1")
}

/// The adaptor profile document, read at run time and never committed here.
fn profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs-md/ahl-adaptor-atl-v1.md")
}

/// `cadence_epoch`, taken from the clock a second before the run.
///
/// The log stamps every checkpoint with the wall clock, and adaptor §5.2.2 item 3 requires the
/// earliest checkpoint committing the genesis manifest to fall inside
/// `[cadence_epoch, cadence_epoch + checkpoint_cadence]`. A committed constant could not
/// satisfy that against a log whose clock is now.
fn cadence_epoch() -> String {
    let now =
        time::OffsetDateTime::now_utc().replace_nanosecond(0).expect("zero is a valid nanosecond")
            - time::Duration::seconds(1);
    now.format(&time::format_description::well_known::Rfc3339).expect("RFC 3339 renders")
}

/// The whole running deployment, plus everything the pilot needs to drive it.
pub struct Pilot {
    /// The three server processes.
    pub stack: stack::Stack,
    /// Every key the deployment declares.
    pub keys: scenario::Keys,
    /// The genesis manifest and its identifiers.
    pub genesis: scenario::Genesis,
    /// The trust policy the pilot verifies under.
    pub policy: PathBuf,
    /// Digest of the adaptor profile document, recomputed this run.
    pub profile_hash: String,
    /// Where producer seeds were written, by key name.
    pub key_files: BTreeMap<String, PathBuf>,
    /// A directory for receipts and other run artifacts.
    pub work: PathBuf,
}

/// Bring the deployment up: keys, genesis manifest, configurations, processes, policy.
///
/// # Errors
///
/// A reason a reviewer can act on: a missing checkout, a missing profile document, a build
/// failure, or a server that never became ready. The caller decides whether that is a skip or
/// a failure.
pub fn start() -> Result<Pilot, String> {
    let profile = profile_path();
    stack::preflight(&profile)?;
    let profile_bytes = std::fs::read(&profile)
        .map_err(|source| format!("cannot read `{}`: {source}", profile.display()))?;
    let profile_hash = ahl_core::sha256_hex(&profile_bytes);

    let keys = scenario::Keys::load();
    let epoch = cadence_epoch();
    let genesis = scenario::genesis(&keys, &profile_hash, &epoch);

    let mirror_config = scenario::mirror_config(&genesis.entry_id, &keys, "mirror.sqlite3");
    let mut witness_configs = BTreeMap::new();
    for (witness_id, seed) in [
        (scenario::WITNESS_1, scenario::WITNESS_1_SEED),
        (scenario::WITNESS_2, scenario::WITNESS_2_SEED),
    ] {
        witness_configs.insert(
            witness_id.to_owned(),
            scenario::witness_config(
                witness_id,
                seed,
                &genesis.entry_id,
                &keys,
                &format!("{witness_id}.sqlite3"),
            ),
        );
    }

    let stack = stack::start(
        &scenario::tree_uuid_string(),
        &scenario::LOG_SEED,
        &mirror_config,
        &witness_configs,
    )?;
    scenario::bootstrap(&stack, &genesis)?;

    let work = stack.dir.path().join("work");
    std::fs::create_dir_all(&work)
        .map_err(|source| format!("cannot create a work dir: {source}"))?;
    let policy = scenario::policy_file(&work, &genesis, &keys, &profile, &profile_hash, &stack);
    let mut key_files = BTreeMap::new();
    for (name, seed) in
        [(scenario::PRODUCER, scenario::PRODUCER_1_SEED), ("producer-2", scenario::PRODUCER_2_SEED)]
    {
        key_files.insert(name.to_owned(), scenario::key_file(&work, name, seed));
    }

    Ok(Pilot { stack, keys, genesis, policy, profile_hash, key_files, work })
}

#[test]
fn the_live_stack_starts_and_binds_to_the_log_the_harness_derived() {
    if !enabled() {
        eprintln!("skipped: set AHL_E2E=1 to run the end-to-end pilot");
        return;
    }
    let pilot = match start() {
        Ok(pilot) => pilot,
        Err(reason) => panic!("the pilot could not start: {reason}"),
    };

    // The mirror holds the genesis manifest at entry index 0, retrievable by its AHL entry id.
    let path = format!("/v1/entries/{}", pilot.genesis.entry_id);
    let (status, body) =
        stack::http(&pilot.stack.mirror.base, "GET", &path, None).expect("the mirror answers");
    assert_eq!(status, 200, "the mirror does not serve the genesis manifest");
    assert_eq!(
        ahl_core::sha256_hex(&body),
        pilot.genesis.entry_id,
        "the bytes the mirror served do not digest to the entry id requested"
    );

    // Both witnesses have cosigned the checkpoint that commits it.
    for witness_id in [scenario::WITNESS_1, scenario::WITNESS_2] {
        let path = format!("/v1/logs/{}/checkpoint", scenario::log_id());
        let (status, body) = stack::http(pilot.stack.witness(witness_id), "GET", &path, None)
            .expect("the witness answers");
        assert_eq!(status, 200, "witness `{witness_id}` retained no checkpoint");
        let cosigned: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(cosigned["witness_id"], serde_json::json!(witness_id));
        assert_eq!(cosigned["checkpoint"]["tree_size"], serde_json::json!(1));
    }

    // The policy pins the profile document held on disk this run.
    let policy = std::fs::read_to_string(&pilot.policy).expect("the policy is readable");
    assert!(policy.contains(&pilot.profile_hash), "the policy does not pin the digest it computed");
    assert!(policy.contains("PILOT-ONLY"), "the pilot-only pin is not stated in the policy");
}
