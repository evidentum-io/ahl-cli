//! The mandatory cache invariant of design note §5, and the determinism rule of §8.
//!
//! > for every command, cold cache, warm cache and adversarially poisoned cache produce
//! > identical verdicts and identical exit codes — evaluated against a **fixed recorded
//! > network transcript**, since the invariant is meaningless against a live endpoint whose
//! > state changes between runs.
//!
//! Every run here therefore replays `tests/fixtures/mirror-transcript.json`, which is
//! generated deterministically from the committed conformance corpus by
//! `cargo run --bin gen_fixtures`.

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

mod common;

use std::path::Path;

use common::{ahl_cli, corpus, fixtures, policy, PolicySpec};

const AT: &str = "--evaluation-time";
const FIXED: &str = "2026-08-16T12:00:00Z";

/// Overwrite every stored object with attacker bytes, leaving the index intact.
///
/// This is the strongest thing a cache poisoner can do without touching the network: the index
/// still points at entries, so the CLI will look them up and get lies back.
fn poison_objects(cache_dir: &Path) {
    let objects = cache_dir.join("objects");
    for entry in std::fs::read_dir(&objects).expect("object store") {
        let path = entry.expect("entry").path();
        std::fs::write(&path, b"{\"attacker\":\"controlled\"}").expect("poison");
    }
}

/// Store **semantically wrong bytes under their own matching digest** and repoint every index
/// entry at them.
///
/// This is the poisoning that matters, and the one a digest check cannot catch: an attacker
/// with write access to the cache directory can always store bytes whose digest is exactly the
/// digest the index names. Only the caller's own proof checks catch it, and only an eviction
/// driven by *those* restores the cold-cache answer.
fn poison_semantically(cache_dir: &Path) {
    let attacker = br#"{"range":{"from_index":0,"to_index":1},"entries":[],"checkpoint":{}}"#;
    let digest = ahl_core::sha256_hex(attacker);
    let object_name: String =
        digest.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    std::fs::write(cache_dir.join("objects").join(&object_name), attacker).expect("plant object");
    for entry in std::fs::read_dir(cache_dir.join("index")).expect("request index") {
        let path = entry.expect("entry").path();
        std::fs::write(&path, &digest).expect("repoint index");
    }
}

/// Point every index entry at a digest nothing is stored under.
fn poison_index(cache_dir: &Path) {
    let index = cache_dir.join("index");
    for entry in std::fs::read_dir(&index).expect("request index") {
        let path = entry.expect("entry").path();
        std::fs::write(&path, format!("sha256:{}", "ff".repeat(32))).expect("poison");
    }
}

/// Swap the two index entries with each other, so each request key resolves to another
/// request's genuinely-stored, genuinely-well-formed object.
fn cross_wire_index(cache_dir: &Path) {
    let index = cache_dir.join("index");
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&index)
        .expect("request index")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    if entries.len() < 2 {
        return;
    }
    let first = std::fs::read(&entries[0]).expect("read");
    let second = std::fs::read(&entries[1]).expect("read");
    std::fs::write(&entries[0], second).expect("write");
    std::fs::write(&entries[1], first).expect("write");
}

struct Scenario<'a> {
    args: Vec<&'a str>,
    name: &'a str,
}

fn run_with_cache(scenario: &Scenario<'_>, cache_dir: &Path) -> common::Run {
    let mut args = vec!["--cache-dir"];
    let cache = cache_dir.display().to_string();
    args.push(&cache);
    args.extend(scenario.args.iter().copied());
    ahl_cli(&args)
}

/// Run one scenario cold, warm, and against three kinds of poisoned cache, and require every
/// run to produce identical stdout and an identical exit code.
fn assert_cache_invariant(scenario: &Scenario<'_>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");

    let cold = run_with_cache(scenario, &cache);
    let warm = run_with_cache(scenario, &cache);
    assert_eq!(cold.code, warm.code, "{}: cold vs warm exit code", scenario.name);
    assert_eq!(cold.stdout, warm.stdout, "{}: cold vs warm stdout", scenario.name);
    assert!(
        std::fs::read_dir(cache.join("objects")).expect("objects").count() > 0,
        "{}: the warm run must actually have had a cache to read",
        scenario.name
    );

    poison_objects(&cache);
    let poisoned = run_with_cache(scenario, &cache);
    assert_eq!(poisoned.code, cold.code, "{}: poisoned objects changed the outcome", scenario.name);
    assert_eq!(
        poisoned.stdout, cold.stdout,
        "{}: poisoned objects changed the verdict",
        scenario.name
    );

    poison_index(&cache);
    let dangling = run_with_cache(scenario, &cache);
    assert_eq!(dangling.code, cold.code, "{}: a dangling index changed the outcome", scenario.name);
    assert_eq!(
        dangling.stdout, cold.stdout,
        "{}: a dangling index changed the verdict",
        scenario.name
    );

    // Repopulate, then cross-wire: every entry resolves to a *valid* object for a different
    // request. This is the case a digest check alone does not catch, and the one the
    // "re-verified from its bytes as if it had just arrived" rule exists for.
    let _ = run_with_cache(scenario, &cache);
    cross_wire_index(&cache);
    let crossed = run_with_cache(scenario, &cache);
    assert_eq!(
        crossed.code, cold.code,
        "{}: a cross-wired index changed the outcome",
        scenario.name
    );
    assert_eq!(
        crossed.stdout, cold.stdout,
        "{}: a cross-wired index changed the verdict",
        scenario.name
    );

    // Repopulate, then poison **semantically**: bytes that pass every integrity check the
    // cache can perform and are simply the wrong answer. A digest check cannot catch this, so
    // eviction has to be driven by the caller's own proof checks; without that, this run
    // returns `3` where the cold one returned `0`.
    let _ = run_with_cache(scenario, &cache);
    poison_semantically(&cache);
    let semantic = run_with_cache(scenario, &cache);
    assert_eq!(
        semantic.code, cold.code,
        "{}: a digest-consistent poisoned object changed the outcome",
        scenario.name
    );
    assert_eq!(
        semantic.stdout, cold.stdout,
        "{}: a digest-consistent poisoned object changed the verdict",
        scenario.name
    );
}

#[test]
fn closure_holds_the_cache_invariant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();
    assert_cache_invariant(&Scenario {
        name: "closure",
        args: vec![
            "--policy",
            &policy_path,
            AT,
            FIXED,
            "--json",
            "--transcript",
            &transcript,
            "closure",
            "--trigger-index",
            "6",
            "--checkpoint",
            "8",
            "--tree-material",
            &trees,
        ],
    });
}

#[test]
fn reconstruct_holds_the_cache_invariant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();
    assert_cache_invariant(&Scenario {
        name: "reconstruct",
        args: vec![
            "--policy",
            &policy_path,
            AT,
            FIXED,
            "--json",
            "--transcript",
            &transcript,
            "reconstruct",
            "--dataset",
            "customers",
            "--record",
            "hmac-sha256:d45b7c71b3822609907522286467cc2ddceb40a77176282b31e9c81296840510",
            "--valid-time",
            FIXED,
            "--checkpoint",
            "32",
        ],
    });
}

#[test]
fn an_equivocating_series_holds_the_cache_invariant_too() {
    // A poisoned cache must not turn a `1` into anything else, either.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript-equivocating.json").display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();
    assert_cache_invariant(&Scenario {
        name: "equivocating closure",
        args: vec![
            "--policy",
            &policy_path,
            AT,
            FIXED,
            "--json",
            "--transcript",
            &transcript,
            "closure",
            "--trigger-index",
            "6",
            "--checkpoint",
            "13",
            "--tree-material",
            &trees,
        ],
    });
}

#[test]
fn the_latest_checkpoint_is_never_served_from_cache() {
    // The series query answers "what does the log publish now?". A valid old answer is a
    // replay, so it carries no cache key at all — visible here as a cache that never grows an
    // entry for it however many times the command runs.
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();
    let args = vec![
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--json",
        "--transcript",
        &transcript,
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &trees,
    ];
    let _ = run_with_cache(&Scenario { name: "series", args }, &cache);

    // Only the range enumeration is cacheable at tree_size 8: one entry, not two.
    let entries = std::fs::read_dir(cache.join("index")).expect("index").count();
    assert_eq!(entries, 1, "only the range enumeration is cacheable, got {entries} entries");
}

// --- §8 determinism ----------------------------------------------------------------------

#[test]
fn the_same_inputs_and_policy_produce_byte_identical_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();

    for surface in [vec!["--json"], vec![]] {
        let mut args = vec!["--policy", policy_path.as_str(), AT, FIXED];
        args.extend(surface.iter().copied());
        args.extend([
            "--transcript",
            transcript.as_str(),
            "closure",
            "--trigger-index",
            "6",
            "--checkpoint",
            "8",
            "--tree-material",
            trees.as_str(),
        ]);
        let first = ahl_cli(&args);
        let second = ahl_cli(&args);
        assert_eq!(first.stdout, second.stdout, "stdout is not byte-identical");
        assert_eq!(first.code, second.code);
        assert!(!first.stdout.is_empty());
    }
}

#[test]
fn json_key_order_and_set_ordering_are_stable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--json",
        "--transcript",
        &transcript,
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &trees,
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);

    // Key order: the §6 field list, in the order the schema declares it.
    let mut last = 0;
    for field in [
        "\"status\"",
        "\"reason_code\"",
        "\"reason\"",
        "\"claim_type\"",
        "\"boundary\"",
        "\"assurance\"",
        "\"checkpoint\"",
        "\"authenticated\"",
        "\"completeness\"",
        "\"evaluation_time\"",
        "\"evaluation_time_source\"",
        "\"series_usable_bound\"",
        "\"continued_history_bound\"",
        "\"findings\"",
        "\"receipt_note\"",
        "\"affected\"",
    ] {
        let at = run.stdout.find(field).unwrap_or_else(|| panic!("{field} missing"));
        assert!(at > last, "{field} is out of order");
        last = at;
    }

    let report = run.json();
    // Set ordering: affected records by `(dataset, record)`, findings by `(code, detail)`.
    let affected: Vec<(String, String)> = report["affected"]
        .as_array()
        .expect("affected")
        .iter()
        .map(|item| {
            (
                item["dataset"].as_str().unwrap_or_default().to_owned(),
                item["record"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut sorted = affected.clone();
    sorted.sort();
    assert_eq!(affected, sorted, "the affected set must be ordered lexicographically");

    let findings: Vec<(String, String)> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|item| {
            (
                item["code"].as_str().unwrap_or_default().to_owned(),
                item["detail"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut sorted = findings.clone();
    sorted.sort();
    assert_eq!(findings, sorted, "findings must be ordered lexicographically");
}

#[test]
fn an_overridden_evaluation_time_can_never_be_read_as_a_current_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let receipt = corpus().join("receipts/statement-anchored-valid.ahl").display().to_string();

    let overridden = ahl_cli(&["--policy", &policy_path, AT, FIXED, "--json", "verify", &receipt]);
    assert_eq!(overridden.json()["evaluation_time_source"], "override");
    assert_eq!(overridden.json()["evaluation_time"], FIXED);

    let from_clock = ahl_cli(&["--policy", &policy_path, "--json", "verify", &receipt]);
    assert_eq!(from_clock.json()["evaluation_time_source"], "clock");
}

#[test]
fn verify_is_deterministic_across_every_receipt_vector() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("receipts/index.json")).expect("index"),
    )
    .expect("parses");
    for vector in index["vectors"].as_array().expect("vectors") {
        let path = corpus()
            .join("receipts")
            .join(vector["file"].as_str().expect("file"))
            .display()
            .to_string();
        let args = ["--policy", policy_path.as_str(), AT, FIXED, "--json", "verify", &path];
        let first = ahl_cli(&args);
        let second = ahl_cli(&args);
        assert_eq!(first.stdout, second.stdout, "{path} is not deterministic");
        assert_eq!(first.code, second.code);
    }
}
