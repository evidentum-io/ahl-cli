//! One test per row of the design note's §6 outcome table, asserting the **exact exit code**
//! of the built binary.
//!
//! A path not in that table is a defect, not a default, so every row is exercised here rather
//! than reasoned about. The two rows that need a hostile or divergent server are driven from
//! the recorded transcripts in `tests/fixtures/`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::multiple_crate_versions
)]

mod common;

use common::{
    ahl_cli, corpus, exchange_body, fixtures, mutate_receipt, mutate_transcript, policy,
    set_exchange_body, PolicySpec,
};

const AT: &str = "--evaluation-time";
const FIXED: &str = "2026-08-16T12:00:00Z";

fn verify(policy_path: &str, receipt: &str, extra: &[&str]) -> common::Run {
    let mut args = vec!["--policy", policy_path, AT, FIXED, "verify", receipt];
    args.extend_from_slice(extra);
    ahl_cli(&args)
}

// --- exit 2: the CLI could not begin ---------------------------------------------------

#[test]
fn row_receipt_file_unreadable_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &dir.path().join("absent.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
}

#[test]
fn row_receipt_is_a_directory_not_a_regular_file_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(&policy_path.display().to_string(), &dir.path().display().to_string(), &[]);
    assert_eq!(run.code, 2, "{}", run.stderr);
}

#[test]
fn row_policy_failing_the_secure_open_rules_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    // World-readable: the §4 handle checks refuse it before any artifact is read.
    let policy_path = policy(dir.path(), &PolicySpec { mode: 0o644, ..PolicySpec::default() });
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.output().contains("owner-only"), "{}", run.output());
}

#[test]
fn row_unparseable_policy_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, "this is not toml = = =").expect("write");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");
    let run = verify(
        &path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
}

#[test]
fn row_profile_present_but_not_hashing_to_the_pinned_value_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path =
        policy(dir.path(), &PolicySpec { broken_profile: true, ..PolicySpec::default() });
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 2, "the local configuration is broken, and nothing has been shown");
    assert!(run.output().contains("profile-broken"), "{}", run.output());
}

#[test]
fn row_output_path_io_failure_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = dir.path().join("payload.json");
    std::fs::write(
        &payload,
        serde_json::to_vec(&serde_json::json!({
            "ahl_version": "0.3", "type": "ingestion", "producer": "p",
            "manifest": format!("sha256:{}", "11".repeat(32)),
            "valid_time": FIXED, "issued_at": FIXED,
            "dataset": "customers", "record": format!("sha256:{}", "22".repeat(32)),
        }))
        .expect("serialize"),
    )
    .expect("write");
    let seed = dir.path().join("k.seed");
    std::fs::write(&seed, "01".repeat(32)).expect("write");
    std::fs::set_permissions(&seed, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");

    // The destination's parent is a regular file, not a directory.
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").expect("write");
    let run = ahl_cli(&[
        "emit",
        &payload.display().to_string(),
        "--key-file",
        &seed.display().to_string(),
        "--out",
        &blocker.join("statement.json").display().to_string(),
    ]);
    assert_eq!(run.code, 2, "{}", run.stderr);
}

#[test]
fn row_non_loopback_plain_http_target_is_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        // 93.184.215.14 is IANA's example address: never loopback. The refusal happens at
        // resolution time, so nothing is ever connected to.
        "--mirror",
        "http://93.184.215.14",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.output().contains("loopback"), "{}", run.output());
}

// --- exit 1: a rule fired against the user's own artifact -------------------------------

#[test]
fn row_malformed_receipt_bytes_are_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let path = dir.path().join("broken.ahl");
    std::fs::write(&path, b"{not json").expect("write");
    let run = verify(&policy_path.display().to_string(), &path.display().to_string(), &[]);
    assert_eq!(run.code, 1, "{}", run.stderr);
}

#[test]
fn row_non_canonical_receipt_bytes_are_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("receipts/statement-anchored-valid.ahl")).expect("receipt"),
    )
    .expect("parses");
    let path = dir.path().join("pretty.ahl");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("pretty")).expect("write");
    let run = verify(&policy_path.display().to_string(), &path.display().to_string(), &[]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(run.output().contains("JCS-canonical"), "{}", run.output());
}

#[test]
fn row_a_rule_fired_on_the_user_supplied_artifact_is_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/overclaim-must-fail.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
}

#[test]
fn row_artifact_carried_checkpoint_key_not_active_is_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &corpus()
            .join("receipts/statement-anchored-dropped-producer-key-must-fail.ahl")
            .display()
            .to_string(),
        &[],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
}

#[test]
fn row_unknown_claim_type_is_invalid_never_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let receipt = mutate_receipt(dir.path(), "statement-anchored-valid.ahl", |value| {
        value["claim"]["type"] = serde_json::json!("statement-blessed");
    });
    let run = verify(&policy_path.display().to_string(), &receipt.display().to_string(), &[]);
    assert_eq!(run.code, 1, "an unknown claim type is never inert: {}", run.stderr);
}

#[test]
fn row_equivocation_at_or_beyond_the_floor_is_invalid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-equivocating.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "13",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "equivocation-at-or-beyond-floor");
}

// --- exit 3: required evidence could not be established ---------------------------------

#[test]
fn row_unsupported_specification_version_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let receipt = mutate_receipt(dir.path(), "statement-anchored-valid.ahl", |value| {
        value["spec_version"] = serde_json::json!("0.4.0");
    });
    let run = verify(&policy_path.display().to_string(), &receipt.display().to_string(), &[]);
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.output().contains("profile-limitation"), "{}", run.output());
}

#[test]
fn row_profile_referenced_but_not_locally_possessed_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec { profile: false, ..PolicySpec::default() });
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.output().contains("profile-not-possessed"), "{}", run.output());
}

#[test]
fn row_keyed_binding_without_an_authorized_dataset_key_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path =
        policy(dir.path(), &PolicySpec { dataset_key: false, ..PolicySpec::default() });
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/record-ingested-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 3, "never downgraded to plain-verified: {}", run.stderr);
    assert!(run.output().contains("dataset-key-not-held"), "{}", run.output());
}

#[test]
fn row_receipt_limit_exhausted_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut text =
        std::fs::read_to_string(policy(dir.path(), &PolicySpec::default())).expect("read policy");
    text.push_str("\n[policy.limits]\nmax_decoded_bytes = 16\n");
    let path = dir.path().join("tiny.toml");
    std::fs::write(&path, text).expect("write");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");
    let run = verify(
        &path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 3, "rejection, never a degraded acceptance: {}", run.stderr);
    assert!(run.output().contains("limit-exhausted"), "{}", run.output());
}

#[test]
fn row_a_remote_candidate_that_does_not_verify_is_unverifiable_not_invalid() {
    // A checkpoint signed by a key no manifest version declares. Artifact-carried, that is a
    // `1`; served by a mirror, it means usable evidence was not obtained.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-foreign-key.json").display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_mirror_serving_bytes_the_checkpoint_does_not_commit_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-tampered.json").display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_forged_later_manifest_never_authenticates_a_checkpoint() {
    // Adaptor §7.4.1, end to end. The transcript serves a recomputable tree carrying the
    // genuine pinned genesis manifest **plus** a forged later manifest naming attacker log
    // keys, and a checkpoint signed by one of them. Everything else about it is real: the
    // entry is at a genuine index, its inclusion proof verifies, and it links correctly to the
    // manifest version active before it. Only the producer signature stands in the way, and
    // that is exactly the test a chain collected before it is authenticated would skip.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript = fixtures().join("mirror-transcript-forged-manifest.json");

    // The corpus is 33 entries once the forged manifest is appended; the checkpoint at that
    // size is the one the attacker signed.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "33",
        "--transcript",
        &transcript.display().to_string(),
    ]);
    assert_eq!(
        run.code,
        3,
        "a forged governance statement must never authenticate a checkpoint: {}",
        run.output()
    );
    assert!(run.output().contains("does not verify"), "{}", run.output());
    assert!(
        !run.output().contains("\"status\": \"valid\""),
        "the attack must not produce a verdict: {}",
        run.output()
    );
}

#[test]
fn row_mirror_unreachable_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let empty = dir.path().join("empty-transcript.json");
    std::fs::write(&empty, br#"{"exchanges":[]}"#).expect("write");
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &empty.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_malformed_mirror_response_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript =
        mutate_transcript(dir.path(), "mirror-transcript.json", "garbage.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/checkpoints") {
                    exchange["body_base64"] = serde_json::json!("bm90IGpzb24=");
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "a broken server is missing evidence, not a disproved artifact");
}

#[test]
fn row_enumeration_that_does_not_tile_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript =
        mutate_transcript(dir.path(), "mirror-transcript.json", "untiled.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = exchange_body(exchange);
                    // Drop the last entry: the response no longer covers the range it declares.
                    if let Some(entries) = body["entries"].as_array_mut() {
                        entries.pop();
                    }
                    set_exchange_body(exchange, &body);
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_response_declaring_another_checkpoint_identity_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript =
        mutate_transcript(dir.path(), "mirror-transcript.json", "wrong-identity.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = exchange_body(exchange);
                    body["checkpoint"]["root_hash"] =
                        serde_json::json!(format!("sha256:{}", "ab".repeat(32)));
                    set_exchange_body(exchange, &body);
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_network_budget_exhausted_is_unverifiable_with_the_limit_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(
        dir.path(),
        &PolicySpec {
            mirror: Some("https://mirror.example"),
            witness: Some("https://witness.example"),
            network_limits: Some("max_total_bytes = 64\n"),
            ..PolicySpec::default()
        },
    );
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript.json").display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert!(run.output().contains("budget"), "the limit must be named: {}", run.output());
}

#[test]
fn row_topology_mode_is_always_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus().join("vectors/statements").display().to_string(),
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
        "--trigger-index",
        "6",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_rule_violation_inside_a_topology_corpus_keeps_the_outcome_at_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus().join("vectors/statements").display().to_string(),
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
        "--trigger-index",
        "6",
    ]);
    assert_eq!(run.code, 3);
    let findings = run.json();
    let codes: Vec<&str> = findings["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"signature-does-not-verify"),
        "violations must be reported in full: {codes:?}"
    );
}

#[test]
fn row_witness_unreachable_leaves_verify_unchanged() {
    // Reachability is not assurance: `verify` is offline, and no witness endpoint — reachable
    // or not — can change its verdict.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(
        dir.path(),
        &PolicySpec { witness: Some("https://witness.unreachable"), ..PolicySpec::default() },
    );
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
}

#[test]
fn row_witness_unreachable_makes_reconstruction_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript =
        mutate_transcript(dir.path(), "mirror-transcript.json", "no-witness.json", |value| {
            let exchanges = value["exchanges"].as_array_mut().expect("array");
            exchanges.retain(|exchange| {
                !exchange["url"].as_str().unwrap_or_default().contains("witness.example")
            });
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "reconstruct",
        "--dataset",
        "customers",
        "--record",
        "hmac-sha256:d45b7c71b3822609907522286467cc2ddceb40a77176282b31e9c81296840510",
        "--valid-time",
        FIXED,
        "--checkpoint",
        "32",
    ]);
    assert_eq!(run.code, 3, "never downlevelled to a weaker success: {}", run.stderr);
}

#[test]
fn row_a_stale_cosignature_is_a_finding_and_require_fresh_promotes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let receipt = corpus().join("receipts/statement-anchored-valid.ahl");
    let much_later = "2027-08-16T12:00:00Z";

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        much_later,
        "--json",
        "verify",
        &receipt.display().to_string(),
    ]);
    assert_eq!(run.code, 0, "staleness is never by itself a disproof");
    let document = run.json();
    let codes: Vec<&str> = document["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();
    assert!(codes.contains(&"witness-stale"), "{codes:?}");

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        much_later,
        "verify",
        &receipt.display().to_string(),
        "--require-fresh",
    ]);
    assert_eq!(run.code, 3, "--require-fresh promotes it to unverifiable, never to invalid");
}

// --- exit 0 -----------------------------------------------------------------------------

#[test]
fn row_every_required_rule_verified_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("status: valid"));
}

// --- the boundary the reviewer asked for -------------------------------------------------

#[test]
fn the_boundary_between_cannot_parse_topology_input_and_parsed_input_with_violations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let trees = fixtures().join("tree-material.json");

    // (a) The input cannot be opened at all: a local-environment failure before any walking
    //     begins, and therefore `2`.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &dir.path().join("absent.json").display().to_string(),
        "--trigger-index",
        "0",
    ]);
    assert_eq!(run.code, 2, "unopenable input is a local failure: {}", run.output());
    assert!(run.output().contains("input-unreadable"), "{}", run.output());

    // (b) The input opens but does not parse. §6: "Only a failure to read **or parse** the file
    //     at all is `2`, because that is a local-environment failure before any walking
    //     begins." The reason code is asserted too — two different failures share exit `2`, and
    //     only one of them is the one under test.
    let unparseable = dir.path().join("corpus.json");
    std::fs::write(&unparseable, b"{ not json at all").expect("write");
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "closure",
        "--unauthenticated",
        "--corpus",
        &unparseable.display().to_string(),
        "--trigger-index",
        "0",
    ]);
    assert_eq!(run.code, 2, "a parse failure happens before any walking: {}", run.output());
    assert!(run.output().contains("input-unparseable"), "{}", run.output());

    // (c) The input parses and the walk finds violations: findings, not verdicts, and `3`.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus().join("vectors/statements").display().to_string(),
        "--tree-material",
        &trees.display().to_string(),
        "--trigger-index",
        "6",
    ]);
    assert_eq!(run.code, 3, "violations are findings, and the outcome stays at 3");
    let report = run.json();
    assert_eq!(report["reason_code"], "topology-mode");
    let findings = report["findings"].as_array().expect("findings");
    assert!(!findings.is_empty(), "violations are reported in full");
    // And specifically the ones the corpus carries deliberately.
    let codes: Vec<&str> = findings.iter().filter_map(|finding| finding["code"].as_str()).collect();
    assert!(codes.contains(&"signature-does-not-verify"), "{codes:?}");
}
