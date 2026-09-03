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

use std::fmt::Write as _;

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
            "ahl_version": "0.4", "type": "ingestion", "producer": "p",
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

#[test]
fn row_an_anchored_statement_of_an_unknown_type_is_invalid_never_inert() {
    // §6: "Unknown claim type or unknown statement type, authenticated mode | 1 — never
    // skipped, never inert." The transcript anchors a correctly signed statement whose type
    // core §2.3 does not define, committed by the checkpoint the run is grounded on.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-unknown-statement.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "39",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "rule-fired");
    assert!(run.output().contains("attestation"), "{}", run.output());

    // A checkpoint that does not commit it is unaffected.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-unknown-statement.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_series_order_decides_the_selection_so_a_divergence_reaches_its_own_row() {
    // Core §7.3 orders a series by `(tree_size, checkpoint_time)`. The mirror here serves the
    // diverging member **first in the array** while giving it a later time, so a client that
    // takes whichever member came first would ground itself on the branch whose root nothing
    // recomputes and answer a divergence with `3` — "evidence not obtained" — instead of the
    // `1` the divergence supports.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript = mutate_transcript(
        dir.path(),
        "mirror-transcript-equivocating.json",
        "divergent-served-first.json",
        |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/checkpoints") {
                    let mut body = exchange_body(exchange);
                    let members = body.as_array_mut().expect("series");
                    let at = members
                        .iter()
                        .position(|member| {
                            member["tree_size"] == 13
                                && member["checkpoint_time"] != serde_json::json!(FIXED)
                        })
                        .expect("the divergent member is in the recorded series");
                    let divergent = members.remove(at);
                    members.insert(0, divergent);
                    set_exchange_body(exchange, &body);
                }
            }
        },
    );
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
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
fn row_a_withheld_predecessor_is_unverifiable_never_a_complete_answer() {
    // The deployment published members below tree_size 13; this mirror serves only 13 and
    // upward. Design note §3 item 3 requires the predecessor relationship always, and adaptor
    // §5.2.2 item 3's exemption is a fact about the *deployment* that no client can establish:
    // a short answer from `/v1/checkpoints` is a server label, and §2 rule 3 makes server
    // labels not evidence. Reading it as the exemption would hand every mirror a switch that
    // turns a missing relationship into a complete answer.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-withheld-predecessor.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "13",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("no authenticated series member precedes"), "{}", run.output());
    assert!(run.output().contains("server label"), "{}", run.output());
    assert_ne!(run.json()["completeness"], "complete");

    // The very same checkpoint, from a mirror serving the history the deployment published.
    // The trigger is the one that governs there: at tree_size 13 entry 12 supersedes entry 6,
    // which is a different rule and not what this row is about.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "12",
        "--checkpoint",
        "13",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_second_root_at_the_grounded_size_is_unverifiable_never_answered_from_one_branch() {
    // The second member at tree_size 13 is signed by a key this corpus's manifest chain does
    // not declare — the shape a second branch has when seen from inside the first. Its own
    // chain would authorize its own log key, and this run cannot ask the mirror for the
    // entries behind its root: the request shape of adaptor §10.3 names a range and a tree
    // size, never a root. Answering from the branch that happens to resolve would report a
    // complete closure over a size the client cannot show carries one tree.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-foreign-divergence.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "13",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("would be grounded at tree_size 13"), "{}", run.output());
    // `3` is not an accusation: §7 reserves that for two members that both authenticate.
    assert!(!run.stdout.contains("equivocat"), "{}", run.stdout);

    // A second root strictly *above* the grounded size is carried as a finding instead: the
    // result sits below the floor under every reading, and members below a divergence remain
    // usable.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-foreign-divergence.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let codes: Vec<String> = run.json()["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(codes.iter().any(|code| code == "mirror-served-differing-roots"), "{codes:?}");
}

#[test]
fn row_an_unresolved_divergence_below_the_grounded_size_is_unverifiable() {
    // Adaptor §5.2.2 ends the canonical series from the **lowest** size at which divergence
    // occurs, so a divergence the run could not rule out at tree_size 8 is a floor that a
    // result grounded at 20 sits beyond. The size the checkpoint was selected at is not the
    // boundary; the size the result is grounded on is, and the comparison is `<=`.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-divergence-below.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "18",
        "--checkpoint",
        "20",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("at tree_size 8"), "{}", run.output());
    assert!(run.output().contains("would be grounded at tree_size 20"), "{}", run.output());
    // Still not an accusation: §7 reserves that for two members that both authenticate.
    assert!(!run.stdout.contains("equivocat"), "{}", run.stdout);

    // The same checkpoint and trigger from a mirror that served one root at every size.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "18",
        "--checkpoint",
        "20",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_forged_key_binding_never_authorizes_a_successor_manifest() {
    // Core §2.3.6 and adaptor §7.2 derive `key_id` from the public key and require a mismatch
    // to be rejected — of any `key_id -> pubkey` pair, not only the ones inside a manifest. An
    // authorized producer anchors a `key` add whose id is not derived from the key beside it;
    // the attacker then signs a successor manifest under that borrowed name, and the log key it
    // declares signs the checkpoint a closure would be grounded on.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-forged-key-transition.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "40",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("does not verify"), "{}", run.output());

    // The refusal is of one statement, not of the corpus (adaptor §7.4.1).
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-forged-key-transition.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_the_genuinely_first_published_member_is_unverifiable_by_deliberate_refusal() {
    // Adaptor §5.2.2 item 3 describes a member with no predecessor — an operator may first
    // publish at a size larger than the genesis checkpoint — while §6.6 requires the
    // relationship. Nothing is withheld here: this really is the earliest member the fixture's
    // deployment published.
    //
    // The client still answers `3`, because the sources fix no way for a verifier to prove that
    // an observed member is the first one published, so this case cannot be told apart from a
    // withheld predecessor. Pinned as a decision: adopting the carve-out later has to change
    // this row rather than quietly change a verdict.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "4",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("no authenticated series member precedes"), "{}", run.output());
    assert!(run.output().contains("no client can establish it"), "{}", run.output());
    assert_ne!(run.json()["completeness"], "complete");
}

#[test]
fn row_a_log_key_that_is_not_active_yet_is_unverifiable() {
    // Design note §2 rule 4: the signing key must be in the governing version's `log.keys`
    // **and active by `valid_from_index`**. The manifest version governing this checkpoint
    // declares the key that signed it, but declares it as activating at an entry index the
    // checkpoint does not commit — so the corpus had not adopted it yet.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-inactive-log-key.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "39",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    assert!(run.output().contains("does not verify"), "{}", run.output());

    // Checkpoints that version does not govern are unaffected.
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-inactive-log-key.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_log_key_id_that_does_not_recompute_is_unverifiable() {
    // Adaptor §7.2: "A verifier MUST recompute a key id from the public key it is given and
    // MUST reject a mismatch"; §6.5 step 4 repeats it where a checkpoint signature resolves.
    // The manifest version here files one party's public key under another party's key id and
    // the checkpoint names that id, so a client that trusts the carried value resolves the
    // name to the key the manifest chose and the signature verifies.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-mismatched-key-id.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "39",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    // Specifically because the borrowed id resolves to nothing once the version carrying it is
    // rejected — not because some later rule happened to fire at this checkpoint.
    assert!(run.output().contains("does not verify"), "{}", run.output());

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-mismatched-key-id.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_manifest_version_moving_the_cadence_epoch_is_unverifiable() {
    // Core §7.3 and adaptor §7.3.2: `cadence_epoch` is declared once, by the genesis manifest,
    // and repeated unchanged by every later version. The rotation here links correctly and is
    // signed by a producer key in force at its own entry index — every test of §7.4.1 passes —
    // but it moves the epoch, so it is malformed and must not govern. The checkpoint over it is
    // signed by the log key only that version declares.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-moved-epoch.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "39",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert_eq!(run.json()["reason_code"], "evidence-missing");
    // Specifically because the rejected version's log key never governs — not because some
    // later rule happened to fire at this checkpoint.
    assert!(run.output().contains("does not verify"), "{}", run.output());

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &fixtures().join("mirror-transcript-moved-epoch.json").display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
}

#[test]
fn row_a_consistency_proof_carrying_a_non_family_string_is_unusable_remote_evidence() {
    // Adaptor §8.3: a consistency proof is a JSON array of `sha256:<hex>` family strings and
    // nothing else. The element added here is one a lenient reader would drop — leaving a
    // proof that verifies, and certifying the neighbour relationship on a proof the mirror
    // never served. Any departure from the serialization makes the remote evidence unusable.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path());
    let transcript = mutate_transcript(
        dir.path(),
        "mirror-transcript.json",
        "consistency-with-a-non-string.json",
        |value| {
            let mut touched = false;
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().contains("/v1/consistency") {
                    let mut body = exchange_body(exchange);
                    let path = body["consistency_path"].as_array_mut().expect("path");
                    if path.is_empty() {
                        continue;
                    }
                    path.push(serde_json::json!(42));
                    set_exchange_body(exchange, &body);
                    touched = true;
                }
            }
            assert!(touched, "no non-empty consistency proof was recorded to mutate");
        },
    );
    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "--json",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "13",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    assert!(run.output().contains("is not a string"), "{}", run.output());
}

#[test]
fn row_unsupported_specification_version_is_unverifiable() {
    // §7.7: "an artifact declaring a revision earlier than the one this document defines" is a
    // capability the verifier lacks, never a defect of the artifact.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let receipt = mutate_receipt(dir.path(), "statement-anchored-valid.ahl", |value| {
        value["spec_version"] = serde_json::json!("0.5.0");
    });
    let run = verify(&policy_path.display().to_string(), &receipt.display().to_string(), &[]);
    assert_eq!(run.code, 3, "{}", run.stderr);
    assert!(run.output().contains("versions"), "{}", run.output());
    assert!(!run.output().contains("status: invalid"), "{}", run.output());
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
    let output = run.output();
    // The content binding is the assertion that produced the result, and it is reported
    // alongside the ones that did hold.
    assert!(output.contains("content-binding: unverifiable"), "{output}");
    assert!(output.contains("anchoring: verified"), "{output}");
    // §7.7: "a content binding the verifier cannot compute MUST NOT be re-rendered as
    // `content_binding: \"none\"`". The block is reproduced as the receipt carries it.
    assert!(output.contains("content_binding: keyed-authorized"), "{output}");
    assert!(!output.contains("content_binding: none"), "{output}");
    assert!(!output.contains("boundary:"), "only `verified` renders a boundary: {output}");
}

#[test]
fn row_receipt_limit_exhausted_is_unverifiable() {
    // §7.8: "A verifier MUST report WHICH budget was exhausted and the value that was in force,
    // since `unverifiable` without that is not actionable." Both budgets, because an exhausted
    // one leaves every assertion the run could not reach inheriting the gap, and a report that
    // led with one of those would name the symptom while the actionable fact sat further down.
    let dir = tempfile::tempdir().expect("tempdir");
    for (budget, value, named) in [
        ("max_decoded_bytes", "16", "decoded size"),
        ("max_work_units", "3", "verification work units"),
    ] {
        let mut text = std::fs::read_to_string(policy(dir.path(), &PolicySpec::default()))
            .expect("read policy");
        let _ = writeln!(text, "\n[policy.limits]\n{budget} = {value}");
        let path = dir.path().join(format!("{budget}.toml"));
        std::fs::write(&path, text).expect("write");
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("mode");
        let run = verify(
            &path.display().to_string(),
            &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
            &[],
        );
        assert_eq!(run.code, 3, "rejection, never a degraded acceptance: {}", run.stderr);
        let output = run.output();
        // The HEADLINE names the budget: the reason line is the cause, never an assertion that
        // merely inherited the gap.
        assert!(output.contains("reason: [resource-limits]"), "{output}");
        assert!(!output.contains("reason: [versions]"), "{output}");
        assert!(output.contains(named), "the budget is named: {output}");
        assert!(output.contains(value), "the value in force is named: {output}");
        // And the assertions the run could not reach are still reported, each naming the cause
        // it rests on rather than being dropped or presented as a finding of its own.
        assert!(output.contains("resource-limits: unverifiable"), "{output}");
        assert!(output.contains("rests on `resource-limits`"), "{output}");
    }
}

#[test]
fn row_a_rejection_names_the_assertion_that_produced_it_and_the_ones_that_held() {
    // §7.7: a verifier "MUST report the findings alongside" the result, "because the result
    // alone does not say which assertion produced it". `invalid` on one assertion does not
    // make the receipt's other assertions unreported.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &corpus().join("receipts/overclaim-must-fail.ahl").display().to_string(),
        &[],
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let output = run.output();
    assert!(output.contains("status: invalid"), "{output}");
    assert!(output.contains("cross-field: invalid"), "{output}");
    assert!(output.contains("anchoring: verified"), "{output}");
    assert!(!output.contains("boundary:"), "only `verified` renders a boundary: {output}");
}

#[test]
fn row_a_rejection_the_core_classes_unverifiable_is_never_reclassified_here() {
    // The class of a rejection is the core's answer, from the rule that fired. The corpus's one
    // non-`invalid` negative vector is a declared-mode envelope naming a producer-key
    // transition the mode does not carry (I-D §7.4).
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());
    let run = verify(
        &policy_path.display().to_string(),
        &corpus()
            .join("receipts/statement-anchored-uncarried-key-transition-must-fail.ahl")
            .display()
            .to_string(),
        &[],
    );
    assert_eq!(run.code, 3, "{}", run.output());
    let output = run.output();
    assert!(output.contains("status: unverifiable"), "{output}");
    assert!(output.contains("envelope-validity: unverifiable"), "{output}");
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
        "39",
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
        &ahl_cli::testing::statements_with_published_tree_material(dir.path())
            .display()
            .to_string(),
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
fn row_a_defect_in_the_governance_chain_never_silences_the_rest_of_a_topology_corpus() {
    // §6 fixes topology mode's contract: violations are findings, reported **in full** and
    // never suppressed, with the outcome at `3`. Entry 1's `key` add carries a `key_id` that
    // does not recompute from the `pubkey` beside it — it must never join a key set (core
    // §2.3.6, adaptor §7.2) — and entry 2 is signed by a key nothing declares. Excluding the
    // first must not take the second out of the report.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());

    // Two published test keys of the conformance corpus, used here only as key material: the
    // id names one and the payload carries the other's public key.
    let producer = ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
    let attacker = ahl_core::TestKey::from_seed_hex("attacker", &"7d".repeat(32)).expect("seed");
    let fake = ahl_core::TestKey::from_seed_hex("fake", &"7c".repeat(32)).expect("seed");
    let stranger = ahl_core::TestKey::from_seed_hex("stranger", &"09".repeat(32)).expect("seed");

    let entries = serde_json::json!([
        { "entry_index": 0, "envelope": ahl_core::envelope(
            serde_json::json!({
                "type": "manifest",
                "producer": "producer-1",
                "keys": [ producer.key_object(0) ],
                "log": { "log_id": "sha256:aa", "keys": [] },
            }), &producer) },
        { "entry_index": 1, "envelope": ahl_core::envelope(
            serde_json::json!({
                "type": "key",
                "action": "add",
                "manifest": "sha256:aa",
                "key": { "key_id": fake.key_id(), "pubkey": attacker.pubkey() },
            }), &producer) },
        { "entry_index": 2, "envelope": ahl_core::envelope(
            serde_json::json!({
                "type": "retraction", "manifest": "sha256:aa",
                "dataset": "d", "record": "sha256:bb",
                "scope": { "effective_from": "2026-01-01T00:00:00Z", "retroactive": true },
            }), &stranger) },
    ]);
    let corpus_path = dir.path().join("corpus.json");
    std::fs::write(&corpus_path, serde_json::to_vec(&entries).expect("serialize"))
        .expect("write corpus");

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus_path.display().to_string(),
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
        "--trigger-index",
        "2",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    let report = run.json();
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();
    assert!(codes.contains(&"governance-element-excluded"), "{codes:?}");
    assert!(
        codes.contains(&"signature-does-not-verify"),
        "entry 2's violation disappeared behind the excluded element: {codes:?}"
    );
    assert!(
        !codes.contains(&"corpus-governance-unresolvable"),
        "one bad element must not make the chain unresolvable: {codes:?}"
    );
}

#[test]
fn row_the_reason_a_topology_chain_emptied_is_reported_beside_the_fact_that_it_did() {
    // The terminal path of the same rule. This corpus's only manifest carries a `predecessor`
    // the genesis manifest must not have (core §2.3.5, adaptor §7.4.1): it is excluded, and
    // then no chain remains. Reporting only "the chain does not resolve" would replace a
    // violation the walk had already established with a general one — the suppression §6
    // forbids, moved to the last line.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default());

    let producer = ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
    let entries = serde_json::json!([
        { "entry_index": 0, "envelope": ahl_core::envelope(
            serde_json::json!({
                "type": "manifest",
                "producer": "producer-1",
                "predecessor": format!("sha256:{}", "aa".repeat(32)),
                "keys": [ producer.key_object(0) ],
                "log": { "log_id": "sha256:aa", "keys": [] },
            }), &producer) },
        { "entry_index": 1, "envelope": ahl_core::envelope(
            serde_json::json!({
                "type": "retraction", "manifest": "sha256:aa",
                "dataset": "d", "record": "sha256:bb",
                "scope": { "effective_from": "2026-01-01T00:00:00Z", "retroactive": true },
            }), &producer) },
    ]);
    let corpus_path = dir.path().join("corpus.json");
    std::fs::write(&corpus_path, serde_json::to_vec(&entries).expect("serialize"))
        .expect("write corpus");

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus_path.display().to_string(),
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
        "--trigger-index",
        "1",
    ]);
    assert_eq!(run.code, 3, "{}{}", run.stdout, run.stderr);
    let report = run.json();
    let findings = report["findings"].as_array().expect("findings");
    let codes: Vec<&str> = findings.iter().filter_map(|f| f["code"].as_str()).collect();
    assert!(codes.contains(&"governance-element-excluded"), "{codes:?}");
    assert!(codes.contains(&"corpus-governance-unresolvable"), "{codes:?}");
    assert!(
        findings
            .iter()
            .any(|f| f["detail"].as_str().unwrap_or_default().contains("no predecessor reference")),
        "the rule that fired must be named: {findings:?}"
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
    assert!(document["boundary"].is_string(), "a valid result renders the boundary");

    let run = ahl_cli(&[
        "--policy",
        &policy_path.display().to_string(),
        AT,
        much_later,
        "--json",
        "verify",
        &receipt.display().to_string(),
        "--require-fresh",
    ]);
    assert_eq!(run.code, 3, "--require-fresh promotes it to unverifiable, never to invalid");
    let document = run.json();
    // A boundary asserts the property in words, so it is rendered where the FINAL status is
    // `valid` and nowhere else — the core's boundary is never carried under a status the
    // freshness overlay moved.
    assert!(document["boundary"].is_null(), "{document}");
    // And the status is the reduction of the assertions reported beside it: the overlay is one
    // of them, `unverifiable` and never `invalid`.
    let assertions = document["assertions"].as_array().expect("assertions");
    let freshness = assertions
        .iter()
        .find(|entry| entry["assertion"] == "witness-freshness")
        .expect("the overlay is reported as an assertion");
    assert_eq!(freshness["outcome"], "unverifiable");
    assert!(
        assertions.iter().all(
            |entry| entry["outcome"] == "verified" || entry["assertion"] == "witness-freshness"
        ),
        "nothing else moved: {document}"
    );
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
        &ahl_cli::testing::statements_with_published_tree_material(dir.path())
            .display()
            .to_string(),
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
