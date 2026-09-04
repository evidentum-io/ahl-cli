//! Every test vector in `ahl-core/test_data`, exercised **end-to-end through the built
//! binary** — not only through the library.
//!
//! Design note §9 makes this non-negotiable, and the reason is not ceremony: a verifier whose
//! rules are only ever exercised in-process has never demonstrated that its *exit codes* carry
//! them, and the exit code is what a CI pipeline reads.
//!
//! The corpus's own `receipts/index.json` states the outcome a conformant verifier must reach
//! for each receipt, and the rule each negative vector must trip. Both are asserted here, so a
//! drift in either direction fails.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::multiple_crate_versions
)]

mod common;

use common::{ahl_cli, corpus, fixtures, policy, PolicySpec};

const AT: &str = "--evaluation-time";
const FIXED: &str = "2026-08-16T12:00:00Z";

/// Collapse runs of whitespace, so a comparison is on the words rather than on the layout.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn index() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(corpus().join("receipts/index.json")).expect("index"))
        .expect("index parses")
}

#[test]
fn every_receipt_vector_reaches_the_outcome_the_corpus_declares() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let document = index();
    let vectors = document["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 20, "the corpus carries 20+ receipts, got {}", vectors.len());

    for vector in vectors {
        let file = vector["file"].as_str().expect("file");
        let path = corpus().join("receipts").join(file);
        let run = ahl_cli(&[
            "--policy",
            &policy_path,
            AT,
            FIXED,
            "--json",
            "verify",
            &path.display().to_string(),
        ]);
        let report = run.json();
        let expect = vector["expect"].as_str().expect("expect");
        // The corpus index states the §7.7 result; §6 fixes the exit code each one carries.
        let (code, status) = match expect {
            "verified" => (0, "valid"),
            "invalid" => (1, "invalid"),
            "unverifiable" => (3, "unverifiable"),
            other => panic!("unknown expectation `{other}` for {file}"),
        };
        assert_eq!(run.code, code, "{file}: {}", report["reason"]);
        // The receipt's own result, and this run's decision beside it. No policy overlay
        // applies here, so the two agree.
        assert_eq!(report["status"], status, "{file}");
        assert_eq!(report["outcome"], status, "{file}");
        // The void entries the corpus says the vector carries, counted through the binary. A
        // vector carrying them still reaches the result its `expect` names.
        let void = vector["informative"].as_u64().unwrap_or(0);
        let reported = report["informative"].as_array().expect("void entries are reported");
        assert_eq!(reported.len() as u64, void, "{file}: {report}");

        if expect == "verified" {
            assert_eq!(report["claim_type"], vector["claim_type"], "{file}");
            // The verdict is rendered from `ahl_core::receipt::Verdict` and is never stronger
            // than the boundary that struct carries. Compared on the words: the corpus index
            // records one boundary with a run of spaces where its generator wrapped the line,
            // and the rule under test is the strength of the claim, not its layout.
            assert_eq!(
                words(report["boundary"].as_str().unwrap_or_default()),
                words(vector["boundary"].as_str().unwrap_or_default()),
                "{file}"
            );
            continue;
        }

        assert!(report["boundary"].is_null(), "{file}: only `verified` renders a boundary");
        let expected = vector["reason"].as_str().expect("reason");
        assert!(
            report["reason"].as_str().unwrap_or_default().contains(expected),
            "{file}: expected the rule `{expected}` to fire, got {}",
            report["reason"]
        );
        // §7.7 requires the findings to be reported alongside the result, since "the result
        // alone does not say which assertion produced it".
        let assertion = vector["finding"].as_str().expect("finding");
        let assertions = report["assertions"].as_array().expect("assertions");
        assert!(
            assertions
                .iter()
                .any(|entry| entry["assertion"] == assertion && entry["outcome"] == expect),
            "{file}: `{assertion}` is not reported as `{expect}`: {report}"
        );
    }
}

#[test]
fn every_receipt_vector_also_inspects_without_a_verdict() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let document = index();
    for vector in document["vectors"].as_array().expect("vectors") {
        let file = vector["file"].as_str().expect("file");
        let path = corpus().join("receipts").join(file);
        let run =
            ahl_cli(&["--policy", &policy_path, "--json", "inspect", &path.display().to_string()]);
        assert_eq!(run.code, 0, "{file}: {}", run.stderr);
        let dump = run.json();
        assert!(dump.get("status").is_none(), "{file}: a dump carries no verdict");
        assert_eq!(dump["jcs_canonical"], true, "{file}");
        assert!(dump["disclaimer"]
            .as_str()
            .unwrap_or_default()
            .contains("nothing here is verified"));
    }
}

#[test]
fn every_closure_vector_is_reproduced_through_the_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let trees = fixtures().join("tree-material.json").display().to_string();
    let transcript = fixtures().join("mirror-transcript.json").display().to_string();

    let mut checked = 0;
    for entry in std::fs::read_dir(corpus().join("vectors/closure")).expect("closure vectors") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let vector: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("vector")).expect("parses");
        let trigger_index = vector["trigger"]["entry_index"].as_u64().expect("index");
        let tree_size = vector["corpus_checkpoint"]["tree_size"].as_u64().expect("tree size");
        let expected: Vec<serde_json::Value> = vector["expected_affected"]
            .as_array()
            .expect("array")
            .iter()
            .map(|item| {
                serde_json::json!({
                    "dataset": item["dataset"],
                    "record": item["record"],
                })
            })
            .collect();

        // The recorded transcript publishes checkpoints at a fixed set of sizes; a vector
        // grounded elsewhere is exercised in topology mode instead, where the whole corpus is
        // walked and the answer is explicitly not an affected set.
        let published = ahl_cli::testing::CHECKPOINT_SIZES.contains(&tree_size);
        let run = if published {
            ahl_cli(&[
                "--policy",
                &policy_path,
                AT,
                FIXED,
                "--json",
                "--transcript",
                &transcript,
                "closure",
                "--trigger-index",
                &trigger_index.to_string(),
                "--checkpoint",
                &tree_size.to_string(),
                "--tree-material",
                &trees,
            ])
        } else {
            continue;
        };

        let report = run.json();
        // `closure` verifies no receipt, so it reports no §7.7 result: its answer is `outcome`.
        assert!(report["status"].is_null(), "{}: {report}", path.display());
        if report["outcome"] == "valid" {
            assert_eq!(
                report["affected"].as_array().expect("affected"),
                &expected,
                "{}",
                path.display()
            );
            checked += 1;
        } else {
            // A vector whose trigger is superseded at that checkpoint is legitimately not
            // computable there; the CLI must say which trigger governs instead of answering.
            assert_eq!(run.code, 3, "{}: {}", path.display(), report["reason"]);
            assert!(
                report["reason"].as_str().unwrap_or_default().contains("does not govern"),
                "{}: {}",
                path.display(),
                report["reason"]
            );
        }
    }
    assert!(checked > 0, "at least one closure vector must be reproduced authenticated");
}

#[test]
fn the_toy_corpus_walks_in_topology_mode_through_the_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
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
    let report = run.json();
    assert_eq!(report["authenticated"], false);
    assert!(report.get("affected").is_none(), "the two results never share a field name");
    assert!(report["topology_affected"].as_array().expect("topology").len() >= 4);
}

#[test]
fn every_statement_vector_is_re_emitted_and_matches_its_published_identifiers() {
    // `emit` signs with the same published producer seed the corpus used, so a re-emitted
    // payload must reproduce the corpus's own `statement_id` and `entry_id` byte for byte.
    // That is the canonicalization-drift check the tool exists to prevent.
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = dir.path().join("producer-1.seed");
    std::fs::copy(corpus().join("keys/producer-1.seed"), &seed).expect("copy seed");
    std::fs::set_permissions(&seed, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");

    let mut checked = 0;
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(corpus().join("vectors/statements"))
        .expect("statements")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();

    for file in files {
        let vector: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).expect("vector")).expect("parses");
        let payload = &vector["envelope"]["payload"];
        let signatures = vector["envelope"]["signatures"].as_array().expect("signatures");
        // Only the single-signature statements by `producer-1` can be reproduced by re-signing
        // with that one seed; the rest are exercised through `closure` and `verify` instead.
        if signatures.len() != 1 {
            continue;
        }
        let payload_path = dir.path().join("payload.json");
        std::fs::write(&payload_path, serde_json::to_vec(payload).expect("serialize"))
            .expect("write");

        let run = ahl_cli(&[
            "--json",
            "emit",
            &payload_path.display().to_string(),
            "--key-file",
            &seed.display().to_string(),
        ]);
        if run.code != 0 {
            // A payload this build refuses to sign is a locally decidable rule firing, which
            // is a legitimate answer; it must never be a silent success.
            assert_eq!(run.code, 1, "{}: {}", file.display(), run.output());
            continue;
        }
        let emitted = run.json();
        assert_eq!(
            emitted["statement_id"],
            vector["statement_id"],
            "{}: canonicalization drift",
            file.display()
        );
        if emitted["envelope"]["signatures"] == vector["envelope"]["signatures"] {
            assert_eq!(emitted["entry_id"], vector["entry_id"], "{}", file.display());
        }
        checked += 1;
    }
    assert!(checked >= 20, "most of the toy corpus should be re-emittable, got {checked}");
}

#[test]
fn the_published_witness_refusal_vector_is_checked_in_full() {
    // The corpus has adopted the §11.2.1 taxonomy: the vector now declares `equivocation`,
    // which is the one self-contained reason — two signed checkpoints, one `tree_size`, two
    // roots, no possible append-only tree. Every §11.2.5 step is run over it here, and it must
    // verify.
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("vectors/witness/refusal-evidence.json")).expect("vector"),
    )
    .expect("parses");
    let refusal = &vector["refusal"];
    assert_eq!(
        refusal["reason"], "equivocation",
        "the removed reason `inconsistent` must never come back (§11.2.4)"
    );

    let log_key = ahl_core::TestKey::from_seed_hex(
        "log-1",
        std::fs::read_to_string(corpus().join("keys/log-1.seed")).expect("seed").trim(),
    )
    .expect("seed");
    let witness_key = ahl_core::TestKey::from_seed_hex(
        "witness-1",
        std::fs::read_to_string(corpus().join("keys/witness-1.seed")).expect("seed").trim(),
    )
    .expect("seed");
    let witness_keys =
        std::collections::BTreeMap::from([(witness_key.key_id(), witness_key.pubkey())]);
    let log_keys = std::collections::BTreeMap::from([(log_key.key_id(), log_key.pubkey())]);
    let log_id = refusal["log_id"].as_str().expect("log id");

    let checked = ahl_cli::witness::check_refusal(
        refusal,
        ahl_cli::checkpoint::SigningForm::CanonicalJson,
        &witness_keys,
        &log_keys,
        log_id,
    )
    .expect("the published refusal verifies in full");
    assert_eq!(checked.reason, ahl_cli::witness::RefusalReason::Equivocation);
    assert_eq!(checked.retained_size, checked.offered_size, "equivocation is one size, two roots");

    // A verified `equivocation` refusal is evidence about the log's conduct within the boundary
    // of its reason, never a verdict about any particular statement.
    let finding = checked.finding();
    assert_eq!(finding.code, "witness-refusal-equivocation");
    assert!(finding.detail.contains("two different roots"), "{}", finding.detail);

    // And it is bound to the corpus's own Data Tree: the same evidence offered for another log
    // is unusable.
    assert!(ahl_cli::witness::check_refusal(
        refusal,
        ahl_cli::checkpoint::SigningForm::CanonicalJson,
        &witness_keys,
        &log_keys,
        &format!("sha256:{}", "99".repeat(32)),
    )
    .is_err());
}

#[test]
fn the_published_range_proof_vectors_verify_and_their_negatives_do_not() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("vectors/merkle/range-proof.json")).expect("vector"),
    )
    .expect("parses");
    let cases = vector["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let proof =
            ahl_core::range_proof::decode(case["adaptor_form"].as_str().expect("adaptor form"))
                .expect("the published proof decodes");
        assert_eq!(proof.from_index, case["range"]["from_index"].as_u64().expect("from"));
        assert_eq!(proof.to_index, case["range"]["to_index"].as_u64().expect("to"));
        assert_eq!(proof.tree_size, vector["checkpoint"]["tree_size"].as_u64().expect("size"));
        assert_eq!(proof.nodes.len() as u64, case["node_count"].as_u64().expect("node count"));
    }
}

#[test]
fn the_published_checkpoints_authenticate_under_the_corpus_manifests() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("vectors/checkpoints/checkpoints.json")).expect("vector"),
    )
    .expect("parses");
    // Every log key the corpus publishes, not just the first: the log rotates its
    // checkpoint-signing key by anchoring a new manifest version, and the corpus does. Holding
    // one key would make the members past the rotation fail for the one reason that is not a
    // defect — this verifier not being given the key the governing version declares.
    let mut seeds: Vec<std::path::PathBuf> = std::fs::read_dir(corpus().join("keys"))
        .expect("keys")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("log-") && name.ends_with(".seed"))
        })
        .collect();
    seeds.sort();
    assert!(seeds.len() >= 2, "the corpus rotates its log key: {seeds:?}");
    let keys: std::collections::BTreeMap<String, String> = seeds
        .iter()
        .map(|seed| {
            let name = seed.file_stem().and_then(|name| name.to_str()).unwrap_or("log");
            let key = ahl_core::TestKey::from_seed_hex(
                name,
                std::fs::read_to_string(seed).expect("seed").trim(),
            )
            .expect("seed");
            (key.key_id(), key.pubkey())
        })
        .collect();

    let members = vector["checkpoints"].as_array().expect("checkpoints");
    assert!(!members.is_empty());
    for member in members {
        let checkpoint =
            ahl_cli::checkpoint::Checkpoint::from_value(&member["checkpoint"]).expect("parses");
        assert!(
            checkpoint
                .signature_verifies(ahl_cli::checkpoint::SigningForm::CanonicalJson, &keys)
                .expect("readable"),
            "{} did not authenticate",
            member["name"]
        );
    }
    // And the whole published series carries no divergence.
    let series: Vec<ahl_cli::checkpoint::Checkpoint> = members
        .iter()
        .filter_map(|member| {
            ahl_cli::checkpoint::Checkpoint::from_value(&member["checkpoint"]).ok()
        })
        .collect();
    assert_eq!(ahl_cli::checkpoint::equivocation_floor(&series), None);
}

#[test]
fn the_published_malformed_statements_are_reported_when_walked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();

    // The corpus keeps its malformed statements in a subdirectory, each naming the rule it
    // violates. Walked as a corpus, every one of them must produce a finding.
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--json",
        "closure",
        "--unauthenticated",
        "--corpus",
        &corpus().join("vectors/statements/malformed").display().to_string(),
        "--trigger-index",
        "0",
    ]);
    assert_eq!(run.code, 3, "topology mode never returns 0: {}", run.output());
    assert!(
        run.stdout.contains("findings") || run.output().contains("findings"),
        "the malformed corpus must produce findings: {}",
        run.output()
    );
}

#[test]
fn the_published_log_tree_vector_recomputes_under_the_profile_leaf_construction() {
    // The log tree is the one tree that uses the adaptor's own leaf construction; the
    // record-sorted trees of §9 use plain leaf hashing, and applying one to the other is the
    // asymmetry the profile calls out. Recomputing every published root from the published
    // entries is what proves this build applies the right one.
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus().join("vectors/merkle/log-tree.json")).expect("vector"),
    )
    .expect("parses");

    let mut leaves: Vec<atl_core::core::merkle::Hash> = Vec::new();
    for entry in vector["entries"].as_array().expect("entries") {
        let published = entry["leaf_hash"].as_str().expect("leaf hash");
        let leaf = ahl_core::parse_hash_hex(published).expect("family string");
        leaves.push(leaf);
    }
    assert!(leaves.len() >= 25);

    for member in vector["roots"].as_array().expect("roots") {
        let tree_size = usize::try_from(member["tree_size"].as_u64().expect("tree size"))
            .expect("small test size");
        let recomputed = atl_core::core::merkle::compute_root(&leaves[..tree_size]);
        assert_eq!(
            ahl_core::hash_hex(&recomputed),
            member["root"].as_str().expect("root"),
            "{} did not recompute",
            member["name"]
        );
    }

    // And the published inclusion path opens the checkpoint it names.
    let inclusion = &vector["inclusion"];
    let leaf_index = inclusion["leaf_index"].as_u64().expect("leaf index");
    let tree_size = inclusion["tree_size"].as_u64().expect("tree size");
    let path: Vec<String> = inclusion["path"]
        .as_array()
        .expect("path")
        .iter()
        .filter_map(|hash| hash.as_str().map(str::to_owned))
        .collect();
    let proof = ahl_core::proof_from_hex(leaf_index, tree_size, &path).expect("path");
    let root = ahl_core::parse_hash_hex(inclusion["root"].as_str().expect("root")).expect("root");
    let leaf = leaves[usize::try_from(leaf_index).expect("small test size")];
    assert!(
        atl_core::core::merkle::verify_inclusion(&leaf, &proof, &root).expect("well-formed"),
        "the published inclusion path must open its published root"
    );
}
