//! Records the fixed network transcripts the integration tests replay.
//!
//! Design note §5 states the cache invariant — cold, warm and adversarially poisoned caches
//! produce identical verdicts and exit codes — and states that it must be evaluated against a
//! **fixed recorded transcript**, because against a live endpoint whose state changes between
//! runs "identical" would not be a property of the CLI at all. This binary is how that
//! transcript comes to exist.
//!
//! It has no clock read and no randomness: everything comes from the committed `ahl-core`
//! conformance corpus and the published test key seeds, so two consecutive runs leave
//! `tests/fixtures/` byte-identical. If they do not, that is a bug.
//!
//! ```text
//! cargo run --bin gen_fixtures
//! ```

use std::path::Path;

use ahl_cli::commands::{closure, reconstruct};
use ahl_cli::evaluation::EvaluationTime;
use ahl_cli::testing::{tree_material, MirrorFixture};

fn main() -> std::process::ExitCode {
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    if let Err(error) = std::fs::create_dir_all(&out) {
        eprintln!("gen_fixtures: cannot create {}: {error}", out.display());
        return std::process::ExitCode::FAILURE;
    }

    let Ok(evaluation) = EvaluationTime::resolve(Some(ahl_cli::testing::FIXED_TIME)) else {
        eprintln!("gen_fixtures: the fixed instant did not parse");
        return std::process::ExitCode::FAILURE;
    };

    // Four fixtures, because the §6 table distinguishes outcomes a single honest transcript
    // cannot exercise: a divergent series, a checkpoint signed by a key no manifest declares,
    // and a mirror serving bytes the checkpoint does not commit.
    let honest = MirrorFixture::conformance();
    let equivocating = MirrorFixture::conformance().with_equivocation_at(13);
    let foreign_key = MirrorFixture::conformance().with_foreign_log_key(8);
    let tampered = MirrorFixture::conformance().with_tampered_entry(3);
    let forged_manifest = MirrorFixture::conformance().with_forged_manifest();

    for fixture in [&honest, &equivocating, &foreign_key, &tampered, &forged_manifest] {
        // Drive every request path the integration tests replay: an authenticated closure at
        // several checkpoints, and a reconstruction, which additionally reads the witness.
        let mut sizes = ahl_cli::testing::CHECKPOINT_SIZES.to_vec();
        sizes.push(fixture.forged_tree_size());
        for tree_size in sizes {
            let _ = closure::run(
                &fixture.policy,
                &evaluation,
                &closure::Options {
                    trigger: closure::TriggerRef::EntryIndex(6),
                    unauthenticated: false,
                    corpus: None,
                    tree_material: None,
                    checkpoint: Some(tree_size),
                },
                Some(fixture),
            );
        }
        let (dataset, record) = fixture.record_a();
        let _ = reconstruct::run(
            &fixture.policy,
            &evaluation,
            &reconstruct::Options {
                dataset,
                record,
                valid_time: ahl_cli::testing::FIXED_TIME.to_owned(),
                checkpoint: Some(32),
            },
            Some(fixture),
        );
    }

    let written = [
        ("mirror-transcript.json", honest.transcript()),
        ("mirror-transcript-equivocating.json", equivocating.transcript()),
        ("mirror-transcript-foreign-key.json", foreign_key.transcript()),
        ("mirror-transcript-tampered.json", tampered.transcript()),
        ("mirror-transcript-forged-manifest.json", forged_manifest.transcript()),
        ("tree-material.json", tree_material(&MirrorFixture::corpus_root())),
    ];
    for (name, value) in written {
        let Ok(mut bytes) = serde_json::to_vec_pretty(&value) else {
            eprintln!("gen_fixtures: cannot serialize {name}");
            return std::process::ExitCode::FAILURE;
        };
        bytes.push(b'\n');
        if let Err(error) = std::fs::write(out.join(name), &bytes) {
            eprintln!("gen_fixtures: cannot write {name}: {error}");
            return std::process::ExitCode::FAILURE;
        }
        println!("wrote {} ({} bytes)", out.join(name).display(), bytes.len());
    }
    std::process::ExitCode::SUCCESS
}
