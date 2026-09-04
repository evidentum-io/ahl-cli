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

/// Every fixture a transcript is recorded from, paired with the file it is written to.
///
/// `None` where the conformance corpus publishes no usable key seeds. Building them in one
/// place keeps the pairing of a fixture with its filename in one place too, and gives the
/// missing-seed case a single exit rather than one per fixture.
///
/// Several fixtures are needed because the §6 outcome table distinguishes outcomes a single
/// honest transcript cannot exercise: a divergent series, a checkpoint signed by a key no
/// manifest declares, a mirror serving bytes the checkpoint does not commit, a forged later
/// manifest, an anchored statement of a type core §2.3 does not define, a mirror withholding
/// the history below the checkpoint a result is grounded on, a second root at that size signed
/// by a key this corpus does not authorize, a manifest version declaring a log key that is not
/// active yet, one whose log key object files a public key under another party's id, and one
/// that moves `cadence_epoch`.
fn fixtures() -> Option<Vec<(&'static str, MirrorFixture)>> {
    Some(vec![
        ("mirror-transcript.json", MirrorFixture::conformance()?),
        (
            "mirror-transcript-equivocating.json",
            MirrorFixture::conformance()?.with_equivocation_at(13),
        ),
        (
            "mirror-transcript-foreign-key.json",
            MirrorFixture::conformance()?.with_foreign_log_key(8),
        ),
        ("mirror-transcript-tampered.json", MirrorFixture::conformance()?.with_tampered_entry(3)),
        (
            "mirror-transcript-forged-manifest.json",
            MirrorFixture::conformance()?.with_forged_manifest(),
        ),
        (
            "mirror-transcript-unknown-statement.json",
            MirrorFixture::conformance()?.with_unknown_statement_type(),
        ),
        (
            "mirror-transcript-withheld-predecessor.json",
            MirrorFixture::conformance()?.with_series_from(13),
        ),
        (
            "mirror-transcript-foreign-divergence.json",
            MirrorFixture::conformance()?.with_foreign_divergence_at(13),
        ),
        (
            "mirror-transcript-divergence-below.json",
            MirrorFixture::conformance()?.with_foreign_divergence_at(8),
        ),
        (
            "mirror-transcript-forged-key-transition.json",
            MirrorFixture::conformance()?.with_forged_key_transition(),
        ),
        (
            "mirror-transcript-inactive-log-key.json",
            MirrorFixture::conformance()?.with_future_activated_log_key(),
        ),
        (
            "mirror-transcript-mismatched-key-id.json",
            MirrorFixture::conformance()?.with_mismatched_log_key_id(),
        ),
        (
            "mirror-transcript-moved-epoch.json",
            MirrorFixture::conformance()?.with_moved_cadence_epoch(),
        ),
    ])
}

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

    // Several fixtures, because the §6 table distinguishes outcomes a single honest transcript
    // cannot exercise: a divergent series, a checkpoint signed by a key no manifest declares,
    // a mirror serving bytes the checkpoint does not commit, a forged later manifest, and an
    // anchored statement of a type core §2.3 does not define.
    let Some(fixtures) = fixtures() else {
        eprintln!("gen_fixtures: the conformance corpus publishes no usable key seeds");
        return std::process::ExitCode::FAILURE;
    };

    for (_, fixture) in &fixtures {
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

    let written = fixtures.iter().map(|(name, fixture)| (*name, fixture.transcript())).chain(
        std::iter::once(("tree-material.json", tree_material(&MirrorFixture::corpus_root()))),
    );
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
