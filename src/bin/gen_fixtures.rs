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

    // Several fixtures, because the §6 table distinguishes outcomes a single honest transcript
    // cannot exercise: a divergent series, a checkpoint signed by a key no manifest declares,
    // a mirror serving bytes the checkpoint does not commit, a forged later manifest, and an
    // anchored statement of a type core §2.3 does not define.
    let honest = MirrorFixture::conformance();
    let equivocating = MirrorFixture::conformance().with_equivocation_at(13);
    let foreign_key = MirrorFixture::conformance().with_foreign_log_key(8);
    let tampered = MirrorFixture::conformance().with_tampered_entry(3);
    let forged_manifest = MirrorFixture::conformance().with_forged_manifest();
    let unknown_statement = MirrorFixture::conformance().with_unknown_statement_type();
    // The four adversarial series the outcome table needs and an honest transcript cannot
    // carry: a mirror withholding the history below the checkpoint a result is grounded on, a
    // second root at that size signed by a key this corpus does not authorize, a manifest
    // version declaring a log key that is not active yet, one whose log key object files a
    // public key under another party's id, and one that moves `cadence_epoch`.
    let withheld_predecessor = MirrorFixture::conformance().with_series_from(13);
    let foreign_divergence = MirrorFixture::conformance().with_foreign_divergence_at(13);
    let divergence_below = MirrorFixture::conformance().with_foreign_divergence_at(8);
    let forged_key_transition = MirrorFixture::conformance().with_forged_key_transition();
    let inactive_log_key = MirrorFixture::conformance().with_future_activated_log_key();
    let mismatched_key_id = MirrorFixture::conformance().with_mismatched_log_key_id();
    let moved_epoch = MirrorFixture::conformance().with_moved_cadence_epoch();

    for fixture in [
        &honest,
        &equivocating,
        &foreign_key,
        &tampered,
        &forged_manifest,
        &unknown_statement,
        &withheld_predecessor,
        &foreign_divergence,
        &divergence_below,
        &forged_key_transition,
        &inactive_log_key,
        &mismatched_key_id,
        &moved_epoch,
    ] {
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
        ("mirror-transcript-unknown-statement.json", unknown_statement.transcript()),
        ("mirror-transcript-withheld-predecessor.json", withheld_predecessor.transcript()),
        ("mirror-transcript-foreign-divergence.json", foreign_divergence.transcript()),
        ("mirror-transcript-divergence-below.json", divergence_below.transcript()),
        ("mirror-transcript-forged-key-transition.json", forged_key_transition.transcript()),
        ("mirror-transcript-inactive-log-key.json", inactive_log_key.transcript()),
        ("mirror-transcript-mismatched-key-id.json", mismatched_key_id.transcript()),
        ("mirror-transcript-moved-epoch.json", moved_epoch.transcript()),
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
