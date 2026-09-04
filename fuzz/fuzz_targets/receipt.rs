//! Arbitrary bytes through the `verify` path under a fixed policy.
//!
//! This is the widest entry point the client has. Behind it sit the version read of I-D §7.5
//! step 1, the JCS canonicality check, adaptor profile resolution against the pinned digest,
//! the whole `ahl-core` receipt run, and then this crate's own overlays — freshness against
//! the governing cadence, witness quorum, the policy overlay rows and the report rendering.
//! Every one of them must produce a report, never abort: the exit-code contract requires a
//! report on every path, and a panic would deny the caller even an exit code.
//!
//! Both `require_fresh` settings are driven, because the flag selects a different branch of
//! the staleness overlay.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (Some(policy), Some(evaluation)) = (ahl_cli_fuzz::policy(), ahl_cli_fuzz::evaluation())
    else {
        return;
    };

    for require_fresh in [false, true] {
        let options = ahl_cli::commands::verify::Options {
            // Unread on this path: the bytes are handed in directly.
            receipt: std::path::PathBuf::new(),
            require_fresh,
        };
        let _ = ahl_cli::commands::verify::run_bytes(policy, evaluation, data, &options);
    }
});
