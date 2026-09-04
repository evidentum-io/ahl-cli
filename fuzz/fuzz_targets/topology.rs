//! Arbitrary bytes through the local corpus reader and the topology walk.
//!
//! `closure --unauthenticated` reads a corpus file the operator points at and walks it without
//! anchoring anything, so every structural decision is made over bytes nobody authenticated:
//! entry indexes, duplicate positions, envelope objects, and then the derivation topology
//! itself. The reader reports what it cannot use as a finding rather than refusing the file,
//! which makes the finding path — not only the accept path — the one that has to hold.
//!
//! `dense_envelopes` is driven as well: it is the second reader of the same material, and it
//! is where a corpus with holes in its index space is turned into a dense sequence.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(corpus) = ahl_cli::corpus::from_json_bytes(data, ahl_cli_fuzz::local_limits()) else {
        return;
    };
    let _ = ahl_cli::corpus::walk(&corpus);
    let _ = corpus.dense_envelopes();
});
