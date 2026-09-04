//! Arbitrary bytes through the trust policy parser: UTF-8, then TOML, then the ordered
//! validation of every section.
//!
//! The policy file is the client's trust anchor, and it is the one input an operator edits by
//! hand — so it is also the one most likely to be malformed by accident. What is under test is
//! the whole of `policy::load` after the handle checks: the TOML parse, the family-string
//! checks on the genesis entry id and key fingerprints, the witness key sections, the adaptor
//! profile entries, the dataset key decode, the endpoint checks and the limit sections. None
//! may panic on any input, however absurd the values or however deeply nested the tables.
//!
//! `base` is a directory that does not exist, so a policy naming a dataset key by `file`
//! reaches the read and is refused, without this target touching a real key.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let base = std::path::Path::new("/nonexistent-fuzz-base");
    let _ = ahl_cli::policy::from_toml_str(text, base);
});
