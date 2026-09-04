//! Arbitrary bytes as the body of every mirror and witness response.
//!
//! A mirror is an untrusted server, and the client's rule is that nothing it says is evidence
//! until it verifies against material selected locally. This target answers every request —
//! the checkpoint series, the range subranges, the consistency path, the entry lookup — with
//! the same fuzzed body, and drives the whole establishment: series parse and ordering,
//! enumeration and tiling, root recomputation, governance resolution and checkpoint
//! authentication. A body that is not JSON, that is JSON of the wrong shape, or that carries
//! indexes and sizes chosen to break an assumption must come back as missing evidence.
//!
//! The two parsers that take a response body directly are driven as well: the §10.4 range
//! response check, and the §11.2.5 witness refusal check.

#![no_main]

use std::collections::BTreeMap;

use ahl_cli::checkpoint::{Checkpoint, SigningForm};
use ahl_cli::enumerate::LeafForm;
use ahl_cli::net::{FetchFailure, Fetcher, Request, Response};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// A server that answers every request with one body, and never fails a fetch.
///
/// Failing the fetch would be the uninteresting half: the client already reports an
/// unreachable endpoint as missing evidence. What is under test is a server that answers.
#[derive(Debug)]
struct OneBody(Vec<u8>);

impl Fetcher for OneBody {
    fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
        Ok(Response { status: 200, body: self.0.clone() })
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(policy) = ahl_cli_fuzz::policy() else { return };
    let fetcher = OneBody(data.to_vec());

    if let Ok(mirror) = ahl_cli::anchored::Mirror::new(
        &fetcher,
        ahl_cli_fuzz::MIRROR,
        ahl_cli_fuzz::PROFILE_ID,
        policy.network,
    ) {
        // The series parse and the §7.3 ordering it feeds.
        let _ = mirror.series();
        // The full establishment at a size the corpus publishes, which is where enumeration,
        // tiling, root recomputation and governance resolution all run.
        let _ = ahl_cli::anchored::establish(&mirror, policy, 4);
    }

    // The two body parsers that take a value directly, so they are reached even for a body the
    // establishment above rejects before it gets that far.
    let Ok(value) = serde_json::from_slice::<Value>(data) else { return };

    if let Ok(selected) = Checkpoint::from_value(&value) {
        let _ =
            ahl_cli::enumerate::verify_range_response(&value, &selected, LeafForm::Direct, 0, 4);
    }

    // No witness or log key is resolved, so this reaches the shape checks and the
    // key-not-resolved path; a body copying a corpus key id reaches the signature check.
    let empty: BTreeMap<String, String> = BTreeMap::new();
    let _ = ahl_cli::witness::check_refusal(
        &value,
        SigningForm::CanonicalJson,
        &empty,
        &empty,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
});
