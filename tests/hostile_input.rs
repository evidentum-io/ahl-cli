//! One hostile-input test per bullet of design note §7, plus the §11.2.5 refusal checks
//! failing one at a time.
//!
//! The network-facing bullets run against real loopback servers that answer with hand-written
//! HTTP, because the point is what the client does with bytes on a socket rather than what a
//! mock returns. The bullets about material the client selects — non-tiling subranges, a
//! response declaring another checkpoint identity — run against mutated recordings, because
//! those need a valid proof over the wrong thing rather than a broken connection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::multiple_crate_versions
)]

mod common;

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use ahl_cli::checkpoint::{Checkpoint, SigningForm};
use ahl_cli::net::{FetchFailure, Fetcher, HttpFetcher, Request};
use ahl_cli::policy::NetworkLimits;
use ahl_cli::witness::{check_refusal, RefusalReason};
use ahl_core::TestKey;
use serde_json::json;

use common::{ahl_cli, corpus, fixtures, policy, PolicySpec};

const AT: &str = "--evaluation-time";
const FIXED: &str = "2026-08-16T12:00:00Z";

// ---------------------------------------------------------------------------
// §7 bullet 1: HTTPS only; plain HTTP to loopback only, checked on the resolved peer
// ---------------------------------------------------------------------------

/// A one-shot loopback server writing `response` verbatim.
fn one_shot(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut discard = [0u8; 8192];
            let _ = stream.read(&mut discard);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn limits() -> NetworkLimits {
    NetworkLimits { wall_clock_seconds: 10, ..NetworkLimits::default() }
}

#[test]
fn bullet_plain_http_to_a_non_loopback_peer_is_refused_through_the_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = policy(dir.path(), &PolicySpec::default()).display().to_string();
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--mirror",
        // IANA's example address: never loopback, and never connected to, because the refusal
        // happens on the resolved peer address before any socket is opened.
        "http://93.184.215.14",
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
    ]);
    assert_eq!(run.code, 2, "a configuration the CLI refuses to attempt");
    assert!(run.output().contains("loopback"), "{}", run.output());
}

#[test]
fn bullet_a_hostname_resolving_off_loopback_is_refused_however_it_is_spelled() {
    // The check is on the address actually connected to, not on the hostname text. A name that
    // *looks* local but resolves elsewhere is refused; that is what closes DNS rebinding.
    let fetcher = HttpFetcher::new(limits());
    let failure = fetcher
        .fetch(&Request::get("http://93.184.215.14:80/v1/checkpoints"))
        .expect_err("non-loopback");
    assert!(matches!(failure, FetchFailure::Refused { .. }), "{failure}");
}

#[test]
fn bullet_a_non_https_scheme_has_no_escape_hatch() {
    let fetcher = HttpFetcher::new(limits());
    for url in ["ftp://example.invalid/x", "file:///etc/passwd"] {
        assert!(matches!(
            fetcher.fetch(&Request::get(url)).expect_err("bad scheme"),
            FetchFailure::Refused { .. }
        ));
    }
}

// ---------------------------------------------------------------------------
// §7 bullet 2: redirects are not followed at all
// ---------------------------------------------------------------------------

#[test]
fn bullet_a_redirect_is_a_fetch_failure_naming_the_location() {
    let (url, handle) =
        one_shot(http_response("302 Found", "location: /v1/somewhere-else\r\n", b""));
    let fetcher = HttpFetcher::new(limits());
    let failure = fetcher.fetch(&Request::get(format!("{url}/v1/range"))).expect_err("302");
    assert!(failure.to_string().contains("/v1/somewhere-else"), "{failure}");
    assert!(failure.to_string().contains("never followed"), "{failure}");
    handle.join().expect("server thread");
}

#[test]
fn bullet_a_cross_host_or_downgrade_redirect_is_refused_rather_than_reported_as_missing() {
    for location in ["https://elsewhere.example/v1/range", "http://elsewhere.example/v1/range"] {
        let (url, handle) = one_shot(http_response(
            "301 Moved Permanently",
            &format!("location: {location}\r\n"),
            b"",
        ));
        let fetcher = HttpFetcher::new(limits());
        let failure = fetcher.fetch(&Request::get(format!("{url}/v1/range"))).expect_err("301");
        assert!(matches!(failure, FetchFailure::Refused { .. }), "{location}: {failure}");
        handle.join().expect("server thread");
    }
}

// ---------------------------------------------------------------------------
// §7 bullet 3: budgets, counted after decompression
// ---------------------------------------------------------------------------

#[test]
fn bullet_an_oversized_response_exhausts_the_named_budget() {
    let (url, handle) = one_shot(http_response("200 OK", "", &vec![b'x'; 65_536]));
    let fetcher = HttpFetcher::new(NetworkLimits { max_response_bytes: 1024, ..limits() });
    let failure = fetcher.fetch(&Request::get(format!("{url}/big"))).expect_err("oversized");
    assert!(matches!(failure, FetchFailure::Budget(_)), "{failure}");
    handle.join().expect("server thread");
}

#[test]
fn bullet_a_decompression_bomb_is_bounded_by_the_decompressed_size() {
    // Content-Length is a hint: a kilobyte on the wire, a megabyte out of the decoder.
    let payload = vec![0u8; 4 << 20];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&payload).expect("compress");
    let compressed = encoder.finish().expect("finish");
    assert!(compressed.len() < 16_384, "the fixture must be small on the wire");

    let (url, handle) =
        one_shot(http_response("200 OK", "content-encoding: gzip\r\n", &compressed));
    let fetcher = HttpFetcher::new(NetworkLimits { max_response_bytes: 65_536, ..limits() });
    let failure = fetcher.fetch(&Request::get(format!("{url}/bomb"))).expect_err("bomb");
    assert!(matches!(failure, FetchFailure::Budget(_)), "{failure}");
    assert!(failure.to_string().contains("after decompression"), "{failure}");
    handle.join().expect("server thread");
}

#[test]
fn bullet_a_content_length_that_lies_is_never_the_bound() {
    // A response declaring one byte and sending far more: the budget still fires, because the
    // bound is on what is read, not on what is declared.
    let body = vec![b'y'; 32_768];
    let mut out = b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: close\r\n\r\n".to_vec();
    out.extend_from_slice(&body);
    let (url, handle) = one_shot(out);
    let fetcher = HttpFetcher::new(NetworkLimits { max_response_bytes: 16, ..limits() });
    let response = fetcher.fetch(&Request::get(format!("{url}/liar")));
    match response {
        Ok(ok) => assert!(
            ok.body.len() as u64 <= 16,
            "more than the budget was accepted: {} bytes",
            ok.body.len()
        ),
        Err(failure) => assert!(matches!(failure, FetchFailure::Budget(_)), "{failure}"),
    }
    handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// §7 bullet 4: client-driven chunking, tiling, and checkpoint identity
// ---------------------------------------------------------------------------

#[test]
fn bullet_subranges_that_do_not_tile_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript =
        common::mutate_transcript(dir.path(), "mirror-transcript.json", "gap.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = common::exchange_body(exchange);
                    // Renumber every entry: the response no longer covers what it declares.
                    if let Some(entries) = body["entries"].as_array_mut() {
                        for entry in entries.iter_mut() {
                            let index = entry["entry_index"].as_u64().unwrap_or(0);
                            entry["entry_index"] = json!(index + 1);
                        }
                    }
                    common::set_exchange_body(exchange, &body);
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
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
    assert_eq!(run.code, 3, "{}", run.output());
}

#[test]
fn bullet_a_response_declaring_another_checkpoint_identity_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = common::mutate_transcript(
        dir.path(),
        "mirror-transcript.json",
        "wrong-log.json",
        |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = common::exchange_body(exchange);
                    body["checkpoint"]["log_id"] = json!(format!("sha256:{}", "cd".repeat(32)));
                    common::set_exchange_body(exchange, &body);
                }
            }
        },
    );
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
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
    assert_eq!(run.code, 3, "{}", run.output());
}

#[test]
fn bullet_a_republished_checkpoint_with_the_same_identity_is_still_accepted() {
    // Identity matching is on `{log_id, tree_size, root_hash}`, not byte-identity: a quiet log
    // may publish several signed checkpoints at one size with the same root, and rejecting
    // those would break honest deployments.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript = common::mutate_transcript(
        dir.path(),
        "mirror-transcript.json",
        "republished.json",
        |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = common::exchange_body(exchange);
                    // Same identity fields, a later restatement time and a different signature.
                    body["checkpoint"]["checkpoint_time"] = json!("2026-08-16T18:00:00Z");
                    body["checkpoint"]["signature"] = json!("base64:AAAA");
                    common::set_exchange_body(exchange, &body);
                }
            }
        },
    );
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "an honest restatement must not be rejected: {}", run.output());
}

#[test]
fn bullet_a_server_supplied_continuation_token_is_never_followed() {
    // There is no cursor: the next subrange is computed from the previous bound. A response
    // carrying a `next` member changes nothing, and a response that stops early is refused.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript =
        common::mutate_transcript(dir.path(), "mirror-transcript.json", "cursor.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    let mut body = common::exchange_body(exchange);
                    body["next"] = json!("cursor:aabbcc");
                    body["has_more"] = json!(false);
                    common::set_exchange_body(exchange, &body);
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--transcript",
        &transcript.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(run.code, 0, "an invented cursor is ignored, not honoured: {}", run.output());
}

// ---------------------------------------------------------------------------
// §7 bullet 5: refusal evidence is a witness artifact, not an HTTP status
// ---------------------------------------------------------------------------

fn log_key() -> TestKey {
    TestKey::from_seed_hex(
        "log-1",
        std::fs::read_to_string(corpus().join("keys/log-1.seed")).expect("seed").trim(),
    )
    .expect("seed")
}

fn witness_key() -> TestKey {
    TestKey::from_seed_hex(
        "witness-1",
        std::fs::read_to_string(corpus().join("keys/witness-1.seed")).expect("seed").trim(),
    )
    .expect("seed")
}

const LOG_ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn signed_checkpoint(tree_size: u64, root: &str) -> serde_json::Value {
    let mut checkpoint = Checkpoint {
        log_id: LOG_ID.to_owned(),
        tree_size,
        root_hash: root.to_owned(),
        checkpoint_time: FIXED.to_owned(),
        key_id: log_key().key_id(),
        signature: String::new(),
    };
    if let Ok(bytes) = checkpoint.signing_bytes(SigningForm::CanonicalJson) {
        checkpoint.signature = log_key().sign(&bytes);
    }
    serde_json::to_value(checkpoint).expect("value")
}

fn root(byte: u8) -> String {
    format!("sha256:{}", hex::encode([byte; 32]))
}

fn sign_refusal(mut refusal: serde_json::Value) -> serde_json::Value {
    let mut object = refusal.as_object().cloned().expect("object");
    object.remove("signature");
    let bytes = ahl_core::jcs(&serde_json::Value::Object(object));
    refusal["signature"] = json!(witness_key().sign(&bytes));
    refusal
}

fn equivocation_refusal() -> serde_json::Value {
    sign_refusal(json!({
        "type": "witness-refusal",
        "witness_id": "witness-1",
        "log_id": LOG_ID,
        "reason": "equivocation",
        "retained": signed_checkpoint(13, &root(0x01)),
        "offered": signed_checkpoint(13, &root(0x02)),
        "detail": "two roots at one tree size",
        "refused_at": FIXED,
        "key_id": witness_key().key_id(),
    }))
}

fn check(
    refusal: &serde_json::Value,
) -> ahl_cli::error::CliResult<ahl_cli::witness::CheckedRefusal> {
    check_refusal(
        refusal,
        SigningForm::CanonicalJson,
        &BTreeMap::from([(witness_key().key_id(), witness_key().pubkey())]),
        &BTreeMap::from([(log_key().key_id(), log_key().pubkey())]),
        LOG_ID,
    )
}

#[test]
fn a_witness_refusal_fails_each_11_2_5_check_in_turn() {
    // The baseline verifies, so every mutation below isolates exactly one check.
    assert_eq!(
        check(&equivocation_refusal()).expect("baseline").reason,
        RefusalReason::Equivocation
    );

    // §11.2.5 step 1 — the witness signature over `JCS(refusal minus "signature")`.
    let mut tampered = equivocation_refusal();
    tampered["detail"] = json!("rewritten after signing");
    let error = check(&tampered).expect_err("step 1");
    assert!(error.to_string().contains("witness signature did not verify"), "{error}");

    // §11.2.5 step 1 — a witness key the corpus does not declare.
    let error = check_refusal(
        &equivocation_refusal(),
        SigningForm::CanonicalJson,
        &BTreeMap::new(),
        &BTreeMap::from([(log_key().key_id(), log_key().pubkey())]),
        LOG_ID,
    )
    .expect_err("unknown witness key");
    assert!(error.to_string().contains("not one this corpus declares"), "{error}");

    // §11.2.5 step 2 — the log signature on the RETAINED checkpoint.
    let mut refusal = equivocation_refusal();
    refusal["retained"]["signature"] = json!(format!("base64:{}", "A".repeat(86) + "=="));
    let error = check(&sign_refusal(refusal)).expect_err("step 2 retained");
    assert!(error.to_string().contains("proves nothing about the log"), "{error}");

    // §11.2.5 step 2 — the log signature on the OFFERED checkpoint.
    let mut refusal = equivocation_refusal();
    refusal["offered"]["signature"] = json!(format!("base64:{}", "A".repeat(86) + "=="));
    let error = check(&sign_refusal(refusal)).expect_err("step 2 offered");
    assert!(error.to_string().contains("proves nothing about the log"), "{error}");

    // §11.2.5 step 2 — the log id both checkpoints must carry.
    let mut refusal = equivocation_refusal();
    refusal["offered"] = signed_checkpoint(13, &root(0x02));
    refusal["offered"]["log_id"] = json!(format!("sha256:{}", "99".repeat(32)));
    assert!(check(&sign_refusal(refusal)).is_err(), "step 2 log id");

    // §11.2.5 step 2 — the corpus's bound Data Tree.
    let mut refusal = equivocation_refusal();
    refusal["log_id"] = json!(format!("sha256:{}", "99".repeat(32)));
    let error = check(&sign_refusal(refusal)).expect_err("step 2 bound tree");
    assert!(error.to_string().contains("bound Data Tree"), "{error}");

    // §11.2.5 step 3 — the reason-specific recheck.
    let mut refusal = equivocation_refusal();
    refusal["offered"] = signed_checkpoint(14, &root(0x02));
    let error = check(&sign_refusal(refusal)).expect_err("step 3 recheck");
    assert!(error.to_string().contains("does not support the declared reason"), "{error}");
    assert!(error.to_string().contains("never substitutes"), "{error}");

    // §11.2.2 — the pair binding, checked BEFORE consistency verification.
    let mut refusal = equivocation_refusal();
    refusal["reason"] = json!("extension-failed");
    refusal["retained"] = signed_checkpoint(4, &root(0x01));
    refusal["offered"] = signed_checkpoint(8, &root(0x02));
    refusal["proof"] = json!({ "from_size": 2, "to_size": 6, "path": [root(0x03)] });
    let error = check(&sign_refusal(refusal)).expect_err("§11.2.2");
    assert!(error.to_string().contains("§11.2.2"), "{error}");
    assert!(error.to_string().contains("before it is verified"), "{error}");

    // §11.2 — `proof` is REQUIRED for `extension-failed` and forbidden for the other two.
    let mut refusal = equivocation_refusal();
    refusal["reason"] = json!("extension-failed");
    let error = check(&sign_refusal(refusal)).expect_err("missing proof");
    assert!(error.to_string().contains("REQUIRED"), "{error}");

    let mut refusal = equivocation_refusal();
    refusal["proof"] = json!({ "from_size": 13, "to_size": 13, "path": [] });
    let error = check(&sign_refusal(refusal)).expect_err("stray proof");
    assert!(error.to_string().contains("requires to be absent"), "{error}");

    // §11.2.4 — `missing-consistency-proof` was removed, not renamed.
    for removed in ["missing-consistency-proof", "inconsistent"] {
        let mut refusal = equivocation_refusal();
        refusal["reason"] = json!(removed);
        let error = check(&sign_refusal(refusal)).expect_err("removed reason");
        assert!(error.to_string().contains("removed, not renamed"), "{error}");
    }

    // §11.2 — both checkpoints are REQUIRED in every refusal.
    for member in ["retained", "offered"] {
        let mut refusal = equivocation_refusal();
        refusal.as_object_mut().expect("object").remove(member);
        let error = check(&sign_refusal(refusal)).expect_err("missing checkpoint");
        assert!(error.to_string().contains("REQUIRED in every refusal"), "{error}");
    }
}

#[test]
fn an_http_status_is_an_operational_failure_never_refusal_evidence() {
    // A mirror's invented `reason` field is not refusal evidence, however plausible it looks.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();
    let transcript =
        common::mutate_transcript(dir.path(), "mirror-transcript.json", "invented.json", |value| {
            for exchange in value["exchanges"].as_array_mut().expect("array") {
                if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/range") {
                    exchange["status"] = json!(409);
                    common::set_exchange_body(
                        exchange,
                        &json!({ "reason": "equivocation", "detail": "trust me" }),
                    );
                }
            }
        });
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
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
    assert_eq!(run.code, 3, "an invented status must never become an accusation");
    assert!(
        !run.output().contains("equivocation-at-or-beyond-floor"),
        "a status is never read as refusal evidence: {}",
        run.output()
    );
}

// ---------------------------------------------------------------------------
// §7 bullet 6: equivocation requires two authenticated checkpoints
// ---------------------------------------------------------------------------

/// Inject a second, badly signed member at `tree_size` into the recorded series.
fn with_garbage_branch_at(dir: &std::path::Path, name: &str, tree_size: u64) -> std::path::PathBuf {
    common::mutate_transcript(dir, "mirror-transcript.json", name, |value| {
        let mut injected = false;
        for exchange in value["exchanges"].as_array_mut().expect("array") {
            if exchange["url"].as_str().unwrap_or_default().ends_with("/v1/checkpoints") {
                let mut body = common::exchange_body(exchange);
                let members = body.as_array_mut().expect("series");
                let at = members
                    .iter()
                    .position(|member| member["tree_size"] == json!(tree_size))
                    .expect("the size is in the recorded series");
                let mut forged = members[at].clone();
                forged["root_hash"] = json!(root(0xee));
                forged["signature"] = json!("base64:AAAA");
                members.push(forged);
                common::set_exchange_body(exchange, &body);
                injected = true;
            }
        }
        assert!(injected, "no series response was recorded to mutate");
    })
}

#[test]
fn bullet_two_unauthenticated_objects_differing_at_one_size_are_not_an_accusation() {
    // A hostile mirror injecting a badly signed second checkpoint must not make the CLI accuse
    // an honest log. §7 reserves an accusation for two members that **both** authenticate, so
    // neither run below may say the log equivocated.
    //
    // What the injection does change is whether a result can be grounded. Away from the
    // grounded size, members either side of a divergence remain usable and the object is
    // carried as a finding, so one bogus object cannot derail an honest run. **At** the
    // grounded size the client cannot establish that the second root fails to authenticate
    // under a chain of its own — adaptor §10.3 addresses an enumeration by `tree_size` alone,
    // so the entries behind that root cannot even be requested — and §5.2.2 forbids grounding
    // anything at a divergence. That is `3`, which is still not an accusation.
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = common::networked_policy(dir.path()).display().to_string();

    let elsewhere = with_garbage_branch_at(dir.path(), "garbage-branch-elsewhere.json", 20);
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--json",
        "--transcript",
        &elsewhere.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(
        run.code,
        0,
        "a bogus object away from the grounded size must not derail an honest run: {}",
        run.output()
    );
    assert!(!run.stdout.contains("equivocat"), "{}", run.stdout);

    let grounded = with_garbage_branch_at(dir.path(), "garbage-branch-grounded.json", 8);
    let run = ahl_cli(&[
        "--policy",
        &policy_path,
        AT,
        FIXED,
        "--json",
        "--transcript",
        &grounded.display().to_string(),
        "closure",
        "--trigger-index",
        "6",
        "--checkpoint",
        "8",
        "--tree-material",
        &fixtures().join("tree-material.json").display().to_string(),
    ]);
    assert_eq!(
        run.code,
        3,
        "nothing may be grounded at a size the client cannot show carries one tree: {}",
        run.output()
    );
    assert!(!run.stdout.contains("equivocat"), "still not an accusation: {}", run.stdout);
}

// ---------------------------------------------------------------------------
// Local hostile input
// ---------------------------------------------------------------------------

#[test]
fn a_hostile_local_file_cannot_exhaust_memory_where_a_hostile_server_cannot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut text =
        std::fs::read_to_string(policy(dir.path(), &PolicySpec::default())).expect("policy");
    text.push_str("\n[limits.local]\nmax_file_bytes = 512\n");
    let path = dir.path().join("bounded.toml");
    std::fs::write(&path, text).expect("write");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");

    let run = ahl_cli(&[
        "--policy",
        &path.display().to_string(),
        AT,
        FIXED,
        "verify",
        &corpus().join("receipts/propagation-complete-valid.ahl").display().to_string(),
    ]);
    assert_eq!(run.code, 3, "the local budget is named, not silently raised: {}", run.output());
    assert!(run.output().contains("budget"), "{}", run.output());
}

#[test]
fn a_symlinked_policy_or_key_is_refused_rather_than_traversed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = policy(dir.path(), &PolicySpec::default());
    let link = dir.path().join("policy-link.toml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let run = ahl_cli(&[
        "--policy",
        &link.display().to_string(),
        "verify",
        &corpus().join("receipts/statement-anchored-valid.ahl").display().to_string(),
    ]);
    assert_eq!(run.code, 2);
    assert!(run.output().contains("symbolic link"), "{}", run.output());
}
