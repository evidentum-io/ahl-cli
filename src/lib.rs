//! `ahl-cli` — the open self-hosted **client** of the AHL stack.
//!
//! # What this crate is
//!
//! A client, and only a client. It holds no log, serves no interface, and is not a
//! conformance target of its own: it exercises the verifier side of L1–L3 against a log served
//! by `atl-server` + `ahl-mirror` + `ahl-witness`, or against local files.
//!
//! | Command | Input | Output | Network |
//! |---|---|---|---|
//! | `verify` | `.ahl` receipt + policy | verdict with rendered boundary | **never** |
//! | `inspect` | `.ahl` receipt | structural dump, **no verdict** | never |
//! | `emit` | statement payload + signing key | signed candidate envelope | never |
//! | `closure` | corpus or log + trigger reference | affected set + authentication state | optional |
//! | `reconstruct` | corpus or log + checkpoint + valid time | projection + authentication state | optional |
//!
//! Retrieval is a flag on `closure` and `reconstruct` only, never a verb of its own: fetching
//! bytes nobody verifies is not a feature.
//!
//! # Architecture
//!
//! A library plus a thin binary (`src/bin/ahl-cli.rs`), the same shape as the sibling
//! `ahl-mirror` and `ahl-witness`. Everything except the process wiring lives here, so the
//! whole command surface — including its exit codes — is testable without spawning a process.
//!
//! | module | responsibility |
//! | --- | --- |
//! | [`outcome`] | the four outcomes, their exit codes, and the precedence between them |
//! | [`error`] | every rejection, each carrying the outcome the §6 table assigns it |
//! | [`secure`] | handle-based file checks: regular file, owner-only, no symlinked final component |
//! | [`install`] | the no-replace atomic install, which fails closed rather than racing |
//! | [`policy`] | the local trust policy, the untrusted endpoints, and the limits |
//! | [`profile`] | content-addressed adaptor-profile resolution from local possession |
//! | [`keys`] | signing material for `emit`, read from a file or a named environment variable |
//! | [`duration`] | the restricted ISO 8601 grammar of core spec §7.3 |
//! | [`evaluation`] | the single clock read, and the flag that replaces it |
//! | [`net`] | HTTPS only, no redirects, budgets counted after decompression |
//! | [`transcript`] | a fixed recorded transcript, replayed as a fetcher |
//! | [`cache`] | the two-layer cache: object store plus untrusted request index |
//! | [`checkpoint`] | authentication, checkpoint identity, and the equivocation floor |
//! | [`enumerate`] | client-driven chunked enumeration, tiling, and root recomputation |
//! | [`governance`] | governance resolved from anchored entries, independently of any receipt |
//! | [`witness`] | cosignatures and the §11.2.5 refusal checks |
//! | [`corpus`] | local corpus loading and the walk that produces findings, not verdicts |
//! | [`anchored`] | establishing an AHL-backed view, in the order the design note fixes |
//! | [`report`] | the stable result schema and its two surfaces |
//! | [`commands`] | the five verbs |
//! | [`cli`] | argument parsing and the single place an outcome becomes an exit code |
//! | [`testing`] | the deterministic conformance fixture the recorded transcripts come from |
//!
//! # Three kinds of input, and the boundaries between them
//!
//! **Trusted — the local trust policy.** Operator-configured, never derived from an artifact.
//! Policy fields are never defaulted from the artifact under verification: a missing
//! `genesis_entry_id` is a configuration error, never an accept.
//!
//! **Trusted only as secrets, held apart — dataset keys.** HMAC keys whose entire purpose is
//! that unauthorized parties cannot compute the commitment.
//!
//! **Untrusted — locations.** Mirror and witness URLs are *addresses, not authorities*: no
//! trust follows from configuring one, and neither `log_id` nor a profile id derives an
//! endpoint.
//!
//! **Untrusted — everything else**, without exception: the receipt and its embedded receipts,
//! its genesis anchor, every HTTP response, every profile document arriving by any route other
//! than the policy-pinned path, every filename, every label inside any of them, and the cache.
//!
//! # Reuse, not reimplementation
//!
//! Canonicalization, family-string parsing, envelope and checkpoint identifiers, cosignature
//! byte construction, receipt verification, closure computation, range proofs and Merkle
//! primitives come from [`ahl_core`] and, through it, from `atl-core`. The one deliberate
//! exception is [`governance`]: `ahl-core` resolves governance inside `verify_receipt`, from
//! the chain a receipt carries, and does not expose those rules, so a client that must resolve
//! them from a **live enumeration** re-derives them against the same normative text. The
//! README records that, and every other place the frozen sources left a client something to
//! decide.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
// `ahl-core`'s pinned `atl-core` revision brings `thiserror` 1.x (and the `syn` 2.x it needs)
// while this crate's own `thiserror` is 2.x (needing `syn` 3.x): see ahl-core's Cargo.toml for
// the fuller rationale. Not actionable from library code.
#![allow(clippy::multiple_crate_versions)]
// Test code favours `.expect()` messages that document the fixture, indexes fixture material
// it built itself, and occasionally `panic!`s in a match arm the test proves unreachable: an
// assertion that fires IS the failure report there. Production paths are held to the
// manifest's deny without exception.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::missing_panics_doc
    )
)]

pub mod anchored;
pub mod cache;
pub mod checkpoint;
pub mod cli;
pub mod commands;
pub mod corpus;
pub mod duration;
pub mod enumerate;
pub mod error;
pub mod evaluation;
pub mod governance;
pub mod install;
pub mod keys;
pub mod net;
pub mod outcome;
pub mod policy;
pub mod producer;
pub mod profile;
pub mod report;
pub mod secure;
pub mod testing;
pub mod transcript;
pub mod witness;
