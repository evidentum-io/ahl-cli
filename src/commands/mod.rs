//! The five verbs, each in its own module.
//!
//! `verify` and `inspect` never open signing material; `emit` never reaches the network and
//! never adjudicates a log-position-dependent rule; `closure` and `reconstruct` refuse to
//! produce an authenticated result until every element §3 requires is established.

pub mod emit;
pub mod inspect;
pub mod verify;
