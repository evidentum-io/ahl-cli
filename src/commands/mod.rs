//! The six verbs, each in its own module.
//!
//! `verify` and `inspect` never open signing material; `emit` never reaches the network and
//! never adjudicates a log-position-dependent rule; `closure` and `reconstruct` refuse to
//! produce an authenticated result until every element §3 requires is established; `issue`
//! assembles and adjudicates nothing, leaving every verdict to `verify`.

pub mod closure;
pub mod emit;
pub mod inspect;
pub mod issue;
pub mod reconstruct;
pub mod verify;
