//! Every way a command can fail, with the [`Outcome`] each one maps to.
//!
//! The mapping is the §6 outcome table expressed in the type system: a variant carries the
//! outcome it produces, so no code path can invent one by accident. A path that is not in the
//! table is a defect, not a default — which is why [`CliError::outcome`] is a total match with
//! no wildcard arm.
//!
//! What is NOT here is the class of a receipt rejection. A completed verification run reaches
//! one of the three I-D §7.7 values and the core decides which, so this enum carries only the
//! rows §6 assigns to the CLI itself: usage, local configuration, local I/O, the artifact's own
//! bytes before the core is entered, and evidence a server did not supply.

use crate::outcome::Outcome;

/// A rejection, with the rule that fired and the outcome it produces.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    // -- exit 2: the CLI could not begin ------------------------------------------------
    /// Command-line usage the CLI refuses to attempt.
    #[error("usage: {0}")]
    Usage(String),

    /// A file could not be opened, is not a regular file, or failed the §4 handle checks.
    #[error("cannot read {what} at `{path}`: {detail}")]
    Open {
        /// What the file was supposed to be (`policy`, `receipt`, `key`, ...).
        what: &'static str,
        /// The path as given.
        path: String,
        /// Why the open or the handle check failed.
        detail: String,
    },

    /// Input that opened but could not be parsed at all, before any evaluation began.
    ///
    /// Distinct from [`Self::Malformed`]: that one is a rule firing against an artifact the
    /// CLI is adjudicating, this one is a local-environment failure that happens *before* any
    /// adjudication starts — which is exactly the line §6 draws for topology mode, where a
    /// failure to read or parse the file at all is `2` and everything found by walking it is a
    /// finding.
    #[error("cannot parse {what} at `{path}`: {detail}")]
    Unparseable {
        /// What the file was supposed to be.
        what: &'static str,
        /// The path as given.
        path: String,
        /// Why it did not parse.
        detail: String,
    },

    /// The trust policy could not be parsed, or is internally inconsistent.
    #[error("trust policy is unusable: {0}")]
    Policy(String),

    /// The adaptor profile is configured but the bytes at the policy path do not hash to the
    /// pinned value, or cannot be read at all. The local configuration is broken and nothing
    /// about the artifact has been shown.
    #[error("adaptor profile `{id}` at `{path}` is broken: {detail}")]
    ProfileBroken {
        /// The profile id as configured.
        id: String,
        /// The configured path.
        path: String,
        /// Why.
        detail: String,
    },

    /// An output path could not be written, or a non-clobbering install was refused.
    #[error("cannot write `{path}`: {detail}")]
    Output {
        /// The destination.
        path: String,
        /// Why.
        detail: String,
    },

    /// A target the CLI refuses to attempt: plain HTTP to a non-loopback peer, or a redirect
    /// that would leave the configured endpoint.
    #[error("refusing to fetch `{url}`: {detail}")]
    RefusedTarget {
        /// The URL as configured or as redirected to.
        url: String,
        /// Why the CLI will not attempt it.
        detail: String,
    },

    /// An invariant this crate is responsible for did not hold.
    #[error("internal invariant: {0}")]
    Internal(String),

    /// A verification run did not complete, so it reached no result at all.
    ///
    /// I-D §7.7: "A run that does not complete — an I/O failure, an exhausted heap, a crash —
    /// yields no result in this model. It is a local execution failure, reported as such; it
    /// says nothing about the receipt and MUST NOT be rendered as any of the three values."
    /// Kept apart from [`Self::Internal`] because the two answer different questions: an
    /// invariant this crate broke is a defect here, while a run that stopped is a statement
    /// about the local environment and about nothing else.
    #[error("the verification run did not complete: {0}")]
    ExecutionFailed(String),

    // -- exit 1: a rule fired against the user's own artifact ---------------------------
    /// The artifact's bytes are present but malformed, non-canonical, or structurally invalid.
    #[error("{what} is malformed: {detail}")]
    Malformed {
        /// Which artifact.
        what: &'static str,
        /// Which rule its bytes broke.
        detail: String,
    },

    /// A normative rule fired against the user-supplied artifact.
    #[error("{0}")]
    RuleFired(String),

    /// Two authenticated checkpoints diverge, and the result is grounded at or beyond the
    /// floor. Positive proof of misbehaviour, not absence of evidence.
    #[error(
        "the checkpoint series equivocates from tree_size {floor}: two authenticated members \
         carry different roots, and this result is grounded at or beyond that floor"
    )]
    EquivocationAtOrBeyondFloor {
        /// The lowest `tree_size` at which divergence occurs.
        floor: u64,
    },

    // -- exit 3: required evidence could not be established ------------------------------
    /// Local policy anchors a corpus other than the one the presented material carries.
    ///
    /// `unverifiable`, never `invalid`: the artifact may be a perfectly valid one of another
    /// corpus, and what is missing is a trust anchor this verifier was not configured with —
    /// a property of the verifier rather than of the material. Reporting it as a rule fired
    /// against the artifact would let a verifier configured for corpus A make a statement about
    /// corpus B's material that a verifier configured for B contradicts.
    #[error("{0}")]
    GenesisAnchorMismatch(String),

    /// The pinned adaptor profile is not locally possessed at all.
    #[error("adaptor profile `{id}` is not locally possessed")]
    ProfileNotPossessed {
        /// The profile id the artifact pins.
        id: String,
    },

    /// The receipt needs a capability the pinned profile does not define, or a version this
    /// build does not implement. The profile's limitation is named.
    #[error("{0}")]
    ProfileLimitation(String),

    /// A resource limit was exhausted. Rejection, never a degraded acceptance.
    #[error("limit exhausted: {0}")]
    LimitExhausted(String),

    /// Required evidence could not be obtained: an unreachable server, a malformed remote
    /// response, an enumeration that does not tile, a proof that did not verify on a
    /// **remote candidate**. A hostile server returning one bogus object disproves nothing
    /// about the user's artifact.
    #[error("required evidence could not be established: {0}")]
    EvidenceMissing(String),

    /// The command ran in topology mode, which never returns `valid`.
    #[error("topology mode: {0}")]
    TopologyMode(String),
}

impl CliError {
    /// The outcome this error produces. Total by construction — see the module docs.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        match self {
            Self::Usage(_)
            | Self::Open { .. }
            | Self::Unparseable { .. }
            | Self::Policy(_)
            | Self::ProfileBroken { .. }
            | Self::Output { .. }
            | Self::RefusedTarget { .. }
            | Self::Internal(_)
            | Self::ExecutionFailed(_) => Outcome::Error,
            Self::Malformed { .. }
            | Self::RuleFired(_)
            | Self::EquivocationAtOrBeyondFloor { .. } => Outcome::Invalid,
            Self::GenesisAnchorMismatch(_)
            | Self::ProfileNotPossessed { .. }
            | Self::ProfileLimitation(_)
            | Self::LimitExhausted(_)
            | Self::EvidenceMissing(_)
            | Self::TopologyMode(_) => Outcome::Unverifiable,
        }
    }

    /// A stable machine string naming the class of failure, for `--json` consumers.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Usage(_) => "usage",
            Self::Open { .. } => "input-unreadable",
            Self::Unparseable { .. } => "input-unparseable",
            Self::Policy(_) => "policy-unusable",
            Self::ProfileBroken { .. } => "profile-broken",
            Self::Output { .. } => "output-io",
            Self::RefusedTarget { .. } => "target-refused",
            Self::Internal(_) => "internal",
            Self::ExecutionFailed(_) => "execution-failed",
            Self::Malformed { .. } => "malformed",
            Self::RuleFired(_) => "rule-fired",
            Self::EquivocationAtOrBeyondFloor { .. } => "equivocation-at-or-beyond-floor",
            Self::GenesisAnchorMismatch(_) => "genesis-anchor-mismatch",
            Self::ProfileNotPossessed { .. } => "profile-not-possessed",
            Self::ProfileLimitation(_) => "profile-limitation",
            Self::LimitExhausted(_) => "limit-exhausted",
            Self::EvidenceMissing(_) => "evidence-missing",
            Self::TopologyMode(_) => "topology-mode",
        }
    }
}

/// The crate's result type.
pub type CliResult<T> = core::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<CliError> {
        vec![
            CliError::Usage("u".to_owned()),
            CliError::Open { what: "receipt", path: "p".to_owned(), detail: "d".to_owned() },
            CliError::Unparseable { what: "corpus", path: "p".to_owned(), detail: "d".to_owned() },
            CliError::Policy("p".to_owned()),
            CliError::ProfileBroken {
                id: "i".to_owned(),
                path: "p".to_owned(),
                detail: "d".to_owned(),
            },
            CliError::Output { path: "p".to_owned(), detail: "d".to_owned() },
            CliError::RefusedTarget { url: "u".to_owned(), detail: "d".to_owned() },
            CliError::Internal("i".to_owned()),
            CliError::ExecutionFailed("stopped".to_owned()),
            CliError::Malformed { what: "receipt", detail: "d".to_owned() },
            CliError::RuleFired("r".to_owned()),
            CliError::EquivocationAtOrBeyondFloor { floor: 4 },
            CliError::GenesisAnchorMismatch("another corpus".to_owned()),
            CliError::ProfileNotPossessed { id: "i".to_owned() },
            CliError::ProfileLimitation("l".to_owned()),
            CliError::LimitExhausted("l".to_owned()),
            CliError::EvidenceMissing("e".to_owned()),
            CliError::TopologyMode("t".to_owned()),
        ]
    }

    #[test]
    fn every_variant_names_an_outcome_and_a_reason_code() {
        for error in all() {
            assert!(!error.reason_code().is_empty());
            assert!(!error.to_string().is_empty());
            // Every outcome is one of the four; `Valid` is never produced by an error.
            assert_ne!(error.outcome(), Outcome::Valid);
        }
    }

    #[test]
    fn reason_codes_are_unique_per_variant() {
        let mut codes: Vec<&str> = all().iter().map(CliError::reason_code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "reason codes must be distinct");
    }

    #[test]
    fn a_parse_failure_before_any_walking_is_a_local_failure_not_a_verdict() {
        // §6: in topology mode "only a failure to read or parse the file at all is `2`, because
        // that is a local-environment failure before any walking begins".
        let error = CliError::Unparseable {
            what: "corpus",
            path: "corpus.json".to_owned(),
            detail: "expected value".to_owned(),
        };
        assert_eq!(error.outcome(), Outcome::Error);
        assert_eq!(error.reason_code(), "input-unparseable");
        // And it is not the same thing as a rule firing against an artifact.
        assert_eq!(
            CliError::Malformed { what: "receipt", detail: "d".to_owned() }.outcome(),
            Outcome::Invalid
        );
    }

    #[test]
    fn remote_evidence_failures_are_unverifiable_not_invalid() {
        // §6: "A hostile server returning one bogus object disproves nothing about the user's
        // artifact." Only the user's own artifact can be disproved.
        assert_eq!(
            CliError::EvidenceMissing("bad remote checkpoint".to_owned()).outcome(),
            Outcome::Unverifiable
        );
        assert_eq!(
            CliError::RuleFired("bad subject signature".to_owned()).outcome(),
            Outcome::Invalid
        );
    }
}
