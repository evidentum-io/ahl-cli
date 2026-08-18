//! Every way a command can fail, with the [`Outcome`] each one maps to.
//!
//! The mapping is the §6 outcome table expressed in the type system: a variant carries the
//! outcome it produces, so no code path can invent one by accident. A path that is not in the
//! table is a defect, not a default — which is why [`CliError::outcome`] is a total match with
//! no wildcard arm.

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

    /// A `keyed` content binding was claimed but no authorized dataset key is held.
    #[error("no authorized dataset key is held for dataset `{dataset}`")]
    DatasetKeyNotHeld {
        /// The dataset whose key is missing.
        dataset: String,
    },

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
            | Self::Policy(_)
            | Self::ProfileBroken { .. }
            | Self::Output { .. }
            | Self::RefusedTarget { .. }
            | Self::Internal(_) => Outcome::Error,
            Self::Malformed { .. }
            | Self::RuleFired(_)
            | Self::EquivocationAtOrBeyondFloor { .. } => Outcome::Invalid,
            Self::ProfileNotPossessed { .. }
            | Self::ProfileLimitation(_)
            | Self::DatasetKeyNotHeld { .. }
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
            Self::Policy(_) => "policy-unusable",
            Self::ProfileBroken { .. } => "profile-broken",
            Self::Output { .. } => "output-io",
            Self::RefusedTarget { .. } => "target-refused",
            Self::Internal(_) => "internal",
            Self::Malformed { .. } => "malformed",
            Self::RuleFired(_) => "rule-fired",
            Self::EquivocationAtOrBeyondFloor { .. } => "equivocation-at-or-beyond-floor",
            Self::ProfileNotPossessed { .. } => "profile-not-possessed",
            Self::ProfileLimitation(_) => "profile-limitation",
            Self::DatasetKeyNotHeld { .. } => "dataset-key-not-held",
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
            CliError::Policy("p".to_owned()),
            CliError::ProfileBroken {
                id: "i".to_owned(),
                path: "p".to_owned(),
                detail: "d".to_owned(),
            },
            CliError::Output { path: "p".to_owned(), detail: "d".to_owned() },
            CliError::RefusedTarget { url: "u".to_owned(), detail: "d".to_owned() },
            CliError::Internal("i".to_owned()),
            CliError::Malformed { what: "receipt", detail: "d".to_owned() },
            CliError::RuleFired("r".to_owned()),
            CliError::EquivocationAtOrBeyondFloor { floor: 4 },
            CliError::ProfileNotPossessed { id: "i".to_owned() },
            CliError::ProfileLimitation("l".to_owned()),
            CliError::DatasetKeyNotHeld { dataset: "d".to_owned() },
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
