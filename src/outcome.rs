//! The four outcomes and their exit-code contract.
//!
//! Collapsing *disproved* into *could not establish* is what makes a verifier useless in CI,
//! so the two are distinct outcomes with distinct exit codes:
//!
//! | Exit | Outcome | Meaning |
//! |---|---|---|
//! | `0` | [`Outcome::Valid`] | every required rule verified |
//! | `1` | [`Outcome::Invalid`] | a normative rule fired against the artifact |
//! | `2` | [`Outcome::Error`] | the CLI could not begin |
//! | `3` | [`Outcome::Unverifiable`] | well-formed, nothing disproved, required evidence missing |
//!
//! `0`, `1` and `2` carry exactly their `atl-cli` meanings, so a consumer written against the
//! family canon still reads them correctly; `3` is a documented AHL extension and is never
//! rendered as INVALID in any surface — text, JSON, or exit status.
//!
//! # Precedence
//!
//! Where more than one thing goes wrong, a rule fired against the artifact (`1`) outranks
//! missing external evidence (`3`), which outranks a local-environment failure (`2`) — see
//! [`Outcome::rank`] and [`Outcome::worse_of`]. The one exception is a local failure occurring
//! **before any artifact has been read**, which is always `2`; callers express that by
//! short-circuiting rather than by combining, which is why [`Outcome::worse_of`] has no
//! knowledge of it.

use std::fmt;

/// What a command concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Every required rule verified. Exit `0`.
    Valid,
    /// A normative rule fired against the artifact: structure, signature, proof, cross-field
    /// rule, equivocation between authenticated checkpoints, unknown claim or statement type.
    /// Exit `1`.
    Invalid,
    /// The CLI could not begin: usage, unreadable or unparseable policy, output-path I/O,
    /// internal invariant. Exit `2`.
    Error,
    /// Well-formed, nothing disproved, but required evidence could not be established. Exit `3`.
    Unverifiable,
}

impl Outcome {
    /// The process exit code for this outcome.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Valid => 0,
            Self::Invalid => 1,
            Self::Error => 2,
            Self::Unverifiable => 3,
        }
    }

    /// The stable machine string this outcome is rendered as in `--json` and in text.
    ///
    /// `Unverifiable` is never rendered as `invalid` in any surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Error => "error",
            Self::Unverifiable => "unverifiable",
        }
    }

    /// The I-D §7.7 result value this outcome renders, where it renders one.
    ///
    /// `Valid`, `Invalid` and `Unverifiable` are the three values of a COMPLETED run, under the
    /// names §7.7 spells them. [`Self::Error`] is none of them: §7.7 scopes a run that did not
    /// complete out of the model, so it maps to `None` rather than to a fourth string.
    #[must_use]
    pub const fn as_result_value(self) -> Option<&'static str> {
        match self {
            Self::Valid => Some("verified"),
            Self::Invalid => Some("invalid"),
            Self::Unverifiable => Some("unverifiable"),
            Self::Error => None,
        }
    }

    /// Precedence rank: higher wins when two outcomes are combined.
    ///
    /// A rule fired against the artifact outranks missing external evidence, which outranks a
    /// local-environment failure. `Valid` is the floor: anything at all outranks it.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Valid => 0,
            Self::Error => 1,
            Self::Unverifiable => 2,
            Self::Invalid => 3,
        }
    }

    /// Combine two outcomes by the precedence rule above.
    #[must_use]
    pub const fn worse_of(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_contract() {
        assert_eq!(Outcome::Valid.exit_code(), 0);
        assert_eq!(Outcome::Invalid.exit_code(), 1);
        assert_eq!(Outcome::Error.exit_code(), 2);
        assert_eq!(Outcome::Unverifiable.exit_code(), 3);
    }

    #[test]
    fn unverifiable_is_never_rendered_as_invalid() {
        assert_eq!(Outcome::Unverifiable.as_str(), "unverifiable");
        assert_ne!(Outcome::Unverifiable.as_str(), Outcome::Invalid.as_str());
        assert_ne!(Outcome::Unverifiable.exit_code(), Outcome::Invalid.exit_code());
    }

    #[test]
    fn a_rule_fired_against_the_artifact_outranks_missing_evidence_and_local_failure() {
        assert_eq!(Outcome::Unverifiable.worse_of(Outcome::Invalid), Outcome::Invalid);
        assert_eq!(Outcome::Invalid.worse_of(Outcome::Unverifiable), Outcome::Invalid);
        assert_eq!(Outcome::Error.worse_of(Outcome::Unverifiable), Outcome::Unverifiable);
        assert_eq!(Outcome::Unverifiable.worse_of(Outcome::Error), Outcome::Unverifiable);
        assert_eq!(Outcome::Valid.worse_of(Outcome::Error), Outcome::Error);
        assert_eq!(Outcome::Valid.worse_of(Outcome::Valid), Outcome::Valid);
    }

    #[test]
    fn combining_is_associative_over_the_whole_lattice() {
        let all = [Outcome::Valid, Outcome::Error, Outcome::Unverifiable, Outcome::Invalid];
        for a in all {
            for b in all {
                for c in all {
                    assert_eq!(a.worse_of(b).worse_of(c), a.worse_of(b.worse_of(c)));
                }
            }
        }
    }

    #[test]
    fn only_a_completed_run_renders_one_of_the_three_result_values() {
        assert_eq!(Outcome::Valid.as_result_value(), Some("verified"));
        assert_eq!(Outcome::Invalid.as_result_value(), Some("invalid"));
        assert_eq!(Outcome::Unverifiable.as_result_value(), Some("unverifiable"));
        // A local failure is not one of the three values and must never be rendered as one.
        assert_eq!(Outcome::Error.as_result_value(), None);
    }

    #[test]
    fn display_matches_the_machine_string() {
        assert_eq!(Outcome::Valid.to_string(), "valid");
        assert_eq!(Outcome::Error.to_string(), "error");
    }
}
