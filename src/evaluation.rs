//! The single clock read, and the flag that replaces it.
//!
//! Freshness is the only clock-dependent evaluation in the CLI. `--evaluation-time` overrides
//! it for tests and historical analysis, and output always carries
//! `evaluation_time_source`, so an overridden result can never be read as a current one.
//!
//! Checkpoint selection is a separate flag (`--checkpoint`): one flag never does both jobs.
//! Conflating them is how a tool ends up answering "as of when?" and "which tree?" with one
//! number.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{CliError, CliResult};
use crate::report::TimeSource;

/// The instant a run evaluates freshness at, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationTime {
    /// The instant itself.
    pub instant: OffsetDateTime,
    /// Its RFC 3339 rendering, as reported.
    pub rendered: String,
    /// Clock or override.
    pub source: TimeSource,
}

impl EvaluationTime {
    /// Read the system clock.
    ///
    /// # Errors
    ///
    /// [`CliError::Internal`] if the instant cannot be rendered as RFC 3339, which the
    /// platform clock cannot produce.
    pub fn from_clock() -> CliResult<Self> {
        let instant = OffsetDateTime::now_utc();
        Ok(Self {
            rendered: render(instant)?,
            instant,
            source: TimeSource::Clock,
        })
    }

    /// Take the instant from `--evaluation-time`.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] if the value is not RFC 3339.
    pub fn from_override(value: &str) -> CliResult<Self> {
        let instant = OffsetDateTime::parse(value, &Rfc3339).map_err(|source| {
            CliError::Usage(format!("`--evaluation-time {value}` is not RFC 3339: {source}"))
        })?;
        Ok(Self {
            rendered: render(instant)?,
            instant,
            source: TimeSource::Override,
        })
    }

    /// Resolve from an optional override.
    ///
    /// # Errors
    ///
    /// As [`Self::from_override`] and [`Self::from_clock`].
    pub fn resolve(value: Option<&str>) -> CliResult<Self> {
        value.map_or_else(Self::from_clock, Self::from_override)
    }

    /// Nanoseconds elapsed since `earlier`, saturating at zero for a future instant.
    #[must_use]
    pub fn nanos_since(&self, earlier: OffsetDateTime) -> u128 {
        let delta = self.instant - earlier;
        if delta.is_negative() {
            0
        } else {
            delta.whole_nanoseconds().unsigned_abs()
        }
    }
}

fn render(instant: OffsetDateTime) -> CliResult<String> {
    instant
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|source| CliError::Internal(format!("cannot render evaluation time: {source}")))
}

/// Parse an RFC 3339 instant carried by an artifact.
///
/// # Errors
///
/// [`CliError::Malformed`] naming the field, so a bad timestamp in an artifact is reported as
/// a rule against the artifact rather than as a usage error.
pub fn parse_artifact_time(field: &'static str, value: &str) -> CliResult<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|source| CliError::Malformed {
        what: field,
        detail: format!("`{value}` is not RFC 3339: {source}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_reported_as_an_override() {
        let evaluated = EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("valid");
        assert_eq!(evaluated.source, TimeSource::Override);
        assert_eq!(evaluated.rendered, "2026-08-16T12:00:00Z");
    }

    #[test]
    fn an_offset_override_is_rendered_in_utc() {
        let evaluated = EvaluationTime::resolve(Some("2026-08-16T13:00:00+01:00")).expect("valid");
        assert_eq!(evaluated.rendered, "2026-08-16T12:00:00Z");
    }

    #[test]
    fn the_clock_is_used_only_when_no_override_is_given() {
        let evaluated = EvaluationTime::resolve(None).expect("clock");
        assert_eq!(evaluated.source, TimeSource::Clock);
        assert!(evaluated.rendered.ends_with('Z'));
    }

    #[test]
    fn a_non_rfc3339_override_is_a_usage_error_not_a_verdict() {
        let error = EvaluationTime::resolve(Some("yesterday")).expect_err("not RFC 3339");
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Error);
    }

    #[test]
    fn elapsed_nanoseconds_saturate_for_a_future_instant() {
        let evaluated = EvaluationTime::resolve(Some("2026-08-16T12:00:00Z")).expect("valid");
        let later = parse_artifact_time("checkpoint_time", "2026-08-16T13:00:00Z").expect("valid");
        assert_eq!(evaluated.nanos_since(later), 0);
        let earlier =
            parse_artifact_time("checkpoint_time", "2026-08-16T11:00:00Z").expect("valid");
        assert_eq!(evaluated.nanos_since(earlier), 3_600_000_000_000);
    }

    #[test]
    fn a_bad_artifact_timestamp_is_reported_against_the_artifact() {
        let error = parse_artifact_time("checkpoint_time", "not-a-time").expect_err("malformed");
        assert!(matches!(error, CliError::Malformed { .. }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid);
    }
}
