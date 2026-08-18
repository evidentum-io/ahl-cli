//! The restricted ISO 8601 duration grammar of core spec §7.3 / adaptor profile §7.3.1.
//!
//! `checkpoint_cadence` and `witness_grace_period` are durations limited to **time
//! components** — `P[n]DT[n]H[n]M[n]S`. Years and calendar months are prohibited: their
//! length is context-dependent, so admitting them would make cadence, series completeness and
//! incorporation bounds depend on which calendar arithmetic an implementation happened to use,
//! and two conforming verifiers could reach different verdicts on the same series. A value
//! carrying `Y`, or `M` in the **date** part, is malformed and is rejected, never approximated.
//! `M` after the `T` is minutes and is permitted.
//!
//! Fractional seconds are capped at nine digits — matching the nanosecond precision of an ATL
//! checkpoint timestamp — and a tenth digit is rejected rather than truncated or rounded:
//! truncation is exactly the implementation-dependent divergence the component restriction
//! exists to prevent.
//!
//! Comparison is **by normalized value, not by spelling**: `PT60M` and `PT1H` are the same
//! cadence, as are `PT86400S`, `PT24H` and `P1D`. Because years and calendar months are
//! excluded, every permitted duration normalizes to an exact number of nanoseconds, so
//! normalization is well defined and no calendar arithmetic is involved.

use crate::error::{CliError, CliResult};

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_FRACTIONAL_DIGITS: usize = 9;

/// Parse a restricted ISO 8601 duration into nanoseconds.
///
/// # Errors
///
/// [`CliError::Malformed`] naming the rule that fired: a prohibited component, an
/// over-precise fractional part, an out-of-order or repeated designator, or a value that
/// overflows.
///
/// ```
/// use ahl_cli::duration::parse_time_only_duration;
///
/// assert_eq!(parse_time_only_duration("cadence", "PT1H").unwrap(), 3_600_000_000_000);
/// assert_eq!(
///     parse_time_only_duration("cadence", "PT60M").unwrap(),
///     parse_time_only_duration("cadence", "PT1H").unwrap(),
/// );
/// // Five months, not five minutes: prohibited in these fields.
/// assert!(parse_time_only_duration("cadence", "P5M").is_err());
/// ```
// A grammar, parsed in one pass. The date part and the time part are deliberately not two
// functions: the prohibition on `Y` and date-part `M` is only meaningful against the position
// the character occupies, and that position is what this single pass tracks.
#[allow(clippy::too_many_lines)]
pub fn parse_time_only_duration(field: &'static str, value: &str) -> CliResult<u64> {
    let malformed = |detail: String| CliError::Malformed { what: field, detail };

    let rest = value
        .strip_prefix('P')
        .ok_or_else(|| malformed(format!("`{value}` does not start with `P`")))?;
    if rest.is_empty() {
        return Err(malformed(format!("`{value}` carries no components")));
    }

    let (date_part, time_part) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };

    let mut nanos: u64 = 0;

    // Date part: days only. `Y` and `M` are prohibited, and rejected by name so the message
    // says which rule fired rather than "unexpected character".
    let mut number = String::new();
    for ch in date_part.chars() {
        match ch {
            '0'..='9' => number.push(ch),
            'Y' | 'M' => {
                return Err(malformed(format!(
                    "`{value}` carries `{ch}` in the date part; years and calendar months are \
                     prohibited in {field} because their length is context-dependent"
                )))
            }
            'D' => {
                let days = take_number(&mut number, value, 'D', field)?;
                nanos = nanos
                    .checked_add(
                        days.checked_mul(86_400)
                            .and_then(|s| s.checked_mul(NANOS_PER_SECOND))
                            .ok_or_else(|| malformed(format!("`{value}` overflows")))?,
                    )
                    .ok_or_else(|| malformed(format!("`{value}` overflows")))?;
            }
            'W' => {
                return Err(malformed(format!(
                    "`{value}` carries a week designator, which {field} does not permit"
                )))
            }
            other => return Err(malformed(format!("`{value}` carries an unexpected `{other}`"))),
        }
    }
    if !number.is_empty() {
        return Err(malformed(format!("`{value}` ends the date part with no designator")));
    }

    let Some(time_part) = time_part else {
        if nanos == 0 {
            return Err(malformed(format!("`{value}` carries no components")));
        }
        return Ok(nanos);
    };
    if time_part.is_empty() {
        return Err(malformed(format!("`{value}` has a `T` with no time components")));
    }

    let mut number = String::new();
    let mut fraction: Option<String> = None;
    for ch in time_part.chars() {
        match ch {
            '0'..='9' => {
                if let Some(digits) = fraction.as_mut() {
                    digits.push(ch);
                } else {
                    number.push(ch);
                }
            }
            '.' | ',' => {
                if fraction.is_some() {
                    return Err(malformed(format!("`{value}` carries two decimal separators")));
                }
                fraction = Some(String::new());
            }
            'H' | 'M' | 'S' => {
                if fraction.is_some() && ch != 'S' {
                    return Err(malformed(format!(
                        "`{value}` puts a fractional part on `{ch}`; only seconds may be \
                         fractional in {field}"
                    )));
                }
                let whole = take_number(&mut number, value, ch, field)?;
                let unit_seconds = match ch {
                    'H' => 3_600,
                    'M' => 60,
                    _ => 1,
                };
                let mut part = whole
                    .checked_mul(unit_seconds)
                    .and_then(|s| s.checked_mul(NANOS_PER_SECOND))
                    .ok_or_else(|| malformed(format!("`{value}` overflows")))?;
                if let Some(digits) = fraction.take() {
                    part = part
                        .checked_add(fractional_nanos(&digits, value, field)?)
                        .ok_or_else(|| malformed(format!("`{value}` overflows")))?;
                }
                nanos = nanos
                    .checked_add(part)
                    .ok_or_else(|| malformed(format!("`{value}` overflows")))?;
            }
            other => return Err(malformed(format!("`{value}` carries an unexpected `{other}`"))),
        }
    }
    if !number.is_empty() || fraction.is_some() {
        return Err(malformed(format!("`{value}` ends the time part with no designator")));
    }
    Ok(nanos)
}

fn take_number(
    buffer: &mut String,
    value: &str,
    designator: char,
    field: &'static str,
) -> CliResult<u64> {
    if buffer.is_empty() {
        return Err(CliError::Malformed {
            what: field,
            detail: format!("`{value}` carries a `{designator}` with no number"),
        });
    }
    let parsed = buffer.parse::<u64>().map_err(|_| CliError::Malformed {
        what: field,
        detail: format!("`{value}` carries a number too large for `{designator}`"),
    })?;
    buffer.clear();
    Ok(parsed)
}

fn fractional_nanos(digits: &str, value: &str, field: &'static str) -> CliResult<u64> {
    if digits.is_empty() {
        return Err(CliError::Malformed {
            what: field,
            detail: format!("`{value}` has a decimal separator with no digits"),
        });
    }
    if digits.len() > MAX_FRACTIONAL_DIGITS {
        return Err(CliError::Malformed {
            what: field,
            detail: format!(
                "`{value}` carries {} fractional digits; at most {MAX_FRACTIONAL_DIGITS} are \
                 permitted, and a longer value is rejected rather than truncated or rounded",
                digits.len()
            ),
        });
    }
    let mut padded = digits.to_owned();
    while padded.len() < MAX_FRACTIONAL_DIGITS {
        padded.push('0');
    }
    padded.parse::<u64>().map_err(|_| CliError::Malformed {
        what: field,
        detail: format!("`{value}` carries an unparseable fractional part"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> CliResult<u64> {
        parse_time_only_duration("checkpoint_cadence", value)
    }

    #[test]
    fn time_components_parse_to_exact_nanoseconds() {
        assert_eq!(parse("PT1H").expect("valid"), 3_600 * NANOS_PER_SECOND);
        assert_eq!(parse("PT15M").expect("valid"), 900 * NANOS_PER_SECOND);
        assert_eq!(parse("PT30S").expect("valid"), 30 * NANOS_PER_SECOND);
        assert_eq!(parse("P1D").expect("valid"), 86_400 * NANOS_PER_SECOND);
        assert_eq!(
            parse("P1DT2H3M4S").expect("valid"),
            (86_400 + 7_200 + 180 + 4) * NANOS_PER_SECOND
        );
    }

    #[test]
    fn comparison_is_by_value_not_by_spelling() {
        assert_eq!(parse("PT60M").expect("valid"), parse("PT1H").expect("valid"));
        assert_eq!(parse("PT86400S").expect("valid"), parse("P1D").expect("valid"));
        assert_eq!(parse("PT24H").expect("valid"), parse("P1D").expect("valid"));
    }

    #[test]
    fn years_and_calendar_months_are_rejected_never_approximated() {
        let error = parse("P1Y").expect_err("years prohibited");
        assert!(error.to_string().contains("prohibited"), "{error}");
        let error = parse("P5M").expect_err("calendar months prohibited");
        assert!(error.to_string().contains("prohibited"), "{error}");
        // `M` after `T` is minutes and is permitted.
        assert_eq!(parse("PT5M").expect("valid"), 300 * NANOS_PER_SECOND);
    }

    #[test]
    fn fractional_seconds_are_capped_at_nine_digits() {
        assert_eq!(parse("PT0.000000001S").expect("valid"), 1);
        assert_eq!(parse("PT1.5S").expect("valid"), 1_500_000_000);
        let error = parse("PT0.0000000001S").expect_err("ten digits");
        assert!(error.to_string().contains("rather than truncated"), "{error}");
    }

    #[test]
    fn a_fractional_part_on_hours_or_minutes_is_rejected() {
        assert!(parse("PT1.5H").is_err());
        assert!(parse("PT1.5M").is_err());
    }

    #[test]
    fn structural_malformations_are_rejected_by_name() {
        for value in [
            "1H",       // no leading P
            "P",        // no components
            "PT",       // T with nothing after it
            "PTH",      // designator with no number
            "PT1",      // number with no designator
            "P1",       // date number with no designator
            "P1W",      // weeks
            "PT1.2.3S", // two separators
            "PT1.S",    // separator with no digits
            "P1X",      // unexpected designator
            "PT1X",     // unexpected time designator
        ] {
            assert!(parse(value).is_err(), "`{value}` must be rejected");
        }
    }

    #[test]
    fn overflow_is_reported_rather_than_wrapping() {
        assert!(parse(&format!("PT{}S", u64::MAX)).is_err());
        assert!(parse(&format!("P{}D", u64::MAX)).is_err());
        assert!(parse("P99999999999999999999D").is_err());
    }
}
