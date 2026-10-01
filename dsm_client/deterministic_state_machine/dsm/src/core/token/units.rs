// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token units: what a person types and reads, and the base units a balance
//! holds.
//!
//! A token's committed policy fixes its decimals (SoFi §47). An amount is
//! written in whole tokens with up to that many fraction digits after a
//! point — `10000.00` for a two-decimal token — and held as an integer count
//! of base units. These two functions are the only conversion between them,
//! so every route and every screen agrees on what an amount means.

/// Why a typed amount is not an amount of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenUnitsError {
    /// Nothing but whitespace, or a point with no digit on either side.
    Empty,
    /// A character that is neither a digit nor the one decimal point.
    NotADigit(char),
    /// More than one decimal point.
    SecondPoint,
    /// More fraction digits than the token's decimals allow.
    TooManyFractionDigits { given: usize, decimals: u32 },
    /// The amount does not fit in a balance.
    Overflow,
}

impl core::fmt::Display for TokenUnitsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "no amount was given"),
            Self::NotADigit(c) => write!(f, "{c:?} is not a digit or the decimal point"),
            Self::SecondPoint => write!(f, "an amount has at most one decimal point"),
            Self::TooManyFractionDigits { given, decimals } => write!(
                f,
                "{given} digits after the point, and this token has {decimals} decimals"
            ),
            Self::Overflow => write!(f, "the amount is too large for a balance"),
        }
    }
}

impl std::error::Error for TokenUnitsError {}

/// The base units `text` names for a token with `decimals` decimals.
///
/// `text` is whole tokens, optionally followed by a point and at most
/// `decimals` fraction digits; surrounding whitespace is ignored. A bare
/// integer is whole tokens, never base units: `10000` and `10000.00` are the
/// same amount of a two-decimal token.
pub fn parse_token_units(text: &str, decimals: u32) -> Result<u128, TokenUnitsError> {
    let text = text.trim();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.contains('.') {
                return Err(TokenUnitsError::SecondPoint);
            }
            (whole, fraction)
        }
        None => (text, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(TokenUnitsError::Empty);
    }
    if let Some(c) = whole
        .chars()
        .chain(fraction.chars())
        .find(|c| !c.is_ascii_digit())
    {
        return Err(TokenUnitsError::NotADigit(c));
    }
    // A u32 always fits a usize on the targets DSM builds for.
    let places = decimals as usize;
    if fraction.len() > places {
        return Err(TokenUnitsError::TooManyFractionDigits {
            given: fraction.len(),
            decimals,
        });
    }
    let scale = 10u128
        .checked_pow(decimals)
        .ok_or(TokenUnitsError::Overflow)?;
    let whole_units = digits_value(whole)?
        .checked_mul(scale)
        .ok_or(TokenUnitsError::Overflow)?;
    // The fraction's digits, padded on the right to the token's decimals.
    // `fraction.len() <= places`, and `places` came from a u32.
    let padding = (places - fraction.len()) as u32;
    let fraction_units = digits_value(fraction)?
        .checked_mul(
            10u128
                .checked_pow(padding)
                .ok_or(TokenUnitsError::Overflow)?,
        )
        .ok_or(TokenUnitsError::Overflow)?;
    whole_units
        .checked_add(fraction_units)
        .ok_or(TokenUnitsError::Overflow)
}

/// `base` base units written in whole tokens, with exactly `decimals`
/// fraction digits: 1_000_000 of a two-decimal token is `10000.00`.
pub fn format_token_units(base: u128, decimals: u32) -> String {
    let digits = base.to_string();
    let places = decimals as usize;
    if places == 0 {
        return digits;
    }
    let padded = if digits.len() <= places {
        format!("{}{digits}", "0".repeat(places + 1 - digits.len()))
    } else {
        digits
    };
    let split = padded.len() - places;
    format!("{}.{}", &padded[..split], &padded[split..])
}

/// The value of a run of ASCII digits; the empty run is zero.
fn digits_value(digits: &str) -> Result<u128, TokenUnitsError> {
    digits.bytes().try_fold(0u128, |acc, b| {
        acc.checked_mul(10)
            .and_then(|v| v.checked_add(u128::from(b - b'0')))
            .ok_or(TokenUnitsError::Overflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_tokens_with_or_without_the_point_are_the_same_amount() {
        assert_eq!(parse_token_units("10000.00", 2), Ok(1_000_000));
        assert_eq!(parse_token_units("10000", 2), Ok(1_000_000));
        assert_eq!(parse_token_units("10000.", 2), Ok(1_000_000));
        assert_eq!(parse_token_units(" 100.00 ", 2), Ok(10_000));
    }

    #[test]
    fn fraction_digits_are_padded_to_the_tokens_decimals() {
        assert_eq!(parse_token_units("0.15", 2), Ok(15));
        assert_eq!(parse_token_units("0.5", 2), Ok(50));
        assert_eq!(parse_token_units(".5", 2), Ok(50));
        assert_eq!(parse_token_units("3326.65", 2), Ok(332_665));
        assert_eq!(parse_token_units("1", 8), Ok(100_000_000));
    }

    #[test]
    fn a_zero_decimal_token_takes_whole_units_only() {
        assert_eq!(parse_token_units("50", 0), Ok(50));
        assert_eq!(
            parse_token_units("50.0", 0),
            Err(TokenUnitsError::TooManyFractionDigits {
                given: 1,
                decimals: 0
            })
        );
    }

    #[test]
    fn what_is_not_an_amount_is_refused_and_says_why() {
        assert_eq!(parse_token_units("", 2), Err(TokenUnitsError::Empty));
        assert_eq!(parse_token_units(".", 2), Err(TokenUnitsError::Empty));
        assert_eq!(
            parse_token_units("1.234", 2),
            Err(TokenUnitsError::TooManyFractionDigits {
                given: 3,
                decimals: 2
            })
        );
        assert_eq!(
            parse_token_units("1,000", 2),
            Err(TokenUnitsError::NotADigit(','))
        );
        assert_eq!(
            parse_token_units("-1", 2),
            Err(TokenUnitsError::NotADigit('-'))
        );
        assert_eq!(
            parse_token_units("1.2.3", 2),
            Err(TokenUnitsError::SecondPoint)
        );
        assert_eq!(
            parse_token_units("340282366920938463463374607431768211456", 0),
            Err(TokenUnitsError::Overflow)
        );
        assert_eq!(
            parse_token_units("340282366920938463463374607431768211455", 2),
            Err(TokenUnitsError::Overflow)
        );
    }

    #[test]
    fn formatting_shows_every_decimal_place_and_round_trips() {
        assert_eq!(format_token_units(1_000_000, 2), "10000.00");
        assert_eq!(format_token_units(15, 2), "0.15");
        assert_eq!(format_token_units(5, 2), "0.05");
        assert_eq!(format_token_units(0, 2), "0.00");
        assert_eq!(format_token_units(50, 0), "50");
        for (base, decimals) in [(332_665u128, 2u32), (10_000, 2), (7, 8), (123, 0)] {
            assert_eq!(
                parse_token_units(&format_token_units(base, decimals), decimals),
                Ok(base)
            );
        }
    }
}
