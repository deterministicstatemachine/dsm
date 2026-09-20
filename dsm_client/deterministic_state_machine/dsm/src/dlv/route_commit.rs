// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one constant-product arithmetic (SoFi §19.5): the trader's quote, the
//! owner's fold and every verifier's re-simulation reach this function, and
//! there is exactly one floor division in it. Nothing else lives here.

/// The basis points denominator. `fee_bps` at or above this is not a hop.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Why a constant-product hop has no output.
///
/// The `Option` returned by [`constant_product_output`] collapses all of these
/// into one `None`, which makes a DUST TRADE and a MALFORMED HOP
/// indistinguishable at a verifier. Amendment 2c-C3's arithmetic discipline
/// requires each admissibility condition to refuse with its own reason, so the
/// classified form below is the one a successor-validity predicate calls.
///
/// This is a NARROWING of one arithmetic, never a second one:
/// [`constant_product_output`] is defined in terms of this function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantProductRefusal {
    /// `a = 0`. Market admissibility forbids it — which is also what makes
    /// "both reserve legs zero" an unambiguous retirement marker.
    InputAmountZero,
    /// `x = 0`.
    ReserveInZero,
    /// `y = 0`.
    ReserveOutZero,
    /// `f >= D`. Fee at or above 100 % is not a real hop.
    FeeAtOrAboveDenominator,
    /// A checked product exceeded `u128`. Reachable: `reserve_out` times the
    /// fee-adjusted input is up to ~2^142.
    ArithmeticOverflow,
    /// The single floor division truncated to zero — a legitimately-shaped
    /// trade too small to move the pool. NOT a malformed hop.
    OutputZero,
}

impl ConstantProductRefusal {
    /// A stable name for logs and for crossing a boundary.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InputAmountZero => "INPUT_AMOUNT_ZERO",
            Self::ReserveInZero => "RESERVE_IN_ZERO",
            Self::ReserveOutZero => "RESERVE_OUT_ZERO",
            Self::FeeAtOrAboveDenominator => "FEE_AT_OR_ABOVE_DENOMINATOR",
            Self::ArithmeticOverflow => "ARITHMETIC_OVERFLOW",
            Self::OutputZero => "OUTPUT_ZERO",
        }
    }
}

impl core::fmt::Display for ConstantProductRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Constant-product AMM output for one hop, with the refusal classified.
///
/// THE one arithmetic — the trader's quote, the owner's fold, the economic
/// verifier's re-simulation and the successor-validity predicate all reach it,
/// and there is exactly one floor division in it. The fee is carried as a
/// `* 10_000` numerator on BOTH sides rather than rescaling the input first,
/// so no second rounding exists to disagree about.
pub fn constant_product_output_classified(
    input_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u32,
) -> Result<u64, ConstantProductRefusal> {
    if input_amount == 0 {
        return Err(ConstantProductRefusal::InputAmountZero);
    }
    if reserve_in == 0 {
        return Err(ConstantProductRefusal::ReserveInZero);
    }
    if reserve_out == 0 {
        return Err(ConstantProductRefusal::ReserveOutZero);
    }
    if fee_bps >= BPS_DENOMINATOR {
        // Fee >= 100 % is not a real AMM hop; refuse rather than divide a
        // positive numerator by zero.
        return Err(ConstantProductRefusal::FeeAtOrAboveDenominator);
    }
    let input_amount = u128::from(input_amount);
    let reserve_in = u128::from(reserve_in);
    let reserve_out = u128::from(reserve_out);

    let fee_complement = u128::from(BPS_DENOMINATOR - fee_bps);
    let overflow = || ConstantProductRefusal::ArithmeticOverflow;
    let input_after_fee_num = input_amount
        .checked_mul(fee_complement)
        .ok_or_else(overflow)?;
    let denom_lhs = reserve_in
        .checked_mul(u128::from(BPS_DENOMINATOR))
        .ok_or_else(overflow)?;
    let denom = denom_lhs
        .checked_add(input_after_fee_num)
        .ok_or_else(overflow)?;
    let num = reserve_out
        .checked_mul(input_after_fee_num)
        .ok_or_else(overflow)?;
    let out = num / denom;
    if out == 0 {
        return Err(ConstantProductRefusal::OutputZero);
    }
    u64::try_from(out).map_err(|_| overflow())
}

/// Constant-product AMM output for one hop: the ONE implementation, shared
/// by the trader's quote, the owner's fold, and the economic verifier's
/// re-simulation — three callers, one arithmetic, no drift.
///
/// Callers that must distinguish "too small to move the pool" from "malformed"
/// want [`constant_product_output_classified`]; this form deliberately erases
/// that distinction for callers whose only decision is go / no-go.
pub fn constant_product_output(
    input_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u32,
) -> Option<u64> {
    constant_product_output_classified(input_amount, reserve_in, reserve_out, fee_bps).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE FUSED-ROUNDING CONFORMANCE VECTOR (SoFi v2.0 §5.1).
    ///
    /// The spec fixes one floor division and forbids rounding the fee-adjusted
    /// input first. At `a=1, x=1, y=3, fee_bps=30` the two rules genuinely
    /// part company: the fused rule yields 1, while flooring `a·(D−f)/D` first
    /// collapses a sub-unit input to zero and takes the whole output with it.
    ///
    /// Note the spec's own example says this holds for "any fee_bps in the
    /// legal range", which overstates it: at `f=0` there is no fee to round
    /// and at `f=9999` both rules yield 0. The divergence is real for ordinary
    /// fees, which is where a low-liquidity vault actually operates, so the
    /// vector pins a fee that exhibits it rather than quoting the claim.
    #[test]
    fn the_fee_adjusted_input_is_never_rounded_before_the_curve() {
        const D: u128 = 10_000;
        let doubly_rounded = |a: u128, x: u128, y: u128, f: u128| -> u128 {
            let pre = (a * (D - f)) / D; // the forbidden first rounding
            if pre == 0 {
                return 0;
            }
            (y * pre * D) / (x * D + pre * D)
        };

        assert_eq!(
            constant_product_output(1, 1, 3, 30),
            Some(1),
            "the fused rule keeps the sub-unit input alive"
        );
        assert_eq!(
            doubly_rounded(1, 1, 3, 30),
            0,
            "…and the doubly-rounded variant loses the whole output"
        );

        // The same shape across a spread of ordinary fees, so the vector is
        // not a single lucky point.
        for f in [1u32, 5, 30, 100, 300] {
            assert_eq!(
                constant_product_output(1, 1, 3, f),
                Some(1),
                "fused rule at fee_bps={f}"
            );
            assert_eq!(
                doubly_rounded(1, 1, 3, f as u128),
                0,
                "doubly-rounded variant at fee_bps={f}"
            );
        }

        // Honest boundaries: with no fee there is nothing to round, and a
        // near-total fee zeroes both. Recording them stops a later reader
        // from "fixing" the vector by widening it to every legal fee.
        assert_eq!(constant_product_output(1, 1, 3, 0), Some(1));
        assert_eq!(doubly_rounded(1, 1, 3, 0), 1, "no fee, no divergence");
        assert_eq!(constant_product_output(1, 1, 3, 9_999), None);
    }
}
