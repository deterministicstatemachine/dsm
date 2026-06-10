// SPDX-License-Identifier: MIT OR Apache-2.0

//! dBTC bearer-state frontier reconciliation (spec §0.4 P5 — dBTC pass).
//!
//! Generic P5 ([`crate::recovery::bearer_lock`]) locks every recovered bearer asset
//! `LockedRecovery` and EXCLUDES dBTC from the generic token path — dBTC stays
//! `LockedRecovery` until its OWN bearer-state frontier reconciles. This module is the PURE,
//! deterministic core of that reconciliation: it maps the per-vault conditions (each derived
//! by the SDK classifier from a posted, verified `DbtcVaultAdvertisementV1`) and the
//! capsule-restored hint into the aggregate [`BearerAssetLockState`] + spendable cap for the
//! dBTC token.
//!
//! Fail-closed: the SDK only calls this with vaults it could actually fetch + verify; if it
//! cannot account for a vault (missing/malformed/unknown ad, or no enumeration source), dBTC
//! is left `LockedRecovery`. With no outcomes at all this returns `LockedRecovery` too.
//! Arithmetic is checked — any overflow collapses to `(LockedRecovery, 0)` rather than
//! producing a bogus spendable cap. The capsule is a candidate-id hint, NEVER a balance
//! oracle: a vault becomes spendable only because its posted frontier proves it.

use crate::recovery::bearer_lock::{reconcile_token_frontier, BearerAssetLockState};

/// The verified condition of a SINGLE dBTC vault, produced by the SDK classifier from its
/// posted advertisement. Distinct from the aggregate [`BearerAssetLockState`] — there is no
/// per-vault `LockedRecovery`/`Reduced` (those are token-level aggregate outcomes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbtcVaultCondition {
    /// The vault holds spendable dBTC backing (active + routeable). Contributes its amount to
    /// the spendable frontier.
    Spendable,
    /// Value is in-flight (deposit not yet confirmed, or a busy/withdrawing vault). Blocked.
    InFlight,
    /// Value has exited / been claimed / bridged out / invalidated. Blocked.
    Finalized,
    /// A refund path is open (expired/refunded). Blocked.
    RefundPending,
}

/// One classified, verified dBTC vault outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbtcVaultOutcome {
    pub amount_sats: u64,
    pub condition: DbtcVaultCondition,
}

/// Aggregate verified per-vault outcomes + the capsule-restored `hint_sats` into the dBTC
/// token's bearer-asset lock state + spendable cap (spec §0.4 P5).
///
/// - sums are CHECKED; any overflow → `(LockedRecovery, 0)` (fail-closed);
/// - `spendable_sum > 0` → [`reconcile_token_frontier`] (`≥hint → Spendable`, else
///   `Reduced(cap = spendable_sum)`);
/// - `spendable_sum == 0` → the dominant blocking condition, by precedence
///   `InFlight → RefundPending → Finalized`, each `cap = 0`;
/// - no outcomes at all → `(LockedRecovery, 0)` (no evidence — never unlock).
///
/// The blocking states (`InFlight`/`Finalized`/`RefundPending`/`LockedRecovery`) refuse egress
/// regardless of cap (`BearerAssetLockState::permits_egress` is false for them).
pub fn aggregate_dbtc_frontier(
    hint_sats: u64,
    outcomes: &[DbtcVaultOutcome],
) -> (BearerAssetLockState, u64) {
    if outcomes.is_empty() {
        return (BearerAssetLockState::LockedRecovery, 0);
    }

    let mut spendable: u64 = 0;
    let mut inflight: u64 = 0;
    let mut finalized: u64 = 0;
    let mut refund: u64 = 0;

    for o in outcomes {
        let bucket = match o.condition {
            DbtcVaultCondition::Spendable => &mut spendable,
            DbtcVaultCondition::InFlight => &mut inflight,
            DbtcVaultCondition::Finalized => &mut finalized,
            DbtcVaultCondition::RefundPending => &mut refund,
        };
        match bucket.checked_add(o.amount_sats) {
            Some(v) => *bucket = v,
            // Overflow → cannot compute a trustworthy frontier → fail closed.
            None => return (BearerAssetLockState::LockedRecovery, 0),
        }
    }

    if spendable > 0 {
        return reconcile_token_frontier(hint_sats, spendable);
    }
    // No spendable value: surface the dominant blocking condition (all refuse egress).
    if inflight > 0 {
        (BearerAssetLockState::InFlight, 0)
    } else if refund > 0 {
        (BearerAssetLockState::RefundPending, 0)
    } else if finalized > 0 {
        (BearerAssetLockState::Finalized, 0)
    } else {
        // Outcomes present but all zero-amount → no proven value → stay locked.
        (BearerAssetLockState::LockedRecovery, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(amount_sats: u64, condition: DbtcVaultCondition) -> DbtcVaultOutcome {
        DbtcVaultOutcome {
            amount_sats,
            condition,
        }
    }

    #[test]
    fn empty_outcomes_stay_locked() {
        assert_eq!(
            aggregate_dbtc_frontier(100, &[]),
            (BearerAssetLockState::LockedRecovery, 0)
        );
    }

    #[test]
    fn spendable_at_or_above_hint_is_spendable() {
        assert_eq!(
            aggregate_dbtc_frontier(100, &[o(100, DbtcVaultCondition::Spendable)]),
            (BearerAssetLockState::Spendable, 100)
        );
        assert_eq!(
            aggregate_dbtc_frontier(
                100,
                &[o(80, DbtcVaultCondition::Spendable), o(40, DbtcVaultCondition::Spendable)]
            ),
            (BearerAssetLockState::Spendable, 120)
        );
    }

    #[test]
    fn spendable_below_hint_is_reduced_capped() {
        assert_eq!(
            aggregate_dbtc_frontier(100, &[o(40, DbtcVaultCondition::Spendable)]),
            (BearerAssetLockState::Reduced, 40)
        );
        // Spendable portion alongside in-flight: cap = ONLY the spendable sum (in-flight blocked).
        assert_eq!(
            aggregate_dbtc_frontier(
                100,
                &[
                    o(40, DbtcVaultCondition::Spendable),
                    o(50, DbtcVaultCondition::InFlight),
                ]
            ),
            (BearerAssetLockState::Reduced, 40)
        );
    }

    #[test]
    fn no_spendable_surfaces_dominant_blocking_condition() {
        assert_eq!(
            aggregate_dbtc_frontier(100, &[o(50, DbtcVaultCondition::InFlight)]),
            (BearerAssetLockState::InFlight, 0)
        );
        // Precedence: InFlight before RefundPending before Finalized.
        assert_eq!(
            aggregate_dbtc_frontier(
                100,
                &[
                    o(10, DbtcVaultCondition::Finalized),
                    o(20, DbtcVaultCondition::RefundPending),
                    o(30, DbtcVaultCondition::InFlight),
                ]
            ),
            (BearerAssetLockState::InFlight, 0)
        );
        assert_eq!(
            aggregate_dbtc_frontier(
                100,
                &[
                    o(10, DbtcVaultCondition::Finalized),
                    o(20, DbtcVaultCondition::RefundPending),
                ]
            ),
            (BearerAssetLockState::RefundPending, 0)
        );
        assert_eq!(
            aggregate_dbtc_frontier(100, &[o(10, DbtcVaultCondition::Finalized)]),
            (BearerAssetLockState::Finalized, 0)
        );
    }

    #[test]
    fn all_zero_amounts_stay_locked() {
        assert_eq!(
            aggregate_dbtc_frontier(100, &[o(0, DbtcVaultCondition::Spendable)]),
            (BearerAssetLockState::LockedRecovery, 0)
        );
    }

    #[test]
    fn spendable_overflow_fails_closed() {
        assert_eq!(
            aggregate_dbtc_frontier(
                0,
                &[
                    o(u64::MAX, DbtcVaultCondition::Spendable),
                    o(1, DbtcVaultCondition::Spendable),
                ]
            ),
            (BearerAssetLockState::LockedRecovery, 0)
        );
    }
}
