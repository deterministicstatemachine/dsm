// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bearer-asset reconciliation lock states (spec §0.4 P5).
//!
//! The recovery **two-gate model** separates identity recovery from bearer-asset spend
//! authority. Identity succession (Phase D) proves `A_new` is the valid successor — it does
//! NOT make recovered bearer assets spendable. Every bearer asset restored from a recovery
//! capsule enters [`BearerAssetLockState::LockedRecovery`] and stays there until its OWN
//! verified frontier reconciles it — **the capsule is never a balance oracle.**
//!
//! State machine (spec §0.4):
//! `LockedRecovery → reconciled{ Spendable | Reduced | InFlight | Finalized | RefundPending }`.
//! Egress is refused while `LockedRecovery` or below the reconciled frontier.
//!
//! This module is the PURE core: the state enum, its fail-closed wire codec, the egress
//! predicate, and the generic token-frontier reconciliation rule. The lock registry, the
//! per-asset egress chokepoint, and dBTC's bearer-state frontier replay live above it
//! (`dsm_sdk`). dBTC assets MUST NOT be reconciled through the generic token path — they
//! stay `LockedRecovery` until the dedicated dBTC replay pass (enforced at the SDK layer).

use crate::types::error::DsmError;

/// Per-asset bearer reconciliation state. Wire tags 1..=6; 0 (and any unknown) is INVALID
/// and rejected on decode (fail-closed — never silently read as a permissive state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerAssetLockState {
    /// Restored from the capsule, not yet reconciled. Egress REFUSED.
    LockedRecovery,
    /// Verified frontier matches (or exceeds) the restored hint. Full egress permitted.
    Spendable,
    /// Verified frontier is LOWER than the restored hint. Egress permitted only within the
    /// reconciled frontier (the registry stores the cap).
    Reduced,
    /// Value is in-flight elsewhere (e.g. a pending dBTC withdrawal). Egress REFUSED.
    InFlight,
    /// Value was finalized elsewhere (e.g. bridged out). Egress REFUSED.
    Finalized,
    /// A refund is pending against this asset. Egress REFUSED.
    RefundPending,
}

impl BearerAssetLockState {
    /// Wire tag (1..=6). 0 is reserved as the invalid/unspecified sentinel.
    pub fn to_wire(self) -> u8 {
        match self {
            BearerAssetLockState::LockedRecovery => 1,
            BearerAssetLockState::Spendable => 2,
            BearerAssetLockState::Reduced => 3,
            BearerAssetLockState::InFlight => 4,
            BearerAssetLockState::Finalized => 5,
            BearerAssetLockState::RefundPending => 6,
        }
    }

    /// Decode a wire tag. Fail-closed: 0 / unknown → `Err` (NEVER defaulted to a permissive
    /// state). A corrupt or unrecognized lock byte must block egress, not silently allow it.
    pub fn from_wire(tag: u8) -> Result<Self, DsmError> {
        match tag {
            1 => Ok(BearerAssetLockState::LockedRecovery),
            2 => Ok(BearerAssetLockState::Spendable),
            3 => Ok(BearerAssetLockState::Reduced),
            4 => Ok(BearerAssetLockState::InFlight),
            5 => Ok(BearerAssetLockState::Finalized),
            6 => Ok(BearerAssetLockState::RefundPending),
            other => Err(DsmError::verification(format!(
                "BearerAssetLockState: invalid wire tag {other} (fail-closed)"
            ))),
        }
    }

    /// Whether this state permits ANY egress. Only `Spendable` (unconditional) and `Reduced`
    /// (capped at the reconciled frontier — the caller enforces the amount). `LockedRecovery`,
    /// `InFlight`, `Finalized`, and `RefundPending` all REFUSE.
    pub fn permits_egress(self) -> bool {
        matches!(
            self,
            BearerAssetLockState::Spendable | BearerAssetLockState::Reduced
        )
    }

    /// Whether egress under this state is capped at the reconciled frontier (`Reduced` only).
    pub fn is_frontier_capped(self) -> bool {
        matches!(self, BearerAssetLockState::Reduced)
    }

    /// Short human-readable label for gate error messages.
    pub fn label(self) -> &'static str {
        match self {
            BearerAssetLockState::LockedRecovery => "LockedRecovery",
            BearerAssetLockState::Spendable => "Spendable",
            BearerAssetLockState::Reduced => "Reduced",
            BearerAssetLockState::InFlight => "InFlight",
            BearerAssetLockState::Finalized => "Finalized",
            BearerAssetLockState::RefundPending => "RefundPending",
        }
    }
}

/// Generic token-frontier reconciliation rule (spec §0.4 P5).
///
/// Given the capsule-restored `hint` amount and the independently-VERIFIED latest frontier
/// `verified`, returns the reconciled state + the spendable cap:
/// - `verified >= hint` → `(Spendable, verified)` — no reduction, full egress;
/// - `verified <  hint` → `(Reduced,   verified)` — egress capped at the verified frontier.
///
/// The caller MUST have proven `verified` against the asset's latest accepted state (posted /
/// bilateral). With no such proof the asset stays `LockedRecovery` (this fn is simply not
/// called). This rule is for ORDINARY tokens only; dBTC reconciliation is the dedicated pass.
pub fn reconcile_token_frontier(hint: u64, verified: u64) -> (BearerAssetLockState, u64) {
    if verified >= hint {
        (BearerAssetLockState::Spendable, verified)
    } else {
        (BearerAssetLockState::Reduced, verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trips_all_states() {
        for s in [
            BearerAssetLockState::LockedRecovery,
            BearerAssetLockState::Spendable,
            BearerAssetLockState::Reduced,
            BearerAssetLockState::InFlight,
            BearerAssetLockState::Finalized,
            BearerAssetLockState::RefundPending,
        ] {
            assert_eq!(BearerAssetLockState::from_wire(s.to_wire()).unwrap(), s);
        }
    }

    #[test]
    fn wire_zero_and_unknown_fail_closed() {
        assert!(BearerAssetLockState::from_wire(0).is_err());
        assert!(BearerAssetLockState::from_wire(7).is_err());
        assert!(BearerAssetLockState::from_wire(255).is_err());
    }

    #[test]
    fn only_spendable_and_reduced_permit_egress() {
        assert!(BearerAssetLockState::Spendable.permits_egress());
        assert!(BearerAssetLockState::Reduced.permits_egress());
        assert!(!BearerAssetLockState::LockedRecovery.permits_egress());
        assert!(!BearerAssetLockState::InFlight.permits_egress());
        assert!(!BearerAssetLockState::Finalized.permits_egress());
        assert!(!BearerAssetLockState::RefundPending.permits_egress());
        // Only Reduced is frontier-capped.
        assert!(BearerAssetLockState::Reduced.is_frontier_capped());
        assert!(!BearerAssetLockState::Spendable.is_frontier_capped());
    }

    #[test]
    fn reconcile_full_frontier_is_spendable() {
        assert_eq!(
            reconcile_token_frontier(100, 100),
            (BearerAssetLockState::Spendable, 100)
        );
        // Frontier exceeds hint (e.g. ingress after the capsule sealed) → still Spendable.
        assert_eq!(
            reconcile_token_frontier(100, 150),
            (BearerAssetLockState::Spendable, 150)
        );
    }

    #[test]
    fn reconcile_lower_frontier_is_reduced_capped() {
        assert_eq!(
            reconcile_token_frontier(100, 40),
            (BearerAssetLockState::Reduced, 40)
        );
        // A drained-to-zero frontier reduces the cap to 0 (locked-value, no egress amount fits).
        assert_eq!(
            reconcile_token_frontier(100, 0),
            (BearerAssetLockState::Reduced, 0)
        );
    }
}
