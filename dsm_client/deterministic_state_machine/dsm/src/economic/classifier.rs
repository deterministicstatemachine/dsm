// SPDX-License-Identifier: Apache-2.0

//! Which `R_econ` obligation an operation carries.
//!
//! ## Exhaustive, with no wildcard arm
//!
//! [`classify`] matches every [`Operation`] variant by name. A new variant
//! therefore **fails to compile** until somebody decides what it does to the
//! economic root. That is the entire point: a wildcard arm would silently
//! classify tomorrow's value-bearing operation as economically inert, and the
//! failure would be a missing debit rather than a compile error.
//!
//! ## Not a mirror of `Operation::is_value_bearing`
//!
//! `is_value_bearing` exists to gate recovery, and it answers a different
//! question. `DlvUnlock` is value-egress by that measure yet executes with
//! empty deltas, so it is `None` here. Keeping the two separate is deliberate;
//! wiring this to that would make one function serve two purposes and quietly
//! change both when either moved.
//!
//! ## `UnsupportedValueTransition` is not `None`
//!
//! It means *"this really does touch online economic value, but its
//! foreign-verifiable source predicate is unspecified."* A lineage containing
//! one can never become a `ValidatedEconomicRoot` — which is the honest
//! outcome, and categorically different from claiming the operation was inert.

use crate::types::operations::Operation;

/// What an operation does to `R_econ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicEffect {
    /// Touches no economic leaf.
    None,
    /// Has a closed, fully specified write set on `R_econ`.
    ///
    /// The write set itself is a function of the operation **and the
    /// pre-state** — an exact subtraction needs the old value — so it is not
    /// computable from the operation alone and is not carried here. This arm
    /// names the category; the mutations and their credit sources are built by
    /// the write-set construction, against the state.
    ClosedWriteSet,
    /// Moves value inside the device-bound offline allocation only.
    ///
    /// The allocation is not an `R_econ` member and has no leaf. An operation
    /// classified here must leave every economic leaf untouched, which is what
    /// [`check_tripwire`] enforces.
    OfflineAccountOnly,
    /// Touches online economic value with no defined foreign-verifiable
    /// source predicate.
    UnsupportedValueTransition,
}

/// Classify an operation's economic effect.
pub fn classify(operation: &Operation) -> EconomicEffect {
    use EconomicEffect::*;
    use Operation::*;
    match operation {
        // ── No economic leaf ────────────────────────────────────────────
        Genesis | Noop => None,
        Create { .. } | Update { .. } | Delete { .. } => None,
        AddRelationship { .. } | CreateRelationship { .. } | RemoveRelationship { .. } => None,
        Link { .. } | Unlink { .. } | Invalidate { .. } | Generic { .. } => None,
        // Recovery re-roots identity material; it does not move value.
        Recovery { .. } => None,
        // Value-egress by the recovery gate's measure, but it executes with
        // empty deltas and moves nothing. This divergence is exactly why the
        // two classifications are separate functions.
        DlvUnlock { .. } => None,

        // ── Closed write sets ───────────────────────────────────────────
        Mint { .. } | Burn { .. } | CreateToken { .. } => ClosedWriteSet,
        // One balance credit of exactly the derived payout, funded by the
        // consumed ticket (CreditSourceValidatedFaucetDistribution, 0x0030).
        // NOT a mint: the units come from the network's finite bootstrap
        // allocation, and the accepting transition refuses the operation
        // without a matching pending admission.
        FaucetClaim { .. } => ClosedWriteSet,
        DlvSettle { .. } | DlvClose { .. } => ClosedWriteSet,
        // The 3.6 v2 vault operations state their complete economic effect
        // in the signed operation: both funding legs (create), or the exact
        // reserve movement with the parent vault-state binding (owner apply).
        DlvCreateFundedV2 { .. } | DlvOwnerApplyV2 { .. } => ClosedWriteSet,
        // One role-dependent economic event, not a Transfer fact and a
        // separate Receive fact: the role follows from whether
        // `to_device_id` is the local device.
        Transfer {
            authority_policy, ..
        } => match authority_policy {
            Option::None => ClosedWriteSet,
            // Opting into the offline-bearer tier moves allocation, not
            // balance. The boundaries (load and unload) are where the online
            // balance changes, and they are their own operations.
            Option::Some(_) => OfflineAccountOnly,
        },

        // ── Touches value, predicate unspecified ────────────────────────
        //
        // A standalone `Receive` credits with no independently verifiable
        // debit to fund it: the peer's debit is what funds a recipient
        // credit, and a bare Receive does not carry one.
        Receive { .. } => UnsupportedValueTransition,
        // Lock/unlock move value between spendable and encumbered. `R_econ`
        // has no encumbered leaf, so there is no write set to state — not a
        // no-op, an unspecified one.
        Lock { .. } | Unlock { .. } | LockToken { .. } | UnlockToken { .. } => {
            UnsupportedValueTransition
        }
        // Legacy DlvCreate classifies by ECONOMIC EFFECT, not operation name
        // (owner ruling 2026-08-28): the exact tokenless shape — no token, no
        // amount — moves nothing (the `Fund` reserve mutation refuses to ride
        // it; only value-bearing creates may encumber), so it is `None`, and
        // state-only vaults keep working. ANY value-bearing shape stays
        // unsupported below. The structural tripwire remains load-bearing:
        // if balance/reserve/receipt/consumed-source state changed, `None`
        // is impossible.
        DlvCreate {
            token_id: Option::None,
            locked_amount: Option::None,
            ..
        } => None,
        // The legacy DLV value operations. `DlvCreate` carries a SINGULAR
        // token_id and locked_amount while real funding is two-leg, and
        // `DlvOwnerApply` carries neither `fee_bps` nor `c_n` while its
        // sidecar carries the pair — one side holds an authenticated fact the
        // other lacks, so no equality check between them is even expressible.
        // Their replacements are separate tags (29/30) rather than mutations
        // of these, so that a legacy operation cannot be reinterpreted.
        DlvCreate { .. } | DlvOwnerApply { .. } => UnsupportedValueTransition,
        DlvClaim { .. } | DlvInvalidate { .. } => UnsupportedValueTransition,
    }
}

/// Economic leaf families observed to have changed across a transition.
///
/// Supplied by the caller that applied the transition, from the state it
/// actually holds — the point of the tripwire is that it does **not** consult
/// the classification it is checking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObservedEconomicChange {
    pub balances_changed: bool,
    pub vault_reserves_changed: bool,
    pub settlement_receipts_changed: bool,
    pub consumed_sources_changed: bool,
}

impl ObservedEconomicChange {
    pub fn any(&self) -> bool {
        self.balances_changed
            || self.vault_reserves_changed
            || self.settlement_receipts_changed
            || self.consumed_sources_changed
    }
}

/// A classification contradicted by what the transition actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicTripwire {
    pub claimed: EconomicEffect,
    pub observed: ObservedEconomicChange,
}

impl core::fmt::Display for EconomicTripwire {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "economic tripwire: operation classified {:?} but economic state changed \
             (balances={}, reserves={}, receipts={}, consumed_sources={}) — the classification \
             is wrong, or the operation reached a leaf it has no write set for",
            self.claimed,
            self.observed.balances_changed,
            self.observed.vault_reserves_changed,
            self.observed.settlement_receipts_changed,
            self.observed.consumed_sources_changed
        )
    }
}

impl std::error::Error for EconomicTripwire {}

/// The structural tripwire: a classification claiming no economic write must
/// be contradicted by any economic write.
///
/// This matters more than the operation names above. The names are a decision
/// somebody made; this is a check against what actually happened, so it catches
/// a variant misclassified today and a code path that reaches a leaf by some
/// route nobody enumerated. `OfflineAccountOnly` is held to the same standard
/// — the offline allocation is outside `R_econ`, so an operation that claims to
/// move only allocation and yet moved a leaf has broken the separation the
/// whole regime split rests on.
pub fn check_tripwire(
    claimed: EconomicEffect,
    observed: ObservedEconomicChange,
) -> Result<(), EconomicTripwire> {
    let must_not_write = matches!(
        claimed,
        EconomicEffect::None | EconomicEffect::OfflineAccountOnly
    );
    if must_not_write && observed.any() {
        return Err(EconomicTripwire { claimed, observed });
    }
    Ok(())
}
