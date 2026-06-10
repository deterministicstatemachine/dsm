// SPDX-License-Identifier: MIT OR Apache-2.0

//! dBTC Bitcoin-backing decision core (spec §0.4 P5 — dBTC pass, SPV/UTXO hardening).
//!
//! The dBTC reconcile classifier ([`crate::recovery::dbtc_reconcile`]) can derive a vault's
//! condition from its posted advertisement — but that advertisement is UNSIGNED and lives on
//! availability-only storage, and a recovery adversary holds the same mnemonic as the
//! legitimate owner, so **any DSM-side attestation (posted ad, K_A signature) is forgeable by
//! the thief.** The only thing the thief CANNOT forge is **Bitcoin truth**: whether the
//! vault's HTLC output is still unspent and buried on-chain.
//!
//! So dBTC unlock to `Spendable` is gated on three Bitcoin-verified facts the SDK gathers
//! live (UTXO query + header height + bearer-preimage re-derivation), NOT on the posted ad:
//!   1. the HTLC output at the vault's address is still **unspent** (not swept/withdrawn);
//!   2. the funding tx is **confirmed** to ≥ `min_confirmations`;
//!   3. the bearer can **derive the claim preimage** (`SHA256(preimage) == hash_lock`),
//!      i.e. the recovered identity can actually sweep it.
//!
//! This module is the PURE decision: facts → per-vault [`DbtcVaultCondition`]. The live
//! gathering (network) is the SDK's job; if it cannot establish a fact, it passes the
//! conservative value and this maps to a blocking condition — fail-closed. The per-vault
//! conditions then feed [`crate::recovery::aggregate_dbtc_frontier`] unchanged.

use crate::recovery::dbtc_reconcile::DbtcVaultCondition;

/// Bitcoin-verified facts about one dBTC vault, gathered live by the SDK. Every field is the
/// SDK's best Bitcoin-truth determination; unknowable facts MUST be passed as the
/// safety-conservative value (`false`) so the decision blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbtcBitcoinFacts {
    /// The HTLC output at the vault's `htlc_address` is still UNSPENT on Bitcoin (the BTC is
    /// still locked — not swept/withdrawn). `false` if spent OR if liveness can't be checked.
    pub htlc_utxo_unspent: bool,
    /// The funding transaction is buried to ≥ `min_confirmations` (the deposit is final).
    /// `false` if not yet confirmed OR if confirmation depth can't be established.
    pub funding_confirmed: bool,
    /// The recovered bearer re-derived the claim preimage and `SHA256(preimage) == hash_lock`
    /// — i.e. this identity can actually sweep the vault. `false` if the hash_lock does not
    /// match (the vault is not claimable by this bearer).
    pub preimage_derivable: bool,
}

/// Decide a single vault's recovery condition from its Bitcoin-verified facts.
///
/// `Spendable` ONLY when all three facts hold (unspent + confirmed + claimable). Otherwise
/// the dominant blocking reason:
/// - not claimable by this bearer → `Finalized` (not this identity's to spend);
/// - HTLC output already spent on Bitcoin → `Finalized` (already withdrawn/swept);
/// - unspent + claimable but not yet confirmed → `InFlight` (deposit still settling).
///
/// (There is no `Spendable`-from-posted-ad path: this is the only route to `Spendable` for
/// dBTC, and it requires Bitcoin truth.)
pub fn classify_dbtc_backing(facts: &DbtcBitcoinFacts) -> DbtcVaultCondition {
    if facts.htlc_utxo_unspent && facts.funding_confirmed && facts.preimage_derivable {
        DbtcVaultCondition::Spendable
    } else if !facts.preimage_derivable || !facts.htlc_utxo_unspent {
        // Not claimable by this bearer (hash_lock mismatch → not our vault), OR the HTLC
        // output is already spent on Bitcoin (withdrawn/swept). Either way: value gone.
        DbtcVaultCondition::Finalized
    } else {
        // Claimable + unspent, but funding not yet confirmed to depth → deposit still settling.
        DbtcVaultCondition::InFlight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(unspent: bool, confirmed: bool, derivable: bool) -> DbtcBitcoinFacts {
        DbtcBitcoinFacts {
            htlc_utxo_unspent: unspent,
            funding_confirmed: confirmed,
            preimage_derivable: derivable,
        }
    }

    #[test]
    fn all_three_facts_yield_spendable() {
        assert_eq!(
            classify_dbtc_backing(&facts(true, true, true)),
            DbtcVaultCondition::Spendable
        );
    }

    #[test]
    fn spent_htlc_is_finalized() {
        // Unspent=false → BTC already swept → already withdrawn → Finalized (blocked).
        assert_eq!(
            classify_dbtc_backing(&facts(false, true, true)),
            DbtcVaultCondition::Finalized
        );
    }

    #[test]
    fn not_derivable_is_finalized_not_ours() {
        // Not claimable by this bearer takes precedence — not this identity's to spend.
        assert_eq!(
            classify_dbtc_backing(&facts(true, true, false)),
            DbtcVaultCondition::Finalized
        );
        assert_eq!(
            classify_dbtc_backing(&facts(false, false, false)),
            DbtcVaultCondition::Finalized
        );
    }

    #[test]
    fn unspent_claimable_unconfirmed_is_inflight() {
        assert_eq!(
            classify_dbtc_backing(&facts(true, false, true)),
            DbtcVaultCondition::InFlight
        );
    }

    #[test]
    fn any_missing_fact_never_spendable() {
        // Fail-closed: no combination short of (unspent && confirmed && derivable) is Spendable.
        for unspent in [false, true] {
            for confirmed in [false, true] {
                for derivable in [false, true] {
                    let c = classify_dbtc_backing(&facts(unspent, confirmed, derivable));
                    if !(unspent && confirmed && derivable) {
                        assert_ne!(
                            c,
                            DbtcVaultCondition::Spendable,
                            "u={unspent} c={confirmed} d={derivable}"
                        );
                    }
                }
            }
        }
    }
}
