// SPDX-License-Identifier: Apache-2.0

//! The validated side of the economic lineage.
//!
//! ## The separation is enforced by the compiler, not by discipline
//!
//! [`ValidatedEconomicRoot`] has a private field and **no public constructor
//! that takes a [`RegisteredEconomicRoot`]**. There is no `From`, no
//! `into_validated`, no `assume_valid`. The only way to obtain position 0 is
//! [`activate`], which checks the activation precondition; positions above 0
//! require substrate acceptance that this module does not yet have (see
//! "What is missing" below).
//!
//! That is deliberate. `accepted_root != valid_root` is the single most
//! load-bearing statement in the economic design, and a convenience conversion
//! — added later, in a hurry, "just for this call site" — is exactly how it
//! would stop being true. Making the coercion unwritable costs nothing and
//! removes the failure mode.
//!
//! ```text
//! ValidatedEconomicRoot(0) = the canonical EMPTY economic root
//!                            verifier-derived, never trader-chosen
//! ```
//!
//! ## Activation: no legacy snapshot, ever
//!
//! `R_econ(0) = empty` is non-circular for a **fresh** identity. It is not a
//! valid bootstrap for a device that already holds balances, reserves,
//! receipts or an outstanding offline allocation: taking whatever the device
//! currently holds and calling it position 0 would let the device assert its
//! own opening balances, which re-creates self-rooting at the base of the
//! lineage — the precise defect the whole construction exists to remove.
//!
//! So a device holding value cannot activate. A migration protocol for
//! existing holdings is future work; it must never be an implicit snapshot.
//!
//! ## What is missing, and why it is missing rather than approximated
//!
//! Advancing a validated root requires, conjunctively:
//!
//! ```text
//! ValidatedEconomicRoot(k) == witness.pre_economic_root
//! register[k+1] uniquely identifies { post_economic_root, admission_manifest_addr }
//! verify_economic_transition(pre, witness) == post_economic_root
//! the local acceptance substrate verifies                        <-- NOT YET
//! it and the witness bind THE SAME operation_digest              <-- NOT YET
//! registered post_economic_root == witness.post_economic_root
//! ```
//!
//! The two marked conditions need the admission lifecycle: an accepted DSM
//! successor or an accepted offline boundary attestation, and the digest that
//! binds it to this witness. Without the shared `operation_digest`, a trader
//! presents a valid successor and a valid economic transition **describing
//! different operations** — so a successor constructor that skipped it would
//! be strictly worse than none.
//!
//! There is therefore **no successor constructor here at all**. Nothing in
//! this module can produce `ValidatedEconomicRoot(k+1)`, which means nothing
//! can accidentally claim validation it has not performed.

use crate::economic::tree::empty_economic_root;

/// A root this verifier has established is the result of a valid transition
/// from a validated predecessor.
///
/// **Verifier-derived.** There is no network event that declares a root
/// validated, and no message a peer can send that produces one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedEconomicRoot {
    economic_position: u64,
    economic_root: [u8; 32],
}

impl ValidatedEconomicRoot {
    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    pub fn economic_root(&self) -> [u8; 32] {
        self.economic_root
    }
}

/// What the device currently holds, as observed by the activating device
/// itself.
///
/// Every field is a reason activation might be refused. A device that cannot
/// answer one of these has not established that it holds nothing, and
/// defaulting an unknown to "empty" would be assuming exactly the thing being
/// checked — so the caller must state all four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicActivationSnapshot {
    pub online_balances_empty: bool,
    pub vault_reserves_empty: bool,
    pub settlement_receipt_state_empty: bool,
    pub outstanding_offline_allocation: bool,
}

impl EconomicActivationSnapshot {
    /// The snapshot of a genuinely fresh identity.
    pub fn fresh() -> Self {
        Self {
            online_balances_empty: true,
            vault_reserves_empty: true,
            settlement_receipt_state_empty: true,
            outstanding_offline_allocation: false,
        }
    }
}

/// Why a device may not activate an economic lineage at the empty root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedLegacyEconomicState {
    pub snapshot: EconomicActivationSnapshot,
}

impl core::fmt::Display for UnsupportedLegacyEconomicState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cannot activate an economic lineage on a device that already holds value \
             (balances_empty={}, reserves_empty={}, receipts_empty={}, outstanding_allocation={}): \
             calling the current holdings position 0 would let the device assert its own opening \
             balances, which is self-rooting at the base of the lineage. Beta: use a fresh \
             identity. A migration protocol is future work and must never be an implicit snapshot",
            self.snapshot.online_balances_empty,
            self.snapshot.vault_reserves_empty,
            self.snapshot.settlement_receipt_state_empty,
            self.snapshot.outstanding_offline_allocation
        )
    }
}

impl std::error::Error for UnsupportedLegacyEconomicState {}

/// The ONLY way to obtain a `ValidatedEconomicRoot`.
///
/// Succeeds exactly when the device holds nothing, and yields position 0 at
/// the canonical empty root — a value every verifier derives identically
/// without being told it.
pub fn activate(
    snapshot: EconomicActivationSnapshot,
) -> Result<ValidatedEconomicRoot, UnsupportedLegacyEconomicState> {
    let clean = snapshot.online_balances_empty
        && snapshot.vault_reserves_empty
        && snapshot.settlement_receipt_state_empty
        && !snapshot.outstanding_offline_allocation;
    if !clean {
        return Err(UnsupportedLegacyEconomicState { snapshot });
    }
    Ok(ValidatedEconomicRoot {
        economic_position: 0,
        economic_root: empty_economic_root(),
    })
}
