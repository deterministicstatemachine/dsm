// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Recovery Module
//!
//! Implements the offline-first, post-quantum recovery protocol described in the whitepaper:
//! tombstone and succession receipts under a genesis-anchored recovery authority, posted
//! relationship-chain evidence, and receipt rollups for recovery without history replay.

pub mod activation;
pub mod assembly;
pub mod authority_anchor;
pub mod bearer_lock;
pub mod bundle;
pub mod cell;
pub mod chain_segment;
pub mod contact_set;
pub mod dbtc_backing;
pub mod dbtc_reconcile;
pub mod dbtc_vault_index;
pub mod gate_set;
pub mod pdsmt_posting;
pub mod recovery_keys;
pub mod rollup;
pub mod succession_binding;
pub mod succession_proof;
pub mod tombstone;

pub use activation::{compute_evidence_root, validate_recovery_activation, RecoveryActivationSeal};
pub use assembly::{
    assemble_recovery_activation, AssembledActivation, CounterpartyRecoveryInput,
    RecoveryAssemblyInputs,
};
pub use authority_anchor::{
    compute_authority_pubkey_commit, create_recovery_authority_anchor, RecoveryAuthorityAnchor,
};
pub use bearer_lock::{reconcile_token_frontier, BearerAssetLockState};
pub use dbtc_backing::{classify_dbtc_backing, DbtcBitcoinFacts};
pub use dbtc_reconcile::{aggregate_dbtc_frontier, DbtcVaultCondition, DbtcVaultOutcome};
pub use dbtc_vault_index::{build_dbtc_vault_index, PostedDbtcVaultIndex};
pub use bundle::RecoveryBundle;
pub use cell::RecoveryCell;
pub use chain_segment::{
    rel_chain_state_from_proto, rel_chain_state_to_proto, RecoveryEstablishmentReceipt,
    RelationshipChainSegment,
};
pub use gate_set::{build_gate_set, CounterpartyValueWitness, FrozenGateSet};
pub use pdsmt_posting::{
    build_pdsmt_snapshot, decode_leaf_set, encode_leaf_set, verify_head_with_leaves,
    PostedPdsmtHead, PostedPdsmtLeafRecord, GENESIS_PARENT_HEAD_HASH,
};
pub use succession_binding::{
    build_recovery_establishment_op, compute_carry_forward_commitment, is_recovery_establish_op,
    recovery_establishment_floor, verify_forward_ancestry, verify_recovery_reestablish_request,
    CrossRelationshipSuccessionEvidence, RECOVERY_ESTABLISH_MESSAGE,
};
pub use succession_proof::RecoverySuccessionProof;
pub use rollup::{ReceiptRollup, RollupEntry};
pub use recovery_keys::{derive_recovery_authority_seed, derive_recovery_key};
pub use tombstone::{ContactTombstoneAck, TombstoneReceipt, SuccessionReceipt, RecoveryReceipt};

use crate::types::error::DsmError;

/// Initialize the recovery subsystem
pub fn init_recovery() {
    // Initialize the recovery subsystem components
    tracing::info!("Initializing offline-first recovery subsystem...");

    // Initialize rollup accumulator
    rollup::init_rollup_subsystem();

    // Initialize tombstone/succession receipts
    tombstone::init_tombstone_subsystem();

    tracing::info!("Recovery subsystem initialized");
}

/// Create tombstone receipt to invalidate old device binding
pub fn create_tombstone_receipt(
    old_smt_root: &[u8],
    old_counter: u64,
    old_rollup: &[u8],
    device_id: &str,
    private_key: &[u8],
) -> Result<TombstoneReceipt, DsmError> {
    tombstone::create_tombstone(
        old_smt_root,
        old_counter,
        old_rollup,
        device_id,
        private_key,
    )
}

/// Create succession receipt to bind new device
pub fn create_succession_receipt(
    tombstone_hash: &[u8],
    new_device_commitment: &[u8],
    device_id: &str,
    private_key: &[u8],
) -> Result<SuccessionReceipt, DsmError> {
    tombstone::create_succession(
        tombstone_hash,
        new_device_commitment,
        device_id,
        private_key,
    )
}

/// Verify tombstone receipt
pub fn verify_tombstone_receipt(
    tombstone: &TombstoneReceipt,
    public_key: &[u8],
) -> Result<bool, DsmError> {
    tombstone::verify_tombstone(tombstone, public_key)
}

/// Verify succession receipt
pub fn verify_succession_receipt(
    succession: &SuccessionReceipt,
    tombstone_hash: &[u8],
    public_key: &[u8],
) -> Result<bool, DsmError> {
    tombstone::verify_succession(succession, tombstone_hash, public_key)
}

/// Update receipt rollup with new receipt
pub fn update_rollup(
    rollup: &mut ReceiptRollup,
    receipt_id: &[u8],
    receipt_hash: &[u8],
    counterparty_id: &str,
    new_height: u64,
) -> Result<(), DsmError> {
    rollup::update_rollup(
        rollup,
        receipt_id,
        receipt_hash,
        counterparty_id,
        new_height,
    )
}

/// Verify rollup against expected value
pub fn verify_rollup(rollup: &ReceiptRollup, expected: &[u8]) -> bool {
    rollup::verify_rollup(rollup, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollup_operations() -> Result<(), DsmError> {
        let mut rollup = ReceiptRollup::new();
        let initial_hash = rollup.current_hash();

        // Update rollup
        update_rollup(&mut rollup, b"receipt1", &[1; 32], "peer1", 1)?;

        // Hash should change
        assert_ne!(rollup.current_hash(), initial_hash);

        // Verify rollup
        assert!(verify_rollup(&rollup, &rollup.current_hash()));

        Ok(())
    }
}
