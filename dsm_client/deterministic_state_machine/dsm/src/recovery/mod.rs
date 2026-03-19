//! DSM Recovery Module
//!
//! Implements the offline-first, post-quantum recovery protocol described in the whitepaper.
//! Uses AEAD-encrypted NFC capsules containing SMT roots, per-counterparty bilateral tips,
//! and receipt rollups for immediate recovery without history replay.

pub mod capsule;
pub mod rollup;
pub mod tombstone;

pub use capsule::{EncryptedCapsule, RecoveryCapsule, CapsuleMetadata};
pub use rollup::{ReceiptRollup, RollupEntry};
pub use tombstone::{TombstoneReceipt, SuccessionReceipt, RecoveryReceipt};

use crate::types::error::DsmError;
use std::collections::HashMap;

/// Initialize the recovery subsystem
pub fn init_recovery() {
    // Initialize the recovery subsystem components
    tracing::info!("Initializing offline-first recovery subsystem...");

    // Initialize capsule encryption/decryption
    if let Err(e) = capsule::init_capsule_subsystem() {
        tracing::error!("Failed to initialize capsule subsystem: {}", e);
    }

    // Initialize rollup accumulator
    rollup::init_rollup_subsystem();

    // Initialize tombstone/succession receipts
    tombstone::init_tombstone_subsystem();

    tracing::info!("Recovery subsystem initialized");
}

/// Create an encrypted recovery capsule for NFC ring storage
pub fn create_recovery_capsule(
    smt_root: &[u8],
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>, // counterparty_id -> (height, head_hash)
    rollup: &ReceiptRollup,
    mnemonic: &str,
    device_id: &str,
    counter: u64,
) -> Result<EncryptedCapsule, DsmError> {
    capsule::create_encrypted_capsule(
        smt_root,
        counterparty_tips,
        rollup,
        mnemonic,
        device_id,
        counter,
    )
}

/// Decrypt and verify a recovery capsule from NFC ring
pub fn decrypt_recovery_capsule(
    encrypted_capsule: &EncryptedCapsule,
    mnemonic: &str,
    device_id: &str,
) -> Result<RecoveryCapsule, DsmError> {
    capsule::decrypt_capsule(encrypted_capsule, mnemonic, device_id)
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
    fn test_capsule_creation() -> Result<(), DsmError> {
        // Test capsule creation and decryption
        let smt_root = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer1".to_string(), (1u64, vec![0; 32]));
        counterparty_tips.insert("peer2".to_string(), (2u64, vec![1; 32]));

        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let device_id = "test_device";
        let counter = 1u64;

        // Create encrypted capsule
        let encrypted = create_recovery_capsule(
            &smt_root,
            counterparty_tips.clone(),
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;

        // Decrypt capsule
        let decrypted = decrypt_recovery_capsule(&encrypted, mnemonic, device_id)?;

        // Verify contents
        assert_eq!(decrypted.smt_root, smt_root);
        assert_eq!(decrypted.counterparty_tips.len(), 2);
        assert!(decrypted.counterparty_tips.contains_key("peer1"));
        assert!(decrypted.counterparty_tips.contains_key("peer2"));

        Ok(())
    }

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
