//! Receipt Rollup Accumulator Implementation
//!
//! Implements the receipt rollup accumulator as described in the whitepaper:
//! Roll_t+1 = H("RM" || Roll_t || rid_t || H(Rec_t) || ID(8)_Bi || ht'_i)
//!
//! This provides cryptographic binding of the ordered sequence of accepted receipts.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use std::sync::atomic::{AtomicBool, Ordering};

static ROLLUP_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the rollup accumulator subsystem
pub fn init_rollup_subsystem() {
    if !ROLLUP_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        tracing::info!("Receipt rollup subsystem initialized");
        ROLLUP_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

/// Individual rollup entry
#[derive(Debug, Clone)]
pub struct RollupEntry {
    /// Receipt ID (rid_t)
    pub receipt_id: Vec<u8>,
    /// Hash of the receipt (H(Rec_t))
    pub receipt_hash: Vec<u8>,
    /// 8-byte peer digest (ID(8)_Bi)
    pub peer_digest: [u8; 8],
    /// New height after this receipt (ht'_i)
    pub new_height: u64,
}

/// Receipt rollup accumulator
#[derive(Debug, Clone)]
pub struct ReceiptRollup {
    /// Current rollup hash (32 bytes)
    current_hash: [u8; 32],
    /// Ordered list of entries for verification
    entries: Vec<RollupEntry>,
}

impl ReceiptRollup {
    /// Create new empty rollup (Roll_0 = 0^256)
    pub fn new() -> Self {
        Self {
            current_hash: [0u8; 32],
            entries: Vec::new(),
        }
    }

    /// Get current rollup hash
    pub fn current_hash(&self) -> [u8; 32] {
        self.current_hash
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if rollup is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entries for verification
    pub fn entries(&self) -> &[RollupEntry] {
        &self.entries
    }
}

impl Default for ReceiptRollup {
    fn default() -> Self {
        Self::new()
    }
}

/// Update rollup with new receipt
pub fn update_rollup(
    rollup: &mut ReceiptRollup,
    receipt_id: &[u8],
    receipt_hash: &[u8],
    counterparty_id: &str,
    new_height: u64,
) -> Result<(), DsmError> {
    // Create 8-byte counterparty digest from counterparty_id
    let peer_digest = create_peer_digest(counterparty_id);

    // Create rollup entry
    let entry = RollupEntry {
        receipt_id: receipt_id.to_vec(),
        receipt_hash: receipt_hash.to_vec(),
        peer_digest,
        new_height,
    };

    // Compute new roll accumulator per whitepaper §13:
    //   Roll_{t+1} := H("DSM/recovery-roll\0" || Roll_t || rid_t || H(Rec_t) || ID(8)_Bi || ht'_i)
    let mut hasher = dsm_domain_hasher("DSM/recovery-roll");
    hasher.update(&rollup.current_hash);
    hasher.update(&entry.receipt_id);
    hasher.update(&entry.receipt_hash);
    hasher.update(&entry.peer_digest);
    hasher.update(&entry.new_height.to_le_bytes());

    rollup.current_hash = *hasher.finalize().as_bytes();
    rollup.entries.push(entry);

    Ok(())
}

/// Verify rollup against expected hash
pub fn verify_rollup(rollup: &ReceiptRollup, expected: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(&rollup.current_hash, expected)
}

/// Recompute rollup hash from entries (for verification)
pub fn recompute_rollup_hash(entries: &[RollupEntry]) -> [u8; 32] {
    let mut current_hash = [0u8; 32];

    for entry in entries {
        let mut hasher = dsm_domain_hasher("DSM/recovery-roll");
        hasher.update(&current_hash);
        hasher.update(&entry.receipt_id);
        hasher.update(&entry.receipt_hash);
        hasher.update(&entry.peer_digest);
        hasher.update(&entry.new_height.to_le_bytes());

        current_hash = *hasher.finalize().as_bytes();
    }

    current_hash
}

/// Create 8-byte peer digest from peer ID
fn create_peer_digest(counterparty_id: &str) -> [u8; 8] {
    let mut hasher = dsm_domain_hasher("DSM/recovery-roll-proof");
    hasher.update(counterparty_id.as_bytes());
    let hash = hasher.finalize();
    let mut digest = [0u8; 8];
    digest.copy_from_slice(&hash.as_bytes()[..8]);
    digest
}

/// Verify that a sequence of entries produces the expected rollup hash
pub fn verify_rollup_sequence(entries: &[RollupEntry], expected_hash: &[u8]) -> bool {
    let computed = recompute_rollup_hash(entries);
    constant_time_eq::constant_time_eq(&computed, expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollup_creation() {
        init_rollup_subsystem();
        let rollup = ReceiptRollup::new();
        assert_eq!(rollup.current_hash(), [0u8; 32]);
        assert!(rollup.is_empty());
    }

    #[test]
    fn test_rollup_update() -> Result<(), DsmError> {
        let mut rollup = ReceiptRollup::new();
        let initial_hash = rollup.current_hash();

        update_rollup(&mut rollup, b"receipt1", &[1; 32], "peer1", 1)?;

        assert_ne!(rollup.current_hash(), initial_hash);
        assert_eq!(rollup.len(), 1);

        Ok(())
    }

    #[test]
    fn test_rollup_verification() -> Result<(), DsmError> {
        let mut rollup = ReceiptRollup::new();

        update_rollup(&mut rollup, b"receipt1", &[1; 32], "peer1", 1)?;

        let current_hash = rollup.current_hash();
        assert!(verify_rollup(&rollup, &current_hash));

        // Wrong hash should fail
        assert!(!verify_rollup(&rollup, &[2; 32]));

        Ok(())
    }

    #[test]
    fn test_rollup_sequence_verification() -> Result<(), DsmError> {
        let mut rollup = ReceiptRollup::new();

        // Add multiple entries
        update_rollup(&mut rollup, b"r1", &[1; 32], "p1", 1)?;
        update_rollup(&mut rollup, b"r2", &[2; 32], "p2", 2)?;
        update_rollup(&mut rollup, b"r3", &[3; 32], "p1", 3)?;

        let entries = rollup.entries();
        let expected_hash = rollup.current_hash();

        assert!(verify_rollup_sequence(entries, &expected_hash));

        Ok(())
    }

    #[test]
    fn test_peer_digest() {
        let digest1 = create_peer_digest("peer1");
        let digest2 = create_peer_digest("peer2");
        let digest1_again = create_peer_digest("peer1");

        assert_eq!(digest1.len(), 8);
        assert_eq!(digest2.len(), 8);
        assert_ne!(digest1, digest2);
        assert_eq!(digest1, digest1_again);
    }
}
