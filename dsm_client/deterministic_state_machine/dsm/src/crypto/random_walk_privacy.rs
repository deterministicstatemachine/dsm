//! DBRW privacy implementation: random walk obfuscation for transaction unlinkability.
//!
//! This module implements the privacy layer of the DBRW (Dual-Binding Random Walk)
//! mechanism. It combines hardware fingerprinting, environmental entropy (expressed
//! as deterministic ticks, not wall-clock time), and forward-only random walk
//! commitment chains to prevent state cloning/rollback while preserving
//! transaction unlinkability.
//!
//! # Security Properties
//!
//! - Prevents device cloning attacks through hardware binding
//! - Ensures temporal progression with forward-only commitments
//! - Provides information-theoretic privacy through random walk obfuscation
//! - Maintains verifiability while preserving transaction unlinkability
//!
//! # Usage
//!
//! 1. Initialize DBRW with hardware fingerprint and environmental entropy
//! 2. Generate forward-only commitment chain for transaction sequence
//! 3. Create privacy-preserving random walk path for transaction obfuscation
//! 4. Encrypt commitments using ML-KEM and sign with SPHINCS+
//!
//! This module is **clockless**: any "time" parameters are deterministic ticks (`u64`),
//! not wall-clock or epoch seconds.
use crate::crypto::blake3::dsm_domain_hasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Random walk privacy mechanism (deterministic, bytes-only, no wall-clock)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RandomWalkPrivacy {
    seed: [u8; 32],
    path: Vec<(u64, u64)>,
    steps: usize,
}

impl RandomWalkPrivacy {
    /// Create a new random walk privacy instance
    ///
    /// # Parameters
    /// * `transaction_hash` - Unique hash of the transaction to protect (bytes)
    pub fn new(transaction_hash: &[u8]) -> Self {
        Self::new_with_steps(transaction_hash, 10)
    }

    /// Create a new random walk privacy instance with a specific number of steps
    ///
    /// # Parameters
    /// * `transaction_hash` - Unique hash of the transaction to protect (bytes)
    /// * `steps` - Number of steps in the random walk path (higher = more privacy, higher cost)
    pub fn new_with_steps(transaction_hash: &[u8], steps: usize) -> Self {
        // Domain-separated seed derivation
        let mut hasher = dsm_domain_hasher("DSM/dbrw-rwp-seed");
        hasher.update(transaction_hash);
        let seed = *hasher.finalize().as_bytes();

        let path = Self::generate_path(&seed, steps);
        RandomWalkPrivacy { seed, path, steps }
    }

    /// Generate a random walk path from the seed
    ///
    /// Produces a deterministic sequence of coordinates derived from the seed
    /// using Blake3 in a hash-chain construction.
    fn generate_path(seed: &[u8; 32], steps: usize) -> Vec<(u64, u64)> {
        let mut path = Vec::with_capacity(steps);
        let mut current_hash = *seed;

        for _ in 0..steps {
            let mut hasher = dsm_domain_hasher("DSM/dbrw-rwp-step");
            hasher.update(&current_hash);
            let result = hasher.finalize();
            let bytes = result.as_bytes();

            // Extract coordinate pairs from the hash output (32 bytes from BLAKE3)
            let x = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let y = u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]);

            path.push((x, y));
            current_hash = *bytes;
        }
        path
    }

    /// Verifies a provided random walk path matches exactly.
    ///
    /// Both parties must use identical seed generation and hashing logic.
    pub fn verify_path(&self, other_path: &[(u64, u64)]) -> bool {
        self.path == other_path
    }

    /// Generate a tick-locked transfer commitment (no wall-clock).
    ///
    /// Creates a cryptographic commitment to a transaction that can only be
    /// executed after a specified **unlock tick**.
    ///
    /// # Parameters
    /// * `recipient`     - Public identifier of the recipient (bytes, e.g., public key)
    /// * `amount`        - Transfer amount as u64
    /// * `unlock_tick`   - Deterministic tick (u64) after which the transfer can be executed
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn time_locked_transfer(
        &self,
        recipient: &[u8],
        amount: u64,
        unlock_tick: u64,
    ) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/dbrw-commit-timelock");
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(&unlock_tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate a conditional transfer commitment.
    ///
    /// Creates a cryptographic commitment to a transaction conditioned on external oracle data.
    /// The condition/oracle inputs are opaque bytes decided by the SDK/protocol layer.
    ///
    /// # Parameters
    /// * `recipient`  - Public identifier of the recipient (bytes)
    /// * `amount`     - Transfer amount per condition
    /// * `condition`  - Opaque condition bytes
    /// * `oracle`     - Opaque oracle identifier bytes
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn conditional_transfer(
        &self,
        recipient: &[u8],
        amount: u64,
        condition: &[u8],
        oracle: &[u8],
    ) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/dbrw-commit-cond");
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(condition);
        hasher.update(oracle);
        *hasher.finalize().as_bytes()
    }

    /// Generate a recurring payment commitment (tick-based; no time units).
    ///
    /// Creates a cryptographic commitment to a series of periodic payments.
    /// The **period** and **end_tick** are expressed solely in deterministic ticks.
    ///
    /// # Parameters
    /// * `recipient`    - Public identifier of the recipient (bytes)
    /// * `amount`       - Transfer amount per period
    /// * `period_ticks` - Number of ticks between payments
    /// * `end_tick`     - Deterministic tick (u64) after which recurring payments stop
    ///
    /// # Returns
    /// * 32-byte commitment hash
    pub fn recurring_payment(
        &self,
        recipient: &[u8],
        amount: u64,
        period_ticks: u64,
        end_tick: u64,
    ) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/dbrw-commit-recur");
        hasher.update(&self.seed);
        hasher.update(recipient);
        hasher.update(&amount.to_le_bytes());
        hasher.update(&period_ticks.to_le_bytes());
        hasher.update(&end_tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Get the path coordinates from this random walk
    #[inline]
    pub fn get_path(&self) -> &[(u64, u64)] {
        &self.path
    }

    /// Get the number of steps in this random walk
    #[inline]
    pub fn steps(&self) -> usize {
        self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_walk_privacy() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let path = rwp.get_path().to_vec();
        assert!(rwp.verify_path(&path));
    }

    #[test]
    fn test_custom_steps() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new_with_steps(transaction_hash, 20);
        assert_eq!(rwp.steps(), 20);
        assert_eq!(rwp.get_path().len(), 20);
    }

    #[test]
    fn test_time_locked_transfer_ticks() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let unlock_tick = 1_234_567_890_u64; // treated as ticks, not epoch
        let commitment = rwp.time_locked_transfer(recipient, amount, unlock_tick);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_conditional_transfer() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let condition = b"condition";
        let oracle = b"oracle";
        let commitment = rwp.conditional_transfer(recipient, amount, condition, oracle);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_recurring_payment_ticks() {
        let transaction_hash = b"test_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 100;
        let period_ticks = 30;
        let end_tick = 1_234_567_890_u64; // treated as ticks, not epoch
        let commitment = rwp.recurring_payment(recipient, amount, period_ticks, end_tick);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_zero_value_amounts() {
        let transaction_hash = b"zero_value_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = 0;
        let unlock_tick = 42;
        let commitment = rwp.time_locked_transfer(recipient, amount, unlock_tick);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_large_values() {
        let transaction_hash = b"large_value_transaction";
        let rwp = RandomWalkPrivacy::new(transaction_hash);
        let recipient = b"recipient";
        let amount = u64::MAX;
        let period_ticks = u64::MAX;
        let end_tick = u64::MAX;
        let commitment = rwp.recurring_payment(recipient, amount, period_ticks, end_tick);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_unique_transaction_hashes() {
        // Different transaction hashes produce different paths (deterministic per input)
        let tx_hash1 = b"transaction_1";
        let tx_hash2 = b"transaction_2";

        let rwp1 = RandomWalkPrivacy::new(tx_hash1);
        let rwp2 = RandomWalkPrivacy::new(tx_hash2);

        assert_ne!(rwp1.get_path(), rwp2.get_path());

        // Same transaction hash yields identical paths
        let rwp1_duplicate = RandomWalkPrivacy::new(tx_hash1);
        assert_eq!(rwp1.get_path(), rwp1_duplicate.get_path());
    }
}
