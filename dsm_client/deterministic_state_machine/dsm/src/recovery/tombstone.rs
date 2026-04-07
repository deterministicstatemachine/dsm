//! Tombstone and Succession Receipt Implementation
//!
//! Implements self-anchored receipts for device recovery:
//! - Tombstone (TR): Invalidates old device binding
//! - Succession (SR): Binds new device with PQ signatures
//!
//! Both use SPHINCS+ signatures for post-quantum security, and logical time
//! comes from the deterministic BLAKE3 tick counter (no wall clock).

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;
use crate::utils::deterministic_time as dt;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

static TOMBSTONE_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the tombstone/succession subsystem
pub fn init_tombstone_subsystem() {
    if !TOMBSTONE_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        tracing::info!("Tombstone/succession subsystem initialized");
        TOMBSTONE_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

/// Tombstone receipt - invalidates old device binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneReceipt {
    /// Device ID being invalidated
    pub device_id: String,
    /// Old SMT root at time of invalidation (r⋆)
    pub old_smt_root: Vec<u8>,
    /// Old counter value (c⋆)
    pub old_counter: u64,
    /// Old rollup hash (Roll⋆)
    pub old_rollup_hash: Vec<u8>,
    /// Logical tick (monotone) of tombstone creation
    pub tick: u64,
    /// SPHINCS+ signature over tombstone data
    pub signature: Vec<u8>,
    /// Hash of this tombstone (for succession reference)
    pub tombstone_hash: Vec<u8>,
}

/// Succession receipt - binds new device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionReceipt {
    /// Device ID for new device
    pub device_id: String,
    /// Hash of the tombstone this succeeds
    pub tombstone_hash: Vec<u8>,
    /// New device binding commitment
    pub new_device_commitment: Vec<u8>,
    /// Logical tick (monotone) of succession creation
    pub tick: u64,
    /// SPHINCS+ signature over succession data
    pub signature: Vec<u8>,
    /// Hash of this succession receipt
    pub succession_hash: Vec<u8>,
}

/// Recovery receipt enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryReceipt {
    Tombstone(TombstoneReceipt),
    Succession(SuccessionReceipt),
}

impl TombstoneReceipt {
    /// Compute tombstone hash: H(device_id || old_smt_root || old_counter || old_rollup_hash || tick)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/tombstone");
        hasher.update(self.device_id.as_bytes());
        hasher.update(&self.old_smt_root);
        hasher.update(&self.old_counter.to_le_bytes());
        hasher.update(&self.old_rollup_hash);
        hasher.update(&self.tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify tombstone signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(public_key, &self.tombstone_hash, &self.signature)
    }

    /// Serialize the full receipt to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        bincode::serialize(self).map_err(|e| {
            DsmError::serialization_error(
                format!("TombstoneReceipt::to_bytes: {e}"),
                "TombstoneReceipt",
                None::<String>,
                None::<std::io::Error>,
            )
        })
    }

    /// Deserialize a receipt from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        bincode::deserialize(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("TombstoneReceipt::from_bytes: {e}"),
                "TombstoneReceipt",
                None::<String>,
                None::<std::io::Error>,
            )
        })
    }
}

impl SuccessionReceipt {
    /// Compute succession hash: H(device_id || tombstone_hash || new_device_commitment || tick)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/tombstone-succession");
        hasher.update(self.device_id.as_bytes());
        hasher.update(&self.tombstone_hash);
        hasher.update(&self.new_device_commitment);
        hasher.update(&self.tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
    /// Verify succession signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(public_key, &self.succession_hash, &self.signature)
    }
}

/// Create tombstone receipt
pub fn create_tombstone(
    old_smt_root: &[u8],
    old_counter: u64,
    old_rollup_hash: &[u8],
    device_id: &str,
    private_key: &[u8],
) -> Result<TombstoneReceipt, DsmError> {
    let tick = dt::tick_index();
    let mut tombstone = TombstoneReceipt {
        device_id: device_id.to_string(),
        old_smt_root: old_smt_root.to_vec(),
        old_counter,
        old_rollup_hash: old_rollup_hash.to_vec(),
        tick,
        signature: Vec::new(),
        tombstone_hash: Vec::new(),
    };
    tombstone.tombstone_hash = tombstone.compute_hash().to_vec();
    tombstone.signature = sphincs_sign(private_key, &tombstone.tombstone_hash)?;
    Ok(tombstone)
}

/// Verify tombstone receipt
pub fn verify_tombstone(tombstone: &TombstoneReceipt, public_key: &[u8]) -> Result<bool, DsmError> {
    if tombstone.tombstone_hash != tombstone.compute_hash().to_vec() {
        return Ok(false);
    }
    tombstone.verify_signature(public_key)
}

/// Create succession receipt
pub fn create_succession(
    tombstone_hash: &[u8],
    new_device_commitment: &[u8],
    device_id: &str,
    private_key: &[u8],
) -> Result<SuccessionReceipt, DsmError> {
    let tick = dt::tick_index();
    let mut succession = SuccessionReceipt {
        device_id: device_id.to_string(),
        tombstone_hash: tombstone_hash.to_vec(),
        new_device_commitment: new_device_commitment.to_vec(),
        tick,
        signature: Vec::new(),
        succession_hash: Vec::new(),
    };
    succession.succession_hash = succession.compute_hash().to_vec();
    succession.signature = sphincs_sign(private_key, &succession.succession_hash)?;
    Ok(succession)
}

/// Verify succession receipt
pub fn verify_succession(
    succession: &SuccessionReceipt,
    tombstone_hash: &[u8],
    public_key: &[u8],
) -> Result<bool, DsmError> {
    if succession.tombstone_hash != tombstone_hash {
        return Ok(false);
    }
    if succession.succession_hash != succession.compute_hash().to_vec() {
        return Ok(false);
    }
    succession.verify_signature(public_key)
}

/// Verify tombstone-succession pair for recovery
pub fn verify_recovery_pair(
    tombstone: &TombstoneReceipt,
    succession: &SuccessionReceipt,
    public_key: &[u8],
) -> Result<bool, DsmError> {
    // Verify tombstone
    if !verify_tombstone(tombstone, public_key)? {
        return Ok(false);
    }

    // Verify succession references tombstone
    if !verify_succession(succession, &tombstone.tombstone_hash, public_key)? {
        return Ok(false);
    }

    // Verify same device ID
    if tombstone.device_id != succession.device_id {
        return Ok(false);
    }

    // Verify succession was created after tombstone (monotone tick ordering)
    if succession.tick <= tombstone.tick {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tombstone_creation() -> Result<(), DsmError> {
        init_tombstone_subsystem();

        let old_smt_root = vec![1; 32];
        let old_counter = 42u64;
        let old_rollup = vec![2; 32];
        let device_id = "test_device";
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair()?;

        let tombstone = create_tombstone(&old_smt_root, old_counter, &old_rollup, device_id, &sk)?;
        assert!(verify_tombstone(&tombstone, &pk)?);
        assert_eq!(tombstone.device_id, device_id);

        Ok(())
    }
}
