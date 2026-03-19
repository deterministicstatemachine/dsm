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
use crate::util::deterministic_time as dt;
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
        // Verify SPHINCS+ signature over the tombstone hash using the default variant
        sphincs_verify(public_key, &self.tombstone_hash, &self.signature)
    }

    /// Encode tombstone receipt to canonical bytes.
    ///
    /// Format: `[device_id_len:u32 BE][device_id][old_smt_root_len:u32 BE][old_smt_root]`
    ///         `[old_counter:u64 LE][old_rollup_hash_len:u32 BE][old_rollup_hash]`
    ///         `[tick:u64 LE][sig_len:u32 BE][signature][hash_len:u32 BE][tombstone_hash]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::encode_field(&mut buf, self.device_id.as_bytes());
        Self::encode_field(&mut buf, &self.old_smt_root);
        buf.extend_from_slice(&self.old_counter.to_le_bytes());
        Self::encode_field(&mut buf, &self.old_rollup_hash);
        buf.extend_from_slice(&self.tick.to_le_bytes());
        Self::encode_field(&mut buf, &self.signature);
        Self::encode_field(&mut buf, &self.tombstone_hash);
        buf
    }

    /// Decode tombstone receipt from canonical bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        let mut pos = 0;
        let device_id_bytes = Self::decode_field(data, &mut pos)?;
        let device_id = String::from_utf8(device_id_bytes).map_err(|e| {
            DsmError::serialization_error(
                "Invalid UTF-8 in device_id",
                "tombstone",
                None::<&str>,
                Some(e),
            )
        })?;
        let old_smt_root = Self::decode_field(data, &mut pos)?;
        if pos + 8 > data.len() {
            return Err(DsmError::serialization_error(
                "Truncated old_counter",
                "tombstone",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        let old_counter = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default());
        pos += 8;
        let old_rollup_hash = Self::decode_field(data, &mut pos)?;
        if pos + 8 > data.len() {
            return Err(DsmError::serialization_error(
                "Truncated tick",
                "tombstone",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        let tick = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default());
        pos += 8;
        let signature = Self::decode_field(data, &mut pos)?;
        let tombstone_hash = Self::decode_field(data, &mut pos)?;

        Ok(Self {
            device_id,
            old_smt_root,
            old_counter,
            old_rollup_hash,
            tick,
            signature,
            tombstone_hash,
        })
    }

    fn encode_field(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    fn decode_field(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, DsmError> {
        if *pos + 4 > data.len() {
            return Err(DsmError::serialization_error(
                "Truncated field length",
                "tombstone",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        let len = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap_or_default()) as usize;
        *pos += 4;
        if *pos + len > data.len() {
            return Err(DsmError::serialization_error(
                "Truncated field data",
                "tombstone",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        let field = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(field)
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
        // Verify SPHINCS+ signature over the succession hash using the default variant
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
    // Deterministic logical time (hash ignored, tick used)
    let (_, tick) = dt::peek();

    let mut tombstone = TombstoneReceipt {
        device_id: device_id.to_string(),
        old_smt_root: old_smt_root.to_vec(),
        old_counter,
        old_rollup_hash: old_rollup_hash.to_vec(),
        tick,
        signature: Vec::new(),
        tombstone_hash: Vec::new(),
    };

    // Compute hash
    tombstone.tombstone_hash = tombstone.compute_hash().to_vec();

    // Sign with SPHINCS+ using the default variant
    tombstone.signature = sphincs_sign(private_key, &tombstone.tombstone_hash)?;

    Ok(tombstone)
}

/// Create succession receipt
pub fn create_succession(
    tombstone_hash: &[u8],
    new_device_commitment: &[u8],
    device_id: &str,
    private_key: &[u8],
) -> Result<SuccessionReceipt, DsmError> {
    // Deterministic logical time (hash ignored, tick used)
    let (_, tick) = dt::peek();

    let mut succession = SuccessionReceipt {
        device_id: device_id.to_string(),
        tombstone_hash: tombstone_hash.to_vec(),
        new_device_commitment: new_device_commitment.to_vec(),
        tick,
        signature: Vec::new(),
        succession_hash: Vec::new(),
    };

    // Compute hash
    succession.succession_hash = succession.compute_hash().to_vec();

    // Sign with SPHINCS+ using the default variant
    succession.signature = sphincs_sign(private_key, &succession.succession_hash)?;

    Ok(succession)
}

/// Verify tombstone receipt
pub fn verify_tombstone(tombstone: &TombstoneReceipt, public_key: &[u8]) -> Result<bool, DsmError> {
    // Verify hash integrity
    let computed_hash = tombstone.compute_hash();
    if !constant_time_eq::constant_time_eq(&computed_hash, &tombstone.tombstone_hash) {
        return Ok(false);
    }

    // Verify signature
    tombstone.verify_signature(public_key)
}

/// Verify succession receipt
pub fn verify_succession(
    succession: &SuccessionReceipt,
    tombstone_hash: &[u8],
    public_key: &[u8],
) -> Result<bool, DsmError> {
    // Verify succession references correct tombstone
    if !constant_time_eq::constant_time_eq(&succession.tombstone_hash, tombstone_hash) {
        return Ok(false);
    }

    // Verify hash integrity
    let computed_hash = succession.compute_hash();
    if !constant_time_eq::constant_time_eq(&computed_hash, &succession.succession_hash) {
        return Ok(false);
    }

    // Verify signature
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

        // Mock private key (in real implementation, this would be a proper SPHINCS+ key)
        let private_key = vec![3; 128];

        let tombstone = create_tombstone(
            &old_smt_root,
            old_counter,
            &old_rollup,
            device_id,
            &private_key,
        )?;

        assert_eq!(tombstone.device_id, device_id);
        assert_eq!(tombstone.old_smt_root, old_smt_root);
        assert_eq!(tombstone.old_counter, old_counter);
        assert!(!tombstone.signature.is_empty());
        assert!(!tombstone.tombstone_hash.is_empty());

        Ok(())
    }

    #[test]
    fn test_succession_creation() -> Result<(), DsmError> {
        let tombstone_hash = vec![1; 32];
        let new_commitment = vec![2; 32];
        let device_id = "test_device";
        let private_key = vec![3; 128];

        let succession =
            create_succession(&tombstone_hash, &new_commitment, device_id, &private_key)?;

        assert_eq!(succession.device_id, device_id);
        assert_eq!(succession.tombstone_hash, tombstone_hash);
        assert_eq!(succession.new_device_commitment, new_commitment);
        assert!(!succession.signature.is_empty());

        Ok(())
    }

    #[test]
    fn test_hash_integrity() -> Result<(), DsmError> {
        let old_smt_root = vec![1; 32];
        let old_counter = 42u64;
        let old_rollup = vec![2; 32];
        let device_id = "test_device";
        let private_key = vec![3; 128];

        let tombstone = create_tombstone(
            &old_smt_root,
            old_counter,
            &old_rollup,
            device_id,
            &private_key,
        )?;

        // Hash should be reproducible
        let hash1 = tombstone.compute_hash();
        let hash2 = tombstone.compute_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.to_vec(), tombstone.tombstone_hash);

        Ok(())
    }
}
