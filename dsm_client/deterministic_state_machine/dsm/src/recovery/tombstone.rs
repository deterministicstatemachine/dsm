// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tombstone and Succession Receipt Implementation
//!
//! Implements self-anchored receipts for device recovery:
//! - Tombstone (TR): Invalidates old device binding
//! - Succession (SR): Binds new device with PQ signatures
//!
//! Both use SPHINCS+ signatures for post-quantum security. Neither carries a
//! time: a succession is bound to its tombstone by the tombstone's hash.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;
use crate::types::proto::{
    ContactTombstoneAckProto, Message as _, SuccessionReceiptProto, TombstoneReceiptProto,
};
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
    /// Compute tombstone hash: H(device_id || old_smt_root || old_counter || old_rollup_hash)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TOMBSTONE);
        hasher.update(self.device_id.as_bytes());
        hasher.update(&self.old_smt_root);
        hasher.update(&self.old_counter.to_le_bytes());
        hasher.update(&self.old_rollup_hash);
        *hasher.finalize().as_bytes()
    }

    /// Verify tombstone signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(public_key, &self.tombstone_hash, &self.signature)
    }

    /// Serialize the full receipt to protobuf bytes (canonical wire codec).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    /// Deserialize a receipt from protobuf bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let proto = TombstoneReceiptProto::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("TombstoneReceipt::from_bytes: {e}"),
                "TombstoneReceipt",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self::from_proto(proto))
    }

    fn to_proto(&self) -> TombstoneReceiptProto {
        TombstoneReceiptProto {
            device_id: self.device_id.clone(),
            old_smt_root: self.old_smt_root.clone(),
            old_counter: self.old_counter,
            old_rollup_hash: self.old_rollup_hash.clone(),
            signature: self.signature.clone(),
            tombstone_hash: self.tombstone_hash.clone(),
        }
    }

    fn from_proto(p: TombstoneReceiptProto) -> Self {
        Self {
            device_id: p.device_id,
            old_smt_root: p.old_smt_root,
            old_counter: p.old_counter,
            old_rollup_hash: p.old_rollup_hash,
            signature: p.signature,
            tombstone_hash: p.tombstone_hash,
        }
    }
}

impl SuccessionReceipt {
    /// Compute succession hash: H(device_id || tombstone_hash || new_device_commitment)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher =
            dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TOMBSTONE_SUCCESSION);
        hasher.update(self.device_id.as_bytes());
        hasher.update(&self.tombstone_hash);
        hasher.update(&self.new_device_commitment);
        *hasher.finalize().as_bytes()
    }
    /// Verify succession signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(public_key, &self.succession_hash, &self.signature)
    }

    /// Serialize to canonical protobuf bytes (mirrors `TombstoneReceipt::to_bytes`).
    pub fn to_bytes(&self) -> Vec<u8> {
        SuccessionReceiptProto {
            device_id: self.device_id.clone(),
            tombstone_hash: self.tombstone_hash.clone(),
            new_device_commitment: self.new_device_commitment.clone(),
            signature: self.signature.clone(),
            succession_hash: self.succession_hash.clone(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = SuccessionReceiptProto::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("SuccessionReceipt::from_bytes: {e}"),
                "SuccessionReceipt",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self {
            device_id: p.device_id,
            tombstone_hash: p.tombstone_hash,
            new_device_commitment: p.new_device_commitment,
            signature: p.signature,
            succession_hash: p.succession_hash,
        })
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
    let mut tombstone = TombstoneReceipt {
        device_id: device_id.to_string(),
        old_smt_root: old_smt_root.to_vec(),
        old_counter,
        old_rollup_hash: old_rollup_hash.to_vec(),
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
    let mut succession = SuccessionReceipt {
        device_id: device_id.to_string(),
        tombstone_hash: tombstone_hash.to_vec(),
        new_device_commitment: new_device_commitment.to_vec(),
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

    Ok(true)
}

/// A contact's acknowledgement that it recorded a device's tombstone: its AK's
/// signature over `H(DSM/recovery-ack; tombstone_hash ‖ acknowledging_device_id)`
/// (P4). A recovering device counts a contact as synced only on an
/// acknowledgement that verifies under that contact's AK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactTombstoneAck {
    pub tombstone_hash: [u8; 32],
    pub acknowledging_device_id: [u8; 32],
    pub signature: Vec<u8>,
}

impl ContactTombstoneAck {
    fn signing_digest(tombstone_hash: &[u8; 32], acknowledging_device_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_RECOVERY_ACK);
        hasher.update(tombstone_hash);
        hasher.update(acknowledging_device_id);
        *hasher.finalize().as_bytes()
    }

    /// The acknowledging device signs with its AK secret key.
    pub fn sign(
        tombstone_hash: [u8; 32],
        acknowledging_device_id: [u8; 32],
        secret_key: &[u8],
    ) -> Result<Self, DsmError> {
        let signature = sphincs_sign(
            secret_key,
            &Self::signing_digest(&tombstone_hash, &acknowledging_device_id),
        )?;
        Ok(Self {
            tombstone_hash,
            acknowledging_device_id,
            signature,
        })
    }

    /// Whether the acknowledgement verifies under `public_key`, the
    /// acknowledging device's AK.
    pub fn verify(&self, public_key: &[u8]) -> Result<(), DsmError> {
        let digest = Self::signing_digest(&self.tombstone_hash, &self.acknowledging_device_id);
        if sphincs_verify(public_key, &digest, &self.signature)? {
            Ok(())
        } else {
            Err(DsmError::verification(
                "contact tombstone acknowledgement does not verify under the contact's AK",
            ))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        ContactTombstoneAckProto {
            tombstone_hash: self.tombstone_hash.to_vec(),
            acknowledging_device_id: self.acknowledging_device_id.to_vec(),
            signature: self.signature.clone(),
        }
        .encode_to_vec()
    }

    /// Decode, refusing any field of the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let proto = ContactTombstoneAckProto::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("ContactTombstoneAck::from_bytes: {e}"),
                "ContactTombstoneAck",
                None::<String>,
                Some(e),
            )
        })?;
        let d32 = |bytes: Vec<u8>, what: &str| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|e| DsmError::verification(format!("contact tombstone ack: {what}: {e}")))
        };
        Ok(Self {
            tombstone_hash: d32(proto.tombstone_hash, "tombstone_hash")?,
            acknowledging_device_id: d32(proto.acknowledging_device_id, "device id")?,
            signature: proto.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An acknowledgement counts only under the acknowledging contact's own
    /// AK, for exactly the tombstone and device it names; its codec is exact.
    #[test]
    fn a_contact_tombstone_ack_verifies_only_as_signed() -> Result<(), DsmError> {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair()?;
        let (other_pk, ..) = crate::crypto::sphincs::generate_sphincs_keypair()?;
        let ack = ContactTombstoneAck::sign([0x11; 32], [0x22; 32], &sk)?;
        assert!(ack.verify(&pk).is_ok());
        assert!(ack.verify(&other_pk).is_err(), "another key's AK");
        let for_another_tombstone = ContactTombstoneAck {
            tombstone_hash: [0x12; 32],
            ..ack.clone()
        };
        assert!(for_another_tombstone.verify(&pk).is_err());
        let from_another_device = ContactTombstoneAck {
            acknowledging_device_id: [0x23; 32],
            ..ack.clone()
        };
        assert!(from_another_device.verify(&pk).is_err());
        assert_eq!(ContactTombstoneAck::from_bytes(&ack.to_bytes())?, ack);
        let short = ContactTombstoneAckProto {
            tombstone_hash: vec![0x11; 31],
            acknowledging_device_id: vec![0x22; 32],
            signature: ack.signature.clone(),
        }
        .encode_to_vec();
        assert!(ContactTombstoneAck::from_bytes(&short).is_err());
        Ok(())
    }

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

    #[test]
    fn test_tombstone_protobuf_roundtrip() -> Result<(), DsmError> {
        init_tombstone_subsystem();

        let old_smt_root = vec![7; 32];
        let old_rollup = vec![9; 32];
        let device_id = "device_round_trip";
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair()?;

        let original = create_tombstone(&old_smt_root, 123, &old_rollup, device_id, &sk)?;
        let bytes = original.to_bytes();
        let decoded = TombstoneReceipt::from_bytes(&bytes)?;

        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.old_smt_root, original.old_smt_root);
        assert_eq!(decoded.old_counter, original.old_counter);
        assert_eq!(decoded.old_rollup_hash, original.old_rollup_hash);
        assert_eq!(decoded.signature, original.signature);
        assert_eq!(decoded.tombstone_hash, original.tombstone_hash);
        assert!(verify_tombstone(&decoded, &pk)?);

        Ok(())
    }

    #[test]
    fn test_succession_protobuf_roundtrip() -> Result<(), DsmError> {
        init_tombstone_subsystem();
        let device_id = "device_succession_round_trip";
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair()?;
        let tombstone = create_tombstone(&[7; 32], 1, &[9; 32], device_id, &sk)?;
        let original = create_succession(
            &tombstone.tombstone_hash,
            [0xAB; 32].as_ref(),
            device_id,
            &sk,
        )?;

        let decoded = SuccessionReceipt::from_bytes(&original.to_bytes())?;
        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.tombstone_hash, original.tombstone_hash);
        assert_eq!(
            decoded.new_device_commitment,
            original.new_device_commitment
        );
        assert_eq!(decoded.signature, original.signature);
        assert_eq!(decoded.succession_hash, original.succession_hash);
        assert!(verify_succession(&decoded, &tombstone.tombstone_hash, &pk)?);
        // Re-encode is byte-identical (canonical).
        assert_eq!(original.to_bytes(), decoded.to_bytes());
        Ok(())
    }
}
