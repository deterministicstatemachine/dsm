// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery succession proof (spec §0.5 — bilateral re-establish transport).
//!
//! A [`RecoverySuccessionProof`] is the minimal artifact A_new posts so a counterparty C can
//! run its re-establish accept-guard ([`crate::recovery::verify_recovery_reestablish_request`])
//! BEFORE co-signing the new `(A_new,C)` first state: the recovery authority public key
//! (`K_A_pub`) plus the tombstone/succession pair proving A_new succeeds A_old.
//!
//! Distinct from [`crate::recovery::RecoveryBundle`], which ALSO carries the
//! [`crate::recovery::RecoveryActivationSeal`] — that seal is produced only AFTER every
//! re-establish completes (it commits the per-counterparty evidence root), so it is not yet
//! available at re-establish time. This proof carries strictly the pre-co-sign authorization.
//!
//! Authority binding is NOT self-certifying: C must genesis-anchor `authority_pubkey` against
//! A_new's [`crate::recovery::RecoveryAuthorityAnchor`] before trusting the receipt signatures.
//! The proof is availability-only (storage carries it; the receiver verifies everything).
//!
//! Wire: a protobuf container of nested canonical sub-object encodings. Protobuf-only,
//! fail-closed decode.

use crate::recovery::tombstone::{SuccessionReceipt, TombstoneReceipt};
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, RecoverySuccessionProofV1};

/// The pre-co-sign recovery succession artifacts a counterparty needs to accept a
/// bilateral re-establish (§0.5).
#[derive(Clone, Debug)]
pub struct RecoverySuccessionProof {
    /// The recovery authority public key (`K_A_pub`). The receiver binds it to A_new's
    /// [`crate::recovery::RecoveryAuthorityAnchor`] before trusting the receipts below.
    pub authority_pubkey: Vec<u8>,
    pub tombstone: TombstoneReceipt,
    pub succession: SuccessionReceipt,
}

impl RecoverySuccessionProof {
    /// Serialize to canonical protobuf bytes (nested sub-object encodings).
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoverySuccessionProofV1 {
            authority_pubkey: self.authority_pubkey.clone(),
            tombstone: self.tombstone.to_bytes(),
            succession: self.succession.to_bytes(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed: every nested sub-object must decode and
    /// the authority pubkey must be non-empty).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RecoverySuccessionProofV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RecoverySuccessionProof::from_bytes: {e}"),
                "RecoverySuccessionProof",
                None::<String>,
                Some(e),
            )
        })?;
        if p.authority_pubkey.is_empty() {
            return Err(DsmError::verification(
                "RecoverySuccessionProof: empty authority_pubkey",
            ));
        }
        Ok(Self {
            authority_pubkey: p.authority_pubkey,
            tombstone: TombstoneReceipt::from_bytes(&p.tombstone)?,
            succession: SuccessionReceipt::from_bytes(&p.succession)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::recovery::tombstone::{create_succession, create_tombstone};

    fn sample_proof() -> (RecoverySuccessionProof, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x37; 32]).expect("kp");
        let device_id = "DEV_SUCC_PROOF";
        let tombstone =
            create_tombstone(&[0x11; 32], 0, &[0x22; 32], device_id, &kp.secret_key).expect("t");
        let succession = create_succession(
            &tombstone.tombstone_hash,
            &[0xBB; 32].to_vec(),
            device_id,
            &kp.secret_key,
        )
        .expect("s");
        let proof = RecoverySuccessionProof {
            authority_pubkey: kp.public_key.clone(),
            tombstone,
            succession,
        };
        (proof, kp.public_key.clone())
    }

    #[test]
    fn proof_round_trips() {
        let (proof, _pk) = sample_proof();
        let decoded = RecoverySuccessionProof::from_bytes(&proof.to_bytes()).expect("decode");
        assert_eq!(decoded.authority_pubkey, proof.authority_pubkey);
        assert_eq!(
            decoded.tombstone.tombstone_hash,
            proof.tombstone.tombstone_hash
        );
        assert_eq!(decoded.tombstone.signature, proof.tombstone.signature);
        assert_eq!(
            decoded.succession.succession_hash,
            proof.succession.succession_hash
        );
        assert_eq!(decoded.succession.signature, proof.succession.signature);
        // Re-encode is byte-identical (canonical).
        assert_eq!(proof.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn proof_rejects_empty_authority_pubkey() {
        let (proof, _pk) = sample_proof();
        let mut p = RecoverySuccessionProofV1::decode(proof.to_bytes().as_slice()).unwrap();
        p.authority_pubkey.clear();
        assert!(RecoverySuccessionProof::from_bytes(&p.encode_to_vec()).is_err());
    }

    #[test]
    fn proof_rejects_corrupt_nested_tombstone() {
        let (proof, _pk) = sample_proof();
        let mut p = RecoverySuccessionProofV1::decode(proof.to_bytes().as_slice()).unwrap();
        p.tombstone = vec![0xFF; 8]; // not a valid TombstoneReceiptProto
        assert!(RecoverySuccessionProof::from_bytes(&p.encode_to_vec()).is_err());
    }
}
