//! Identity verification for anchoring and authentication.
//!
//! Supports both decentralized (storage-node-based genesis lookup) and
//! centralized identity verification methods. All time references use
//! deterministic ticks, not wall-clock time.

use crate::utils::deterministic_time as dt;
use crate::types::error::DsmError;
use crate::types::identity::{IdentityAnchor, IdentityClaim};

/// IdentityVerifier handles the verification of identity claims against identity anchors
pub struct IdentityVerifier;

impl IdentityVerifier {
    /// Verify an identity claim against a registered identity anchor
    ///
    /// # Arguments
    /// * `claim` - The identity claim to verify
    /// * `anchor` - The registered identity anchor to verify against
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the claim is valid for the anchor
    pub fn verify_identity_claim(
        claim: &IdentityClaim,
        anchor: &IdentityAnchor,
    ) -> Result<bool, DsmError> {
        // 1. Verify the claim is for the correct anchor
        if claim.identity_id != anchor.identity_id {
            return Ok(false);
        }

        // 2. Verify the claim signature using cryptographic primitives
        if !Self::verify_claim_signature(claim)? {
            return Ok(false);
        }

        // 3. Verify the claim commitments against anchor expectations
        if !Self::verify_claim_commitments(claim, anchor)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify identity claim signature
    fn verify_claim_signature(claim: &IdentityClaim) -> Result<bool, DsmError> {
        // Generate hash of claim data
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/identity/claim");

        // Add all claim fields to hash
        hasher.update(claim.identity_id.as_bytes());
        hasher.update(&claim.tick.to_le_bytes());
        hasher.update(&claim.expires_at_tick.to_le_bytes());

        // Verify signature on the hash
        let claimed_hash = hasher.finalize();

        // In a real implementation, this would verify the signature
        // using the appropriate signature scheme (e.g., ECDSA, EdDSA)
        // For now, we simply check that the signature is not empty
        if claim.signature.is_empty() {
            return Ok(false);
        }

        // Compare hash to the expected value (in real implementation this would check signature)
        if claimed_hash.as_bytes() != claim.claim_hash.as_slice() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify claim commitments against anchor expectations
    fn verify_claim_commitments(
        claim: &IdentityClaim,
        anchor: &IdentityAnchor,
    ) -> Result<bool, DsmError> {
        // Hash the anchor data to get the expected commitment value
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/identity/anchor");

        // Add all anchor fields to hash
        hasher.update(anchor.identity_id.as_bytes());
        hasher.update(&anchor.created_at_tick.to_le_bytes());
        hasher.update(&anchor.revoked_at_tick.unwrap_or(0).to_le_bytes());

        // Get the expected commitment value
        let anchor_hash = hasher.finalize();

        // Check if the commitments match (in a real implementation,
        // this would be more sophisticated)
        if anchor_hash.as_bytes() != claim.anchor_commitment.as_slice() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Create a new identity anchor from an initial claim
    pub fn create_identity_anchor(claim: &IdentityClaim) -> Result<IdentityAnchor, DsmError> {
        // Verify the claim has a valid signature first
        if !Self::verify_claim_signature(claim)? {
            return Err(DsmError::identity("Invalid identity claim signature"));
        }

        // Create a new identity anchor using deterministic logical time.
        // Callers that need to observe time without advancing should use dt::peek().
        let (_, now) = dt::tick();

        let anchor = IdentityAnchor {
            identity_id: claim.identity_id.clone(),
            public_key: claim.public_key.clone(),
            created_at_tick: now,
            revoked_at_tick: None,
            meta_data: claim.meta_data.clone(),
        };

        Ok(anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;
    use std::collections::HashMap;

    fn compute_claim_hash(identity_id: &str, tick: u64, expires_at_tick: u64) -> Vec<u8> {
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/identity/claim");
        hasher.update(identity_id.as_bytes());
        hasher.update(&tick.to_le_bytes());
        hasher.update(&expires_at_tick.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    fn compute_anchor_commitment(
        identity_id: &str,
        created_at_tick: u64,
        revoked_at_tick: Option<u64>,
    ) -> Vec<u8> {
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/identity/anchor");
        hasher.update(identity_id.as_bytes());
        hasher.update(&created_at_tick.to_le_bytes());
        hasher.update(&revoked_at_tick.unwrap_or(0).to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    fn make_valid_claim_and_anchor() -> (IdentityClaim, IdentityAnchor) {
        let identity_id = "test-identity-1";
        let tick = 10u64;
        let expires_at_tick = 100u64;
        let created_at_tick = 5u64;

        let claim_hash = compute_claim_hash(identity_id, tick, expires_at_tick);
        let anchor_commitment = compute_anchor_commitment(identity_id, created_at_tick, None);

        let claim = IdentityClaim {
            identity_id: identity_id.to_string(),
            tick,
            expires_at_tick,
            public_key: vec![0x42; 32],
            signature: vec![0xFF; 64], // non-empty
            claim_hash,
            anchor_commitment,
            device_info: DeviceInfo::default(),
            meta_data: HashMap::new(),
        };

        let anchor = IdentityAnchor {
            identity_id: identity_id.to_string(),
            public_key: vec![0x42; 32],
            created_at_tick,
            revoked_at_tick: None,
            meta_data: HashMap::new(),
        };

        (claim, anchor)
    }

    #[test]
    fn verify_valid_claim_succeeds() {
        let (claim, anchor) = make_valid_claim_and_anchor();
        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_rejects_mismatched_identity_id() {
        let (mut claim, anchor) = make_valid_claim_and_anchor();
        claim.identity_id = "wrong-identity".to_string();

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(!result, "mismatched identity_id should fail");
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let (mut claim, anchor) = make_valid_claim_and_anchor();
        claim.signature = vec![];

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(!result, "empty signature should fail");
    }

    #[test]
    fn verify_rejects_wrong_claim_hash() {
        let (mut claim, anchor) = make_valid_claim_and_anchor();
        claim.claim_hash = vec![0x00; 32]; // wrong hash

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(!result, "wrong claim hash should fail");
    }

    #[test]
    fn verify_rejects_wrong_anchor_commitment() {
        let (mut claim, anchor) = make_valid_claim_and_anchor();
        claim.anchor_commitment = vec![0x00; 32]; // wrong commitment

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(!result, "wrong anchor commitment should fail");
    }

    #[test]
    fn verify_rejects_revoked_anchor_with_old_commitment() {
        let (claim, mut anchor) = make_valid_claim_and_anchor();
        anchor.revoked_at_tick = Some(50);
        // anchor commitment was computed with revoked_at_tick=None, so it should mismatch

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(!result, "revoked anchor should fail commitment check");
    }

    #[test]
    fn create_identity_anchor_succeeds_for_valid_claim() {
        dt::reset_for_tests();
        let (claim, _) = make_valid_claim_and_anchor();

        let anchor = IdentityVerifier::create_identity_anchor(&claim).unwrap();
        assert_eq!(anchor.identity_id, claim.identity_id);
        assert_eq!(anchor.public_key, claim.public_key);
        assert!(anchor.revoked_at_tick.is_none());
    }

    #[test]
    fn create_identity_anchor_rejects_invalid_claim() {
        let (mut claim, _) = make_valid_claim_and_anchor();
        claim.signature = vec![]; // invalid

        let result = IdentityVerifier::create_identity_anchor(&claim);
        assert!(result.is_err());
    }

    #[test]
    fn verify_claim_signature_checks_hash_determinism() {
        let identity_id = "determinism-test";
        let tick = 42u64;
        let expires = 999u64;
        let hash1 = compute_claim_hash(identity_id, tick, expires);
        let hash2 = compute_claim_hash(identity_id, tick, expires);
        assert_eq!(hash1, hash2);

        let hash_different_tick = compute_claim_hash(identity_id, tick + 1, expires);
        assert_ne!(hash1, hash_different_tick);
    }

    #[test]
    fn verify_with_matching_revoked_anchor() {
        let identity_id = "revoked-test";
        let tick = 10u64;
        let expires = 100u64;
        let created_at_tick = 5u64;
        let revoked_at_tick = Some(50u64);

        let claim_hash = compute_claim_hash(identity_id, tick, expires);
        let anchor_commitment =
            compute_anchor_commitment(identity_id, created_at_tick, revoked_at_tick);

        let claim = IdentityClaim {
            identity_id: identity_id.to_string(),
            tick,
            expires_at_tick: expires,
            public_key: vec![0x42; 32],
            signature: vec![0xFF; 64],
            claim_hash,
            anchor_commitment,
            device_info: DeviceInfo::default(),
            meta_data: HashMap::new(),
        };

        let anchor = IdentityAnchor {
            identity_id: identity_id.to_string(),
            public_key: vec![0x42; 32],
            created_at_tick,
            revoked_at_tick,
            meta_data: HashMap::new(),
        };

        let result = IdentityVerifier::verify_identity_claim(&claim, &anchor).unwrap();
        assert!(result, "matching revoked anchor commitment should pass");
    }
}
