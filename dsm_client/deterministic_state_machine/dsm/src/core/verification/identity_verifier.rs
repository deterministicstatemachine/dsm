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
