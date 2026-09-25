// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ML-KEM (Kyber) identity binding: a device's SPHINCS+ attestation key
//! (AK) signs
//!
//! ```text
//! domain_hash("DSM/kyber-identity-binding", device_id || genesis_hash || kyber_pk)
//! ```
//!
//! A verifier that already trusts the peer's AK (pinned from its self-proving
//! directory entry) checks this before relying on the Kyber key.

use crate::common::domain_tags::TAG_DSM_KYBER_IDENTITY_BINDING;
use crate::crypto::blake3::domain_hash;
use crate::crypto::{kyber, sphincs};
use crate::types::error::DsmError;

/// The digest a device's AK signs to bind `kyber_pubkey` to its identity.
pub fn binding_digest(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    kyber_pubkey: &[u8],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(64 + kyber_pubkey.len());
    preimage.extend_from_slice(device_id);
    preimage.extend_from_slice(genesis_hash);
    preimage.extend_from_slice(kyber_pubkey);
    *domain_hash(TAG_DSM_KYBER_IDENTITY_BINDING, &preimage).as_bytes()
}

/// A peer's Kyber key is bound to `(device_id, genesis_hash)` under the AK
/// `signing_public_key`. Missing, malformed or unbound material is refused.
pub fn verify_kyber_identity_binding(
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    kyber_pubkey: &[u8],
    binding_sig: &[u8],
    signing_public_key: &[u8],
) -> Result<(), DsmError> {
    if kyber_pubkey.is_empty() || binding_sig.is_empty() {
        return Err(DsmError::invalid_operation(
            "kyber identity binding: missing Kyber public key or binding signature (fail-closed)",
        ));
    }
    if kyber_pubkey.len() != kyber::public_key_bytes() {
        return Err(DsmError::invalid_operation(format!(
            "kyber identity binding: Kyber public key must be {} bytes (ML-KEM-768), got {}",
            kyber::public_key_bytes(),
            kyber_pubkey.len()
        )));
    }
    let digest = binding_digest(device_id, genesis_hash, kyber_pubkey);
    if !sphincs::sphincs_verify(signing_public_key, &digest, binding_sig)? {
        return Err(DsmError::invalid_operation(
            "kyber identity binding: signature does not bind this Kyber key to (device_id, genesis) \
             under the peer's AK — rejecting (possible substitution/equivocation)",
        ));
    }
    Ok(())
}
