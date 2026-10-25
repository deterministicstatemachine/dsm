// SPDX-License-Identifier: MIT OR Apache-2.0
//! Classical signature verification for the offline anchor's chip witness.
//!
//! The anchor's TROPIC01 chip signs each root advance with its resident Ed25519
//! key (`σ^chip`), and a receiver verifies it under the `pk_chip` the anchor's
//! bundle pins. DSM's own protocol signatures remain SPHINCS+; nothing here signs,
//! and nothing here touches DSM key material.

use crate::types::error::DsmError;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

/// Verify a raw 64-byte Ed25519 signature over `message` under a raw 32-byte public
/// key: the chip's `σ^chip`. Strict verification rejects non-canonical inputs.
pub fn verify_ed25519(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), DsmError> {
    let verifying_key = Ed25519VerifyingKey::from_bytes(pubkey)
        .map_err(|_| DsmError::verification("attestation: malformed Ed25519 public key"))?;
    let sig = Ed25519Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| DsmError::verification("attestation: Ed25519 signature did not verify"))
}
