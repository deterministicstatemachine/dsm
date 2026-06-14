// SPDX-License-Identifier: MIT OR Apache-2.0
//! Classical signature verification for EXTERNAL secure-element device attestation.
//!
//! This is the deliberately scoped classical exception from the anti-clone
//! attestation specification (`.github/instructions/dsm_anticlone.instructions.md`,
//! section 9.2). It verifies signatures produced by an external hardware secure
//! element (a Trezor Safe 7), whose attestation keys are classical: Ed25519 for the
//! TROPIC01 leg and ECDSA P-256 with SHA-256 for the OPTIGA leg. DSM's own protocol
//! signatures remain SPHINCS+; nothing here signs, and nothing here touches DSM key
//! material. The module exists only to check that an offline-bearer transition was
//! approved by a pinned hardware island the owner cannot rewrite.

use crate::types::error::DsmError;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;

/// Fixed-format Ed25519 SubjectPublicKeyInfo prefix (RFC 8410); the 32-byte raw key
/// follows immediately, for a total SPKI length of 44 bytes.
const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Extract the raw 32-byte Ed25519 public key from a SubjectPublicKeyInfo DER.
pub fn ed25519_pubkey_from_spki(spki_der: &[u8]) -> Result<[u8; 32], DsmError> {
    if spki_der.len() != ED25519_SPKI_PREFIX.len() + 32
        || spki_der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
    {
        return Err(DsmError::verification(
            "attestation: not a well-formed Ed25519 SubjectPublicKeyInfo",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&spki_der[ED25519_SPKI_PREFIX.len()..]);
    Ok(key)
}

/// Verify a raw 64-byte Ed25519 signature over `message` under a raw 32-byte public
/// key. Used for the TROPIC01 leg. Strict verification rejects non-canonical inputs.
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

/// Verify an ECDSA P-256 (SHA-256) signature in DER form over `message` under a
/// SubjectPublicKeyInfo (DER). Used for the OPTIGA leg and for issuer certificate
/// signatures whose public key is presented as SPKI.
pub fn verify_ecdsa_p256_sha256(
    spki_der: &[u8],
    message: &[u8],
    der_signature: &[u8],
) -> Result<(), DsmError> {
    let verifying_key = P256VerifyingKey::from_public_key_der(spki_der).map_err(|_| {
        DsmError::verification("attestation: malformed P-256 SubjectPublicKeyInfo")
    })?;
    verify_ecdsa_p256_sha256_inner(&verifying_key, message, der_signature)
}

/// Verify an ECDSA P-256 (SHA-256) DER signature over `message` under a SEC1
/// uncompressed public-key point. Used for the pinned root keys, which are raw points.
pub fn verify_ecdsa_p256_sha256_sec1(
    sec1_point: &[u8],
    message: &[u8],
    der_signature: &[u8],
) -> Result<(), DsmError> {
    let verifying_key = P256VerifyingKey::from_sec1_bytes(sec1_point)
        .map_err(|_| DsmError::verification("attestation: malformed P-256 SEC1 public key"))?;
    verify_ecdsa_p256_sha256_inner(&verifying_key, message, der_signature)
}

fn verify_ecdsa_p256_sha256_inner(
    verifying_key: &P256VerifyingKey,
    message: &[u8],
    der_signature: &[u8],
) -> Result<(), DsmError> {
    let sig = P256Signature::from_der(der_signature)
        .map_err(|_| DsmError::verification("attestation: malformed P-256 DER signature"))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| DsmError::verification("attestation: ECDSA P-256 signature did not verify"))
}
