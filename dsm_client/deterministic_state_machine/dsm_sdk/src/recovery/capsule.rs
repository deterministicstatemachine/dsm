// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline recovery capsule (v3) - hardened AEAD.
//!
//! Requirements:
//! - AEAD: XChaCha20-Poly1305
//! - Deterministic nonce: H("DSM/recovery-capsule/nonce-v2\0" || u64le(capsule_index) || roll_accumulator)[0..24]
//! - Strict associated data:
//!   AD = "DSM/recovery-capsule-v3\0" || smt_root || u64le(capsule_index)
//!
//! Note: This module does *not* use wall-clock time or randomness.
//! Key management is handled by the caller (e.g., derived from a recovery secret).

use crate::types::error::DsmError;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use dsm::crypto::blake3::dsm_domain_hasher;

pub const RECOVERY_CAPSULE_V3_AAD_DOMAIN: &[u8] = b"DSM/recovery-capsule-v3\0";
pub const RECOVERY_CAPSULE_V3_NONCE_DOMAIN: &[u8] = b"DSM/recovery-capsule/nonce-v2\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCapsuleV3 {
    pub capsule_index: u64,
    pub smt_root: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn derive_nonce(capsule_index: u64, roll_accumulator: &[u8]) -> [u8; 24] {
    let mut h = dsm_domain_hasher("DSM/recovery-capsule/nonce-v2");
    h.update(&capsule_index.to_le_bytes());
    h.update(roll_accumulator);
    let out = h.finalize();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&out.as_bytes()[0..24]);
    nonce
}

fn build_aad(smt_root: &[u8; 32], capsule_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECOVERY_CAPSULE_V3_AAD_DOMAIN.len() + 32 + 8);
    aad.extend_from_slice(RECOVERY_CAPSULE_V3_AAD_DOMAIN);
    aad.extend_from_slice(smt_root);
    aad.extend_from_slice(&capsule_index.to_le_bytes());
    aad
}

/// Encrypt a recovery capsule payload.
///
/// `key32` must be exactly 32 bytes.
pub fn encrypt_recovery_capsule_v3(
    key32: &[u8; 32],
    smt_root: &[u8; 32],
    capsule_index: u64,
    roll_accumulator: &[u8],
    plaintext: &[u8],
) -> Result<RecoveryCapsuleV3, DsmError> {
    let nonce = derive_nonce(capsule_index, roll_accumulator);
    let aad = build_aad(smt_root, capsule_index);

    let cipher = XChaCha20Poly1305::new_from_slice(key32)
        .map_err(|_| DsmError::invalid_parameter("recovery capsule key must be 32 bytes"))?;
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            DsmError::crypto("Recovery capsule encryption failed", None::<std::io::Error>)
        })?;

    Ok(RecoveryCapsuleV3 {
        capsule_index,
        smt_root: *smt_root,
        nonce,
        ciphertext: ct,
    })
}

/// Decrypt a recovery capsule payload.
pub fn decrypt_recovery_capsule_v3(
    key32: &[u8; 32],
    capsule: &RecoveryCapsuleV3,
) -> Result<Vec<u8>, DsmError> {
    let aad = build_aad(&capsule.smt_root, capsule.capsule_index);
    let cipher = XChaCha20Poly1305::new_from_slice(key32)
        .map_err(|_| DsmError::invalid_parameter("recovery capsule key must be 32 bytes"))?;
    cipher
        .decrypt(
            &XNonce::from(capsule.nonce),
            Payload {
                msg: capsule.ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| DsmError::crypto("Recovery capsule decryption failed", None::<std::io::Error>))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let smt_root = [9u8; 32];
        let idx = 42u64;
        let roll = b"roll";
        let pt = b"hello capsule";

        let cap = match encrypt_recovery_capsule_v3(&key, &smt_root, idx, roll, pt) {
            Ok(cap) => cap,
            Err(e) => panic!("Failed to encrypt capsule: {:?}", e),
        };
        let out = match decrypt_recovery_capsule_v3(&key, &cap) {
            Ok(out) => out,
            Err(e) => panic!("Failed to decrypt capsule: {:?}", e),
        };
        assert_eq!(out, pt);
    }

    #[test]
    fn aad_binding_rejects_wrong_root_or_index() {
        let key = [7u8; 32];
        let smt_root = [9u8; 32];
        let idx = 42u64;
        let roll = b"roll";
        let pt = b"hello capsule";

        let cap = match encrypt_recovery_capsule_v3(&key, &smt_root, idx, roll, pt) {
            Ok(cap) => cap,
            Err(e) => panic!("Failed to encrypt capsule: {:?}", e),
        };

        let mut wrong = cap.clone();
        wrong.smt_root = [8u8; 32];
        assert!(decrypt_recovery_capsule_v3(&key, &wrong).is_err());

        let mut wrong2 = cap.clone();
        wrong2.capsule_index = 43;
        assert!(decrypt_recovery_capsule_v3(&key, &wrong2).is_err());
    }

    #[test]
    fn deterministic_nonce_changes_with_roll_or_index() {
        let key = [7u8; 32];
        let smt_root = [9u8; 32];
        let pt = b"hello capsule";

        let a = match encrypt_recovery_capsule_v3(&key, &smt_root, 1, b"r1", pt) {
            Ok(a) => a,
            Err(e) => panic!("Failed to encrypt capsule a: {:?}", e),
        };
        let b = match encrypt_recovery_capsule_v3(&key, &smt_root, 1, b"r1", pt) {
            Ok(b) => b,
            Err(e) => panic!("Failed to encrypt capsule b: {:?}", e),
        };
        assert_eq!(a.nonce, b.nonce);

        let c = match encrypt_recovery_capsule_v3(&key, &smt_root, 2, b"r1", pt) {
            Ok(c) => c,
            Err(e) => panic!("Failed to encrypt capsule c: {:?}", e),
        };
        assert_ne!(a.nonce, c.nonce);

        let d = match encrypt_recovery_capsule_v3(&key, &smt_root, 1, b"r2", pt) {
            Ok(d) => d,
            Err(e) => panic!("Failed to encrypt capsule d: {:?}", e),
        };
        assert_ne!(a.nonce, d.nonce);
    }
}
