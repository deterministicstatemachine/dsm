// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sealed spool payloads (DSM Amendment A7, storage spec §8).
//!
//! Everything a relationship sends through the spool — a transfer, a reply,
//! an evidence half, a checkpoint, a message — is sealed end to end between
//! its two parties. A storage node holds ciphertext and a message id, nothing
//! else: the sender's headers travel inside the seal.
//!
//! The key comes from a Kyber exchange the two parties already make. For a
//! transfer step it is that step's own encapsulation — the same one whose
//! shared secret seeds the next per-step signing key — and for a message it is
//! an encapsulation made for it. Either way the recipient decapsulates with
//! its own Kyber secret and derives the same key:
//!
//! ```text
//! K = H(DSM/spool-seal/v1 ‖ 0x00 ‖ shared_secret ‖ message_id)
//! ciphertext = XChaCha20-Poly1305(K, nonce = 0^24, aad = message_id, inner envelope bytes)
//! ```
//!
//! Every seal has its own key — a fresh shared secret per exchange and a
//! distinct message id per payload — so a fixed nonce never repeats under a
//! key. The message id is bound as associated data, so a sealed body cannot
//! be moved onto another id.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::common::domain_tags::TAG_DSM_SPOOL_SEAL;
use crate::crypto::blake3::dsm_domain_hasher;

/// The transport message id every envelope carries.
pub const MESSAGE_ID_LEN: usize = 16;

/// A Kyber (ML-KEM-768) ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;

/// Why a sealed payload did not open. Nothing about the plaintext is revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The shared secret, the message id or the bytes are not the ones sealed.
    DoesNotOpen,
    /// The cipher refused to seal (never expected for bounded inputs).
    SealFailed,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealError::DoesNotOpen => write!(f, "sealed payload does not open"),
            SealError::SealFailed => write!(f, "sealing failed"),
        }
    }
}

impl std::error::Error for SealError {}

/// The one key a (shared secret, message id) pair seals under.
pub fn seal_key(shared_secret: &[u8], message_id: &[u8; MESSAGE_ID_LEN]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_SPOOL_SEAL);
    h.update(shared_secret);
    h.update(message_id);
    *h.finalize().as_bytes()
}

fn cipher(shared_secret: &[u8], message_id: &[u8; MESSAGE_ID_LEN]) -> XChaCha20Poly1305 {
    let key = seal_key(shared_secret, message_id);
    XChaCha20Poly1305::new((&key).into())
}

/// Seal `inner` — the exact bytes of the inner envelope — for `message_id`.
pub fn seal(
    shared_secret: &[u8],
    message_id: &[u8; MESSAGE_ID_LEN],
    inner: &[u8],
) -> Result<Vec<u8>, SealError> {
    cipher(shared_secret, message_id)
        .encrypt(
            &XNonce::default(),
            Payload {
                msg: inner,
                aad: message_id,
            },
        )
        .map_err(|_| SealError::SealFailed)
}

/// Open a sealed payload. Fails, revealing nothing, unless the shared secret,
/// the message id and every ciphertext byte are the ones sealed.
pub fn open(
    shared_secret: &[u8],
    message_id: &[u8; MESSAGE_ID_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SealError> {
    cipher(shared_secret, message_id)
        .decrypt(
            &XNonce::default(),
            Payload {
                msg: ciphertext,
                aad: message_id,
            },
        )
        .map_err(|_| SealError::DoesNotOpen)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS: [u8; 32] = [7u8; 32];
    const ID: [u8; MESSAGE_ID_LEN] = [1u8; MESSAGE_ID_LEN];

    #[test]
    fn a_sealed_payload_opens_to_its_bytes() {
        let sealed = seal(&SS, &ID, b"inner envelope").unwrap();
        assert_ne!(sealed.as_slice(), b"inner envelope".as_slice());
        assert_eq!(open(&SS, &ID, &sealed).unwrap(), b"inner envelope");
    }

    #[test]
    fn it_opens_under_nothing_else() {
        let sealed = seal(&SS, &ID, b"inner envelope").unwrap();
        assert_eq!(
            open(&[8u8; 32], &ID, &sealed),
            Err(SealError::DoesNotOpen),
            "another secret"
        );
        assert_eq!(
            open(&SS, &[2u8; MESSAGE_ID_LEN], &sealed),
            Err(SealError::DoesNotOpen),
            "another id"
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert_eq!(
            open(&SS, &ID, &tampered),
            Err(SealError::DoesNotOpen),
            "a changed byte"
        );
        assert_eq!(
            open(&SS, &ID, &sealed[..sealed.len() - 1]),
            Err(SealError::DoesNotOpen),
            "truncated"
        );
    }

    #[test]
    fn every_message_has_its_own_key() {
        assert_ne!(seal_key(&SS, &ID), seal_key(&SS, &[2u8; MESSAGE_ID_LEN]));
        assert_ne!(seal_key(&SS, &ID), seal_key(&[8u8; 32], &ID));
        let a = seal(&SS, &ID, b"same").unwrap();
        let b = seal(&SS, &[2u8; MESSAGE_ID_LEN], b"same").unwrap();
        assert_ne!(a, b, "the same bytes under two ids seal differently");
    }
}
