//! Symmetric AEAD helpers (AES-256-GCM).
//!
//! This module intentionally owns generic symmetric encryption helpers so
//! ML-KEM/Kyber remains scoped to KEM operations only.

use crate::types::error::DsmError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

/// AES-256-GCM encryption.
pub fn aes_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    if key.len() != 32 {
        return Err(DsmError::crypto(
            "Invalid key size for AES-256".to_string(),
            None::<std::io::Error>,
        ));
    }
    if nonce.len() != 12 {
        return Err(DsmError::crypto(
            "Invalid nonce size for AES-GCM".to_string(),
            None::<std::io::Error>,
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        DsmError::crypto(
            "Invalid AES-256 key length".to_string(),
            None::<std::io::Error>,
        )
    })?;

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let nonce = Nonce::from(nonce_arr);

    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| DsmError::crypto("AES encryption failed".to_string(), None::<std::io::Error>))
}

/// AES-256-GCM decryption.
pub fn aes_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
    if key.len() != 32 {
        return Err(DsmError::crypto(
            "Invalid key size for AES-256".to_string(),
            None::<std::io::Error>,
        ));
    }
    if nonce.len() != 12 {
        return Err(DsmError::crypto(
            "Invalid nonce size for AES-GCM".to_string(),
            None::<std::io::Error>,
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        DsmError::crypto(
            "Invalid AES-256 key length".to_string(),
            None::<std::io::Error>,
        )
    })?;

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let nonce = Nonce::from(nonce_arr);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DsmError::crypto("AES decryption failed".to_string(), None::<std::io::Error>))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encryption_decryption() {
        let msg = b"Test AES-GCM encryption";
        let key = vec![0xAAu8; 32];
        let nonce = vec![0x55u8; 12];

        let encrypted = aes_encrypt(&key, &nonce, msg);
        assert!(encrypted.is_ok(), "AES encryption should succeed");

        let ciphertext = encrypted.expect("ciphertext");
        let decrypted = aes_decrypt(&key, &nonce, &ciphertext);
        assert!(decrypted.is_ok(), "AES decryption should succeed");

        assert_eq!(msg, decrypted.expect("plaintext").as_slice());
    }

    #[test]
    fn test_aes_wrong_key() {
        let msg = b"Secret";
        let key1 = vec![1u8; 32];
        let key2 = vec![2u8; 32];
        let nonce = vec![0u8; 12];

        let ciphertext = aes_encrypt(&key1, &nonce, msg).expect("Encryption should succeed");
        let decrypted = aes_decrypt(&key2, &nonce, &ciphertext);
        assert!(
            decrypted.is_err(),
            "AES decryption with wrong key should fail"
        );
    }

    #[test]
    fn test_aes_wrong_nonce() {
        let msg = b"Secret";
        let key = vec![1u8; 32];
        let nonce1 = vec![1u8; 12];
        let nonce2 = vec![2u8; 12];

        let ciphertext = aes_encrypt(&key, &nonce1, msg).expect("Encryption should succeed");
        let decrypted = aes_decrypt(&key, &nonce2, &ciphertext);
        assert!(
            decrypted.is_err(),
            "AES decryption with wrong nonce should fail"
        );
    }

    #[test]
    fn test_aes_invalid_key_size() {
        let msg = b"Test";
        let bad_key = vec![0u8; 16];
        let nonce = vec![0u8; 12];

        let result = aes_encrypt(&bad_key, &nonce, msg);
        assert!(result.is_err(), "Should reject invalid key size");
    }

    #[test]
    fn test_aes_corrupted_ciphertext() {
        let msg = b"Test message";
        let key = vec![1u8; 32];
        let nonce = vec![0u8; 12];

        let mut ciphertext = aes_encrypt(&key, &nonce, msg).expect("Encryption should succeed");

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = aes_decrypt(&key, &nonce, &ciphertext);
        assert!(
            result.is_err(),
            "Decryption of corrupted ciphertext should fail"
        );
    }

    #[test]
    fn test_aes_empty_message() {
        let key = vec![1u8; 32];
        let nonce = vec![0u8; 12];
        let msg = b"";

        let encrypted = aes_encrypt(&key, &nonce, msg).expect("Should encrypt empty message");
        let decrypted = aes_decrypt(&key, &nonce, &encrypted).expect("Should decrypt");

        assert_eq!(msg, decrypted.as_slice(), "Empty message should roundtrip");
    }

    #[test]
    fn test_aes_large_message() {
        let key = vec![1u8; 32];
        let nonce = vec![0u8; 12];
        let msg = vec![0xAAu8; 10000];

        let encrypted = aes_encrypt(&key, &nonce, &msg).expect("Should encrypt large message");
        let decrypted = aes_decrypt(&key, &nonce, &encrypted).expect("Should decrypt");

        assert_eq!(msg, decrypted, "Large message should roundtrip");
    }
}
