//! Encrypted Recovery Capsule Implementation
//!
//! Implements AEAD-encrypted capsules for NFC ring storage containing:
//! - SMT root hash
//! - Per-peer bilateral chain tips (height, head hash)
//! - Receipt rollup accumulator
//! - Metadata (version, flags, logical time, counter)

use crate::types::error::DsmError;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
// use aes_gcm::AeadCore; // not needed after removal of generate_nonce usage
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use rand::{rngs::OsRng, RngCore};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

static CAPSULE_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the capsule encryption/decryption subsystem
pub fn init_capsule_subsystem() -> Result<(), DsmError> {
    if !CAPSULE_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        // Verify cryptographic primitives are available via construction helpers (Key/Nonce)
        // Verify cryptographic primitives via constructors (no generic-array usage)
        let _ = Aes256Gcm::new_from_slice(&[0u8; 32]);

        tracing::info!("Capsule encryption subsystem initialized");
        CAPSULE_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
    Ok(())
}

/// Capsule metadata
#[derive(Debug, Clone)]
pub struct CapsuleMetadata {
    /// Protocol version
    pub version: u16,
    /// Feature flags
    pub flags: u16,
    /// Logical time t
    pub logical_time: u64,
    /// Monotonic counter c
    pub counter: u64,
}

/// Decrypted recovery capsule contents
#[derive(Debug, Clone)]
pub struct RecoveryCapsule {
    /// SMT root hash (32 bytes)
    pub smt_root: Vec<u8>,
    /// Per-counterparty bilateral tips: counterparty_id -> (height, head_hash)
    pub counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    /// Receipt rollup accumulator (32 bytes)
    pub rollup_hash: Vec<u8>,
    /// Capsule metadata
    pub metadata: CapsuleMetadata,
}

/// Encrypted capsule for NFC storage
#[derive(Debug, Clone)]
pub struct EncryptedCapsule {
    /// AEAD-encrypted payload
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag
    pub tag: Vec<u8>,
    /// Nonce used for encryption (96 bits)
    pub nonce: Vec<u8>,
    /// Salt used for KDF
    pub salt: Vec<u8>,
    /// Metadata (unencrypted for validation)
    pub metadata: CapsuleMetadata,
}

impl EncryptedCapsule {
    /// Get total size in bytes for NFC capacity planning
    pub fn size_bytes(&self) -> usize {
        self.ciphertext.len() + self.tag.len() + self.nonce.len() + self.salt.len() + 12
        // metadata
    }

    /// Serialize encrypted capsule to bytes for transport/storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_bytes() + 32); // approximate

        // 1. Nonce (12 bytes fixed)
        if self.nonce.len() != 12 {
            // Should not happen if created via create_encrypted_capsule
            // But handle gracefully or panic? For now, assume valid.
        }
        bytes.extend_from_slice(&self.nonce);

        // 2. Salt (variable)
        bytes.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.salt);

        // 3. Tag (16 bytes fixed)
        bytes.extend_from_slice(&self.tag);

        // 4. Ciphertext (variable)
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);

        // 5. Metadata (20 bytes fixed)
        bytes.extend_from_slice(&self.metadata.version.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.flags.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.logical_time.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.counter.to_le_bytes());

        bytes
    }

    /// Deserialize encrypted capsule from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        let mut p = data;

        // Helper to read fixed bytes
        fn read_bytes(p: &mut &[u8], n: usize) -> Result<Vec<u8>, DsmError> {
            if p.len() < n {
                return Err(DsmError::invalid_operation("capsule decode: short read"));
            }
            let v = p[..n].to_vec();
            *p = &p[n..];
            Ok(v)
        }

        fn read_u32(p: &mut &[u8]) -> Result<u32, DsmError> {
            if p.len() < 4 {
                return Err(DsmError::invalid_operation("capsule decode: short u32"));
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&p[..4]);
            *p = &p[4..];
            Ok(u32::from_le_bytes(b))
        }

        // 1. Nonce (12 bytes)
        let nonce = read_bytes(&mut p, 12)?;

        // 2. Salt
        let salt_len = read_u32(&mut p)? as usize;
        let salt = read_bytes(&mut p, salt_len)?;

        // 3. Tag (16 bytes)
        let tag = read_bytes(&mut p, 16)?;

        // 4. Ciphertext
        let ct_len = read_u32(&mut p)? as usize;
        let ciphertext = read_bytes(&mut p, ct_len)?;

        // 5. Metadata (20 bytes)
        if p.len() < 20 {
            return Err(DsmError::invalid_operation(
                "capsule decode: short metadata",
            ));
        }
        let mut v2 = [0u8; 2];
        v2.copy_from_slice(&p[..2]);
        p = &p[2..];
        let version = u16::from_le_bytes(v2);

        let mut f2 = [0u8; 2];
        f2.copy_from_slice(&p[..2]);
        p = &p[2..];
        let flags = u16::from_le_bytes(f2);

        let mut u8_buf = [0u8; 8];
        u8_buf.copy_from_slice(&p[..8]);
        p = &p[8..];
        let logical_time = u64::from_le_bytes(u8_buf);

        u8_buf.copy_from_slice(&p[..8]);
        // p = &p[8..]; // Unused
        let counter = u64::from_le_bytes(u8_buf);

        Ok(EncryptedCapsule {
            ciphertext,
            tag,
            nonce,
            salt,
            metadata: CapsuleMetadata {
                version,
                flags,
                logical_time,
                counter,
            },
        })
    }
}

impl RecoveryCapsule {
    /// Deserialize recovery capsule from plaintext bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        decode_capsule_bytes(data)
    }

    /// Canonical deterministic serialization of a plaintext `RecoveryCapsule`.
    ///
    /// This is the single source of truth for capsule encoding. Both the
    /// mnemonic-based path (`create_encrypted_capsule`) and the cached-key
    /// path in the SDK must use this method to avoid format drift.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // smt_root
        out.extend_from_slice(&(self.smt_root.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.smt_root);
        // counterparty_tips sorted by key (deterministic)
        let mut keys: Vec<_> = self.counterparty_tips.keys().cloned().collect();
        keys.sort();
        out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for k in keys {
            let (h, head) = &self.counterparty_tips[&k];
            let kb = k.as_bytes();
            out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
            out.extend_from_slice(kb);
            out.extend_from_slice(&h.to_le_bytes());
            out.extend_from_slice(&(head.len() as u32).to_le_bytes());
            out.extend_from_slice(head);
        }
        // rollup_hash
        out.extend_from_slice(&(self.rollup_hash.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.rollup_hash);
        // metadata
        out.extend_from_slice(&self.metadata.version.to_le_bytes());
        out.extend_from_slice(&self.metadata.flags.to_le_bytes());
        out.extend_from_slice(&self.metadata.logical_time.to_le_bytes());
        out.extend_from_slice(&self.metadata.counter.to_le_bytes());
        out
    }
}

/// Create encrypted recovery capsule for NFC ring storage
pub fn create_encrypted_capsule(
    smt_root: &[u8],
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: &super::ReceiptRollup,
    mnemonic: &str,
    device_id: &str,
    counter: u64,
) -> Result<EncryptedCapsule, DsmError> {
    // Create capsule metadata
    let metadata = CapsuleMetadata {
        version: 1,
        flags: 0,
        logical_time: counter, // Use counter as logical time for now
        counter,
    };

    // Create recovery capsule
    let capsule = RecoveryCapsule {
        smt_root: smt_root.to_vec(),
        counterparty_tips,
        rollup_hash: rollup.current_hash().to_vec(),
        metadata: metadata.clone(),
    };

    let plaintext = capsule.to_bytes();

    // Derive encryption key from mnemonic using Argon2id.
    // device_id is a Base32 Crockford string (52 chars). SaltString max is 64
    // base64 chars. BLAKE3 hash to 32 bytes → 44 base64 chars, fits.
    let device_hash = blake3::hash(device_id.as_bytes());
    let salt_string = SaltString::encode_b64(device_hash.as_bytes())
        .map_err(|_| DsmError::crypto("Failed to create salt", None::<String>))?;

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(mnemonic.as_bytes(), &salt_string)
        .map_err(|_| DsmError::crypto("Failed to derive key", None::<String>))?;

    let hash_ref = password_hash.hash.as_ref().ok_or_else(|| {
        DsmError::invalid_operation("Argon2 produced no hash bytes (missing 'hash' field)")
    })?;
    let key_bytes = hash_ref.as_bytes();
    if key_bytes.len() < 32 {
        return Err(DsmError::crypto("Derived key too short", None::<String>));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..32])
        .map_err(|_| DsmError::crypto("Invalid key length", None::<String>))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt capsule
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| DsmError::verification("Failed to encrypt capsule"))?; // aes_gcm::Error doesn't implement Error trait

    // Extract tag (last 16 bytes of ciphertext for AES-GCM)
    let tag_start = ciphertext.len().saturating_sub(16);
    let tag = ciphertext[tag_start..].to_vec();
    let ciphertext = ciphertext[..tag_start].to_vec();

    Ok(EncryptedCapsule {
        ciphertext,
        tag,
        nonce: nonce_bytes.to_vec(),
        salt: salt_string.as_str().as_bytes().to_vec(),
        metadata,
    })
}

/// Decrypt and verify recovery capsule
pub fn decrypt_capsule(
    encrypted: &EncryptedCapsule,
    mnemonic: &str,
    device_id: &str,
) -> Result<RecoveryCapsule, DsmError> {
    // Recreate salt (must match encryption: BLAKE3 hash of device_id string)
    let device_hash = blake3::hash(device_id.as_bytes());
    let salt_string = SaltString::encode_b64(device_hash.as_bytes())
        .map_err(|_| DsmError::crypto("Failed to recreate salt", None::<String>))?;

    // Verify salt matches
    if salt_string.as_str().as_bytes() != encrypted.salt {
        return Err(DsmError::crypto("Salt mismatch", None::<String>));
    }

    // Derive decryption key
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(mnemonic.as_bytes(), &salt_string)
        .map_err(|_| DsmError::crypto("Failed to derive decryption key", None::<String>))?;

    let hash_ref = password_hash.hash.as_ref().ok_or_else(|| {
        DsmError::invalid_operation("Argon2 produced no hash bytes (missing 'hash' field)")
    })?;
    let key_bytes = hash_ref.as_bytes();
    if key_bytes.len() < 32 {
        return Err(DsmError::crypto(
            "Derived decryption key too short",
            None::<String>,
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..32])
        .map_err(|_| DsmError::crypto("Invalid key length", None::<String>))?;

    if encrypted.nonce.len() != 12 {
        return Err(DsmError::crypto("Invalid nonce length", None::<String>));
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&encrypted.nonce);
    let nonce = Nonce::from(nonce_bytes);

    // Reconstruct ciphertext with tag
    let mut full_ciphertext = encrypted.ciphertext.clone();
    full_ciphertext.extend_from_slice(&encrypted.tag);

    // Decrypt capsule
    let plaintext = cipher
        .decrypt(&nonce, full_ciphertext.as_slice())
        .map_err(|_| DsmError::verification("Failed to decrypt capsule"))?; // aes_gcm::Error doesn't implement Error trait

    let capsule = RecoveryCapsule::from_bytes(&plaintext)?;

    // Verify metadata integrity
    if capsule.metadata.version != encrypted.metadata.version
        || capsule.metadata.counter != encrypted.metadata.counter
    {
        return Err(DsmError::crypto(
            "Capsule metadata integrity check failed",
            None::<String>,
        ));
    }

    Ok(capsule)
}

/// Decrypt recovery capsule using a pre-derived key (32 bytes)
/// Skips Argon2 derivation and salt verification (assumes caller handled it or key is correct).
pub fn decrypt_capsule_with_key(
    encrypted: &EncryptedCapsule,
    key: &[u8],
) -> Result<RecoveryCapsule, DsmError> {
    if key.len() != 32 {
        return Err(DsmError::crypto("Invalid key length", None::<String>));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| DsmError::crypto("Invalid key length", None::<String>))?;

    if encrypted.nonce.len() != 12 {
        return Err(DsmError::crypto("Invalid nonce length", None::<String>));
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&encrypted.nonce);
    let nonce = Nonce::from(nonce_bytes);

    // Reconstruct ciphertext with tag
    let mut full_ciphertext = encrypted.ciphertext.clone();
    full_ciphertext.extend_from_slice(&encrypted.tag);

    // Decrypt capsule
    let plaintext = cipher
        .decrypt(&nonce, full_ciphertext.as_slice())
        .map_err(|_| DsmError::verification("Failed to decrypt capsule"))?;

    // Reuse the internal decode function (we need to expose it or duplicate it)
    // Since decode_capsule is inside decrypt_capsule, we should extract it.
    // For now, I'll duplicate the decode logic or refactor.
    // Refactoring is better.
    decode_capsule_bytes(&plaintext)
}

fn decode_capsule_bytes(data: &[u8]) -> Result<RecoveryCapsule, DsmError> {
    let mut p = data;

    fn read_u32(p: &mut &[u8]) -> Result<u32, DsmError> {
        if p.len() < 4 {
            return Err(DsmError::invalid_operation("capsule decode: short u32"));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&p[..4]);
        *p = &p[4..];
        Ok(u32::from_le_bytes(b))
    }
    fn read_u64(p: &mut &[u8]) -> Result<u64, DsmError> {
        if p.len() < 8 {
            return Err(DsmError::invalid_operation("capsule decode: short u64"));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&p[..8]);
        *p = &p[8..];
        Ok(u64::from_le_bytes(b))
    }
    fn read_len_bytes(p: &mut &[u8]) -> Result<Vec<u8>, DsmError> {
        let n = read_u32(p)? as usize;
        if p.len() < n {
            return Err(DsmError::invalid_operation("capsule decode: short vec"));
        }
        let v = p[..n].to_vec();
        *p = &p[n..];
        Ok(v)
    }
    fn decode_metadata(p: &mut &[u8]) -> Result<CapsuleMetadata, DsmError> {
        if p.len() < 2 + 2 + 8 + 8 {
            return Err(DsmError::invalid_operation("capsule decode: short meta"));
        }
        let mut v2 = [0u8; 2];
        v2.copy_from_slice(&p[..2]);
        *p = &p[2..];
        let mut f2 = [0u8; 2];
        f2.copy_from_slice(&p[..2]);
        *p = &p[2..];
        let logical = read_u64(p)?;
        let counter = read_u64(p)?;
        Ok(CapsuleMetadata {
            version: u16::from_le_bytes(v2),
            flags: u16::from_le_bytes(f2),
            logical_time: logical,
            counter,
        })
    }

    let smt_root = read_len_bytes(&mut p)?;
    let tips_n = read_u32(&mut p)? as usize;
    let mut tips = HashMap::with_capacity(tips_n);
    for _ in 0..tips_n {
        let kb = read_len_bytes(&mut p)?;
        let key = String::from_utf8(kb)
            .map_err(|_| DsmError::invalid_operation("capsule decode: bad utf8"))?;
        let h = read_u64(&mut p)?;
        let head = read_len_bytes(&mut p)?;
        tips.insert(key, (h, head));
    }
    let rollup_hash = read_len_bytes(&mut p)?;
    let metadata = decode_metadata(&mut p)?;
    Ok(RecoveryCapsule {
        smt_root,
        counterparty_tips: tips,
        rollup_hash,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::ReceiptRollup;

    #[test]
    fn test_capsule_encrypt_decrypt() -> Result<(), DsmError> {
        init_capsule_subsystem()?;

        let smt_root = vec![1; 32];
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer1".to_string(), (1u64, vec![2; 32]));

        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let device_id = "test_device";
        let counter = 42u64;

        // Encrypt
        let encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips.clone(),
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;

        // Decrypt
        let decrypted = decrypt_capsule(&encrypted, mnemonic, device_id)?;

        // Verify
        assert_eq!(decrypted.smt_root, smt_root);
        assert_eq!(decrypted.counterparty_tips, counterparty_tips);
        assert_eq!(decrypted.metadata.counter, counter);

        Ok(())
    }

    #[test]
    fn test_capsule_serialize_round_trip() -> Result<(), DsmError> {
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("alice".to_string(), (5u64, vec![0xAA; 32]));
        counterparty_tips.insert("bob".to_string(), (10u64, vec![0xBB; 32]));

        let capsule = RecoveryCapsule {
            smt_root: vec![0x11; 32],
            counterparty_tips,
            rollup_hash: vec![0x22; 32],
            metadata: CapsuleMetadata {
                version: 1,
                flags: 0,
                logical_time: 42,
                counter: 42,
            },
        };

        let bytes = capsule.to_bytes();
        let decoded = RecoveryCapsule::from_bytes(&bytes)?;

        assert_eq!(decoded.smt_root, capsule.smt_root);
        assert_eq!(decoded.counterparty_tips, capsule.counterparty_tips);
        assert_eq!(decoded.rollup_hash, capsule.rollup_hash);
        assert_eq!(decoded.metadata.version, capsule.metadata.version);
        assert_eq!(decoded.metadata.flags, capsule.metadata.flags);
        assert_eq!(decoded.metadata.logical_time, capsule.metadata.logical_time);
        assert_eq!(decoded.metadata.counter, capsule.metadata.counter);

        // Encoding is deterministic: re-encode must produce identical bytes
        let bytes2 = decoded.to_bytes();
        assert_eq!(
            bytes, bytes2,
            "re-encoding must be identical (deterministic)"
        );

        Ok(())
    }

    #[test]
    fn test_nfc_capsule_encrypt_serialize_decrypt_round_trip() -> Result<(), DsmError> {
        init_capsule_subsystem()?;

        let smt_root = vec![0xCC; 32];
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer_a".to_string(), (1u64, vec![0xDD; 32]));
        counterparty_tips.insert("peer_b".to_string(), (2u64, vec![0xEE; 32]));

        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let device_id = "NFC_RING_TEST_DEVICE";
        let counter = 7u64;

        // Create encrypted capsule (simulates NFC write payload)
        let encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips.clone(),
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;

        // Serialize to bytes (NFC write) then deserialize (NFC read)
        let wire_bytes = encrypted.to_bytes();
        let restored = EncryptedCapsule::from_bytes(&wire_bytes)?;

        // Verify envelope fields survive the round trip
        assert_eq!(restored.nonce, encrypted.nonce);
        assert_eq!(restored.salt, encrypted.salt);
        assert_eq!(restored.tag, encrypted.tag);
        assert_eq!(restored.ciphertext, encrypted.ciphertext);
        assert_eq!(restored.metadata.counter, counter);

        // Decrypt the restored capsule (simulates recovery from NFC ring)
        let decrypted = decrypt_capsule(&restored, mnemonic, device_id)?;

        assert_eq!(decrypted.smt_root, smt_root);
        assert_eq!(decrypted.counterparty_tips, counterparty_tips);
        assert_eq!(decrypted.rollup_hash, rollup.current_hash().to_vec());
        assert_eq!(decrypted.metadata.counter, counter);

        Ok(())
    }

    #[test]
    fn test_wrong_mnemonic_fails() -> Result<(), DsmError> {
        init_capsule_subsystem()?;

        let smt_root = vec![1; 32];
        let counterparty_tips = HashMap::new();
        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wrong_mnemonic =
            "wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong";
        let device_id = "test_device";
        let counter = 1u64;

        let encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips,
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;

        // Should fail with wrong mnemonic
        assert!(decrypt_capsule(&encrypted, wrong_mnemonic, device_id).is_err());

        Ok(())
    }

    #[test]
    fn test_nonce_wrong_length_panics() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![1; 32];
        let counterparty_tips = HashMap::new();
        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let device_id = "test_device";
        let counter = 7u64;

        let mut encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips,
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;
        // Force an invalid nonce length (must be 12 bytes)
        encrypted.nonce = vec![0u8; 8];

        let res = decrypt_capsule(&encrypted, mnemonic, device_id);
        assert!(
            res.is_err(),
            "decrypt should fail when nonce length is invalid"
        );
        Ok(())
    }

    #[test]
    fn test_ciphertext_tamper_fails() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![1; 32];
        let counterparty_tips = HashMap::new();
        let rollup = ReceiptRollup::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let device_id = "test_device";
        let counter = 99u64;

        let mut encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips,
            &rollup,
            mnemonic,
            device_id,
            counter,
        )?;
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        assert!(
            decrypt_capsule(&encrypted, mnemonic, device_id).is_err(),
            "tampered ciphertext must fail to decrypt"
        );
        Ok(())
    }
}
