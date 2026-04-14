//! Encrypted recovery capsule implementation.
//!
//! Live recovery capsules follow the whitepaper recovery-ring path:
//! - mnemonic-only Argon2id seed derivation
//! - BLAKE3 key derivation for the 32-byte AEAD key
//! - deterministic nonce from capsule index + receipt rollup
//! - XChaCha20-Poly1305 with fixed associated data

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

static CAPSULE_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

const RECOVERY_CAPSULE_MAGIC: &[u8; 4] = b"RCV3";
const RECOVERY_CAPSULE_AAD: &[u8] = b"DSM/recovery-capsule-v3\0";
const RECOVERY_RING_ARGON2_SALT: &[u8] = b"DSM/recovery-ring\0";
const RECOVERY_AEAD_CONTEXT: &str = "DSM/recovery-aead\0";
const RECOVERY_AUTHORITY_CONTEXT: &str = "DSM/recovery-authority\0";
const RECOVERY_NONCE_DOMAIN: &str = "DSM/recovery-nonce";
const RECOVERY_CHALLENGE_DOMAIN: &str = "DSM/recovery-challenge";

/// Initialize the capsule encryption/decryption subsystem.
pub fn init_capsule_subsystem() -> Result<(), DsmError> {
    if !CAPSULE_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        let _ = XChaCha20Poly1305::new_from_slice(&[0u8; 32]);
        tracing::info!("Capsule encryption subsystem initialized");
        CAPSULE_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
    Ok(())
}

/// Capsule metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleMetadata {
    /// Protocol version.
    pub version: u16,
    /// Feature flags.
    pub flags: u16,
    /// Logical monotone index for transport/display.
    pub logical_time: u64,
    /// Monotone capsule counter.
    pub counter: u64,
}

/// Decrypted recovery capsule contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCapsule {
    /// Per-device SMT root (32 bytes).
    pub smt_root: Vec<u8>,
    /// Per-counterparty bilateral tips: counterparty_id -> (height, head_hash).
    pub counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    /// Receipt rollup accumulator (32 bytes).
    pub rollup_hash: Vec<u8>,
    /// Challenge binding for the current recovery stream (32 bytes).
    pub challenge: Vec<u8>,
    /// Capsule metadata.
    pub metadata: CapsuleMetadata,
    /// Device ID of the device that created this capsule (32 bytes).
    /// Empty for pre-v4 capsules that don't carry this field.
    pub source_device_id: Vec<u8>,
    /// Genesis hash of the Device Tree this capsule belongs to (32 bytes).
    /// Empty for pre-v4 capsules that don't carry this field.
    pub genesis_hash: Vec<u8>,
}

/// Encrypted capsule for NFC storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedCapsule {
    /// AEAD-encrypted payload (without detached tag).
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
    /// Nonce used for encryption (24 bytes for XChaCha20-Poly1305).
    pub nonce: Vec<u8>,
    /// Reserved for compatibility. v3 capsules leave this empty.
    pub salt: Vec<u8>,
    /// Metadata duplicated outside the ciphertext for quick inspection.
    pub metadata: CapsuleMetadata,
}

impl EncryptedCapsule {
    /// Get total size in bytes for NFC capacity planning.
    pub fn size_bytes(&self) -> usize {
        RECOVERY_CAPSULE_MAGIC.len()
            + 4
            + self.nonce.len()
            + 4
            + self.salt.len()
            + 4
            + self.tag.len()
            + 4
            + self.ciphertext.len()
            + 20
    }

    /// Serialize encrypted capsule to bytes for transport/storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_bytes());
        bytes.extend_from_slice(RECOVERY_CAPSULE_MAGIC);
        bytes.extend_from_slice(&(self.nonce.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&(self.tag.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.metadata.version.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.flags.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.logical_time.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.counter.to_le_bytes());
        bytes
    }

    /// Deserialize encrypted capsule from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        if data.starts_with(RECOVERY_CAPSULE_MAGIC) {
            decode_v3_encrypted_capsule(data)
        } else {
            Err(DsmError::invalid_operation(
                "Unsupported recovery capsule format - only v3 capsules are supported",
            ))
        }
    }
}

impl RecoveryCapsule {
    /// Deserialize recovery capsule from plaintext bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DsmError> {
        decode_capsule_bytes(data)
    }

    /// Canonical deterministic serialization of a plaintext `RecoveryCapsule`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.smt_root.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.smt_root);
        out.extend_from_slice(&self.metadata.version.to_le_bytes());
        out.extend_from_slice(&self.metadata.flags.to_le_bytes());
        out.extend_from_slice(&self.metadata.logical_time.to_le_bytes());
        out.extend_from_slice(&self.metadata.counter.to_le_bytes());
        let mut keys: Vec<_> = self.counterparty_tips.keys().cloned().collect();
        keys.sort();
        out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for key in keys {
            let (height, head_hash) = &self.counterparty_tips[&key];
            let key_bytes = key.as_bytes();
            out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(key_bytes);
            out.extend_from_slice(&height.to_le_bytes());
            out.extend_from_slice(&(head_hash.len() as u32).to_le_bytes());
            out.extend_from_slice(head_hash);
        }
        out.extend_from_slice(&(self.rollup_hash.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.rollup_hash);
        out.extend_from_slice(&(self.challenge.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.challenge);
        // v4 extension: source device binding (backward-compatible trailing fields)
        out.extend_from_slice(&(self.source_device_id.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.source_device_id);
        out.extend_from_slice(&(self.genesis_hash.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out
    }
}

/// Derive the 32-byte recovery key from a mnemonic.
pub fn derive_recovery_key(mnemonic: &str) -> Result<[u8; 32], DsmError> {
    let argon2 = Argon2::default();
    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(mnemonic.as_bytes(), RECOVERY_RING_ARGON2_SALT, &mut seed)
        .map_err(|e| DsmError::crypto(format!("Argon2id failed: {e}"), None::<std::io::Error>))?;

    let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_AEAD_CONTEXT);
    hasher.update(&seed);
    let key = *hasher.finalize().as_bytes();
    seed.zeroize();
    Ok(key)
}

/// Derive a 32-byte seed for the recovery authority SPHINCS+ keypair.
///
/// Uses the same Argon2id intermediate as `derive_recovery_key`, but a distinct
/// BLAKE3 domain (`DSM/recovery-authority`) so the two keys are cryptographically
/// independent. The resulting seed is fed to `generate_keypair_from_seed()` to
/// produce a deterministic SPHINCS+ keypair that acts as the mnemonic-derived
/// recovery authority — the root of trust for tombstone and succession signing.
pub fn derive_recovery_authority_seed(mnemonic: &str) -> Result<[u8; 32], DsmError> {
    let argon2 = Argon2::default();
    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(mnemonic.as_bytes(), RECOVERY_RING_ARGON2_SALT, &mut seed)
        .map_err(|e| DsmError::crypto(format!("Argon2id failed: {e}"), None::<std::io::Error>))?;

    let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_AUTHORITY_CONTEXT);
    hasher.update(&seed);
    let authority_seed = *hasher.finalize().as_bytes();
    seed.zeroize();
    Ok(authority_seed)
}

/// Create encrypted recovery capsule for NFC ring storage using the mnemonic-derived key.
pub fn create_encrypted_capsule(
    smt_root: &[u8],
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: &super::ReceiptRollup,
    mnemonic: &str,
    counter: u64,
) -> Result<EncryptedCapsule, DsmError> {
    let key = derive_recovery_key(mnemonic)?;
    create_encrypted_capsule_with_key(smt_root, counterparty_tips, rollup, &key, counter)
}

/// Create encrypted recovery capsule using a pre-derived recovery key.
///
/// `source_device_id` and `genesis_hash` are optional device-binding fields.
/// When present (non-empty), the capsule is self-contained for recovery —
/// it knows which Device Tree leaf to tombstone and which genesis it belongs to.
pub fn create_encrypted_capsule_with_key(
    smt_root: &[u8],
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: &super::ReceiptRollup,
    key: &[u8; 32],
    counter: u64,
) -> Result<EncryptedCapsule, DsmError> {
    create_encrypted_capsule_with_binding(
        smt_root,
        counterparty_tips,
        rollup,
        key,
        counter,
        &[],
        &[],
    )
}

/// Create encrypted recovery capsule with full device-binding metadata.
pub fn create_encrypted_capsule_with_binding(
    smt_root: &[u8],
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: &super::ReceiptRollup,
    key: &[u8; 32],
    counter: u64,
    source_device_id: &[u8],
    genesis_hash: &[u8],
) -> Result<EncryptedCapsule, DsmError> {
    if smt_root.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "recovery capsule smt_root must be 32 bytes, got {}",
            smt_root.len()
        )));
    }

    let metadata = CapsuleMetadata {
        version: 3,
        flags: 0,
        logical_time: counter,
        counter,
    };
    let rollup_hash = rollup.current_hash().to_vec();
    let capsule = RecoveryCapsule {
        smt_root: smt_root.to_vec(),
        counterparty_tips,
        rollup_hash: rollup_hash.clone(),
        challenge: derive_challenge(&rollup_hash, smt_root, counter).to_vec(),
        metadata: metadata.clone(),
        source_device_id: source_device_id.to_vec(),
        genesis_hash: genesis_hash.to_vec(),
    };
    encrypt_capsule_with_key(&capsule, key)
}

/// Decrypt and verify a recovery capsule using the mnemonic-derived key.
pub fn decrypt_capsule(
    encrypted: &EncryptedCapsule,
    mnemonic: &str,
) -> Result<RecoveryCapsule, DsmError> {
    let key = derive_recovery_key(mnemonic)?;
    decrypt_capsule_with_key(encrypted, &key)
}

/// Decrypt a recovery capsule using a pre-derived key.
pub fn decrypt_capsule_with_key(
    encrypted: &EncryptedCapsule,
    key: &[u8],
) -> Result<RecoveryCapsule, DsmError> {
    if key.len() != 32 {
        return Err(DsmError::crypto("Invalid key length", None::<String>));
    }
    if encrypted.nonce.len() != 24 {
        return Err(DsmError::verification(
            "Unsupported recovery capsule format: expected XChaCha nonce",
        ));
    }
    if encrypted.metadata.version < 3 {
        return Err(DsmError::verification(
            "Unsupported legacy recovery capsule version",
        ));
    }
    if encrypted.tag.len() != 16 {
        return Err(DsmError::verification(
            "Unsupported recovery capsule tag length",
        ));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DsmError::crypto("Invalid key length", None::<String>))?;

    let mut full_ciphertext = encrypted.ciphertext.clone();
    full_ciphertext.extend_from_slice(&encrypted.tag);

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&encrypted.nonce),
            Payload {
                msg: full_ciphertext.as_slice(),
                aad: RECOVERY_CAPSULE_AAD,
            },
        )
        .map_err(|_| DsmError::verification("Failed to decrypt capsule"))?;

    let capsule = RecoveryCapsule::from_bytes(&plaintext)?;
    validate_capsule(&capsule, &encrypted.metadata)?;
    Ok(capsule)
}

fn encrypt_capsule_with_key(
    capsule: &RecoveryCapsule,
    key: &[u8; 32],
) -> Result<EncryptedCapsule, DsmError> {
    validate_capsule(capsule, &capsule.metadata)?;
    let nonce_bytes = derive_nonce(capsule.metadata.counter, &capsule.rollup_hash);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DsmError::crypto("Invalid key length", None::<String>))?;
    let full_ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: capsule.to_bytes().as_slice(),
                aad: RECOVERY_CAPSULE_AAD,
            },
        )
        .map_err(|_| DsmError::verification("Failed to encrypt capsule"))?;

    let tag_start = full_ciphertext
        .len()
        .checked_sub(16)
        .ok_or_else(|| DsmError::verification("Recovery capsule ciphertext too short"))?;

    Ok(EncryptedCapsule {
        ciphertext: full_ciphertext[..tag_start].to_vec(),
        tag: full_ciphertext[tag_start..].to_vec(),
        nonce: nonce_bytes.to_vec(),
        salt: Vec::new(),
        metadata: capsule.metadata.clone(),
    })
}

fn derive_nonce(counter: u64, rollup_hash: &[u8]) -> [u8; 24] {
    let mut hasher = dsm_domain_hasher(RECOVERY_NONCE_DOMAIN);
    hasher.update(&counter.to_le_bytes());
    hasher.update(rollup_hash);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&hasher.finalize().as_bytes()[..24]);
    nonce
}

fn derive_challenge(rollup_hash: &[u8], smt_root: &[u8], counter: u64) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(RECOVERY_CHALLENGE_DOMAIN);
    hasher.update(rollup_hash);
    hasher.update(smt_root);
    hasher.update(&counter.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn validate_capsule(capsule: &RecoveryCapsule, metadata: &CapsuleMetadata) -> Result<(), DsmError> {
    if metadata.version != 3 || capsule.metadata.version != 3 {
        return Err(DsmError::verification(
            "Unsupported recovery capsule version",
        ));
    }
    if capsule.smt_root.len() != 32 {
        return Err(DsmError::verification("Invalid capsule SMT root length"));
    }
    if capsule.rollup_hash.len() != 32 {
        return Err(DsmError::verification("Invalid capsule rollup hash length"));
    }
    if capsule.challenge.len() != 32 {
        return Err(DsmError::verification("Invalid capsule challenge length"));
    }
    if capsule.metadata.version != metadata.version
        || capsule.metadata.counter != metadata.counter
        || capsule.metadata.logical_time != metadata.logical_time
        || capsule.metadata.flags != metadata.flags
    {
        return Err(DsmError::verification(
            "Capsule metadata integrity check failed",
        ));
    }
    for (counterparty_id, (_height, head_hash)) in &capsule.counterparty_tips {
        if head_hash.len() != 32 {
            return Err(DsmError::verification(format!(
                "Invalid recovery capsule head hash length for {counterparty_id}",
            )));
        }
    }

    let expected_challenge = derive_challenge(
        &capsule.rollup_hash,
        &capsule.smt_root,
        capsule.metadata.counter,
    );
    if capsule.challenge.as_slice() != expected_challenge {
        return Err(DsmError::verification(
            "Recovery capsule challenge mismatch",
        ));
    }
    Ok(())
}

fn decode_v3_encrypted_capsule(data: &[u8]) -> Result<EncryptedCapsule, DsmError> {
    let mut p = &data[RECOVERY_CAPSULE_MAGIC.len()..];
    let nonce = read_len_bytes(&mut p)?;
    let salt = read_len_bytes(&mut p)?;
    let tag = read_len_bytes(&mut p)?;
    let ciphertext = read_len_bytes(&mut p)?;
    let metadata = decode_metadata(&mut p)?;
    if !p.is_empty() {
        return Err(DsmError::invalid_operation(
            "capsule decode: trailing bytes in v3 envelope",
        ));
    }
    Ok(EncryptedCapsule {
        ciphertext,
        tag,
        nonce,
        salt,
        metadata,
    })
}

fn decode_capsule_bytes(data: &[u8]) -> Result<RecoveryCapsule, DsmError> {
    let mut p = data;
    let smt_root = read_len_bytes(&mut p)?;
    let metadata = decode_metadata(&mut p)?;
    let tips_n = read_u32(&mut p)? as usize;
    let mut tips = HashMap::with_capacity(tips_n);
    for _ in 0..tips_n {
        let key_bytes = read_len_bytes(&mut p)?;
        let key = String::from_utf8(key_bytes)
            .map_err(|_| DsmError::invalid_operation("capsule decode: bad utf8"))?;
        let height = read_u64(&mut p)?;
        let head_hash = read_len_bytes(&mut p)?;
        tips.insert(key, (height, head_hash));
    }
    let rollup_hash = read_len_bytes(&mut p)?;
    let challenge = read_len_bytes(&mut p)?;
    // v4 extension: source device binding (backward-compatible optional trailing fields).
    // If no bytes remain, this is a pre-v4 capsule and both fields default to empty.
    let source_device_id = if p.len() >= 4 {
        read_len_bytes(&mut p)?
    } else {
        Vec::new()
    };
    let genesis_hash = if p.len() >= 4 {
        read_len_bytes(&mut p)?
    } else {
        Vec::new()
    };
    if !p.is_empty() {
        return Err(DsmError::invalid_operation(
            "capsule decode: trailing plaintext bytes",
        ));
    }
    Ok(RecoveryCapsule {
        smt_root,
        counterparty_tips: tips,
        rollup_hash,
        challenge,
        metadata,
        source_device_id,
        genesis_hash,
    })
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
    if p.len() < 20 {
        return Err(DsmError::invalid_operation("capsule decode: short meta"));
    }
    let mut version = [0u8; 2];
    version.copy_from_slice(&p[..2]);
    *p = &p[2..];
    let mut flags = [0u8; 2];
    flags.copy_from_slice(&p[..2]);
    *p = &p[2..];
    let logical_time = read_u64(p)?;
    let counter = read_u64(p)?;
    Ok(CapsuleMetadata {
        version: u16::from_le_bytes(version),
        flags: u16::from_le_bytes(flags),
        logical_time,
        counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{update_rollup, ReceiptRollup};

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_capsule_encrypt_decrypt() -> Result<(), DsmError> {
        init_capsule_subsystem()?;

        let smt_root = vec![1; 32];
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer1".to_string(), (1u64, vec![2; 32]));
        let rollup = ReceiptRollup::new();
        let counter = 42u64;

        let encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips.clone(),
            &rollup,
            MNEMONIC,
            counter,
        )?;
        let decrypted = decrypt_capsule(&encrypted, MNEMONIC)?;

        assert_eq!(decrypted.smt_root, smt_root);
        assert_eq!(decrypted.counterparty_tips, counterparty_tips);
        assert_eq!(decrypted.rollup_hash, rollup.current_hash().to_vec());
        assert_eq!(decrypted.metadata.counter, counter);
        assert_eq!(decrypted.metadata.version, 3);

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
            challenge: vec![0x33; 32],
            metadata: CapsuleMetadata {
                version: 3,
                flags: 0,
                logical_time: 42,
                counter: 42,
            },
            source_device_id: vec![0x44; 32],
            genesis_hash: vec![0x55; 32],
        };

        let bytes = capsule.to_bytes();
        let decoded = RecoveryCapsule::from_bytes(&bytes)?;

        assert_eq!(decoded, capsule);
        assert_eq!(bytes, decoded.to_bytes());
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
        let counter = 7u64;

        let encrypted = create_encrypted_capsule(
            &smt_root,
            counterparty_tips.clone(),
            &rollup,
            MNEMONIC,
            counter,
        )?;
        let wire_bytes = encrypted.to_bytes();
        let restored = EncryptedCapsule::from_bytes(&wire_bytes)?;
        let decrypted = decrypt_capsule(&restored, MNEMONIC)?;

        assert_eq!(restored.nonce.len(), 24);
        assert!(restored.salt.is_empty());
        assert_eq!(restored.tag.len(), 16);
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
        let encrypted =
            create_encrypted_capsule(&smt_root, counterparty_tips, &rollup, MNEMONIC, 1u64)?;

        assert!(decrypt_capsule(
            &encrypted,
            "wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong wrong",
        )
        .is_err());

        Ok(())
    }

    #[test]
    fn test_nonce_wrong_length_rejected() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![1; 32];
        let counterparty_tips = HashMap::new();
        let rollup = ReceiptRollup::new();
        let mut encrypted =
            create_encrypted_capsule(&smt_root, counterparty_tips, &rollup, MNEMONIC, 7u64)?;
        encrypted.nonce = vec![0u8; 8];

        assert!(decrypt_capsule(&encrypted, MNEMONIC).is_err());
        Ok(())
    }

    #[test]
    fn test_ciphertext_tamper_fails() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![1; 32];
        let counterparty_tips = HashMap::new();
        let rollup = ReceiptRollup::new();
        let mut encrypted =
            create_encrypted_capsule(&smt_root, counterparty_tips, &rollup, MNEMONIC, 99u64)?;
        if let Some(first) = encrypted.ciphertext.first_mut() {
            *first ^= 0xFF;
        }
        assert!(decrypt_capsule(&encrypted, MNEMONIC).is_err());
        Ok(())
    }

    #[test]
    fn test_mnemonic_and_cached_key_paths_match() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![7; 32];
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer1".to_string(), (3u64, vec![5; 32]));
        let rollup = ReceiptRollup::new();
        let key = derive_recovery_key(MNEMONIC)?;

        let via_mnemonic =
            create_encrypted_capsule(&smt_root, counterparty_tips.clone(), &rollup, MNEMONIC, 11)?;
        let via_key =
            create_encrypted_capsule_with_key(&smt_root, counterparty_tips, &rollup, &key, 11)?;

        assert_eq!(via_mnemonic.nonce, via_key.nonce);
        assert_eq!(via_mnemonic.tag, via_key.tag);
        assert_eq!(via_mnemonic.ciphertext, via_key.ciphertext);
        assert_eq!(
            decrypt_capsule_with_key(&via_key, &key)?,
            decrypt_capsule(&via_mnemonic, MNEMONIC)?
        );
        Ok(())
    }

    #[test]
    fn test_nonce_changes_with_rollup_or_counter() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let smt_root = vec![9; 32];
        let tips = HashMap::new();
        let base_rollup = ReceiptRollup::new();

        let first = create_encrypted_capsule(&smt_root, tips.clone(), &base_rollup, MNEMONIC, 1)?;
        let same = create_encrypted_capsule(&smt_root, tips.clone(), &base_rollup, MNEMONIC, 1)?;
        assert_eq!(first.nonce, same.nonce);

        let second = create_encrypted_capsule(&smt_root, tips.clone(), &base_rollup, MNEMONIC, 2)?;
        assert_ne!(first.nonce, second.nonce);

        let mut updated_rollup = ReceiptRollup::new();
        update_rollup(&mut updated_rollup, b"receipt1", &[1; 32], "peer1", 1)?;
        let third = create_encrypted_capsule(&smt_root, tips, &updated_rollup, MNEMONIC, 1)?;
        assert_ne!(first.nonce, third.nonce);

        Ok(())
    }

    #[test]
    fn test_invalid_counterparty_tip_length_rejected() -> Result<(), DsmError> {
        init_capsule_subsystem()?;
        let key = derive_recovery_key(MNEMONIC)?;
        let mut counterparty_tips = HashMap::new();
        counterparty_tips.insert("peer1".to_string(), (1u64, vec![0xAA; 31]));

        let capsule = RecoveryCapsule {
            smt_root: vec![0x11; 32],
            counterparty_tips,
            rollup_hash: vec![0x22; 32],
            challenge: derive_challenge(&[0x22; 32], &[0x11; 32], 5).to_vec(),
            metadata: CapsuleMetadata {
                version: 3,
                flags: 0,
                logical_time: 5,
                counter: 5,
            },
            source_device_id: Vec::new(),
            genesis_hash: Vec::new(),
        };

        assert!(encrypt_capsule_with_key(&capsule, &key).is_err());
        Ok(())
    }
}
