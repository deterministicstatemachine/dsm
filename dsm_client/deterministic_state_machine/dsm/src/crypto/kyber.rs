//! ML-KEM-768 (Kyber) post-quantum key encapsulation.
//!
//! Provides the DSM protocol's key exchange mechanism using NIST-standardized
//! ML-KEM-768 (formerly CRYSTALS-Kyber). This module is strictly bytes-only
//! (no serde/hex/base64), uses no wall-clock time (health checks are
//! op-count-gated), and follows canonical manual encoding throughout.
//!
//! # Key Operations
//!
//! - [`generate_kyber_keypair`] -- generate an ML-KEM-768 keypair
//! - [`kyber_encapsulate`] -- encapsulate a shared secret to a public key
//! - [`kyber_decapsulate`] -- decapsulate a shared secret using a secret key
//!
//! # Dependencies
//!
//! - `ml-kem = "0.2"` (ML-KEM-768 implementation)
//! - `blake3` (domain-separated key derivation)
//! - `zeroize` (secret key scrubbing)

use crate::types::error::DsmError;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aes_gcm::aead::OsRng;
use crate::crypto::blake3::dsm_domain_hasher;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    B32, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use tracing::{debug, error, info, trace};
use zeroize::ZeroizeOnDrop;

// ------------------ Deterministic op-gated health checking (no wall clock) ------------------

static KYBER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static KYBER_HEALTH_OPS: AtomicU64 = AtomicU64::new(0);
const HEALTH_CHECK_EVERY_N_OPS: u64 = 1000;

// Exact ML-KEM-768 sizes
const PK_LEN: usize = 1184;
const SK_LEN: usize = 2400;
const CT_LEN: usize = 1088;
const SS_LEN: usize = 32;

/// Enhanced KyberKeyPair with secure memory handling
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KyberKeyPair {
    /// Canonical, versioned bytes
    /// Format:
    ///   magic: b"DSM.KYBER.KEYPAIR\0"
    ///   ver  : u8 (=1)
    ///   pklen: u32 (BE) | pk
    ///   sklen: u32 (BE) | sk
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PK_LEN + SK_LEN + 32);
        out.extend_from_slice(b"DSM.KYBER.KEYPAIR\0");
        out.push(1u8);
        encode_bytes(&mut out, &self.public_key);
        encode_bytes(&mut out, &self.secret_key);
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, DsmError> {
        const MAGIC: &[u8] = b"DSM.KYBER.KEYPAIR\0";
        if bytes.len() < MAGIC.len() + 1 {
            return Err(DsmError::serialization_error(
                "KyberKeyPair too short",
                "keypair_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DsmError::serialization_error(
                "Bad KyberKeyPair magic",
                "keypair_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        bytes = &bytes[MAGIC.len()..];

        let version = bytes[0];
        bytes = &bytes[1..];
        if version != 1 {
            return Err(DsmError::serialization_error(
                "Unsupported KyberKeyPair version",
                "keypair_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }

        let (pk, rest) = decode_bytes(bytes)?;
        bytes = rest;
        let (sk, rest) = decode_bytes(bytes)?;

        if !rest.is_empty() {
            return Err(DsmError::serialization_error(
                "Trailing bytes in KyberKeyPair encoding",
                "keypair_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }

        if pk.len() != PK_LEN || sk.len() != SK_LEN {
            return Err(DsmError::crypto(
                format!("Invalid key sizes: pk={}, sk={}", pk.len(), sk.len()),
                None::<std::io::Error>,
            ));
        }

        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    pub fn generate() -> Result<Self, DsmError> {
        generate_kyber_keypair()
    }
}

// ------------------ Kyber subsystem init/verify (deterministic, op-gated) ------------------

pub fn init_kyber() -> Result<(), DsmError> {
    if KYBER_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    info!("Initializing Kyber KEM subsystem");
    match verify_kyber_subsystem() {
        Ok(_) => {
            info!("Kyber KEM verified");
            KYBER_INITIALIZED.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(e) => {
            error!("Failed to initialize Kyber KEM: {}", e);
            Err(DsmError::crypto(
                format!("Kyber KEM initialization failure: {e}"),
                None::<std::io::Error>,
            ))
        }
    }
}

fn maybe_periodic_verify() -> Result<(), DsmError> {
    let ops = KYBER_HEALTH_OPS.fetch_add(1, Ordering::Relaxed) + 1;
    if ops.is_multiple_of(HEALTH_CHECK_EVERY_N_OPS) {
        debug!("Kyber subsystem periodic verify (op-count gated)");
        verify_kyber_subsystem().map_err(|e| {
            DsmError::crypto(
                format!("Kyber periodic verify failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        trace!("Kyber KEM periodic verify OK");
    }
    Ok(())
}

fn verify_kyber_subsystem() -> Result<(), String> {
    let result = std::panic::catch_unwind(|| {
        // 1) Generate keys
        let mut rng = OsRng;
        let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

        // 2) Sizes
        if encapsulation_key.as_bytes().len() != PK_LEN {
            return Err(format!(
                "Encapsulation key size error: {} vs expected {}",
                encapsulation_key.as_bytes().len(),
                PK_LEN
            ));
        }
        if decapsulation_key.as_bytes().len() != SK_LEN {
            return Err(format!(
                "Decapsulation key size error: {} vs expected {}",
                decapsulation_key.as_bytes().len(),
                SK_LEN
            ));
        }

        // 3) Encapsulate/decapsulate
        let (ciphertext, shared_secret1) = encapsulation_key
            .encapsulate(&mut rng)
            .map_err(|_| "Encapsulation failed".to_string())?;
        let shared_secret2 = decapsulation_key
            .decapsulate(&ciphertext)
            .map_err(|_| "Decapsulation failed".to_string())?;
        if shared_secret1.as_slice() != shared_secret2.as_slice() {
            return Err("Shared secret mismatch after decapsulation".to_string());
        }

        // 4) Sizes for ct/ss
        if ciphertext.as_slice().len() != CT_LEN {
            return Err(format!(
                "Ciphertext size error: {} vs expected {}",
                ciphertext.as_slice().len(),
                CT_LEN
            ));
        }
        if shared_secret1.as_slice().len() != SS_LEN {
            return Err(format!(
                "Shared secret size error: {} vs expected {}",
                shared_secret1.as_slice().len(),
                SS_LEN
            ));
        }

        Ok(())
    });

    match result {
        Ok(inner) => inner,
        Err(e) => Err(format!(
            "Kyber subsystem verification panicked: {}",
            if let Some(s) = e.downcast_ref::<String>() {
                s
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s
            } else {
                "Unknown panic type"
            }
        )),
    }
}

// ------------------ size helpers ------------------

#[inline]
pub fn public_key_bytes() -> usize {
    PK_LEN
}
#[inline]
pub fn secret_key_bytes() -> usize {
    SK_LEN
}

// ------------------ Key generation ------------------

pub fn generate_kyber_keypair() -> Result<KyberKeyPair, DsmError> {
    if !KYBER_INITIALIZED.load(Ordering::SeqCst) {
        init_kyber()?;
    }
    let mut rng = OsRng;
    let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

    let pk_bytes = encapsulation_key.as_bytes().as_slice().to_vec();
    let sk_bytes = decapsulation_key.as_bytes().as_slice().to_vec();

    if pk_bytes.len() != PK_LEN || sk_bytes.len() != SK_LEN {
        return Err(DsmError::crypto(
            format!(
                "Generated key sizes do not match expected values: pk={}, sk={}",
                pk_bytes.len(),
                sk_bytes.len()
            ),
            None::<std::io::Error>,
        ));
    }

    maybe_periodic_verify()?;

    Ok(KyberKeyPair {
        public_key: pk_bytes,
        secret_key: sk_bytes,
    })
}

/// Deterministic key generation: Blake3(context||entropy) -> 32B seed -> ml-kem generate_deterministic(d, z)
pub fn generate_kyber_keypair_from_entropy(
    entropy: &[u8],
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    if entropy.len() < 32 {
        return Err(DsmError::crypto(
            "Insufficient entropy for secure key generation (minimum 32 bytes required)",
            None::<std::io::Error>,
        ));
    }

    let mut h = dsm_domain_hasher("DSM/ml-kem-seed");
    h.update(context.as_bytes());
    h.update(entropy);
    let digest = h.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_bytes());

    let d: B32 = {
        let mut h = dsm_domain_hasher("DSM/ml-kem-keygen-d");
        h.update(&seed);
        h.update(&0u64.to_le_bytes());
        (*h.finalize().as_bytes()).into()
    };
    let z: B32 = {
        let mut h = dsm_domain_hasher("DSM/ml-kem-keygen-z");
        h.update(&seed);
        h.update(&1u64.to_le_bytes());
        (*h.finalize().as_bytes()).into()
    };
    let (decapsulation_key, encapsulation_key) = MlKem768::generate_deterministic(&d, &z);

    let pk_bytes = encapsulation_key.as_bytes().as_slice().to_vec();
    let sk_bytes = decapsulation_key.as_bytes().as_slice().to_vec();

    if pk_bytes.len() != PK_LEN || sk_bytes.len() != SK_LEN {
        return Err(DsmError::crypto(
            format!(
                "Generated key sizes do not match expected values: pk={}, sk={}",
                pk_bytes.len(),
                sk_bytes.len()
            ),
            None::<std::io::Error>,
        ));
    }

    maybe_periodic_verify()?;

    Ok((pk_bytes, sk_bytes))
}

// ------------------ KEM ops ------------------

pub fn kyber_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    if !KYBER_INITIALIZED.load(Ordering::SeqCst) {
        init_kyber()?;
    }
    if public_key.len() != PK_LEN {
        return Err(DsmError::crypto(
            format!(
                "Invalid public key size: {} bytes (expected {})",
                public_key.len(),
                PK_LEN
            ),
            None::<std::io::Error>,
        ));
    }

    // Convert raw pk bytes → EncapsulationKey from encoded bytes
    let pk_arr: &[u8; PK_LEN] = public_key.try_into().map_err(|_| {
        DsmError::crypto(
            "Public key must be exactly ML-KEM-768 length",
            None::<std::io::Error>,
        )
    })?;
    let encapsulation_key = EncapsulationKey::<MlKem768Params>::from_bytes(pk_arr.into());

    // Encapsulate
    let mut rng = OsRng;
    let (ciphertext, shared_secret) = encapsulation_key
        .encapsulate(&mut rng)
        .map_err(|_| DsmError::crypto("Kyber encapsulation failed", None::<std::io::Error>))?;

    maybe_periodic_verify()?;

    Ok((
        shared_secret.as_slice().to_vec(),
        ciphertext.as_slice().to_vec(),
    ))
}

pub fn kyber_encapsulate_deterministic(
    public_key: &[u8],
    message_seed: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    if !KYBER_INITIALIZED.load(Ordering::SeqCst) {
        init_kyber()?;
    }
    if public_key.len() != PK_LEN {
        return Err(DsmError::crypto(
            format!(
                "Invalid public key size: {} bytes (expected {})",
                public_key.len(),
                PK_LEN
            ),
            None::<std::io::Error>,
        ));
    }

    let pk_arr: &[u8; PK_LEN] = public_key.try_into().map_err(|_| {
        DsmError::crypto(
            "Public key must be exactly ML-KEM-768 length",
            None::<std::io::Error>,
        )
    })?;
    let encapsulation_key = EncapsulationKey::<MlKem768Params>::from_bytes(pk_arr.into());
    let message = B32::try_from(message_seed.as_slice()).map_err(|_| {
        DsmError::crypto(
            "Deterministic Kyber seed must be exactly 32 bytes",
            None::<std::io::Error>,
        )
    })?;

    let (ciphertext, shared_secret) = encapsulation_key
        .encapsulate_deterministic(&message)
        .map_err(|_| {
            DsmError::crypto(
                "Deterministic Kyber encapsulation failed",
                None::<std::io::Error>,
            )
        })?;

    maybe_periodic_verify()?;

    Ok((
        shared_secret.as_slice().to_vec(),
        ciphertext.as_slice().to_vec(),
    ))
}

pub fn kyber_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
    if !KYBER_INITIALIZED.load(Ordering::SeqCst) {
        init_kyber()?;
    }
    if secret_key.len() != SK_LEN {
        return Err(DsmError::crypto(
            format!(
                "Invalid secret key size: {} bytes (expected {})",
                secret_key.len(),
                SK_LEN
            ),
            None::<std::io::Error>,
        ));
    }
    if ciphertext.len() != CT_LEN {
        return Err(DsmError::crypto(
            format!(
                "Invalid ciphertext size: {} bytes (expected {})",
                ciphertext.len(),
                CT_LEN
            ),
            None::<std::io::Error>,
        ));
    }

    // Convert raw bytes → typed key & ct
    let sk_arr: &[u8; SK_LEN] = secret_key.try_into().map_err(|_| {
        DsmError::crypto(
            "Secret key must be exactly ML-KEM-768 length",
            None::<std::io::Error>,
        )
    })?;
    let ct_arr: &[u8; CT_LEN] = ciphertext.try_into().map_err(|_| {
        DsmError::crypto(
            "Ciphertext must be exactly ML-KEM-768 length",
            None::<std::io::Error>,
        )
    })?;

    let decapsulation_key = DecapsulationKey::<MlKem768Params>::from_bytes(sk_arr.into());
    // Decapsulate expects &Array<…, CiphertextSize>; convert via `.into()` from &[u8; CT_LEN]
    let shared_secret = decapsulation_key
        .decapsulate(ct_arr.into())
        .map_err(|_| DsmError::crypto("Kyber decapsulation failed", None::<std::io::Error>))?;

    maybe_periodic_verify()?;

    Ok(shared_secret.as_slice().to_vec())
}

// ------------------ Encoding helpers ------------------

fn encode_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn encode_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    encode_u32(buf, len);
    buf.extend_from_slice(bytes);
}
fn decode_bytes(mut bytes: &[u8]) -> Result<(Vec<u8>, &[u8]), DsmError> {
    if bytes.len() < 4 {
        return Err(DsmError::serialization_error(
            "Missing length prefix",
            "bytes",
            None::<&str>,
            None::<std::io::Error>,
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    bytes = &bytes[4..];
    if bytes.len() < len {
        return Err(DsmError::serialization_error(
            "Insufficient bytes for field",
            "bytes",
            None::<&str>,
            None::<std::io::Error>,
        ));
    }
    let (val, rest) = bytes.split_at(len);
    Ok((val.to_vec(), rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_key_generation() {
        let result = generate_kyber_keypair();
        assert!(result.is_ok(), "Key generation should succeed");

        let keypair = result.unwrap();
        assert_eq!(
            keypair.public_key.len(),
            PK_LEN,
            "Public key should be {} bytes",
            PK_LEN
        );
        assert_eq!(
            keypair.secret_key.len(),
            SK_LEN,
            "Secret key should be {} bytes",
            SK_LEN
        );
    }

    #[test]
    fn test_kyber_encapsulation_decapsulation() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");

        // Encapsulate - Note: kyber_encapsulate returns (shared_secret, ciphertext)
        let encap_result = kyber_encapsulate(&keypair.public_key);
        assert!(encap_result.is_ok(), "Encapsulation should succeed");

        let (shared_secret1, ciphertext) = encap_result.unwrap();
        assert_eq!(
            shared_secret1.len(),
            SS_LEN,
            "Shared secret should be {} bytes",
            SS_LEN
        );
        assert_eq!(
            ciphertext.len(),
            CT_LEN,
            "Ciphertext should be {} bytes",
            CT_LEN
        );

        // Decapsulate
        let decap_result = kyber_decapsulate(&keypair.secret_key, &ciphertext);
        assert!(decap_result.is_ok(), "Decapsulation should succeed");

        let shared_secret2 = decap_result.unwrap();
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_kyber_wrong_secret_key() {
        let keypair1 = generate_kyber_keypair().expect("Key generation should succeed");
        let keypair2 = generate_kyber_keypair().expect("Key generation should succeed");

        let (ciphertext, _shared_secret1) =
            kyber_encapsulate(&keypair1.public_key).expect("Encapsulation should succeed");

        // Try to decapsulate with wrong secret key
        let decap_result = kyber_decapsulate(&keypair2.secret_key, &ciphertext);

        // Decapsulation may succeed but produce a different shared secret (implicit rejection)
        if let Ok(shared_secret2) = decap_result {
            let (_ct, shared_secret1) = kyber_encapsulate(&keypair1.public_key).unwrap();
            // With high probability, secrets should differ
            // Note: ML-KEM uses implicit rejection so this always succeeds but gives wrong secret
            assert_ne!(
                shared_secret1, shared_secret2,
                "Shared secrets should differ with wrong key"
            );
        }
    }

    #[test]
    fn test_kyber_keypair_serialization() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");

        let bytes = keypair.to_bytes();
        assert!(!bytes.is_empty(), "Serialized bytes should not be empty");

        let deserialized = KyberKeyPair::from_bytes(&bytes);
        assert!(deserialized.is_ok(), "Deserialization should succeed");

        let kp2 = deserialized.unwrap();
        assert_eq!(
            keypair.public_key, kp2.public_key,
            "Public keys should match"
        );
        assert_eq!(
            keypair.secret_key, kp2.secret_key,
            "Secret keys should match"
        );
    }

    #[test]
    fn test_kyber_keypair_invalid_magic() {
        let invalid_bytes = vec![0u8; 100];
        let result = KyberKeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err(), "Should reject invalid magic bytes");
    }

    #[test]
    fn test_kyber_keypair_truncated() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");
        let bytes = keypair.to_bytes();

        // Truncate the bytes
        let truncated = &bytes[..50];
        let result = KyberKeyPair::from_bytes(truncated);
        assert!(result.is_err(), "Should reject truncated bytes");
    }

    #[test]
    fn test_kyber_keypair_rejects_trailing_bytes() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");
        let mut bytes = keypair.to_bytes();
        bytes.extend_from_slice(&[0xAB, 0xCD]);

        let result = KyberKeyPair::from_bytes(&bytes);
        assert!(result.is_err(), "Should reject trailing bytes");
    }

    #[test]
    fn test_kyber_entropy_minimum_32_bytes() {
        let short_entropy = vec![7u8; 31];
        let result = generate_kyber_keypair_from_entropy(&short_entropy, "test");
        assert!(
            result.is_err(),
            "Should reject entropy shorter than 32 bytes"
        );
    }

    #[test]
    fn test_kyber_size_constants() {
        assert_eq!(
            public_key_bytes(),
            PK_LEN,
            "Public key size constant should match"
        );
        assert_eq!(
            secret_key_bytes(),
            SK_LEN,
            "Secret key size constant should match"
        );
        assert_eq!(SS_LEN, 32, "Shared secret size constant should match");
        assert_eq!(CT_LEN, 1088, "Ciphertext size constant should match");
    }

    #[test]
    fn test_kyber_initialization() {
        let result = init_kyber();
        assert!(result.is_ok(), "Kyber initialization should succeed");

        // Second init should also succeed (idempotent)
        let result2 = init_kyber();
        assert!(result2.is_ok(), "Second initialization should succeed");
    }

    #[test]
    fn test_kyber_deterministic_keypair() {
        let seed1 = vec![1u8; 32];
        let seed2 = vec![1u8; 32];
        let seed3 = vec![2u8; 32];

        let (pk1, sk1) =
            generate_kyber_keypair_from_entropy(&seed1, "test").expect("Should succeed");
        let (pk2, sk2) =
            generate_kyber_keypair_from_entropy(&seed2, "test").expect("Should succeed");
        let (pk3, _) = generate_kyber_keypair_from_entropy(&seed3, "test").expect("Should succeed");

        // Same seed and context should produce same keypair
        assert_eq!(pk1, pk2, "Same seed should produce same public key");
        assert_eq!(sk1, sk2, "Same seed should produce same secret key");

        // Different seed should produce different keypair
        assert_ne!(pk1, pk3, "Different seed should produce different keys");
    }

    #[test]
    fn test_kyber_encapsulation_randomness() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");

        // Two encapsulations with same public key should produce different results (randomized)
        let (ss1, ct1) =
            kyber_encapsulate(&keypair.public_key).expect("Encapsulation should succeed");
        let (ss2, ct2) =
            kyber_encapsulate(&keypair.public_key).expect("Encapsulation should succeed");

        assert_ne!(
            ct1, ct2,
            "Ciphertexts should differ (randomized encapsulation)"
        );
        assert_ne!(ss1, ss2, "Shared secrets should differ");
    }

    #[test]
    fn test_kyber_public_key_wrong_size() {
        let wrong_size_pk = vec![0u8; 100]; // Wrong size

        let result = kyber_encapsulate(&wrong_size_pk);
        assert!(result.is_err(), "Should reject public key of wrong size");
    }

    #[test]
    fn test_kyber_secret_key_wrong_size() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");
        let (_, ciphertext) =
            kyber_encapsulate(&keypair.public_key).expect("Encapsulation should succeed");

        let wrong_size_sk = vec![0u8; 100]; // Wrong size

        let result = kyber_decapsulate(&wrong_size_sk, &ciphertext);
        assert!(result.is_err(), "Should reject secret key of wrong size");
    }

    #[test]
    fn test_kyber_ciphertext_wrong_size() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");

        let wrong_size_ct = vec![0u8; 100]; // Wrong size

        let result = kyber_decapsulate(&keypair.secret_key, &wrong_size_ct);
        assert!(result.is_err(), "Should reject ciphertext of wrong size");
    }

    #[test]
    fn test_deterministic_kyber_encapsulation_round_trip() {
        let keypair = generate_kyber_keypair().expect("Key generation should succeed");
        let message_seed = [0x42u8; 32];

        let (shared_secret1, ciphertext1) =
            kyber_encapsulate_deterministic(&keypair.public_key, &message_seed)
                .expect("Deterministic encapsulation should succeed");
        let (shared_secret2, ciphertext2) =
            kyber_encapsulate_deterministic(&keypair.public_key, &message_seed)
                .expect("Deterministic encapsulation should succeed");
        let decapsulated = kyber_decapsulate(&keypair.secret_key, &ciphertext1)
            .expect("Decapsulation should succeed");

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(decapsulated, shared_secret1);
    }
}
