//! Cryptographic primitives and operations for the DSM protocol.
//!
//! This module is the root of the DSM cryptographic stack. Every primitive
//! is post-quantum safe and operates without wall-clock time. The stack
//! comprises:
//!
//! | Primitive | Module | Purpose |
//! |-----------|--------|---------|
//! | BLAKE3-256 | [`blake3`] | All hashing, domain-separated via `BLAKE3-256("DSM/<name>\0" \|\| data)` |
//! | SPHINCS+ (BLAKE3-only) | [`sphincs`], [`signatures`] | Post-quantum EUF-CMA digital signatures |
//! | ML-KEM-768 (Kyber) | [`kyber`] | Post-quantum key encapsulation mechanism |
//! | Pedersen commitments | [`pedersen`] | Hiding + binding cryptographic commitments |
//! | C-DBRW | [`cdbrw_binding`] | Challenge-seeded DBRW anti-cloning (post-quantum) |
//! | ChaCha20-Poly1305 / AES-256-GCM | [`kyber`] (AES helpers) | Authenticated symmetric encryption |
//!
//! # Domain Separation Convention
//!
//! All BLAKE3 hashing in the protocol uses domain-separated tags of the form
//! `"DSM/<domain>\0"`, where `\0` is a literal NUL byte. The NUL terminator
//! prevents ambiguity between tags that share a common prefix. Use
//! [`blake3::dsm_domain_hasher`] to obtain a pre-loaded hasher.
//!
//! # Module Organisation
//!
//! - **Core hashing**: [`blake3`], [`hash`], [`canonical_lp`]
//! - **Signatures**: [`sphincs`] (low-level), [`signatures`] (high-level API), [`streaming_signature`]
//! - **Key exchange**: [`kyber`] (ML-KEM-768 + AES-GCM helpers)
//! - **Commitments**: [`pedersen`]
//! - **Anti-cloning**: [`cdbrw_binding`]
//! - **RNG**: [`rng`] (OS and deterministic random byte generation)
//! - **Privacy**: [`random_walk_privacy`]
//! - **Device memory**: [`device_memory_manager`]
//! - **Testing**: [`adb_test_utils`] (ADB-based hardware testing for C-DBRW)
//!
//! # Error handling
//!
//! Public crypto APIs return [`DsmError`]. `expect`/`unwrap` are limited to
//! `#[cfg(test)]` modules, property tests, and the `testing` feature (`SignatureKeyPair::generate_for_testing`).

use crate::types::error::DsmError;

// Re-export the main crypto modules
pub mod adb_test_utils;
pub mod blake3;
pub mod canonical_lp;
pub mod cdbrw_binding;
pub mod device_memory_manager;
pub mod ephemeral_key;
pub mod hash;
pub mod kyber;
pub mod pedersen;
pub mod random_walk_privacy;
pub mod rng;
pub mod signatures;
pub mod sphincs;
pub mod streaming_signature;

// Micro-level determinism property tests.
// Kept under `crypto` so they can access crypto primitives without exposing new APIs.
#[cfg(test)]
mod determinism_pbt_tests;

// SPHINCS+ property-based tests (round-trip, non-malleability, size, determinism).
#[cfg(test)]
mod sphincs_pbt_tests;

// SPHINCS+ Known Answer Tests (deterministic keygen stability, cross-key rejection).
#[cfg(test)]
mod sphincs_kat_tests;

// ML-KEM-768 / AES-GCM property-based tests (KEM round-trip, det keygen, AES tamper).
#[cfg(test)]
mod kyber_pbt_tests;

// ===== Re-exports (curated, no duplicates) =====

// Kyber (KEM + AES-GCM helpers)
pub use kyber::{
    aes_decrypt, aes_encrypt, generate_kyber_keypair, init_kyber, kyber_decapsulate,
    kyber_encapsulate, EncapsulationResult, KyberKeyPair,
};

// Pedersen
pub use pedersen::{PedersenCommitment, PedersenParams, SecurityLevel};

// SPHINCS+ low-level (when you need direct control)
pub use sphincs::SphincsKeyPair;

// High-level signing API (preferred)
pub use signatures::{sign_message, verify_signature, SignatureKeyPair};

// ===== Convenience wrappers =====

/// Generate a Kyber keypair and return `(public, secret)`.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let keypair = kyber::generate_kyber_keypair()?;
    Ok((keypair.public_key.clone(), keypair.secret_key.clone()))
}

/// Hash arbitrary data using domain-separated BLAKE3.
///
/// Applies the domain tag `"DSM/hash-data\0"` before hashing.
///
/// # Returns
///
/// A 32-byte BLAKE3 digest as `Vec<u8>`.
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    blake3::domain_hash("DSM/hash-data", data)
        .as_bytes()
        .to_vec()
}

/// Hash multiple byte slices into a single 32-byte digest.
///
/// Uses the domain tag `"DSM/hash-multiple\0"`. All parts are fed into
/// the hasher in order, producing a single BLAKE3 digest.
///
/// # Returns
///
/// A 32-byte BLAKE3 digest as `Vec<u8>`.
pub fn hash_multiple(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = blake3::dsm_domain_hasher("DSM/hash-multiple");
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().as_bytes().to_vec()
}

// ===== Initialization =====

/// Initialize crypto subsystems used by DSM.
pub fn init_crypto() -> Result<(), DsmError> {
    // Kyber KEM/AES
    kyber::init_kyber()?;

    // SPHINCS+ (ensures self-tests run at startup)
    sphincs::init_sphincs()?;

    Ok(())
}

// ===== Nonce generation =====
// Notes:
// - AES-GCM requires a 96-bit (12-byte) nonce. Use `generate_gcm_nonce`.
// - If you truly need a 32-byte nonce for some protocol, use `generate_nonce_32`.

/// Generate a random 12-byte nonce suitable for AES-GCM.
pub fn generate_gcm_nonce() -> Vec<u8> {
    // Use our RNG module to avoid accidental thread_rng usage.
    crate::crypto::rng::random_bytes(12)
}

/// Generate a random 32-byte nonce (only for protocols that require 256-bit nonces).
pub fn generate_nonce_32() -> Vec<u8> {
    crate::crypto::rng::random_bytes(32)
}

/// Generate a deterministic 12-byte nonce for state-machine operations (domain separated).
pub fn generate_deterministic_gcm_nonce(context: &[u8], counter: u64) -> Vec<u8> {
    let mut hasher = blake3::dsm_domain_hasher("DSM/deterministic-nonce-gcm");
    hasher.update(context);
    hasher.update(&counter.to_le_bytes());
    let hash = hasher.finalize();
    hash.as_bytes()[..12].to_vec()
}

/// Generate a deterministic 32-byte nonce (only for protocols that require 256-bit nonces).
pub fn generate_deterministic_nonce_32(context: &[u8], counter: u64) -> Vec<u8> {
    let mut hasher = blake3::dsm_domain_hasher("DSM/deterministic-nonce-32");
    hasher.update(context);
    hasher.update(&counter.to_le_bytes());
    let hash = hasher.finalize();
    hash.as_bytes()[..32].to_vec()
}

/// Generate a deterministic 32-byte nonce for OnlineTransferRequest.
/// Formula: Hash(domain || sender_id || receiver_id || prev_tip || seq || payload_digest)
/// - domain: "DSM:OnlineTransferRequest:nonce:v1"
/// - sender_id: from_device_id (32 bytes)
/// - receiver_id: to_device_id (32 bytes)  
/// - prev_tip: chain_tip (32 bytes)
/// - seq: sequence counter (u64)
/// - payload_digest: BLAKE3 hash of canonical request body excluding nonce (32 bytes)
pub fn generate_online_transfer_nonce(
    sender_id: &[u8; 32],
    receiver_id: &[u8; 32],
    prev_tip: &[u8; 32],
    seq: u64,
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/OnlineTransferRequest/nonce/v1");
    hasher.update(sender_id);
    hasher.update(receiver_id);
    hasher.update(prev_tip);
    hasher.update(&seq.to_le_bytes());
    hasher.update(payload_digest);
    *hasher.finalize().as_bytes()
}
