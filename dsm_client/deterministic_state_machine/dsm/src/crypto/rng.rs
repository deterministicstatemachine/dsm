//! Cryptographically secure random number generation
//!
//! This module is initialized at startup to ensure proper randomness.
//! Notes:
//! - Deterministic RNG is intended for tests and reproducible runs. Never enable in prod.
//! - We avoid logging any seed material.
//! - Entropy mixing uses BLAKE3 XOF/KDF instead of ad-hoc expansion.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::sync::Mutex;

use crate::types::error::DsmError;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand::CryptoRng;

// Global flags/state
static RNG_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Single shared deterministic RNG (testing / reproducible runs).
// Guarded by a Mutex; when present, `random_bytes` draws from it.
static DETERMINISTIC_RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();

/// A wrapper struct that implements `RngCore` + `CryptoRng`
/// and delegates to `random_bytes` (which respects the deterministic flag).
pub struct SecureRng;

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = random_bytes(dest.len());
        dest.copy_from_slice(&bytes);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SecureRng {}

/// Ensure the RNG subsystem is initialized (idempotent & race-safe).
pub fn ensure_rng_initialization() {
    // Fast path if we've already done a probe once
    if RNG_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    // Probe OS RNG
    let _ = random_bytes(8);

    // Mark initialized
    RNG_INITIALIZED.store(true, Ordering::SeqCst);
    tracing::info!("Random number generator subsystem initialized");
}

/// Initialize RNG with a deterministic seed (for testing / reproducibility).
/// This replaces any existing deterministic RNG instance.
/// WARNING: Do not call this in production paths.
pub fn init_with_seed(seed: u64) {
    // Derive a 32-byte key from the u64 using BLAKE3 derive_key for domain separation.
    let mut seed_key = blake3::derive_key("DSM:deterministic-rng:u64", &seed.to_le_bytes());

    // Build ChaCha20Rng from derived key
    let rng = ChaCha20Rng::from_seed(seed_key);

    // Zero the derived key from stack as a hygiene (not strictly necessary).
    seed_key.fill(0);

    // Install/replace the global deterministic RNG.
    match DETERMINISTIC_RNG.get() {
        Some(lock) => {
            if let Ok(mut g) = lock.lock() {
                *g = rng;
            } else {
                tracing::error!("Failed to acquire deterministic RNG lock");
            }
        }
        None => {
            let _ = DETERMINISTIC_RNG.set(Mutex::new(rng));
        }
    }

    RNG_INITIALIZED.store(true, Ordering::SeqCst);
    // Do not log seed or derived material.
    tracing::info!("Deterministic RNG initialized (testing/repro)");
}

/// Generate cryptographically secure random bytes.
/// Uses deterministic RNG if initialized via `init_with_seed`, otherwise OS RNG.
///
/// # Arguments
/// * `len` - number of bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];

    // If a deterministic RNG is installed, use it under lock
    if let Some(lock) = DETERMINISTIC_RNG.get() {
        if let Ok(mut rng) = lock.lock() {
            rng.fill_bytes(&mut bytes);
            return bytes;
        } else {
            tracing::error!("Deterministic RNG poisoned; falling back to OS RNG");
        }
    }

    // Fall back to strong OS entropy
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate cryptographically secure random bytes using OS entropy.
///
/// This returns Ok always unless the OS RNG panics; if you want explicit failure
/// handling, wire this to `getrandom`/`try_fill_bytes` in your rand version.
pub fn generate_secure_random(len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Generate deterministic random bytes from arbitrary seed material.
///
/// Uses BLAKE3 KDF to derive a 32-byte key, then seeds ChaCha20Rng.
/// Suitable for tests and reproducible benchmarks.
///
/// # Arguments
/// * `seed` - arbitrary-length seed material
/// * `len`  - number of bytes
pub fn generate_deterministic_random(seed: &[u8], len: usize) -> Vec<u8> {
    // Derive a 32-byte key from the seed with domain separation.
    let key = blake3::derive_key("DSM:deterministic-rng:arbitrary-seed", seed);
    let mut rng = ChaCha20Rng::from_seed(key);

    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Mix multiple entropy sources to create a single output using BLAKE3 XOF.
///
/// This is preferable to ad-hoc hash+counter expansion.
/// Domain separation is included via a context string.
pub fn mix_entropy(sources: &[&[u8]], output_len: usize) -> Vec<u8> {
    // Hash all sources with a domain separator
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/det-rng-seed");
    for src in sources {
        // Prefix each source with its length to avoid ambiguous concatenations
        let len = (src.len() as u64).to_le_bytes();
        hasher.update(&len);
        hasher.update(src);
    }

    // Use XOF to produce exactly output_len bytes
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        ensure_rng_initialization();
        let random1 = random_bytes(32);
        let random2 = random_bytes(32);
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        // Extremely likely to differ
        assert_ne!(random1, random2);
    }

    #[test]
    fn test_generate_secure_random() -> Result<(), DsmError> {
        let random1 = generate_secure_random(32)?;
        let random2 = generate_secure_random(32)?;
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2);
        Ok(())
    }

    #[allow(clippy::similar_names)]
    #[test]
    fn test_generate_deterministic_random() {
        let seed1 = b"test seed 1";
        let seed2 = b"test seed 2";

        // Same seed -> same output
        let det1a = generate_deterministic_random(seed1, 32);
        let det1b = generate_deterministic_random(seed1, 32);
        assert_eq!(det1a, det1b);

        // Different seed -> different output
        let det2a = generate_deterministic_random(seed2, 32);
        assert_ne!(det1a, det2a);
    }

    #[test]
    fn test_mix_entropy() {
        let source1 = b"entropy source 1";
        let source2 = b"entropy source 2";

        // Same order -> same output
        let mix1 = mix_entropy(&[source1, source2], 32);
        let mix2 = mix_entropy(&[source1, source2], 32);
        assert_eq!(mix1, mix2);

        // Different order -> different output
        let mix3 = mix_entropy(&[source2, source1], 32);
        assert_ne!(mix1, mix3);

        // Output length should be respected
        let mix4 = mix_entropy(&[source1, source2], 64);
        assert_eq!(mix4.len(), 64);
    }

    #[test]
    fn test_init_with_seed_global() {
        init_with_seed(42);
        let a = random_bytes(16);
        let b = random_bytes(16);
        // Deterministic global RNG produces a sequence; two draws should differ,
        // but repeating from the start (by re-seeding) should match.
        init_with_seed(42);
        let a2 = random_bytes(16);
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }
}
