// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographically secure random bytes, drawn from the operating system.
//!
//! There is no seeded or deterministic mode: every draw comes from `OsRng`,
//! and an entropy-source failure aborts rather than returning weak bytes.

use crate::types::error::DsmError;
use rand::CryptoRng;
use rand::{rngs::OsRng, RngCore, TryRngCore};

/// A wrapper struct that implements `RngCore` + `CryptoRng` over [`random_bytes`].
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
}

impl CryptoRng for SecureRng {}

/// Generate cryptographically secure random bytes from OS entropy.
///
/// # Arguments
/// * `len` - number of bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    // OsRng failure is a fatal, unrecoverable system condition (entropy source
    // unavailable). We log the error and then hard-abort to avoid returning
    // weak/fake entropy while also satisfying clippy's no-panic production lint.
    let mut rng = OsRng;
    match rng.try_fill_bytes(&mut bytes) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!(error = %e, "OsRng failed to provide entropy");
            // SAFETY: abort is intentional here to fail-closed on entropy-source failure; continuing would risk weak randomness in production.
            std::process::abort();
        }
    }
    bytes
}

/// Generate cryptographically secure random bytes using OS entropy, reporting
/// an entropy-source failure as an error.
pub fn generate_secure_random(len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut bytes).map_err(|e| {
        DsmError::crypto(
            format!("OsRng entropy failure: {e}"),
            None::<std::io::Error>,
        )
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
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
}
