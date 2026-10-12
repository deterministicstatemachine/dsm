// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPHINCS+ signatures: the host's view of `dsm_sphincs`.
//!
//! The construction, the FIPS 205 (SLH-DSA) structure instantiated with
//! BLAKE3 (construction version 2), lives in `crates/dsm-sphincs`, the one
//! implementation the host and the RP2350 anchor firmware link. This module
//! maps its errors to `DsmError` and adds key generation from OS entropy.
//!
//! Keys are `pk = PK.seed ‖ PK.root` (2n bytes) and
//! `sk = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` (4n bytes). SPX256f is the
//! default for device keys; SPX128f signs the anchor partition.

use crate::types::error::DsmError;
use zeroize::Zeroizing;

pub use dsm_sphincs::{
    public_key_bytes, secret_key_bytes, signature_bytes, sizes, SphincsKeyPair, SphincsVariant,
    CONSTRUCTION_VERSION,
};

fn crypto_error(e: dsm_sphincs::Error) -> DsmError {
    let dsm_sphincs::Error::Crypto(why) = e;
    DsmError::crypto(why.message(), None::<std::io::Error>)
}

/// A key pair from 32 bytes of OS entropy.
pub fn generate_keypair(v: SphincsVariant) -> Result<SphincsKeyPair, DsmError> {
    let seed = Zeroizing::new(crate::crypto::rng::generate_secure_random(32)?);
    let seed32: &[u8; 32] = seed.as_slice().try_into().map_err(|e| {
        DsmError::crypto(
            format!(
                "OS entropy returned {} bytes for a 32-byte seed: {e}",
                seed.len()
            ),
            None::<std::io::Error>,
        )
    })?;
    generate_keypair_from_seed(v, seed32)
}

/// The key pair a 32-byte seed determines.
pub fn generate_keypair_from_seed(
    v: SphincsVariant,
    seed32: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    dsm_sphincs::generate_keypair_from_seed(v, seed32).map_err(crypto_error)
}

/// Sign `m` under `sk` (`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`).
pub fn sign(v: SphincsVariant, sk: &[u8], m: &[u8]) -> Result<Vec<u8>, DsmError> {
    dsm_sphincs::sign(v, sk, m).map_err(crypto_error)
}

/// Whether `sig` is a signature on `m` under `pk`. A key or signature of the
/// wrong length for `v` does not verify; an empty message is an error.
pub fn verify(v: SphincsVariant, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<bool, DsmError> {
    dsm_sphincs::verify(v, pk, m, sig).map_err(crypto_error)
}

// ===================== Default Variant Wrappers ==========================

/// Generate SPHINCS+ keypair using default variant (SPX256f).
///
/// SPX256f (fast): ~10x faster keygen than SPX256s, larger signatures
/// (49,856 vs 29,792 bytes). Acceptable since genesis only signs once
/// and bilateral transfers are infrequent. Target: genesis < 2 seconds.
pub fn generate_sphincs_keypair() -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let kp = generate_keypair(SphincsVariant::SPX256f)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

/// Sign a message using SPHINCS+ with default variant (SPX256f).
pub fn sphincs_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, DsmError> {
    sign(SphincsVariant::SPX256f, sk, msg)
}

/// Verify a SPHINCS+ signature using default variant (SPX256f).
/// Returns Ok(true) if valid, Ok(false) if invalid, or Err on other errors.
pub fn sphincs_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, DsmError> {
    verify(SphincsVariant::SPX256f, pk, msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_signs_with_the_shared_construction() -> Result<(), DsmError> {
        assert_eq!(CONSTRUCTION_VERSION, 2);
        let kp = generate_keypair(SphincsVariant::SPX128f)?;
        let sig = sign(SphincsVariant::SPX128f, &kp.secret_key, b"host")?;
        assert_eq!(
            sig,
            dsm_sphincs::sign(SphincsVariant::SPX128f, &kp.secret_key, b"host")
                .map_err(crypto_error)?
        );
        assert!(verify(
            SphincsVariant::SPX128f,
            &kp.public_key,
            b"host",
            &sig
        )?);
        Ok(())
    }

    #[test]
    fn a_construction_error_is_a_crypto_error() -> Result<(), DsmError> {
        let kp = generate_keypair(SphincsVariant::SPX128f)?;
        let err = sign(SphincsVariant::SPX128f, &kp.secret_key, b"")
            .expect_err("an empty message is not signed");
        assert!(
            err.to_string().contains("Cannot sign empty message"),
            "{err}"
        );
        Ok(())
    }
}
