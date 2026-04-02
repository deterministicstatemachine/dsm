//! Canonical length-prefixed byte writer for commitment hashing.
//!
//! Motivation: avoid scattering
//! manual `hasher.update(...)` sequences across the codebase. Centralize the
//! canonical preimage format (domain-separated + length-prefixed fields) so
//! cryptographic contracts stay stable as business structs evolve.
//!
//! This module is **protocol-path safe**:
//! - no wall-clock usage
//! - no JSON/serde encoding
//! - deterministic bytes only

use blake3::Hasher;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;

/// Write a length-prefixed byte slice into the hasher.
///
/// Length prefix is `u32` little-endian, followed by raw bytes.
/// Returns [`Err`] if `bytes.len()` does not fit in `u32`.
#[inline]
pub fn write_lp(hasher: &mut Hasher, bytes: &[u8]) -> Result<(), DsmError> {
    let len: u32 = bytes.len().try_into().map_err(|_| {
        DsmError::crypto_op(
            "canonical_lp",
            "field length exceeds u32::MAX",
            Option::<String>::None,
        )
    })?;
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

/// Same encoding as [`write_lp`] for an exactly-32-byte field (infallible).
#[inline]
pub fn write_lp_b32(hasher: &mut Hasher, bytes: &[u8; 32]) {
    hasher.update(&32u32.to_le_bytes());
    hasher.update(bytes.as_slice());
}

/// Append one canonical LP field to a `Vec` (same encoding as [`write_lp`]).
#[inline]
pub fn append_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DsmError> {
    let len: u32 = bytes.len().try_into().map_err(|_| {
        DsmError::crypto_op(
            "canonical_lp",
            "field length exceeds u32::MAX",
            Option::<String>::None,
        )
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Hash a domain-separated sequence of 1 length-prefixed field.
#[inline]
pub fn hash_lp1(domain: &[u8], a: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a)?;
    Ok(*h.finalize().as_bytes())
}

/// [`hash_lp1`] when the payload is exactly 32 bytes (e.g. a state/commitment root).
#[inline]
pub fn hash_lp1_b32(domain: &[u8], a: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp_b32(&mut h, a);
    *h.finalize().as_bytes()
}

/// Hash a domain-separated sequence of 2 length-prefixed fields.
#[inline]
pub fn hash_lp2(domain: &[u8], a: &[u8], b: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a)?;
    write_lp(&mut h, b)?;
    Ok(*h.finalize().as_bytes())
}

/// Hash a domain-separated sequence of 3 length-prefixed fields.
#[inline]
pub fn hash_lp3(domain: &[u8], a: &[u8], b: &[u8], c: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a)?;
    write_lp(&mut h, b)?;
    write_lp(&mut h, c)?;
    Ok(*h.finalize().as_bytes())
}
