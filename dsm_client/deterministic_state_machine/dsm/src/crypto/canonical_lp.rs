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

/// Write a length-prefixed byte slice into the hasher.
///
/// Length prefix is `u32` little-endian, followed by raw bytes.
#[inline]
pub fn write_lp(hasher: &mut Hasher, bytes: &[u8]) {
    let len: u32 = bytes.len().try_into().unwrap_or(u32::MAX);
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
}

/// Hash a domain-separated sequence of 1 length-prefixed fields.
#[inline]
pub fn hash_lp1(domain: &[u8], a: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a);
    *h.finalize().as_bytes()
}

/// Hash a domain-separated sequence of 2 length-prefixed fields.
#[inline]
pub fn hash_lp2(domain: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a);
    write_lp(&mut h, b);
    *h.finalize().as_bytes()
}

/// Hash a domain-separated sequence of 3 length-prefixed fields.
#[inline]
pub fn hash_lp3(domain: &[u8], a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/canonical-lp");
    h.update(domain);
    write_lp(&mut h, a);
    write_lp(&mut h, b);
    write_lp(&mut h, c);
    *h.finalize().as_bytes()
}
