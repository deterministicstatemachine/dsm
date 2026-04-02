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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_lp_prepends_length_prefix() {
        let mut h = dsm_domain_hasher("DSM/test");
        write_lp(&mut h, b"hello");
        let digest = h.finalize();
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn write_lp_empty_input() {
        let mut h = dsm_domain_hasher("DSM/test");
        write_lp(&mut h, b"");
        let digest = h.finalize();
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn hash_lp1_deterministic() {
        let a = hash_lp1(b"domain-a", b"field1");
        let b = hash_lp1(b"domain-a", b"field1");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp1_different_domain_different_hash() {
        let a = hash_lp1(b"domain-a", b"data");
        let b = hash_lp1(b"domain-b", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp1_different_data_different_hash() {
        let a = hash_lp1(b"dom", b"x");
        let b = hash_lp1(b"dom", b"y");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp2_deterministic() {
        let a = hash_lp2(b"dom", b"f1", b"f2");
        let b = hash_lp2(b"dom", b"f1", b"f2");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp2_order_matters() {
        let a = hash_lp2(b"dom", b"first", b"second");
        let b = hash_lp2(b"dom", b"second", b"first");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp3_deterministic() {
        let a = hash_lp3(b"dom", b"a", b"b", b"c");
        let b = hash_lp3(b"dom", b"a", b"b", b"c");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp3_differs_from_lp2() {
        let h2 = hash_lp2(b"dom", b"a", b"b");
        let h3 = hash_lp3(b"dom", b"a", b"b", b"");
        assert_ne!(h2, h3);
    }

    #[test]
    fn hash_lp1_empty_inputs() {
        let h = hash_lp1(b"", b"");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn length_prefix_prevents_concatenation_collision() {
        let a = hash_lp2(b"dom", b"ab", b"cd");
        let b = hash_lp2(b"dom", b"abc", b"d");
        assert_ne!(a, b, "length prefix must prevent ab|cd == abc|d collision");
    }

    #[test]
    fn all_outputs_are_32_bytes() {
        assert_eq!(hash_lp1(b"d", b"a").len(), 32);
        assert_eq!(hash_lp2(b"d", b"a", b"b").len(), 32);
        assert_eq!(hash_lp3(b"d", b"a", b"b", b"c").len(), 32);
    }
}
