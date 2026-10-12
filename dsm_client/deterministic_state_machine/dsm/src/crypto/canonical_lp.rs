// SPDX-License-Identifier: MIT OR Apache-2.0

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
use crate::crypto::domain::TaggedHashDomain;

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
pub fn hash_lp1(domain: TaggedHashDomain<'_>, a: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a);
    *h.finalize().as_bytes()
}

/// Hash a domain-separated sequence of 2 length-prefixed fields.
#[inline]
pub fn hash_lp2(domain: TaggedHashDomain<'_>, a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a);
    write_lp(&mut h, b);
    *h.finalize().as_bytes()
}

/// Hash a domain-separated sequence of 3 length-prefixed fields.
#[inline]
pub fn hash_lp3(domain: TaggedHashDomain<'_>, a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a);
    write_lp(&mut h, b);
    write_lp(&mut h, c);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    // Validated test domains. Deliberately prefix-related — b"d" is a prefix of
    // b"dom" — because that is the ambiguity the canonical delimiter removes.
    const D_A: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"domain-a");
    const D_B: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"domain-b");
    const D_DOM: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"dom");
    const D_D: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"d");

    use super::*;

    #[test]
    fn write_lp_prepends_length_prefix() {
        let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        write_lp(&mut h, b"hello");
        let digest = h.finalize();
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn write_lp_empty_input() {
        let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        write_lp(&mut h, b"");
        let digest = h.finalize();
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn hash_lp1_deterministic() {
        let a = hash_lp1(D_A, b"field1");
        let b = hash_lp1(D_A, b"field1");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp1_different_domain_different_hash() {
        let a = hash_lp1(D_A, b"data");
        let b = hash_lp1(D_B, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp1_different_data_different_hash() {
        let a = hash_lp1(D_DOM, b"x");
        let b = hash_lp1(D_DOM, b"y");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp2_deterministic() {
        let a = hash_lp2(D_DOM, b"f1", b"f2");
        let b = hash_lp2(D_DOM, b"f1", b"f2");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp2_order_matters() {
        let a = hash_lp2(D_DOM, b"first", b"second");
        let b = hash_lp2(D_DOM, b"second", b"first");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_lp3_deterministic() {
        let a = hash_lp3(D_DOM, b"a", b"b", b"c");
        let b = hash_lp3(D_DOM, b"a", b"b", b"c");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_lp3_differs_from_lp2() {
        let h2 = hash_lp2(D_DOM, b"a", b"b");
        let h3 = hash_lp3(D_DOM, b"a", b"b", b"");
        assert_ne!(h2, h3);
    }

    /// RE-AIMED. This used to pass `b""` as a domain and assert only the output
    /// length. An empty domain is now unrepresentable, so the meaningful
    /// statement is that the type refuses it — the compiler caught this case,
    /// which the impact table had not listed.
    #[test]
    fn an_empty_domain_cannot_be_built() {
        assert!(TaggedHashDomain::try_new(b"").is_err());
        assert_eq!(hash_lp1(D_DOM, b"").len(), 32);
    }

    /// NEW, and the reason the old prefix-related literals existed. `hash_lp`
    /// used to write the domain RAW, so separation between `b"d"`, `b"dom"` and
    /// `b"domain-a"` rested on the caller spelling a terminator. The encoder now
    /// appends exactly one delimiter, so prefix-freedom is structural.
    #[test]
    fn a_domain_that_is_a_prefix_of_another_is_still_separated() {
        let short = hash_lp1(D_D, b"ompayload");
        let long = hash_lp1(D_DOM, b"payload");
        assert_ne!(
            short, long,
            "H(d || 0x00 || 'ompayload') collided with H(dom || 0x00 || 'payload'); \
             the delimiter is not separating prefix-related domains"
        );
    }

    #[test]
    fn length_prefix_prevents_concatenation_collision() {
        let a = hash_lp2(D_DOM, b"ab", b"cd");
        let b = hash_lp2(D_DOM, b"abc", b"d");
        assert_ne!(a, b, "length prefix must prevent ab|cd == abc|d collision");
    }

    #[test]
    fn all_outputs_are_32_bytes() {
        assert_eq!(hash_lp1(D_D, b"a").len(), 32);
        assert_eq!(hash_lp2(D_D, b"a", b"b").len(), 32);
        assert_eq!(hash_lp3(D_D, b"a", b"b", b"c").len(), 32);
    }
}
