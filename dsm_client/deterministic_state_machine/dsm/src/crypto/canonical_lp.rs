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
use crate::types::error::DsmError;

/// The length prefix of a field `len` bytes long: `u32` little-endian.
///
/// A field longer than `u32::MAX` bytes has no 4-byte prefix and is refused.
/// Two such fields of different lengths would otherwise share one prefix, and
/// the framing that keeps `lp(a) ‖ lp(b)` unambiguous would not hold.
#[inline]
pub fn lp_prefix(len: usize) -> Result<[u8; 4], DsmError> {
    u32::try_from(len).map(u32::to_le_bytes).map_err(|e| {
        DsmError::invalid_parameter(format!(
            "a length-prefixed field of {len} bytes exceeds the 4-byte prefix's bound of {} \
             bytes and is not hashed: {e}",
            u32::MAX
        ))
    })
}

/// Write a length-prefixed byte slice into the hasher.
///
/// Length prefix is `u32` little-endian ([`lp_prefix`]), followed by raw
/// bytes. A slice the prefix cannot frame is refused before anything is
/// written.
#[inline]
pub fn write_lp(hasher: &mut Hasher, bytes: &[u8]) -> Result<(), DsmError> {
    let prefix = lp_prefix(bytes.len())?;
    hasher.update(&prefix);
    hasher.update(bytes);
    Ok(())
}

/// Hash a domain-separated sequence of 1 length-prefixed fields.
#[inline]
pub fn hash_lp1(domain: TaggedHashDomain<'_>, a: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a)?;
    Ok(*h.finalize().as_bytes())
}

/// Hash a domain-separated sequence of 2 length-prefixed fields.
#[inline]
pub fn hash_lp2(domain: TaggedHashDomain<'_>, a: &[u8], b: &[u8]) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a)?;
    write_lp(&mut h, b)?;
    Ok(*h.finalize().as_bytes())
}

/// Hash a domain-separated sequence of 3 length-prefixed fields.
#[inline]
pub fn hash_lp3(
    domain: TaggedHashDomain<'_>,
    a: &[u8],
    b: &[u8],
    c: &[u8],
) -> Result<[u8; 32], DsmError> {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_CANONICAL_LP);
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    write_lp(&mut h, a)?;
    write_lp(&mut h, b)?;
    write_lp(&mut h, c)?;
    Ok(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    // Validated test domains. Deliberately prefix-related — b"DSM/d" is a
    // prefix of b"DSM/dom" — because that is the ambiguity the canonical
    // delimiter removes.
    const D_A: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/domain-a");
    const D_B: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/domain-b");
    const D_DOM: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/dom");
    const D_D: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/d");

    use super::*;

    #[test]
    fn write_lp_prepends_length_prefix() -> Result<(), DsmError> {
        let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        write_lp(&mut h, b"hello")?;
        let mut explicit = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        explicit.update(&5u32.to_le_bytes());
        explicit.update(b"hello");
        assert_eq!(h.finalize(), explicit.finalize());
        Ok(())
    }

    #[test]
    fn write_lp_empty_input() -> Result<(), DsmError> {
        let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        write_lp(&mut h, b"")?;
        let mut explicit = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_TEST);
        explicit.update(&0u32.to_le_bytes());
        assert_eq!(h.finalize(), explicit.finalize());
        Ok(())
    }

    /// MR-DSM-0248. Every length the 4-byte prefix can frame is framed as its
    /// exact `u32` little-endian value, and the first length it cannot frame,
    /// `u32::MAX + 1`, is refused, as is every length beyond it. Before this
    /// the prefix saturated: every field over 4 GiB was written with the
    /// prefix of `u32::MAX`, so two such fields of different lengths shared a
    /// prefix.
    ///
    /// The bound is tested on [`lp_prefix`], the one function `write_lp`
    /// takes its prefix from, because a `&[u8]` one byte over the bound
    /// cannot be built here without backing it: the crate forbids `unsafe`
    /// (so no slice over unbacked memory), and the safe constructions all
    /// allocate the 4 GiB the test may not.
    ///
    /// MUTATION CONTROL: saturate the prefix again in `lp_prefix` and this
    /// goes red.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_length_one_byte_over_the_prefix_bound_is_refused() -> Result<(), DsmError> {
        let bound = usize::try_from(u32::MAX)
            .map_err(|e| DsmError::invalid_parameter(format!("u32::MAX as usize: {e}")))?;
        for len in [0, 1, bound - 1, bound] {
            assert_eq!(
                lp_prefix(len)?,
                u32::try_from(len)
                    .map_err(|e| DsmError::invalid_parameter(format!("{len}: {e}")))?
                    .to_le_bytes(),
                "a length the prefix frames is framed as itself: {len}"
            );
        }
        assert_eq!(lp_prefix(bound)?, [0xFF; 4]);
        for len in [bound + 1, bound + 2, usize::MAX] {
            assert!(
                matches!(lp_prefix(len), Err(DsmError::InvalidParameter(_))),
                "a length the prefix cannot frame must be refused: {len}"
            );
        }
        Ok(())
    }

    #[test]
    fn hash_lp1_deterministic() -> Result<(), DsmError> {
        let a = hash_lp1(D_A, b"field1")?;
        let b = hash_lp1(D_A, b"field1")?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp1_different_domain_different_hash() -> Result<(), DsmError> {
        let a = hash_lp1(D_A, b"data")?;
        let b = hash_lp1(D_B, b"data")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp1_different_data_different_hash() -> Result<(), DsmError> {
        let a = hash_lp1(D_DOM, b"x")?;
        let b = hash_lp1(D_DOM, b"y")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp2_deterministic() -> Result<(), DsmError> {
        let a = hash_lp2(D_DOM, b"f1", b"f2")?;
        let b = hash_lp2(D_DOM, b"f1", b"f2")?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp2_order_matters() -> Result<(), DsmError> {
        let a = hash_lp2(D_DOM, b"first", b"second")?;
        let b = hash_lp2(D_DOM, b"second", b"first")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp3_deterministic() -> Result<(), DsmError> {
        let a = hash_lp3(D_DOM, b"a", b"b", b"c")?;
        let b = hash_lp3(D_DOM, b"a", b"b", b"c")?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn hash_lp3_differs_from_lp2() -> Result<(), DsmError> {
        let h2 = hash_lp2(D_DOM, b"a", b"b")?;
        let h3 = hash_lp3(D_DOM, b"a", b"b", b"")?;
        assert_ne!(h2, h3);
        Ok(())
    }

    /// RE-AIMED. This used to pass `b""` as a domain and assert only the output
    /// length. An empty domain is now unrepresentable, so the meaningful
    /// statement is that the type refuses it — the compiler caught this case,
    /// which the impact table had not listed.
    #[test]
    fn an_empty_domain_cannot_be_built() -> Result<(), DsmError> {
        assert!(TaggedHashDomain::try_new(b"").is_err());
        assert_eq!(hash_lp1(D_DOM, b"")?.len(), 32);
        Ok(())
    }

    /// NEW, and the reason the old prefix-related literals existed. `hash_lp`
    /// used to write the domain RAW, so separation between `b"DSM/d"`,
    /// `b"DSM/dom"` and `b"DSM/domain-a"` rested on the caller spelling a
    /// terminator. The encoder now
    /// appends exactly one delimiter, so prefix-freedom is structural.
    #[test]
    fn a_domain_that_is_a_prefix_of_another_is_still_separated() -> Result<(), DsmError> {
        let short = hash_lp1(D_D, b"ompayload")?;
        let long = hash_lp1(D_DOM, b"payload")?;
        assert_ne!(
            short, long,
            "H(DSM/d || 0x00 || 'ompayload') collided with H(DSM/dom || 0x00 || 'payload'); \
             the delimiter is not separating prefix-related domains"
        );
        Ok(())
    }

    #[test]
    fn length_prefix_prevents_concatenation_collision() -> Result<(), DsmError> {
        let a = hash_lp2(D_DOM, b"ab", b"cd")?;
        let b = hash_lp2(D_DOM, b"abc", b"d")?;
        assert_ne!(a, b, "length prefix must prevent ab|cd == abc|d collision");
        Ok(())
    }

    #[test]
    fn all_outputs_are_32_bytes() -> Result<(), DsmError> {
        assert_eq!(hash_lp1(D_D, b"a")?.len(), 32);
        assert_eq!(hash_lp2(D_D, b"a", b"b")?.len(), 32);
        assert_eq!(hash_lp3(D_D, b"a", b"b", b"c")?.len(), 32);
        Ok(())
    }
}
