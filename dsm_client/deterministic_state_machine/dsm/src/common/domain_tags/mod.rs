// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain tag constants for BLAKE3 domain-separated hashing.
//!
//! The dsm_domain_hasher(tag) primitive appends the trailing NUL byte at
//! hash time, so constants in this module are plain tag strings unless
//! explicitly suffixed with _NUL for compatibility cases.
//!
//! This module is intentionally split into a hierarchical structure so DSM
//! and DJTE namespaces remain easy to navigate and maintain.

mod djte;
mod dsm;

pub use dsm::*;
pub use djte::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::domain::TaggedHashDomain;
    use std::collections::HashSet;

    fn all_tags() -> Vec<TaggedHashDomain<'static>> {
        let mut tags = dsm::all_tags();
        tags.extend_from_slice(djte::TAGS);
        tags
    }

    #[test]
    fn all_tags_are_unique() {
        let tags = all_tags();
        let set: HashSet<&[u8]> = tags.iter().map(|t| t.source_bytes()).collect();
        assert_eq!(set.len(), tags.len(), "All domain tags must be unique");
    }

    #[test]
    fn all_tags_have_expected_prefixes() {
        for tag in all_tags() {
            let b = tag.source_bytes();
            assert!(
                b.starts_with(b"DSM/") || b.starts_with(b"DJTE."),
                "Tag {:?} must use DSM/ or DJTE. prefix",
                String::from_utf8_lossy(b)
            );
        }
    }

    /// PREFIX-FREEDOM, evaluated on the bytes the hasher actually consumes.
    ///
    /// The no-length-prefix argument in `hash.rs` holds only if a tag is
    /// self-delimiting. `tagged_hasher` makes it so by writing
    /// `source_bytes() || 0x00`, so `"A"` and `"AB"` become `"A\0"` and `"AB\0"`
    /// and differ at byte 1.
    ///
    /// That reasoning used to break when a tag CONTAINED a NUL, because the
    /// hasher appended a second one and `"X\0"` became a strict prefix of
    /// `"X\0\0"`. `TaggedHashDomain` now makes such a tag unrepresentable, so
    /// this test can no longer fail that way — but it is kept, because a tag
    /// that is a plain prefix of another (`"DSM/a"` vs `"DSM/ab"`) is still
    /// expressible and still must not collide once encoded.
    #[test]
    fn no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it() {
        let tags = all_tags();
        let hashed: Vec<(String, Vec<u8>)> = tags
            .iter()
            .map(|t| {
                let mut bytes = t.source_bytes().to_vec();
                bytes.push(0); // the separator tagged_hasher appends
                (
                    String::from_utf8_lossy(t.source_bytes()).into_owned(),
                    bytes,
                )
            })
            .collect();

        for (i, (name_a, a)) in hashed.iter().enumerate() {
            for (j, (name_b, b)) in hashed.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !b.starts_with(a),
                    "domain tag {name_a:?} is a prefix of {name_b:?} once the \
                     encoder's NUL separator is applied. H(tag_a || rest) can then \
                     equal H(tag_b || rest'), so the two domains are not separated."
                );
            }
        }
    }

    /// Was a runtime check; now a statement about the type.
    ///
    /// Every registered tag is a `TaggedHashDomain`, and neither constructor can
    /// produce one containing a NUL — `from_static` rejects at COMPILE time and
    /// `try_new` at construction. So "no registered tag carries a NUL" is not
    /// something this test discovers, it is something the type guarantees; the
    /// assertion below can only fail if a third constructor is ever added.
    ///
    /// That is the whole point of the cut: the invariant moved from a test that
    /// had to be remembered to a type that cannot be bypassed.
    #[test]
    fn no_registered_tag_can_carry_a_nul_by_construction() {
        for tag in all_tags() {
            assert!(
                !tag.source_bytes().contains(&0),
                "a registered tag contains a NUL, which TaggedHashDomain should \
                 have made unrepresentable — a constructor was added that does \
                 not validate"
            );
        }

        // The guarantee itself, exercised directly.
        assert!(TaggedHashDomain::try_new(b"DSM/x\0").is_err());
        assert!(TaggedHashDomain::try_new(b"DSM/a\0b").is_err());
        assert!(TaggedHashDomain::try_new(b"").is_err());
    }
}
