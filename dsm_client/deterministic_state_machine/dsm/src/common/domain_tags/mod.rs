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
    use std::collections::HashSet;

    fn all_tags() -> Vec<&'static str> {
        let mut tags = dsm::all_tags();
        tags.extend_from_slice(djte::TAGS);
        tags
    }

    #[test]
    fn all_tags_are_unique() {
        let tags = all_tags();
        let set: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(set.len(), tags.len(), "All domain tags must be unique");
    }

    #[test]
    fn all_tags_have_expected_prefixes() {
        for tag in all_tags() {
            assert!(
                tag.starts_with("DSM/") || tag.starts_with("DJTE."),
                "Tag {tag:?} must use DSM/ or DJTE. prefix"
            );
        }
    }

    /// PREFIX-FREEDOM, evaluated on the bytes the hasher actually consumes.
    ///
    /// `hash.rs` argues that no length prefix is needed because the fields that
    /// follow a tag are fixed width. That argument holds only if the tag is
    /// self-delimiting. `dsm_domain_hasher` makes it so by writing `tag || 0x00`
    /// (`crypto/blake3.rs:170-173`): `"A"` and `"AB"` become `"A\0"` and
    /// `"AB\0"`, which differ at byte 1, so no tag can be a prefix of another.
    ///
    /// That reasoning breaks the moment a tag CONTAINS a NUL, because the hasher
    /// appends a second one and `"X\0"` becomes a strict prefix of `"X\0\0"`.
    /// Comparing the source strings would not see that — `"X"` is a prefix of
    /// `"X\0"` in the source too, but the interesting question is what the
    /// hasher receives. So this compares the hashed form.
    ///
    /// The check is pairwise and directional over every ordered pair, and it
    /// subsumes `all_tags_are_unique`: equal tags satisfy `starts_with` too.
    #[test]
    fn no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it() {
        let tags = all_tags();
        let hashed: Vec<(&str, Vec<u8>)> = tags
            .iter()
            .map(|t| {
                let mut bytes = t.as_bytes().to_vec();
                bytes.push(0); // the separator dsm_domain_hasher appends
                (*t, bytes)
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
                     hasher's NUL separator is applied. H(tag_a || rest) can then \
                     equal H(tag_b || rest'), so the two domains are not separated \
                     and the no-length-prefix argument in hash.rs does not hold."
                );
            }
        }
    }

    /// INVERTED from a characterization of the SDK trimming shim.
    ///
    /// It used to record that `TAG_DSM_DLV_OPEN_NUL` hashed differently in core
    /// than in the SDK, because `dsm_sdk::wire::domain_hash_bytes` called
    /// `tag.trim_end_matches('\0')` first. Both the shim and that tag's NUL are
    /// gone, so the property flips: NO registered tag carries a NUL, therefore
    /// no registered tag can hash differently between layers.
    ///
    /// SCOPE, unchanged and still important: `all_tags()` is the DECLARED
    /// REGISTRY, not the set of domains this repository hashes. Bare literals
    /// never reach this module, and some still carry a trailing NUL —
    /// `cert_resync.rs:363` and `kyber_identity.rs:29` are impact-table rows B3
    /// and B4 and are not fixed yet. Catching those needs a lint over call
    /// sites; a test that reads a registry can only speak for the registry.
    #[test]
    fn no_registered_tag_carries_a_nul_so_the_layers_cannot_diverge() {
        let tags = all_tags();

        let nul_suffixed: Vec<&str> = tags
            .iter()
            .copied()
            .filter(|t| *t != t.trim_end_matches('\0'))
            .collect();

        assert!(
            nul_suffixed.is_empty(),
            "these registered tags carry a NUL: {nul_suffixed:?}. The delimiter \
             belongs to the encoder, never to the constant — a tag that spells \
             it cannot be built as a TaggedHashDomain and would hash differently \
             depending on which helper a caller reached for."
        );

        // Belt and braces: with no NULs, trimming is the identity, so no two
        // declared tags can collapse into one another under any normalization.
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i >= j {
                    continue;
                }
                assert_ne!(
                    a.trim_end_matches('\0'),
                    b.trim_end_matches('\0'),
                    "tags {a:?} and {b:?} collapse to ONE domain under trimming"
                );
            }
        }
    }

    #[test]
    fn tags_do_not_trail_nul_except_compat_tags() {
        // NO tag may carry a NUL. The delimiter belongs to the encoder, never
        // to the constant — see docs/adr/0001. The last exception,
        // TAG_DSM_DLV_OPEN_NUL, became TAG_DSM_DLV_OPEN when the SDK's trimming
        // shim was deleted; that rename was proven byte-preserving by
        // dlv_open_digest_is_frozen_across_the_delimiter_cut.
        let allowed_trailing_nul: [&str; 0] = [];

        for tag in all_tags() {
            if allowed_trailing_nul.contains(&tag) {
                assert!(tag.ends_with('\0'), "Compat tag {tag:?} must end with NUL");
            } else {
                assert!(
                    !tag.ends_with('\0'),
                    "Tag {tag:?} must NOT be NUL-terminated; the hasher appends NUL"
                );
            }
        }
    }
}
