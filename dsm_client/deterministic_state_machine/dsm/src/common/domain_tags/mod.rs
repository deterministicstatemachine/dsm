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

    /// CHARACTERIZATION of the SDK trimming shim, from the tag side.
    ///
    /// `dsm_sdk::wire::domain_hash_bytes` calls `tag.trim_end_matches('\0')`
    /// before hashing, while `dsm_domain_hasher` does not. So for any tag whose
    /// declared value ends with a NUL, the two layers hash DIFFERENT bytes for
    /// the same declared domain, and any two tags that differ only by a trailing
    /// NUL become the SAME domain on the SDK side.
    ///
    /// This records the state before the delimiter cut. It is not the fix: the
    /// fix is one canonical implementation with no silent trimming. It pins two
    /// things so the cut can be judged:
    ///
    ///   - which tags are affected at all (those ending in NUL), and
    ///   - that no two DECLARED tags currently collapse into one another under
    ///     trimming, which is what makes the shim survivable today rather than
    ///     actively wrong.
    ///
    /// If someone re-adds an `X` / `X\0` pair, the second assertion fails and
    /// says why. Both `TAG_DSM_CONTACT_ADD_NUL` and `TAG_DSM_DLV_PARTITION_NUL`
    /// were exactly such a pair before they were deleted.
    #[test]
    fn characterize_which_tags_the_sdk_trimming_shim_changes() {
        let tags = all_tags();

        let nul_suffixed: Vec<&str> = tags
            .iter()
            .copied()
            .filter(|t| *t != t.trim_end_matches('\0'))
            .collect();

        // Exactly one tag is affected today. It is the only one the SDK shim
        // hashes differently from core.
        assert_eq!(
            nul_suffixed,
            vec![TAG_DSM_DLV_OPEN_NUL],
            "the set of tags whose bytes differ between core and the SDK shim \
             changed; every tag listed here is hashed as `tag || 0x00` by \
             dsm_domain_hasher and as `trim(tag) || 0x00` by \
             dsm_sdk::wire::domain_hash_bytes"
        );

        // No two DECLARED tags may become the same domain once trimmed.
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i >= j {
                    continue;
                }
                assert_ne!(
                    a.trim_end_matches('\0'),
                    b.trim_end_matches('\0'),
                    "tags {a:?} and {b:?} are distinct as declared but collapse to \
                     ONE domain inside dsm_sdk::wire::domain_hash_bytes, which \
                     trims the trailing NUL. Two logical domains sharing a digest \
                     space is a domain-separation failure, not a naming quirk."
                );
            }
        }
    }

    #[test]
    fn tags_do_not_trail_nul_except_compat_tags() {
        // TAG_DSM_DLV_OPEN_NUL is the ONLY tag permitted to carry a NUL, and
        // only because no plain "DSM/dlv/open" exists for it to shadow. The
        // CONTACT_ADD and DLV_PARTITION _NUL variants were deleted: each had a
        // plain sibling, so `sibling\0` was a strict prefix of `variant\0\0`
        // once the hasher appended its separator — see
        // no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it.
        let allowed_trailing_nul = [TAG_DSM_DLV_OPEN_NUL];

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
