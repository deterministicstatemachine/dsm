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

    #[test]
    fn tags_do_not_trail_nul_except_compat_tags() {
        let allowed_trailing_nul = [
            TAG_DSM_CONTACT_ADD_NUL,
            TAG_DSM_DLV_OPEN_NUL,
            TAG_DSM_DLV_PARTITION_NUL,
        ];

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
