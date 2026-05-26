//! Domain tag constants for BLAKE3 domain-separated hashing.
//!
//! The dsm_domain_hasher(tag) primitive appends the trailing NUL byte at
//! hash time, so constants in this module are plain tag strings unless
//! explicitly suffixed with _NUL for compatibility cases.
//!
//! This module is intentionally split into scoped submodules so we keep a
//! single source of truth without one giant flat file.

mod bilateral_transport;
mod core;
mod crypto_keys;
mod djte;
mod genesis_identity;
mod misc;
mod policy_registry;
mod recovery;
mod vault_dbtc;

pub use core::*;
pub use djte::*;
pub use bilateral_transport::*;
pub use crypto_keys::*;
pub use genesis_identity::*;
pub use misc::*;
pub use policy_registry::*;
pub use recovery::*;
pub use vault_dbtc::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn all_tags() -> Vec<&'static str> {
        let mut tags = Vec::new();
        tags.extend_from_slice(core::TAGS);
        tags.extend_from_slice(bilateral_transport::TAGS);
        tags.extend_from_slice(crypto_keys::TAGS);
        tags.extend_from_slice(genesis_identity::TAGS);
        tags.extend_from_slice(misc::TAGS);
        tags.extend_from_slice(policy_registry::TAGS);
        tags.extend_from_slice(recovery::TAGS);
        tags.extend_from_slice(vault_dbtc::TAGS);
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
                tag.starts_with("DSM/") || tag.starts_with("DJTE.") || tag == TAG_NOT_DSM,
                "Tag {tag:?} must use DSM/ or DJTE. prefix (except TAG_NOT_DSM test sentinel)"
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
