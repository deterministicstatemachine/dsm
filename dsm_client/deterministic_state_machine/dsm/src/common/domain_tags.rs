//! Centralized domain tag constants for BLAKE3 domain-separated hashing.
//!
//! # NUL terminator convention (Issue #182 Finding #3 resolution)
//!
//! These constants do NOT include a trailing `\0` byte. The
//! `dsm::crypto::blake3::dsm_domain_hasher(tag)` primitive APPENDS the
//! NUL terminator automatically when constructing the BLAKE3 preimage:
//!
//! ```text
//! BLAKE3-256("DSM/<domain>\0" || data)
//! ```
//!
//! Storing the constants without the trailing NUL eliminates the
//! double-NUL footgun: a caller writing
//! `dsm_domain_hasher(TAG_RECEIPT_COMMIT)` in this convention produces
//! exactly one NUL in the preimage. Production hashing already uses
//! inline string literals like `dsm_domain_hasher("DSM/smt-leaf")` (no
//! trailing NUL) — this convention now matches.
//!
//! Whitepaper alignment: §2.1 specifies `H_X(input) := BLAKE3-256(tag
//! || NUL || input)` where the NUL is part of the *primitive*, not the
//! tag identifier. So tag identifiers carried as Rust `&str` constants
//! should NOT include the NUL byte.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit";
pub const TAG_SMT_NODE: &str = "DSM/smt-node";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf";
pub const TAG_DBRW: &str = "DSM/dbrw";
// Device Tree (standard Merkle) — see Issue #182 Finding #2 for the
// open spec ambiguity between §2.2 (`merkle-node`/`merkle-leaf`) and
// §16.3 (`dev-merkle`/`dev-empty`). Implementation continues to use
// the §16.3 ("normative") tags pending Brandon's resolution.
pub const TAG_DEV_MERKLE: &str = "DSM/dev-merkle";
pub const TAG_DEV_LEAF: &str = "DSM/dev-leaf";
pub const TAG_DEV_EMPTY: &str = "DSM/dev-empty";

// `tagged_bytes()` REMOVED — Issue #182 Finding #3.
// The helper was only used in the module's own self-tests and had
// ambiguous semantics relative to the auto-NUL `dsm_domain_hasher`
// primitive. Use `dsm::crypto::blake3::dsm_domain_hasher(tag)` (or
// `domain_hash`/`domain_hash_bytes`) for all domain-separated hashing.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Tags MUST NOT include the trailing NUL — the hasher primitive
    /// appends it. See module docs for the convention rationale.
    #[test]
    fn all_tags_have_no_trailing_nul() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
        ];
        for tag in &tags {
            assert!(
                !tag.ends_with('\0'),
                "Tag {tag:?} must NOT be NUL-terminated; the hasher appends NUL"
            );
            assert!(!tag.is_empty(), "Tag must not be empty");
        }
    }

    #[test]
    fn all_tags_are_unique() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
        ];
        let set: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(set.len(), tags.len(), "All domain tags must be unique");
    }

    #[test]
    fn all_tags_start_with_dsm_prefix() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
        ];
        for tag in &tags {
            assert!(tag.starts_with("DSM/"), "Tag {tag:?} must start with DSM/");
        }
    }
}
