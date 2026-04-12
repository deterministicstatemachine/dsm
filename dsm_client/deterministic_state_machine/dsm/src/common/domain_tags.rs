//! Centralized domain tag constants for BLAKE3 domain-separated hashing.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit";
pub const TAG_SMT_NODE: &str = "DSM/smt-node";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf";
pub const TAG_DBRW: &str = "DSM/dbrw";
// Device Tree (standard Merkle) — whitepaper-aligned merkle domains.
pub const TAG_DEV_MERKLE: &str = "DSM/merkle-node";
pub const TAG_DEV_LEAF: &str = "DSM/merkle-leaf";
pub const TAG_DEV_EMPTY: &str = "DSM/dev-empty";

/// Helper to build a tagged preimage by prefixing the ASCII tag and a single NUL.
pub fn tagged_bytes(tag: &str, body: &[u8]) -> Vec<u8> {
    let canonical_tag = tag.trim_end_matches('\0');
    let mut out = Vec::with_capacity(canonical_tag.len() + 1 + body.len());
    out.extend_from_slice(canonical_tag.as_bytes());
    out.push(0u8);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn exported_tags_are_not_nul_terminated() {
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
                "exported tag {tag:?} must not carry a baked-in NUL"
            );
            assert!(tag.len() > 1, "tag must contain more than just the prefix");
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

    #[test]
    fn tagged_bytes_appends_single_nul_before_body() {
        let result = tagged_bytes("DSM/test", b"hello");
        assert_eq!(&result[..9], b"DSM/test\0");
        assert_eq!(&result[9..], b"hello");
        assert_eq!(result.len(), 9 + 5);
    }

    #[test]
    fn tagged_bytes_with_empty_body() {
        let result = tagged_bytes(TAG_DBRW, b"");
        assert_eq!(result, b"DSM/dbrw\0");
    }

    #[test]
    fn tagged_bytes_different_tags_produce_different_output() {
        let a = tagged_bytes(TAG_SMT_NODE, b"data");
        let b = tagged_bytes(TAG_SMT_LEAF, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn tagged_bytes_different_bodies_produce_different_output() {
        let a = tagged_bytes(TAG_DBRW, b"alpha");
        let b = tagged_bytes(TAG_DBRW, b"beta");
        assert_ne!(a, b);
    }
}
