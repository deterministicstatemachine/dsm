//! Centralized domain tag constants for BLAKE3 domain-separated hashing.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit\0";
pub const TAG_SMT_NODE: &str = "DSM/smt-node\0";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf\0";
pub const TAG_DBRW: &str = "DSM/dbrw\0";
// Device Tree (standard Merkle)
pub const TAG_DEV_MERKLE: &str = "DSM/dev-merkle\0";
pub const TAG_DEV_LEAF: &str = "DSM/dev-leaf\0";
pub const TAG_DEV_EMPTY: &str = "DSM/dev-empty\0";

/// Helper to build a tagged preimage by prefixing the ASCII tag and NUL.
pub fn tagged_bytes(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + body.len());
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_tags_are_nul_terminated() {
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
            assert!(tag.ends_with('\0'), "Tag {tag:?} must be NUL-terminated");
            assert!(tag.len() > 1, "Tag must contain more than just NUL");
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
    fn tagged_bytes_concatenates_tag_and_body() {
        let result = tagged_bytes("DSM/test\0", b"hello");
        assert_eq!(&result[..9], b"DSM/test\0");
        assert_eq!(&result[9..], b"hello");
        assert_eq!(result.len(), 9 + 5);
    }

    #[test]
    fn tagged_bytes_with_empty_body() {
        let result = tagged_bytes(TAG_DBRW, b"");
        assert_eq!(result, TAG_DBRW.as_bytes());
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
