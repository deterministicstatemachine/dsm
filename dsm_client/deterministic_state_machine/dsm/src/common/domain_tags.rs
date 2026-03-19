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
