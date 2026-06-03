// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core/common domain tags
//!
//! High-signal shared tags used broadly in core hashing primitives and identity/state wiring.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit";
pub const TAG_SMT_NODE: &str = "DSM/smt-node";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf";
pub const TAG_DBRW: &str = "DSM/dbrw";
pub const TAG_HASH_DATA: &str = "DSM/hash-data";
pub const TAG_ENTITY_ID: &str = "DSM/entity-id";
pub const TAG_DEVICE_ID: &str = "DSM/device-id";
pub const TAG_DSM_NODE_ID: &str = "DSM/node-id";
pub const TAG_DSM_BYTECOMMIT: &str = "DSM/bytecommit";
pub const TAG_BILATERAL_SESSION: &str = "DSM/bilateral-session";
pub const TAG_SMT_KEY: &str = "DSM/smt-key";
pub const TAG_TIP: &str = "DSM/tip";
pub const TAG_STATE_HASH: &str = "DSM/state-hash";
pub const TAG_COMMITMENT: &str = "DSM/commitment";
pub const TAG_COMMITMENT_OPEN: &str = "DSM/commitment-open";
pub const TAG_COMMITMENT_FIELDS: &str = "DSM/commitment-fields";
pub const TAG_MERKLE_NODE: &str = "DSM/merkle-node";
pub const TAG_MERKLE_LEAF: &str = "DSM/merkle-leaf";
// Device Tree (standard Merkle) — see Issue #182 Finding #2 for the
// open spec ambiguity between §2.2 (`merkle-node`/`merkle-leaf`) and
// §16.3 (`dev-merkle`/`dev-empty`). Implementation continues to use
// the §16.3 ("normative") tags pending Brandon's resolution.
pub const TAG_DEV_MERKLE: &str = "DSM/dev-merkle";
pub const TAG_DEV_LEAF: &str = "DSM/dev-leaf";
pub const TAG_DEV_EMPTY: &str = "DSM/dev-empty";
/// Canonical padding leaf for odd-count Merkle levels in the Device Tree.
pub const TAG_DEV_PAD: &str = "DSM/dev-tree-pad";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_RECEIPT_COMMIT,
    TAG_SMT_NODE,
    TAG_SMT_LEAF,
    TAG_DBRW,
    TAG_HASH_DATA,
    TAG_ENTITY_ID,
    TAG_DEVICE_ID,
    TAG_DSM_NODE_ID,
    TAG_DSM_BYTECOMMIT,
    TAG_BILATERAL_SESSION,
    TAG_SMT_KEY,
    TAG_TIP,
    TAG_STATE_HASH,
    TAG_COMMITMENT,
    TAG_COMMITMENT_OPEN,
    TAG_COMMITMENT_FIELDS,
    TAG_MERKLE_NODE,
    TAG_MERKLE_LEAF,
    TAG_DEV_MERKLE,
    TAG_DEV_LEAF,
    TAG_DEV_EMPTY,
    TAG_DEV_PAD,
];
