// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core/common domain tags
//!
//! High-signal shared tags used broadly in core hashing primitives and identity/state wiring.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit";
pub const TAG_SMT_NODE: &str = "DSM/smt-node";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf";
pub const TAG_HASH_DATA: &str = "DSM/hash-data";
pub const TAG_ENTITY_ID: &str = "DSM/entity-id";
pub const TAG_DEVICE_ID: &str = "DSM/device-id";
pub const TAG_DSM_NODE_ID: &str = "DSM/node-id";
pub const TAG_DSM_BYTECOMMIT: &str = "DSM/bytecommit";
pub const TAG_BILATERAL_SESSION: &str = "DSM/bilateral-session";
pub const TAG_SMT_KEY: &str = "DSM/smt-key";
pub const TAG_TIP: &str = "DSM/tip";
pub const TAG_STATE_HASH: &str = "DSM/state-hash";
/// SMT key of the single per-device anchor-state leaf: `H(tag ‖ B)`. One stable key per
/// device (the fused anchor is device-level: one appliance, one counter); its VALUE is the
/// anchor-core v2 leaf `anchor_state_leaf(B, h_i, u_i)`, replaced old→successor on every
/// bearer transfer's device-SMT advance. Never keyed by relationship/root/frontier/counter.
pub const TAG_FUSED_ANCHOR_STATE_LEAF: &str = "DSM/fused-anchor-state-leaf/v1";
/// SMT key of the per-(device, asset) offline-cash allocation leaf:
/// `H(tag ‖ genesis_id ‖ device_id ‖ anchor_bundle_B ‖ asset_id)`. Accounts for value
/// deliberately loaded from the online balance into this device's offline-bearer allocation
/// (device-bound single-device cash). Distinct from the anchor-state leaf, which proves
/// offline position/counter; this leaf accounts for the loaded VALUE.
pub const TAG_OFFLINE_ALLOCATION_LEAF: &str = "DSM/offline-allocation/v1";
/// Value of the offline-cash allocation leaf: `H(tag ‖ amount_be ‖ sequence_be)`. The
/// sequence advances on every load/unload/spend so a repeated amount still changes the leaf.
pub const TAG_OFFLINE_ALLOCATION_STATE: &str = "DSM/offline-allocation-state/v1";
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
    TAG_HASH_DATA,
    TAG_ENTITY_ID,
    TAG_DEVICE_ID,
    TAG_DSM_NODE_ID,
    TAG_DSM_BYTECOMMIT,
    TAG_BILATERAL_SESSION,
    TAG_SMT_KEY,
    TAG_TIP,
    TAG_STATE_HASH,
    TAG_FUSED_ANCHOR_STATE_LEAF,
    TAG_OFFLINE_ALLOCATION_LEAF,
    TAG_OFFLINE_ALLOCATION_STATE,
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
