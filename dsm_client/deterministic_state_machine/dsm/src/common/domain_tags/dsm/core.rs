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
/// SMT key of the per-(vault, asset) reserve leaf:
/// `H(tag ‖ genesis_id ‖ device_id ‖ vault_id ‖ policy_commit)`. Accounts for value the
/// owner has ENCUMBERED into a specific vault. Deliberately not a `balances` entry: a
/// vault-scoped key in that map would be folded into `balance_witness` and change the chain
/// tip a counterparty derives on every unrelated transfer.
pub const TAG_VAULT_RESERVE_LEAF: &str = "DSM/vault-reserve/v1";
/// Value of a vault reserve leaf: `H(tag ‖ amount_be ‖ vault_sequence_be)`. The sequence is
/// the VAULT's own `current_sequence`, not a per-leaf counter, so this leaf and the
/// vault-state leaf carry the same sequence and a verifier holding both proofs against one
/// root can cross-check them without a third record.
pub const TAG_VAULT_RESERVE_STATE: &str = "DSM/vault-reserve-state/v1";
/// Key of a settlement receipt leaf: `H(tag ‖ genesis ‖ devid ‖ vault_id ‖ receipt_id)`.
/// Witnesses that a trader's own `DlvSettle` advance COMMITTED. A pending pointer states an
/// intent and costs nothing to publish; folding one into effective reserves without this
/// witness let a trader drain a vault's quotable liquidity for free.
pub const TAG_SETTLEMENT_RECEIPT_LEAF: &str = "DSM/settlement-receipt/v1";
/// Value of a settlement receipt leaf: the whole settled trade (X, sequence step, both
/// policy commits, both amounts). Keyed by receipt id, so replay writes the identical value
/// at the identical slot while a different trade under the same id is a visible mismatch.
pub const TAG_SETTLEMENT_RECEIPT_STATE: &str = "DSM/settlement-receipt-state/v1";
/// Signing payload binding a receipt to the trader's post-advance root. Folds the leaf
/// VALUE rather than restating the trade, so the signature and the SMT path are checked
/// against the same bytes and cannot describe different settlements.
pub const TAG_SETTLEMENT_RECEIPT_SIGN: &str = "DSM/settlement-receipt-sign";
/// What a pending pointer commits to so it names exactly ONE receipt:
/// `H(tag ‖ vault_id ‖ receipt_id ‖ leaf_value)`. Excludes the trader's post-advance
/// root, because the pointer is published BEFORE the advance that produces it.
pub const TAG_SETTLEMENT_RECEIPT_COMMIT: &str = "DSM/settlement-receipt-commit/v1";
/// Deterministic receipt id: `H(tag ‖ vault_id ‖ x)`. Derived, not chosen, so the pointer
/// publisher and the settling advance agree on it without coordinating.
pub const TAG_SETTLEMENT_RECEIPT_ID: &str = "DSM/settlement-receipt-id/v1";
/// Reserve inclusion proof signing payload: `H(tag ‖ vault_id ‖ seq_be ‖ smt_root ‖
/// owner_genesis ‖ owner_devid ‖ (policy_commit ‖ amount_be)*)`. Turns "the owner says the
/// vault holds 10,000 ERA" into "the owner's device root commits it".
pub const TAG_VAULT_RESERVE_INCLUSION: &str = "DSM/vault-reserve-inclusion/v1";
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
    TAG_VAULT_RESERVE_LEAF,
    TAG_VAULT_RESERVE_STATE,
    TAG_SETTLEMENT_RECEIPT_LEAF,
    TAG_SETTLEMENT_RECEIPT_STATE,
    TAG_SETTLEMENT_RECEIPT_SIGN,
    TAG_SETTLEMENT_RECEIPT_COMMIT,
    TAG_SETTLEMENT_RECEIPT_ID,
    TAG_VAULT_RESERVE_INCLUSION,
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
