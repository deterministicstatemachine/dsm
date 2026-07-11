// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline-cash allocation SMT leaf primitive.
//!
//! DSM's two-regime money model: the same Genesis balance is *online* (cross-device,
//! network-synced) but can be deliberately **loaded** into a *device-bound offline pool*
//! ("cash in hand") while online, spent offline via the bearer path, and reconciled back.
//! This module is the pure-crypto layer for the pool's accounting leaf.
//!
//! The offline allocation is committed as a per-`(device, asset)` leaf in the device SMT,
//! in a namespace disjoint from relationship-tip leaves (`DSM/smt-key`), the anchor-state
//! leaf (`DSM/fused-anchor-state-leaf/v1`), and vault-state leaves (`DSM/vault-smt-key`).
//!
//! Division of labor with the anchor-state leaf: the **anchor-state leaf** proves offline
//! position / origin / counter progression; the **allocation leaf** accounts for the loaded
//! *value*. A load debits online `available` and increments this leaf; an offline-bearer
//! spend draws it down; an unload reverses it back to `available`.
//!
//! The KEY is a pure function of `(genesis_id, device_id, anchor_bundle_B, asset_id)`, so the
//! same allocation occupies one stable leaf position for its lifetime — successive
//! load/unload/spend transitions are updates of that one leaf. The VALUE commits
//! `(amount, sequence)`; the sequence advances on every transition so a repeated amount
//! (load 30 → spend 10 → load 10 → 30 again) still changes the leaf and cannot replay.
//!
//! All hashing is domain-separated BLAKE3. No JSON, no hex, no wall-clock.

use crate::common::domain_tags::{TAG_OFFLINE_ALLOCATION_LEAF, TAG_OFFLINE_ALLOCATION_STATE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// 256-bit SMT key of the per-`(device, asset)` offline-cash allocation leaf:
/// `H("DSM/offline-allocation/v1" ‖ genesis_id ‖ device_id ‖ anchor_bundle_B ‖ asset_id)`.
///
/// Bound to the device's anchor bundle `B` (chip-rooted, per-device) so the allocation is
/// non-portable: it belongs to exactly this device's offline-bearer island.
pub fn offline_allocation_key(
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    anchor_bundle_b: &[u8; 32],
    asset_id: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ALLOCATION_LEAF);
    h.update(genesis_id);
    h.update(device_id);
    h.update(anchor_bundle_b);
    h.update(asset_id);
    *h.finalize().as_bytes()
}

/// 256-bit allocation-leaf VALUE committing `(amount, sequence)`:
/// `H("DSM/offline-allocation-state/v1" ‖ amount_be ‖ sequence_be)`. Big-endian for
/// endianness stability across devices. `sequence` is a monotone per-leaf transition
/// counter: increment it on every load/unload/spend so the leaf value is distinct even
/// when `amount` returns to a prior value.
pub fn offline_allocation_value(amount: u64, sequence: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ALLOCATION_STATE);
    h.update(&amount.to_be_bytes());
    h.update(&sequence.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Verify that `device_root` commits the offline-allocation leaf for
/// `(genesis_id, device_id, anchor_bundle_B, asset_id)` with value `(amount, sequence)`,
/// via the supplied inclusion `proof_bytes`. Fail-closed on any mismatch or empty proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_offline_allocation_leaf(
    device_root: &[u8; 32],
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    anchor_bundle_b: &[u8; 32],
    asset_id: &[u8; 32],
    amount: u64,
    sequence: u64,
    proof_bytes: &[u8],
) -> bool {
    let key = offline_allocation_key(genesis_id, device_id, anchor_bundle_b, asset_id);
    let value = offline_allocation_value(amount, sequence);
    let Some(proof) = SmtInclusionProof::from_bytes(proof_bytes) else {
        return false;
    };
    proof.key == key
        && proof.value == Some(value)
        && SparseMerkleTree::verify_proof_against_root(&proof, device_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32])
    }

    #[test]
    fn key_is_deterministic_and_field_sensitive() {
        let (g, d, b, a) = ids();
        assert_eq!(
            offline_allocation_key(&g, &d, &b, &a),
            offline_allocation_key(&g, &d, &b, &a)
        );
        // Any field change moves the leaf position.
        for i in 0..4 {
            let mut fields = [g, d, b, a];
            fields[i][0] ^= 0xff;
            assert_ne!(
                offline_allocation_key(&g, &d, &b, &a),
                offline_allocation_key(&fields[0], &fields[1], &fields[2], &fields[3]),
                "field {i} must change the key"
            );
        }
    }

    #[test]
    fn key_is_domain_separated_from_anchor_state_leaf() {
        let (g, d, b, a) = ids();
        // The allocation leaf (device+asset) and the anchor-state leaf (bundle only) must
        // never collide, so both can live in one device SMT.
        let alloc = offline_allocation_key(&g, &d, &b, &a);
        let anchor = crate::core::bilateral_transaction_manager::anchor_state_leaf_key(&b);
        assert_ne!(alloc, anchor);
    }

    #[test]
    fn value_advances_with_sequence_even_at_equal_amount() {
        let v_30_s1 = offline_allocation_value(30, 1);
        let v_30_s2 = offline_allocation_value(30, 2);
        assert_ne!(v_30_s1, v_30_s2, "equal amount, new sequence must differ");
        let v_20_s2 = offline_allocation_value(20, 2);
        assert_ne!(v_30_s2, v_20_s2, "amount change must differ");
        assert_eq!(offline_allocation_value(30, 1), v_30_s1, "deterministic");
    }

    #[test]
    fn inclusion_verifies_and_rejects_tamper() {
        let (g, d, b, a) = ids();
        let (amount, seq) = (30u64, 1u64);
        let key = offline_allocation_key(&g, &d, &b, &a);
        let value = offline_allocation_value(amount, seq);

        let mut tree = SparseMerkleTree::new(64);
        tree.update_leaf(&key, &value).expect("update_leaf");
        let root = *tree.root();
        let proof = tree.get_inclusion_proof(&key, 256).expect("proof").to_bytes();

        assert!(verify_offline_allocation_leaf(
            &root, &g, &d, &b, &a, amount, seq, &proof
        ));
        // Wrong amount / sequence / asset must all fail closed.
        assert!(!verify_offline_allocation_leaf(&root, &g, &d, &b, &a, 31, seq, &proof));
        assert!(!verify_offline_allocation_leaf(&root, &g, &d, &b, &a, amount, 2, &proof));
        let mut a2 = a;
        a2[0] ^= 0xff;
        assert!(!verify_offline_allocation_leaf(&root, &g, &d, &b, &a2, amount, seq, &proof));
        // Tampered root fails.
        let mut bad_root = root;
        bad_root[0] ^= 0xff;
        assert!(!verify_offline_allocation_leaf(
            &bad_root, &g, &d, &b, &a, amount, seq, &proof
        ));
    }

    #[test]
    fn empty_proof_fails_closed() {
        let (g, d, b, a) = ids();
        assert!(!verify_offline_allocation_leaf(
            &[0u8; 32], &g, &d, &b, &a, 0, 0, &[]
        ));
    }
}
