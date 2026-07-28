// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault reserve SMT leaf primitive — encumbered liquidity, provable to a peer.
//!
//! A SoFi vault advertises reserves that a trader quotes against. Until now those
//! reserves were *numbers inside the vault's fulfillment condition*: the owner asserted
//! them, nothing held them, and a settled swap moved no value at all. A quote against a
//! self-declared reserve is economically meaningless — the trader is trusting an integer.
//!
//! This module is the accounting leaf that makes the claim real. Funding a vault moves
//! value **out of** the owner's `balances` map and into a per-`(vault, asset)` leaf in the
//! owner's device SMT. The value is then encumbered by construction: `BalanceDelta` can
//! only reach `balances`, so no transfer, mint or burn can touch a reserve. Only the two
//! vault chokepoints can.
//!
//! This is the offline-cash allocation leaf with `anchor_bundle_B → vault_id`. That
//! primitive already solves exactly this shape — value committed outside `balances`,
//! conservation enforced at a chokepoint, a monotone sequence defeating replay, replay on
//! `restore` via `extra_leaves`, and a stateless third-party verifier — and it is proven.
//! Reusing its shape is deliberate; inventing a second mechanism for the same problem is
//! how the two would drift.
//!
//! Namespace is disjoint from relationship-tip leaves (`DSM/smt-key`), the anchor-state
//! leaf (`DSM/fused-anchor-state-leaf/v1`), the offline-cash allocation leaf
//! (`DSM/offline-allocation/v1`) and vault-state leaves (`DSM/vault-smt-key`), so all of
//! them coexist in one device SMT. A test pins that.
//!
//! ONE DELIBERATE DIFFERENCE FROM THE ALLOCATION LEAF. The sequence here is the **vault's**
//! `current_sequence`, not a per-leaf counter. That makes this leaf and the vault-state
//! leaf carry the same sequence at the same root, so a trader holding both proofs can
//! cross-check "these reserves belong to that vault state" without a third record — which
//! is precisely what a quote has to establish before it is worth signing.
//!
//! Amounts are `u64` base units, matching `DeviceState::balances`. A u128 reserve would
//! put a narrowing conversion at the settlement boundary, which is where a silent
//! truncation mints money.
//!
//! All hashing is domain-separated BLAKE3. No JSON, no hex, no wall-clock.

use crate::common::domain_tags::{TAG_VAULT_RESERVE_LEAF, TAG_VAULT_RESERVE_STATE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// 256-bit SMT key of the per-`(vault, asset)` reserve leaf:
/// `H("DSM/vault-reserve/v1" ‖ genesis_id ‖ device_id ‖ vault_id ‖ policy_commit)`.
///
/// Keyed by `vault_id` as well as asset because an owner may run several vaults over the
/// same pair. An encumbrance that could not name its vault would leave the owner unable to
/// attribute a settlement and the trader unable to prove per-vault solvency.
pub fn vault_reserve_key(
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    policy_commit: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_VAULT_RESERVE_LEAF);
    h.update(genesis_id);
    h.update(device_id);
    h.update(vault_id);
    h.update(policy_commit);
    *h.finalize().as_bytes()
}

/// 256-bit reserve-leaf VALUE committing `(amount, vault_sequence)`:
/// `H("DSM/vault-reserve-state/v1" ‖ amount_be ‖ vault_sequence_be)`. Big-endian for
/// endianness stability across devices.
///
/// `vault_sequence` is the vault's own sequence at the point this reserve was written. It
/// advances on every settlement, so a reserve that returns to a prior amount (swap out,
/// swap back) still produces a distinct leaf and cannot be replayed.
pub fn vault_reserve_value(amount: u64, vault_sequence: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_VAULT_RESERVE_STATE);
    h.update(&amount.to_be_bytes());
    h.update(&vault_sequence.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Verify that `device_root` commits the reserve leaf for
/// `(genesis_id, device_id, vault_id, policy_commit)` with value
/// `(amount, vault_sequence)`, via the supplied inclusion `proof_bytes`.
///
/// This is what converts "the owner says the vault holds 10,000 ERA" into "the owner's own
/// device root commits 10,000 ERA encumbered in that vault at that sequence". Stateless:
/// a trader runs it against published bytes with no access to the owner's device.
/// Fail-closed on any mismatch or empty proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_vault_reserve_leaf(
    device_root: &[u8; 32],
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    policy_commit: &[u8; 32],
    amount: u64,
    vault_sequence: u64,
    proof_bytes: &[u8],
) -> bool {
    let key = vault_reserve_key(genesis_id, device_id, vault_id, policy_commit);
    let value = vault_reserve_value(amount, vault_sequence);
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
        let (g, d, v, p) = ids();
        assert_eq!(
            vault_reserve_key(&g, &d, &v, &p),
            vault_reserve_key(&g, &d, &v, &p)
        );
        // Any field change moves the leaf position. In particular vault_id and
        // policy_commit: two vaults over the same pair, and two assets in one
        // vault, must never share a leaf.
        for i in 0..4 {
            let mut fields = [g, d, v, p];
            fields[i][0] ^= 0xff;
            assert_ne!(
                vault_reserve_key(&g, &d, &v, &p),
                vault_reserve_key(&fields[0], &fields[1], &fields[2], &fields[3]),
                "field {i} must change the key"
            );
        }
    }

    /// Every leaf family that shares the device SMT must occupy a disjoint
    /// namespace. A collision here would let one kind of leaf overwrite
    /// another's accounting.
    #[test]
    fn key_is_domain_separated_from_every_other_leaf_family() {
        let (g, d, v, p) = ids();
        let reserve = vault_reserve_key(&g, &d, &v, &p);

        let anchor = crate::core::bilateral_transaction_manager::anchor_state_leaf_key(&v);
        assert_ne!(reserve, anchor, "vs the anchor-state leaf");

        let allocation =
            crate::types::offline_allocation_leaf::offline_allocation_key(&g, &d, &v, &p);
        assert_ne!(reserve, allocation, "vs the offline-cash allocation leaf");

        let vault_state = crate::dlv::vault_smt_leaf::compute_vault_smt_key(&v);
        assert_ne!(reserve, vault_state, "vs the vault-state leaf");

        let relationship = crate::core::bilateral_transaction_manager::compute_smt_key(&d, &d);
        assert_ne!(reserve, relationship, "vs a relationship-tip leaf");
    }

    /// A reserve that returns to a prior amount at a later vault sequence must
    /// still produce a distinct leaf — otherwise a swap out and back would
    /// replay an older proof.
    #[test]
    fn value_advances_with_sequence_even_at_equal_amount() {
        let v_10k_s1 = vault_reserve_value(10_000, 1);
        let v_10k_s2 = vault_reserve_value(10_000, 2);
        assert_ne!(v_10k_s1, v_10k_s2, "equal amount, new sequence must differ");
        assert_ne!(
            vault_reserve_value(9_000, 2),
            v_10k_s2,
            "amount change must differ"
        );
        assert_eq!(vault_reserve_value(10_000, 1), v_10k_s1, "deterministic");
    }

    /// Sequence 0 is a real genesis sequence, not an absence. A funded vault
    /// commits its reserves at sequence 0 before any trade.
    #[test]
    fn sequence_zero_is_a_committable_state() {
        assert_ne!(vault_reserve_value(10_000, 0), vault_reserve_value(0, 0));
        assert_ne!(
            vault_reserve_value(10_000, 0),
            vault_reserve_value(10_000, 1)
        );
    }

    #[test]
    fn inclusion_verifies_and_rejects_tamper() {
        let (g, d, v, p) = ids();
        let (amount, seq) = (10_000u64, 0u64);
        let key = vault_reserve_key(&g, &d, &v, &p);
        let value = vault_reserve_value(amount, seq);

        let mut tree = SparseMerkleTree::new(64);
        tree.update_leaf(&key, &value).expect("update_leaf");
        let root = *tree.root();
        let proof = tree
            .get_inclusion_proof(&key, 256)
            .expect("proof")
            .to_bytes();

        assert!(verify_vault_reserve_leaf(
            &root, &g, &d, &v, &p, amount, seq, &proof
        ));

        // Overstating the reserve is the attack this exists to stop.
        assert!(!verify_vault_reserve_leaf(
            &root, &g, &d, &v, &p, 10_001, seq, &proof
        ));
        // A stale sequence must not verify against current reserves.
        assert!(!verify_vault_reserve_leaf(
            &root, &g, &d, &v, &p, amount, 1, &proof
        ));
        // Nor may a proof be re-pointed at a different vault or asset.
        let mut v2 = v;
        v2[0] ^= 0xff;
        assert!(!verify_vault_reserve_leaf(
            &root, &g, &d, &v2, &p, amount, seq, &proof
        ));
        let mut p2 = p;
        p2[0] ^= 0xff;
        assert!(!verify_vault_reserve_leaf(
            &root, &g, &d, &v, &p2, amount, seq, &proof
        ));
        let mut bad_root = root;
        bad_root[0] ^= 0xff;
        assert!(!verify_vault_reserve_leaf(
            &bad_root, &g, &d, &v, &p, amount, seq, &proof
        ));
    }

    #[test]
    fn empty_proof_fails_closed() {
        let (g, d, v, p) = ids();
        assert!(!verify_vault_reserve_leaf(
            &[0u8; 32],
            &g,
            &d,
            &v,
            &p,
            0,
            0,
            &[]
        ));
    }
}
