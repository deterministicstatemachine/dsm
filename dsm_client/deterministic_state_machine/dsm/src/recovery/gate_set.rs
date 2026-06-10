// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery gate-set construction (spec §0.5 gap 13, R4 layer 3 + final rule).
//!
//! Builds the FROZEN recovery gate-set as:
//!
//! ```text
//! GateSet = value-capable leaves from A_old's latest valid append-only PDSMT head
//!         ∪ independently genesis-authenticated counterparty claims proving a
//!           value-capable relationship with A_old (at/before the snapshot).
//! ```
//!
//! The union (layer 3) is the anti-shrink backstop: a `K_A`-holding spender can sign a
//! head that OMITS a counterparty `C`, but `C`'s OWN genesis-authenticated PDSMT leaf for
//! the SAME (symmetric, device-pair) `rel_key` — `owner=C, counterparty=A_old,
//! value_capable=true` — forces `C` into the gate-set regardless. `rel_key` symmetry
//! (`compute_smt_key` = `H(min‖max)`) is what lets `C`'s leaf reference the same
//! relationship.
//!
//! This module is PURE and deterministic. The caller (SDK/integration) MUST first
//! establish, for each supplied head: that its `authority_pubkey` is the genesis-anchored
//! authority for the head's `(genesis_id, device_id)` (via [`crate::recovery::RecoveryAuthorityAnchor`]),
//! that the device is in its genesis Device Tree (device-tree quorum), and that the head
//! is the latest valid head at/before the snapshot (the append-only chain, layer 1).
//! Given those, this module verifies head signatures + leaf inclusion/completeness
//! (layer 2) and applies the union rule, returning the frozen set + its commitment.
//!
//! The frozen `gate_set_commit` becomes the activation seal's `contact_set_commit`;
//! [`crate::recovery::validate_recovery_activation`] then requires valid
//! `CrossRelationshipSuccessionEvidence` for EVERY member — failing closed on any gap.
//! That is where the "activation fails closed if any union member lacks evidence" half of
//! the final rule is enforced.

use crate::core::bilateral_transaction_manager::compute_smt_key;
use crate::recovery::capsule::contact_set_commit_from_device_ids;
use crate::recovery::pdsmt_posting::{verify_head_with_leaves, PostedPdsmtHead, PostedPdsmtLeafRecord};
use crate::types::device_state::ValueCapability;
use crate::types::error::DsmError;
use std::collections::{BTreeMap, BTreeSet};

/// A counterparty's own genesis-authenticated value-capable claim about its relationship
/// with `A_old` — the anti-shrink union witness. `authority_commit` is `C`'s
/// genesis-anchored recovery-authority commitment (`H(K_C_pub)`, established by the caller
/// from C's [`crate::recovery::RecoveryAuthorityAnchor`]); the head carries the raw pubkey,
/// so [`PostedPdsmtHead::verify`] checks it against this anchored commit. `leaf` is `C`'s own
/// PDSMT leaf for the shared `rel_key`, included under `head`.
#[derive(Clone, Debug)]
pub struct CounterpartyValueWitness {
    pub head: PostedPdsmtHead,
    pub authority_commit: [u8; 32],
    pub leaf: PostedPdsmtLeafRecord,
}

/// The frozen recovery gate-set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenGateSet {
    /// Counterparty device ids that the recovery activation MUST account for.
    pub members: BTreeSet<[u8; 32]>,
    /// `contact_set_commit` over `members` — the seal's anti-shrink/anti-drift anchor.
    pub gate_set_commit: [u8; 32],
    /// member device id → the `(A_old, member)` relationship key (for evidence binding).
    pub rel_keys: BTreeMap<[u8; 32], [u8; 32]>,
}

/// Construct the frozen recovery gate-set for `a_old` (R4 final rule).
///
/// - `a_old_head` / `a_old_authority_pubkey` / `a_old_leaves`: `A_old`'s latest valid
///   posted PDSMT head (caller-established) + its enumerated leaf records.
/// - `counterparty_witnesses`: independent value-capable claims by counterparties.
///
/// Fail-closed: any head-signature / inclusion / binding / `rel_key`-symmetry failure
/// aborts with an error and yields NO gate-set.
pub fn build_gate_set(
    a_old: &[u8; 32],
    a_old_head: &PostedPdsmtHead,
    a_old_authority_commit: &[u8; 32],
    a_old_leaves: &[PostedPdsmtLeafRecord],
    counterparty_witnesses: &[CounterpartyValueWitness],
) -> Result<FrozenGateSet, DsmError> {
    if &a_old_head.device_id != a_old {
        return Err(DsmError::verification(
            "gate-set: A_old head device_id != A_old under recovery",
        ));
    }
    // Layer 2: A_old's head signature (under its genesis-anchored authority) + every leaf
    // included under both roots.
    verify_head_with_leaves(a_old_head, a_old_authority_commit, a_old_leaves)?;

    let mut members: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut rel_keys: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();

    // Primary set: A_old's leaves that are NOT proven `No` (R4: `Yes` and `Unknown` both
    // include; only positively-proven `No` is excluded).
    for leaf in a_old_leaves {
        if !leaf.value_capability.includes_in_gate() {
            continue;
        }
        let expected = compute_smt_key(a_old, &leaf.counterparty_device_id);
        if leaf.rel_key != expected {
            return Err(DsmError::verification(
                "gate-set: A_old leaf rel_key != H(A_old, counterparty)",
            ));
        }
        members.insert(leaf.counterparty_device_id);
        rel_keys.insert(leaf.counterparty_device_id, leaf.rel_key);
    }

    // Layer 3 — union backstop: each counterparty's own value-capable claim about A_old.
    for w in counterparty_witnesses {
        let c = w.head.device_id;
        if w.leaf.owner_device_id != c {
            return Err(DsmError::verification(
                "gate-set: witness leaf owner_device_id != witness head device_id",
            ));
        }
        if &w.leaf.counterparty_device_id != a_old {
            return Err(DsmError::verification(
                "gate-set: witness leaf is not about A_old",
            ));
        }
        // A witness must NOT positively assert `No` (that would contradict its purpose).
        // `Yes` and `Unknown` both contribute to the anti-shrink union (include direction).
        if w.leaf.value_capability == ValueCapability::No {
            return Err(DsmError::verification(
                "gate-set: witness leaf positively asserts No (contradictory anti-shrink witness)",
            ));
        }
        // Symmetric rel_key ties C's leaf to the SAME relationship as A_old's view.
        let expected = compute_smt_key(&c, a_old);
        if w.leaf.rel_key != expected {
            return Err(DsmError::verification(
                "gate-set: witness leaf rel_key != H(C, A_old)",
            ));
        }
        // C's own head signature (under C's genesis-anchored authority) + the witness leaf's
        // inclusion under C's posted roots.
        verify_head_with_leaves(&w.head, &w.authority_commit, std::slice::from_ref(&w.leaf))?;

        members.insert(c);
        rel_keys.insert(c, w.leaf.rel_key);
    }

    let gate_set_commit = contact_set_commit_from_device_ids(&members);
    Ok(FrozenGateSet {
        members,
        gate_set_commit,
        rel_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
    use crate::recovery::pdsmt_posting::GENESIS_PARENT_HEAD_HASH;

    const A_OLD: [u8; 32] = [0xA0; 32];

    /// Build a signed PDSMT head + its leaf records (with real SMT inclusion proofs) for
    /// `owner` under `genesis`, one leaf per `(counterparty, value_capable)`. Returns
    /// (head, anchored_authority_commit, leaves) — the head carries its own pubkey.
    fn posted_snapshot(
        owner: [u8; 32],
        genesis: [u8; 32],
        seed: u8,
        entries: &[([u8; 32], ValueCapability)],
    ) -> (PostedPdsmtHead, [u8; 32], Vec<PostedPdsmtLeafRecord>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("kp");

        // Build leaf records (proofs filled after the trees exist).
        let mut leaves: Vec<PostedPdsmtLeafRecord> = entries
            .iter()
            .enumerate()
            .map(|(i, (cp, vc))| PostedPdsmtLeafRecord {
                genesis_id: genesis,
                owner_device_id: owner,
                rel_key: compute_smt_key(&owner, cp),
                counterparty_device_id: *cp,
                counterparty_genesis_id: None,
                current_tip: [0x70 ^ i as u8; 32],
                value_capability: *vc,
                value_capability_reason: match vc {
                    ValueCapability::Yes => "token transfer".into(),
                    ValueCapability::No => String::new(),
                    ValueCapability::Unknown => "unknown-unbackfilled".into(),
                },
                inclusion_proof_to_pd_smt_root: Vec::new(),
                inclusion_proof_to_leaf_index_root: Vec::new(),
            })
            .collect();

        // pd_smt: rel_key -> current_tip; leaf_index: rel_key -> committed_digest.
        let mut pd = SparseMerkleTree::new(256);
        let mut idx = SparseMerkleTree::new(256);
        for l in &leaves {
            pd.update_leaf(&l.rel_key, &l.current_tip).unwrap();
            idx.update_leaf(&l.rel_key, &l.committed_digest()).unwrap();
        }
        let pd_root = *pd.root();
        let idx_root = *idx.root();
        for l in &mut leaves {
            l.inclusion_proof_to_pd_smt_root =
                pd.get_inclusion_proof(&l.rel_key, 256).unwrap().to_bytes();
            l.inclusion_proof_to_leaf_index_root =
                idx.get_inclusion_proof(&l.rel_key, 256).unwrap().to_bytes();
        }

        let mut head = PostedPdsmtHead {
            genesis_id: genesis,
            device_id: owner,
            pd_smt_root: pd_root,
            leaf_index_root: idx_root,
            snapshot_id: [seed; 32],
            authority_pubkey_commit: compute_authority_pubkey_commit(&kp.public_key),
            parent_head_hash: GENESIS_PARENT_HEAD_HASH,
            head_number: 0,
            signature: Vec::new(),
            authority_pubkey: kp.public_key.clone(),
        };
        head.signature = sphincs_sign(&kp.secret_key, &head.digest()).expect("sign");
        // Return the genesis-anchored authority commit (what build_gate_set/verify take).
        (
            head,
            compute_authority_pubkey_commit(&kp.public_key),
            leaves,
        )
    }

    /// A counterparty `c` posts its OWN snapshot containing a value-capable leaf about A_old.
    fn witness_for(
        c: [u8; 32],
        c_genesis: [u8; 32],
        seed: u8,
        vc: ValueCapability,
    ) -> CounterpartyValueWitness {
        let (head, commit, leaves) = posted_snapshot(c, c_genesis, seed, &[(A_OLD, vc)]);
        CounterpartyValueWitness {
            head,
            authority_commit: commit,
            leaf: leaves.into_iter().next().unwrap(),
        }
    }

    #[test]
    fn primary_set_is_value_capable_leaves_only() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let c2 = [0xC2; 32];
        let c3 = [0xC3; 32];
        // C1, C2 value-capable; C3 a pure contact relationship.
        let (head, pk, leaves) = posted_snapshot(
            A_OLD,
            g_a,
            0x42,
            &[
                (c1, ValueCapability::Yes),
                (c2, ValueCapability::Yes),
                (c3, ValueCapability::No),
            ],
        );
        let gs = build_gate_set(&A_OLD, &head, &pk, &leaves, &[]).expect("gate set");
        assert_eq!(gs.members, BTreeSet::from([c1, c2]));
        assert_eq!(
            gs.gate_set_commit,
            contact_set_commit_from_device_ids(&BTreeSet::from([c1, c2]))
        );
    }

    #[test]
    fn unknown_leaves_included_only_proven_no_excluded() {
        let g_a = [0x6E; 32];
        let yes = [0xC1; 32];
        let unknown = [0xC2; 32];
        let no = [0xC3; 32];
        let (head, pk, leaves) = posted_snapshot(
            A_OLD,
            g_a,
            0x42,
            &[
                (yes, ValueCapability::Yes),
                (unknown, ValueCapability::Unknown),
                (no, ValueCapability::No),
            ],
        );
        let gs = build_gate_set(&A_OLD, &head, &pk, &leaves, &[]).expect("gate set");
        // R4: Yes AND Unknown are INCLUDED; only positively-proven No is excluded.
        assert_eq!(gs.members, BTreeSet::from([yes, unknown]));
    }

    #[test]
    fn unknown_witness_is_included() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let omitted = [0xC9; 32];
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        // An `Unknown` witness still forces its device in (Unknown includes, fail-closed).
        let w = witness_for(omitted, [0xD9; 32], 0x55, ValueCapability::Unknown);
        let gs = build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).expect("gate set");
        assert_eq!(gs.members, BTreeSet::from([c1, omitted]));
    }

    #[test]
    fn union_forces_in_an_omitted_counterparty() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let omitted = [0xC9; 32];
        // A_old's head lists only C1 (a shrink that OMITS `omitted`).
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        // `omitted` posts its OWN value-capable claim about A_old.
        let w = witness_for(omitted, [0xD9; 32], 0x55, ValueCapability::Yes);
        let gs = build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).expect("gate set");
        // The omitted counterparty is forced into the gate-set despite A_old's shrink.
        assert_eq!(gs.members, BTreeSet::from([c1, omitted]));
    }

    #[test]
    fn union_witness_proven_no_is_rejected() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        // A witness that positively asserts `No` is contradictory and rejected.
        let w = witness_for([0xC9; 32], [0xD9; 32], 0x55, ValueCapability::No);
        assert!(build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).is_err());
    }

    #[test]
    fn union_witness_must_be_about_a_old() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        // Witness whose leaf is about a DIFFERENT device, not A_old.
        let (w_head, w_commit, w_leaves) = posted_snapshot(
            [0xC9; 32],
            [0xD9; 32],
            0x55,
            &[([0xBB; 32], ValueCapability::Yes)],
        );
        let w = CounterpartyValueWitness {
            head: w_head,
            authority_commit: w_commit,
            leaf: w_leaves.into_iter().next().unwrap(),
        };
        assert!(build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).is_err());
    }

    #[test]
    fn forged_witness_authority_rejected() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        let mut w = witness_for([0xC9; 32], [0xD9; 32], 0x55, ValueCapability::Yes);
        // A wrong anchored commit (not the head's committed authority) → head verify fails.
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x01; 32]).unwrap();
        w.authority_commit = compute_authority_pubkey_commit(&other.public_key);
        assert!(build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).is_err());
    }

    #[test]
    fn wrong_a_old_head_device_rejected() {
        let g_a = [0x6E; 32];
        let (head, pk, leaves) =
            posted_snapshot([0xBE; 32], g_a, 0x42, &[([0xC1; 32], ValueCapability::Yes)]);
        // Head is for a different device than the A_old under recovery.
        assert!(build_gate_set(&A_OLD, &head, &pk, &leaves, &[]).is_err());
    }

    #[test]
    fn union_is_idempotent_when_head_and_witness_agree() {
        let g_a = [0x6E; 32];
        let c1 = [0xC1; 32];
        // A_old lists C1; C1 ALSO posts its own value-capable claim → no duplication.
        let (head, pk, leaves) = posted_snapshot(A_OLD, g_a, 0x42, &[(c1, ValueCapability::Yes)]);
        let w = witness_for(c1, [0xD1; 32], 0x55, ValueCapability::Yes);
        let gs = build_gate_set(&A_OLD, &head, &pk, &leaves, &[w]).expect("gate set");
        assert_eq!(gs.members, BTreeSet::from([c1]));
    }
}
