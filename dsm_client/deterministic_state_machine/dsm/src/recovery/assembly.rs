// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery activation assembly (spec §0.5 Phase D step 2 — PURE core).
//!
//! Turns FETCHED, genesis-authenticated posted state into the
//! `(seal, gate_set, evidence)` triple consumed by
//! [`crate::recovery::validate_recovery_activation`] (and the SDK's still-fail-closed
//! `verify_and_record_activation` chokepoint). This module is PURE + deterministic — all
//! network/identity I/O is the SDK wrapper's job. It does NOT unlock anything: the seal it
//! produces is merely an input to the (separately gated) activation chokepoint.
//!
//! What it does, FAILING CLOSED at every step:
//! 1. builds the anti-shrink counterparty witnesses from each C's own leaf about A_old;
//! 2. builds the frozen gate-set ([`build_gate_set`]) — verifies A_old's head + every
//!    witness head;
//! 3. for EVERY gate member, requires fetched posted state and assembles a
//!    [`CrossRelationshipSuccessionEvidence`], binding the posted ancestry segment and
//!    establishment receipt to C's genesis-authenticated PDSMT tips;
//! 4. computes the evidence root and builds the [`RecoveryActivationSeal`];
//! 5. re-runs [`validate_recovery_activation`] so the returned triple is guaranteed to
//!    pass the canonical validator.
//!
//! Authority split — caller PRECONDITIONS (this module trusts the supplied pubkeys and
//! verifies signatures/inclusion against them; the SDK genesis-anchors each one first):
//! - `recovery_authority_pubkey` (A's `K_A`): authenticates the tombstone/succession
//!   proving A_new succeeds A_old. Genesis-anchored via A's `RecoveryAuthorityAnchor`.
//! - each counterparty C's `authority_commit`: the genesis-anchored commitment that
//!   authenticates C's posted head/leaves (and thus `counterparty_root`). The head carries
//!   the raw pubkey; verification checks `H(pubkey) == authority_commit`. Established by the
//!   SDK via C's own anchor + device-tree quorum.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::bilateral_transaction_manager::compute_smt_key;
use crate::recovery::activation::{
    compute_evidence_root, validate_recovery_activation, RecoveryActivationSeal,
};
use crate::recovery::chain_segment::{RecoveryEstablishmentReceipt, RelationshipChainSegment};
use crate::recovery::gate_set::{build_gate_set, CounterpartyValueWitness, FrozenGateSet};
use crate::recovery::pdsmt_posting::{verify_head_with_leaves, PostedPdsmtHead, PostedPdsmtLeafRecord};
use crate::recovery::succession_binding::{
    compute_carry_forward_commitment, CrossRelationshipSuccessionEvidence,
};
use crate::recovery::tombstone::{SuccessionReceipt, TombstoneReceipt};
use crate::types::device_state::ValueCapability;
use crate::types::error::DsmError;

/// One counterparty C's fetched, genesis-authenticated posted recovery state.
#[derive(Clone, Debug)]
pub struct CounterpartyRecoveryInput {
    /// C's signed PDSMT head. `head.device_id == C`; `head.pd_smt_root` is the
    /// `counterparty_root` the per-C evidence inclusion is checked against. The head carries
    /// its own `authority_pubkey`, checked against `authority_commit` below.
    pub head: PostedPdsmtHead,
    /// C's genesis-anchored recovery-authority commitment (`H(K_C_pub)`, established by the
    /// SDK from C's [`crate::recovery::RecoveryAuthorityAnchor`] + device-tree quorum).
    pub authority_commit: [u8; 32],
    /// C's enumerated leaves — MUST include the leaf about A_old (`old_rel_key`) and, once C
    /// has co-established, the leaf about A_new (`new_rel_key`).
    pub leaves: Vec<PostedPdsmtLeafRecord>,
    /// C's posted `(A_old,C)` ancestry segment `h_cap -> T_old_current`.
    pub old_segment: RelationshipChainSegment,
    /// C's posted `(A_new,C)` establishment receipt (the first state binding carry-forward).
    pub establishment: RecoveryEstablishmentReceipt,
    /// The capsule floor `h_cap` for `(A_old, C)` (A_new supplies it from its capsule).
    pub h_cap: [u8; 32],
}

/// All inputs to assemble a recovery activation (spec §0.5 step 2).
#[derive(Clone, Debug)]
pub struct RecoveryAssemblyInputs {
    pub genesis_id: [u8; 32],
    pub a_old: [u8; 32],
    pub a_new: [u8; 32],
    /// A_old's latest valid posted PDSMT head + genesis-anchored authority commit + leaves.
    pub a_old_head: PostedPdsmtHead,
    pub a_old_authority_commit: [u8; 32],
    pub a_old_leaves: Vec<PostedPdsmtLeafRecord>,
    /// Per-counterparty fetched posted state, keyed by C device id.
    pub counterparties: BTreeMap<[u8; 32], CounterpartyRecoveryInput>,
    /// The identity-level tombstone/succession (A's `K_A`) proving A_new succeeds A_old.
    pub tombstone: TombstoneReceipt,
    pub succession: SuccessionReceipt,
    /// Seal context produced by the recovery flow (bound into the seal, not derived here).
    pub recovery_intent_digest: [u8; 32],
    pub tombstone_proposal_digest: [u8; 32],
    pub final_per_device_smt_root: [u8; 32],
    pub final_receipt_roll: [u8; 32],
}

/// The assembled, validator-passing activation triple.
#[derive(Clone, Debug)]
pub struct AssembledActivation {
    pub seal: RecoveryActivationSeal,
    pub gate_set: BTreeSet<[u8; 32]>,
    pub evidence: BTreeMap<[u8; 32], CrossRelationshipSuccessionEvidence>,
}

/// Assemble + verify the recovery activation (spec §0.5 step 2). Fail-closed throughout.
///
/// `recovery_authority_pubkey` is A's genesis-anchored `K_A_pub`; the SDK has already bound
/// it to A's `RecoveryAuthorityAnchor`, and each counterparty's `authority_pubkey` to C's
/// own anchor. Returns the triple the activation chokepoint consumes — it does NOT unlock.
pub fn assemble_recovery_activation(
    inputs: &RecoveryAssemblyInputs,
    recovery_authority_pubkey: &[u8],
) -> Result<AssembledActivation, DsmError> {
    // 1. Anti-shrink witnesses: each fetched C's OWN leaf about A_old (not proven No).
    let mut witnesses: Vec<CounterpartyValueWitness> = Vec::new();
    for (c, cin) in &inputs.counterparties {
        if &cin.head.device_id != c {
            return Err(DsmError::verification(
                "assembly: counterparty head device_id != map key",
            ));
        }
        let old_rel_key = compute_smt_key(&inputs.a_old, c);
        if let Some(leaf) = cin.leaves.iter().find(|l| {
            l.rel_key == old_rel_key
                && l.owner_device_id == *c
                && l.counterparty_device_id == inputs.a_old
        }) {
            // A `No` leaf is not a valid anti-shrink witness (build_gate_set rejects it).
            if leaf.value_capability != ValueCapability::No {
                witnesses.push(CounterpartyValueWitness {
                    head: cin.head.clone(),
                    authority_commit: cin.authority_commit,
                    leaf: leaf.clone(),
                });
            }
        }
    }

    // 2. Frozen gate-set (verifies A_old's head + every witness head + leaf inclusion).
    let frozen: FrozenGateSet = build_gate_set(
        &inputs.a_old,
        &inputs.a_old_head,
        &inputs.a_old_authority_commit,
        &inputs.a_old_leaves,
        &witnesses,
    )?;

    // 3. Assemble per-member evidence. A gate member with no fetched posted state FAILS
    //    CLOSED (cannot prove its succession → cannot complete recovery).
    let mut evidence: BTreeMap<[u8; 32], CrossRelationshipSuccessionEvidence> = BTreeMap::new();
    for c in &frozen.members {
        let cin = inputs.counterparties.get(c).ok_or_else(|| {
            DsmError::verification(format!(
                "assembly: gate member {} has no fetched posted state (fail closed)",
                crate::types::identifiers::encode_crockford(c)
            ))
        })?;
        let ev = assemble_one_evidence(inputs, c, cin)?;
        evidence.insert(*c, ev);
    }

    // 4. Evidence root over the verified outcomes (verifying each here is also the
    //    fail-closed gate; validate_recovery_activation re-verifies in step 5).
    let mut entries: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(evidence.len());
    for (c, ev) in &evidence {
        let tip = ev.verify(recovery_authority_pubkey)?;
        entries.push((*c, tip));
    }
    let evidence_root = compute_evidence_root(&entries);

    // 5. Build the seal and re-run the canonical validator (so the returned triple is
    //    guaranteed to pass verify_and_record_activation's validate step).
    let seal = RecoveryActivationSeal {
        genesis_id: inputs.genesis_id,
        old_device_id: inputs.a_old,
        new_device_id: inputs.a_new,
        recovery_intent_digest: inputs.recovery_intent_digest,
        tombstone_proposal_digest: inputs.tombstone_proposal_digest,
        contact_set_commit: frozen.gate_set_commit,
        evidence_root,
        synced_contact_count: frozen.members.len() as u64,
        final_per_device_smt_root: inputs.final_per_device_smt_root,
        final_receipt_roll: inputs.final_receipt_roll,
    };
    validate_recovery_activation(&seal, &frozen.members, &evidence, recovery_authority_pubkey)?;

    Ok(AssembledActivation {
        seal,
        gate_set: frozen.members,
        evidence,
    })
}

/// Assemble one counterparty's [`CrossRelationshipSuccessionEvidence`] from its posted
/// state, binding the ancestry segment + establishment receipt to C's genesis-authenticated
/// PDSMT tips. Fail-closed on any missing leaf, head/inclusion failure, or binding mismatch.
fn assemble_one_evidence(
    inputs: &RecoveryAssemblyInputs,
    c: &[u8; 32],
    cin: &CounterpartyRecoveryInput,
) -> Result<CrossRelationshipSuccessionEvidence, DsmError> {
    let old_rel_key = compute_smt_key(&inputs.a_old, c);
    let new_rel_key = compute_smt_key(&inputs.a_new, c);

    // C's leaf about A_old (current (A_old,C) tip) and about A_new (established (A_new,C) tip).
    let old_leaf = cin
        .leaves
        .iter()
        .find(|l| l.rel_key == old_rel_key)
        .ok_or_else(|| {
            DsmError::verification("assembly: C has no posted leaf for old_rel_key (fail closed)")
        })?;
    let new_leaf = cin
        .leaves
        .iter()
        .find(|l| l.rel_key == new_rel_key)
        .ok_or_else(|| {
            DsmError::verification(
                "assembly: C has no posted leaf for new_rel_key — successor relationship not \
                 co-established yet (fail closed)",
            )
        })?;

    // Authenticate C's head + BOTH leaves' inclusion under C's signed roots. This makes
    // counterparty_root (= pd_smt_root) and both inclusion proofs trusted.
    verify_head_with_leaves(
        &cin.head,
        &cin.authority_commit,
        std::slice::from_ref(old_leaf),
    )?;
    verify_head_with_leaves(
        &cin.head,
        &cin.authority_commit,
        std::slice::from_ref(new_leaf),
    )?;

    let t_old_current = old_leaf.current_tip;
    let t_new_established = new_leaf.current_tip;
    let counterparty_root = cin.head.pd_smt_root;

    // Bind the posted ancestry segment to (old_rel_key, h_cap, T_old_current) + self-verify.
    let seg = &cin.old_segment;
    if seg.rel_key != old_rel_key {
        return Err(DsmError::verification(
            "assembly: old_segment rel_key != old_rel_key",
        ));
    }
    if seg.floor_tip != cin.h_cap {
        return Err(DsmError::verification(
            "assembly: old_segment floor_tip != capsule h_cap",
        ));
    }
    if seg.current_tip != t_old_current {
        return Err(DsmError::verification(
            "assembly: old_segment current_tip != C's posted T_old_current",
        ));
    }
    seg.verify()?;

    // Bind the establishment receipt to (new_rel_key, A_new, C, T_new_established) + verify.
    let est = &cin.establishment;
    if est.rel_key != new_rel_key {
        return Err(DsmError::verification(
            "assembly: establishment rel_key != new_rel_key",
        ));
    }
    est.verify(&inputs.a_new, c)?;
    if est.established_tip() != t_new_established {
        return Err(DsmError::verification(
            "assembly: establishment tip != C's posted T_new_established",
        ));
    }

    let carry_forward_commitment = compute_carry_forward_commitment(
        &old_rel_key,
        &new_rel_key,
        &cin.h_cap,
        &t_old_current,
        &inputs.tombstone.tombstone_hash,
        &inputs.succession.succession_hash,
        &inputs.a_old,
        &inputs.a_new,
        c,
    );

    Ok(CrossRelationshipSuccessionEvidence {
        a_old: inputs.a_old,
        a_new: inputs.a_new,
        c: *c,
        old_rel_key,
        new_rel_key,
        h_cap: cin.h_cap,
        t_old_current,
        old_chain: seg.states.clone(),
        t_new_established,
        new_establishment_state: est.state.clone(),
        carry_forward_commitment,
        counterparty_root,
        old_inclusion_proof: old_leaf.inclusion_proof_to_pd_smt_root.clone(),
        new_inclusion_proof: new_leaf.inclusion_proof_to_pd_smt_root.clone(),
        tombstone: inputs.tombstone.clone(),
        succession: inputs.succession.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};
    use crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids;
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
    use crate::recovery::pdsmt_posting::GENESIS_PARENT_HEAD_HASH;
    use crate::recovery::succession_binding::build_recovery_establishment_op;
    use crate::recovery::tombstone::{create_succession, create_tombstone};
    use crate::types::device_state::RelationshipChainState;
    use crate::types::operations::{Operation, TransactionMode};

    const A_OLD: [u8; 32] = [0xA0; 32];
    const A_NEW: [u8; 32] = [0xA1; 32];
    const G_A: [u8; 32] = [0x6E; 32];

    /// (rel_key, counterparty_device_id, current_tip, value_capability)
    type LeafSpec = ([u8; 32], [u8; 32], [u8; 32], ValueCapability);

    /// Build a signed PDSMT head + leaves (with real SparseMerkleTree inclusion proofs) for
    /// `owner` under `genesis`. Returns (head, anchored_authority_commit, leaves).
    fn signed_pdsmt(
        owner: [u8; 32],
        genesis: [u8; 32],
        seed: u8,
        specs: &[LeafSpec],
    ) -> (PostedPdsmtHead, [u8; 32], Vec<PostedPdsmtLeafRecord>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("kp");
        let mut leaves: Vec<PostedPdsmtLeafRecord> = specs
            .iter()
            .map(|(rk, cp, tip, vc)| PostedPdsmtLeafRecord {
                genesis_id: genesis,
                owner_device_id: owner,
                rel_key: *rk,
                counterparty_device_id: *cp,
                counterparty_genesis_id: None,
                current_tip: *tip,
                value_capability: *vc,
                value_capability_reason: match vc {
                    ValueCapability::Yes => "token transfer".into(),
                    ValueCapability::No => String::new(),
                    ValueCapability::Unknown => "unknown".into(),
                },
                inclusion_proof_to_pd_smt_root: Vec::new(),
                inclusion_proof_to_leaf_index_root: Vec::new(),
            })
            .collect();

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
        (
            head,
            compute_authority_pubkey_commit(&kp.public_key),
            leaves,
        )
    }

    fn old_chain_state(rel_key: [u8; 32], parent: [u8; 32], tag: u8) -> RelationshipChainState {
        RelationshipChainState {
            rel_key,
            embedded_parent: parent,
            counterparty_devid: A_OLD, // old-chain endpoint is A_old (succession check)
            operation: Operation::CreateRelationship {
                message: format!("old-{tag}"),
                counterparty_id: A_OLD.to_vec(),
                commitment: vec![tag; 8],
                proof: Vec::new(),
                mode: TransactionMode::Bilateral,
            },
            entropy: vec![tag],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: None,
            counterparty_sig: None,
        }
    }

    /// Build a fully-consistent assembly fixture for a single counterparty `c` that is
    /// value-capable in A_old's head. Returns (inputs, K_A_pub).
    fn fixture_one(c: [u8; 32], c_seed: u8) -> (RecoveryAssemblyInputs, Vec<u8>) {
        let ka = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("ka");
        let a_old_str = crate::types::identifiers::encode_crockford(&A_OLD);
        let tombstone =
            create_tombstone(&[0x01; 32], 0, &[0x02; 32], &a_old_str, &ka.secret_key).expect("t");
        let succession = create_succession(
            &tombstone.tombstone_hash,
            A_NEW.as_ref(),
            &a_old_str,
            &ka.secret_key,
        )
        .expect("s");

        let old_rel_key = compute_smt_key(&A_OLD, &c);
        let new_rel_key = compute_smt_key(&A_NEW, &c);
        let h_cap = [0x33; 32];

        // Old ancestry segment: h_cap -> one step -> T_old_current.
        let s = old_chain_state(old_rel_key, h_cap, 1);
        let t_old_current = s.compute_chain_tip();
        let segment = RelationshipChainSegment {
            rel_key: old_rel_key,
            floor_tip: h_cap,
            current_tip: t_old_current,
            states: vec![s],
        };

        // Carry-forward + establishment receipt (first (A_new,C) state binding it).
        let carry = compute_carry_forward_commitment(
            &old_rel_key,
            &new_rel_key,
            &h_cap,
            &t_old_current,
            &tombstone.tombstone_hash,
            &succession.succession_hash,
            &A_OLD,
            &A_NEW,
            &c,
        );
        let est_state = RelationshipChainState {
            rel_key: new_rel_key,
            embedded_parent: initial_chain_tip_from_device_ids(&A_NEW, &c),
            counterparty_devid: c,
            operation: build_recovery_establishment_op(&c, &carry, &h_cap),
            entropy: vec![9],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: None,
            counterparty_sig: None,
        };
        let t_new_established = est_state.compute_chain_tip();
        let establishment = RecoveryEstablishmentReceipt {
            rel_key: new_rel_key,
            state: est_state,
        };

        // A_old's head: lists c as value-capable.
        let (a_old_head, a_old_commit, a_old_leaves) = signed_pdsmt(
            A_OLD,
            G_A,
            0x42,
            &[(old_rel_key, c, [0x70; 32], ValueCapability::Yes)],
        );

        // C's head: commits BOTH old_rel_key->T_old_current and new_rel_key->T_new_established.
        let (c_head, c_commit, c_leaves) = signed_pdsmt(
            c,
            [0xD0 ^ c_seed; 32],
            c_seed,
            &[
                (old_rel_key, A_OLD, t_old_current, ValueCapability::Yes),
                (new_rel_key, A_NEW, t_new_established, ValueCapability::Yes),
            ],
        );

        let mut counterparties = BTreeMap::new();
        counterparties.insert(
            c,
            CounterpartyRecoveryInput {
                head: c_head,
                authority_commit: c_commit,
                leaves: c_leaves,
                old_segment: segment,
                establishment,
                h_cap,
            },
        );

        let inputs = RecoveryAssemblyInputs {
            genesis_id: G_A,
            a_old: A_OLD,
            a_new: A_NEW,
            a_old_head,
            a_old_authority_commit: a_old_commit,
            a_old_leaves,
            counterparties,
            tombstone,
            succession,
            recovery_intent_digest: [0x11; 32],
            tombstone_proposal_digest: [0x12; 32],
            final_per_device_smt_root: [0x13; 32],
            final_receipt_roll: [0x14; 32],
        };
        (inputs, ka.public_key.clone())
    }

    #[test]
    fn assembles_and_validates_single_counterparty() {
        let c = [0xC1; 32];
        let (inputs, ka_pub) = fixture_one(c, 0x55);
        let out = assemble_recovery_activation(&inputs, &ka_pub).expect("assembles");
        assert_eq!(out.gate_set, BTreeSet::from([c]));
        assert_eq!(out.evidence.len(), 1);
        assert_eq!(out.seal.synced_contact_count, 1);
        assert_eq!(out.seal.old_device_id, A_OLD);
        assert_eq!(out.seal.new_device_id, A_NEW);
        // The returned triple passes the canonical validator independently.
        validate_recovery_activation(&out.seal, &out.gate_set, &out.evidence, &ka_pub)
            .expect("validator accepts the assembled triple");
    }

    #[test]
    fn missing_posted_state_for_gate_member_fails_closed() {
        let c = [0xC1; 32];
        let (mut inputs, ka_pub) = fixture_one(c, 0x55);
        // c is in A_old's value-capable head (so it's a gate member) but drop its posted
        // state → cannot prove succession → fail closed.
        inputs.counterparties.clear();
        assert!(assemble_recovery_activation(&inputs, &ka_pub).is_err());
    }

    #[test]
    fn missing_new_rel_key_leaf_fails_closed() {
        let c = [0xC1; 32];
        let (mut inputs, ka_pub) = fixture_one(c, 0x55);
        // C never co-established (A_new,C): drop its new_rel_key leaf. The head signature no
        // longer matches the leaf set, but more fundamentally the successor relationship is
        // unproven → fail closed.
        let new_rel_key = compute_smt_key(&A_NEW, &c);
        let cin = inputs.counterparties.get_mut(&c).unwrap();
        cin.leaves.retain(|l| l.rel_key != new_rel_key);
        assert!(assemble_recovery_activation(&inputs, &ka_pub).is_err());
    }

    #[test]
    fn segment_floor_not_capsule_h_cap_fails_closed() {
        let c = [0xC1; 32];
        let (mut inputs, ka_pub) = fixture_one(c, 0x55);
        let cin = inputs.counterparties.get_mut(&c).unwrap();
        cin.old_segment.floor_tip = [0xEE; 32]; // != capsule h_cap
        assert!(assemble_recovery_activation(&inputs, &ka_pub).is_err());
    }

    #[test]
    fn wrong_recovery_authority_fails_closed() {
        let c = [0xC1; 32];
        let (inputs, _ka_pub) = fixture_one(c, 0x55);
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x01; 32]).unwrap();
        // A different authority cannot have signed A's tombstone/succession.
        assert!(assemble_recovery_activation(&inputs, &other.public_key).is_err());
    }

    #[test]
    fn anti_shrink_witness_forces_member_then_requires_its_evidence() {
        // A_old's head OMITS c2 (a shrink), but c2 posts its own value-capable leaf about
        // A_old AND full succession evidence → c2 is forced into the gate AND its evidence
        // assembles → activation still completes (the union is honored, not bypassed).
        let c1 = [0xC1; 32];
        let c2 = [0xC2; 32];
        let (mut inputs, ka_pub) = fixture_one(c1, 0x55);

        // Build c2's full consistent posted state + segment + receipt (reuse fixture_one for
        // c2, then graft its counterparty entry — its tombstone/succession/K_A match because
        // fixture_one is deterministic in the K_A seed).
        let (inputs2, ka_pub2) = fixture_one(c2, 0x66);
        assert_eq!(ka_pub, ka_pub2); // same deterministic K_A
        let c2_in = inputs2.counterparties.get(&c2).unwrap().clone();
        inputs.counterparties.insert(c2, c2_in);
        // A_old's head still lists only c1 → c2 enters ONLY via the anti-shrink union witness.

        let out = assemble_recovery_activation(&inputs, &ka_pub).expect("assembles with union");
        assert_eq!(out.gate_set, BTreeSet::from([c1, c2]));
        assert_eq!(out.evidence.len(), 2);
    }
}
