// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery activation (P4) — all-contact identity succession (spec §0.5).
//!
//! The successor device becomes spend-authoritative only after EVERY gate-set
//! member's OWN online-posted, genesis-authenticated state proves the
//! cross-relationship succession for this genesis — retire `(A_old,C)` and
//! establish a new bilateral `(A_new,C)` whose first accepted state carries forward
//! the old relationship's verified frontier — and the set of such proofs equals the
//! gate-set EXACTLY (no omission / substitution / duplicate). `rel_key` is
//! device-pair-derived (§18.1), so `(A_old,C)` and `(A_new,C)` are distinct leaves;
//! in-place same-`rel_key` migration is impossible by construction.
//!
//! Per-counterparty evidence is verified by [`crate::recovery::succession_binding`]
//! (device-pair `rel_key` derivation + tombstone/succession successor proof + old-chain
//! hash forward-ancestry from the capsule floor + carry-forward commitment + inclusion
//! of BOTH old and new tips in the counterparty's posted SMT root). There is **no**
//! standalone signed ack, **no** contacts-DB pubkey lookup, and **no** numeric height —
//! acceptance is hash adjacency only.
//!
//! Recovery authority is the counterparties' posted state, NOT the stolen device,
//! the capsule, or the local contacts DB (spec §0.5). The `gate_set` supplied here
//! is the authoritative online-posted, value-capable relationship set under the
//! genesis; this module enforces that the seal accounts for EXACTLY that set.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::recovery::capsule::contact_set_commit_from_device_ids;
use crate::recovery::succession_binding::CrossRelationshipSuccessionEvidence;
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, RecoveryActivationSealProto};
use std::collections::{BTreeMap, BTreeSet};

/// Fail-closed `Vec<u8>` → `[u8; 32]` for seal codec fields.
fn seal_fixed32(b: &[u8], field: &str) -> Result<[u8; 32], DsmError> {
    <[u8; 32]>::try_from(b).map_err(|_| {
        DsmError::verification(format!(
            "RecoveryActivationSeal: field `{field}` is {} bytes, expected 32",
            b.len()
        ))
    })
}

const EVIDENCE_ROOT_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_ACK_ROOT;
const ACTIVATION_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_ACTIVATION;

/// Commit to the complete, ordered set of per-counterparty evidence outcomes
/// (sorted by counterparty id): each entry is `(counterparty_devid, verified_tip)`.
/// Any omission, substitution, or change of a verified tip changes this root.
pub fn compute_evidence_root(entries: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<&([u8; 32], [u8; 32])> = entries.iter().collect();
    sorted.sort_unstable_by_key(|e| e.0);
    let mut hasher = dsm_domain_hasher(EVIDENCE_ROOT_DOMAIN);
    hasher.update(&(sorted.len() as u32).to_le_bytes());
    for (cp, tip) in sorted {
        hasher.update(cp);
        hasher.update(tip);
    }
    *hasher.finalize().as_bytes()
}

/// The recovery activation seal. A valid seal is the sole condition under which a
/// recovered successor may become spend-authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryActivationSeal {
    pub genesis_id: [u8; 32],
    pub old_device_id: [u8; 32],
    pub new_device_id: [u8; 32],
    pub recovery_intent_digest: [u8; 32],
    pub tombstone_proposal_digest: [u8; 32],
    pub contact_set_commit: [u8; 32],
    /// Commitment over the per-counterparty evidence outcomes (replaces the former
    /// signed-ack `ack_root`).
    pub evidence_root: [u8; 32],
    pub synced_contact_count: u64,
    pub final_per_device_smt_root: [u8; 32],
    pub final_receipt_roll: [u8; 32],
}

impl RecoveryActivationSeal {
    /// Deterministic digest binding the whole seal.
    pub fn activation_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(ACTIVATION_DOMAIN);
        for f in [
            &self.genesis_id,
            &self.old_device_id,
            &self.new_device_id,
            &self.recovery_intent_digest,
            &self.tombstone_proposal_digest,
            &self.contact_set_commit,
            &self.evidence_root,
            &self.final_per_device_smt_root,
            &self.final_receipt_roll,
        ] {
            h.update(f);
        }
        h.update(&self.synced_contact_count.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Serialize to canonical protobuf bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoveryActivationSealProto {
            genesis_id: self.genesis_id.to_vec(),
            old_device_id: self.old_device_id.to_vec(),
            new_device_id: self.new_device_id.to_vec(),
            recovery_intent_digest: self.recovery_intent_digest.to_vec(),
            tombstone_proposal_digest: self.tombstone_proposal_digest.to_vec(),
            contact_set_commit: self.contact_set_commit.to_vec(),
            evidence_root: self.evidence_root.to_vec(),
            synced_contact_count: self.synced_contact_count,
            final_per_device_smt_root: self.final_per_device_smt_root.to_vec(),
            final_receipt_roll: self.final_receipt_roll.to_vec(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed on any non-32-byte field).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RecoveryActivationSealProto::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RecoveryActivationSeal::from_bytes: {e}"),
                "RecoveryActivationSeal",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self {
            genesis_id: seal_fixed32(&p.genesis_id, "genesis_id")?,
            old_device_id: seal_fixed32(&p.old_device_id, "old_device_id")?,
            new_device_id: seal_fixed32(&p.new_device_id, "new_device_id")?,
            recovery_intent_digest: seal_fixed32(
                &p.recovery_intent_digest,
                "recovery_intent_digest",
            )?,
            tombstone_proposal_digest: seal_fixed32(
                &p.tombstone_proposal_digest,
                "tombstone_proposal_digest",
            )?,
            contact_set_commit: seal_fixed32(&p.contact_set_commit, "contact_set_commit")?,
            evidence_root: seal_fixed32(&p.evidence_root, "evidence_root")?,
            synced_contact_count: p.synced_contact_count,
            final_per_device_smt_root: seal_fixed32(
                &p.final_per_device_smt_root,
                "final_per_device_smt_root",
            )?,
            final_receipt_roll: seal_fixed32(&p.final_receipt_roll, "final_receipt_roll")?,
        })
    }
}

/// Validate the activation seal (spec §0.5 / P4).
///
/// - `gate_set`: the authoritative online-posted, value-capable relationship set
///   under the genesis (counterparty device ids).
/// - `evidence`: each gate-set counterparty's posted recovery evidence, already
///   storage-fetched and **genesis-authenticated by the caller** (storage =
///   availability; verification = client-side).
///
/// Enforces: count == gate-set; `contact_set_commit` == commit(gate-set);
/// evidence keys == gate-set EXACTLY (no omission/substitution/duplicate); every
/// counterparty's posted state proves the cross-relationship succession (retire
/// `(A_old,C)`, establish `(A_new,C)` carrying forward the old frontier — old-chain
/// forward-ancestry from the capsule floor + carry-forward commitment + inclusion of
/// both tips in its posted root); and `evidence_root` commits exactly the verified
/// outcomes.
pub fn validate_recovery_activation(
    seal: &RecoveryActivationSeal,
    gate_set: &BTreeSet<[u8; 32]>,
    evidence: &BTreeMap<[u8; 32], CrossRelationshipSuccessionEvidence>,
    recovery_authority_pubkey: &[u8],
) -> Result<(), DsmError> {
    if seal.synced_contact_count as usize != gate_set.len() {
        return Err(DsmError::verification(format!(
            "activation: synced_contact_count {} != gate-set size {}",
            seal.synced_contact_count,
            gate_set.len()
        )));
    }
    if seal.contact_set_commit != contact_set_commit_from_device_ids(gate_set) {
        return Err(DsmError::verification(
            "activation: contact_set_commit does not match the gate-set",
        ));
    }
    // Set-equality: evidence keys == gate-set. Map keys are unique, so this also
    // rules out duplicates; a missing or extra counterparty fails here.
    let ev_ids: BTreeSet<[u8; 32]> = evidence.keys().copied().collect();
    if &ev_ids != gate_set {
        return Err(DsmError::verification(
            "activation: evidence set is not equal to the gate-set (omission or substitution)",
        ));
    }
    // Per-counterparty: verify the cross-relationship succession (retire (A_old,C),
    // establish (A_new,C) carrying forward the old frontier).
    let mut entries: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(gate_set.len());
    for cp in gate_set {
        let ev = evidence.get(cp).ok_or_else(|| {
            DsmError::verification("activation: missing evidence for a gate-set counterparty")
        })?;
        // Bind the evidence to THIS gate-set counterparty and THIS recovery.
        if ev.c != *cp {
            return Err(DsmError::verification(
                "activation: evidence counterparty does not match the gate-set key",
            ));
        }
        if ev.a_old != seal.old_device_id || ev.a_new != seal.new_device_id {
            return Err(DsmError::verification(
                "activation: evidence does not bind the old→new device under recovery",
            ));
        }
        let tip = ev.verify(recovery_authority_pubkey)?;
        entries.push((*cp, tip));
    }
    if seal.evidence_root != compute_evidence_root(&entries) {
        return Err(DsmError::verification("activation: evidence_root mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::recovery::succession_binding::CrossRelationshipSuccessionEvidence;
    use crate::recovery::tombstone::{create_succession, create_tombstone};

    const OLD: [u8; 32] = [0xA0; 32];
    const NEW: [u8; 32] = [0xA1; 32];

    /// Stub evidence (constructible; its per-counterparty `verify` is not reached by
    /// the set-logic tests, which fail at count/commit/set-equality/binding first).
    fn stub_ev(c: [u8; 32]) -> CrossRelationshipSuccessionEvidence {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let a_old_str = crate::types::identifiers::encode_crockford(&OLD);
        let tombstone =
            create_tombstone(&[0x01; 32], 0, &[0x02; 32], &a_old_str, &kp.secret_key).expect("t");
        let succession = create_succession(
            &tombstone.tombstone_hash,
            NEW.as_ref(),
            &a_old_str,
            &kp.secret_key,
        )
        .expect("s");
        CrossRelationshipSuccessionEvidence {
            a_old: OLD,
            a_new: NEW,
            c,
            old_rel_key: [0; 32],
            new_rel_key: [0; 32],
            h_cap: [0; 32],
            t_old_current: [0; 32],
            old_chain: Vec::new(),
            t_new_established: [0x77; 32],
            new_establishment_state: crate::types::device_state::RelationshipChainState {
                rel_key: [0; 32],
                embedded_parent: [0; 32],
                counterparty_devid: c,
                operation: crate::types::operations::Operation::Noop,
                entropy: vec![0],
                encapsulated_entropy: None,
                balance_witness: BTreeMap::new(),
                entity_sig: None,
                counterparty_sig: None,
            },
            carry_forward_commitment: [0; 32],
            counterparty_root: [0x44; 32],
            old_inclusion_proof: Vec::new(),
            new_inclusion_proof: Vec::new(),
            tombstone,
            succession,
        }
    }

    fn gate(ids: &[[u8; 32]]) -> BTreeSet<[u8; 32]> {
        ids.iter().copied().collect()
    }

    fn seal_for(gate_set: &BTreeSet<[u8; 32]>) -> RecoveryActivationSeal {
        RecoveryActivationSeal {
            genesis_id: [0x09; 32],
            old_device_id: OLD,
            new_device_id: NEW,
            recovery_intent_digest: [0x03; 32],
            tombstone_proposal_digest: [0x04; 32],
            contact_set_commit: contact_set_commit_from_device_ids(gate_set),
            evidence_root: [0; 32],
            synced_contact_count: gate_set.len() as u64,
            final_per_device_smt_root: [0x05; 32],
            final_receipt_roll: [0x06; 32],
        }
    }

    #[test]
    fn seal_codec_round_trips() {
        let g = gate(&[[1; 32], [2; 32], [3; 32]]);
        let mut seal = seal_for(&g);
        seal.evidence_root = [0xEE; 32];
        let decoded = RecoveryActivationSeal::from_bytes(&seal.to_bytes()).expect("decode seal");
        assert_eq!(seal, decoded);
        assert_eq!(seal.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn count_mismatch_fails() {
        let g = gate(&[[1; 32], [2; 32]]);
        let mut seal = seal_for(&g);
        seal.synced_contact_count = 1;
        let ev: BTreeMap<_, _> = [([1u8; 32], stub_ev([1; 32])), ([2u8; 32], stub_ev([2; 32]))]
            .into_iter()
            .collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn contact_set_commit_mismatch_fails() {
        let g = gate(&[[1; 32], [2; 32]]);
        let mut seal = seal_for(&g);
        seal.contact_set_commit[0] ^= 0x01;
        let ev: BTreeMap<_, _> = [([1u8; 32], stub_ev([1; 32])), ([2u8; 32], stub_ev([2; 32]))]
            .into_iter()
            .collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn omission_fails() {
        let g = gate(&[[1; 32], [2; 32]]);
        let seal = seal_for(&g);
        // Evidence missing counterparty [2;32] → set-equality fails.
        let ev: BTreeMap<_, _> = [([1u8; 32], stub_ev([1; 32]))].into_iter().collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn substitution_fails() {
        let g = gate(&[[1; 32], [2; 32]]);
        let seal = seal_for(&g);
        // Evidence has an outsider [9;32] instead of [2;32] → set-equality fails.
        let ev: BTreeMap<_, _> = [([1u8; 32], stub_ev([1; 32])), ([9u8; 32], stub_ev([9; 32]))]
            .into_iter()
            .collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn binding_mismatch_fails() {
        // count + commit + set-equality pass; the per-counterparty binding check fires
        // because the evidence does not bind the old device under recovery.
        let g = gate(&[[1; 32]]);
        let seal = seal_for(&g);
        let mut e = stub_ev([1; 32]);
        e.a_old = [0xEE; 32]; // not seal.old_device_id
        let ev: BTreeMap<_, _> = [([1u8; 32], e)].into_iter().collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn evidence_counterparty_key_mismatch_fails() {
        let g = gate(&[[1; 32]]);
        let seal = seal_for(&g);
        let mut e = stub_ev([1; 32]);
        e.c = [0x55; 32]; // evidence's counterparty != gate-set key
        let ev: BTreeMap<_, _> = [([1u8; 32], e)].into_iter().collect();
        assert!(validate_recovery_activation(&seal, &g, &ev, &[]).is_err());
    }

    #[test]
    fn evidence_root_is_order_independent() {
        let a = ([1u8; 32], [0xAA; 32]);
        let b = ([2u8; 32], [0xBB; 32]);
        assert_eq!(
            compute_evidence_root(&[a, b]),
            compute_evidence_root(&[b, a])
        );
        let b2 = ([2u8; 32], [0xCC; 32]);
        assert_ne!(
            compute_evidence_root(&[a, b]),
            compute_evidence_root(&[a, b2])
        );
    }
}
