// SPDX-License-Identifier: MIT OR Apache-2.0

//! Relationship-state evidence postings (spec §0.5 Phase D prerequisite).
//!
//! PDSMT heads/leaves (see [`crate::recovery::pdsmt_posting`]) prove *what the current tip
//! is* plus value-capability classification. They do NOT prove *how* a relationship
//! reached that tip. Recovery succession ([`crate::recovery::succession_binding`]) requires
//! each counterparty C's actual relationship-state material so the verifier can prove:
//!
//! 1. **old-chain ancestry** — C's `(A_old,C)` states from the capsule floor `h_cap`
//!    (exclusive) up to its current tip `T_old_current`
//!    ([`RelationshipChainSegment`]); and
//! 2. **successor establishment** — the new `(A_new,C)` first state whose
//!    `CreateRelationship` op binds the carry-forward commitment
//!    ([`RecoveryEstablishmentReceipt`]).
//!
//! Both objects are **availability-only** and **content-addressed**: the content id is a
//! BLAKE3 domain-separated digest of the canonical protobuf bytes. The client
//! re-verifies everything locally — it recomputes every state's chain tip, walks the
//! ancestry between two pinned endpoints, and checks the establishment is a first state.
//! **Storage never attests.** A missing or invalid object FAILS CLOSED at the verifier;
//! it can never advance recovery, only block it.
//!
//! Wire: protobuf-only ([`RelationshipChainSegmentV1`] / [`RecoveryEstablishmentReceiptV1`]
//! with the faithful [`RelationshipChainStateProto`] codec). Acceptance is hash adjacency /
//! parent consumption — never numeric heights.

use std::collections::BTreeMap;

use crate::core::bilateral_transaction_manager::{
    compute_smt_key, initial_chain_tip_from_device_ids,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::recovery::succession_binding::verify_forward_ancestry;
use crate::types::device_state::RelationshipChainState;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::proto::{
    BalanceWitnessEntryProto, Message as _, RecoveryEstablishmentReceiptV1,
    RelationshipChainSegmentV1, RelationshipChainStateProto,
};

const REL_SEGMENT_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_REL_SEGMENT;
const ESTABLISH_RECEIPT_DOMAIN: &str =
    crate::common::domain_tags::TAG_DSM_RECOVERY_ESTABLISH_RECEIPT;

/// Coerce a protobuf `bytes` field to a fixed 32-byte array, failing closed on any other
/// length (a wrong-length hash field is a malformed object, never silently truncated/padded).
fn fixed32(field: &str, v: &[u8]) -> Result<[u8; 32], DsmError> {
    v.try_into().map_err(|_| {
        DsmError::verification(format!(
            "chain_segment: {field} must be 32 bytes, got {}",
            v.len()
        ))
    })
}

// ──────────────────────────────────────────────────────────────────────────
// RelationshipChainState protobuf codec (faithful round-trip).
//
// EVERY field that feeds `compute_chain_tip()` is preserved so a decoder can recompute the
// tip and assert equality. proto3 `optional` distinguishes None from an empty Some, which
// the chain-tip hash treats differently.
// ──────────────────────────────────────────────────────────────────────────

/// Encode a [`RelationshipChainState`] to its faithful protobuf message.
pub fn rel_chain_state_to_proto(s: &RelationshipChainState) -> RelationshipChainStateProto {
    RelationshipChainStateProto {
        rel_key: s.rel_key.to_vec(),
        embedded_parent: s.embedded_parent.to_vec(),
        counterparty_devid: s.counterparty_devid.to_vec(),
        operation: s.operation.to_bytes(),
        entropy: s.entropy.clone(),
        encapsulated_entropy: s.encapsulated_entropy.clone(),
        dbrw_summary_hash: s.dbrw_summary_hash.map(|d| d.to_vec()),
        // BTreeMap iterates sorted by 32B policy_commit → canonical order on the wire.
        balance_witness: s
            .balance_witness
            .iter()
            .map(|(pc, v)| BalanceWitnessEntryProto {
                policy_commit: pc.to_vec(),
                value: *v,
            })
            .collect(),
        entity_sig: s.entity_sig.clone(),
        counterparty_sig: s.counterparty_sig.clone(),
    }
}

/// Decode a [`RelationshipChainState`] from its protobuf message (fail-closed).
pub fn rel_chain_state_from_proto(
    p: &RelationshipChainStateProto,
) -> Result<RelationshipChainState, DsmError> {
    let dbrw_summary_hash = match &p.dbrw_summary_hash {
        Some(d) => Some(fixed32("dbrw_summary_hash", d)?),
        None => None,
    };

    let mut balance_witness: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (i, e) in p.balance_witness.iter().enumerate() {
        let pc = fixed32("balance_witness.policy_commit", &e.policy_commit)?;
        // BTreeMap dedups silently; a duplicate key on the wire is a malformed object.
        if balance_witness.insert(pc, e.value).is_some() {
            return Err(DsmError::verification(format!(
                "chain_segment: duplicate balance_witness policy_commit at index {i}"
            )));
        }
    }

    Ok(RelationshipChainState {
        rel_key: fixed32("rel_key", &p.rel_key)?,
        embedded_parent: fixed32("embedded_parent", &p.embedded_parent)?,
        counterparty_devid: fixed32("counterparty_devid", &p.counterparty_devid)?,
        operation: Operation::from_bytes(&p.operation)
            .map_err(|e| DsmError::verification(format!("chain_segment: operation: {e}")))?,
        entropy: p.entropy.clone(),
        encapsulated_entropy: p.encapsulated_entropy.clone(),
        balance_witness,
        entity_sig: p.entity_sig.clone(),
        counterparty_sig: p.counterparty_sig.clone(),
        dbrw_summary_hash,
    })
}

// ──────────────────────────────────────────────────────────────────────────
// Relationship-chain ancestry segment.
// ──────────────────────────────────────────────────────────────────────────

/// A contiguous forward-ancestry segment of ONE relationship chain — C's `(A_old,C)`
/// states from the capsule floor `floor_tip` (`h_cap`, EXCLUSIVE) up to `current_tip`
/// (`T_old_current`). Availability-only + content-addressed; verified locally.
#[derive(Clone, Debug)]
pub struct RelationshipChainSegment {
    /// Device-pair `rel_key` of the relationship this segment covers.
    pub rel_key: [u8; 32],
    /// The capsule floor `h_cap`. The segment starts AFTER this tip (exclusive).
    pub floor_tip: [u8; 32],
    /// `T_old_current` — the tip the walk must reach.
    pub current_tip: [u8; 32],
    /// States from `floor_tip` (exclusive) to `current_tip` (inclusive), in chain order.
    /// EMPTY iff `floor_tip == current_tip` (the no-divergence common case).
    pub states: Vec<RelationshipChainState>,
}

impl RelationshipChainSegment {
    /// Serialize to canonical protobuf bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        RelationshipChainSegmentV1 {
            rel_key: self.rel_key.to_vec(),
            floor_tip: self.floor_tip.to_vec(),
            current_tip: self.current_tip.to_vec(),
            states: self.states.iter().map(rel_chain_state_to_proto).collect(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed: every nested state must decode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RelationshipChainSegmentV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RelationshipChainSegment::from_bytes: {e}"),
                "RelationshipChainSegment",
                None::<String>,
                Some(e),
            )
        })?;
        let mut states = Vec::with_capacity(p.states.len());
        for sp in &p.states {
            states.push(rel_chain_state_from_proto(sp)?);
        }
        Ok(Self {
            rel_key: fixed32("rel_key", &p.rel_key)?,
            floor_tip: fixed32("floor_tip", &p.floor_tip)?,
            current_tip: fixed32("current_tip", &p.current_tip)?,
            states,
        })
    }

    /// Content id = `BLAKE3("DSM/recovery/rel-chain-segment/v1" || canonical-bytes)`.
    /// An availability/dedup handle only — integrity rests on [`Self::verify`], not on
    /// the content id being canonical across encoders.
    pub fn content_id(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(REL_SEGMENT_DOMAIN);
        h.update(&self.to_bytes());
        *h.finalize().as_bytes()
    }

    /// Verify the segment is a self-consistent forward-ancestry walk: every state is on
    /// `rel_key`, adjacency holds from `floor_tip` through each `embedded_parent`, and the
    /// recomputed final tip equals `current_tip`. An empty `states` is valid iff
    /// `floor_tip == current_tip`. (Reuses the canonical
    /// [`verify_forward_ancestry`] walk — no duplicate adjacency logic.)
    ///
    /// This proves the OBJECT is a valid path. Binding it to an authenticated endpoint
    /// (`current_tip == T_old_current` from C's genesis-authenticated PDSMT head) and to
    /// the capsule floor is the evidence-assembly step's job
    /// ([`crate::recovery::CrossRelationshipSuccessionEvidence`]).
    pub fn verify(&self) -> Result<(), DsmError> {
        let walked = verify_forward_ancestry(&self.rel_key, &self.floor_tip, &self.states)?;
        if walked != self.current_tip {
            return Err(DsmError::verification(
                "rel-chain-segment: walk does not reach the declared current_tip",
            ));
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────
// New-relationship establishment receipt.
// ──────────────────────────────────────────────────────────────────────────

/// The new `(A_new,C)` bilateral establishment receipt — the FIRST state of the successor
/// relationship whose `CreateRelationship` op binds the carry-forward commitment.
/// Availability-only + content-addressed; verified locally.
#[derive(Clone, Debug)]
pub struct RecoveryEstablishmentReceipt {
    /// `new_rel_key` = `compute_smt_key(A_new, C)`.
    pub rel_key: [u8; 32],
    /// The first `(A_new,C)` state.
    pub state: RelationshipChainState,
}

impl RecoveryEstablishmentReceipt {
    /// Serialize to canonical protobuf bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoveryEstablishmentReceiptV1 {
            rel_key: self.rel_key.to_vec(),
            state: Some(rel_chain_state_to_proto(&self.state)),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RecoveryEstablishmentReceiptV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RecoveryEstablishmentReceipt::from_bytes: {e}"),
                "RecoveryEstablishmentReceipt",
                None::<String>,
                Some(e),
            )
        })?;
        let state = p.state.as_ref().ok_or_else(|| {
            DsmError::verification("establish-receipt: missing state")
        })?;
        Ok(Self {
            rel_key: fixed32("rel_key", &p.rel_key)?,
            state: rel_chain_state_from_proto(state)?,
        })
    }

    /// Content id = `BLAKE3("DSM/recovery/establish-receipt/v1" || canonical-bytes)`.
    pub fn content_id(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(ESTABLISH_RECEIPT_DOMAIN);
        h.update(&self.to_bytes());
        *h.finalize().as_bytes()
    }

    /// The established tip = `compute_chain_tip` of the first state (== `T_new_established`).
    pub fn established_tip(&self) -> [u8; 32] {
        self.state.compute_chain_tip()
    }

    /// The carry-forward commitment bound into the establishment op, if the op is a
    /// `CreateRelationship` (the only valid establishment shape). `None` otherwise — the
    /// caller treats `None` as a fail-closed mismatch.
    pub fn bound_commitment(&self) -> Option<[u8; 32]> {
        match &self.state.operation {
            Operation::CreateRelationship { commitment, .. } => commitment.as_slice().try_into().ok(),
            _ => None,
        }
    }

    /// Verify the receipt is a well-formed first-state `(A_new,C)` establishment: the
    /// device-pair `rel_key` matches, the state is on that key toward C, and it carries the
    /// canonical first-ever parent (the first-state constraint). The carry-forward *value*
    /// binding (`commitment == carry_forward_commitment`) is checked during evidence
    /// assembly ([`crate::recovery::CrossRelationshipSuccessionEvidence`]), which knows the
    /// expected commitment.
    pub fn verify(&self, a_new: &[u8; 32], c: &[u8; 32]) -> Result<(), DsmError> {
        let expected_rel_key = compute_smt_key(a_new, c);
        if self.rel_key != expected_rel_key {
            return Err(DsmError::verification(
                "establish-receipt: rel_key != compute_smt_key(A_new, C)",
            ));
        }
        if self.state.rel_key != self.rel_key {
            return Err(DsmError::verification(
                "establish-receipt: state.rel_key != receipt rel_key",
            ));
        }
        if &self.state.counterparty_devid != c {
            return Err(DsmError::verification(
                "establish-receipt: state.counterparty_devid != C",
            ));
        }
        if self.state.embedded_parent != initial_chain_tip_from_device_ids(a_new, c) {
            return Err(DsmError::verification(
                "establish-receipt: not a first-state establishment (wrong canonical parent)",
            ));
        }
        match &self.state.operation {
            Operation::CreateRelationship { counterparty_id, .. } => {
                if counterparty_id.as_slice() != c {
                    return Err(DsmError::verification(
                        "establish-receipt: op counterparty_id != C",
                    ));
                }
            }
            _ => {
                return Err(DsmError::verification(
                    "establish-receipt: op is not CreateRelationship",
                ))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::succession_binding::build_recovery_establishment_op;
    use crate::types::operations::{Operation, TransactionMode};

    const A_NEW: [u8; 32] = [0xA1; 32];
    const C: [u8; 32] = [0xCC; 32];

    fn mk_state(rel_key: [u8; 32], parent: [u8; 32], c: [u8; 32], tag: u8) -> RelationshipChainState {
        let mut bw = BTreeMap::new();
        bw.insert([tag; 32], tag as u64);
        RelationshipChainState {
            rel_key,
            embedded_parent: parent,
            counterparty_devid: c,
            operation: Operation::CreateRelationship {
                message: format!("op-{tag}"),
                counterparty_id: c.to_vec(),
                commitment: vec![tag; 16],
                proof: vec![tag; 4],
                mode: TransactionMode::Bilateral,
            },
            entropy: vec![tag, tag, tag],
            encapsulated_entropy: if tag % 2 == 0 { Some(vec![tag; 4]) } else { None },
            balance_witness: bw,
            entity_sig: Some(vec![0x11; 8]),
            counterparty_sig: None,
            dbrw_summary_hash: Some([tag; 32]),
        }
    }

    fn sample_segment() -> RelationshipChainSegment {
        let rk = [0x55; 32];
        let floor = [0x01; 32];
        let s0 = mk_state(rk, floor, C, 2);
        let t0 = s0.compute_chain_tip();
        let s1 = mk_state(rk, t0, C, 3);
        let t1 = s1.compute_chain_tip();
        RelationshipChainSegment {
            rel_key: rk,
            floor_tip: floor,
            current_tip: t1,
            states: vec![s0, s1],
        }
    }

    #[test]
    fn rel_chain_state_proto_round_trips_tip() {
        let s = mk_state([0x55; 32], [0x01; 32], C, 2);
        let decoded = rel_chain_state_from_proto(&rel_chain_state_to_proto(&s)).expect("decode");
        // The chain tip — the security-relevant invariant — is preserved exactly.
        assert_eq!(decoded.compute_chain_tip(), s.compute_chain_tip());
        // None vs Some(empty) presence is preserved (odd tag → None encap).
        let s_none = mk_state([0x55; 32], [0x01; 32], C, 3);
        let d_none = rel_chain_state_from_proto(&rel_chain_state_to_proto(&s_none)).expect("d");
        assert_eq!(d_none.encapsulated_entropy, None);
        assert_eq!(d_none.compute_chain_tip(), s_none.compute_chain_tip());
    }

    #[test]
    fn segment_round_trips_and_verifies() {
        let seg = sample_segment();
        seg.verify().expect("valid segment verifies");
        let decoded = RelationshipChainSegment::from_bytes(&seg.to_bytes()).expect("decode");
        // Field-equality via canonical bytes + content id (the type intentionally has no
        // PartialEq — RelationshipChainState/Operation don't implement Eq).
        assert_eq!(seg.to_bytes(), decoded.to_bytes());
        assert_eq!(decoded.content_id(), seg.content_id());
        assert_eq!(decoded.rel_key, seg.rel_key);
        assert_eq!(decoded.floor_tip, seg.floor_tip);
        assert_eq!(decoded.current_tip, seg.current_tip);
        assert_eq!(decoded.states.len(), seg.states.len());
        decoded.verify().expect("decoded still verifies");
    }

    #[test]
    fn empty_segment_valid_only_at_floor() {
        let rk = [0x55; 32];
        let floor = [0x77; 32];
        let ok = RelationshipChainSegment {
            rel_key: rk,
            floor_tip: floor,
            current_tip: floor,
            states: Vec::new(),
        };
        ok.verify().expect("empty == floor is valid (no divergence)");

        let bad = RelationshipChainSegment {
            rel_key: rk,
            floor_tip: floor,
            current_tip: [0x78; 32], // not the floor, but no states to reach it
            states: Vec::new(),
        };
        assert!(bad.verify().is_err());
    }

    #[test]
    fn segment_tampered_state_fails_walk() {
        let mut seg = sample_segment();
        // Mutate a middle state so its recomputed tip no longer matches the next parent.
        seg.states[0].entropy = vec![0xFF; 9];
        assert!(seg.verify().is_err());
    }

    #[test]
    fn segment_broken_adjacency_fails() {
        let mut seg = sample_segment();
        seg.states[1].embedded_parent = [0xEE; 32]; // not a descendant of states[0]
        assert!(seg.verify().is_err());
    }

    #[test]
    fn segment_wrong_rel_key_in_state_fails() {
        let mut seg = sample_segment();
        seg.states[0].rel_key = [0x99; 32];
        assert!(seg.verify().is_err());
    }

    #[test]
    fn segment_from_bytes_rejects_short_hash() {
        let seg = sample_segment();
        let mut p = RelationshipChainSegmentV1::decode(seg.to_bytes().as_slice()).unwrap();
        p.rel_key = vec![0x00; 31]; // wrong length
        assert!(RelationshipChainSegment::from_bytes(&p.encode_to_vec()).is_err());
    }

    fn sample_receipt() -> RecoveryEstablishmentReceipt {
        let rk = compute_smt_key(&A_NEW, &C);
        let carry = [0xBC; 32];
        let state = RelationshipChainState {
            rel_key: rk,
            embedded_parent: initial_chain_tip_from_device_ids(&A_NEW, &C),
            counterparty_devid: C,
            operation: build_recovery_establishment_op(&C, &carry, &[0x33; 32]),
            entropy: vec![0x01],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: Some(vec![0x22; 8]),
            counterparty_sig: Some(vec![0x33; 8]),
            dbrw_summary_hash: None,
        };
        RecoveryEstablishmentReceipt { rel_key: rk, state }
    }

    #[test]
    fn receipt_round_trips_and_verifies() {
        let r = sample_receipt();
        r.verify(&A_NEW, &C).expect("valid receipt verifies");
        let decoded = RecoveryEstablishmentReceipt::from_bytes(&r.to_bytes()).expect("decode");
        assert_eq!(r.to_bytes(), decoded.to_bytes());
        assert_eq!(decoded.content_id(), r.content_id());
        assert_eq!(decoded.established_tip(), r.established_tip());
        assert_eq!(decoded.bound_commitment(), Some([0xBC; 32]));
        decoded.verify(&A_NEW, &C).expect("decoded verifies");
    }

    #[test]
    fn receipt_wrong_counterparty_fails() {
        let r = sample_receipt();
        assert!(r.verify(&A_NEW, &[0xDD; 32]).is_err());
    }

    #[test]
    fn receipt_non_first_state_fails() {
        let mut r = sample_receipt();
        r.state.embedded_parent = [0x12; 32]; // not the canonical first-ever parent
        assert!(r.verify(&A_NEW, &C).is_err());
    }

    #[test]
    fn receipt_non_create_relationship_op_fails() {
        let mut r = sample_receipt();
        r.state.operation = Operation::Noop;
        assert!(r.verify(&A_NEW, &C).is_err());
    }

    #[test]
    fn receipt_rel_key_mismatch_fails() {
        let mut r = sample_receipt();
        r.rel_key = [0x00; 32]; // != compute_smt_key(A_new, C)
        assert!(r.verify(&A_NEW, &C).is_err());
    }

    #[test]
    fn receipt_from_bytes_rejects_missing_state() {
        let r = sample_receipt();
        let mut p = RecoveryEstablishmentReceiptV1::decode(r.to_bytes().as_slice()).unwrap();
        p.state = None;
        assert!(RecoveryEstablishmentReceipt::from_bytes(&p.encode_to_vec()).is_err());
    }
}
