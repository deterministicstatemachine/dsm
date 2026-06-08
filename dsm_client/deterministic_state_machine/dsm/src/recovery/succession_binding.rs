// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-relationship succession evidence (spec §0.5).
//!
//! Recovery does NOT migrate `(A_old,C)` in place — `rel_key` is device-pair-derived
//! (`compute_smt_key`, §18.1), so `(A_old,C)` and `(A_new,C)` are different SMT leaves
//! by construction. Instead recovery **retires** `(A_old,C)` and **establishes** a new
//! bilateral `(A_new,C)` relationship whose **first accepted state** commits to the old
//! relationship's verified frontier (a "carry-forward" bridge). Continuity is expressed
//! by that commitment, not by reusing the leaf key.
//!
//! Authentication split (REUSE, do not reinvent):
//! - The new `(A_new,C)` establishment receipt is a normal **bilateral** stitched
//!   receipt (co-signed by A_new — alive — and C — syncing), authenticated by
//!   [`crate::verification::receipt_verification::verify_stitched_receipt`]
//!   (both sigs + EK-cert chains + inclusion + parent adjacency + uniqueness). That is
//!   the integration layer's job (it supplies `ReceiptVerificationContext`).
//! - This module verifies the **recovery-specific overlay**: device-pair `rel_key`
//!   derivation, the tombstone/succession successor proof, the old-chain
//!   forward-ancestry `h^cap ⟶* T_old_current`, the carry-forward commitment, the
//!   first-state constraint, and inclusion of BOTH tips in C's posted root.
//! - `counterparty_root` is a caller precondition: it must come from C's
//!   genesis-authenticated posted state (storage = availability; verification
//!   client-side), not taken on faith.
//!
//! Acceptance uses hash adjacency / parent consumption only — never numeric heights.

use crate::core::bilateral_transaction_manager::{compute_smt_key, initial_chain_tip_from_device_ids};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::recovery::tombstone::{verify_recovery_pair, SuccessionReceipt, TombstoneReceipt};
use crate::types::device_state::RelationshipChainState;
use crate::types::error::DsmError;
use crate::verification::proof_primitives::verify_smt_inclusion_proof_bytes;

const CARRY_FORWARD_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_CARRY_FORWARD;

/// The carry-forward commitment bound into the FIRST accepted state of the new
/// `(A_new,C)` relationship — a complete, auditable bridge from the old device leaf to
/// the new one. Binds BOTH the capsule floor it was measured against (`h_cap`) and C's
/// current old tip (`t_old_current`).
#[allow(clippy::too_many_arguments)]
pub fn compute_carry_forward_commitment(
    old_rel_key: &[u8; 32],
    new_rel_key: &[u8; 32],
    h_cap: &[u8; 32],
    t_old_current: &[u8; 32],
    tombstone_hash: &[u8],
    succession_hash: &[u8],
    a_old: &[u8; 32],
    a_new: &[u8; 32],
    c: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(CARRY_FORWARD_DOMAIN);
    h.update(old_rel_key);
    h.update(new_rel_key);
    h.update(h_cap);
    h.update(t_old_current);
    h.update(&(tombstone_hash.len() as u32).to_le_bytes());
    h.update(tombstone_hash);
    h.update(&(succession_hash.len() as u32).to_le_bytes());
    h.update(succession_hash);
    h.update(a_old);
    h.update(a_new);
    h.update(c);
    *h.finalize().as_bytes()
}

/// Walk a relationship chain forward from `floor_tip` by `embedded_parent` adjacency
/// (recomputing each tip via `compute_chain_tip`), returning the final tip. Pure hash
/// adjacency / parent consumption — no heights.
///
/// An **empty `chain` is valid**: it means no post-floor activity, so the floor IS the
/// current tip — this returns `floor_tip` and the caller's `walked == t_old_current`
/// check then enforces `t_old_current == h_cap`. This is the COMMON, no-divergence
/// recovery case (A_new's capsule tip already equals C's tip); a non-empty walk is the
/// exception (a thief spend in the post-floor, pre-tombstone window).
///
/// Walk integrity needs NO per-state signatures: both endpoints are pinned — `floor_tip`
/// from A_new's capsule and `t_old_current` (the caller's check target) in C's
/// genesis-authenticated PDSMT head — and DSM is deterministic + collision-resistant, so
/// the hash-adjacency walk between two fixed, authenticated tips is UNIQUE. A fabricated
/// or rolled-back step cannot reach the authenticated endpoint without a BLAKE3 collision.
pub fn verify_forward_ancestry(
    rel_key: &[u8; 32],
    floor_tip: &[u8; 32],
    chain: &[RelationshipChainState],
) -> Result<[u8; 32], DsmError> {
    let mut parent = *floor_tip;
    let mut last = *floor_tip;
    for s in chain {
        if &s.rel_key != rel_key {
            return Err(DsmError::verification("ancestry: rel_key mismatch in chain"));
        }
        if s.embedded_parent != parent {
            return Err(DsmError::verification(
                "ancestry: broken parent adjacency (not a forward descendant of the floor)",
            ));
        }
        last = s.compute_chain_tip();
        parent = last;
    }
    Ok(last)
}

/// One counterparty's complete cross-relationship recovery evidence (spec §0.5).
/// `counterparty_root` MUST be genesis-authenticated by the caller before use.
#[derive(Clone, Debug)]
pub struct CrossRelationshipSuccessionEvidence {
    pub a_old: [u8; 32],
    pub a_new: [u8; 32],
    pub c: [u8; 32],
    pub old_rel_key: [u8; 32],
    pub new_rel_key: [u8; 32],
    /// Capsule floor for the old relationship (A's sealed `(A_old,C)` tip).
    pub h_cap: [u8; 32],
    /// C's current `(A_old,C)` tip (a forward descendant of `h_cap`).
    pub t_old_current: [u8; 32],
    /// C's `(A_old,C)` states from `h_cap` (exclusive) up to `t_old_current`.
    pub old_chain: Vec<RelationshipChainState>,
    /// The new `(A_new,C)` relationship's first established tip.
    pub t_new_established: [u8; 32],
    /// The new establishment receipt's parent tip (must be the canonical first-ever
    /// parent for `(A_new,C)` — the first-state constraint).
    pub new_first_parent_tip: [u8; 32],
    /// The carry-forward commitment bound into the new first state.
    pub carry_forward_commitment: [u8; 32],
    /// C's posted per-device SMT root (genesis-authenticated by the caller).
    pub counterparty_root: [u8; 32],
    pub old_inclusion_proof: Vec<u8>,
    pub new_inclusion_proof: Vec<u8>,
    pub tombstone: TombstoneReceipt,
    pub succession: SuccessionReceipt,
}

impl CrossRelationshipSuccessionEvidence {
    /// Verify the recovery-specific semantics (checks 1–5 of spec §0.5): device-pair
    /// `rel_key` derivation, successor proof, old-chain forward-ancestry, carry-forward
    /// commitment, and the first-state constraint. Pure — no SMT proofs needed.
    /// `recovery_authority_pubkey` MUST be genesis-anchored to G_A by the caller.
    pub fn verify_succession_semantics(
        &self,
        recovery_authority_pubkey: &[u8],
    ) -> Result<(), DsmError> {
        // 1. Device-pair rel_key derivation (the leaves are distinct by construction).
        if self.a_old == self.a_new {
            return Err(DsmError::verification("succession: A_old == A_new"));
        }
        if self.old_rel_key != compute_smt_key(&self.a_old, &self.c) {
            return Err(DsmError::verification("succession: old_rel_key != H(A_old,C)"));
        }
        if self.new_rel_key != compute_smt_key(&self.a_new, &self.c) {
            return Err(DsmError::verification("succession: new_rel_key != H(A_new,C)"));
        }

        // 2. A_new is the mnemonic-authorized successor of A_old (genesis-anchored auth).
        let a_old_str = crate::types::identifiers::encode_crockford(&self.a_old);
        if self.tombstone.device_id != a_old_str {
            return Err(DsmError::verification("succession: tombstone is not for A_old"));
        }
        if self.succession.new_device_commitment.as_slice() != self.a_new {
            return Err(DsmError::verification(
                "succession: succession does not bind A_new",
            ));
        }
        if !verify_recovery_pair(&self.tombstone, &self.succession, recovery_authority_pubkey)? {
            return Err(DsmError::verification(
                "succession: tombstone/succession pair invalid under the genesis recovery authority",
            ));
        }

        // 3. Old-chain forward-ancestry: h^cap ⟶* T_old_current (no heights), all on
        //    the old relationship endpoint A_old.
        let walked = verify_forward_ancestry(&self.old_rel_key, &self.h_cap, &self.old_chain)?;
        if walked != self.t_old_current {
            return Err(DsmError::verification(
                "succession: old-chain ancestry does not reach T_old_current",
            ));
        }
        for s in &self.old_chain {
            if s.counterparty_devid != self.a_old {
                return Err(DsmError::verification(
                    "succession: old-chain state endpoint is not A_old",
                ));
            }
        }

        // 4. Carry-forward commitment binds (old/new rel_key, h_cap, T_old_current,
        //    tombstone, succession, A_old, A_new, C).
        let expected = compute_carry_forward_commitment(
            &self.old_rel_key,
            &self.new_rel_key,
            &self.h_cap,
            &self.t_old_current,
            &self.tombstone.tombstone_hash,
            &self.succession.succession_hash,
            &self.a_old,
            &self.a_new,
            &self.c,
        );
        if self.carry_forward_commitment != expected {
            return Err(DsmError::verification(
                "succession: carry-forward commitment mismatch",
            ));
        }

        // 5. First-state constraint: the new relationship's establishment receipt must
        //    have the canonical first-ever parent tip for (A_new,C) — the successor
        //    channel must be BORN as such (no bolting recovery onto a later update).
        let expected_first_parent = initial_chain_tip_from_device_ids(&self.a_new, &self.c);
        if self.new_first_parent_tip != expected_first_parent {
            return Err(DsmError::verification(
                "succession: new relationship is not a first-state establishment",
            ));
        }

        Ok(())
    }

    /// Full per-counterparty evidence check: the recovery semantics PLUS inclusion of
    /// BOTH `old_rel_key → T_old_current` and `new_rel_key → T_new_established` in C's
    /// posted (genesis-authenticated) root. Returns the verified new tip.
    ///
    /// NOTE: bilateral authentication of the new establishment receipt itself
    /// (signatures + EK-cert chains + adjacency) is performed by
    /// `verify_stitched_receipt` at the integration layer; this method assumes the
    /// receipt's tips are the values verified there.
    pub fn verify(&self, recovery_authority_pubkey: &[u8]) -> Result<[u8; 32], DsmError> {
        self.verify_succession_semantics(recovery_authority_pubkey)?;

        let old_ok = verify_smt_inclusion_proof_bytes(
            &self.counterparty_root,
            &self.old_rel_key,
            &self.t_old_current,
            &self.old_inclusion_proof,
        )?;
        if !old_ok {
            return Err(DsmError::verification(
                "succession: old-tip inclusion failed against counterparty root",
            ));
        }
        let new_ok = verify_smt_inclusion_proof_bytes(
            &self.counterparty_root,
            &self.new_rel_key,
            &self.t_new_established,
            &self.new_inclusion_proof,
        )?;
        if !new_ok {
            return Err(DsmError::verification(
                "succession: new-tip inclusion failed against counterparty root",
            ));
        }
        Ok(self.t_new_established)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::recovery::tombstone::{create_succession, create_tombstone};
    use crate::types::operations::Operation;
    use std::collections::BTreeMap;

    const A_OLD: [u8; 32] = [0xA0; 32];
    const A_NEW: [u8; 32] = [0xA1; 32];
    const C: [u8; 32] = [0xC0; 32];

    fn old_state(rel_key: [u8; 32], parent: [u8; 32], endpoint: [u8; 32], e: u8) -> RelationshipChainState {
        RelationshipChainState {
            rel_key,
            embedded_parent: parent,
            counterparty_devid: endpoint,
            operation: Operation::Noop,
            entropy: vec![e],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: None,
            counterparty_sig: None,
            dbrw_summary_hash: None,
        }
    }

    /// Build a fully-valid evidence (recovery semantics) + the authority pubkey.
    fn fixture() -> (CrossRelationshipSuccessionEvidence, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let a_old_str = crate::types::identifiers::encode_crockford(&A_OLD);

        let tombstone = create_tombstone(&[0x01; 32], 0, &[0x02; 32], &a_old_str, &kp.secret_key)
            .expect("tombstone");
        let succession =
            create_succession(&tombstone.tombstone_hash, &A_NEW.to_vec(), &a_old_str, &kp.secret_key)
                .expect("succession");

        let old_rel_key = compute_smt_key(&A_OLD, &C);
        let new_rel_key = compute_smt_key(&A_NEW, &C);
        let h_cap = [0x33; 32];
        // One old-chain step from the floor to the current old tip.
        let s = old_state(old_rel_key, h_cap, A_OLD, 1);
        let t_old_current = s.compute_chain_tip();
        let carry = compute_carry_forward_commitment(
            &old_rel_key,
            &new_rel_key,
            &h_cap,
            &t_old_current,
            &tombstone.tombstone_hash,
            &succession.succession_hash,
            &A_OLD,
            &A_NEW,
            &C,
        );
        let ev = CrossRelationshipSuccessionEvidence {
            a_old: A_OLD,
            a_new: A_NEW,
            c: C,
            old_rel_key,
            new_rel_key,
            h_cap,
            t_old_current,
            old_chain: vec![s],
            t_new_established: [0x77; 32],
            new_first_parent_tip: initial_chain_tip_from_device_ids(&A_NEW, &C),
            carry_forward_commitment: carry,
            counterparty_root: [0x44; 32],
            old_inclusion_proof: Vec::new(),
            new_inclusion_proof: Vec::new(),
            tombstone,
            succession,
        };
        (ev, kp.public_key.clone())
    }

    #[test]
    fn valid_semantics_pass() {
        let (ev, pk) = fixture();
        ev.verify_succession_semantics(&pk).expect("valid semantics");
    }

    #[test]
    fn empty_old_chain_valid_only_at_floor() {
        // Common case: NO post-floor activity → empty old_chain, floor IS the current tip.
        let (mut ev, pk) = fixture();
        ev.old_chain = Vec::new();
        ev.t_old_current = ev.h_cap;
        ev.carry_forward_commitment = compute_carry_forward_commitment(
            &ev.old_rel_key,
            &ev.new_rel_key,
            &ev.h_cap,
            &ev.t_old_current,
            &ev.tombstone.tombstone_hash,
            &ev.succession.succession_hash,
            &ev.a_old,
            &ev.a_new,
            &ev.c,
        );
        ev.verify_succession_semantics(&pk)
            .expect("empty old_chain at the floor (no divergence) is valid");

        // Empty old_chain but a t_old_current that ISN'T the floor cannot be reached by
        // the (empty) walk → rejected.
        let mut bad = ev.clone();
        bad.t_old_current[0] ^= 0x01;
        bad.carry_forward_commitment = compute_carry_forward_commitment(
            &bad.old_rel_key,
            &bad.new_rel_key,
            &bad.h_cap,
            &bad.t_old_current,
            &bad.tombstone.tombstone_hash,
            &bad.succession.succession_hash,
            &bad.a_old,
            &bad.a_new,
            &bad.c,
        );
        assert!(bad.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn wrong_new_rel_key_fails() {
        let (mut ev, pk) = fixture();
        ev.new_rel_key[0] ^= 0x01;
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn wrong_old_rel_key_fails() {
        let (mut ev, pk) = fixture();
        ev.old_rel_key[0] ^= 0x01;
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn wrong_recovery_authority_fails() {
        let (ev, _pk) = fixture();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).expect("kp");
        assert!(ev.verify_succession_semantics(&other.public_key).is_err());
    }

    #[test]
    fn succession_not_binding_a_new_fails() {
        // Rebuild succession binding a different successor.
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let (mut ev, pk) = fixture();
        let a_old_str = crate::types::identifiers::encode_crockford(&A_OLD);
        ev.succession = create_succession(
            &ev.tombstone.tombstone_hash,
            &[0xBB; 32].to_vec(),
            &a_old_str,
            &kp.secret_key,
        )
        .expect("succ");
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn broken_old_ancestry_fails() {
        let (mut ev, pk) = fixture();
        ev.old_chain[0].embedded_parent = [0xDE; 32]; // not the floor
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn ancestry_tip_mismatch_fails() {
        let (mut ev, pk) = fixture();
        ev.t_old_current[0] ^= 0x01; // no longer the chain's final tip
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn old_chain_wrong_endpoint_fails() {
        let (mut ev, pk) = fixture();
        // Recompute the chain with a non-A_old endpoint but keep t_old_current consistent.
        let s = old_state(ev.old_rel_key, ev.h_cap, [0xEE; 32], 1);
        ev.t_old_current = s.compute_chain_tip();
        ev.old_chain = vec![s];
        // carry-forward still references the old t_old_current → also mismatched, but the
        // endpoint check fires regardless.
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn carry_forward_mismatch_fails() {
        let (mut ev, pk) = fixture();
        ev.carry_forward_commitment[0] ^= 0x01;
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn not_first_state_fails() {
        let (mut ev, pk) = fixture();
        ev.new_first_parent_tip = [0x12; 32]; // not the canonical genesis tip
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }
}
