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

/// Build the `CreateRelationship` operation for a recovery establishment state — the
/// FIRST state of the new `(A_new,C)` relationship. The carry-forward commitment is
/// placed in the op's `commitment` field so it is bound INTO the state hash when the
/// state is co-signed; this is what `verify_succession_semantics` checks to prove the
/// channel was born as the recovery successor. The bilateral re-establish flow puts this
/// op in the first `(A_new,C)` state (parent = `initial_chain_tip_from_device_ids(A_new,C)`)
/// and both parties co-sign it.
pub fn build_recovery_establishment_op(
    c: &[u8; 32],
    carry_forward_commitment: &[u8; 32],
    h_cap: &[u8; 32],
) -> crate::types::operations::Operation {
    // `proof` carries the capsule floor `h_cap`. It is ALREADY committed (an input to
    // `carry_forward_commitment`); revealing the 32-byte preimage here lets C recompute the
    // carry-forward over its own `(A_old,C)` chain in the accept-guard
    // (`verify_recovery_reestablish_request`). Because it rides in the co-signed op, h_cap is
    // tamper-evident. (verify_succession_semantics / the assembler check the op's
    // counterparty_id + commitment, not proof, so this is compatible.)
    crate::types::operations::Operation::CreateRelationship {
        message: RECOVERY_ESTABLISH_MESSAGE.to_string(),
        counterparty_id: c.to_vec(),
        commitment: carry_forward_commitment.to_vec(),
        proof: h_cap.to_vec(),
        mode: crate::types::operations::TransactionMode::Bilateral,
    }
}

/// The canonical operation marker for a recovery re-establish `CreateRelationship`
/// (set by [`build_recovery_establishment_op`]).
pub const RECOVERY_ESTABLISH_MESSAGE: &str = "recovery-establish";

/// Whether `op` is a recovery re-establish proposal — a `CreateRelationship` carrying the
/// canonical [`RECOVERY_ESTABLISH_MESSAGE`] marker. The bilateral handler uses this to decide
/// whether an incoming prepare must pass [`verify_recovery_reestablish_request`] before C
/// co-signs (ordinary establishes are untouched). The marker only SELECTS the guard; the guard
/// itself re-derives and checks every binding, so a forged marker cannot bypass verification.
pub fn is_recovery_establish_op(op: &crate::types::operations::Operation) -> bool {
    matches!(
        op,
        crate::types::operations::Operation::CreateRelationship { message, .. }
            if message == RECOVERY_ESTABLISH_MESSAGE
    )
}

/// Extract the capsule floor `h_cap` a recovery-establish op carries in its `proof` field.
/// Returns `None` if the op is not a `CreateRelationship` or `proof` is not exactly 32 bytes
/// (fail-closed — the accept-guard then has no floor to verify and rejects).
pub fn recovery_establishment_floor(op: &crate::types::operations::Operation) -> Option<[u8; 32]> {
    match op {
        crate::types::operations::Operation::CreateRelationship { proof, .. } => {
            <[u8; 32]>::try_from(proof.as_slice()).ok()
        }
        _ => None,
    }
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
            return Err(DsmError::verification(
                "ancestry: rel_key mismatch in chain",
            ));
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

/// C-SIDE accept-guard for a recovery re-establish (spec §0.5) — **gate 1 (identity
/// succession) of the two-gate model; NOT a standalone anti-theft control.** When counterparty
/// `C` receives a bilateral `CreateRelationship` "recovery-establish" proposal from `A_new`, it
/// MUST run this BEFORE co-signing. It proves, from C's OWN local `(A_old,C)` chain plus A's
/// genesis-anchored tombstone/succession, that:
///   1. the op is a `recovery-establish` `CreateRelationship` toward C carrying a commitment;
///   2. `A_new` is the mnemonic-authorized successor of `A_old`
///      ([`verify_recovery_pair`] under the genesis-anchored recovery authority);
///   3. the device-pair keys derive correctly and C's old-chain endpoint is `A_old`;
///   4. the claimed capsule floor `h_cap` is a genuine ancestor of C's current `(A_old,C)`
///      tip (forward-ancestry walk over C's own states → `t_old_current`);
///   5. the op's commitment EQUALS the carry-forward C recomputes from those — i.e. the
///      successor channel is being born bridging C's REAL CURRENT frontier, not a fabricated
///      or stale one.
///
/// **What this guard does and does not stop.** It blocks (a) any party WITHOUT the genesis
/// recovery authority (a non-mnemonic forger — a MITM, a malicious storage node, C itself)
/// from producing a re-establish, and (b) ANYONE — including a mnemonic holder — from
/// re-establishing onto a fabricated or stale `(A_old,C)` frontier (the carry-forward is pinned
/// to C's real current tip, so no value-inflating / channel-forking frontier can be born).
/// It does **NOT** distinguish the legitimate owner from a mnemonic thief: the mnemonic IS the
/// recovery authority, so a thief who holds it passes gate 1 by construction — that is the
/// unavoidable stolen-seed problem, not a defect of this guard. Double-spend safety against a
/// recovering party (owner-with-stale-ring OR thief) replaying spent value comes from gate 2
/// (P5 `LOCKED_RECOVERY` + per-asset frontier reconciliation against external truth), which is
/// independent of this guard. See §0.4 (two-gate doctrine).
///
/// `recovery_authority_pubkey` MUST be genesis-anchored to A's genesis by the caller (via the
/// `RecoveryAuthorityAnchor` + device-tree quorum) before this is trusted. Fail-closed: any
/// check failing means C MUST NOT co-sign.
#[allow(clippy::too_many_arguments)]
pub fn verify_recovery_reestablish_request(
    op: &crate::types::operations::Operation,
    a_old: &[u8; 32],
    a_new: &[u8; 32],
    c_self: &[u8; 32],
    tombstone: &TombstoneReceipt,
    succession: &SuccessionReceipt,
    recovery_authority_pubkey: &[u8],
    h_cap: &[u8; 32],
    c_old_chain: &[RelationshipChainState],
) -> Result<(), DsmError> {
    // 1. The op is a recovery-establish CreateRelationship toward C; extract the commitment.
    let commitment = match op {
        crate::types::operations::Operation::CreateRelationship {
            counterparty_id,
            commitment,
            ..
        } => {
            if counterparty_id.as_slice() != c_self {
                return Err(DsmError::verification(
                    "reestablish: op counterparty_id != C (self)",
                ));
            }
            commitment.clone()
        }
        _ => {
            return Err(DsmError::verification(
                "reestablish: op is not CreateRelationship",
            ))
        }
    };

    if a_old == a_new {
        return Err(DsmError::verification("reestablish: A_old == A_new"));
    }

    // 2. A_new is the mnemonic-authorized successor of A_old (genesis-anchored authority).
    let a_old_str = crate::types::identifiers::encode_crockford(a_old);
    if tombstone.device_id != a_old_str {
        return Err(DsmError::verification(
            "reestablish: tombstone is not for A_old",
        ));
    }
    if succession.new_device_commitment.as_slice() != a_new {
        return Err(DsmError::verification(
            "reestablish: succession does not bind A_new",
        ));
    }
    if !verify_recovery_pair(tombstone, succession, recovery_authority_pubkey)? {
        return Err(DsmError::verification(
            "reestablish: tombstone/succession pair invalid under the genesis recovery authority",
        ));
    }

    // 3. Device-pair keys + C's old-chain endpoint is A_old.
    let old_rel_key = compute_smt_key(a_old, c_self);
    let new_rel_key = compute_smt_key(a_new, c_self);
    for s in c_old_chain {
        if &s.counterparty_devid != a_old {
            return Err(DsmError::verification(
                "reestablish: C old-chain state endpoint is not A_old",
            ));
        }
    }

    // 4. h_cap is a genuine ancestor of C's current (A_old,C) tip (binds the claimed floor to
    //    C's real chain) → C's current tip.
    let t_old_current = verify_forward_ancestry(&old_rel_key, h_cap, c_old_chain)?;

    // 5. The op's commitment is exactly the carry-forward C recomputes from its own frontier.
    let expected = compute_carry_forward_commitment(
        &old_rel_key,
        &new_rel_key,
        h_cap,
        &t_old_current,
        &tombstone.tombstone_hash,
        &succession.succession_hash,
        a_old,
        a_new,
        c_self,
    );
    if commitment.as_slice() != expected {
        return Err(DsmError::verification(
            "reestablish: op commitment != carry-forward over C's real (A_old,C) frontier",
        ));
    }
    Ok(())
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
    /// The new `(A_new,C)` relationship's first established tip (== `compute_chain_tip`
    /// of `new_establishment_state`; included in `counterparty_root`).
    pub t_new_established: [u8; 32],
    /// The new `(A_new,C)` relationship's FIRST state — must be a first-state
    /// establishment (canonical first-ever parent) whose `CreateRelationship` operation
    /// binds the carry-forward commitment INTO the state hash. This is what makes the
    /// successor channel provably "born as such" (no bolting recovery onto an ordinary
    /// `(A_new,C)` relationship).
    pub new_establishment_state: RelationshipChainState,
    /// The carry-forward commitment (recomputed + checked == the commitment bound in
    /// `new_establishment_state`'s operation).
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
            return Err(DsmError::verification(
                "succession: old_rel_key != H(A_old,C)",
            ));
        }
        if self.new_rel_key != compute_smt_key(&self.a_new, &self.c) {
            return Err(DsmError::verification(
                "succession: new_rel_key != H(A_new,C)",
            ));
        }

        // 2. A_new is the mnemonic-authorized successor of A_old (genesis-anchored auth).
        let a_old_str = crate::types::identifiers::encode_crockford(&self.a_old);
        if self.tombstone.device_id != a_old_str {
            return Err(DsmError::verification(
                "succession: tombstone is not for A_old",
            ));
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

        // 5. First-state + carry-forward BINDING. The new (A_new,C) establishment state
        //    must (a) be on new_rel_key toward C, (b) be a first-state (canonical
        //    first-ever parent), (c) bind the carry-forward commitment INTO its
        //    `CreateRelationship` operation, and (d) hash to t_new_established. Together
        //    this proves the successor channel was BORN as such — the carry-forward is in
        //    the signed state hash, not a free-floating field — so recovery semantics
        //    cannot be bolted onto an ordinary or later (A_new,C) relationship.
        let est = &self.new_establishment_state;
        if est.rel_key != self.new_rel_key {
            return Err(DsmError::verification(
                "succession: establishment state rel_key != new_rel_key",
            ));
        }
        if est.counterparty_devid != self.c {
            return Err(DsmError::verification(
                "succession: establishment state counterparty != C",
            ));
        }
        if est.embedded_parent != initial_chain_tip_from_device_ids(&self.a_new, &self.c) {
            return Err(DsmError::verification(
                "succession: new relationship is not a first-state establishment",
            ));
        }
        match &est.operation {
            crate::types::operations::Operation::CreateRelationship {
                counterparty_id,
                commitment,
                ..
            } => {
                if counterparty_id.as_slice() != self.c {
                    return Err(DsmError::verification(
                        "succession: establishment op counterparty_id != C",
                    ));
                }
                if commitment.as_slice() != self.carry_forward_commitment {
                    return Err(DsmError::verification(
                        "succession: establishment op does not bind the carry-forward commitment",
                    ));
                }
            }
            _ => {
                return Err(DsmError::verification(
                    "succession: establishment state op is not CreateRelationship",
                ))
            }
        }
        if est.compute_chain_tip() != self.t_new_established {
            return Err(DsmError::verification(
                "succession: establishment state does not hash to T_new_established",
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

        // Inclusion of BOTH tips under C's `counterparty_root`. `counterparty_root` IS C's
        // posted PDSMT `pd_smt_root` — a `SparseMerkleTree` root — and the proofs are C's
        // posted leaf proofs (`inclusion_proof_to_pd_smt_root`, `SmtInclusionProof` bytes).
        // The verifier MUST therefore be the SparseMerkleTree verifier (the SAME one
        // `pdsmt_posting` uses for `verify_inclusion`); the protobuf-`SmtProof` verifier
        // (`proof_primitives`) reconstructs a DIFFERENT tree and cannot validate these
        // proofs against a SparseMerkleTree root.
        crate::recovery::pdsmt_posting::verify_smt_leaf(
            &self.counterparty_root,
            &self.old_rel_key,
            &self.t_old_current,
            &self.old_inclusion_proof,
            "succession old-tip",
        )?;
        crate::recovery::pdsmt_posting::verify_smt_leaf(
            &self.counterparty_root,
            &self.new_rel_key,
            &self.t_new_established,
            &self.new_inclusion_proof,
            "succession new-tip",
        )?;
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

    fn old_state(
        rel_key: [u8; 32],
        parent: [u8; 32],
        endpoint: [u8; 32],
        e: u8,
    ) -> RelationshipChainState {
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
        let succession = create_succession(
            &tombstone.tombstone_hash,
            A_NEW.as_ref(),
            &a_old_str,
            &kp.secret_key,
        )
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
        // The new (A_new,C) establishment FIRST state: canonical first parent, carry-forward
        // bound into its CreateRelationship op.
        let est = RelationshipChainState {
            rel_key: new_rel_key,
            embedded_parent: initial_chain_tip_from_device_ids(&A_NEW, &C),
            counterparty_devid: C,
            operation: build_recovery_establishment_op(&C, &carry, &h_cap),
            entropy: vec![9],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: None,
            counterparty_sig: None,
            dbrw_summary_hash: None,
        };
        let t_new_established = est.compute_chain_tip();
        let ev = CrossRelationshipSuccessionEvidence {
            a_old: A_OLD,
            a_new: A_NEW,
            c: C,
            old_rel_key,
            new_rel_key,
            h_cap,
            t_old_current,
            old_chain: vec![s],
            t_new_established,
            new_establishment_state: est,
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
        ev.verify_succession_semantics(&pk)
            .expect("valid semantics");
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
        // The new (A_new,C) establishment must be BORN binding this recomputed carry-forward:
        // rebuild its op + re-derive the included tip so the "born as successor" check holds.
        ev.new_establishment_state.operation =
            build_recovery_establishment_op(&ev.c, &ev.carry_forward_commitment, &ev.h_cap);
        ev.t_new_established = ev.new_establishment_state.compute_chain_tip();
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
        // Keep the carry-forward binding internally consistent so the rejection comes from
        // the (empty) ancestry walk failing to reach t_old_current, not the binding check.
        bad.new_establishment_state.operation =
            build_recovery_establishment_op(&bad.c, &bad.carry_forward_commitment, &bad.h_cap);
        bad.t_new_established = bad.new_establishment_state.compute_chain_tip();
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
            [0xBB; 32].as_ref(),
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
        // Non-canonical first parent → not a first-state establishment (also breaks the
        // tip-hash binding). Recompute t_new_established so the FIRST-STATE check is what
        // fires (otherwise the hash-binding check would mask it).
        ev.new_establishment_state.embedded_parent = [0x12; 32];
        ev.t_new_established = ev.new_establishment_state.compute_chain_tip();
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn carry_forward_not_bound_in_establishment_op_fails() {
        // The establishment op carries a DIFFERENT commitment than carry_forward_commitment
        // → the "born as successor" binding fails (can't bolt recovery onto an ordinary rel).
        let (mut ev, pk) = fixture();
        ev.new_establishment_state.operation =
            build_recovery_establishment_op(&C, &[0xBE; 32], &ev.h_cap); // wrong commitment
        ev.t_new_established = ev.new_establishment_state.compute_chain_tip();
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn is_recovery_establish_op_selects_only_the_marker() {
        // The real recovery-establish op carries the canonical marker → selected.
        let op = build_recovery_establishment_op(&C, &[0x11; 32], &[0x22; 32]);
        assert!(is_recovery_establish_op(&op));
        assert_eq!(recovery_establishment_floor(&op), Some([0x22; 32]));
        // An ordinary CreateRelationship (different message) is NOT selected — the BLE guard
        // must leave normal establishes alone.
        let ordinary = Operation::CreateRelationship {
            message: "create rel".to_string(),
            counterparty_id: C.to_vec(),
            commitment: [0x11; 32].to_vec(),
            proof: [0x22; 32].to_vec(),
            mode: crate::types::operations::TransactionMode::Bilateral,
        };
        assert!(!is_recovery_establish_op(&ordinary));
        // A non-CreateRelationship op is never selected.
        assert!(!is_recovery_establish_op(&Operation::Noop));
    }

    #[test]
    fn establishment_op_not_create_relationship_fails() {
        let (mut ev, pk) = fixture();
        ev.new_establishment_state.operation = Operation::Noop; // not CreateRelationship
        ev.t_new_established = ev.new_establishment_state.compute_chain_tip();
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    #[test]
    fn establishment_tip_mismatch_fails() {
        // t_new_established doesn't match the establishment state's hash → rejected
        // (the included tip must BE the established state).
        let (mut ev, pk) = fixture();
        ev.t_new_established[0] ^= 0x01;
        assert!(ev.verify_succession_semantics(&pk).is_err());
    }

    /// Populate `counterparty_root` + the two inclusion proofs with REAL SparseMerkleTree
    /// proofs for `old_rel_key → t_old_current` and `new_rel_key → t_new_established` —
    /// exactly how C's posted PDSMT carries them. This exercises the FULL `ev.verify`
    /// inclusion path (the part `verify_succession_semantics` skips), against a genuine
    /// SparseMerkleTree root.
    fn with_real_inclusion(ev: &mut CrossRelationshipSuccessionEvidence) {
        use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
        let mut pd = SparseMerkleTree::new(256);
        pd.update_leaf(&ev.old_rel_key, &ev.t_old_current).unwrap();
        pd.update_leaf(&ev.new_rel_key, &ev.t_new_established)
            .unwrap();
        ev.counterparty_root = *pd.root();
        ev.old_inclusion_proof = pd
            .get_inclusion_proof(&ev.old_rel_key, 256)
            .unwrap()
            .to_bytes();
        ev.new_inclusion_proof = pd
            .get_inclusion_proof(&ev.new_rel_key, 256)
            .unwrap()
            .to_bytes();
    }

    #[test]
    fn full_verify_with_real_pdsmt_inclusion_proofs_passes() {
        // Regression: ev.verify must validate REAL SparseMerkleTree PDSMT proofs against a
        // SparseMerkleTree counterparty_root. (Previously it used the protobuf SmtProof
        // verifier, which cannot decode/validate these — a latent liveness-fatal mismatch.)
        let (mut ev, pk) = fixture();
        with_real_inclusion(&mut ev);
        let tip = ev
            .verify(&pk)
            .expect("full evidence with real PDSMT proofs verifies");
        assert_eq!(tip, ev.t_new_established);
    }

    #[test]
    fn full_verify_rejects_tampered_old_inclusion_proof() {
        let (mut ev, pk) = fixture();
        with_real_inclusion(&mut ev);
        // Flip a byte in the proof → recomputed root != counterparty_root → fail closed.
        let last = ev.old_inclusion_proof.len() - 1;
        ev.old_inclusion_proof[last] ^= 0x01;
        assert!(ev.verify(&pk).is_err());
    }

    #[test]
    fn full_verify_rejects_wrong_counterparty_root() {
        let (mut ev, pk) = fixture();
        with_real_inclusion(&mut ev);
        ev.counterparty_root[0] ^= 0x01; // proofs no longer recompute this root
        assert!(ev.verify(&pk).is_err());
    }

    #[test]
    fn full_verify_rejects_tip_not_in_root() {
        // A new tip that isn't the one committed under counterparty_root must fail inclusion
        // (the semantics check passes for a matching establishment, but inclusion does not).
        let (mut ev, pk) = fixture();
        with_real_inclusion(&mut ev);
        // Rebuild establishment so semantics still pass but the committed new tip differs.
        ev.new_establishment_state.entropy = vec![0xAB; 5];
        ev.t_new_established = ev.new_establishment_state.compute_chain_tip();
        // counterparty_root/proofs still commit the OLD t_new_established → inclusion fails.
        assert!(ev.verify(&pk).is_err());
    }

    // ── C-side recovery re-establish accept-guard ──────────────────────────

    /// Build a valid C-side re-establish request from the fixture (the op carries the
    /// carry-forward C will recompute over its own (A_old,C) chain).
    fn reestablish_request() -> (Operation, CrossRelationshipSuccessionEvidence, Vec<u8>) {
        let (ev, pk) = fixture();
        let op = build_recovery_establishment_op(&C, &ev.carry_forward_commitment, &ev.h_cap);
        (op, ev, pk)
    }

    #[test]
    fn reestablish_accept_guard_passes_for_valid_request() {
        let (op, ev, pk) = reestablish_request();
        verify_recovery_reestablish_request(
            &op,
            &A_OLD,
            &A_NEW,
            &C,
            &ev.tombstone,
            &ev.succession,
            &pk,
            &ev.h_cap,
            &ev.old_chain,
        )
        .expect("valid recovery re-establish request must be accepted");
    }

    #[test]
    fn reestablish_rejects_wrong_carry_forward_in_op() {
        let (_op, ev, pk) = reestablish_request();
        let bad_op = build_recovery_establishment_op(&C, &[0xBE; 32], &ev.h_cap); // not the real carry-forward
        assert!(verify_recovery_reestablish_request(
            &bad_op,
            &A_OLD,
            &A_NEW,
            &C,
            &ev.tombstone,
            &ev.succession,
            &pk,
            &ev.h_cap,
            &ev.old_chain,
        )
        .is_err());
    }

    #[test]
    fn reestablish_rejects_wrong_recovery_authority() {
        let (op, ev, _pk) = reestablish_request();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x01; 32]).unwrap();
        // A thief without A's genesis-anchored authority can't pass verify_recovery_pair.
        assert!(verify_recovery_reestablish_request(
            &op,
            &A_OLD,
            &A_NEW,
            &C,
            &ev.tombstone,
            &ev.succession,
            &other.public_key,
            &ev.h_cap,
            &ev.old_chain,
        )
        .is_err());
    }

    #[test]
    fn reestablish_rejects_non_create_relationship_op() {
        let (_op, ev, pk) = reestablish_request();
        assert!(verify_recovery_reestablish_request(
            &Operation::Noop,
            &A_OLD,
            &A_NEW,
            &C,
            &ev.tombstone,
            &ev.succession,
            &pk,
            &ev.h_cap,
            &ev.old_chain,
        )
        .is_err());
    }

    #[test]
    fn reestablish_rejects_op_for_wrong_counterparty() {
        let (op, ev, pk) = reestablish_request();
        // Same op but verified as if C were a DIFFERENT device → counterparty_id != C(self).
        assert!(verify_recovery_reestablish_request(
            &op,
            &A_OLD,
            &A_NEW,
            &[0xDD; 32],
            &ev.tombstone,
            &ev.succession,
            &pk,
            &ev.h_cap,
            &ev.old_chain,
        )
        .is_err());
    }

    #[test]
    fn reestablish_rejects_broken_old_chain_ancestry() {
        let (op, mut ev, pk) = reestablish_request();
        // Tamper C's old chain so h_cap no longer walks to the committed t_old_current.
        ev.old_chain[0].embedded_parent = [0xDE; 32];
        assert!(verify_recovery_reestablish_request(
            &op,
            &A_OLD,
            &A_NEW,
            &C,
            &ev.tombstone,
            &ev.succession,
            &pk,
            &ev.h_cap,
            &ev.old_chain,
        )
        .is_err());
    }
}
