// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! The P0–P6 proof obligations, as tests.
//!
//! Each test here is one of the obligations the area 8 / position-commitment
//! design carried, in the same numbering spirit: the gates that must exist,
//! demonstrated by presenting material that is *individually valid* and
//! *jointly wrong* — the composition failures three review rounds kept
//! finding in the documents, now pinned against the code.

use std::sync::OnceLock;

use dsm::ccb::{
    delegation_genesis_sentinel, genesis_v3_commitment, role, sigalg, transition_genesis_sentinel,
    DeviceTreeRootTransition, GenesisParamsV3, RootProgressionDelegation,
};
use dsm::common::device_tree::DeviceTree;
use dsm::core::identity::authority_resolver::{
    authenticate_anchor_owner, resolve_owner_authority_at_position, PresentedIdentity,
    ResolveFailure, SignedDelegation, SignedTransition,
};
use dsm::core::identity::genesis_v2::derive_devid;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::crypto::sphincs::sphincs_sign;

const NET: &[u8] = b"dsm-test";

/// One fully-populated identity world, built once: a GRK, two delegations
/// (`D_0` from the sentinel, `D_1` activating at `T_1`), four transitions
/// whose roots deliberately RECUR (`A → B → A → C`), a device tree containing
/// the device, and the presented key material.
struct World {
    g_o: [u8; 32],
    params: GenesisParamsV3,
    grk: SignatureKeyPair,
    delegate0: SignatureKeyPair,
    d0: SignedDelegation,
    d1: SignedDelegation,
    transitions: Vec<SignedTransition>,
    tree: DeviceTree,
    ak: SignatureKeyPair,
    atta: [u8; 32],
    d_o: [u8; 32],
}

fn kp(seed: u8) -> SignatureKeyPair {
    SignatureKeyPair::generate_from_entropy(&[seed; 32]).expect("fixture")
}

fn sign_delegation(d: &RootProgressionDelegation, grk: &SignatureKeyPair) -> SignedDelegation {
    let msg = d.signing_digest().expect("fixture");
    SignedDelegation {
        delegation: d.clone(),
        grk_signature: sphincs_sign(&grk.secret_key, &msg).expect("fixture"),
    }
}

fn sign_transition(t: &DeviceTreeRootTransition, key: &SignatureKeyPair) -> SignedTransition {
    let msg = t.signing_digest();
    SignedTransition {
        transition: t.clone(),
        delegate_signature: sphincs_sign(&key.secret_key, &msg).expect("fixture"),
    }
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let grk = kp(0x01);
        let delegate0 = kp(0x02);
        let delegate1 = kp(0x03);
        let ak = kp(0x04);
        let atta = [0x22; 32];
        let d_o = derive_devid(&ak.public_key, &atta);

        let params = GenesisParamsV3::new(
            [0x11; 32],
            NET,
            3,
            sigalg::SPHINCS_PLUS_SPX256F,
            &grk.public_key,
        )
        .expect("fixture");
        let g_o = genesis_v3_commitment(&params).expect("fixture");

        // The device tree; the same tree at every generation of this fixture,
        // with root values that recur by using two alternating trees.
        let tree = DeviceTree::new(vec![d_o, [0xEE; 32]]);
        let root_a = tree.root();
        let other = DeviceTree::single([0xEE; 32]);
        let root_b = other.root();
        let root_c = DeviceTree::new(vec![d_o, [0xEE; 32], [0xDD; 32]]).root();

        let d0 = RootProgressionDelegation {
            genesis_id: g_o,
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: delegate0.public_key.clone(),
            delegation_number: 0,
            parent_delegation_digest: delegation_genesis_sentinel(),
            activation_transition_digest: transition_genesis_sentinel(),
        };

        // Transitions: T0 sentinel→A (v0, D0), T1 A→B (v1, D0),
        // T2 B→A (v2, D1: D1 activates at T1), T3 A→C (v4, D1).
        // Root values recur (A at T0 and T2) — the edge, not the root, is
        // what fixes every position.
        let t0 = DeviceTreeRootTransition {
            genesis_id: g_o,
            predecessor_transition_digest: transition_genesis_sentinel(),
            new_root: root_a,
            version_number: 0,
            delegation_digest: d0.digest().expect("fixture"),
        };
        let t1 = DeviceTreeRootTransition {
            genesis_id: g_o,
            predecessor_transition_digest: t0.digest(),
            new_root: root_b,
            version_number: 1,
            delegation_digest: d0.digest().expect("fixture"),
        };

        let d1 = RootProgressionDelegation {
            genesis_id: g_o,
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: delegate1.public_key.clone(),
            delegation_number: 1,
            parent_delegation_digest: d0.digest().expect("fixture"),
            activation_transition_digest: t1.digest(),
        };

        let t2 = DeviceTreeRootTransition {
            genesis_id: g_o,
            predecessor_transition_digest: t1.digest(),
            new_root: root_a,
            version_number: 2,
            delegation_digest: d1.digest().expect("fixture"),
        };
        let t3 = DeviceTreeRootTransition {
            genesis_id: g_o,
            predecessor_transition_digest: t2.digest(),
            new_root: root_c,
            version_number: 4,
            delegation_digest: d1.digest().expect("fixture"),
        };

        let transitions = vec![
            sign_transition(&t0, &delegate0),
            sign_transition(&t1, &delegate0),
            sign_transition(&t2, &delegate1),
            sign_transition(&t3, &delegate1),
        ];

        World {
            g_o,
            d0: sign_delegation(&d0, &grk),
            d1: sign_delegation(&d1, &grk),
            params,
            grk,
            delegate0,
            transitions,
            tree,
            ak,
            atta,
            d_o,
        }
    })
}

fn presented<'a>(
    w: &'a World,
    dels: &'a [SignedDelegation],
    trans: &'a [SignedTransition],
    proof: &'a dsm::common::device_tree::DevTreeProof,
) -> PresentedIdentity<'a> {
    PresentedIdentity {
        genesis_params: &w.params,
        delegations: dels,
        transitions: trans,
        inclusion: proof,
        ak_pk: &w.ak.public_key,
        atta: &w.atta,
    }
}

fn is_invalid(r: &Result<impl core::fmt::Debug, ResolveFailure>) -> bool {
    matches!(r, Err(ResolveFailure::Invalid(_)))
}

/// The happy path: the full chain, bound at `T_2` (whose root CONTAINS the
/// device), proven end to end.
#[test]
fn the_full_chain_resolves_at_a_bound_position() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest();
    let p = presented(w, &dels, &w.transitions, &proof);
    let proven = resolve_owner_authority_at_position(&w.g_o, &position, &p).expect("fixture");
    assert_eq!(proven.ak_pk, w.ak.public_key);
    assert_eq!(proven.device_id, w.d_o);
    assert_eq!(proven.position, position);
}

/// Position-scoped, not tip-scoped: a chain LONGER than the bound position
/// still verifies at the position, and the longer tail changes nothing.
#[test]
fn a_longer_chain_does_not_disturb_a_position_scoped_proof() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[0].transition.digest(); // T0, root A
    let p = presented(w, &dels, &w.transitions, &proof);
    resolve_owner_authority_at_position(&w.g_o, &position, &p).expect("fixture");
}

/// P0: flipping one byte of the presented GRK key makes G disagree with g_o,
/// and NOTHING downstream runs.
#[test]
fn a_forged_genesis_parameter_set_fails_at_p0() {
    let w = world();
    let mut flipped_pk = w.grk.public_key.clone();
    flipped_pk[0] ^= 1;
    let forged = GenesisParamsV3::new(
        [0x11; 32],
        NET,
        3,
        sigalg::SPHINCS_PLUS_SPX256F,
        &flipped_pk,
    )
    .expect("fixture");
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest();
    let mut p = presented(w, &dels, &w.transitions, &proof);
    p.genesis_params = &forged;
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(is_invalid(&r), "P0 must refuse: {r:?}");
}

/// Truncated ancestry is refused — asserted on the OUTCOME. Presenting
/// `[T0, T3]` with the middle withheld: `T3`'s predecessor edge cannot
/// resolve against the shorter prefix, so the bound position is unreachable.
/// Under the burned old_root model this attachment would have SUCCEEDED
/// (running root A, version 4 > 0) and revived the retired `D_0`.
#[test]
fn a_truncated_ancestry_is_refused_not_reattached() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let truncated = vec![w.transitions[0].clone(), w.transitions[3].clone()];
    let position = w.transitions[3].transition.digest();
    let p = presented(w, &dels, &truncated, &proof);
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(
        matches!(r, Err(ResolveFailure::Incomplete(_))),
        "the edge cannot resolve, and without a frontier withholding is \
         indistinguishable from absence: {r:?}"
    );
}

/// Supersession is enforced, not declared: once `act(D_1)` (= `T_1`) is in a
/// transition's proper ancestry, a successor of `T_1` bound to `D_0` is
/// refused EVEN THOUGH `D_0` is validly GRK-signed and on the chain.
#[test]
fn a_retired_delegation_cannot_sign_past_its_successors_activation() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");

    // A forged T2 bound to D0 instead of the applicable D1.
    let rogue = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: w.transitions[1].transition.digest(),
        new_root: w.tree.root(),
        version_number: 2,
        delegation_digest: w.d0.delegation.digest().expect("fixture"),
    };
    let signed_rogue = sign_transition(&rogue, &w.delegate0);
    let trans = vec![
        w.transitions[0].clone(),
        w.transitions[1].clone(),
        signed_rogue.clone(),
    ];
    let position = rogue.digest();
    let p = presented(w, &dels, &trans, &proof);
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(
        is_invalid(&r),
        "a retired delegation must be refused: {r:?}"
    );
}

/// Inactivity cascades: a `D_2` whose predecessor `D_1`'s activation never
/// resolves must NOT become applicable, even though `act(D_2)` itself
/// resolves — the lineage skipped an edge it never proved.
#[test]
fn an_unresolved_predecessor_blocks_all_descendant_activations() {
    let w = world();
    let delegate2 = kp(0x05);

    // D1' activates at a transition that will never exist on the chain.
    let phantom = [0x99; 32];
    let d1_unresolved = RootProgressionDelegation {
        activation_transition_digest: phantom,
        ..w.d1.delegation.clone()
    };
    let d1s = sign_delegation(&d1_unresolved, &w.grk);

    // D2 chains D1' and activates at T1 — which RESOLVES. Without the
    // cascade, D2 would become applicable.
    let d2 = RootProgressionDelegation {
        genesis_id: w.g_o,
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
        delegated_pk: delegate2.public_key.clone(),
        delegation_number: 2,
        parent_delegation_digest: d1_unresolved.digest().expect("fixture"),
        activation_transition_digest: w.transitions[1].transition.digest(),
    };
    let d2s = sign_delegation(&d2, &w.grk);

    // A transition after T1 bound to D2.
    let t2_by_d2 = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: w.transitions[1].transition.digest(),
        new_root: w.tree.root(),
        version_number: 2,
        delegation_digest: d2.digest().expect("fixture"),
    };
    let signed = sign_transition(&t2_by_d2, &delegate2);

    let dels = vec![w.d0.clone(), d1s, d2s];
    let trans = vec![
        w.transitions[0].clone(),
        w.transitions[1].clone(),
        signed.clone(),
    ];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = t2_by_d2.digest();
    let p = presented(w, &dels, &trans, &proof);
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(
        is_invalid(&r),
        "D2 must not activate through an unresolved D1: {r:?}"
    );
}

/// Forks are refused, never ordered — on BOTH chains. A second delegation at
/// number 1, and a second successor of T0; in each case the higher/newer
/// alternative must NOT win.
#[test]
fn forks_are_refused_on_both_chains() {
    let w = world();
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest();

    // Delegation fork: a different D1 (other key), same number, validly signed.
    let other = kp(0x06);
    let d1_fork = RootProgressionDelegation {
        delegated_pk: other.public_key.clone(),
        ..w.d1.delegation.clone()
    };
    let dels = vec![
        w.d0.clone(),
        w.d1.clone(),
        sign_delegation(&d1_fork, &w.grk),
    ];
    let p = presented(w, &dels, &w.transitions, &proof);
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(is_invalid(&r), "delegation fork must refuse: {r:?}");

    // Transition fork: a second, validly-signed successor of T0 with a HIGHER
    // version. Refused — not selected by version.
    let t1_fork = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: w.transitions[0].transition.digest(),
        new_root: w.tree.root(),
        version_number: 9,
        delegation_digest: w.d0.delegation.digest().expect("fixture"),
    };
    let dels2 = vec![w.d0.clone(), w.d1.clone()];
    let mut trans = w.transitions.clone();
    trans.push(sign_transition(&t1_fork, &w.delegate0));
    let p2 = presented(w, &dels2, &trans, &proof);
    let r2 = resolve_owner_authority_at_position(&w.g_o, &position, &p2);
    assert!(
        is_invalid(&r2),
        "transition fork must refuse — the higher version must not win: {r2:?}"
    );
}

/// P4/P5: a presented key whose recomputed d_o is not in the tree is refused,
/// and the right AttA with the wrong key is refused identically.
#[test]
fn identity_recomputation_gates_membership() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest();

    let stranger = kp(0x07);
    let mut p = presented(w, &dels, &w.transitions, &proof);
    p.ak_pk = &stranger.public_key;
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(
        is_invalid(&r),
        "a stranger's key recomputes a d_o the tree does not contain: {r:?}"
    );

    let wrong_atta = [0x33; 32];
    let mut p2 = presented(w, &dels, &w.transitions, &proof);
    p2.atta = &wrong_atta;
    let r2 = resolve_owner_authority_at_position(&w.g_o, &position, &p2);
    assert!(is_invalid(&r2), "wrong AttA, same refusal: {r2:?}");
}

/// Stage 6, the join: a valid AnchorV3 under `K_1` plus a valid P0–P6 proof
/// for a distinct `K_2` must be refused, even though both halves are
/// individually valid and neither is forged. This is the case a suite built
/// from valid/invalid object pairs never generates on its own.
#[test]
fn two_individually_valid_halves_do_not_join() {
    use dsm::ccb::{
        vault_state_commitment, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy,
        StorageSetMembers, VaultStateV2,
    };
    use dsm::dlv::vault_state_anchor_v3::sign_vault_state_anchor_v3;

    let w = world();
    let position = w.transitions[2].transition.digest();

    let mut token_a = [0u8; 32];
    let mut token_b = [0u8; 32];
    token_a[0] = 1;
    token_b[0] = 2;
    let state = VaultStateV2 {
        owner_genesis_id: w.g_o,
        owner_device_id: w.d_o,
        vault_id: [0x55; 32],
        generation: 0,
        reserve_a: 10,
        reserve_b: 10,
        market_policy: MarketPolicy::beta_constant_product(token_a, token_b).expect("fixture"),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(30).expect("fixture"),
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: None,
        parent_state_commitment: [0x44; 32],
        owner_authority_transition_digest: position,
        storage_set: StorageSetMembers::new(&[b"n1", b"n2", b"n3"]).expect("fixture"),
        quorum: 4,
    };
    let vn_bytes = state.encode().expect("fixture");
    let c_n = vault_state_commitment(&state).expect("fixture");

    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let p = presented(w, &dels, &w.transitions, &proof);

    // The honest join succeeds: the anchor is signed by the SAME key P0–P6
    // proves.
    let honest =
        sign_vault_state_anchor_v3(&c_n, &w.ak.secret_key, &w.ak.public_key).expect("fixture");
    authenticate_anchor_owner(&honest, &vn_bytes, &p).expect("fixture");

    // K_1 ≠ K_2: an attacker signs the same c_n with a key it controls, and
    // presents the REAL owner's identity proof beside it. Both halves are
    // valid; the join must refuse.
    let attacker = kp(0x08);
    let forged = sign_vault_state_anchor_v3(&c_n, &attacker.secret_key, &attacker.public_key)
        .expect("fixture");
    let r = authenticate_anchor_owner(&forged, &vn_bytes, &p);
    assert!(
        is_invalid(&r),
        "two individually valid halves must not join: {r:?}"
    );
}

/// Position-scoping is enforced, not promised: material strictly AFTER the
/// bound position — an invalidly-signed successor, and a fork whose
/// predecessor IS the position — must not disturb a proof bound to it. The
/// earlier `a_longer_chain…` test could not catch this, because its longer
/// tail was valid: it proved a valid tail is harmless, not that the tail is
/// ignored.
#[test]
fn garbage_after_the_bound_position_cannot_disturb_the_proof() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest(); // bound at T2

    // An invalidly-signed successor of T2.
    let bad_succ = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: position,
        new_root: [0xAB; 32],
        version_number: 3,
        delegation_digest: w.d1.delegation.digest().expect("fixture"),
    };
    let bad_signed = SignedTransition {
        transition: bad_succ.clone(),
        delegate_signature: vec![0u8; 64], // garbage
    };
    let mut trans = w.transitions[..3].to_vec();
    trans.push(bad_signed);
    let p = presented(w, &dels, &trans, &proof);
    resolve_owner_authority_at_position(&w.g_o, &position, &p)
        .expect("an invalid successor AFTER the position is not this proof's business");

    // A fork whose predecessor IS the bound position: two distinct,
    // validly-signed successors of T2.
    let succ_a = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: position,
        new_root: [0xAC; 32],
        version_number: 3,
        delegation_digest: w.d1.delegation.digest().expect("fixture"),
    };
    let succ_b = DeviceTreeRootTransition {
        genesis_id: w.g_o,
        predecessor_transition_digest: position,
        new_root: [0xAD; 32],
        version_number: 5,
        delegation_digest: w.d1.delegation.digest().expect("fixture"),
    };
    let mut trans2 = w.transitions[..3].to_vec();
    trans2.push(sign_transition(&succ_a, &w.delegate0));
    trans2.push(sign_transition(&succ_b, &w.delegate0));
    let p2 = presented(w, &dels, &trans2, &proof);
    resolve_owner_authority_at_position(&w.g_o, &position, &p2)
        .expect("a fork strictly after the position is evidence about a later edge, not this one");
}

/// An unordered bag has an order-independent outcome. The same object
/// presented twice with DIFFERENT signature bytes is ambiguous and refused —
/// in both presentation orders, identically — rather than letting whichever
/// copy the bag yields last supply the signature.
#[test]
fn duplicate_objects_with_differing_signatures_are_refused_in_both_orders() {
    let w = world();
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let position = w.transitions[2].transition.digest();

    // Delegation: D1 with its real signature and with garbage.
    let d1_garbage = SignedDelegation {
        delegation: w.d1.delegation.clone(),
        grk_signature: vec![0u8; 64],
    };
    for dels in [
        vec![w.d0.clone(), w.d1.clone(), d1_garbage.clone()],
        vec![w.d0.clone(), d1_garbage.clone(), w.d1.clone()],
    ] {
        let p = presented(w, &dels, &w.transitions, &proof);
        let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
        assert!(is_invalid(&r), "ambiguous delegation must refuse: {r:?}");
    }

    // Transition: T1 (WITHIN the prefix) with its real signature and garbage.
    let t1_garbage = SignedTransition {
        transition: w.transitions[1].transition.clone(),
        delegate_signature: vec![0u8; 64],
    };
    let dels = vec![w.d0.clone(), w.d1.clone()];
    for trans in [
        {
            let mut t = w.transitions.clone();
            t.push(t1_garbage.clone());
            t
        },
        {
            let mut t = vec![t1_garbage.clone()];
            t.extend(w.transitions.clone());
            t
        },
    ] {
        let p = presented(w, &dels, &trans, &proof);
        let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
        assert!(is_invalid(&r), "ambiguous transition must refuse: {r:?}");
    }
}

/// A bound position that is authentic but beyond the presented material is
/// Incomplete — absence and withholding are indistinguishable without a
/// frontier, and the resolver says so rather than guessing.
#[test]
fn a_position_beyond_the_presented_chain_is_incomplete_never_substituted() {
    let w = world();
    let dels = vec![w.d0.clone(), w.d1.clone()];
    let proof = w.tree.proof(&w.d_o).expect("fixture");
    let prefix = vec![w.transitions[0].clone(), w.transitions[1].clone()];
    let position = w.transitions[3].transition.digest();
    let p = presented(w, &dels, &prefix, &proof);
    let r = resolve_owner_authority_at_position(&w.g_o, &position, &p);
    assert!(
        matches!(r, Err(ResolveFailure::Incomplete(_))),
        "the resolver must not substitute the reachable tip for the bound position: {r:?}"
    );
}
