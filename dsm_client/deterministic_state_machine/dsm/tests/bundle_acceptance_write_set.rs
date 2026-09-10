// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! THE BUNDLE-ACCEPTANCE LEAF REACHES THE WRITE SET — amendment 2c-D §8.
//!
//! What becomes true here: a qualifying economic operation may carry exactly
//! one `0x0032` leaf for its authenticated `economic_operation_id`, and the
//! write-set boundary — not the tree's key derivation — is what says so.
//!
//! **What this file does NOT establish.** Reaching and writing a
//! bundle-acceptance leaf is not `TA_B` verification, not
//! `IndependentRealization`, not fence release, not realized settlement, and
//! not receipt publication. Those stay gated on the witness/`TA_B` work that
//! follows. A leaf admitted here says only that this identity's accepted
//! transition committed a bundle identity — never that the bundle was
//! binding-final or accepted by anyone else.
//!
//! **Why the cardinality tests look the way they do.** Two acceptance leaves
//! for ONE operation derive the SAME key, so
//! `EconomicTransitionWitness::new`'s strict-ascent rule refuses them before
//! any verifier runs. That is a consequence of how the tree stores things, and
//! relying on it would leave the protocol rule unowned. So the primary test
//! uses two acceptances with DIFFERENT operation ids: distinct keys, a witness
//! that constructs cleanly, and a refusal that can only come from the
//! admission boundary. A same-id case is covered too, by building the witness
//! struct directly to bypass the ordering rule and reach the verifier.

use std::collections::BTreeMap;

use dsm::economic::credit::{CreditSource, CreditSourceDlvReserveConsumption};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{EconomicBalanceState, EconomicBundleAcceptanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{
    build_write_set, verify_operation_write_set, CreditSourceFacts, EconomicPreState, WriteSetError,
};
use dsm::types::operations::{Operation, TransactionMode};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const VAULT: [u8; 32] = [0x03; 32];
const C_DSM_PLUS: [u8; 32] = [0xC5; 32];
const X: [u8; 32] = [0xA0; 32];
const B: [u8; 32] = [0xB0; 32];
const INPUT: u64 = 1_000;
const OUTPUT: u64 = 900;
const PARENT: u64 = 7;

fn pc_a() -> [u8; 32] {
    [0x10; 32]
}
fn pc_b() -> [u8; 32] {
    [0x20; 32]
}

fn econ_op_id() -> [u8; 32] {
    dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS)
}

fn settle() -> Operation {
    Operation::DlvSettle {
        vault_id: VAULT.to_vec(),
        owner_public_key: vec![0x01; 64],
        owner_devid: [0x41; 32],
        owner_genesis: [0x42; 32],
        input_policy_commit: pc_a(),
        output_policy_commit: pc_b(),
        parent_sequence: PARENT,
        parent_binding: [0xC0; 32],
        route_commit_bytes: vec![0x09; 8],
        external_commitment_x: X,
        input_amount: INPUT,
        output_amount: OUTPUT,
        fee_bps: 30,
        sigma: [0x66; 32],
        settler_public_key: vec![0x02; 64],
        settler_devid: DEV,
        settlement_receipt_id: dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&VAULT, &X),
        signature: vec![0x77; 48],
        mode: TransactionMode::Unilateral,
    }
}

fn facts() -> CreditSourceFacts {
    CreditSourceFacts::DlvReserveConsumption {
        owner_economic_position: 3,
        reserve_consumption_evidence_addr: [0xEE; 32],
    }
}

fn acceptance(bundle: [u8; 32], operation_id: [u8; 32]) -> EconomicLeafState {
    EconomicLeafState::BundleAcceptance(EconomicBundleAcceptanceState {
        bundle,
        economic_operation_id: operation_id,
    })
}

/// An acceptance mutation inserted from zero into `tree`, with the real
/// sibling path — the same construction a producer would emit.
fn acceptance_mutation(tree: &mut EconomicSmt, state: &EconomicLeafState) -> EconomicLeafMutation {
    let key = state.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    tree.insert(key, state.leaf_value().expect("encodable"));
    EconomicLeafMutation::new(None, Some(state.clone()), siblings).expect("mutation")
}

/// The honest three-mutation settle write set, built by the REAL builder, plus
/// the tree it left behind so an acceptance can be appended at a real path.
fn built_settle() -> (EconomicTransitionWitness, EconomicSmt, Operation) {
    let op = settle();
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G, &DEV),
        funded.leaf_value().expect("value"),
    );
    let mut balances = BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = tree.root();

    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &facts(),
    )
    .expect("the settle write set builds");

    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id(),
        dsm::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    (witness, tree, op)
}

/// Re-sort a witness's mutations into the strict key ascent the type requires,
/// REMAP the credit-source indices onto their mutations' new positions, and
/// rebuild without `new`'s checks so a deliberately malformed set can still
/// reach the verifier.
///
/// The remap is not test scaffolding — it is the real obligation an acceptance
/// leaf creates. `credit_mutation_index` is an index into `mutations`, and the
/// order is canonical by derived leaf key, so inserting ANY leaf can move the
/// credit it funds. A producer that appends an acceptance without re-indexing
/// its credit sources emits a write set whose reserve consumption no longer
/// names the output credit, and the refusal it gets
/// ("reserve-consumption source does not fund the output credit") says nothing
/// about acceptance leaves. Discovered here by doing exactly that.
fn witness_with(
    base: &EconomicTransitionWitness,
    mut mutations: Vec<EconomicLeafMutation>,
    sort: bool,
) -> EconomicTransitionWitness {
    let mut credit_sources = base.credit_sources.clone();
    if sort {
        // Where each mutation the credits refer to ends up, by leaf key.
        let before: Vec<[u8; 32]> = base
            .mutations
            .iter()
            .map(|m| m.leaf_key(&G, &DEV).expect("keyed"))
            .collect();
        mutations.sort_by_key(|m| m.leaf_key(&G, &DEV).expect("keyed"));
        let after: Vec<[u8; 32]> = mutations
            .iter()
            .map(|m| m.leaf_key(&G, &DEV).expect("keyed"))
            .collect();
        // Rebuilt rather than mutated in place: `credit_mutation_index` has no
        // setter, and production should not grow one for a test. This fixture
        // only ever emits the reserve-consumption arm.
        credit_sources = credit_sources
            .into_iter()
            .map(|c| {
                let old = c.credit_mutation_index() as usize;
                let key = before[old];
                let new = u32::try_from(
                    after
                        .iter()
                        .position(|k| *k == key)
                        .expect("the funded mutation survived the sort"),
                )
                .expect("index fits");
                match c {
                    CreditSource::DlvReserveConsumption(d) => {
                        CreditSource::DlvReserveConsumption(CreditSourceDlvReserveConsumption {
                            credit_mutation_index: new,
                            ..d
                        })
                    }
                    other => other,
                }
            })
            .collect();
    }
    EconomicTransitionWitness {
        pre_economic_root: base.pre_economic_root,
        post_economic_root: base.post_economic_root,
        economic_operation_id: base.economic_operation_id,
        operation_digest: base.operation_digest,
        mutations,
        credit_sources,
    }
}

/// The honest settle still verifies, unchanged. Guards the relaxation: the
/// arm now admits `3 + acceptances.len()` mutations, and with no acceptance
/// that must still be exactly three.
#[test]
fn a_settle_without_an_acceptance_leaf_is_unaffected() {
    let (witness, _tree, op) = built_settle();
    assert_eq!(witness.mutations.len(), 3);
    verify_operation_write_set(&op, &G, &DEV, &witness).expect("the honest settle still verifies");
}

/// ONE acceptance leaf, naming this operation, is admitted.
#[test]
fn one_acceptance_leaf_is_admitted_in_a_settle_write_set() {
    let (witness, mut tree, op) = built_settle();
    let m = acceptance_mutation(&mut tree, &acceptance(B, econ_op_id()));
    let mut ms = witness.mutations.clone();
    ms.push(m);
    let w = witness_with(&witness, ms, true);

    assert_eq!(w.mutations.len(), 4);
    verify_operation_write_set(&op, &G, &DEV, &w)
        .expect("a settle may carry one bundle-acceptance leaf");
}

/// TWO acceptance leaves are refused — and the keys DO NOT collide here, so
/// the refusal cannot be the tree's ordering rule standing in for the
/// protocol's cardinality.
///
/// Two different `economic_operation_id`s give two different positions, so
/// this witness is well-formed by every structural rule that existed before
/// 2c-D. Only the admission boundary can reject it.
#[test]
fn two_acceptance_leaves_at_distinct_positions_are_refused() {
    let (witness, mut tree, op) = built_settle();
    let other_id = dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &[0xC6; 32]);
    assert_ne!(
        other_id,
        econ_op_id(),
        "the two leaves must not share a key"
    );

    let m1 = acceptance_mutation(&mut tree, &acceptance(B, econ_op_id()));
    let m2 = acceptance_mutation(&mut tree, &acceptance([0xB1; 32], other_id));
    let mut ms = witness.mutations.clone();
    ms.push(m1);
    ms.push(m2);
    let w = witness_with(&witness, ms, true);

    assert!(
        matches!(
            verify_operation_write_set(&op, &G, &DEV, &w),
            Err(WriteSetError::WrongWriteSet { detail })
                if detail.contains("more than one bundle-acceptance leaf")
        ),
        "cardinality must be enforced where the write set is admitted"
    );
}

/// The same-position case reaches the verifier too, by bypassing the ordering
/// rule that would otherwise refuse it first.
///
/// Both halves matter: a caller who can construct a witness by hand must still
/// be refused, and the refusal must name cardinality rather than ordering.
#[test]
fn two_acceptance_leaves_at_one_position_are_refused_by_the_write_set_not_by_ordering() {
    let (witness, mut tree, op) = built_settle();
    let state = acceptance(B, econ_op_id());
    let m1 = acceptance_mutation(&mut tree, &state);
    let m2 = acceptance_mutation(&mut tree, &acceptance([0xB1; 32], econ_op_id()));
    assert_eq!(
        m1.leaf_key(&G, &DEV).expect("keyed"),
        m2.leaf_key(&G, &DEV).expect("keyed"),
        "one operation id is one position, whatever the bundle"
    );

    let mut ms = witness.mutations.clone();
    ms.push(m1);
    ms.push(m2);
    // NOT sorted: sorting cannot separate two mutations at one key, and
    // `EconomicTransitionWitness::new` would refuse the set outright.
    let w = witness_with(&witness, ms, false);

    assert!(
        matches!(
            verify_operation_write_set(&op, &G, &DEV, &w),
            Err(WriteSetError::WrongWriteSet { detail })
                if detail.contains("more than one bundle-acceptance leaf")
        ),
        "the write set must refuse this on its own terms"
    );
}

/// A leaf naming another economic operation is refused, even though it is
/// well-formed and sits at a valid position in this identity's tree.
#[test]
fn an_acceptance_leaf_naming_another_operation_is_refused() {
    let (witness, mut tree, op) = built_settle();
    let other_id = dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &[0xC6; 32]);
    let m = acceptance_mutation(&mut tree, &acceptance(B, other_id));
    let mut ms = witness.mutations.clone();
    ms.push(m);
    let w = witness_with(&witness, ms, true);

    assert!(
        matches!(
            verify_operation_write_set(&op, &G, &DEV, &w),
            Err(WriteSetError::WrongWriteSet { detail })
                if detail.contains("names another economic operation")
        ),
        "the carried operation id is not caller-authoritative"
    );
}

/// The leaf is write-once: a pre-state contradicts the shape, and the refusal
/// says so rather than falling through to a generic mutation-shape error.
#[test]
fn an_acceptance_leaf_with_a_pre_state_is_refused() {
    let (witness, mut tree, op) = built_settle();
    let state = acceptance(B, econ_op_id());
    let key = state.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    tree.insert(key, state.leaf_value().expect("encodable"));
    let m = EconomicLeafMutation::new(
        Some(state.clone()),
        Some(acceptance([0xB1; 32], econ_op_id())),
        siblings,
    )
    .expect("mutation");

    let mut ms = witness.mutations.clone();
    ms.push(m);
    let w = witness_with(&witness, ms, true);

    assert!(
        matches!(
            verify_operation_write_set(&op, &G, &DEV, &w),
            Err(WriteSetError::WrongWriteSet { detail })
                if detail.contains("write-once")
        ),
        "a bundle-acceptance leaf has no pre-state"
    );
}

/// The class stays illegal outside a settle. A transfer carrying one is
/// refused by leaf class, before any cardinality rule is consulted — which is
/// how settlement receipts are already kept out, and why no per-arm emptiness
/// check exists for either.
#[test]
fn an_acceptance_leaf_outside_a_settle_write_set_is_refused_by_class() {
    let (witness, mut tree, _op) = built_settle();
    let burn = Operation::Burn {
        amount: dsm::types::token_types::Balance::from_state(50, [0u8; 32]),
        token_id: b"T".to_vec(),
        policy_commit: pc_a(),
        proof_of_ownership: Vec::new(),
        message: String::new(),
    };
    let m = acceptance_mutation(&mut tree, &acceptance(B, econ_op_id()));
    // Built inline rather than through `witness_with`: this set REPLACES the
    // settle's mutations rather than extending them, so there is no credit
    // source to re-index — and the class refusal fires before any credit
    // logic would run anyway.
    let w = EconomicTransitionWitness {
        pre_economic_root: witness.pre_economic_root,
        post_economic_root: witness.post_economic_root,
        economic_operation_id: witness.economic_operation_id,
        operation_digest: witness.operation_digest,
        mutations: vec![m],
        credit_sources: Vec::new(),
    };

    assert!(
        matches!(
            verify_operation_write_set(&burn, &G, &DEV, &w),
            Err(WriteSetError::UnexpectedLeafClass)
        ),
        "only the operation that produces the successor may carry its acceptance"
    );
}

/// A changed operation id moves the position, at this layer and not only in
/// the key unit test — so an acceptance cannot be re-pointed at another
/// transition while keeping its place in the tree.
#[test]
fn a_changed_operation_id_moves_the_acceptance_position() {
    let a = acceptance(B, econ_op_id());
    let other_id = dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &[0xC6; 32]);
    let b = acceptance(B, other_id);
    assert_ne!(
        a.leaf_key(&G, &DEV),
        b.leaf_key(&G, &DEV),
        "the same bundle under two transitions occupies two positions"
    );
}
