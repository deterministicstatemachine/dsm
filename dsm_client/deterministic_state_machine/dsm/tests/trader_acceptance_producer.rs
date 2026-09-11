// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! THE PRODUCER MEETS §7 — amendment 2c-D, producer adoption.
//!
//! What becomes true here: a `TA_B` built by
//! [`dsm::economic::acceptance_produce::produce_trader_acceptance`] from the
//! post-state a REAL settle write set left behind satisfies 2c-D §7's
//! verifier. Before this file the two halves had never met — §7 was exercised
//! against hand-assembled acceptances, and the producer did not exist.
//!
//! Why that gap mattered: an artifact that a verifier can check and a producer
//! can never emit is a verifier with no subject. `verify_trader_acceptance`
//! could have been wrong in any way that a hand-built fixture also happened to
//! be wrong, and nothing would have said so.
//!
//! **What this file does NOT establish.** A `TA_B` that verifies is not a
//! realized settlement. §7 itself says so: acceptance is a precondition of
//! realization, never its trigger, and realization additionally needs `B`
//! binding-final and C4's correspondence. Nothing here releases a fence,
//! advances a frontier, or publishes a receipt — and
//! `a_settled_market_publishes_a_trader_acceptance_and_realizes_nothing`
//! in `dlv_routes` is the control that says so over the LIVE path.

use std::collections::BTreeMap;

use dsm::ccb::{
    Allocation, DsmSuccessorEvidence, EncumbranceSet, FeePolicy, MarketPolicy, MarketTerms,
    ReleasePolicy, Route, RouteLeg, StorageSetMembers, TradeIntent, VaultStateV2,
};
use dsm::dlv::successor_validity::{
    check_correspondence, check_market_correspondence, AcceptedTransition, BundleCoordinates,
    MarketCorrespondence,
};
use dsm::economic::acceptance_produce::produce_trader_acceptance;
use dsm::economic::acceptance_verify::{verify_trader_acceptance, AcceptanceInvalid};
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::trader_acceptance::TraderAcceptance;
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{
    build_write_set, CreditSourceFacts, EconomicPreState, EconomicWriteContext,
};
use dsm::types::operations::{Operation, TransactionMode};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const VAULT: [u8; 32] = [0x03; 32];
const C_DSM_PLUS: [u8; 32] = [0xC5; 32];
const X: [u8; 32] = [0xA0; 32];
const B: [u8; 32] = [0xB0; 32];
const POSITION: u64 = 3;

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
        parent_sequence: 7,
        parent_binding: [0xC0; 32],
        route_commit_bytes: vec![0x09; 8],
        external_commitment_x: X,
        input_amount: 1_000,
        output_amount: 900,
        fee_bps: 30,
        sigma: [0x66; 32],
        settler_public_key: vec![0x02; 64],
        settler_devid: DEV,
        settlement_receipt_id: dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&VAULT, &X),
        signature: vec![0x77; 48],
        mode: TransactionMode::Unilateral,
    }
}

/// The REAL settle write set, and the post-state tree it left behind.
///
/// Everything downstream reads out of these two values, which is the point:
/// the acceptance leaf and its path are the ones production emits, not ones
/// this file assembled to be checkable.
fn settled() -> (EconomicTransitionWitness, EconomicSmt) {
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
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: 3,
            reserve_consumption_evidence_addr: [0xEE; 32],
        },
        &EconomicWriteContext::DlvSettle { bundle_id: B },
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
    (witness, tree)
}

/// Market terms whose `sigma_dsm` genuinely signs the digest §7 step 2
/// reconstructs, over the SAME settle operation the write set consumed.
fn terms_signed_by(sk: &[u8]) -> MarketTerms {
    let op_bytes = settle().to_bytes();
    let digest = dsm::economic::successor_evidence::substrate_signing_digest(
        &G,
        &DEV,
        &C_DSM_PLUS,
        &dsm::economic::faucet::dsm_operation_digest(&op_bytes),
    );
    let sigma = dsm::crypto::sphincs::sphincs_sign(sk, &digest).expect("sign");
    MarketTerms {
        intent: TradeIntent {
            token_in: pc_a(),
            amount_in: 1_000,
            token_out: pc_b(),
            exact_out: 900,
            fee_bps: 30,
            nonce: [0x5A; 32],
        },
        route_set_commitment: X,
        selected_route: Route::new(vec![RouteLeg::Single(Allocation {
            parent_binding: [0xC0; 32],
            delta_in: 1_000,
            delta_out: 900,
            encumbrance_claim: [0xE1; 32],
            fee_policy: FeePolicy::new(30).expect("fee below denominator"),
        })])
        .expect("one leg"),
        trader_parent: [0xC1; 32],
        trader_successor: C_DSM_PLUS,
        recovery_material: DsmSuccessorEvidence::new(
            [0x77; 32], [0xC1; 32], DEV, op_bytes, [0xE0; 32], sigma,
        )
        .expect("evidence"),
    }
}

/// Steps 4 and 7 arrive as C4's own fact, exactly as they do in production.
fn correspondence() -> MarketCorrespondence {
    let v = VaultStateV2 {
        owner_genesis_id: [1; 32],
        owner_device_id: [2; 32],
        vault_id: [3; 32],
        generation: 7,
        reserve_a: 10_000,
        reserve_b: 5_000,
        market_policy: MarketPolicy::beta_constant_product(pc_a(), pc_b()).expect("ordered pair"),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(30).expect("fee below denominator"),
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: None,
        parent_state_commitment: [4; 32],
        owner_authority_transition_digest: [5; 32],
        storage_set: StorageSetMembers::new(&[(b"dsm-node-1".as_slice(), [9; 32])])
            .expect("one member"),
        quorum: 1,
    };
    let supplied = v.encode().expect("encode");
    let witness = check_correspondence(&v, [0xC0; 32], &supplied).expect("10.a");
    check_market_correspondence(
        &AcceptedTransition {
            embedded_parent: [0xC1; 32],
            c_dsm_plus: C_DSM_PLUS,
            external_commitment_x: X,
            parent_binding: [0xC0; 32],
            parent_sequence: 7,
            input_policy_commit: [0x10; 32],
            input_amount: 1_000,
            output_policy_commit: [0x20; 32],
            output_amount: 900,
            fee_bps: 30,
        },
        &BundleCoordinates {
            trader_parent: [0xC1; 32],
            trader_successor: C_DSM_PLUS,
            route_set_commitment: X,
            leg_parent_binding: [0xC0; 32],
            leg_delta_in: 1_000,
            leg_delta_out: 900,
            leg_fee_bps: 30,
            transition_parent_binding: [0xC0; 32],
        },
        [0xC0; 32],
        witness,
    )
    .expect("CORR.1-5")
}

struct Fixture {
    acceptance: TraderAcceptance,
    terms: MarketTerms,
    validated: ValidatedEconomicRoot,
    ak: Vec<u8>,
}

fn fixture() -> Fixture {
    let (witness, tree) = settled();
    let root = tree.root();
    let acceptance = produce_trader_acceptance(&tree, &witness, &G, &DEV, root, POSITION)
        .expect("producible")
        .expect("a market settle always writes its acceptance leaf");
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
    Fixture {
        acceptance,
        terms: terms_signed_by(&sk),
        validated: ValidatedEconomicRoot::rehydrate_from_admitted_store(POSITION, root),
        ak: pk,
    }
}

/// THE REACHABILITY CLAIM, in one assertion: what the settle path emits is
/// what §7 accepts.
#[test]
fn a_produced_acceptance_verifies_through_the_seven_conjuncts() {
    let f = fixture();
    let witness = verify_trader_acceptance(
        &f.acceptance,
        &f.terms,
        B,
        &correspondence(),
        &f.validated,
        &f.ak,
    )
    .expect("the produced acceptance satisfies §7");
    assert_eq!(witness.bundle(), B, "the witness names the emitted bundle");
    assert_eq!(
        witness.economic_operation_id(),
        econ_op_id(),
        "and the operation the write set was built for"
    );
    assert_eq!(witness.economic_root(), f.validated.economic_root());
}

/// The producer takes `b` and the operation id from the emitted leaf, so what
/// §7 authenticates is exactly what the write set committed.
#[test]
fn the_produced_acceptance_carries_the_emitted_leaf_verbatim() {
    let f = fixture();
    assert_eq!(f.acceptance.acceptance_leaf().bundle, B);
    assert_eq!(
        f.acceptance.acceptance_leaf().economic_operation_id,
        econ_op_id()
    );
    assert_eq!(f.acceptance.trader_genesis(), G);
    assert_eq!(f.acceptance.economic_position(), POSITION);
    assert_eq!(f.acceptance.acceptance_path().len(), 256);
}

/// STEP 6. The artifact is untouched; the bundle being composed is a different
/// one. This is the conjunct that keeps a genuine acceptance of one bundle
/// from realizing another.
#[test]
fn a_genuine_acceptance_does_not_realize_some_other_bundle() {
    let f = fixture();
    let other = [0xB1; 32];
    assert_eq!(
        verify_trader_acceptance(
            &f.acceptance,
            &f.terms,
            other,
            &correspondence(),
            &f.validated,
            &f.ak,
        ),
        Err(AcceptanceInvalid::LeafNamesAnotherBundle {
            leaf: B,
            composing: other,
        })
    );
}

/// ALTERED `b`. Rewriting the bundle inside the leaf changes the leaf VALUE,
/// so the path no longer folds — step 5 catches it before step 6 ever reads
/// the bundle. That ordering is 2c-D §6's point stated as a test: `b` is
/// established by the chain, not asserted by the wrapper, so there is no way
/// to substitute one without breaking the inclusion proof.
#[test]
fn an_acceptance_whose_bundle_was_rewritten_no_longer_folds() {
    let f = fixture();
    let mut leaf = f.acceptance.acceptance_leaf().clone();
    leaf.bundle = [0xB1; 32];
    let forged = TraderAcceptance::new(
        f.acceptance.trader_genesis(),
        f.acceptance.economic_position(),
        leaf,
        f.acceptance.acceptance_path().to_vec(),
    )
    .expect("well formed, and untrue");
    assert!(matches!(
        verify_trader_acceptance(
            &forged,
            &f.terms,
            [0xB1; 32],
            &correspondence(),
            &f.validated,
            &f.ak,
        ),
        Err(AcceptanceInvalid::PathDoesNotFoldToTheValidatedRoot { .. })
    ));
}

/// ALTERED OPERATION ID. Step 5's three-way equality fires first: the carried
/// id is not what the authenticated transition recomputes to, and the leaf key
/// is never derived from it.
#[test]
fn an_acceptance_whose_operation_id_was_rewritten_is_refused_before_the_fold() {
    let f = fixture();
    let mut leaf = f.acceptance.acceptance_leaf().clone();
    leaf.economic_operation_id = [0x51; 32];
    let forged = TraderAcceptance::new(
        f.acceptance.trader_genesis(),
        f.acceptance.economic_position(),
        leaf,
        f.acceptance.acceptance_path().to_vec(),
    )
    .expect("well formed, and untrue");
    assert_eq!(
        verify_trader_acceptance(&forged, &f.terms, B, &correspondence(), &f.validated, &f.ak,),
        Err(AcceptanceInvalid::OperationIdentityDisagrees {
            leaf: [0x51; 32],
            recomputed: econ_op_id(),
        })
    );
}

/// ALTERED PATH. One swapped sibling — the smallest change that keeps the
/// artifact well-formed — and the fold lands somewhere else.
#[test]
fn an_acceptance_whose_path_was_reordered_no_longer_folds() {
    let f = fixture();
    let mut path = f.acceptance.acceptance_path().to_vec();
    path.swap(0, 255);
    let forged = TraderAcceptance::new(
        f.acceptance.trader_genesis(),
        f.acceptance.economic_position(),
        f.acceptance.acceptance_leaf().clone(),
        path,
    )
    .expect("well formed, and untrue");
    assert!(matches!(
        verify_trader_acceptance(&forged, &f.terms, B, &correspondence(), &f.validated, &f.ak,),
        Err(AcceptanceInvalid::PathDoesNotFoldToTheValidatedRoot { .. })
    ));
}

/// A PRODUCED ACCEPTANCE STILL PROVES NOTHING WITHOUT THE AUTHORITY. §7 step 2
/// authenticates `G` against `sigma_dsm` under an INDEPENDENTLY established
/// trader AK; producing the artifact does not supply one, and a different key
/// refuses.
#[test]
fn producing_an_acceptance_does_not_supply_the_authority_that_authenticates_it() {
    let f = fixture();
    let (stranger, _sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
    assert_eq!(
        verify_trader_acceptance(
            &f.acceptance,
            &f.terms,
            B,
            &correspondence(),
            &f.validated,
            &stranger,
        ),
        Err(AcceptanceInvalid::GenesisNotAuthenticated)
    );
}

/// THE PUBLICATION ADDRESS IS THE CANONICAL IDENTITY. `TA_B` is published
/// under `DSM/trader-settlement-acceptance/v2`, and a storage object's inner
/// digest is `H_dom(namespace, payload)` — the same computation as `ta_B`. So
/// the object a Def 14.2 receipt binds by `ta_B` and the bytes the fleet holds
/// are addressed by one value, and there is no separate locator to keep in
/// step with it.
#[test]
fn the_publication_address_is_the_canonical_identity() {
    let f = fixture();
    let bytes = f.acceptance.encode().expect("encodable");
    assert_eq!(
        dsm::storage_object::immutable_inner(
            dsm::common::domain_tags::TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
            &bytes,
        ),
        f.acceptance.ta_b().expect("identity"),
        "the namespace's inner digest must be ta_B itself"
    );
}

/// #852 REGRESSION. The settle's own witness — what the resume path decodes
/// from frozen state and what every foreign lineage walk decodes from the
/// fleet — carries the bundle-acceptance leaf, and must decode to itself.
#[test]
fn a_settle_witness_carrying_the_acceptance_leaf_decodes_to_itself() {
    let (witness, _) = settled();
    assert!(
        witness
            .mutations
            .iter()
            .any(|m| matches!(m.post_state, Some(EconomicLeafState::BundleAcceptance(_)))),
        "the fixture must actually carry the leaf, or this test proves nothing"
    );
    let bytes = witness.encode().expect("encodable");
    assert_eq!(
        dsm::economic::decode::decode_transition_witness(&bytes)
            .expect("a market settle's witness decodes"),
        witness
    );
}
