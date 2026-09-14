// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! THE ROUTE-WIDE SETTLE'S WRITE SET — amendment 2c-H H3, H4, H10.
//!
//! One net input debit, one net output credit funded by `0x0035`, one
//! settlement-receipt leaf per vault inserted from zero, and one
//! bundle-acceptance leaf: `N + 3` mutations and exactly one credit source.
//! The intermediate asset never becomes a trader balance.

use std::collections::BTreeMap;

use dsm::economic::credit::CreditSource;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{
    build_write_set, verify_operation_write_set, CreditSourceFacts, EconomicPreState,
    EconomicWriteContext, RouteLegConsumptionFacts, WriteSetError,
};
use dsm::types::operations::{DlvRouteLeg, Operation, TransactionMode};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const C_DSM_PLUS: [u8; 32] = [0xC5; 32];
const X: [u8; 32] = [0xA0; 32];
const B: [u8; 32] = [0xB0; 32];
const PC_A: [u8; 32] = [0x10; 32];
const PC_MID: [u8; 32] = [0x30; 32];
const PC_B: [u8; 32] = [0x20; 32];

fn econ_op_id() -> [u8; 32] {
    dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS)
}

fn leg(
    vault: u8,
    parent: u8,
    input: [u8; 32],
    output: [u8; 32],
    input_amount: u64,
    output_amount: u64,
) -> DlvRouteLeg {
    let vault_id = [vault; 32];
    DlvRouteLeg {
        vault_id,
        owner_public_key: vec![0x01; 64],
        owner_devid: [0x41; 32],
        owner_genesis: [0x42; 32],
        input_policy_commit: input,
        output_policy_commit: output,
        parent_sequence: 7,
        parent_binding: [parent; 32],
        input_amount,
        output_amount,
        fee_bps: 30,
        settlement_receipt_id: dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&vault_id, &X),
    }
}

fn route_with(legs: Vec<DlvRouteLeg>) -> Operation {
    Operation::DlvRouteSettle {
        legs,
        route_commit_bytes: vec![0x09; 8],
        external_commitment_x: X,
        settler_public_key: vec![0x02; 64],
        settler_devid: DEV,
        signature: vec![0x77; 48],
        mode: TransactionMode::Unilateral,
    }
}

/// `PC_A → PC_MID → PC_B` over two vaults: 1,000 in, 453 between, 560 out.
fn two_legs() -> Vec<DlvRouteLeg> {
    vec![
        leg(0x03, 0xE1, PC_A, PC_MID, 1_000, 453),
        leg(0x04, 0xE2, PC_MID, PC_B, 453, 560),
    ]
}

fn facts() -> CreditSourceFacts {
    CreditSourceFacts::DlvRouteReserveConsumption {
        legs: vec![
            RouteLegConsumptionFacts {
                owner_economic_position: 3,
                reserve_consumption_evidence_addr: [0xE1; 32],
            },
            RouteLegConsumptionFacts {
                owner_economic_position: 5,
                reserve_consumption_evidence_addr: [0xE2; 32],
            },
        ],
    }
}

/// The trader holds 5,000 of the input asset and nothing else; the REAL
/// builder composes the write set, and the witness is constructed from it.
fn build(
    op: &Operation,
    facts: &CreditSourceFacts,
) -> Result<EconomicTransitionWitness, WriteSetError> {
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(PC_A, 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G, &DEV),
        funded.leaf_value().expect("value"),
    );
    let mut balances = BTreeMap::new();
    balances.insert(PC_A, 5_000u64);
    let pre_root = tree.root();
    let built = build_write_set(
        op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        facts,
        &EconomicWriteContext::DlvSettle { bundle_id: B },
    )?;
    Ok(EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id(),
        dsm::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness"))
}

#[test]
fn a_route_settle_is_n_plus_three_mutations_and_its_own_verifier_accepts_it() {
    let op = route_with(two_legs());
    let w = build(&op, &facts()).expect("the route write set builds");
    assert_eq!(
        w.mutations.len(),
        2 + 3,
        "debit, credit, two receipts, one acceptance"
    );
    verify_operation_write_set(&op, &G, &DEV, &w)
        .expect("the verifier accepts the builder's write set");

    let balances: Vec<[u8; 32]> = w
        .mutations
        .iter()
        .filter_map(|m| match &m.post_state {
            Some(EconomicLeafState::Balance(b)) => Some(b.policy_commit),
            _ => None,
        })
        .collect();
    assert!(balances.contains(&PC_A) && balances.contains(&PC_B));
    assert!(
        !balances.contains(&PC_MID),
        "H4: the intermediate asset never becomes a trader balance"
    );
    let receipts: Vec<[u8; 32]> = w
        .mutations
        .iter()
        .filter_map(|m| match &m.post_state {
            Some(EconomicLeafState::SettlementReceipt(r)) => Some(r.vault_id),
            _ => None,
        })
        .collect();
    assert_eq!(receipts.len(), 2, "one receipt leaf per vault");
    assert!(receipts.contains(&[0x03; 32]) && receipts.contains(&[0x04; 32]));

    let [CreditSource::DlvRouteReserveConsumption(source)] = w.credit_sources.as_slice() else {
        panic!("exactly one 0x0035 source, got {:?}", w.credit_sources);
    };
    assert_eq!(source.x, X);
    assert_eq!(
        source.legs.iter().map(|e| e.vault_id).collect::<Vec<_>>(),
        vec![[0x03; 32], [0x04; 32]],
        "E_R in route-leg order"
    );
}

#[test]
fn a_route_settle_needs_route_facts_with_one_entry_per_leg() {
    let op = route_with(two_legs());
    let single = CreditSourceFacts::DlvReserveConsumption {
        owner_economic_position: 3,
        reserve_consumption_evidence_addr: [0xE1; 32],
    };
    assert!(matches!(
        build(&op, &single),
        Err(WriteSetError::FactsDoNotMatchOperation)
    ));
    let short = CreditSourceFacts::DlvRouteReserveConsumption {
        legs: vec![RouteLegConsumptionFacts {
            owner_economic_position: 3,
            reserve_consumption_evidence_addr: [0xE1; 32],
        }],
    };
    assert!(matches!(
        build(&op, &short),
        Err(WriteSetError::FactsDoNotMatchOperation)
    ));
}

#[test]
fn a_route_settle_that_does_not_conserve_has_no_write_set() {
    let mut legs = two_legs();
    legs[1].input_amount = 454;
    assert!(matches!(
        build(&route_with(legs), &facts()),
        Err(WriteSetError::MalformedVaultOperation { .. })
    ));
}

#[test]
fn the_verifier_refuses_evidence_out_of_route_order_and_receipts_of_another_route() {
    let op = route_with(two_legs());

    let mut reordered = build(&op, &facts()).expect("builds");
    let CreditSource::DlvRouteReserveConsumption(source) = &mut reordered.credit_sources[0] else {
        panic!("a 0x0035 source");
    };
    source.legs.reverse();
    assert!(
        verify_operation_write_set(&op, &G, &DEV, &reordered).is_err(),
        "E_R out of route-leg order"
    );

    let w = build(&op, &facts()).expect("builds");
    let mut other_legs = two_legs();
    other_legs[1] = leg(0x05, 0xE2, PC_MID, PC_B, 453, 560);
    assert!(
        verify_operation_write_set(&route_with(other_legs), &G, &DEV, &w).is_err(),
        "receipt leaves and evidence of another route"
    );

    // Same vaults, same generations, same ends (1,000 in, 560 out), same E_R:
    // only the intermediate amount differs, so only the receipt leaves say
    // this is not the trade the operation authorized.
    let mut other_middle = two_legs();
    other_middle[0].output_amount = 454;
    other_middle[1].input_amount = 454;
    assert!(
        verify_operation_write_set(&route_with(other_middle), &G, &DEV, &w).is_err(),
        "receipt leaves that state another intermediate amount"
    );
}
