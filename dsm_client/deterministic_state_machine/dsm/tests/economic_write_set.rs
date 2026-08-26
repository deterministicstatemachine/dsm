// SPDX-License-Identifier: Apache-2.0

//! The operation ↔ write-set rule, both sides.
//!
//! The builder and the verifier are generated from one table; these tests
//! prove they agree on every 3.5b operation, that the verifier refuses every
//! near-miss an adversarial producer could substitute, and that the
//! multi-mutation sequencing rules (key order, progressive siblings) are real
//! rather than vacuously satisfied by single-mutation witnesses.

#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;

use dsm::economic::faucet::{dsm_economic_operation_id, era_faucet_id, ERA_FAUCET_PAYOUT};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::{verify_mutation_sequence, EconomicTransitionWitness};
use dsm::economic::write_set::{
    build_write_set, verify_operation_write_set, CreditSourceFacts, WriteSetError,
};
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const PEER_DEV: [u8; 32] = [0x33; 32];
const ECON_OP_ID_INPUT: [u8; 32] = [0xCD; 32];

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn econ_op_id() -> [u8; 32] {
    dsm_economic_operation_id(&G, &DEV, &ECON_OP_ID_INPUT)
}

fn transfer(to: [u8; 32], amount: u64, policy_commit: [u8; 32]) -> Operation {
    Operation::Transfer {
        to_device_id: to.to_vec(),
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"T".to_vec(),
        policy_commit,
        mode: TransactionMode::Unilateral,
        nonce: vec![7; 32],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: Vec::new(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    }
}

fn burn(amount: u64, policy_commit: [u8; 32]) -> Operation {
    Operation::Burn {
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"T".to_vec(),
        policy_commit,
        proof_of_ownership: Vec::new(),
        message: String::new(),
    }
}

fn create_token(initial_supply: u64, fee_amount: u64) -> Operation {
    Operation::CreateToken {
        token_id: b"NEW".to_vec(),
        initial_supply: Balance::from_state(initial_supply, [0u8; 32]),
        policy_commit: [0x77; 32],
        fee_amount,
        name: String::new(),
        symbol: String::new(),
        decimals: 0,
        metadata_uri: None,
        signature: Vec::new(),
    }
}

/// A tree already holding `amount` of `asset` for (G, DEV), plus the matching
/// balance map — the validated pre-state of a device that can debit.
fn funded_tree(asset: [u8; 32], amount: u64) -> (EconomicSmt, BTreeMap<[u8; 32], u64>) {
    let mut tree = EconomicSmt::new();
    let state = EconomicLeafState::Balance(EconomicBalanceState::new(asset, amount).unwrap());
    tree.insert(state.leaf_key(&G, &DEV), state.leaf_value().unwrap());
    let mut balances = BTreeMap::new();
    balances.insert(asset, amount);
    (tree, balances)
}

fn witness_for(
    pre_root: [u8; 32],
    built: dsm::economic::write_set::BuiltWriteSet,
    operation: &Operation,
) -> EconomicTransitionWitness {
    EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id(),
        dsm::economic::faucet::dsm_operation_digest(&operation.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("built write set forms a valid witness")
}

/// Build → witness → BOTH verifier halves, for one operation.
fn round_trip(
    operation: &Operation,
    mut tree: EconomicSmt,
    balances: BTreeMap<[u8; 32], u64>,
    facts: &CreditSourceFacts,
) -> EconomicTransitionWitness {
    let pre_root = tree.root();
    let built = build_write_set(
        operation,
        &G,
        &DEV,
        &econ_op_id(),
        &balances,
        &mut tree,
        facts,
    )
    .expect("buildable");
    let witness = witness_for(pre_root, built, operation);
    verify_mutation_sequence(&witness.mutation_sequence(), &G, &DEV).expect("sequence verifies");
    verify_operation_write_set(operation, &G, &DEV, &witness).expect("exact effect verifies");
    witness
}

// ── Round trips: the producer output IS the verifier's expectation ─────────

#[test]
fn a_burn_round_trips_and_removes_a_zeroed_balance() {
    let (tree, balances) = funded_tree(era(), 50);
    let witness = round_trip(&burn(50, era()), tree, balances, &CreditSourceFacts::None);
    // Exact-zero debit is a REMOVAL: no zero-amount leaf may exist.
    assert!(witness.mutations[0].post_state.is_none());
}

#[test]
fn a_partial_burn_keeps_the_remainder() {
    let (tree, balances) = funded_tree(era(), 50);
    let witness = round_trip(&burn(20, era()), tree, balances, &CreditSourceFacts::None);
    match &witness.mutations[0].post_state {
        Some(EconomicLeafState::Balance(b)) => assert_eq!(b.amount, 30),
        other => panic!("expected remainder balance, got {other:?}"),
    }
}

#[test]
fn a_sender_transfer_debit_round_trips() {
    let (tree, balances) = funded_tree(era(), 100);
    let witness = round_trip(
        &transfer(PEER_DEV, 40, era()),
        tree,
        balances,
        &CreditSourceFacts::None,
    );
    assert!(
        witness.credit_sources.is_empty(),
        "a pure debit funds nothing"
    );
    assert_eq!(witness.mutations.len(), 1);
}

#[test]
fn a_recipient_transfer_credit_round_trips_with_its_consumed_source() {
    // to_device_id == DEV: the role derives as credit, and the write set is
    // TWO mutations — the first multi-mutation write set in the system, so
    // this is also the first real exercise of key ordering + progressive
    // sibling capture.
    let op = transfer(DEV, 40, era());
    let facts = CreditSourceFacts::PeerDebit {
        peer_genesis: [0x55; 32],
        peer_devid: PEER_DEV,
        peer_economic_position: 3,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: [0x66; 32],
    };
    let witness = round_trip(&op, EconomicSmt::new(), BTreeMap::new(), &facts);
    assert_eq!(witness.mutations.len(), 2);
    assert_eq!(witness.credit_sources.len(), 1);
}

#[test]
fn a_faucet_claim_round_trips_on_the_builder() {
    let op = Operation::FaucetClaim {
        faucet_id: era_faucet_id(b"dsm-testnet"),
        ticket_index: 42,
    };
    let facts = CreditSourceFacts::FaucetTicket {
        faucet_claim_evidence_addr: [0x99; 32],
    };
    let witness = round_trip(&op, EconomicSmt::new(), BTreeMap::new(), &facts);
    match &witness.mutations[0].post_state {
        Some(EconomicLeafState::Balance(b)) => assert_eq!(b.amount, ERA_FAUCET_PAYOUT),
        other => panic!("expected the payout credit, got {other:?}"),
    }
}

// ── The owner's two CreateToken tests ──────────────────────────────────────

#[test]
fn create_token_with_zero_supply_validates_as_a_pure_era_fee_debit() {
    let (tree, balances) = funded_tree(era(), 500);
    let witness = round_trip(
        &create_token(0, 500),
        tree,
        balances,
        &CreditSourceFacts::None,
    );
    assert!(
        witness.mutations[0].post_state.is_none(),
        "full fee zeroes the balance"
    );
}

#[test]
fn create_token_with_initial_supply_gets_the_exact_named_refusal() {
    let (mut tree, balances) = funded_tree(era(), 500);
    let err = build_write_set(
        &create_token(1_000, 500),
        &G,
        &DEV,
        &econ_op_id(),
        &balances,
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect_err("initial supply cannot be funded");
    assert_eq!(
        err,
        WriteSetError::CreateTokenInitialSupplyRequiresIssuancePredicate
    );
    // The verifier refuses identically: nobody can hand-craft a witness
    // around the builder.
    let (tree2, _) = funded_tree(era(), 500);
    let some_witness = {
        let (t, b) = funded_tree(era(), 500);
        let pre = t.root();
        let mut t = t;
        let built = build_write_set(
            &burn(500, era()),
            &G,
            &DEV,
            &econ_op_id(),
            &b,
            &mut t,
            &CreditSourceFacts::None,
        )
        .unwrap();
        witness_for(pre, built, &burn(500, era()))
    };
    drop(tree2);
    assert_eq!(
        verify_operation_write_set(&create_token(1_000, 500), &G, &DEV, &some_witness),
        Err(WriteSetError::CreateTokenInitialSupplyRequiresIssuancePredicate)
    );
}

// ── Adversarial near-misses the verifier must refuse ───────────────────────

#[test]
fn a_debit_with_an_extra_mutation_is_refused() {
    // The forgery the write-set rule exists for: a valid accepted Burn paired
    // with a witness that debits correctly AND slips in a consumed-source
    // insertion. Internally consistent, fully funded (no credits), and wrong.
    let (mut tree, balances) = funded_tree(era(), 50);
    let pre_root = tree.root();
    let built = build_write_set(
        &burn(50, era()),
        &G,
        &DEV,
        &econ_op_id(),
        &balances,
        &mut tree,
        &CreditSourceFacts::None,
    )
    .unwrap();
    let mut mutations = built.mutations;
    let record =
        EconomicLeafState::ConsumedSource(dsm::economic::state::EconomicConsumedSourceState {
            source_id: [0x5C; 32],
            consumer_economic_operation_id: econ_op_id(),
        });
    let key = record.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    mutations.push(EconomicLeafMutation::new(None, Some(record.clone()), siblings).unwrap());
    tree.insert(key, record.leaf_value().unwrap());
    let forged = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        econ_op_id(),
        dsm::economic::faucet::dsm_operation_digest(&burn(50, era()).to_bytes()),
        mutations,
        Vec::new(),
    );
    // Depending on key order the forged witness may not even form (keys must
    // ascend); when it does form, the verifier must refuse it.
    if let Ok(forged) = forged {
        assert!(matches!(
            verify_operation_write_set(&burn(50, era()), &G, &DEV, &forged),
            Err(WriteSetError::WrongWriteSet { .. })
        ));
    }
}

#[test]
fn a_debit_of_the_wrong_amount_or_asset_is_refused() {
    let (tree, balances) = funded_tree(era(), 100);
    let op = burn(40, era());
    let witness = round_trip(&op, tree, balances, &CreditSourceFacts::None);
    // Same witness, different claimed operations.
    assert!(verify_operation_write_set(&burn(41, era()), &G, &DEV, &witness).is_err());
    assert!(verify_operation_write_set(&burn(40, [0xEE; 32]), &G, &DEV, &witness).is_err());
    // And the role near-miss: the same delta presented as a transfer TO us
    // (credit role) is refused.
    assert!(verify_operation_write_set(&transfer(DEV, 40, era()), &G, &DEV, &witness).is_err());
}

#[test]
fn a_recipient_credit_without_its_consumed_source_is_refused() {
    // Build the credit half only — one balance mutation, one PeerDebit
    // source, NO consumed-source insertion. The non-reuse leaf is not
    // optional.
    let op = transfer(DEV, 40, era());
    let facts = CreditSourceFacts::PeerDebit {
        peer_genesis: [0x55; 32],
        peer_devid: PEER_DEV,
        peer_economic_position: 3,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: [0x66; 32],
    };
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &BTreeMap::new(),
        &mut tree,
        &facts,
    )
    .unwrap();
    // Strip the consumed-source mutation; keep only the balance credit and
    // re-point the source index at it.
    let credit_only: Vec<_> = built
        .mutations
        .into_iter()
        .filter(|m| matches!(m.post_state, Some(EconomicLeafState::Balance(_))))
        .collect();
    let mut sources = built.credit_sources;
    if let dsm::economic::credit::CreditSource::ValidatedPeerDebit(d) = &mut sources[0] {
        d.credit_mutation_index = 0;
    }
    let mut t2 = EconomicSmt::new();
    let m = &credit_only[0];
    let state = m.post_state.clone().unwrap();
    let key = state.leaf_key(&G, &DEV);
    let siblings = t2.siblings(&key).to_vec();
    let rebuilt = EconomicLeafMutation::new(None, Some(state.clone()), siblings).unwrap();
    t2.insert(key, state.leaf_value().unwrap());
    let stripped = EconomicTransitionWitness::new(
        pre_root,
        t2.root(),
        econ_op_id(),
        dsm::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        vec![rebuilt],
        sources,
    )
    .unwrap();
    assert!(matches!(
        verify_operation_write_set(&op, &G, &DEV, &stripped),
        Err(WriteSetError::WrongWriteSet { .. })
    ));
}

#[test]
fn mint_is_refused_by_the_write_set_rule_itself() {
    let (mut tree, balances) = funded_tree(era(), 100);
    assert_eq!(
        build_write_set(
            &Operation::Mint {
                amount: Balance::from_state(100, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: era(),
                authorized_by: Vec::new(),
                proof_of_authorization: Vec::new(),
                message: String::new(),
            },
            &G,
            &DEV,
            &econ_op_id(),
            &balances,
            &mut tree,
            &CreditSourceFacts::None,
        )
        .expect_err("no issuance predicate"),
        WriteSetError::IssuancePredicateUndefined
    );
}

#[test]
fn insufficient_balance_refuses_the_exact_debit() {
    let (mut tree, balances) = funded_tree(era(), 10);
    assert!(matches!(
        build_write_set(
            &burn(11, era()),
            &G,
            &DEV,
            &econ_op_id(),
            &balances,
            &mut tree,
            &CreditSourceFacts::None,
        ),
        Err(WriteSetError::InsufficientBalance {
            have: 10,
            need: 11,
            ..
        })
    ));
}

// ── Sequencing is real: order and progressive siblings ─────────────────────

#[test]
fn a_permuted_two_mutation_witness_fails_the_sequence() {
    let op = transfer(DEV, 40, era());
    let facts = CreditSourceFacts::PeerDebit {
        peer_genesis: [0x55; 32],
        peer_devid: PEER_DEV,
        peer_economic_position: 3,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: [0x66; 32],
    };
    let good = round_trip(&op, EconomicSmt::new(), BTreeMap::new(), &facts);
    let mut mutations = good.mutations.clone();
    mutations.swap(0, 1);
    // A permuted sequence either fails to FORM (keys must ascend) or fails
    // to verify; both are refusals, and forming AND verifying would be the
    // defect.
    match EconomicTransitionWitness::new(
        good.pre_economic_root,
        good.post_economic_root,
        good.economic_operation_id,
        good.operation_digest,
        mutations,
        good.credit_sources.clone(),
    ) {
        Err(_) => {}
        Ok(permuted) => {
            assert!(
                verify_mutation_sequence(&permuted.mutation_sequence(), &G, &DEV).is_err(),
                "a permuted mutation order must not verify"
            );
        }
    }
}

#[test]
fn stale_siblings_fail_the_sequence() {
    // Capture BOTH mutations' siblings against the PRE tree (not
    // progressively): the second proof is stale and the sequence must refuse.
    let op = transfer(DEV, 40, era());
    let peer_facts = CreditSourceFacts::PeerDebit {
        peer_genesis: [0x55; 32],
        peer_devid: PEER_DEV,
        peer_economic_position: 3,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: [0x66; 32],
    };
    let good = round_trip(&op, EconomicSmt::new(), BTreeMap::new(), &peer_facts);
    let empty = EconomicSmt::new();
    let stale: Vec<_> = good
        .mutations
        .iter()
        .map(|m| {
            let state = m.post_state.clone().unwrap();
            let key = state.leaf_key(&G, &DEV);
            EconomicLeafMutation::new(None, Some(state), empty.siblings(&key).to_vec()).unwrap()
        })
        .collect();
    match EconomicTransitionWitness::new(
        good.pre_economic_root,
        good.post_economic_root,
        good.economic_operation_id,
        good.operation_digest,
        stale,
        good.credit_sources.clone(),
    ) {
        Err(_) => {}
        Ok(w) => {
            assert!(
                verify_mutation_sequence(&w.mutation_sequence(), &G, &DEV).is_err(),
                "stale sibling proofs must not verify"
            );
        }
    }
}

// ── The manifest decoder is strict ─────────────────────────────────────────

#[test]
fn the_manifest_decoder_round_trips_and_refuses_non_canonical_bytes() {
    use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
    use dsm::economic::decode::decode_admission_manifest;
    let manifest = EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: [0xA4; 32],
        },
        vec![[0x02; 32], [0x01; 32]],
    )
    .unwrap();
    let bytes = manifest.encode().unwrap();
    let decoded = decode_admission_manifest(&bytes).expect("round trip");
    assert_eq!(decoded.addr().unwrap(), manifest.addr().unwrap());

    // Trailing byte refused.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_admission_manifest(&trailing).is_err());

    // Unsorted provenance index refused, never canonicalized: swap the two
    // sorted addrs in the encoded bytes.
    let mut unsorted = bytes.clone();
    let n = unsorted.len();
    let (a_start, b_start) = (n - 64, n - 32);
    let a: Vec<u8> = unsorted[a_start..b_start].to_vec();
    let b: Vec<u8> = unsorted[b_start..].to_vec();
    unsorted[a_start..b_start].copy_from_slice(&b);
    unsorted[b_start..].copy_from_slice(&a);
    assert!(
        decode_admission_manifest(&unsorted).is_err(),
        "non-canonical index order must be refused"
    );
}
