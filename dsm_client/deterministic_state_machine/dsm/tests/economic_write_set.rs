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

use dsm::economic::admission::dsm_economic_operation_id;
use dsm::economic::native_reserve::{era_reserve_id, ERA_FAUCET_PAYOUT};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState, EconomicTokenCreationState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::{verify_mutation_sequence, EconomicTransitionWitness};
use dsm::economic::write_set::{
    EconomicPreState, build_write_set, verify_operation_write_set, CreditSourceFacts, WriteSetError,
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
        amount: Balance::amount(amount),
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
        amount: Balance::amount(amount),
        token_id: b"T".to_vec(),
        policy_commit,
        proof_of_ownership: Vec::new(),
        message: String::new(),
    }
}

fn create_token(initial_supply: u64, fee_amount: u64) -> Operation {
    Operation::CreateToken {
        token_id: b"NEW".to_vec(),
        initial_supply: Balance::amount(initial_supply),
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
        dsm::economic::admission::dsm_operation_digest(&operation.to_bytes()),
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
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        facts,
    )
    .expect("buildable");
    let witness = witness_for(pre_root, built, operation);
    verify_mutation_sequence(&witness.mutation_sequence(), &G, &DEV).expect("sequence verifies");
    verify_operation_write_set(operation, &G, &DEV, &witness, P_CREATE)
        .expect("exact effect verifies");
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
        reserve_id: era_reserve_id(b"dsm-testnet"),
        generation: 42,
    };
    let facts = CreditSourceFacts::NativeReserveRelease {
        release_evidence_addr: [0x99; 32],
    };
    let witness = round_trip(&op, EconomicSmt::new(), BTreeMap::new(), &facts);
    match &witness.mutations[0].post_state {
        Some(EconomicLeafState::Balance(b)) => assert_eq!(b.amount, ERA_FAUCET_PAYOUT),
        other => panic!("expected the payout credit, got {other:?}"),
    }
}

// ── CreateToken: the fee debit and the genesis release (SoFi §51) ──────────

/// A token with no genesis supply is not a token (SoFi §50), so it has no
/// write set to build.
#[test]
fn a_zero_supply_creation_has_no_write_set() {
    let (mut tree, balances) = funded_tree(era(), 500);
    assert_eq!(
        build_write_set(
            &create_token(0, 500),
            &G,
            &DEV,
            &econ_op_id(),
            &EconomicPreState::new(&balances, P_CREATE),
            &mut tree,
            &CreditSourceFacts::GenesisRelease,
        )
        .expect_err("a zero-supply creation is not a token"),
        WriteSetError::NoEconomicWriteSet
    );
}

/// A creation is its ERA fee debit, the credit of its whole genesis supply
/// funded by one genesis release naming that credit, and its creation record
/// inserted from zero (Amendment S8). Built and verified from the one table.
#[test]
fn a_token_creation_is_its_fee_debit_and_its_genesis_release() {
    let (tree, balances) = funded_tree(era(), 500);
    let witness = round_trip(
        &create_token(1_000, 500),
        tree,
        balances,
        &CreditSourceFacts::GenesisRelease,
    );
    assert_eq!(
        witness.mutations.len(),
        3,
        "the fee debit, the release and the creation record"
    );
    assert!(witness.mutations.iter().any(|m| m.pre_state.is_none()
        && m.post_state
            == Some(EconomicLeafState::TokenCreation(
                EconomicTokenCreationState {
                    policy_commit: [0x77; 32]
                }
            ))));
    let [dsm::economic::credit::CreditSource::GenesisRelease(release)] =
        witness.credit_sources.as_slice()
    else {
        panic!("one genesis release, got {:?}", witness.credit_sources)
    };
    let credited = &witness.mutations[release.credit_mutation_index as usize];
    match &credited.post_state {
        Some(EconomicLeafState::Balance(b)) => {
            assert_eq!((b.policy_commit, b.amount), ([0x77; 32], 1_000));
        }
        other => panic!("expected the release credit, got {other:?}"),
    }
    // Without a fee, the release and the record.
    let (tree, balances) = funded_tree(era(), 500);
    let witness = round_trip(
        &create_token(1_000, 0),
        tree,
        balances,
        &CreditSourceFacts::GenesisRelease,
    );
    assert_eq!(witness.mutations.len(), 2);
}

/// Amendment S8: a token is created once on its creator's lineage. A tree
/// already holding the creation record cannot build a second creation of the
/// same token.
#[test]
fn a_token_is_created_once_on_its_creators_lineage() {
    let (mut tree, balances) = funded_tree(era(), 500);
    let record = EconomicLeafState::TokenCreation(EconomicTokenCreationState {
        policy_commit: [0x77; 32],
    });
    tree.insert(record.leaf_key(&G, &DEV), record.leaf_value().unwrap());
    assert!(matches!(
        build_write_set(
            &create_token(1_000, 500),
            &G,
            &DEV,
            &econ_op_id(),
            &EconomicPreState::new(&balances, P_CREATE),
            &mut tree,
            &CreditSourceFacts::GenesisRelease,
        ),
        Err(WriteSetError::WrongWriteSet { .. })
    ));
}

/// A creation witness is the effect of exactly its own operation: offered
/// for a creation of another supply or another fee, it is refused.
#[test]
fn a_creation_witness_of_another_supply_or_fee_is_refused() {
    let (mut tree, balances) = funded_tree(era(), 500);
    let pre = tree.root();
    let op = create_token(1_000, 500);
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::GenesisRelease,
    )
    .unwrap();
    let witness = witness_for(pre, built, &op);
    assert_eq!(
        verify_operation_write_set(&op, &G, &DEV, &witness, P_CREATE),
        Ok(())
    );
    for other in [create_token(999, 500), create_token(1_000, 400)] {
        assert!(
            matches!(
                verify_operation_write_set(&other, &G, &DEV, &witness, P_CREATE),
                Err(WriteSetError::WrongWriteSet { .. })
            ),
            "{other:?}"
        );
    }
}

/// A creation witness without its creation record is not the creation's
/// effect: the record is what makes a second creation unbuildable.
#[test]
fn a_creation_witness_without_its_record_is_refused() {
    let (mut tree, balances) = funded_tree(era(), 500);
    let pre = tree.root();
    let op = create_token(1_000, 500);
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::GenesisRelease,
    )
    .unwrap();
    let credit_index = built.credit_sources[0].credit_mutation_index() as usize;
    let credited = built.mutations[credit_index].clone();
    let without_record: Vec<EconomicLeafMutation> = built
        .mutations
        .into_iter()
        .filter(|m| !matches!(m.post_state, Some(EconomicLeafState::TokenCreation(_))))
        .collect();
    assert_eq!(without_record.len(), 2);
    let index = without_record
        .iter()
        .position(|m| *m == credited)
        .expect("the release credit") as u32;
    let witness = EconomicTransitionWitness::new(
        pre,
        built.post_root,
        econ_op_id(),
        dsm::economic::admission::dsm_operation_digest(&op.to_bytes()),
        without_record,
        vec![dsm::economic::credit::CreditSource::GenesisRelease(
            dsm::economic::credit::CreditSourceGenesisRelease {
                credit_mutation_index: index,
            },
        )],
    )
    .expect("a structurally valid witness");
    assert!(matches!(
        verify_operation_write_set(&op, &G, &DEV, &witness, P_CREATE),
        Err(WriteSetError::WrongWriteSet { .. })
    ));
}

/// The creation's credit has one funding statement, the genesis release:
/// no other facts build it, and the verifier refuses a witness of another
/// operation's effect offered for it.
#[test]
fn a_token_creation_is_funded_only_by_its_genesis_release() {
    let (mut tree, balances) = funded_tree(era(), 500);
    assert_eq!(
        build_write_set(
            &create_token(1_000, 500),
            &G,
            &DEV,
            &econ_op_id(),
            &EconomicPreState::new(&balances, P_CREATE),
            &mut tree,
            &CreditSourceFacts::None,
        )
        .expect_err("a credit with no source is not fundable"),
        WriteSetError::FactsDoNotMatchOperation
    );
    let (mut tree, balances) = funded_tree(era(), 500);
    let pre = tree.root();
    let burned = build_write_set(
        &burn(500, era()),
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .unwrap();
    let burn_witness = witness_for(pre, burned, &burn(500, era()));
    assert!(matches!(
        verify_operation_write_set(&create_token(1_000, 500), &G, &DEV, &burn_witness, P_CREATE),
        Err(WriteSetError::WrongWriteSet { .. })
    ));
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
        &EconomicPreState::new(&balances, P_CREATE),
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
        dsm::economic::admission::dsm_operation_digest(&burn(50, era()).to_bytes()),
        mutations,
        Vec::new(),
    );
    // Depending on key order the forged witness may not even form (keys must
    // ascend); when it does form, the verifier must refuse it.
    if let Ok(forged) = forged {
        assert!(matches!(
            verify_operation_write_set(&burn(50, era()), &G, &DEV, &forged, P_CREATE),
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
    assert!(verify_operation_write_set(&burn(41, era()), &G, &DEV, &witness, P_CREATE).is_err());
    assert!(
        verify_operation_write_set(&burn(40, [0xEE; 32]), &G, &DEV, &witness, P_CREATE).is_err()
    );
    // And the role near-miss: the same delta presented as a transfer TO us
    // (credit role) is refused.
    assert!(
        verify_operation_write_set(&transfer(DEV, 40, era()), &G, &DEV, &witness, P_CREATE)
            .is_err()
    );
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
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
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
        dsm::economic::admission::dsm_operation_digest(&op.to_bytes()),
        vec![rebuilt],
        sources,
    )
    .unwrap();
    assert!(matches!(
        verify_operation_write_set(&op, &G, &DEV, &stripped, P_CREATE),
        Err(WriteSetError::WrongWriteSet { .. })
    ));
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
            &EconomicPreState::new(&balances, P_CREATE),
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

// ── 3.6: the DLV pair write sets (funded create, close) ────────────────────

// ── SoFi: the two inserts P15-6 and P15-12 specify ─────────────────────────

const P_CREATE: u64 = 7;

/// A tree that actually HOLDS the balances, and the matching pre-state map.
/// Declaring a balance without seeding its leaf makes the mutation sequence
/// unverifiable — the pre-state must be in the root the paths are against.
fn sofi_funded(pairs: &[([u8; 32], u64)]) -> (EconomicSmt, BTreeMap<[u8; 32], u64>) {
    let mut tree = EconomicSmt::new();
    let mut balances = BTreeMap::new();
    for (asset, amount) in pairs {
        let state = EconomicLeafState::Balance(EconomicBalanceState::new(*asset, *amount).unwrap());
        tree.insert(state.leaf_key(&G, &DEV), state.leaf_value().unwrap());
        balances.insert(*asset, *amount);
    }
    (tree, balances)
}

fn sofi_vault_id() -> [u8; 32] {
    dsm::sofi::derive::vault_id(&G, &DEV, P_CREATE)
}

fn sofi_setup_operation() -> Operation {
    let body = dsm::sofi::wire::SofiSetupBody::new(
        G,
        DEV,
        5,
        sofi_vault_id(),
        [0x66; 32],
        [0x67; 32],
        0x0001,
        &[0x01; 64],
    )
    .expect("a setup body");
    Operation::SofiSetup {
        setup_body: body.encode(),
        signature: vec![0xA1; 8],
    }
}

/// The REAL market policy this vault's state names. It has to be real now:
/// Core re-addresses the bytes the operation carries and requires the address
/// the state commits, so a literal placeholder address authorizes nothing.
fn sofi_market_policy(market: ([u8; 32], [u8; 32])) -> dsm::ccb::state::MarketPolicy {
    dsm::ccb::state::MarketPolicy::beta_constant_product(market.0, market.1)
        .expect("an ordered beta pair")
}

fn sofi_market_policy_addr(market: ([u8; 32], [u8; 32])) -> [u8; 32] {
    dsm::ccb::decode::policy_object_address(
        dsm::ccb::class::MARKET_POLICY,
        &sofi_market_policy(market).encode(),
    )
    .expect("a policy class")
}

/// The MARKET pair is now a parameter, separate from the FUNDING pair the
/// operation claims. That separation is the point of the binding under test:
/// before it, the funding assets were free of the vault's declared market.
fn sofi_genesis_state(market: ([u8; 32], [u8; 32])) -> dsm::sofi::wire::VaultStateLeaf {
    dsm::sofi::wire::VaultStateLeaf {
        owner_genesis: G,
        owner_device_id: DEV,
        create_position: P_CREATE,
        market_policy: sofi_market_policy_addr(market),
        fee_policy: [0x32; 32],
        release_policy: [0x33; 32],
        storage_set_id: [0x77; 32],
        generation: 0,
        reserve_a: 1_000,
        reserve_b: 2_000,
        status: dsm::sofi::wire::VAULT_STATUS_ACTIVE,
    }
}

fn sofi_create_operation(
    market: ([u8; 32], [u8; 32]),
    funding_a: [u8; 32],
    funding_b: [u8; 32],
    amount_a: u64,
    amount_b: u64,
) -> Operation {
    let state = sofi_genesis_state(market);
    let preimage = dsm::sofi::wire::VaultGenesisPreimage {
        owner_genesis: G,
        owner_device_id: DEV,
        create_position: P_CREATE,
        state: state.clone(),
    };
    let vault_id = preimage.vault_id();
    let creation = dsm::sofi::wire::VaultCreation {
        vault_id,
        genesis_root: dsm::sofi::lineage::genesis_root(&vault_id, &state).expect("R_0"),
        amount_a,
        amount_b,
    };
    Operation::SofiVaultCreate {
        genesis_preimage: preimage.encode().expect("preimage encodes"),
        creation: creation.encode(),
        market_policy_preimage: sofi_market_policy(market).encode(),
        funding_a_policy_commit: funding_a,
        funding_b_policy_commit: funding_b,
        signature: vec![0xA1; 8],
    }
}

/// P15-6: ONE relationship leaf, from zero, and no value movement — through
/// the producer, the witness, and BOTH verifier halves.
#[test]
fn a_setup_inserts_exactly_one_relationship_leaf_from_zero() {
    let witness = round_trip(
        &sofi_setup_operation(),
        EconomicSmt::new(),
        BTreeMap::new(),
        &CreditSourceFacts::None,
    );
    assert_eq!(witness.mutations.len(), 1, "exactly one leaf");
    let m = &witness.mutations[0];
    assert!(m.pre_state.is_none(), "inserted from zero");
    match &m.post_state {
        Some(dsm::economic::state::EconomicLeafState::Relationship(r)) => {
            assert_eq!(r.vault_id, sofi_vault_id());
            // `h⁰` is the setup id's derivation, not anything the operation
            // chose.
            let sigma = dsm::sofi::derive::setup_id(&G, &DEV, 5, &sofi_vault_id());
            assert_eq!(r.leaf, dsm::sofi::derive::relationship_leaf_genesis(&sigma));
        }
        other => panic!("a relationship leaf, got {other:?}"),
    }
    assert!(
        witness.credit_sources.is_empty(),
        "a setup is non-economic: it funds nothing"
    );
}

/// A SECOND setup for the same vault is refused, never applied. `h⁰` is a
/// function of the setup id, so an overwrite would reset a chain that has
/// already advanced.
#[test]
fn a_setup_refuses_to_replace_an_existing_relationship() {
    let op = sofi_setup_operation();
    let mut tree = EconomicSmt::new();
    // The first one lands.
    build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("the first setup builds");
    // The second does not.
    let again = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    );
    assert!(
        matches!(again, Err(WriteSetError::WrongWriteSet { .. })),
        "a relationship leaf is inserted once, got {again:?}"
    );
}

/// P15-12: two debits and the record, as ONE write set, through both halves.
#[test]
fn a_vault_creation_debits_the_pair_and_inserts_the_record() {
    let (a, b) = ([0x40; 32], [0x41; 32]);
    let (tree, balances) = sofi_funded(&[(a, 5_000), (b, 9_000)]);
    let witness = round_trip(
        &sofi_create_operation((a, b), a, b, 1_000, 2_000),
        tree,
        balances,
        &CreditSourceFacts::None,
    );
    assert_eq!(
        witness.mutations.len(),
        3,
        "two debits and one record, atomically"
    );
    let creations: Vec<_> = witness
        .mutations
        .iter()
        .filter(|m| {
            matches!(
                m.post_state,
                Some(dsm::economic::state::EconomicLeafState::VaultCreation(_))
            )
        })
        .collect();
    assert_eq!(creations.len(), 1);
    assert!(creations[0].pre_state.is_none(), "insert-only");
    assert!(
        witness.credit_sources.is_empty(),
        "funded from the owner's own balances; no external source"
    );
}

/// The creation's own conjuncts, each refusing on its own.
#[test]
fn a_creation_is_refused_on_each_missing_conjunct() {
    let (a, b) = ([0x40; 32], [0x41; 32]);
    let balances = |x: u64, y: u64| {
        let mut m = BTreeMap::new();
        m.insert(a, x);
        m.insert(b, y);
        m
    };
    let build = |op: &Operation, bal: BTreeMap<[u8; 32], u64>| {
        let (mut tree, _) = sofi_funded(&[(a, bal[&a]), (b, bal[&b])]);
        build_write_set(
            op,
            &G,
            &DEV,
            &econ_op_id(),
            &EconomicPreState::new(&bal, P_CREATE),
            &mut tree,
            &CreditSourceFacts::None,
        )
        .map(|_| ())
    };

    // Amounts that are not the genesis reserves would mint reserves.
    assert!(matches!(
        build(
            &sofi_create_operation((a, b), a, b, 999, 2_000),
            balances(5_000, 9_000)
        ),
        Err(WriteSetError::MalformedVaultOperation { .. })
    ));
    // An unordered pair.
    assert!(matches!(
        build(
            &sofi_create_operation((a, b), b, a, 1_000, 2_000),
            balances(5_000, 9_000)
        ),
        Err(WriteSetError::MalformedVaultOperation { .. })
    ));
    // The same asset twice.
    assert!(matches!(
        build(
            &sofi_create_operation((a, b), a, a, 1_000, 2_000),
            balances(5_000, 9_000)
        ),
        Err(WriteSetError::MalformedVaultOperation { .. })
    ));
    // A balance that cannot cover the funding.
    assert!(build(
        &sofi_create_operation((a, b), a, b, 1_000, 2_000),
        balances(10, 9_000)
    )
    .is_err());
}

/// EACH SOFI LEAF IS LEGAL FOR EXACTLY ONE OPERATION. The verifier's leaf
/// classifier ends in a catch-all, so adding the enum variants forced nothing
/// here: a setup carrying a creation record, or a creation carrying a
/// relationship leaf, has to be refused BY CLASS.
#[test]
fn a_sofi_leaf_is_refused_under_the_wrong_operation() {
    let (a, b) = ([0x40; 32], [0x41; 32]);
    let (mut tree, balances) = sofi_funded(&[(a, 5_000), (b, 9_000)]);

    // The witness a CREATION produces, verified against a SETUP.
    let create = sofi_create_operation((a, b), a, b, 1_000, 2_000);
    let pre_root = tree.root();
    let built = build_write_set(
        &create,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("buildable");
    let creation_witness = witness_for(pre_root, built, &create);
    let setup = sofi_setup_operation();
    assert!(
        matches!(
            verify_operation_write_set(&setup, &G, &DEV, &creation_witness, P_CREATE),
            Err(WriteSetError::UnexpectedLeafClass)
        ),
        "a setup may not carry a creation record"
    );

    // And the witness a SETUP produces, verified against a CREATION.
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let built = build_write_set(
        &setup,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("buildable");
    let setup_witness = witness_for(pre_root, built, &setup);
    assert!(
        matches!(
            verify_operation_write_set(&create, &G, &DEV, &setup_witness, P_CREATE),
            Err(WriteSetError::UnexpectedLeafClass)
        ),
        "a creation may not carry a relationship leaf"
    );
}

/// A VALID CREATION WHOSE KEY ORDER INVERTS ITS ASSET ORDER STILL VERIFIES.
///
/// The producer sorts planned leaves by SMT key (a hash), while `dlv_pair_legs`
/// requires the assets in lexical order. Those two orders are unrelated, so a
/// verifier that matched debits by vector position would reject perfectly
/// valid write sets — and would do it for some asset pairs and not others,
/// looking random.
///
/// The fixture is chosen to be adversarial and ASSERTS that it still is: if a
/// key derivation ever changes and the inversion disappears, this test says so
/// rather than quietly becoming a duplicate of the happy path.
#[test]
fn a_creation_verifies_when_key_order_opposes_asset_order() {
    let (a, b) = ([0x00; 32], [0x01; 32]);
    assert!(a < b, "the assets are in canonical order");
    assert!(
        dsm::economic::keys::balance_key(&G, &DEV, &a)
            > dsm::economic::keys::balance_key(&G, &DEV, &b),
        "this fixture must invert: their SMT keys sort opposite their commits"
    );

    let (tree, balances) = sofi_funded(&[(a, 5_000), (b, 9_000)]);
    let witness = round_trip(
        &sofi_create_operation((a, b), a, b, 1_000, 2_000),
        tree,
        balances,
        &CreditSourceFacts::None,
    );
    assert_eq!(witness.mutations.len(), 3);
}

/// THE ASSET-SUBSTITUTION DOOR, at the real seam.
///
/// Fund the creation from assets the device genuinely HOLDS, in canonical
/// order, in the exact amounts the genesis reserves state — and have the vault
/// declare a market in two entirely different assets. Every other binding
/// holds. It must still be refused, because a later close credits the owner
/// the MARKET's pair, which this creation never funded.
///
/// Until the funding pair was bound to the decoded market policy, this
/// operation was accepted by both write-set halves. The binding had lived in
/// `genesis_accepted`, whose deletion removed it, and after that only the SDK
/// producer enforced it — which is no enforcement at all against a different
/// producer.
#[test]
fn funding_assets_outside_the_declared_market_are_refused_even_when_funded() {
    let market = ([0x40; 32], [0x41; 32]);
    let (junk_a, junk_b) = ([0x70; 32], [0x71; 32]);
    assert!(
        junk_a < junk_b,
        "the substitute pair is canonically ordered"
    );
    assert_ne!(junk_a, market.0);

    // The device really holds the substitutes, in ample amount.
    let (mut tree, balances) = sofi_funded(&[(junk_a, 5_000), (junk_b, 9_000)]);
    let op = sofi_create_operation(market, junk_a, junk_b, 1_000, 2_000);
    let err = build_write_set(
        &op,
        &G,
        &DEV,
        &[0xE0; 32],
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect_err("a creation may not fund from outside its declared market");
    assert!(
        matches!(err, WriteSetError::MalformedVaultOperation { .. }),
        "got {err:?}"
    );
}

/// A SETUP BINDS BOTH ITS COORDINATES, not just the device.
///
/// The leaf's KEY is derived from the authenticated `(G, DevID)` while `h⁰`
/// is derived from the BODY's, so a body naming a foreign genesis would place
/// a leaf computed from that identity at this device's key — two disagreeing
/// claims about whose relationship it is. The device half was checked; the
/// genesis half was not.
#[test]
fn a_setup_naming_a_foreign_genesis_is_refused() {
    let foreign = dsm::sofi::wire::SofiSetupBody::new(
        [0x99; 32], // not G
        DEV,
        5,
        sofi_vault_id(),
        [0x66; 32],
        [0x67; 32],
        0x0001,
        &[0x01; 64],
    )
    .expect("a setup body");
    let op = Operation::SofiSetup {
        setup_body: foreign.encode(),
        signature: vec![0xA1; 8],
    };
    let mut tree = EconomicSmt::new();
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    );
    assert!(
        matches!(built, Err(WriteSetError::MalformedVaultOperation { .. })),
        "a setup writes into its own identity's tree, got {built:?}"
    );
}

/// `R_T^setup` IS THE ROOT THE TRANSITION PRODUCES — producer and verifier
/// agreeing on one derived value, not a signed assertion.
///
/// Before this, `setup_root` had zero readers anywhere: a correctly signed
/// first setup could put ANY 32 bytes there and the index would pin a `ρ`
/// committing them forever. The uniqueness rule held over a field nothing
/// checked.
#[test]
fn a_setups_root_is_the_root_its_own_transition_produces() {
    let op = sofi_setup_operation();
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("buildable");
    let post_root = built.post_root;
    let witness = witness_for(pre_root, built, &op);

    // The derived post-root IS `SMT_Insert(R_p, k_T,v, ABSENT -> L⁰)`.
    let sigma = dsm::sofi::derive::setup_id(&G, &DEV, 5, &sofi_vault_id());
    let state = EconomicLeafState::Relationship(dsm::sofi::wire::TraderRelationshipLeaf {
        vault_id: sofi_vault_id(),
        leaf: dsm::sofi::derive::relationship_leaf_genesis(&sigma),
    });
    let mut expected = EconomicSmt::new();
    expected.insert(state.leaf_key(&G, &DEV), state.leaf_value().unwrap());
    assert_eq!(post_root, expected.root(), "the absent→h⁰ insertion's root");
    assert_eq!(
        witness.post_economic_root, post_root,
        "and the witness commits it"
    );

    // A body asserting some OTHER root is the case the field's whole job is
    // to make impossible.
    let body = dsm::sofi::wire::SofiSetupBody::new(
        G,
        DEV,
        5,
        sofi_vault_id(),
        [0x66; 32],
        [0xEE; 32], // not the derived root
        0x0001,
        &[0x01; 64],
    )
    .expect("a setup body");
    assert_ne!(*body.setup_root(), post_root);
}
