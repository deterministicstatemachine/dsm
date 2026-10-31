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
use dsm::types::operations::{Operation, TransactionMode};
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
        policy_commit,
        token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
        terms_commitment: dsm::types::operations::TransferTerms {
            token_id: b"T".to_vec(),
            nonce: vec![7; 32],
            mode: TransactionMode::Unilateral,
            memo: String::new(),
            salt: vec![0x5A; 32],
        }
        .commitment(),
        signature: Vec::new(),
        authority_policy: None,
    }
}

/// A Transfer of `token`, carrying `carried` as its token's policy.
fn transfer_carrying(to: [u8; 32], amount: u64, token: [u8; 32], carried: &[u8]) -> Operation {
    match transfer(to, amount, token) {
        Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            terms_commitment,
            signature,
            authority_policy,
            ..
        } => Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            terms_commitment,
            token_policy: carried.to_vec(),
            signature,
            authority_policy,
        },
        other => other,
    }
}

/// A Burn of `token`, carrying `carried` as its token's policy.
fn burn_carrying(amount: u64, token: [u8; 32], carried: &[u8]) -> Operation {
    Operation::Burn {
        amount: Balance::amount(amount),
        token_id: b"T".to_vec(),
        policy_commit: token,
        token_policy: carried.to_vec(),
        message: String::new(),
    }
}

fn burn(amount: u64, policy_commit: [u8; 32]) -> Operation {
    Operation::Burn {
        amount: Balance::amount(amount),
        token_id: b"T".to_vec(),
        policy_commit,
        token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
        message: String::new(),
    }
}

/// The protocol's token-creation fee, in ERA base units (SoFi Amendment S18).
const FEE: u64 = dsm::core::token::TOKEN_CREATION_FEE_ERA;

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

// ── A token's committed policy, read in the write set (owner question 9) ──

/// `build_write_set` for `operation` over a tree funded with `amount` of `token`.
fn build_over(
    operation: &Operation,
    token: [u8; 32],
    amount: u64,
) -> Result<dsm::economic::write_set::BuiltWriteSet, WriteSetError> {
    let (mut tree, balances) = funded_tree(token, amount);
    build_write_set(
        operation,
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&balances, P_CREATE),
        &mut tree,
        &CreditSourceFacts::None,
    )
}

/// Owner question 9 (2026-10-27): Core is the enforcement boundary for a
/// Transfer or Burn its token's committed policy forbids. The write set
/// refuses it, from the policy bytes the signed operation carries, before
/// anything moves: the producer's device cannot build it, and a verifier
/// handed the debit refuses the operation that names it. A token whose policy
/// permits the move passes both.
///
/// MUTATION CONTROL: removing the `transferable` refusal from the write set's
/// Transfer arm turns this red, and so does removing the `burn_enabled`
/// refusal from its Burn arm.
#[test]
fn a_transfer_or_burn_its_tokens_policy_forbids_has_no_write_set() {
    use dsm::economic::token_policy::{POLICY_FLAG_BURN, POLICY_FLAG_TRANSFERABLE};
    let (burns_only, burns_only_policy) = policy_token(70, POLICY_FLAG_BURN);
    let (moves_only, moves_only_policy) = policy_token(71, POLICY_FLAG_TRANSFERABLE);

    let forbidden_transfer = transfer_carrying(PEER_DEV, 40, burns_only, &burns_only_policy);
    match build_over(&forbidden_transfer, burns_only, 100) {
        Err(refused) => assert_eq!(
            refused,
            WriteSetError::TokenNotTransferable { token: burns_only }
        ),
        Ok(_) => panic!("a transfer of a token that does not transfer has a write set"),
    }
    let forbidden_burn = burn_carrying(40, moves_only, &moves_only_policy);
    match build_over(&forbidden_burn, moves_only, 100) {
        Err(refused) => assert_eq!(
            refused,
            WriteSetError::TokenNotBurnable { token: moves_only }
        ),
        Ok(_) => panic!("a burn of a token that does not burn has a write set"),
    }

    // The permitted twins build, and their witnesses verify.
    let (tree, balances) = funded_tree(moves_only, 100);
    round_trip(
        &transfer_carrying(PEER_DEV, 40, moves_only, &moves_only_policy),
        tree,
        balances,
        &CreditSourceFacts::None,
    );
    let (tree, balances) = funded_tree(burns_only, 100);
    let pre_root = tree.root();
    let burned = round_trip(
        &burn_carrying(40, burns_only, &burns_only_policy),
        tree,
        balances,
        &CreditSourceFacts::None,
    );

    // A verifier handed that exact debit under a Transfer of the same token
    // refuses the Transfer: the debit is a burn's shape, the token does not
    // transfer.
    let as_transfer = EconomicTransitionWitness::new(
        pre_root,
        burned.post_economic_root,
        econ_op_id(),
        dsm::economic::admission::dsm_operation_digest(&forbidden_transfer.to_bytes()),
        burned.mutations.clone(),
        burned.credit_sources.clone(),
    )
    .expect("a well-formed witness");
    assert_eq!(
        verify_operation_write_set(&forbidden_transfer, &G, &DEV, &as_transfer, P_CREATE),
        Err(WriteSetError::TokenNotTransferable { token: burns_only })
    );
}

/// The policy bytes a Transfer or Burn carries are its token's committed
/// policy, ERA's included, re-hashed to its commit before anything is read
/// out of them: another token's bytes, or none, are refused.
///
/// MUTATION CONTROL: skipping the re-hash turns this red.
#[test]
fn a_transfer_or_burn_carries_exactly_its_tokens_committed_policy() {
    use dsm::economic::token_policy::{POLICY_FLAG_BURN, POLICY_FLAG_TRANSFERABLE};
    let (token, _) = policy_token(72, POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE);
    let (_, other_policy) = policy_token(73, POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE);
    for moved in [token, era()] {
        for carried in [other_policy.clone(), Vec::new()] {
            for operation in [
                transfer_carrying(PEER_DEV, 40, moved, &carried),
                burn_carrying(40, moved, &carried),
            ] {
                match build_over(&operation, moved, 100) {
                    Err(refused) => {
                        assert_eq!(
                            refused,
                            WriteSetError::TokenPolicyNotTheToken { token: moved }
                        )
                    }
                    Ok(_) => panic!("an operation carrying bytes that are not its token's built"),
                }
            }
        }
    }
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
    let (mut tree, balances) = funded_tree(era(), FEE);
    assert_eq!(
        build_write_set(
            &create_token(0, FEE),
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
    let (tree, balances) = funded_tree(era(), FEE);
    let witness = round_trip(
        &create_token(1_000, FEE),
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
    // The fee is the protocol's (SoFi Amendment S18): a creation naming any
    // other, none included, has no write set to build.
    for fee in [0, FEE - 1, FEE + 1] {
        let (mut tree, balances) = funded_tree(era(), FEE + 1);
        assert_eq!(
            build_write_set(
                &create_token(1_000, fee),
                &G,
                &DEV,
                &econ_op_id(),
                &EconomicPreState::new(&balances, P_CREATE),
                &mut tree,
                &CreditSourceFacts::GenesisRelease,
            )
            .expect_err("only the protocol fee"),
            WriteSetError::CreationFeeNotTheProtocols { fee_amount: fee }
        );
    }
}

/// Amendment S8: a token is created once on its creator's lineage. A tree
/// already holding the creation record cannot build a second creation of the
/// same token.
#[test]
fn a_token_is_created_once_on_its_creators_lineage() {
    let (mut tree, balances) = funded_tree(era(), FEE);
    let record = EconomicLeafState::TokenCreation(EconomicTokenCreationState {
        policy_commit: [0x77; 32],
    });
    tree.insert(record.leaf_key(&G, &DEV), record.leaf_value().unwrap());
    assert!(matches!(
        build_write_set(
            &create_token(1_000, FEE),
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
    let (mut tree, balances) = funded_tree(era(), FEE);
    let pre = tree.root();
    let op = create_token(1_000, FEE);
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
    let other_supply = create_token(999, FEE);
    assert!(
        matches!(
            verify_operation_write_set(&other_supply, &G, &DEV, &witness, P_CREATE),
            Err(WriteSetError::WrongWriteSet { .. })
        ),
        "{other_supply:?}"
    );
    // Another fee is not a creation at all (SoFi Amendment S18).
    assert_eq!(
        verify_operation_write_set(&create_token(1_000, 400), &G, &DEV, &witness, P_CREATE),
        Err(WriteSetError::CreationFeeNotTheProtocols { fee_amount: 400 })
    );
}

/// A creation witness without its creation record is not the creation's
/// effect: the record is what makes a second creation unbuildable.
#[test]
fn a_creation_witness_without_its_record_is_refused() {
    let (mut tree, balances) = funded_tree(era(), FEE);
    let pre = tree.root();
    let op = create_token(1_000, FEE);
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
    let (mut tree, balances) = funded_tree(era(), FEE);
    assert_eq!(
        build_write_set(
            &create_token(1_000, FEE),
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
    let (mut tree, balances) = funded_tree(era(), FEE);
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
        verify_operation_write_set(&create_token(1_000, FEE), &G, &DEV, &burn_witness, P_CREATE),
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

/// Same witness, different claimed operations: each is refused by the check
/// for exactly what it changes. The near-miss on the asset names a burnable
/// token and carries its own committed policy, so the policy check passes and
/// only the asset binding can refuse it.
///
/// MUTATION CONTROL: delete the asset comparison in the pure-debit arm of
/// `verify_operation_write_set` and the asset near-miss is accepted: red.
#[test]
fn a_debit_of_the_wrong_amount_or_asset_is_refused() {
    use dsm::economic::token_policy::POLICY_FLAG_BURN;
    let (tree, balances) = funded_tree(era(), 100);
    let op = burn(40, era());
    let witness = round_trip(&op, tree, balances, &CreditSourceFacts::None);
    assert_eq!(
        verify_operation_write_set(&burn(41, era()), &G, &DEV, &witness, P_CREATE),
        Err(WriteSetError::WrongWriteSet {
            detail: "debit delta is not exactly the operation amount"
        })
    );
    let (other, other_policy) = policy_token(74, POLICY_FLAG_BURN);
    assert_eq!(
        verify_operation_write_set(
            &burn_carrying(40, other, &other_policy),
            &G,
            &DEV,
            &witness,
            P_CREATE
        ),
        Err(WriteSetError::WrongWriteSet {
            detail: "debit touches a different asset than the operation names"
        })
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

// ── A consumed source is write-once (MR-DSM-0161) ──────────────────────────

/// One planned leaf write: its key, its pre-state and its post-state.
type Planned = (
    [u8; 32],
    Option<EconomicLeafState>,
    Option<EconomicLeafState>,
);

/// The peer debit every credit below draws on.
fn peer_debit() -> CreditSourceFacts {
    CreditSourceFacts::PeerDebit {
        peer_genesis: [0x55; 32],
        peer_devid: PEER_DEV,
        peer_economic_position: 3,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: [0x66; 32],
    }
}

/// Another operation on the same lineage than the one that consumed the
/// source.
fn second_op_id() -> [u8; 32] {
    dsm_economic_operation_id(&G, &DEV, &[0xCE; 32])
}

/// A credit of 40 ERA from [`peer_debit`], built on an empty tree: the tree
/// it leaves, holding the balance and the consumed-source leaf the builder
/// wrote, and the write set itself.
fn credited_tree() -> (EconomicSmt, dsm::economic::write_set::BuiltWriteSet) {
    let mut tree = EconomicSmt::new();
    let built = build_write_set(
        &transfer(DEV, 40, era()),
        &G,
        &DEV,
        &econ_op_id(),
        &EconomicPreState::new(&BTreeMap::new(), P_CREATE),
        &mut tree,
        &peer_debit(),
    )
    .expect("the first credit consumes the source");
    (tree, built)
}

/// The consumed-source record a write set wrote.
fn consumed_by(
    built: &dsm::economic::write_set::BuiltWriteSet,
) -> dsm::economic::state::EconomicConsumedSourceState {
    built
        .mutations
        .iter()
        .find_map(|m| match &m.post_state {
            Some(EconomicLeafState::ConsumedSource(c)) => Some(c.clone()),
            _ => None,
        })
        .expect("a peer-funded credit writes its consumed source")
}

/// `planned`, applied to `tree` in the order given with progressive
/// siblings, as the builder applies its own plan, formed into the witness of
/// `operation`.
fn witness_applying(
    tree: &mut EconomicSmt,
    planned: Vec<Planned>,
    operation: &Operation,
    economic_operation_id: [u8; 32],
    sources: Vec<dsm::economic::credit::CreditSource>,
) -> EconomicTransitionWitness {
    let pre_root = tree.root();
    let mut mutations = Vec::with_capacity(planned.len());
    for (key, pre, post) in planned {
        let siblings = tree.siblings(&key).to_vec();
        match &post {
            Some(state) => tree.insert(key, state.leaf_value().unwrap()),
            None => tree.remove(&key),
        }
        mutations.push(EconomicLeafMutation::new(pre, post, siblings).unwrap());
    }
    EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        economic_operation_id,
        dsm::economic::admission::dsm_operation_digest(&operation.to_bytes()),
        mutations,
        sources,
    )
    .expect("the witness forms")
}

/// MR-DSM-0161: a peer debit funds one credit. Once its consumed-source leaf
/// is in the tree, the builder refuses a second credit from that debit, under
/// another operation, and the tree is left as it was.
///
/// MUTATION CONTROL: removing the builder's `SourceAlreadyConsumed` refusal
/// from the peer-funded credit (`build_write_set`) turns this test red.
#[test]
fn a_consumed_peer_debit_funds_no_second_credit() {
    let (mut tree, first) = credited_tree();
    let consumed = EconomicLeafState::ConsumedSource(consumed_by(&first));
    assert_eq!(
        tree.get(&consumed.leaf_key(&G, &DEV)),
        Some(&consumed.leaf_value().unwrap()),
        "the first credit wrote the consumed-source leaf"
    );
    let held = tree.root();
    let mut balances = BTreeMap::new();
    balances.insert(era(), 40);
    let again = build_write_set(
        &transfer(DEV, 40, era()),
        &G,
        &DEV,
        &second_op_id(),
        &EconomicPreState::new(&balances, P_CREATE + 1),
        &mut tree,
        &peer_debit(),
    );
    assert!(
        matches!(again, Err(WriteSetError::SourceAlreadyConsumed)),
        "a second credit from a consumed debit: {again:?}"
    );
    assert_eq!(tree.root(), held, "a refused build writes nothing");
}

/// MR-DSM-0161: a witness that rewrites a consumed-source leaf, re-pointing
/// it at a second operation so that the same peer debit funds a second
/// credit, is a consistent mutation sequence and is refused by the write-set
/// rule.
///
/// MUTATION CONTROL: letting the verifier take a consumed-source write
/// whatever its pre-state (`verify_operation_write_set`, the
/// `(None, Some(ConsumedSource))` arm) turns this test red.
#[test]
fn a_witness_that_rewrites_a_consumed_source_is_refused() {
    let (mut tree, first) = credited_tree();
    let consumed = consumed_by(&first);
    let rewritten = dsm::economic::state::EconomicConsumedSourceState {
        source_id: consumed.source_id,
        consumer_economic_operation_id: second_op_id(),
    };
    let balance_key = dsm::economic::keys::balance_key(&G, &DEV, &era());
    let mut planned: Vec<Planned> = vec![
        (
            balance_key,
            Some(EconomicLeafState::Balance(
                EconomicBalanceState::new(era(), 40).unwrap(),
            )),
            Some(EconomicLeafState::Balance(
                EconomicBalanceState::new(era(), 80).unwrap(),
            )),
        ),
        (
            EconomicLeafState::ConsumedSource(consumed.clone()).leaf_key(&G, &DEV),
            Some(EconomicLeafState::ConsumedSource(consumed)),
            Some(EconomicLeafState::ConsumedSource(rewritten)),
        ),
    ];
    planned.sort_by_key(|(key, ..)| *key);
    let credit_index = planned
        .iter()
        .position(|(key, ..)| *key == balance_key)
        .unwrap();
    let mut sources = first.credit_sources;
    if let dsm::economic::credit::CreditSource::ValidatedPeerDebit(d) = &mut sources[0] {
        d.credit_mutation_index = u32::try_from(credit_index).unwrap();
    }
    let op = transfer(DEV, 40, era());
    let witness = witness_applying(&mut tree, planned, &op, second_op_id(), sources);
    verify_mutation_sequence(&witness.mutation_sequence(), &G, &DEV)
        .expect("the rewrite is a consistent sequence over the tree");
    let verdict = verify_operation_write_set(&op, &G, &DEV, &witness, P_CREATE + 1);
    assert!(
        matches!(verdict, Err(WriteSetError::WrongWriteSet { .. })),
        "a rewritten consumed source: {verdict:?}"
    );
}

/// MR-DSM-0161: a debit whose witness also deletes the consumed-source leaf,
/// reopening the peer debit for reuse, is a consistent mutation sequence and
/// is refused by the write-set rule.
///
/// MUTATION CONTROL: letting the verifier pass over the removal of a
/// consumed-source leaf (`verify_operation_write_set`) turns this test red.
#[test]
fn a_witness_that_removes_a_consumed_source_is_refused() {
    let (mut tree, first) = credited_tree();
    let consumed = EconomicLeafState::ConsumedSource(consumed_by(&first));
    let mut planned: Vec<Planned> = vec![
        (
            dsm::economic::keys::balance_key(&G, &DEV, &era()),
            Some(EconomicLeafState::Balance(
                EconomicBalanceState::new(era(), 40).unwrap(),
            )),
            None,
        ),
        (consumed.leaf_key(&G, &DEV), Some(consumed), None),
    ];
    planned.sort_by_key(|(key, ..)| *key);
    let op = burn(40, era());
    let witness = witness_applying(&mut tree, planned, &op, second_op_id(), Vec::new());
    verify_mutation_sequence(&witness.mutation_sequence(), &G, &DEV)
        .expect("the removal is a consistent sequence over the tree");
    let verdict = verify_operation_write_set(&op, &G, &DEV, &witness, P_CREATE + 1);
    assert!(
        matches!(verdict, Err(WriteSetError::WrongWriteSet { .. })),
        "a removed consumed source: {verdict:?}"
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
        dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F,
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

/// Fixture token `i`: a native token whose committed policy transfers. Its
/// commit, and the `TokenPolicyV3` bytes that commit names.
fn sofi_token(i: u8) -> ([u8; 32], Vec<u8>) {
    policy_token(i, dsm::economic::token_policy::POLICY_FLAG_TRANSFERABLE)
}

/// Fixture token `i` whose committed policy has the movement flags `flags`.
fn policy_token(i: u8, flags: u8) -> ([u8; 32], Vec<u8>) {
    use dsm::economic::token_policy as tp;
    let mut blob = vec![
        tp::TOKEN_POLICY_VERSION,
        tp::TOKEN_KIND_FUNGIBLE,
        tp::SUPPLY_CLASS_NATIVE,
        flags,
        tp::ReleaseRule::AllAtCreation.code(),
    ];
    blob.extend_from_slice(&G);
    blob.extend_from_slice(&DEV);
    blob.extend_from_slice(&[1, 1]);
    blob.extend_from_slice(&3u16.to_be_bytes());
    blob.extend_from_slice(b"key");
    let ticker = format!("T{i:02}");
    blob.push(ticker.len() as u8);
    blob.extend_from_slice(ticker.as_bytes());
    blob.extend_from_slice(&5u16.to_be_bytes());
    blob.extend_from_slice(b"Token");
    blob.push(0);
    blob.extend_from_slice(&1_000_000u128.to_be_bytes());
    blob.extend_from_slice(&0u16.to_be_bytes());
    blob.extend_from_slice(&0u16.to_be_bytes());
    blob.push(tp::ALLOWLIST_KIND_NONE);
    blob.extend_from_slice(&0u16.to_be_bytes());
    let bytes =
        prost::Message::encode_to_vec(&dsm::types::proto::TokenPolicyV3 { policy_bytes: blob });
    (
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &bytes),
        bytes,
    )
}

/// The fixture tokens a creation may fund.
fn sofi_tokens() -> Vec<([u8; 32], Vec<u8>)> {
    (0..64).map(sofi_token).collect()
}

/// Two fixture tokens, in canonical order.
fn sofi_pair() -> ([u8; 32], [u8; 32]) {
    let (x, y) = (sofi_token(1).0, sofi_token(2).0);
    if x < y {
        (x, y)
    } else {
        (y, x)
    }
}

/// The policies a creation funding `funded` carries (MR-SOFI-0311): each
/// fixture token's, in the funded order. A commit no fixture token has
/// carries none, which only a creation refused before its policies are read
/// funds.
fn sofi_carried(funded: &[[u8; 32]]) -> Vec<Vec<u8>> {
    let tokens = sofi_tokens();
    funded
        .iter()
        .filter_map(|commit| {
            tokens
                .iter()
                .find(|(c, _)| c == commit)
                .map(|(_, bytes)| bytes.clone())
        })
        .collect()
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
        funding_policies: sofi_carried(&[funding_a, funding_b]),
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
    let (a, b) = sofi_pair();
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
    let (a, b) = sofi_pair();
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
    let (a, b) = sofi_pair();
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
    let key = |asset: &[u8; 32]| dsm::economic::keys::balance_key(&G, &DEV, asset);
    let tokens = sofi_tokens();
    let (a, b) = tokens
        .iter()
        .flat_map(|x| tokens.iter().map(move |y| (x.0, y.0)))
        .find(|(a, b)| a < b && key(a) > key(b))
        .expect("an inverting pair among the fixture tokens");
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
    let market = sofi_pair();
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
        dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F,
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
        dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F,
        &[0x01; 64],
    )
    .expect("a setup body");
    assert_ne!(*body.setup_root(), post_root);
}
