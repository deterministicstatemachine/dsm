// SPDX-License-Identifier: Apache-2.0

//! The 0x0027 (`ValidatedDlvSettlementPayment`) provenance arm, end to end:
//! the owner's `DlvOwnerApplyV2` write set built by the REAL builder over a
//! real reserve pre-state, funded by a trader's settlement-receipt leaf
//! proven into the trader's validated economic root.
//!
//! Every MC-APPLY control mutates ONE input of the honest fixture and
//! requires the named refusal.

#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;

use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    verify_transition_provenance, FaucetTicketWin, PeerLineageFailure, ProvenanceContext,
    ProvenanceError, ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::state::{
    EconomicBalanceState, EconomicLeafState, EconomicSettlementReceiptState,
    EconomicVaultReserveState,
};
use dsm::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{
    build_write_set, verify_operation_write_set, CreditSourceFacts, EconomicPreState, WriteSetError,
};
use dsm::types::operations::{Operation, TransactionMode};
use prost::Message;

const VAULT: [u8; 32] = [0x61; 32];
const G_OWNER: [u8; 32] = [0x81; 32];
const DEV_OWNER: [u8; 32] = [0x82; 32];
const G_TRADER: [u8; 32] = [0x83; 32];
const DEV_TRADER: [u8; 32] = [0x84; 32];
const PARENT: u64 = 4;
const NEW: u64 = 5;
const TRADER_POSITION: u64 = 6;
const INPUT: u64 = 1_000;
const OUTPUT: u64 = 970;
const X: [u8; 32] = [0x91; 32];

fn pc_a() -> [u8; 32] {
    [0x0A; 32]
}
fn pc_b() -> [u8; 32] {
    [0x0B; 32]
}

fn receipt() -> EconomicSettlementReceiptState {
    EconomicSettlementReceiptState::new(VAULT, X, PARENT, NEW, pc_a(), INPUT, pc_b(), OUTPUT)
        .expect("receipt")
}

struct Fixture {
    trader_root: [u8; 32],
    evidence_bytes: Vec<u8>,
    evidence_addr: [u8; 32],
    apply: Operation,
    witness: EconomicTransitionWitness,
}

fn fixture() -> Fixture {
    // The TRADER's validated root: contains the receipt leaf.
    let mut trader_tree = EconomicSmt::new();
    let receipt_state = EconomicLeafState::SettlementReceipt(receipt());
    let key = receipt_state.leaf_key(&G_TRADER, &DEV_TRADER);
    trader_tree.insert(key, receipt_state.leaf_value().expect("value"));
    let trader_root = trader_tree.root();
    let mut siblings = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
    siblings.copy_from_slice(&trader_tree.siblings(&key));

    let evidence = dsm::types::proto::SettlementPaymentEvidenceV1 {
        receipt_state: receipt_state.encode().expect("encode"),
        receipt_siblings: siblings.iter().map(|s| s.to_vec()).collect(),
    };
    let evidence_bytes = evidence.encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_SETTLEMENT_PAYMENT_EVIDENCE,
        &evidence_bytes,
    );

    let apply = Operation::DlvOwnerApplyV2 {
        vault_id: VAULT.to_vec(),
        settlement_receipt_id: receipt().receipt_id,
        pending_pointer_x: X,
        parent_sequence: PARENT,
        new_sequence: NEW,
        parent_binding: [0x23; 32],
        input_policy_commit: pc_a(),
        output_policy_commit: pc_b(),
        input_amount: INPUT,
        output_amount: OUTPUT,
        fee_bps: 30,
        signature: vec![0x77; 48],
        mode: TransactionMode::Unilateral,
    };

    // The OWNER's write set over its real reserve pre-state.
    let (mut tree, balances, reserves) = owner_pre_state(100_000, 50_000);
    let pre_root = tree.root();
    let built = build_write_set(
        &apply,
        &G_OWNER,
        &DEV_OWNER,
        &[0xEE; 32],
        &EconomicPreState {
            balances: &balances,
            vault_reserves: &reserves,
        },
        &mut tree,
        &facts(evidence_addr),
    )
    .expect("the apply write set builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&apply.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    verify_operation_write_set(&apply, &G_OWNER, &DEV_OWNER, &witness)
        .expect("exact effect verifies");

    Fixture {
        trader_root,
        evidence_bytes,
        evidence_addr,
        apply,
        witness,
    }
}

fn facts(evidence_addr: [u8; 32]) -> CreditSourceFacts {
    CreditSourceFacts::DlvSettlementPayment {
        trader_genesis: G_TRADER,
        trader_devid: DEV_TRADER,
        trader_economic_position: TRADER_POSITION,
        payment_evidence_addr: evidence_addr,
    }
}

/// The owner's pre-state: both reserve legs at PARENT.
#[allow(clippy::type_complexity)]
fn owner_pre_state(
    ra: u64,
    rb: u64,
) -> (
    EconomicSmt,
    BTreeMap<[u8; 32], u64>,
    BTreeMap<([u8; 32], [u8; 32]), EconomicVaultReserveState>,
) {
    let mut tree = EconomicSmt::new();
    let mut reserves = BTreeMap::new();
    for (pc, amount) in [(pc_a(), ra), (pc_b(), rb)] {
        let r = EconomicVaultReserveState {
            vault_id: VAULT,
            policy_commit: pc,
            amount,
            vault_sequence: PARENT,
        };
        let state = EconomicLeafState::VaultReserve(r.clone());
        tree.insert(
            state.leaf_key(&G_OWNER, &DEV_OWNER),
            state.leaf_value().expect("value"),
        );
        reserves.insert((VAULT, pc), r);
    }
    (tree, BTreeMap::new(), reserves)
}

struct ApplyResolver {
    trader_root: [u8; 32],
    evidence_addr: [u8; 32],
    evidence_bytes: Vec<u8>,
}

impl ProvenanceResolver for ApplyResolver {
    fn root_register_candidate_set(
        &self,
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, dsm::economic::provenance::PeerLineageFailure> {
        Ok(crate::beta_candidate_set())
    }

    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        if *peer_genesis == G_TRADER
            && *peer_devid == DEV_TRADER
            && peer_economic_position == TRADER_POSITION
        {
            // Debit-shaped placeholder witness (structure only).
            let mut t = EconomicSmt::new();
            let pre = EconomicLeafState::Balance(EconomicBalanceState::new([0x01; 32], 2).unwrap());
            let post =
                EconomicLeafState::Balance(EconomicBalanceState::new([0x01; 32], 1).unwrap());
            let key = pre.leaf_key(&G_TRADER, &DEV_TRADER);
            t.insert(key, pre.leaf_value().unwrap());
            let pre_root = t.root();
            let siblings = t.siblings(&key).to_vec();
            let m = EconomicLeafMutation::new(Some(pre), Some(post.clone()), siblings).unwrap();
            t.insert(key, post.leaf_value().unwrap());
            let witness = EconomicTransitionWitness::new(
                pre_root,
                t.root(),
                [0x0E; 32],
                [0x0F; 32],
                vec![m],
                Vec::new(),
            )
            .unwrap();
            Ok(ValidatedPeerTransition {
                peer_genesis: G_TRADER,
                peer_devid: DEV_TRADER,
                validated_root:
                    dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(
                        TRADER_POSITION,
                        self.trader_root,
                    ),
                witness,
                proven_ak: vec![0xAA; 64],
                c_dsm_plus: [0xC5; 32],
                verified_operation: Operation::Noop,
            })
        } else {
            Err(PeerLineageFailure::Incomplete(
                "no such validated lineage".into(),
            ))
        }
    }

    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
        None
    }

    fn settlement_slot_observation(
        &self,
        _vault_id: &[u8; 32],
        _parent_sequence: u64,
        _storage_set: &dsm::ccb::StorageSetMembers,
        _quorum: u32,
    ) -> dsm::economic::cell_observation::CellObservation {
        // This fixture roots no settlement slots: it cannot observe the
        // cell, which is not the same as observing it empty.
        dsm::economic::cell_observation::CellObservation::Unavailable {
            attributed: 0,
            required: 2,
        }
    }

    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        if *addr == self.evidence_addr {
            Ok(self.evidence_bytes.clone())
        } else {
            Err(PeerLineageFailure::Incomplete("unknown address".into()))
        }
    }

    fn anchored_policy_bytes(
        &self,
        _policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "this fixture roots no token anchors".into(),
        ))
    }
}

fn resolver_for(fx: &Fixture) -> ApplyResolver {
    ApplyResolver {
        trader_root: fx.trader_root,
        evidence_addr: fx.evidence_addr,
        evidence_bytes: fx.evidence_bytes.clone(),
    }
}

fn ctx_for<'a>(op: &'a Operation) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G_OWNER,
        device_id: &DEV_OWNER,
        economic_position: 7,
        network_id: b"dsm-testnet",
        proven_ak: &[0xAB; 64],
        canonical_storage_set_id: [0x6B; 32],
        substrate_b_pair: None,
        verified_operation: Some(op),
    }
}

fn expect_payment_refusal(fx: &Fixture, resolver: &ApplyResolver, op: &Operation, needle: &str) {
    let ctx = ctx_for(op);
    match verify_transition_provenance(&fx.witness, resolver, &ctx) {
        Err(ProvenanceError::DlvSettlementPaymentInvalid(m)) => {
            assert!(m.contains(needle), "expected {needle:?}, got: {m}")
        }
        other => panic!("expected a settlement-payment refusal ({needle}), got {other:?}"),
    }
}

// ── The honest fixture funds ───────────────────────────────────────────────

#[test]
fn a_real_owner_apply_funds_from_the_traders_admitted_payment() {
    let fx = fixture();
    let funded = verify_transition_provenance(&fx.witness, &resolver_for(&fx), &ctx_for(&fx.apply))
        .expect("the honest apply is funded");
    assert_eq!(funded.len(), 1);
    assert_eq!(funded[0].policy_commit, pc_a());
    assert_eq!(funded[0].amount, INPUT);
}

// ── MC-APPLY controls ──────────────────────────────────────────────────────

#[test]
fn a_second_apply_of_the_same_receipt_is_refused_by_the_reserve_cas() {
    // MC-APPLY-1: after the first apply the reserve pre-state at PARENT no
    // longer exists — the SAME apply against the post-state pre-map fails
    // its own Merkle precondition at build.
    let fx = fixture();
    let (mut tree, balances, mut reserves) = owner_pre_state(100_000, 50_000);
    // Advance both legs to NEW, as the first apply left them.
    for (pc, amount) in [(pc_a(), 100_000 + INPUT), (pc_b(), 50_000 - OUTPUT)] {
        let r = EconomicVaultReserveState {
            vault_id: VAULT,
            policy_commit: pc,
            amount,
            vault_sequence: NEW,
        };
        let state = EconomicLeafState::VaultReserve(r.clone());
        tree.insert(
            state.leaf_key(&G_OWNER, &DEV_OWNER),
            state.leaf_value().expect("value"),
        );
        reserves.insert((VAULT, pc), r);
    }
    let err = build_write_set(
        &fx.apply,
        &G_OWNER,
        &DEV_OWNER,
        &[0xEF; 32],
        &EconomicPreState {
            balances: &balances,
            vault_reserves: &reserves,
        },
        &mut tree,
        &facts(fx.evidence_addr),
    )
    .expect_err("a consumed parent generation cannot be folded again");
    assert!(
        err.to_string()
            .contains("not at the consumed parent generation"),
        "the refusal is the generation CAS, got: {err}"
    );
}

#[test]
fn a_trader_root_lacking_the_receipt_is_refused() {
    // MC-APPLY-2: the receipt must prove into the trader's VALIDATED root.
    let fx = fixture();
    let mut r = resolver_for(&fx);
    r.trader_root = [0xCD; 32];
    expect_payment_refusal(
        &fx,
        &r,
        &fx.apply,
        "does not prove into the trader's validated root",
    );
}

#[test]
fn the_apply_operation_is_cross_checked_against_the_receipt_field_by_field() {
    // MC-APPLY-3 (amounts) and MC-APPLY-6 (x): the receipt states the exact
    // settlement; a one-bit-off apply is refused.
    let fx = fixture();
    let r = resolver_for(&fx);
    let mutate = |f: &dyn Fn(&mut Operation)| {
        let mut op = fx.apply.clone();
        f(&mut op);
        op
    };
    for (op, needle) in [
        (
            mutate(&|op| {
                if let Operation::DlvOwnerApplyV2 { input_amount, .. } = op {
                    *input_amount += 1;
                }
            }),
            "does not state this apply's exact settlement",
        ),
        (
            mutate(&|op| {
                if let Operation::DlvOwnerApplyV2 {
                    pending_pointer_x, ..
                } = op
                {
                    pending_pointer_x[0] ^= 0xFF;
                }
            }),
            "does not state this apply's exact settlement",
        ),
        (
            mutate(&|op| {
                if let Operation::DlvOwnerApplyV2 {
                    settlement_receipt_id,
                    ..
                } = op
                {
                    settlement_receipt_id[0] ^= 0xFF;
                }
            }),
            "descriptor coordinates do not equal the operation's",
        ),
    ] {
        expect_payment_refusal(&fx, &r, &op, needle);
    }
}

#[test]
fn a_witness_moving_balances_is_not_an_apply() {
    // MC-APPLY-4: an apply moves no balances — a balance-touching witness
    // cannot claim the apply's write set.
    let fx = fixture();
    let mut tree = EconomicSmt::new();
    let funded = EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 100).unwrap());
    let key = funded.leaf_key(&G_OWNER, &DEV_OWNER);
    tree.insert(key, funded.leaf_value().unwrap());
    let pre_root = tree.root();
    let post = EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 60).unwrap());
    let siblings = tree.siblings(&key).to_vec();
    let m = EconomicLeafMutation::new(Some(funded), Some(post.clone()), siblings).unwrap();
    tree.insert(key, post.leaf_value().unwrap());
    let witness = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&fx.apply.to_bytes()),
        vec![m],
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        verify_operation_write_set(&fx.apply, &G_OWNER, &DEV_OWNER, &witness),
        Err(WriteSetError::UnexpectedLeafClass) | Err(WriteSetError::WrongWriteSet { .. })
    ));
}

#[test]
fn a_non_unit_generation_step_is_refused_at_derivation() {
    // MC-APPLY-5.
    let fx = fixture();
    let mut op = fx.apply.clone();
    if let Operation::DlvOwnerApplyV2 { new_sequence, .. } = &mut op {
        *new_sequence = PARENT + 2;
    }
    assert!(matches!(
        verify_operation_write_set(&op, &G_OWNER, &DEV_OWNER, &fx.witness),
        Err(WriteSetError::MalformedVaultOperation { .. })
    ));
}

#[test]
fn tampered_evidence_bytes_are_refused_by_address() {
    let fx = fixture();
    let mut r = resolver_for(&fx);
    let mut tampered = fx.evidence_bytes.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    r.evidence_bytes = tampered;
    expect_payment_refusal(
        &fx,
        &r,
        &fx.apply,
        "do not hash to the descriptor's address",
    );
}

#[test]
fn an_unresolvable_trader_lineage_fails_closed() {
    let fx = fixture();
    let ctx = ctx_for(&fx.apply);
    struct Nothing;
    impl ProvenanceResolver for Nothing {
        fn root_register_candidate_set(
            &self,
            _network_id: &[u8],
        ) -> Result<dsm::ccb::StorageSetMembers, dsm::economic::provenance::PeerLineageFailure>
        {
            Ok(crate::beta_candidate_set())
        }

        fn validated_peer_transition(
            &self,
            _g: &[u8; 32],
            _d: &[u8; 32],
            _p: u64,
        ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete("outage".into()))
        }
        fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
            None
        }
        fn settlement_slot_observation(
            &self,
            _v: &[u8; 32],
            _p: u64,
            _storage_set: &dsm::ccb::StorageSetMembers,
            _quorum: u32,
        ) -> dsm::economic::cell_observation::CellObservation {
            // This fixture roots no settlement slots: it cannot observe the
            // cell, which is not the same as observing it empty.
            dsm::economic::cell_observation::CellObservation::Unavailable {
                attributed: 0,
                required: 2,
            }
        }
        fn immutable_evidence(
            &self,
            _n: dsm::crypto::domain::TaggedHashDomain<'static>,
            _a: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete("outage".into()))
        }

        fn anchored_policy_bytes(
            &self,
            _policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(
                "this fixture roots no token anchors".into(),
            ))
        }
    }
    match verify_transition_provenance(&fx.witness, &Nothing, &ctx) {
        Err(ProvenanceError::OwnerLineage(PeerLineageFailure::Incomplete(_))) => {}
        other => panic!("an outage must fail closed as Incomplete, got {other:?}"),
    }
}

/// The beta fleet as a catalog resolves it: the network's canonical member
/// ids paired with the register incarnations those members are serving.
///
/// A set id is a function of `(member_id, register_incarnation_id)` pairs, so
/// a fixture cannot state one as a constant — it derives it the same way
/// production does, from candidate entries the profile then checks.
fn beta_candidate_set() -> dsm::ccb::StorageSetMembers {
    dsm::ccb::StorageSetMembers::new(&[
        (&b"dsm-node-1"[..], [0xC1; 32]),
        (&b"dsm-node-2"[..], [0xC2; 32]),
        (&b"dsm-node-3"[..], [0xC3; 32]),
    ])
    .expect("beta candidate set")
}
