// SPDX-License-Identifier: Apache-2.0

//! The pending fence and the validated successor.
//!
//! The fence exists because both naive orderings are wrong: registering first
//! burns a write-once position on something that may never validate, and
//! accepting locally first advances value nothing may yet treat as economic
//! ancestry. These tests are about the window between.

#![allow(clippy::disallowed_methods)]

use dsm::economic::admission::{
    fence_allows, EconomicAdmissionState, FenceBlock, PendingAdmissionKind,
    PendingEconomicAdmission,
};
use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use dsm::economic::classifier::EconomicEffect;
use dsm::economic::credit::{CreditSource, CreditSourceAuthorizedIssuance};
use dsm::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    EconomicValidationError,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::register::RegisteredEconomicRoot;
use dsm::economic::provenance::{ProvenanceError, ProvenanceResolver, ValidatedPeerTransition};
use dsm::economic::state::{EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const ERA: [u8; 32] = [0xAA; 32];

/// Knows no peer transitions. Correct for every fixture here: none of them
/// funds a credit from another identity, so a resolver that answered would be
/// answering a question nobody asked.
struct NoPeers;
impl ProvenanceResolver for NoPeers {
    fn validated_peer_transition(
        &self,
        _g: &[u8; 32],
        _d: &[u8; 32],
        _p: u64,
    ) -> Option<ValidatedPeerTransition> {
        None
    }
}
const SOFI: [u8; 32] = [0xBB; 32];

fn pending(kind: PendingAdmissionKind, state: EconomicAdmissionState) -> PendingEconomicAdmission {
    PendingEconomicAdmission {
        kind,
        state,
        economic_position: 4,
        pre_economic_root: [1; 32],
        post_economic_root: [2; 32],
        operation_digest: [3; 32],
        accepted_substrate_addr: [4; 32],
        admission_manifest_addr: [5; 32],
    }
}

fn bearer_transfer(policy_commit: [u8; 32]) -> Operation {
    Operation::Transfer {
        to_device_id: vec![1; 32],
        amount: Balance::from_state(5, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit,
        mode: TransactionMode::Bilateral,
        nonce: vec![0; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: Vec::new(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    }
}

// ── The fence predicate ────────────────────────────────────────────────────

#[test]
fn the_fence_blocks_economic_writes_and_allows_ordinary_activity() {
    let p = pending(
        PendingAdmissionKind::DsmBacked,
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    let op = Operation::Noop;

    // A publication delay must not look like a device fault: relationship
    // activity that touches no economic leaf continues throughout.
    assert!(fence_allows(&p, EconomicEffect::None, &op).is_ok());

    assert!(matches!(
        fence_allows(&p, EconomicEffect::ClosedWriteSet, &op),
        Err(FenceBlock::EconomicWriteWhilePending { position: 4 })
    ));
    assert!(matches!(
        fence_allows(&p, EconomicEffect::UnsupportedValueTransition, &op),
        Err(FenceBlock::UnsupportedValueWhilePending { position: 4 })
    ));
}

#[test]
fn the_fence_engages_only_while_actually_pending() {
    let op = Operation::Noop;
    // Before local acceptance nothing durable changed, and after admission the
    // protection has served its purpose. Fencing in either state would stall
    // the device for no benefit.
    for state in [
        EconomicAdmissionState::Prepared,
        EconomicAdmissionState::Admitted,
    ] {
        let p = pending(PendingAdmissionKind::DsmBacked, state);
        assert!(
            fence_allows(&p, EconomicEffect::ClosedWriteSet, &op).is_ok(),
            "{state:?} must not fence"
        );
    }
    for state in [
        EconomicAdmissionState::LocalAcceptedPendingEcon,
        EconomicAdmissionState::EvidencePublished,
        EconomicAdmissionState::Registered,
    ] {
        let p = pending(PendingAdmissionKind::DsmBacked, state);
        assert!(
            fence_allows(&p, EconomicEffect::ClosedWriteSet, &op).is_err(),
            "{state:?} must fence"
        );
    }
}

#[test]
fn offline_bearer_activity_is_judged_against_the_pending_substrate() {
    // NOT blanket-allowed. Which answer is right depends on what is pending.
    let dsm_backed = pending(
        PendingAdmissionKind::DsmBacked,
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    // A DSM-backed admission does not touch the offline regime at all, so
    // unrelated bearer activity neither consumes nor mutates R_econ.
    assert!(fence_allows(
        &dsm_backed,
        EconomicEffect::OfflineAccountOnly,
        &bearer_transfer(ERA)
    )
    .is_ok());

    let load = pending(
        PendingAdmissionKind::OfflineLoad {
            asset_policy_commit: ERA,
        },
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    // The very allocation the boundary is moving is not yet admitted.
    assert!(matches!(
        fence_allows(
            &load,
            EconomicEffect::OfflineAccountOnly,
            &bearer_transfer(ERA)
        ),
        Err(FenceBlock::BearerUseOfPendingAllocation { .. })
    ));
    // A different asset's allocation is untouched by this boundary.
    assert!(fence_allows(
        &load,
        EconomicEffect::OfflineAccountOnly,
        &bearer_transfer(SOFI)
    )
    .is_ok());

    let unload = pending(
        PendingAdmissionKind::OfflineUnload {
            asset_policy_commit: ERA,
        },
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    assert!(fence_allows(
        &unload,
        EconomicEffect::OfflineAccountOnly,
        &bearer_transfer(ERA)
    )
    .is_err());
}

#[test]
fn an_unidentifiable_bearer_operation_fails_closed_during_a_boundary_fence() {
    // Classified OfflineAccountOnly but naming no asset: it cannot be SHOWN to
    // be unrelated to the pending allocation, and "cannot be shown unrelated"
    // is not "is unrelated".
    let load = pending(
        PendingAdmissionKind::OfflineLoad {
            asset_policy_commit: ERA,
        },
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    assert!(matches!(
        fence_allows(&load, EconomicEffect::OfflineAccountOnly, &Operation::Noop),
        Err(FenceBlock::BearerUseOfPendingAllocation { .. })
    ));
}

// ── The validated successor ────────────────────────────────────────────────

fn bal(pc: [u8; 32], amount: u64) -> EconomicLeafState {
    EconomicLeafState::Balance(EconomicBalanceState::new(pc, amount).expect("nonzero"))
}

/// A transition from the CANONICAL EMPTY ROOT: one credit of 100 ERA, funded
/// by an authorized issuance.
///
/// Starting from empty matters. A fixture that opened with a funded tree would
/// fail the pre-root check first and mask every other clause under test — the
/// first version of this file did exactly that, and four tests passed for the
/// wrong reason.
const ISSUANCE_ADDR: [u8; 32] = [0xC7; 32];

/// A transition from the empty root that moves NO value: it inserts a
/// consumed-source record.
///
/// This is the only kind of first transition that can validate today, and the
/// reason is worth stating: position 0 is the empty root, so every mutation
/// from it is an insertion; an insertion of a balance or reserve IS a positive
/// credit and needs a funding source; and the only source that can CREATE
/// units is AuthorizedIssuance, whose predicate does not exist. A record
/// insertion is not a credit, so it needs no source.
fn build_valueless_transition(operation_digest: [u8; 32]) -> (EconomicTransitionWitness, [u8; 32]) {
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let record = EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
        source_id: [0x5C; 32],
        consumer_economic_operation_id: [0x0E; 32],
    });
    let key = record.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(record.clone()), siblings).expect("well-formed");
    assert!(!mutation.is_positive_credit(), "a record is not a credit");
    tree.insert(key, record.leaf_value().expect("encodable"));
    let post_root = tree.root();
    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        [0x0E; 32],
        operation_digest,
        vec![mutation],
        Vec::new(),
    )
    .expect("valid witness");
    (witness, post_root)
}

fn build_transition(operation_digest: [u8; 32]) -> (EconomicTransitionWitness, [u8; 32]) {
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();

    let credit = bal(ERA, 100);
    let key = credit.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(credit.clone()), siblings).expect("well-formed");
    assert!(mutation.is_positive_credit());
    tree.insert(key, credit.leaf_value().expect("encodable"));
    let post_root = tree.root();

    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        [0x0E; 32],
        operation_digest,
        vec![mutation],
        vec![CreditSource::AuthorizedIssuance(
            CreditSourceAuthorizedIssuance {
                credit_mutation_index: 0,
                issuance_authorization_addr: ISSUANCE_ADDR,
            },
        )],
    )
    .expect("valid witness");
    (witness, post_root)
}

fn manifest_for(witness: &EconomicTransitionWitness) -> EconomicAdmissionManifest {
    EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: [0xA4; 32],
        },
        witness.derived_provenance_index(),
    )
    .expect("valid manifest")
}

fn registered_for(
    manifest: &EconomicAdmissionManifest,
    position: u64,
    post_root: [u8; 32],
) -> RegisteredEconomicRoot {
    RegisteredEconomicRoot {
        trader_genesis: G,
        trader_devid: DEV,
        economic_position: position,
        post_economic_root: post_root,
        admission_manifest_addr: manifest.addr().expect("addressable"),
        storage_set_id: [0xB1; 32],
    }
}

#[test]
fn a_valueless_transition_advances_the_validated_lineage() {
    let digest = [0x77; 32];
    let (witness, post_root) = build_valueless_transition(digest);
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 1, post_root);
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(digest, [0xA4; 32]);

    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    let (one, funded) = advance_validated(
        &zero,
        &registered,
        &manifest,
        &witness,
        &accepted,
        &NoPeers,
        &G,
        &DEV,
    )
    .expect("a valueless transition validates");
    assert_eq!(one.economic_position(), 1);
    assert_eq!(
        one.economic_root(),
        post_root,
        "the validated root is RECOMPUTED from the mutations, not copied from the registration"
    );
    assert!(funded.is_empty(), "no credits, so nothing to fund");
}

/// THE BOOTSTRAP FINDING, as a test.
///
/// No VALUE can enter a validated lineage today. Position 0 is the empty root,
/// so a first transition's only way to hold value is a credit; every credit
/// needs a funding source; and the only source that can CREATE units is
/// `AuthorizedIssuance`, whose predicate does not exist — the same absence
/// that makes the accepting layer refuse builtin ERA/dBTC issuance.
///
/// This is the system correctly refusing to create value from nothing, not a
/// defect. It does mean the economic root is unusable for value until an
/// authenticated issuance predicate is defined, and that should be visible
/// here rather than discovered later.
#[test]
fn value_cannot_enter_a_lineage_without_an_issuance_predicate() {
    let digest = [0x77; 32];
    let (witness, post_root) = build_transition(digest);
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 1, post_root);
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(digest, [0xA4; 32]);

    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    match advance_validated(
        &zero,
        &registered,
        &manifest,
        &witness,
        &accepted,
        &NoPeers,
        &G,
        &DEV,
    ) {
        Err(EconomicValidationError::Provenance(ProvenanceError::IssuancePredicateUndefined)) => {}
        other => panic!("a credit from undefined issuance must be refused, got {other:?}"),
    }
}

#[test]
fn a_successor_paired_with_a_different_operation_is_refused() {
    // THE clause that is easiest to omit and most costly to omit. Both objects
    // are individually valid; together they describe two different operations.
    let (witness, post_root) = build_transition([0x77; 32]);
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 1, post_root);
    let wrong = AcceptedSubstrate::from_verified_dsm_successor([0x88; 32], [0xA4; 32]);

    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    match advance_validated(
        &zero,
        &registered,
        &manifest,
        &witness,
        &wrong,
        &NoPeers,
        &G,
        &DEV,
    ) {
        Err(EconomicValidationError::OperationDigestMismatch { substrate, witness }) => {
            assert_eq!(substrate, [0x88; 32]);
            assert_eq!(witness, [0x77; 32]);
        }
        other => panic!("a mismatched operation digest must be refused, got {other:?}"),
    }
}

#[test]
fn a_registration_at_the_wrong_position_is_refused() {
    let digest = [0x77; 32];
    let (witness, post_root) = build_transition(digest);
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 5, post_root); // not 0 + 1
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(digest, [0xA4; 32]);
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");

    assert!(matches!(
        advance_validated(
            &zero,
            &registered,
            &manifest,
            &witness,
            &accepted,
            &NoPeers,
            &G,
            &DEV,
        ),
        Err(EconomicValidationError::PositionIsNotSuccessor {
            previous: 0,
            registered: 5
        })
    ));
}

#[test]
fn a_registration_naming_another_manifest_is_refused() {
    let digest = [0x77; 32];
    let (witness, post_root) = build_transition(digest);
    let manifest = manifest_for(&witness);
    let mut registered = registered_for(&manifest, 1, post_root);
    registered.admission_manifest_addr = [0xFF; 32];
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(digest, [0xA4; 32]);
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");

    assert!(matches!(
        advance_validated(
            &zero,
            &registered,
            &manifest,
            &witness,
            &accepted,
            &NoPeers,
            &G,
            &DEV,
        ),
        Err(EconomicValidationError::ManifestAddrMismatch { .. })
    ));
}

#[test]
fn a_registered_root_disagreeing_with_the_witness_is_refused() {
    let digest = [0x77; 32];
    let (witness, _post) = build_transition(digest);
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 1, [0xEE; 32]); // invented root
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(digest, [0xA4; 32]);
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");

    assert!(matches!(
        advance_validated(
            &zero,
            &registered,
            &manifest,
            &witness,
            &accepted,
            &NoPeers,
            &G,
            &DEV,
        ),
        Err(EconomicValidationError::RegisteredRootDiffersFromWitness { .. })
    ));
}
