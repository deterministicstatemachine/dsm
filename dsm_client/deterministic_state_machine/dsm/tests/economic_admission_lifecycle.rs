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
use dsm::economic::provenance::{
    FaucetTicketWin, PeerLineageFailure, ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const ERA: [u8; 32] = [0xAA; 32];

const SOFI: [u8; 32] = [0xBB; 32];
const ISSUANCE_ADDR: [u8; 32] = [0xC1; 32];

fn pending(kind: PendingAdmissionKind, state: EconomicAdmissionState) -> PendingEconomicAdmission {
    let prepared = PendingEconomicAdmission::prepared(kind, 4, [1; 32], [3; 32]);
    if state == EconomicAdmissionState::Prepared {
        return prepared;
    }
    prepared
        .into_locally_accepted(dsm::economic::admission::AcceptedAdmissionCoords {
            post_economic_root: [2; 32],
            accepted_substrate_addr: [4; 32],
            admission_manifest_addr: [5; 32],
            embedded_parent: [0x5E; 32],
            c_dsm_plus: [6; 32],
        })
        .expect("prepared -> accepted")
        .advanced_to(state)
        .expect("forward")
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

// ── The base valid transition: a faucet claim, built the honest way ────────
//
// Under the operation↔write-set conjunct, a transition validates only when
// its mutations are the EXACT semantic effect of the accepted operation. The
// only operation that can enter value at position 1 (the empty root) is a
// faucet claim, so it is the base fixture for every structural clause here.

const C_DSM_PLUS: [u8; 32] = [0xCD; 32];
const EMBEDDED_PARENT: [u8; 32] = [0xCE; 32];
const SUBSTRATE_ADDR: [u8; 32] = [0xA4; 32];

fn canonical_set_id() -> [u8; 32] {
    dsm::economic::register::resolve_root_register_profile(b"dsm-testnet")
        .expect("beta profile")
        .storage_set_id
}

struct FaucetFixture {
    op: Operation,
    witness: EconomicTransitionWitness,
    envelope: Vec<u8>,
    pk: Vec<u8>,
    post_root: [u8; 32],
}

fn faucet_fixture(position: u64) -> FaucetFixture {
    use dsm::economic::credit::CreditSourceValidatedFaucetDistribution;
    use dsm::economic::faucet::{
        dsm_economic_operation_id, dsm_operation_digest, era_faucet_id, faucet_claim_evidence_addr,
        sign_faucet_ticket_claim, FaucetTicketClaimBody, ERA_FAUCET_PAYOUT,
    };
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
    let faucet_id = era_faucet_id(b"dsm-testnet");
    let ticket_index = 42u64;
    let op = Operation::FaucetClaim {
        faucet_id,
        ticket_index,
    };
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let envelope = sign_faucet_ticket_claim(
        &FaucetTicketClaimBody {
            faucet_id,
            ticket_index,
            claimant_genesis: G,
            claimant_devid: DEV,
            claimant_economic_position: position,
            recipient_operation_digest: op_digest,
            claimant_public_key: pk.clone(),
            storage_set_id: canonical_set_id(),
        },
        &sk,
    )
    .expect("signable");

    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = bal(era, ERA_FAUCET_PAYOUT);
    let key = credit.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(credit.clone()), siblings).expect("well-formed");
    tree.insert(key, credit.leaf_value().expect("encodable"));
    let post_root = tree.root();

    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
        op_digest,
        vec![mutation],
        vec![CreditSource::ValidatedFaucetDistribution(
            CreditSourceValidatedFaucetDistribution {
                credit_mutation_index: 0,
                faucet_id,
                ticket_index,
                faucet_claim_evidence_addr: faucet_claim_evidence_addr(&envelope),
            },
        )],
    )
    .expect("valid witness");
    FaucetFixture {
        op,
        witness,
        envelope,
        pk,
        post_root,
    }
}

/// A resolver holding exactly one quorum-winning envelope.
struct OneTicket {
    envelope: Vec<u8>,
}
impl ProvenanceResolver for OneTicket {
    fn validated_peer_transition(
        &self,
        _g: &[u8; 32],
        _d: &[u8; 32],
        _p: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "no peer store in this fixture".into(),
        ))
    }
    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
        Some(FaucetTicketWin {
            envelope_bytes: self.envelope.clone(),
        })
    }

    fn winning_settlement_slot_claim(
        &self,
        _vault_id: &[u8; 32],
        _parent_sequence: u64,
        _storage_set: &dsm::ccb::StorageSetMembers,
        _quorum: u32,
    ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
        None
    }

    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        _addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "no evidence store in this fixture".into(),
        ))
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

fn accepted_for(op: &Operation) -> AcceptedSubstrate {
    AcceptedSubstrate::from_verified_dsm_successor(
        op.clone(),
        C_DSM_PLUS,
        EMBEDDED_PARENT,
        SUBSTRATE_ADDR,
    )
}

fn manifest_for(witness: &EconomicTransitionWitness) -> EconomicAdmissionManifest {
    EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: SUBSTRATE_ADDR,
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
        storage_set_id: canonical_set_id(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    fx: &FaucetFixture,
    registered: &RegisteredEconomicRoot,
    manifest: &EconomicAdmissionManifest,
    witness: &EconomicTransitionWitness,
    accepted: &AcceptedSubstrate,
) -> Result<
    (
        dsm::economic::lineage::ValidatedEconomicRoot,
        Vec<dsm::economic::provenance::FundedCredit>,
    ),
    EconomicValidationError,
> {
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    advance_validated(
        &zero,
        registered,
        manifest,
        witness,
        accepted,
        &OneTicket {
            envelope: fx.envelope.clone(),
        },
        &G,
        &DEV,
        b"dsm-testnet",
        &fx.pk,
    )
}

#[test]
fn a_faucet_claim_transition_advances_the_validated_lineage() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, fx.post_root);
    let accepted = accepted_for(&fx.op);
    let (one, funded) =
        run(&fx, &registered, &manifest, &fx.witness, &accepted).expect("validates");
    assert_eq!(one.economic_position(), 1);
    assert_eq!(funded.len(), 1);
}

#[test]
fn a_witness_that_is_not_the_operations_exact_effect_is_refused() {
    // THE write-set forgery control. The operation is genuinely accepted and
    // the witness is internally consistent AND fully funded-or-fundless — a
    // bare record insertion has no credit to fund, so every pre-existing
    // clause passes. Only the operation↔write-set conjunct can refuse it:
    // remove `verify_operation_write_set` from `advance_validated` and this
    // goes green while validating a write set the operation never performed.
    let fx = faucet_fixture(1);
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
    tree.insert(key, record.leaf_value().expect("encodable"));
    let forged = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
        fx.witness.operation_digest,
        vec![mutation],
        Vec::new(),
    )
    .expect("internally valid");
    let manifest = manifest_for(&forged);
    let registered = registered_for(&manifest, 1, tree.root());
    let accepted = accepted_for(&fx.op);
    match run(&fx, &registered, &manifest, &forged, &accepted) {
        Err(EconomicValidationError::WriteSet(_)) => {}
        other => panic!("a forged write set must be refused by the write-set conjunct: {other:?}"),
    }
}

/// THE BOOTSTRAP FINDING, RESOLVED — and what replaced it.
///
/// This test used to pin `IssuancePredicateUndefined`: with no authenticated
/// issuance predicate, a positive credit could never enter a validated
/// lineage at all, and the wallet was structurally unfundable except through
/// the ERA faucet's bootstrap tickets.
///
/// Class `0x0029` answers that, so the blanket refusal is gone. What replaced
/// it is narrower and is what this test now pins: the predicate must be
/// SATISFIED, not merely defined. A mint whose witness carries no issuance
/// source — as here — is refused because the credit it claims has no source
/// of the kind the operation requires. Existence of a predicate never
/// substitutes for evidence under it.
#[test]
fn issuance_requires_its_predicate_to_be_satisfied_not_merely_defined() {
    let fx = faucet_fixture(1);
    let (witness, post_root) = build_transition(fx.witness.operation_digest);
    let mint = Operation::Mint {
        amount: Balance::from_state(100, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: ERA,
        message: String::new(),
    };
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(
        mint.clone(),
        C_DSM_PLUS,
        EMBEDDED_PARENT,
        SUBSTRATE_ADDR,
    );
    // Rebind the witness digest to the mint operation so the refusal comes
    // from the write-set/source clause, not a digest mismatch.
    let witness = EconomicTransitionWitness::new(
        witness.pre_economic_root,
        witness.post_economic_root,
        dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
        dsm::economic::faucet::dsm_operation_digest(&mint.to_bytes()),
        witness.mutations,
        witness.credit_sources,
    )
    .expect("valid witness");
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 1, post_root);
    // LAYERING SHIFT (producer cut): the witness DOES carry a 0x0023
    // descriptor, so the write-set shape check now passes — the missing
    // verifier arm that used to refuse this as a kind mismatch was one of the
    // defects the producer cut fixed. The refusal therefore moved DOWN to the
    // layer that actually resolves the predicate: provenance must fetch the
    // authorization evidence, and in this fixture no evidence store exists —
    // the predicate is defined but unsatisfiable, and validation fails closed
    // exactly there.
    match run(&fx, &registered, &manifest, &witness, &accepted) {
        Err(EconomicValidationError::Provenance(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("no evidence store in this fixture"),
                "the refusal must be the unresolvable issuance evidence, got: {msg}"
            );
        }
        other => panic!(
            "a mint whose issuance predicate cannot be satisfied must be refused at the \
             provenance layer, got {other:?}"
        ),
    }
}

#[test]
fn a_successor_paired_with_a_different_operation_is_refused() {
    // THE clause that is easiest to omit and most costly to omit. Both
    // objects are individually valid; together they describe two different
    // operations.
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, fx.post_root);
    let other_op = Operation::FaucetClaim {
        faucet_id: dsm::economic::faucet::era_faucet_id(b"dsm-testnet"),
        ticket_index: 43,
    };
    let wrong = accepted_for(&other_op);
    match run(&fx, &registered, &manifest, &fx.witness, &wrong) {
        Err(EconomicValidationError::OperationDigestMismatch { .. }) => {}
        other => panic!("a mismatched operation digest must be refused, got {other:?}"),
    }
}

#[test]
fn a_witness_naming_a_different_successor_is_refused() {
    // v2 identity conjunct: the witness must name THIS successor (C_dsm+),
    // not merely this operation. Same operation bytes, different successor
    // commitment ⇒ refused.
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, fx.post_root);
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(
        fx.op.clone(),
        [0xDD; 32], // a different accepted successor
        EMBEDDED_PARENT,
        SUBSTRATE_ADDR,
    );
    match run(&fx, &registered, &manifest, &fx.witness, &accepted) {
        Err(EconomicValidationError::EconomicOperationIdMismatch { .. }) => {}
        other => panic!("a witness naming another successor must be refused, got {other:?}"),
    }
}

#[test]
fn the_manifest_must_name_the_substrate_evidence_actually_used() {
    // Correction-10 controls: same kind but different evidence ⇒ refused;
    // different KIND ⇒ refused.
    let fx = faucet_fixture(1);
    let wrong_evidence = EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: [0xA5; 32],
        },
        fx.witness.derived_provenance_index(),
    )
    .expect("valid manifest");
    let registered = registered_for(&wrong_evidence, 1, fx.post_root);
    let accepted = accepted_for(&fx.op);
    match run(&fx, &registered, &wrong_evidence, &fx.witness, &accepted) {
        Err(EconomicValidationError::SubstrateEvidenceMismatch { .. }) => {}
        other => panic!("manifest naming other evidence must be refused, got {other:?}"),
    }

    let wrong_kind = EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::OfflineBoundary {
            evidence_addr: SUBSTRATE_ADDR,
        },
        fx.witness.derived_provenance_index(),
    )
    .expect("valid manifest");
    let registered = registered_for(&wrong_kind, 1, fx.post_root);
    match run(&fx, &registered, &wrong_kind, &fx.witness, &accepted) {
        Err(EconomicValidationError::SubstrateKindMismatch) => {}
        other => panic!("a substrate kind mismatch must be refused, got {other:?}"),
    }
}

#[test]
fn a_registration_at_the_wrong_position_is_refused() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 5, fx.post_root); // not 0 + 1
    let accepted = accepted_for(&fx.op);
    assert!(matches!(
        run(&fx, &registered, &manifest, &fx.witness, &accepted),
        Err(EconomicValidationError::PositionIsNotSuccessor {
            previous: 0,
            registered: 5
        })
    ));
}

#[test]
fn a_registration_naming_another_manifest_is_refused() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let mut registered = registered_for(&manifest, 1, fx.post_root);
    registered.admission_manifest_addr = [0xFF; 32];
    let accepted = accepted_for(&fx.op);
    assert!(matches!(
        run(&fx, &registered, &manifest, &fx.witness, &accepted),
        Err(EconomicValidationError::ManifestAddrMismatch { .. })
    ));
}

#[test]
fn a_registered_root_disagreeing_with_the_witness_is_refused() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, [0xEE; 32]); // invented root
    let accepted = accepted_for(&fx.op);
    assert!(matches!(
        run(&fx, &registered, &manifest, &fx.witness, &accepted),
        Err(EconomicValidationError::RegisteredRootDiffersFromWitness { .. })
    ));
}

/// The Mint-shaped witness the issuance test pairs with a Mint operation.
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

// ─── The market-leg token-policy conjunct (SoFi Def 4.1 / Req 4.4 / 4.6) ────
//
// `advance_validated` binds every DLV successor's legs to the applicable
// token policy, resolved through the VERIFIER'S OWN anchoring — these tests
// drive the full validation stack with a real `DlvFund` witness, so the
// conjunct's reachability is proven, not assumed.

/// A resolver that roots exactly the policies the fixture installs — the
/// verifier's own anchor store, in miniature.
struct MarketRooted {
    policies: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl ProvenanceResolver for MarketRooted {
    fn validated_peer_transition(
        &self,
        _peer_genesis: &[u8; 32],
        _peer_devid: &[u8; 32],
        _peer_economic_position: u64,
    ) -> Result<dsm::economic::provenance::ValidatedPeerTransition, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete("no peers here".into()))
    }
    fn winning_faucet_ticket(
        &self,
        _faucet_id: &[u8; 32],
        _ticket_index: u64,
    ) -> Option<dsm::economic::provenance::FaucetTicketWin> {
        None
    }
    fn winning_settlement_slot_claim(
        &self,
        _vault_id: &[u8; 32],
        _parent_sequence: u64,
        _storage_set: &dsm::ccb::StorageSetMembers,
        _quorum: u32,
    ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
        None
    }
    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        _addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete("no evidence store".into()))
    }
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.policies.get(policy_commit).cloned().ok_or_else(|| {
            PeerLineageFailure::Incomplete(
                "not rooted to this token's anchor — root, then retry".into(),
            )
        })
    }
}

/// A canonical v3 policy proto (the exact packed layout, count included),
/// varying only the transferable flag.
fn market_policy_proto(transferable: bool) -> Vec<u8> {
    let mut flags = 0x01u8; // mint_burn
    if transferable {
        flags |= 0x02;
    }
    flags |= 0x08; // unlimited
    let signer = vec![0xE1u8; 64];
    let mut b = vec![3u8, 0u8, flags, 1u8, 1u8];
    b.extend_from_slice(&(signer.len() as u16).to_be_bytes());
    b.extend_from_slice(&signer);
    b.push(3);
    b.extend_from_slice(b"TKX");
    let alias = b"Token X";
    b.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    b.extend_from_slice(alias);
    b.push(0);
    b.extend_from_slice(&0u128.to_be_bytes());
    b.extend_from_slice(&0u128.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.push(0);
    b.extend_from_slice(&0u16.to_be_bytes());
    use prost::Message;
    dsm::types::proto::TokenPolicyV3 { policy_bytes: b }.encode_to_vec()
}

/// A complete, well-formed DlvFund validation drive: two funded legs, the
/// REAL write-set builder, and a predecessor rehydrated at the pre-root, so
/// the only open question is the market-leg policy conjunct.
#[allow(clippy::type_complexity)]
fn dlv_fund_drive(
    leg_x_pc: [u8; 32],
    leg_y_pc: [u8; 32],
    resolver: &MarketRooted,
) -> Result<
    (
        dsm::economic::lineage::ValidatedEconomicRoot,
        Vec<dsm::economic::provenance::FundedCredit>,
    ),
    EconomicValidationError,
> {
    use dsm::economic::write_set::{build_write_set, CreditSourceFacts, EconomicPreState};
    let (lo, hi) = if leg_x_pc < leg_y_pc {
        (leg_x_pc, leg_y_pc)
    } else {
        (leg_y_pc, leg_x_pc)
    };
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(lo, 1_000u64);
    balances.insert(hi, 1_000u64);
    let mut tree = EconomicSmt::new();
    for (pc, amount) in &balances {
        let leaf =
            EconomicLeafState::Balance(EconomicBalanceState::new(*pc, *amount).expect("balance"));
        tree.insert(leaf.leaf_key(&G, &DEV), leaf.leaf_value().expect("value"));
    }
    let pre_root = tree.root();

    let op = Operation::DlvCreateFundedV2 {
        vault_id: vec![0x77; 32],
        creator_public_key: vec![0xE2; 64],
        parameters_hash: vec![0xE3; 32],
        fulfillment_condition: Vec::new(),
        leg_a_policy_commit: lo,
        leg_a_amount: 250,
        leg_b_policy_commit: hi,
        leg_b_amount: 400,
        fee_bps: 30,
        signature: vec![0xE4; 8],
        mode: TransactionMode::Unilateral,
    };
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&op.to_bytes());
    let econ_op_id = dsm::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS);
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &econ_op_id,
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("the real builder builds the fund write set");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id,
        op_digest,
        built.mutations,
        built.credit_sources,
    )
    .expect("valid witness");
    let manifest = manifest_for(&witness);
    let registered = registered_for(&manifest, 8, built.post_root);
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(
        op,
        C_DSM_PLUS,
        EMBEDDED_PARENT,
        SUBSTRATE_ADDR,
    );
    let previous =
        dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(7, pre_root);
    advance_validated(
        &previous,
        &registered,
        &manifest,
        &witness,
        &accepted,
        resolver,
        &G,
        &DEV,
        b"dsm-testnet",
        &[0x55; 64],
    )
}

fn tokx_pc(proto: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, proto)
}

/// The honest case: one builtin leg, one rooted transferable leg — validates
/// end to end. The resolver's map holds ONLY the non-builtin policy, so this
/// simultaneously proves the builtin leg never consults the resolver.
#[test]
fn a_dlv_fund_with_a_rooted_transferable_leg_validates() {
    let proto = market_policy_proto(true);
    let pc = tokx_pc(&proto);
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let resolver = MarketRooted {
        policies: [(pc, proto)].into_iter().collect(),
    };
    let (root, funded) = dlv_fund_drive(pc, era, &resolver)
        .expect("a rooted transferable leg beside a builtin validates");
    assert_eq!(root.economic_position(), 8);
    assert_eq!(funded.len(), 2, "both reserve credits funded by SameMove");
}

/// Both legs builtin (ERA + dBTC): the resolver roots NOTHING and is never
/// asked — pre-rooted by construction, the sole exceptions.
#[test]
fn builtin_legs_never_consult_the_resolver() {
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let dbtc = dsm::core::token::builtin_policy_commit_for_token("dBTC").expect("dBTC");
    let resolver = MarketRooted {
        policies: std::collections::HashMap::new(),
    };
    dlv_fund_drive(era, dbtc, &resolver)
        .expect("a builtin pair validates with no anchoring at all");
}

/// THE MARKET RULE: a non-transferable asset cannot be a market leg — its
/// committed policy restricts it to mint/burn, and a DLV successor moves
/// control between parties.
///
/// MUTATION CONTROL for the lineage conjunct: comment out the
/// `verify_market_leg_policies` call in `advance_validated` and this test
/// goes red by validating reserve encumbrance of a non-transferable asset.
#[test]
fn a_non_transferable_leg_is_refused_as_a_market_leg() {
    let proto = market_policy_proto(false);
    let pc = tokx_pc(&proto);
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let resolver = MarketRooted {
        policies: [(pc, proto)].into_iter().collect(),
    };
    let err = dlv_fund_drive(pc, era, &resolver)
        .expect_err("a non-transferable market leg must be refused");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("MarketLegPolicy") && msg.contains("non-transferable"),
        "the refusal names the market rule, got: {msg}"
    );
}

/// An unrooted leg fails CLOSED as `Incomplete` — an availability condition
/// (root, then retry), never a validity verdict.
#[test]
fn an_unrooted_market_leg_fails_closed_as_incomplete() {
    let proto = market_policy_proto(true);
    let pc = tokx_pc(&proto);
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let resolver = MarketRooted {
        policies: std::collections::HashMap::new(),
    };
    let err = dlv_fund_drive(pc, era, &resolver).expect_err("unrooted leg fails closed");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Incomplete") && msg.contains("not rooted"),
        "the refusal is retryable unavailability, got: {msg}"
    );
}

/// Bytes that do not re-hash to the committed leg are refused: the resolver
/// locates, it never authorizes.
#[test]
fn policy_bytes_that_do_not_hash_to_the_leg_are_refused() {
    let proto = market_policy_proto(true);
    let pc = tokx_pc(&proto);
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let wrong = market_policy_proto(false); // valid bytes, wrong commit
    let resolver = MarketRooted {
        policies: [(pc, wrong)].into_iter().collect(),
    };
    let err = dlv_fund_drive(pc, era, &resolver).expect_err("mismatched bytes refused");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("do not hash to the committed leg"),
        "the refusal is the hash binding, got: {msg}"
    );
}
