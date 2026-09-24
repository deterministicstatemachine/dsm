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
use dsm::economic::credit::CreditSource;
use dsm::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    EconomicValidationError,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::register::RegisteredEconomicRoot;
use dsm::economic::provenance::{
    PeerLineageFailure, ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
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
        amount: Balance::amount(5),
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

/// The reserve state the fixture's release succeeds: `R_0`.
fn reserve_genesis() -> dsm::economic::native_reserve::NativeReserveState {
    dsm::economic::native_reserve::NativeReserveState::genesis(b"dsm-testnet", canonical_set_id())
}

fn faucet_fixture(position: u64) -> FaucetFixture {
    use dsm::economic::admission::{dsm_economic_operation_id, dsm_operation_digest};
    use dsm::economic::credit::CreditSourceNativeReserveRelease;
    use dsm::economic::native_reserve::{
        release_evidence_addr, sign_release, NativeReserveReleaseBody, ReleaseSource,
        ERA_FAUCET_PAYOUT,
    };
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
    let parent = reserve_genesis();
    let reserve_id = parent.reserve_id;
    let generation = 1u64;
    let op = Operation::FaucetClaim {
        reserve_id,
        generation,
    };
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let envelope = sign_release(
        &NativeReserveReleaseBody {
            reserve_id,
            parent_root: parent.root(),
            generation,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: G,
            recipient_devid: DEV,
            recipient_economic_position: position,
            recipient_operation_digest: op_digest,
            storage_set_id: canonical_set_id(),
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk.clone(),
            },
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
        vec![CreditSource::NativeReserveRelease(
            CreditSourceNativeReserveRelease {
                credit_mutation_index: 0,
                reserve_id,
                generation,
                release_evidence_addr: release_evidence_addr(&envelope),
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

/// A resolver whose walk established exactly one final release, at
/// generation 1 of `R_0`.
struct OneTicket {
    envelope: Vec<u8>,
}
impl ProvenanceResolver for OneTicket {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, dsm::economic::provenance::PeerLineageFailure> {
        if network_id != dsm::economic::register::BETA_NETWORK_ID {
            return Err(PeerLineageFailure::Incomplete(format!(
                "no register set for network {network_id:?} in this fixture"
            )));
        }
        Ok(crate::beta_candidate_set())
    }

    fn validated_peer_transition(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(format!(
            "no peer store in this fixture: {genesis:?}/{device_id:?} at {position}"
        )))
    }
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        let parent = reserve_genesis();
        if *reserve_id != parent.reserve_id || generation != 1 {
            return Err(PeerLineageFailure::Incomplete(format!(
                "this fixture's walk reached generation 1 only, not {generation} of {reserve_id:?}"
            )));
        }
        Ok(ReserveReleaseWin {
            envelope_bytes: self.envelope.clone(),
            parent,
        })
    }

    fn immutable_evidence(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(format!(
            "no evidence store in this fixture: {addr:?} under {:?}",
            namespace.source_bytes()
        )))
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(format!(
            "this fixture roots no token anchors: {policy_commit:?}"
        )))
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
    registered_naming(position, post_root, manifest.addr().expect("addressable"))
}

/// A registered root, built the ONLY way there is: sign a claim and project
/// the verified result.
///
/// The fields are private now, so a test cannot poke one afterwards to
/// manufacture a mismatch — it has to register a claim that genuinely says
/// the wrong thing, which is what a hostile trader would have to do too.
fn registered_naming(
    position: u64,
    post_root: [u8; 32],
    manifest_addr: [u8; 32],
) -> RegisteredEconomicRoot {
    registered_for_trader(G, DEV, position, post_root, manifest_addr)
}

/// A registered root of the trader `(genesis, device)`.
fn registered_for_trader(
    genesis: [u8; 32],
    device: [u8; 32],
    position: u64,
    post_root: [u8; 32],
    manifest_addr: [u8; 32],
) -> RegisteredEconomicRoot {
    static KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    let (pk, sk) = KEYS.get_or_init(|| {
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("a claimant keypair")
    });
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        genesis,
        device,
        position,
        post_root,
        manifest_addr,
        canonical_set_id(),
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        pk,
    )
    .expect("a claim body");
    let envelope =
        dsm::economic::claim_envelope::sign_economic_root_claim(&body, sk).expect("sign");
    RegisteredEconomicRoot::from_verified_single_root(
        dsm::economic::claim_envelope::decode_registered_economic_claim(&envelope)
            .expect("decodes")
            .single_root()
            .expect("a single-root claim"),
    )
}

#[allow(clippy::too_many_arguments)]
fn run(
    fx: &FaucetFixture,
    registered: &RegisteredEconomicRoot,
    manifest: &EconomicAdmissionManifest,
    witness: &EconomicTransitionWitness,
    accepted: &AcceptedSubstrate,
) -> Result<dsm::economic::lineage::ValidatedAdvance, EconomicValidationError> {
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
    let advanced = run(&fx, &registered, &manifest, &fx.witness, &accepted).expect("validates");
    assert_eq!(advanced.root.economic_position(), 1);
    assert_eq!(advanced.funded.len(), 1);
    // The claim accepted at the position is the registered one, of this
    // trader.
    assert_eq!(
        (
            advanced.claim.genesis(),
            advanced.claim.device_id(),
            advanced.claim.economic_position(),
            advanced.claim.claim_ref()
        ),
        (G, DEV, 1, registered.claim_ref())
    );
}

/// A registered claim of another trader is not a registration of this
/// lineage, whatever root it names.
#[test]
fn a_registered_claim_of_another_trader_is_refused() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let accepted = accepted_for(&fx.op);
    let addr = manifest.addr().expect("addressable");
    for (genesis, device) in [([0x99; 32], DEV), (G, [0x98; 32])] {
        let foreign = registered_for_trader(genesis, device, 1, fx.post_root, addr);
        assert!(matches!(
            run(&fx, &foreign, &manifest, &fx.witness, &accepted),
            Err(EconomicValidationError::RegisteredClaimNamesAnotherTrader)
        ));
    }
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
        dsm::economic::admission::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
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

#[test]
fn a_successor_paired_with_a_different_operation_is_refused() {
    // THE clause that is easiest to omit and most costly to omit. Both
    // objects are individually valid; together they describe two different
    // operations.
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, fx.post_root);
    let other_op = Operation::FaucetClaim {
        reserve_id: dsm::economic::native_reserve::era_reserve_id(b"dsm-testnet"),
        generation: 43,
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
    let registered = registered_naming(1, fx.post_root, [0xFF; 32]);
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

// ─── The market-leg token-policy conjunct (SoFi Def 4.1 / Req 4.4 / 4.6) ────
//
// `advance_validated` binds every DLV successor's legs to the applicable
// token policy, resolved through the VERIFIER'S OWN anchoring — these tests
// drive the full validation stack with a real `DlvFund` witness, so the
// conjunct's reachability is proven, not assumed.

/// The beta fleet as a catalog resolves it: the network's canonical member
/// ids paired with the register incarnations those members are serving.
///
/// A set id is a function of `(member_id, register_incarnation_id)` pairs, so
/// a fixture cannot state one as a constant — it derives it the same way
/// production does, from candidate entries the profile then checks.
fn beta_candidate_set() -> dsm::ccb::StorageSetMembers {
    // Built from the network's PINNED pairs, so a fixture resolves to the
    // real committed register rather than to values a fixture chose.
    let pinned = dsm::economic::register::pinned_root_register_members(b"dsm-testnet")
        .expect("the beta network is known");
    dsm::ccb::StorageSetMembers::new(pinned).expect("pinned beta set")
}

// ── F1: `p` and `R_T^setup` are established by the ordinary transition ──────

/// THE TWO SETUP CONJUNCTS ARE REACHABLE, and they refuse.
///
/// `R_T^setup` had zero readers before this: a correctly signed first setup
/// could put ANY 32 bytes there, and the `(G, DevID, v)` index would then pin
/// a `ρ` committing them forever — the uniqueness rule holding over a field
/// nothing had checked. `p` was equally unbound.
///
/// Both are established HERE, by the ordinary transition, without waiting for
/// E2: `advance_validated` already holds the predecessor and the root derived
/// from the verified mutation sequence, which is exactly the normative
/// relation. (`ClaimRef_p` still needs the parent envelope, so it stays E2's.)
#[test]
fn a_setup_transition_binds_its_position_and_its_derived_root() {
    use dsm::economic::state::EconomicLeafState;
    use dsm::economic::tree::EconomicSmt;

    let vault_id = dsm::sofi::derive::vault_id(&G, &DEV, 7);
    // The predecessor is the activation root at position 0, so `p` is 0.
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    let sigma = dsm::sofi::derive::setup_id(&G, &DEV, zero.economic_position(), &vault_id);
    let state = EconomicLeafState::Relationship(dsm::sofi::wire::TraderRelationshipLeaf {
        vault_id,
        leaf: dsm::sofi::derive::relationship_leaf_genesis(&sigma),
    });
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    tree.insert(
        state.leaf_key(&G, &DEV),
        state.leaf_value().expect("a leaf value"),
    );
    let derived_root = tree.root();

    // A body whose `p` and `R_T^setup` are the derived ones, and three that
    // are wrong in exactly one way each.
    let body = |position: u64, setup_root: [u8; 32]| {
        dsm::sofi::wire::SofiSetupBody::new(
            G,
            DEV,
            position,
            vault_id,
            [0x66; 32],
            setup_root,
            dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &[0x01; 64],
        )
        .expect("a setup body")
    };
    let op_for = |b: &dsm::sofi::wire::SofiSetupBody| Operation::SofiSetup {
        setup_body: b.encode(),
        signature: vec![0xA1; 8],
    };

    // ONE WITNESS PER OPERATION. `advance_validated` binds the accepted
    // substrate's operation digest to the witness's before it reaches the
    // setup conjuncts, so reusing a witness across bodies would be refused by
    // that check and prove nothing about these two.
    let fx = faucet_fixture(1);
    let go = |b: &dsm::sofi::wire::SofiSetupBody| {
        let op = op_for(b);
        let mut build_tree = EconomicSmt::new();
        let built = dsm::economic::write_set::build_write_set(
            &op,
            &G,
            &DEV,
            &dsm::economic::admission::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
            &dsm::economic::write_set::EconomicPreState::new(&std::collections::BTreeMap::new(), 0),
            &mut build_tree,
            &dsm::economic::write_set::CreditSourceFacts::None,
        )
        .expect("a setup builds");
        // NOT asserted equal to `derived_root` here: `h⁰` is derived from the
        // BODY's own position, so a body naming another `p` produces a
        // self-consistent write set with a DIFFERENT root. That is precisely
        // why the position conjunct is needed — self-consistency is not a
        // binding to the real predecessor.
        let witness = EconomicTransitionWitness::new(
            pre_root,
            built.post_root,
            dsm::economic::admission::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
            dsm::economic::admission::dsm_operation_digest(&op.to_bytes()),
            built.mutations,
            built.credit_sources,
        )
        .expect("a witness");
        let manifest = manifest_for(&witness);
        let registered = registered_for(&manifest, 1, witness.post_economic_root);
        advance_validated(
            &zero,
            &registered,
            &manifest,
            &witness,
            &accepted_for(&op),
            &OneTicket {
                envelope: fx.envelope.clone(),
            },
            &G,
            &DEV,
            b"dsm-testnet",
            &fx.pk,
        )
        .map(|_| ())
    };

    // A body naming another predecessor position.
    assert!(
        matches!(
            go(&body(zero.economic_position() + 5, derived_root)),
            Err(EconomicValidationError::SetupPositionIsNotThePredecessor { .. })
        ),
        "p is the position the parent claim names"
    );

    // A body asserting a root its own transition does not produce — the case
    // the field's whole job is to make impossible.
    assert!(
        matches!(
            go(&body(zero.economic_position(), [0xEE; 32])),
            Err(EconomicValidationError::SetupRootIsNotTheDerivedRoot { .. })
        ),
        "R_T^setup is derived, never asserted"
    );

    // And the correct body reaches the conjuncts and passes them. It may be
    // refused further down for faucet-fixture reasons; what this asserts is
    // that it is NOT refused by either setup conjunct, which is what makes
    // the two refusals above meaningful rather than unreachable.
    let outcome = go(&body(zero.economic_position(), derived_root));
    assert!(
        !matches!(
            outcome,
            Err(EconomicValidationError::SetupPositionIsNotThePredecessor { .. })
                | Err(EconomicValidationError::SetupRootIsNotTheDerivedRoot { .. })
        ),
        "the derived body must pass both setup conjuncts, got {outcome:?}"
    );
}
