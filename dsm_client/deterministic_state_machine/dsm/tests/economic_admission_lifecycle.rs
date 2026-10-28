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
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::token_types::Balance;

const G: [u8; 32] = [0x11; 32];
const ERA: [u8; 32] = [0xAA; 32];

const SOFI: [u8; 32] = [0xBB; 32];

/// The trader's one key pair, and its `AttA`: the device id a faucet release
/// names is the one they derive (`DevID = H(AK ‖ AttA)`), because the reserve
/// cell recognizes a release only when its signer is the device it credits.
fn trader() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair"))
}

const ATTA: [u8; 32] = [0x4A; 32];

/// The trader's device id, derived from its key and `AttA`.
fn dev() -> &'static [u8; 32] {
    static DEVID: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    DEVID.get_or_init(|| dsm::core::identity::genesis_v2::derive_devid(&trader().0, &ATTA))
}

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
            substrate: match kind {
                PendingAdmissionKind::OfflineLoad { .. }
                | PendingAdmissionKind::OfflineUnload { .. } => {
                    dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary
                }
                _ => dsm::economic::admission::AcceptedSubstrateCoords::Successor {
                    embedded_parent: [0x5E; 32],
                    c_dsm_plus: [6; 32],
                },
            },
        })
        .expect("prepared -> accepted")
        .advanced_to(state)
        .expect("forward")
}

fn bearer_transfer(policy_commit: [u8; 32]) -> Operation {
    Operation::Transfer {
        to_device_id: vec![1; 32],
        amount: Balance::amount(5),
        policy_commit,
        token_policy: Vec::new(),
        terms_commitment: dsm::types::operations::TransferTerms {
            token_id: b"ERA".to_vec(),
            nonce: vec![0; 8],
            mode: TransactionMode::Bilateral,
            memo: String::new(),
            salt: vec![0x5A; 32],
        }
        .commitment(),
        signature: Vec::new(),
        authority_policy: None,
    }
}

// ── The fence predicate ────────────────────────────────────────────────────

/// Activity that touches no economic leaf: a token adoption commits a policy
/// leaf and moves no value.
fn ordinary_activity() -> Operation {
    Operation::AdoptToken {
        policy_commit: ERA,
        signature: Vec::new(),
    }
}

#[test]
fn the_fence_blocks_economic_writes_and_allows_ordinary_activity() {
    let p = pending(
        PendingAdmissionKind::DsmBacked,
        EconomicAdmissionState::LocalAcceptedPendingEcon,
    );
    let op = ordinary_activity();

    // A publication delay must not look like a device fault: activity that
    // touches no economic leaf continues throughout.
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
    let op = ordinary_activity();
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
        fence_allows(
            &load,
            EconomicEffect::OfflineAccountOnly,
            &ordinary_activity()
        ),
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
        .expect("R_0")
}

fn faucet_fixture(position: u64) -> FaucetFixture {
    use dsm::economic::admission::{dsm_economic_operation_id, dsm_operation_digest};
    use dsm::economic::credit::CreditSourceNativeReserveRelease;
    use dsm::economic::native_reserve::{
        release_evidence_addr, sign_release, NativeReserveReleaseBody, ReleaseSource,
        ERA_FAUCET_PAYOUT,
    };
    let (pk, sk) = trader().clone();
    let parent = reserve_genesis();
    let reserve_id = *parent.reserve_id();
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
            recipient_devid: *dev(),
            recipient_economic_position: position,
            recipient_operation_digest: op_digest,
            storage_set_id: canonical_set_id(),
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk.clone(),
                claimant_att_a: ATTA,
            },
        },
        &sk,
    )
    .expect("signable");

    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = bal(era, ERA_FAUCET_PAYOUT);
    let key = credit.leaf_key(&G, dev());
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(credit.clone()), siblings).expect("well-formed");
    tree.insert(key, credit.leaf_value().expect("encodable"));
    let post_root = tree.root();

    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        dsm_economic_operation_id(&G, dev(), &C_DSM_PLUS),
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
        if reserve_id != parent.reserve_id() || generation != 1 {
            return Err(PeerLineageFailure::Incomplete(format!(
                "this fixture's walk reached generation 1 only, not {generation} of {reserve_id:?}"
            )));
        }
        // The reader's heads around the release: the genesis, and the chain
        // with this release as generation 1's step.
        let mut chain = dsm::shared_lineage::GenerationChain::from_genesis(
            &dsm::economic::native_reserve::reserve_lineage_genesis(&parent)
                .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?,
        );
        let before = chain.head();
        let state = parent
            .at_generation(1)
            .map_err(|e| PeerLineageFailure::Incomplete(e.to_string()))?;
        chain
            .push(
                state.root(),
                dsm::economic::native_reserve::release_evidence_addr(&self.envelope),
            )
            .map_err(|e| PeerLineageFailure::Incomplete(format!("{e:?}")))?;
        Ok(ReserveReleaseWin {
            envelope_bytes: self.envelope.clone(),
            parent: before,
            child: chain.head(),
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

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(format!(
            "no relationship in this fixture: {signer:?} step {addr:?}"
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

/// [`OneTicket`] whose catalog could not be read: the network's register
/// set is not established.
struct NoRegisterSet(OneTicket);
impl ProvenanceResolver for NoRegisterSet {
    fn root_register_candidate_set(
        &self,
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "the local catalog could not be read".to_string(),
        ))
    }
    fn validated_peer_transition(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        self.0
            .validated_peer_transition(genesis, device_id, position)
    }
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.0.native_reserve_release(reserve_id, generation)
    }
    fn immutable_evidence(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.0.immutable_evidence(namespace, addr)
    }

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.0.held_ek_step(signer, addr)
    }
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.0.anchored_policy_bytes(policy_commit)
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
    registered_for_trader(G, trader(), ATTA, position, post_root, manifest_addr)
}

/// A registered root of the trader `(genesis, derive_devid(pk, att_a))`,
/// signed by that device (DSM Amendment A10).
fn registered_for_trader(
    genesis: [u8; 32],
    signer: &(Vec<u8>, Vec<u8>),
    att_a: [u8; 32],
    position: u64,
    post_root: [u8; 32],
    manifest_addr: [u8; 32],
) -> RegisteredEconomicRoot {
    let (pk, sk) = signer;
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        genesis,
        dsm::core::identity::genesis_v2::derive_devid(pk, &att_a),
        position,
        post_root,
        manifest_addr,
        canonical_set_id(),
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        pk,
        att_a,
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
        dev(),
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
        (G, *dev(), 1, registered.claim_ref())
    );
}

/// Storage spec §4: the verifier's register set not established is not a
/// verdict about the claimant. The resolver's own class survives into the
/// error — an unreadable catalog stays `Incomplete`, never Invalid; the same
/// transition validates once the set is established.
#[test]
fn a_register_set_not_established_is_not_a_verdict_about_the_claimant() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let registered = registered_for(&manifest, 1, fx.post_root);
    let accepted = accepted_for(&fx.op);
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    let refused = advance_validated(
        &zero,
        &registered,
        &manifest,
        &fx.witness,
        &accepted,
        &NoRegisterSet(OneTicket {
            envelope: fx.envelope.clone(),
        }),
        &G,
        dev(),
        b"dsm-testnet",
        &fx.pk,
    );
    assert!(
        matches!(
            refused,
            Err(EconomicValidationError::Provenance(
                dsm::economic::provenance::ProvenanceError::RegisterNotEstablished(
                    PeerLineageFailure::Incomplete(_)
                )
            ))
        ),
        "{refused:?}"
    );
    run(&fx, &registered, &manifest, &fx.witness, &accepted).expect("validates once established");
}

/// A registered claim of another trader is not a registration of this
/// lineage, whatever root it names.
#[test]
fn a_registered_claim_of_another_trader_is_refused() {
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let accepted = accepted_for(&fx.op);
    let addr = manifest.addr().expect("addressable");
    static OTHER: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    let other = OTHER.get_or_init(|| {
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("another trader's keypair")
    });
    for (genesis, signer, att_a) in [([0x99; 32], trader(), ATTA), (G, other, [0x98; 32])] {
        let foreign = registered_for_trader(genesis, signer, att_a, 1, fx.post_root, addr);
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
    let key = record.leaf_key(&G, dev());
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(record.clone()), siblings).expect("well-formed");
    tree.insert(key, record.leaf_value().expect("encodable"));
    let forged = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        dsm::economic::admission::dsm_economic_operation_id(&G, dev(), &C_DSM_PLUS),
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

    let vault_id = dsm::sofi::derive::vault_id(&G, dev(), 7);
    // The predecessor is the activation root at position 0, so `p` is 0.
    let zero = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    let sigma = dsm::sofi::derive::setup_id(&G, dev(), zero.economic_position(), &vault_id);
    let state = EconomicLeafState::Relationship(dsm::sofi::wire::TraderRelationshipLeaf {
        vault_id,
        leaf: dsm::sofi::derive::relationship_leaf_genesis(&sigma),
    });
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    tree.insert(
        state.leaf_key(&G, dev()),
        state.leaf_value().expect("a leaf value"),
    );
    let derived_root = tree.root();

    // A body whose `p` and `R_T^setup` are the derived ones, and three that
    // are wrong in exactly one way each.
    let body = |position: u64, setup_root: [u8; 32]| {
        dsm::sofi::wire::SofiSetupBody::new(
            G,
            *dev(),
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
            dev(),
            &dsm::economic::admission::dsm_economic_operation_id(&G, dev(), &C_DSM_PLUS),
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
            dsm::economic::admission::dsm_economic_operation_id(&G, dev(), &C_DSM_PLUS),
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
            dev(),
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

// ── The activation point of a held first admission ─────────────────────────
//
// The advance and the pending admission commit together, so a first admission
// held at any later step leaves its own credit on the head. The activation
// point is the head less exactly that credit: the admission resumes on the
// activation root, and anything else the head holds is still value held
// before position 0.

/// The first faucet claim's admission, locally accepted for `fx`'s witness at
/// `position` on the activation root, naming `operation`.
fn held_first_claim(
    fx: &FaucetFixture,
    kind: PendingAdmissionKind,
    position: u64,
    operation: &Operation,
) -> PendingEconomicAdmission {
    PendingEconomicAdmission::prepared(
        kind,
        position,
        dsm::economic::tree::empty_economic_root(),
        dsm::economic::admission::dsm_operation_digest(&operation.to_bytes()),
    )
    .into_locally_accepted(dsm::economic::admission::AcceptedAdmissionCoords {
        post_economic_root: fx.post_root,
        accepted_substrate_addr: SUBSTRATE_ADDR,
        admission_manifest_addr: manifest_for(&fx.witness).addr().expect("addressable"),
        substrate: match kind {
            PendingAdmissionKind::OfflineLoad { .. }
            | PendingAdmissionKind::OfflineUnload { .. } => {
                dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary
            }
            _ => dsm::economic::admission::AcceptedSubstrateCoords::Successor {
                c_dsm_plus: C_DSM_PLUS,
                embedded_parent: EMBEDDED_PARENT,
            },
        },
    })
    .expect("prepared -> accepted")
}

/// The trader's head as it reloads: `balances`, `allocations`, and the
/// admission in flight. `restore` takes the root the device persisted with the
/// fields; it is computed here, independently, over the leaves those fields
/// hold: the device's own relationship at `h_0` and, with allocations, the
/// one offline account a load leaves.
fn head_of(
    genesis: [u8; 32],
    fx: &FaucetFixture,
    balances: &[([u8; 32], u64)],
    allocations: &[([u8; 32], u64)],
    pending: Option<PendingEconomicAdmission>,
) -> dsm::types::device_state::RealizedHead {
    use dsm::core::bilateral_transaction_manager::{compute_smt_key, initial_chain_tip_from_device_ids};
    let accounts: std::collections::BTreeMap<
        [u8; 32],
        dsm::types::offline_account::OfflineAccount,
    > = Some(allocations)
        .filter(|held| !held.is_empty())
        .map(|held| {
            (
                [0xB0; 32],
                dsm::types::offline_account::OfflineAccount::restore(
                    held.iter().copied().collect(),
                    0,
                    [0x01; 32],
                    Some([0x0F; 32]),
                ),
            )
        })
        .into_iter()
        .collect();
    let stored_root = *dsm::merkle::sparse_merkle_tree::SparseMerkleTree::from_leaves(
        std::iter::once((
            compute_smt_key(dev(), dev()),
            initial_chain_tip_from_device_ids(dev(), dev()),
        ))
        .chain(accounts.iter().map(|(bundle, account)| {
            (
                dsm::types::offline_account::offline_account_leaf_key(bundle),
                account.root(),
            )
        })),
    )
    .root();
    dsm::types::device_state::DeviceState::restore(
        genesis,
        *dev(),
        fx.pk.clone(),
        None,
        balances.iter().copied().collect(),
        Vec::new(),
        std::collections::BTreeMap::new(),
        accounts,
        pending,
        stored_root,
    )
    .expect("the head reloads")
}

fn era_payout() -> ([u8; 32], u64) {
    (
        dsm::core::token::token_state_manager::era_policy_commit(),
        dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
    )
}

/// A first claim held after its advance: the head holds the claim's own
/// credit and nothing else. Read off the head as it stands, that credit is
/// value held before position 0 and activation refuses; at the activation
/// point the device held nothing, and the admission resumes on the activation
/// root.
#[test]
fn a_held_first_admission_resumes_on_the_activation_root() {
    let fx = faucet_fixture(1);
    let pending = held_first_claim(&fx, PendingAdmissionKind::DsmBacked, 1, &fx.op);
    let head = head_of(G, &fx, &[era_payout()], &[], Some(pending));

    let as_it_stands = EconomicActivationSnapshot {
        online_balances_empty: head.balances_snapshot().is_empty(),
        outstanding_offline_allocation: head.holds_offline_value(),
    };
    activate(as_it_stands).expect_err("the head as it stands carries the held credit");

    let snapshot = EconomicActivationSnapshot::before_first_admission(&head, &fx.witness)
        .expect("the activation point is readable");
    assert_eq!(snapshot, EconomicActivationSnapshot::fresh());
    let root = activate(snapshot).expect("nothing was held at the activation point");
    assert_eq!(root.economic_position(), 0);
    assert_eq!(
        root.economic_root(),
        dsm::economic::tree::empty_economic_root()
    );
}

/// No self-rooting through a held first admission: whatever the head holds
/// that the first admission did not credit — more of the same asset, another
/// asset, an outstanding allocation — was held at the activation point, and
/// activation refuses it exactly as it refuses a device with nothing pending.
#[test]
fn value_the_first_admission_did_not_credit_still_blocks_activation() {
    let fx = faucet_fixture(1);
    let (era, payout) = era_payout();
    type Holdings = (&'static str, Vec<([u8; 32], u64)>, Vec<([u8; 32], u64)>);
    let cases: [Holdings; 3] = [
        (
            "more of the credited asset",
            vec![(era, payout + 1)],
            vec![],
        ),
        (
            "another asset",
            vec![(era, payout), ([0x7A; 32], 7)],
            vec![],
        ),
        (
            "an outstanding allocation",
            vec![(era, payout)],
            vec![([0x7B; 32], 5)],
        ),
    ];
    for (name, balances, allocations) in cases {
        let pending = held_first_claim(&fx, PendingAdmissionKind::DsmBacked, 1, &fx.op);
        let head = head_of(G, &fx, &balances, &allocations, Some(pending));
        let snapshot = match EconomicActivationSnapshot::before_first_admission(&head, &fx.witness)
        {
            Ok(snapshot) => snapshot,
            Err(e) => panic!("{name}: the activation point is readable: {e}"),
        };
        assert_ne!(
            snapshot,
            EconomicActivationSnapshot::fresh(),
            "{name}: held at the activation point"
        );
        let refused =
            activate(snapshot).expect_err("value held at the activation point blocks activation");
        assert_eq!(refused.snapshot, snapshot, "{name}");
    }
}

/// The activation point is read only through the pending first admission's
/// own witness, from the head that carries it.
#[test]
fn the_activation_point_is_read_only_through_the_first_admissions_own_witness() {
    use dsm::economic::lineage::ActivationPointUnreadable;
    let fx = faucet_fixture(1);
    let (era, _) = era_payout();
    let read = |head: &dsm::types::device_state::DeviceState| {
        EconomicActivationSnapshot::before_first_admission(head, &fx.witness)
    };

    // Nothing pending: the head is its own activation point.
    assert_eq!(
        read(&head_of(G, &fx, &[era_payout()], &[], None)),
        Err(ActivationPointUnreadable::NothingPending)
    );

    // Not a first admission: a later position, or a kind no first admission has.
    for (kind, position) in [
        (PendingAdmissionKind::DsmBacked, 2),
        (
            PendingAdmissionKind::OfflineLoad {
                asset_policy_commit: era,
            },
            1,
        ),
    ] {
        let pending = held_first_claim(&fx, kind, position, &fx.op);
        assert_eq!(
            read(&head_of(G, &fx, &[era_payout()], &[], Some(pending))),
            Err(ActivationPointUnreadable::NotAFirstAdmission {
                economic_position: position
            })
        );
    }

    // The witness of another operation than the one pending.
    let other = Operation::FaucetClaim {
        reserve_id: *reserve_genesis().reserve_id(),
        generation: 2,
    };
    let pending = held_first_claim(&fx, PendingAdmissionKind::DsmBacked, 1, &other);
    assert_eq!(
        read(&head_of(G, &fx, &[era_payout()], &[], Some(pending))),
        Err(ActivationPointUnreadable::WitnessOfAnotherTransition)
    );

    // Another identity's head: the witness's leaves are keyed to this
    // trader's genesis, so they do not verify under another's.
    let pending = held_first_claim(&fx, PendingAdmissionKind::DsmBacked, 1, &fx.op);
    assert!(matches!(
        read(&head_of(
            [0x12; 32],
            &fx,
            &[era_payout()],
            &[],
            Some(pending)
        )),
        Err(ActivationPointUnreadable::WitnessDoesNotVerify(..))
    ));

    // A head that does not hold the credit its pending admission made.
    let pending = held_first_claim(&fx, PendingAdmissionKind::DsmBacked, 1, &fx.op);
    assert_eq!(
        read(&head_of(G, &fx, &[], &[], Some(pending))),
        Err(ActivationPointUnreadable::CreditNotOnHead { policy_commit: era })
    );
}

// ── Offline boundaries: a load and an unload, admitted ────────────────────

/// One boundary taken by the device head and admitted after `previous`: its
/// body, its write set against the economic tree, and the registration that
/// names them.
struct AdmittedBoundary {
    outcome: dsm::types::device_state::OfflineBoundaryOutcome,
    verified: dsm::economic::offline_boundary::VerifiedOfflineBoundary,
    evidence_addr: [u8; 32],
    witness: EconomicTransitionWitness,
}

/// The anchor of the trader's offline account: pin material whose bundle
/// recomputes for the trader's online key and device id.
fn boundary_anchor() -> dsm::economic::offline_boundary::BoundaryAnchor {
    dsm::economic::offline_boundary::BoundaryAnchor {
        anchor_id: [0xB1; 32],
        pk_chip: vec![0xB2; 32],
        pk_host: vec![0xB3; 64],
        enrolled_counter: 16,
        birth_commitment: [0xB4; 32],
    }
}

/// The bundle `B` of [`boundary_anchor`] provisioned for the trader.
fn bundle() -> [u8; 32] {
    let a = boundary_anchor();
    anchor_core::enrollment::anchor_bundle(
        &trader().0,
        &a.anchor_id,
        &a.pk_chip,
        &a.pk_host,
        16,
        dev(),
        &dsm::types::operations::canonical_offline_bearer_policy().policy_id,
        &a.birth_commitment,
    )
}

fn boundary(
    head: &dsm::types::device_state::RealizedHead,
    kind: dsm::types::device_state::OfflineBoundaryKind,
    amount: u64,
    pre_root: [u8; 32],
    tree: &mut EconomicSmt,
    balances: &std::collections::BTreeMap<[u8; 32], u64>,
    position: u64,
) -> AdmittedBoundary {
    use dsm::economic::offline_boundary::{offline_boundary_evidence_addr, OfflineBoundaryBody};
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let outcome = head
        .cross_offline_boundary(&bundle(), kind, &era, amount)
        .expect("the head takes the boundary");
    // No spends here: the boundary starts from the account as it stands,
    // which is the account its previous boundary left, or the one opened.
    let account = head
        .offline_account(&bundle())
        .expect("the account is open");
    let since = match account.funding_chain() {
        None => dsm::economic::offline_boundary::BoundarySince::Opened {
            frontier: account.frontier(),
        },
        Some(_) => dsm::economic::offline_boundary::BoundarySince::Previous {
            account_root: account.root(),
        },
    };
    let bytes = OfflineBoundaryBody::of(
        &outcome,
        kind,
        bundle(),
        era,
        amount,
        dsm::economic::offline_boundary::BoundaryAncestry {
            anchor: boundary_anchor(),
            since,
            chain: Vec::new(),
        },
    )
    .expect("body")
    .encode()
    .expect("encode");
    let (verified, exposed) =
        OfflineBoundaryBody::verify(&bytes, &G, dev(), &trader().0).expect("the body verifies");
    assert!(exposed.is_empty(), "no spends, no exposure");
    let built = dsm::economic::write_set::build_boundary_write_set(
        &dsm::economic::write_set::BoundaryEffect {
            kind,
            asset: era,
            amount,
            boundary_id: outcome.operation_id,
        },
        &G,
        dev(),
        &dsm::economic::write_set::EconomicPreState::new(balances, position),
        tree,
    )
    .expect("the boundary's write set");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        verified.operation_id(),
        verified.operation_digest(),
        built.mutations,
        built.credit_sources,
    )
    .expect("a witness");
    AdmittedBoundary {
        outcome,
        verified,
        evidence_addr: offline_boundary_evidence_addr(&bytes),
        witness,
    }
}

fn validate_boundary(
    fx: &FaucetFixture,
    previous: &dsm::economic::lineage::ValidatedEconomicRoot,
    position: u64,
    b: &AdmittedBoundary,
    witness: &EconomicTransitionWitness,
) -> Result<dsm::economic::lineage::ValidatedAdvance, EconomicValidationError> {
    let manifest = EconomicAdmissionManifest::new(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        AdmissionSubstrate::OfflineBoundary {
            evidence_addr: b.evidence_addr,
        },
        witness.derived_provenance_index(),
    )
    .expect("valid manifest");
    let registered = registered_for(&manifest, position, witness.post_economic_root);
    advance_validated(
        previous,
        &registered,
        &manifest,
        witness,
        &AcceptedSubstrate::from_verified_offline_boundary(b.verified, b.evidence_addr),
        &OneTicket {
            envelope: fx.envelope.clone(),
        },
        &G,
        dev(),
        b"dsm-testnet",
        &fx.pk,
    )
}

/// A load debits the online balance it moves into the offline account; an
/// unload credits it back, funded by exactly the account debit its body
/// proves, and consumes that debit: the same unload cannot fund a second
/// credit, and no other amount, asset or boundary validates.
#[test]
fn an_offline_load_and_unload_advance_the_lineage_and_an_unload_funds_once() {
    use dsm::types::device_state::OfflineBoundaryKind::{Load, Unload};
    use dsm::economic::native_reserve::ERA_FAUCET_PAYOUT;
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let fx = faucet_fixture(1);
    let manifest = manifest_for(&fx.witness);
    let at_one = run(
        &fx,
        &registered_for(&manifest, 1, fx.post_root),
        &manifest,
        &fx.witness,
        &accepted_for(&fx.op),
    )
    .expect("the faucet claim validates")
    .root;

    let mut tree = EconomicSmt::new();
    let credit = bal(era, ERA_FAUCET_PAYOUT);
    tree.insert(
        credit.leaf_key(&G, dev()),
        credit.leaf_value().expect("encodable"),
    );
    assert_eq!(tree.root(), at_one.economic_root());
    let head = head_of(G, &fx, &[(era, ERA_FAUCET_PAYOUT)], &[], None)
        .open_offline_account(&bundle(), [0x01; 32], 0)
        .expect("the account opens");

    // ── position 2: load 300 ──
    let online = std::collections::BTreeMap::from([(era, ERA_FAUCET_PAYOUT)]);
    let load = boundary(
        &head,
        Load,
        300,
        at_one.economic_root(),
        &mut tree,
        &online,
        2,
    );
    let at_two = validate_boundary(&fx, &at_one, 2, &load, &load.witness)
        .expect("the load validates")
        .root;
    assert_eq!(
        load.outcome
            .new_device_state
            .offline_allocation(&bundle(), &era),
        Some(300)
    );

    // ── position 3: unload 100 ──
    let online = std::collections::BTreeMap::from([(era, ERA_FAUCET_PAYOUT - 300)]);
    let after_load = tree.clone();
    let unload = boundary(
        &load.outcome.new_device_state,
        Unload,
        100,
        at_two.economic_root(),
        &mut tree,
        &online,
        3,
    );
    let at_three =
        validate_boundary(&fx, &at_two, 3, &unload, &unload.witness).expect("the unload validates");
    assert_eq!(at_three.funded.len(), 1, "the unload's credit is funded");
    assert_eq!(at_three.funded[0].amount(), 100);

    // The same unload cannot fund a second credit: its source is consumed.
    let again = dsm::economic::write_set::build_boundary_write_set(
        &dsm::economic::write_set::BoundaryEffect {
            kind: Unload,
            asset: era,
            amount: 100,
            boundary_id: unload.outcome.operation_id,
        },
        &G,
        dev(),
        &dsm::economic::write_set::EconomicPreState::new(
            &std::collections::BTreeMap::from([(era, ERA_FAUCET_PAYOUT - 200)]),
            4,
        ),
        &mut tree,
    )
    .expect_err("a consumed offline debit funds nothing more");
    assert_eq!(
        again,
        dsm::economic::write_set::WriteSetError::SourceAlreadyConsumed
    );

    // A credit larger than the account debit the body proves is refused.
    let inflated = dsm::economic::write_set::build_boundary_write_set(
        &dsm::economic::write_set::BoundaryEffect {
            kind: Unload,
            asset: era,
            amount: 101,
            boundary_id: unload.outcome.operation_id,
        },
        &G,
        dev(),
        &dsm::economic::write_set::EconomicPreState::new(&online, 3),
        &mut after_load.clone(),
    )
    .expect("a write set for 101");
    let witness = EconomicTransitionWitness::new(
        at_two.economic_root(),
        inflated.post_root,
        unload.verified.operation_id(),
        unload.verified.operation_digest(),
        inflated.mutations,
        inflated.credit_sources,
    )
    .expect("a witness");
    let refused = validate_boundary(&fx, &at_two, 3, &unload, &witness)
        .expect_err("a credit the offline debit does not fund");
    assert!(
        refused
            .to_string()
            .contains("not exactly the amount it unloads"),
        "{refused}"
    );

    // An unload's write set presented on a load's body is refused.
    let refused = validate_boundary(
        &fx,
        &at_two,
        3,
        &AdmittedBoundary {
            outcome: unload.outcome.clone(),
            verified: load.verified,
            evidence_addr: load.evidence_addr,
            witness: unload.witness.clone(),
        },
        &unload.witness,
    )
    .expect_err("another boundary's body");
    assert!(
        matches!(
            refused,
            EconomicValidationError::OperationDigestMismatch { .. }
        ),
        "{refused}"
    );

    // A witness that names another boundary's identity is refused.
    let renamed = EconomicTransitionWitness::new(
        unload.witness.pre_economic_root,
        unload.witness.post_economic_root,
        load.verified.operation_id(),
        unload.witness.operation_digest,
        unload.witness.mutations.clone(),
        unload.witness.credit_sources.clone(),
    )
    .expect("a witness");
    let refused = validate_boundary(&fx, &at_two, 3, &unload, &renamed)
        .expect_err("another boundary's identity");
    assert!(
        matches!(
            refused,
            EconomicValidationError::OfflineBoundaryIdMismatch { .. }
        ),
        "{refused}"
    );
}

/// The `0x0075` arm on its own, beside the write-set check that stands in
/// front of it: it funds a credit only on an unload's admission, and only
/// with its source recorded as consumed in the same witness.
#[test]
fn an_offline_debit_funds_only_an_unload_and_only_once_recorded() {
    use dsm::economic::provenance::{verify_transition_provenance, ProvenanceContext, ProvenanceError};
    use dsm::types::device_state::OfflineBoundaryKind::{Load, Unload};
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let fx = faucet_fixture(1);
    let online = std::collections::BTreeMap::from([(era, 500)]);
    let head = head_of(G, &fx, &[(era, 500)], &[], None)
        .open_offline_account(&bundle(), [0x01; 32], 0)
        .expect("the account opens");
    let mut tree = EconomicSmt::new();
    let held = bal(era, 500);
    tree.insert(
        held.leaf_key(&G, dev()),
        held.leaf_value().expect("encodable"),
    );
    let pre_root = tree.root();
    let load = boundary(&head, Load, 300, pre_root, &mut tree.clone(), &online, 2);
    let after_load = std::collections::BTreeMap::from([(era, 200)]);
    let mut loaded_tree = tree.clone();
    let built = dsm::economic::write_set::build_boundary_write_set(
        &dsm::economic::write_set::BoundaryEffect {
            kind: Load,
            asset: era,
            amount: 300,
            boundary_id: load.outcome.operation_id,
        },
        &G,
        dev(),
        &dsm::economic::write_set::EconomicPreState::new(&online, 2),
        &mut loaded_tree,
    )
    .expect("the load's write set");
    assert_eq!(built.post_root, load.witness.post_economic_root);
    let unload = boundary(
        &load.outcome.new_device_state,
        Unload,
        100,
        loaded_tree.root(),
        &mut loaded_tree.clone(),
        &after_load,
        3,
    );
    let ctx = |offline_boundary| ProvenanceContext {
        genesis: &G,
        device_id: dev(),
        economic_position: 3,
        network_id: b"dsm-testnet",
        proven_ak: &fx.pk,
        canonical_storage_set_id: canonical_set_id(),
        substrate_b_pair: None,
        verified_operation: None,
        offline_boundary,
    };
    let resolver = OneTicket {
        envelope: fx.envelope.clone(),
    };
    verify_transition_provenance(&unload.witness, &resolver, &ctx(Some(&unload.verified)))
        .expect("the unload's own debit funds its credit");
    // On a load's substrate the same credit has no offline debit to fund it.
    assert_eq!(
        verify_transition_provenance(&unload.witness, &resolver, &ctx(Some(&load.verified))),
        Err(ProvenanceError::NotAnOfflineUnload)
    );
    assert_eq!(
        verify_transition_provenance(&unload.witness, &resolver, &ctx(None)),
        Err(ProvenanceError::NotAnOfflineUnload)
    );
    // The credit without the consumption of its source is not funded once.
    let credit_only: Vec<EconomicLeafMutation> = unload
        .witness
        .mutations
        .iter()
        .filter(|m| matches!(m.post_state, Some(EconomicLeafState::Balance(_))))
        .cloned()
        .collect();
    let witness = EconomicTransitionWitness::new(
        unload.witness.pre_economic_root,
        unload.witness.post_economic_root,
        unload.witness.economic_operation_id,
        unload.witness.operation_digest,
        credit_only,
        vec![CreditSource::OfflineBoundaryDebit(
            dsm::economic::credit::CreditSourceOfflineBoundaryDebit {
                credit_mutation_index: 0,
            },
        )],
    )
    .expect("a witness");
    assert!(matches!(
        verify_transition_provenance(&witness, &resolver, &ctx(Some(&unload.verified))),
        Err(ProvenanceError::SourceNotRecordedAsConsumed { .. })
    ));
}
