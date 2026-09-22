// SPDX-License-Identifier: Apache-2.0

//! The native ERA reserve on the wire: the canonical reserve, a release as
//! the recipient's credit, the accepting gate, and the authoritative
//! provenance arm (Part IX §51; rebuild step R4).
//!
//! The controls that matter are the ones an attacker would aim at: the
//! canonical-id rule (an invented reserve id must not be a second genesis
//! supply), the successor rule (a release that does not fit the state the
//! walk validated funds nothing — that is where minting would enter), the
//! recipient rule (`FaucetClaim(A, x) ⇒ recipient = A`), the fence coupling
//! (a claim must not be a raw local mint), and the position+digest binding
//! (one release funds at most one transition).

#![allow(clippy::disallowed_methods)]

use dsm::economic::admission::dsm_operation_digest;
use dsm::economic::classifier::{classify, EconomicEffect};
use dsm::economic::credit::{CreditSource, CreditSourceNativeReserveRelease};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::native_reserve::{
    era_reserve_id, release_constructible, release_evidence_addr, release_source_id, sign_release,
    NativeReserveReleaseBody, NativeReserveState, ReleaseSource, ERA_FAUCET_PAYOUT,
    ERA_RESERVE_GENESIS_SUPPLY,
};
use dsm::economic::provenance::{
    verify_credit_source, PeerLineageFailure, ProvenanceContext, ProvenanceError,
    ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::operations::Operation;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const NETWORK: &[u8] = b"dsm-testnet";
const SET_ID: [u8; 32] = [0xB1; 32];

fn era_commit() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn keypair() -> (Vec<u8>, Vec<u8>) {
    dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
}

fn claim_op(reserve_id: [u8; 32], generation: u64) -> Operation {
    Operation::FaucetClaim {
        reserve_id,
        generation,
    }
}

fn genesis() -> NativeReserveState {
    NativeReserveState::genesis(NETWORK, SET_ID)
}

/// A signed release succeeding `parent`, plus the witness of the transition
/// it funds, built the way an honest claimant builds them.
struct Fixture {
    envelope: Vec<u8>,
    parent: NativeReserveState,
    witness: EconomicTransitionWitness,
    descriptor: CreditSourceNativeReserveRelease,
    pk: Vec<u8>,
}

fn fixture_at(parent: NativeReserveState, position: u64, amount: u64) -> Fixture {
    let (pk, sk) = keypair();
    let reserve_id = parent.reserve_id;
    let generation = parent.generation + 1;
    let op = claim_op(reserve_id, generation);
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let body = NativeReserveReleaseBody {
        reserve_id,
        parent_root: parent.root(),
        generation,
        amount,
        recipient_genesis: G,
        recipient_devid: DEV,
        recipient_economic_position: position,
        recipient_operation_digest: op_digest,
        storage_set_id: SET_ID,
        source: ReleaseSource::FaucetClaimant {
            claimant_public_key: pk.clone(),
        },
    };
    let envelope = sign_release(&body, &sk).expect("signable");

    // The credited transition: empty tree -> +amount ERA.
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = EconomicLeafState::Balance(
        EconomicBalanceState::new(era_commit(), amount).expect("nonzero"),
    );
    let key = credit.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(credit.clone()), siblings).expect("well-formed");
    tree.insert(key, credit.leaf_value().expect("encodable"));
    let post_root = tree.root();

    let descriptor = CreditSourceNativeReserveRelease {
        credit_mutation_index: 0,
        reserve_id,
        generation,
        release_evidence_addr: release_evidence_addr(&envelope),
    };
    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        [0x0E; 32],
        op_digest,
        vec![mutation],
        vec![CreditSource::NativeReserveRelease(descriptor.clone())],
    )
    .expect("valid witness");

    Fixture {
        envelope,
        parent,
        witness,
        descriptor,
        pk,
    }
}

fn fixture(position: u64) -> Fixture {
    fixture_at(genesis(), position, ERA_FAUCET_PAYOUT)
}

/// A resolver whose walk of the reserve established exactly one final
/// release, at `generation` of the state `parent`.
struct OneRelease {
    reserve_id: [u8; 32],
    generation: u64,
    envelope: Vec<u8>,
    parent: NativeReserveState,
}

impl OneRelease {
    fn of(fx: &Fixture) -> Self {
        Self {
            reserve_id: fx.descriptor.reserve_id,
            generation: fx.descriptor.generation,
            envelope: fx.envelope.clone(),
            parent: fx.parent,
        }
    }
}

impl ProvenanceResolver for OneRelease {
    fn root_register_candidate_set(
        &self,
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        Ok(beta_candidate_set())
    }

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

    fn native_reserve_release(&self, r: &[u8; 32], g: u64) -> Option<ReserveReleaseWin> {
        (*r == self.reserve_id && g == self.generation).then(|| ReserveReleaseWin {
            envelope_bytes: self.envelope.clone(),
            parent: self.parent,
        })
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

/// A resolver whose walk reached no release at all.
struct Nothing;

impl ProvenanceResolver for Nothing {
    fn root_register_candidate_set(
        &self,
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        Ok(beta_candidate_set())
    }

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

    fn native_reserve_release(&self, _r: &[u8; 32], _g: u64) -> Option<ReserveReleaseWin> {
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

fn ctx<'a>(position: u64, ak: &'a [u8]) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G,
        device_id: &DEV,
        economic_position: position,
        network_id: NETWORK,
        proven_ak: ak,
        canonical_storage_set_id: SET_ID,
        substrate_b_pair: None,
        verified_operation: None,
    }
}

// ── The authoritative provenance arm ───────────────────────────────────────

/// `user_after = user_before + release`: a final release funds exactly what
/// it released, of the reserve's own asset, from the release's own source id.
#[test]
fn a_final_release_funds_exactly_what_it_released() {
    let fx = fixture(1);
    let funded = verify_credit_source(
        &fx.witness.credit_sources[0],
        &fx.witness,
        &OneRelease::of(&fx),
        &ctx(1, &fx.pk),
    )
    .expect("a final canonical release funds the credit");
    assert_eq!(funded.amount, ERA_FAUCET_PAYOUT);
    assert_eq!(funded.policy_commit, era_commit());
    assert_eq!(
        funded.source_id,
        release_source_id(&fx.descriptor.reserve_id, fx.descriptor.generation)
    );
}

/// `total ERA conserved` through the verifier: every credit a walked lineage
/// funds is exactly what the reserve gave up, and the reserve's own state is
/// what the walk computed — `S_genesis = remaining + Σ credited`.
#[test]
fn credits_funded_along_a_lineage_sum_to_what_the_reserve_released() {
    let mut parent = genesis();
    let mut credited = 0u64;
    for (position, amount) in [(1u64, ERA_FAUCET_PAYOUT), (2, 7), (3, ERA_FAUCET_PAYOUT)] {
        let fx = fixture_at(parent, position, amount);
        let funded = verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(position, &fx.pk),
        )
        .expect("each release funds its credit");
        credited += funded.amount;
        let release = dsm::economic::native_reserve::decode_and_verify_release(&fx.envelope)
            .expect("verifies");
        parent = release_constructible(&parent, &release).expect("the walk's next state");
        assert_eq!(
            parent.remaining_supply + credited,
            ERA_RESERVE_GENESIS_SUPPLY
        );
    }
    assert_eq!(parent.generation, 3);
}

/// `no valid reserve transition can mint ERA`, at the verifier: a release
/// that is not the successor of the state the walk validated funds nothing —
/// here one that releases more than the reserve holds. Remove the successor
/// check from the arm (or the overdraft refusal from the construction
/// predicate) and this goes red.
#[test]
fn a_release_that_is_not_its_parents_successor_funds_nothing() {
    let mut low = genesis();
    low.remaining_supply = 50;
    let fx = fixture_at(low, 1, 51);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseInvalid(
            "is not the successor of its parent"
        ))
    ));
    // The same bytes presented against a parent whose root they do not
    // commit — a fabricated reserve state — fund nothing either.
    let fx = fixture(1);
    let mut fabricated = genesis();
    fabricated.remaining_supply = u64::MAX;
    let resolver = OneRelease {
        parent: fabricated,
        ..OneRelease::of(&fx)
    };
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseInvalid(
            "is not the successor of its parent"
        ))
    ));
}

/// THE stop-the-line control. Everything about this release is internally
/// consistent — signed, its parent fits, evidence address matches — except
/// the reserve id is an INVENTED one. If only descriptor==release were
/// checked, each invented id would be a second genesis supply.
#[test]
fn wrong_reserve_id_cannot_create_a_second_genesis_supply() {
    let mut other = genesis();
    other.reserve_id = [0xF4; 32];
    let fx = fixture_at(other, 1, ERA_FAUCET_PAYOUT);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::NotTheCanonicalReserve { .. })
    ));
    assert_ne!(era_reserve_id(NETWORK), era_reserve_id(b"othernet"));
}

/// `FaucetClaim(A, x) ⇒ recipient = A`. The release names its recipient and
/// the claimant key that signed it; a release whose signing key is not the
/// P0–P6-proven AK of the identity under validation — or whose recipient is
/// someone else — funds nothing for that identity. Remove the recipient
/// check from the arm and this goes red.
#[test]
fn faucet_claim_names_its_claimant_as_recipient() {
    let fx = fixture(1);
    // The key is not the proven AK: storage attribution is not this binding.
    let other_ak = keypair().0;
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(1, &other_ak),
        ),
        Err(ProvenanceError::ReleaseRecipientMismatch)
    ));
    // The release names another recipient than the identity under validation.
    let (pk, sk) = keypair();
    let parent = genesis();
    let op = claim_op(parent.reserve_id, 1);
    let paid_to_someone_else = sign_release(
        &NativeReserveReleaseBody {
            reserve_id: parent.reserve_id,
            parent_root: parent.root(),
            generation: 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: [0x66; 32],
            recipient_devid: [0x67; 32],
            recipient_economic_position: 1,
            recipient_operation_digest: dsm_operation_digest(&op.to_bytes()),
            storage_set_id: SET_ID,
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk.clone(),
            },
        },
        &sk,
    )
    .expect("signable");
    let resolver = OneRelease {
        envelope: paid_to_someone_else.clone(),
        ..OneRelease::of(&fx)
    };
    let mut descriptor = fx.descriptor.clone();
    descriptor.release_evidence_addr = release_evidence_addr(&paid_to_someone_else);
    let src = CreditSource::NativeReserveRelease(descriptor);
    assert!(matches!(
        verify_credit_source(&src, &fx.witness, &resolver, &ctx(1, &pk)),
        Err(ProvenanceError::ReleaseRecipientMismatch)
    ));
}

/// NON-REUSE. The release commits target position 1; presenting the same
/// final release for the transition at position 2 must fail — position
/// binding is what makes the no-nonce operation sound, since two minimal
/// claims' bytes can be identical.
#[test]
fn one_release_funds_at_most_one_position() {
    let fx = fixture(1);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(2, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseBindingMismatch)
    ));
}

#[test]
fn a_foreign_register_set_is_refused() {
    let fx = fixture(1);
    let mut c = ctx(1, &fx.pk);
    c.canonical_storage_set_id = [0x77; 32]; // canonical set differs from the release's
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &c
        ),
        Err(ProvenanceError::ReleaseForeignSet)
    ));
}

#[test]
fn no_final_release_fails_closed_and_generation_zero_is_refused() {
    let fx = fixture(1);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &Nothing,
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::ReleaseNotEstablished { .. })
    ));
    // Generation 0 is the genesis state, never a release.
    let mut d = fx.descriptor.clone();
    d.generation = 0;
    let src = CreditSource::NativeReserveRelease(d);
    assert!(matches!(
        verify_credit_source(&src, &fx.witness, &Nothing, &ctx(1, &fx.pk)),
        Err(ProvenanceError::GenerationIsGenesis)
    ));
}

#[test]
fn the_bytes_the_members_hold_must_be_the_bytes_the_dag_addresses() {
    let fx = fixture(1);
    let mut d = fx.descriptor.clone();
    d.release_evidence_addr = [0x99; 32];
    let src = CreditSource::NativeReserveRelease(d);
    assert!(matches!(
        verify_credit_source(&src, &fx.witness, &OneRelease::of(&fx), &ctx(1, &fx.pk)),
        Err(ProvenanceError::ReleaseEvidenceAddrMismatch)
    ));
}

// ── The accepting gate: not a raw local mint ───────────────────────────────

#[test]
fn conservation_refuses_anything_but_the_derived_payout() {
    use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
    let devid = [0x33u8; 32];
    let head = DeviceState::new([0x44u8; 32], devid, vec![0xAA; 32], 64);
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid, &devid);
    let tip =
        dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&devid, &devid);
    let op = claim_op(era_reserve_id(NETWORK), 42);

    // Wrong amount and wrong asset each refused: nothing is caller-chosen.
    for delta in [
        BalanceDelta {
            policy_commit: era_commit(),
            direction: BalanceDirection::Credit,
            amount: 500,
        },
        BalanceDelta {
            policy_commit: [0xBB; 32],
            direction: BalanceDirection::Credit,
            amount: ERA_FAUCET_PAYOUT,
        },
        BalanceDelta {
            policy_commit: era_commit(),
            direction: BalanceDirection::Debit,
            amount: ERA_FAUCET_PAYOUT,
        },
    ] {
        let err = head
            .advance(
                rel,
                devid,
                op.clone(),
                std::slice::from_ref(&delta),
                Some(tip),
                None,
                None,
            )
            .expect_err("conservation must refuse");
        assert!(
            err.to_string().contains("conservation"),
            "must fail in conservation, got: {err}"
        );
    }
}

// ── Classifier ─────────────────────────────────────────────────────────────

#[test]
fn a_faucet_claim_is_a_closed_write_set() {
    assert_eq!(
        classify(&claim_op(era_reserve_id(NETWORK), 1)),
        EconomicEffect::ClosedWriteSet
    );
}

/// The beta fleet as a catalog resolves it: the network's canonical member
/// ids paired with the register incarnations those members are serving.
fn beta_candidate_set() -> dsm::ccb::StorageSetMembers {
    let pinned = dsm::economic::register::pinned_root_register_members(b"dsm-testnet")
        .expect("the beta network is known");
    dsm::ccb::StorageSetMembers::new(pinned).expect("pinned beta set")
}
