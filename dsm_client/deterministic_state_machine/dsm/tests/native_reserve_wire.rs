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
    era_reserve_id, release_constructible, release_evidence_addr, release_source_id,
    reserve_genesis_supply, sign_release, NativeReserveReleaseBody, NativeReserveState,
    ReleaseRefusal, ReleaseSource, ReserveHeadError, ReserveLineage, ERA_FAUCET_PAYOUT,
};
use dsm::economic::provenance::{
    verify_credit_source, PeerLineageFailure, ProvenanceContext, ProvenanceError,
    ProvenanceResolver, ReserveReleaseWin, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::shared_lineage::{EstablishedSharedHead, GenerationChain, LineageKind, SharedGenesisV1};
use dsm::types::operations::Operation;

const G: [u8; 32] = [0x11; 32];
const NETWORK: &[u8] = b"dsm-testnet";
const SET_ID: [u8; 32] = [0xB1; 32];

fn era_commit() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn keypair() -> (Vec<u8>, Vec<u8>) {
    dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
}

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

fn claim_op(reserve_id: [u8; 32], generation: u64) -> Operation {
    Operation::FaucetClaim {
        reserve_id,
        generation,
    }
}

fn genesis() -> NativeReserveState {
    NativeReserveState::genesis(NETWORK, SET_ID).expect("R_0")
}

/// A signed release succeeding the state at the end of `history`, plus the
/// witness of the transition it funds, built the way an honest claimant
/// builds them, with the reader's established heads before and after it.
struct Fixture {
    envelope: Vec<u8>,
    parent_head: EstablishedSharedHead,
    child_head: EstablishedSharedHead,
    witness: EconomicTransitionWitness,
    descriptor: CreditSourceNativeReserveRelease,
    pk: Vec<u8>,
}

/// The lineage of the reserve whose genesis is `genesis`, through the
/// releases `history` names, one a generation, each established by Core
/// from the head before it: what a reader's walk of those releases
/// established.
fn lineage_through(genesis: &NativeReserveState, history: &[Vec<u8>]) -> ReserveLineage {
    let mut lineage = ReserveLineage::from_genesis(genesis).expect("R_0");
    for envelope in history {
        lineage.establish(envelope).expect("the next generation");
    }
    lineage
}

/// The chain of [`lineage_through`].
fn chain_through(genesis: &NativeReserveState, history: &[Vec<u8>]) -> GenerationChain {
    lineage_through(genesis, history).chain().clone()
}

fn fixture_at(
    genesis: &NativeReserveState,
    history: &[Vec<u8>],
    position: u64,
    amount: u64,
) -> Fixture {
    let parent = genesis
        .at_generation(history.len() as u64)
        .expect("the state the history ends at");
    let (pk, sk) = trader().clone();
    let reserve_id = *parent.reserve_id();
    let generation = parent.generation() + 1;
    let op = claim_op(reserve_id, generation);
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let release_of = |amount: u64| {
        sign_release(
            &NativeReserveReleaseBody {
                reserve_id,
                parent_root: parent.root(),
                generation,
                amount,
                recipient_genesis: G,
                recipient_devid: *dev(),
                recipient_economic_position: position,
                recipient_operation_digest: op_digest,
                storage_set_id: SET_ID,
                source: ReleaseSource::FaucetClaimant {
                    claimant_public_key: pk.clone(),
                    claimant_att_a: ATTA,
                },
            },
            &sk,
        )
        .expect("signable")
    };
    let envelope = release_of(amount);

    // The credited transition: empty tree -> +amount ERA.
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = EconomicLeafState::Balance(
        EconomicBalanceState::new(era_commit(), amount).expect("nonzero"),
    );
    let key = credit.leaf_key(&G, dev());
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

    // The heads a reader holds once its walk passed this release: the
    // lineage through the history, and this release established on it. A
    // release of another amount is no successor Core establishes; the
    // reader's chain then holds the honest release of that generation.
    let mut lineage = lineage_through(genesis, history);
    let parent_head = lineage.chain().head();
    let child_head = match lineage.establish(&envelope) {
        Ok(next) => *next.head(),
        Err(..) => *lineage
            .establish(&release_of(ERA_FAUCET_PAYOUT))
            .expect("the honest release of the generation")
            .head(),
    };
    Fixture {
        envelope,
        parent_head,
        child_head,
        witness,
        descriptor,
        pk,
    }
}

fn fixture(position: u64) -> Fixture {
    fixture_at(&genesis(), &[], position, ERA_FAUCET_PAYOUT)
}

/// A resolver whose walk of the reserve established exactly one final
/// release, at `generation`, between the heads `parent` and `child`.
struct OneRelease {
    reserve_id: [u8; 32],
    generation: u64,
    envelope: Vec<u8>,
    parent: EstablishedSharedHead,
    child: EstablishedSharedHead,
}

impl OneRelease {
    fn of(fx: &Fixture) -> Self {
        Self {
            reserve_id: fx.descriptor.reserve_id,
            generation: fx.descriptor.generation,
            envelope: fx.envelope.clone(),
            parent: fx.parent_head,
            child: fx.child_head,
        }
    }
}

impl ProvenanceResolver for OneRelease {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        if network_id != dsm::economic::register::BETA_NETWORK_ID {
            return Err(PeerLineageFailure::Incomplete(format!(
                "no register set for network {network_id:?} in this fixture"
            )));
        }
        Ok(beta_candidate_set())
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
        if *reserve_id != self.reserve_id || generation != self.generation {
            return Err(PeerLineageFailure::Incomplete(format!(
                "this fixture's walk reached generation {} only, not {generation} of {reserve_id:?}",
                self.generation
            )));
        }
        Ok(ReserveReleaseWin {
            envelope_bytes: self.envelope.clone(),
            parent: self.parent,
            child: self.child,
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

/// A resolver whose walk reached no release at all.
struct Nothing;

impl ProvenanceResolver for Nothing {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        if network_id != dsm::economic::register::BETA_NETWORK_ID {
            return Err(PeerLineageFailure::Incomplete(format!(
                "no register set for network {network_id:?} in this fixture"
            )));
        }
        Ok(beta_candidate_set())
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
        Err(PeerLineageFailure::Incomplete(format!(
            "no reserve release in this fixture: generation {generation} of {reserve_id:?}"
        )))
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

fn ctx<'a>(position: u64, ak: &'a [u8]) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G,
        device_id: dev(),
        economic_position: position,
        network_id: NETWORK,
        proven_ak: ak,
        canonical_storage_set_id: SET_ID,
        substrate_b_pair: None,
        verified_operation: None,
        offline_boundary: None,
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
    assert_eq!(funded.amount(), ERA_FAUCET_PAYOUT);
    assert_eq!(*funded.policy_commit(), era_commit());
    assert_eq!(
        *funded.source_id(),
        release_source_id(&fx.descriptor.reserve_id, fx.descriptor.generation)
    );
}

/// `total ERA conserved` through the verifier: every credit a walked lineage
/// funds is exactly what the reserve gave up, and the reserve's own state is
/// what the walk computed — `S_genesis = remaining + Σ credited`.
#[test]
fn credits_funded_along_a_lineage_sum_to_what_the_reserve_released() {
    let r0 = genesis();
    let mut parent = r0;
    let mut history = Vec::new();
    let mut credited = 0u64;
    for position in 1u64..=3 {
        let fx = fixture_at(&r0, &history, position, ERA_FAUCET_PAYOUT);
        let funded = verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(position, &fx.pk),
        )
        .expect("each release funds its credit");
        credited += funded.amount();
        let release = dsm::economic::native_reserve::decode_and_verify_release(&fx.envelope)
            .expect("verifies");
        parent = release_constructible(&parent, &release).expect("the walk's next state");
        history.push(fx.envelope.clone());
        assert_eq!(
            parent.remaining_supply() + credited,
            reserve_genesis_supply().expect("ERA's genesis supply")
        );
    }
    assert_eq!(parent.generation(), 3);

    // A release of any other amount funds nothing: it is not a release the
    // claim policy allows, so it never became the reserve's successor.
    let off_rule = fixture_at(&r0, &history, 4, 7);
    assert!(verify_credit_source(
        &off_rule.witness.credit_sources[0],
        &off_rule.witness,
        &OneRelease::of(&off_rule),
        &ctx(4, &off_rule.pk),
    )
    .is_err());
}

/// `no valid reserve transition can mint ERA`, at the verifier: a release
/// that is not the successor of the state at the reader's established head
/// before it funds nothing. Here one that releases twice what the release
/// rule allows, and then an honest release presented against a head five
/// generations on, whose state it does not succeed. Remove the successor
/// check from the arm and this goes red.
///
/// A release of more than the reserve holds is possible only at its last
/// generation, which no reader's head reaches in a test (a chain of about
/// 8 × 10^8 releases). That refusal is the construction predicate's,
/// which `EstablishedReserve::succeeded_by` runs for every release the
/// verifier accepts; it is tested in Core
/// (`a_claim_at_exhaustion_is_refused_before_a_release_is_signed`).
#[test]
fn a_release_that_is_not_its_parents_successor_funds_nothing() {
    let r0 = genesis();
    let fx = fixture_at(&r0, &[], 1, 2 * ERA_FAUCET_PAYOUT);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &OneRelease::of(&fx),
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseNotTheSuccessor(
            ReserveHeadError::NotASuccessor(ReleaseRefusal::NotTheReleaseRulesAmount { .. })
        ))
    ));
    // The same honest bytes presented against a head whose state they do not
    // succeed: another state of the lineage, five real releases on.
    let mut history = Vec::new();
    for position in 1..=5 {
        history.push(fixture_at(&r0, &history, position, ERA_FAUCET_PAYOUT).envelope);
    }
    let later = chain_through(&r0, &history).head();
    let fx = fixture(1);
    let resolver = OneRelease {
        parent: later,
        ..OneRelease::of(&fx)
    };
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseNotTheSuccessor(
            ReserveHeadError::NotASuccessor(ReleaseRefusal::ParentRootMismatch)
        ))
    ));
}

/// DSM Amendment A15, MR-DSM-0315: the verifier takes the reserve's state
/// only from the reader's established heads. A parent head that is not a
/// state of this reserve funds nothing (here a vault lineage's head under
/// the reserve's id), and neither does a release that is not the step
/// between the heads: here the reader's chain holds another release at that
/// generation, its own next state's root the same. A reserve head whose
/// root is not the state at its generation cannot be built outside Core:
/// only Core extends a reserve chain (`ReserveLineage::establish`), and
/// `EstablishedReserve::of` refusing one is Core's own test
/// (`a_reserve_state_is_taken_only_from_a_head_of_this_reserve`).
///
/// MUTATION CONTROL: dropping the child-head comparison in the arm turns the
/// step assertion red.
#[test]
fn a_reserve_credit_is_checked_against_the_readers_established_heads() {
    let r0 = genesis();
    let fx = fixture(1);
    let vault = GenerationChain::from_genesis(&SharedGenesisV1::new(
        LineageKind::Vault,
        *r0.reserve_id(),
        r0.root(),
        [0x2F; 32],
    ));
    let resolver = OneRelease {
        parent: vault.head(),
        ..OneRelease::of(&fx)
    };
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseParentNotOnTheReserve(
            ReserveHeadError::NotThisReserve
        ))
    ));

    // Another honest release at generation 1, for position 2: the reader's
    // chain holds it, not this credit's release.
    let other = fixture_at(&r0, &[], 2, ERA_FAUCET_PAYOUT);
    let resolver = OneRelease {
        child: other.child_head,
        ..OneRelease::of(&fx)
    };
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk),
        ),
        Err(ProvenanceError::ReleaseIsNotTheEstablishedStep { generation: 1 })
    ));
}

/// THE stop-the-line control. Everything about this release is internally
/// consistent — signed, its parent fits, evidence address matches — except
/// the reserve id is an INVENTED one. If only descriptor==release were
/// checked, each invented id would be a second genesis supply.
#[test]
fn wrong_reserve_id_cannot_create_a_second_genesis_supply() {
    let other = NativeReserveState::genesis(b"another-network", SET_ID).expect("R_0");
    assert_ne!(other.reserve_id(), genesis().reserve_id());
    let fx = fixture_at(&other, &[], 1, ERA_FAUCET_PAYOUT);
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
    let op = claim_op(*parent.reserve_id(), 1);
    let paid_to_someone_else = sign_release(
        &NativeReserveReleaseBody {
            reserve_id: *parent.reserve_id(),
            parent_root: parent.root(),
            generation: 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: [0x66; 32],
            recipient_devid: dsm::core::identity::genesis_v2::derive_devid(&pk, &ATTA),
            recipient_economic_position: 1,
            recipient_operation_digest: dsm_operation_digest(&op.to_bytes()),
            storage_set_id: SET_ID,
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk.clone(),
                claimant_att_a: ATTA,
            },
        },
        &sk,
    )
    .expect("signable");
    // The reader's chain holds that release at generation 1.
    let chain = chain_through(&genesis(), std::slice::from_ref(&paid_to_someone_else));
    let resolver = OneRelease {
        envelope: paid_to_someone_else.clone(),
        child: chain.head(),
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

/// A release won in a register other than the network's canonical one funds
/// nothing. The verifier's genesis commits the canonical set, so a head the
/// reader holds under another set is not a state of the reserve; and on a
/// canonical head, a release naming another set is no successor.
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
        Err(ProvenanceError::ReleaseParentNotOnTheReserve(
            ReserveHeadError::RootIsNotTheState { generation: 0 }
        ))
    ));

    // On the canonical head, a release that names another set.
    let r0 = genesis();
    let (pk, sk) = trader().clone();
    let op = claim_op(*r0.reserve_id(), 1);
    let foreign = sign_release(
        &NativeReserveReleaseBody {
            reserve_id: *r0.reserve_id(),
            parent_root: r0.root(),
            generation: 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: G,
            recipient_devid: *dev(),
            recipient_economic_position: 1,
            recipient_operation_digest: dsm_operation_digest(&op.to_bytes()),
            storage_set_id: [0x77; 32],
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
                claimant_att_a: ATTA,
            },
        },
        &sk,
    )
    .expect("signable");
    let resolver = OneRelease {
        envelope: foreign.clone(),
        ..OneRelease::of(&fx)
    };
    let mut descriptor = fx.descriptor.clone();
    descriptor.release_evidence_addr = release_evidence_addr(&foreign);
    assert!(matches!(
        verify_credit_source(
            &CreditSource::NativeReserveRelease(descriptor),
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::ReleaseNotTheSuccessor(
            ReserveHeadError::NotASuccessor(ReleaseRefusal::ForeignSet)
        ))
    ));
}

/// A resolver that counts every read of the reserve's lineage.
struct Counting {
    inner: OneRelease,
    reads: std::cell::Cell<usize>,
}

impl ProvenanceResolver for Counting {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        self.inner.root_register_candidate_set(network_id)
    }

    fn validated_peer_transition(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        self.inner
            .validated_peer_transition(genesis, device_id, position)
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.reads.set(self.reads.get() + 1);
        self.inner.native_reserve_release(reserve_id, generation)
    }

    fn immutable_evidence(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.inner.immutable_evidence(namespace, addr)
    }

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.inner.held_ek_step(signer, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.inner.anchored_policy_bytes(policy_commit)
    }
}

/// MR-STOR-0045: what a reserve-funded credit decides from its descriptor
/// alone — that it names the network's canonical reserve, at a generation
/// past the genesis — is decided before the reserve's lineage is read, so a
/// descriptor refused in hand causes no read. The canonical descriptor is
/// read, once, and funds.
/// MUTATION CONTROL: reading the release before the canonical-id check
/// turns this red.
#[test]
fn a_descriptor_refused_in_hand_reads_nothing_of_the_reserve() {
    let counting = |fx: &Fixture| Counting {
        inner: OneRelease::of(fx),
        reads: std::cell::Cell::new(0),
    };

    let other = NativeReserveState::genesis(b"another-network", SET_ID).expect("R_0");
    let fx = fixture_at(&other, &[], 1, ERA_FAUCET_PAYOUT);
    let resolver = counting(&fx);
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::NotTheCanonicalReserve { .. })
    ));
    assert_eq!(resolver.reads.get(), 0, "another reserve is not read");

    let fx = fixture(1);
    let mut d = fx.descriptor.clone();
    d.generation = 0;
    let resolver = counting(&fx);
    assert!(matches!(
        verify_credit_source(
            &CreditSource::NativeReserveRelease(d),
            &fx.witness,
            &resolver,
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::GenerationIsGenesis)
    ));
    assert_eq!(
        resolver.reads.get(),
        0,
        "the genesis is not read as a release"
    );

    let resolver = counting(&fx);
    let funded = verify_credit_source(
        &fx.witness.credit_sources[0],
        &fx.witness,
        &resolver,
        &ctx(1, &fx.pk),
    )
    .expect("the canonical release funds the credit");
    assert_eq!(funded.amount(), ERA_FAUCET_PAYOUT);
    assert_eq!(
        resolver.reads.get(),
        1,
        "the canonical release is read once"
    );
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
    let head = DeviceState::genesis_head([0x44u8; 32], devid, vec![0xAA; 32]);
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid, &devid);
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
            .advance(rel, devid, op.clone(), std::slice::from_ref(&delta), None)
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
