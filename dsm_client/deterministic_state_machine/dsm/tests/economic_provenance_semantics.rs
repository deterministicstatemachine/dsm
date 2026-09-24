// SPDX-License-Identifier: Apache-2.0

//! Credit provenance: **why** a credit may appear.
//!
//! A closed write set proves what changed. Every mutation in a self-crediting
//! write set is individually well-formed, so "what changed" cannot distinguish
//! a funded credit from an invented one. These tests are about the difference.

#![allow(clippy::disallowed_methods)]

use dsm::economic::credit::{CreditSource, CreditSourceGenesisRelease, CreditSourceValidatedPeerDebit};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    validated_peer_debit_source_id, verify_credit_source, verify_transition_provenance,
    ReserveReleaseWin, ProvenanceContext, ProvenanceError, PeerLineageFailure, ProvenanceResolver,
    ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState};
use dsm::economic::tree::ECONOMIC_SMT_HEIGHT;
use dsm::economic::witness::EconomicTransitionWitness;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const ERA: [u8; 32] = [0xAA; 32];
const OP_ID: [u8; 32] = [0x0E; 32];

struct NoPeers;
impl ProvenanceResolver for NoPeers {
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

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(format!(
            "this fixture roots no token anchors: {policy_commit:?}"
        )))
    }
}

const NETWORK: &[u8] = b"dsm-testnet";

/// The context every provenance call in this suite verifies under. `ak` is
/// the claimant key a release is checked against; the arms under test here
/// read no signature.
fn ctx<'a>(position: u64, ak: &'a [u8]) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G,
        device_id: &DEV,
        economic_position: position,
        network_id: NETWORK,
        proven_ak: ak,
        canonical_storage_set_id: [0xB1; 32],
        substrate_b_pair: None,
        verified_operation: None,
    }
}

fn sibs() -> Vec<[u8; 32]> {
    vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT]
}

fn bal(pc: [u8; 32], amount: u64) -> EconomicLeafState {
    EconomicLeafState::Balance(EconomicBalanceState::new(pc, amount).expect("nonzero"))
}

fn mutation(
    pre: Option<EconomicLeafState>,
    post: Option<EconomicLeafState>,
) -> EconomicLeafMutation {
    EconomicLeafMutation::new(pre, post, sibs()).expect("well-formed")
}

fn witness(
    mutations: Vec<EconomicLeafMutation>,
    sources: Vec<CreditSource>,
) -> EconomicTransitionWitness {
    EconomicTransitionWitness::new([1; 32], [2; 32], OP_ID, [4; 32], mutations, sources)
        .expect("structurally valid")
}

// ── The arms ───────────────────────────────────────────────────────────────

#[test]
fn an_unvalidated_peer_debit_fails_closed() {
    // NOT a failure of the peer — a failure of THIS verifier to have
    // established the prerequisite. A credit is not funded by a debit nobody
    // has checked, so the absence of an answer is a refusal, not a pass.
    let w = witness(
        vec![
            mutation(None, Some(bal(ERA, 30))),
            mutation(
                None,
                Some(EconomicLeafState::ConsumedSource(
                    EconomicConsumedSourceState {
                        source_id: validated_peer_debit_source_id(&G, &DEV, 4, 0),
                        consumer_economic_operation_id: OP_ID,
                    },
                )),
            ),
        ],
        vec![CreditSource::ValidatedPeerDebit(
            CreditSourceValidatedPeerDebit {
                credit_mutation_index: 0,
                peer_genesis: G,
                peer_devid: DEV,
                peer_economic_position: 4,
                peer_debit_mutation_index: 0,
                acceptance_evidence_addr: [0x44; 32],
            },
        )],
    );
    match verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64]))
        .unwrap_err()
    {
        ProvenanceError::PeerTransitionNotValidated {
            peer_economic_position: 4,
            failure: PeerLineageFailure::Incomplete(_),
        } => {}
        other => panic!("expected unresolved peer transition, got {other:?}"),
    }
}

// ── Consumed-source records ────────────────────────────────────────────────

#[test]
fn a_transition_with_no_credits_needs_no_provenance() {
    let w = witness(
        vec![mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70)))],
        Vec::new(),
    );
    assert!(
        verify_transition_provenance(&w, &NoPeers, &ctx(1, &[0xAB; 64]))
            .expect("a pure debit is funded by nothing")
            .is_empty()
    );
}

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

// ── Genesis release (0x005F, SoFi §51, Amendment S8) ───────────────────────

/// A resolver whose only rooted anchor is one token policy.
struct Anchors(Vec<u8>);
impl ProvenanceResolver for Anchors {
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
        NoPeers.root_register_candidate_set(network_id)
    }
    fn validated_peer_transition(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        NoPeers.validated_peer_transition(genesis, device_id, position)
    }
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        NoPeers.native_reserve_release(reserve_id, generation)
    }
    fn immutable_evidence(
        &self,
        namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        NoPeers.immutable_evidence(namespace, addr)
    }
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        if *policy_commit == policy_commit_of(&self.0) {
            Ok(self.0.clone())
        } else {
            NoPeers.anchored_policy_bytes(policy_commit)
        }
    }
}

/// `TokenPolicyV3` bytes of a native token created by `creator`, laid out as
/// SoFi §47 packs it.
fn native_policy(creator: ([u8; 32], [u8; 32]), release_rule: u8, supply: u128) -> Vec<u8> {
    let mut blob = vec![3, 0, 0, 0x02, release_rule];
    blob.extend_from_slice(&creator.0);
    blob.extend_from_slice(&creator.1);
    blob.extend_from_slice(&[1, 1]);
    blob.extend_from_slice(&3u16.to_be_bytes());
    blob.extend_from_slice(b"key");
    blob.push(3);
    blob.extend_from_slice(b"TKN");
    blob.extend_from_slice(&5u16.to_be_bytes());
    blob.extend_from_slice(b"Token");
    blob.push(0);
    blob.extend_from_slice(&supply.to_be_bytes());
    blob.extend_from_slice(&0u16.to_be_bytes());
    blob.extend_from_slice(&0u16.to_be_bytes());
    blob.push(0);
    blob.extend_from_slice(&0u16.to_be_bytes());
    prost::Message::encode_to_vec(&dsm::types::proto::TokenPolicyV3 { policy_bytes: blob })
}

fn policy_commit_of(bytes: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, bytes)
}

fn create_token(policy_commit: [u8; 32], supply: u64) -> dsm::types::operations::Operation {
    dsm::types::operations::Operation::CreateToken {
        token_id: b"TKN".to_vec(),
        initial_supply: dsm::types::token_types::Balance::amount(supply),
        policy_commit,
        fee_amount: 0,
        name: "Token".into(),
        symbol: "TKN".into(),
        decimals: 0,
        metadata_uri: None,
        signature: Vec::new(),
    }
}

/// One credit of `amount` of `policy_commit`, funded by a genesis release.
fn release_witness(policy_commit: [u8; 32], amount: u64) -> EconomicTransitionWitness {
    witness(
        vec![mutation(None, Some(bal(policy_commit, amount)))],
        vec![CreditSource::GenesisRelease(CreditSourceGenesisRelease {
            credit_mutation_index: 0,
        })],
    )
}

const RELEASE_AT_CREATION: u8 = 0;
const FAUCET_RELEASE: u8 = 1;

fn verify_release(
    anchors: &Anchors,
    witness: &EconomicTransitionWitness,
    operation: Option<&dsm::types::operations::Operation>,
) -> Result<dsm::economic::provenance::FundedCredit, ProvenanceError> {
    let ak = [0xAB; 64];
    let context = ProvenanceContext {
        verified_operation: operation,
        ..ctx(4, &ak)
    };
    verify_credit_source(&witness.credit_sources[0], witness, anchors, &context)
}

#[test]
fn a_genesis_release_funds_its_creators_whole_supply() {
    let policy = native_policy((G, DEV), RELEASE_AT_CREATION, 1_000);
    let pc = policy_commit_of(&policy);
    let op = create_token(pc, 1_000);
    let funded = verify_release(&Anchors(policy), &release_witness(pc, 1_000), Some(&op))
        .expect("the creator's release of the whole supply");
    assert_eq!((funded.policy_commit, funded.amount), (pc, 1_000));
    assert_eq!(
        funded.source_id,
        dsm::economic::provenance::genesis_release_source_id(&G, &DEV, 4, &pc)
    );
}

/// Amendment S8: a policy names its creator, and only the creator's own
/// transition releases its supply. Anyone else holding the same bytes
/// releases nothing.
#[test]
fn a_genesis_release_of_another_creators_policy_is_refused() {
    for creator in [([0x99; 32], DEV), (G, [0x98; 32])] {
        let policy = native_policy(creator, RELEASE_AT_CREATION, 1_000);
        let pc = policy_commit_of(&policy);
        let op = create_token(pc, 1_000);
        match verify_release(&Anchors(policy), &release_witness(pc, 1_000), Some(&op)) {
            Err(ProvenanceError::GenesisReleaseInvalid(m)) => {
                assert!(m.contains("another creator"), "{m}")
            }
            other => panic!("expected the creator refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_genesis_release_rides_only_its_creating_operation() {
    let policy = native_policy((G, DEV), RELEASE_AT_CREATION, 1_000);
    let pc = policy_commit_of(&policy);
    let burn = dsm::types::operations::Operation::Burn {
        amount: dsm::types::token_types::Balance::amount(1),
        token_id: b"TKN".to_vec(),
        policy_commit: pc,
        proof_of_ownership: Vec::new(),
        message: String::new(),
    };
    for operation in [None, Some(&burn)] {
        assert!(matches!(
            verify_release(
                &Anchors(policy.clone()),
                &release_witness(pc, 1_000),
                operation
            ),
            Err(ProvenanceError::GenesisReleaseInvalid(_))
        ));
    }
}

#[test]
fn a_genesis_release_needs_the_all_at_creation_rule() {
    let policy = native_policy((G, DEV), FAUCET_RELEASE, 1_000);
    let pc = policy_commit_of(&policy);
    let op = create_token(pc, 1_000);
    assert!(matches!(
        verify_release(&Anchors(policy), &release_witness(pc, 1_000), Some(&op)),
        Err(ProvenanceError::GenesisReleaseInvalid(_))
    ));
}

#[test]
fn a_genesis_release_credits_exactly_the_genesis_supply() {
    let policy = native_policy((G, DEV), RELEASE_AT_CREATION, 1_000);
    let pc = policy_commit_of(&policy);
    let op = create_token(pc, 999);
    assert_eq!(
        verify_release(&Anchors(policy), &release_witness(pc, 999), Some(&op)),
        Err(ProvenanceError::AmountMismatch {
            source: 1_000,
            credit: 999
        })
    );
}

/// Bytes served under a commit they do not hash to are not the policy: they
/// supply nothing, and the release is not established on them.
#[test]
fn policy_bytes_that_are_not_the_commit_establish_nothing() {
    let policy = native_policy((G, DEV), RELEASE_AT_CREATION, 1_000);
    let pc = policy_commit_of(&policy);
    let op = create_token(pc, 1_000);
    let other = native_policy((G, DEV), RELEASE_AT_CREATION, 2_000);
    struct Wrong(Vec<u8>);
    impl ProvenanceResolver for Wrong {
        fn root_register_candidate_set(
            &self,
            network_id: &[u8],
        ) -> Result<dsm::ccb::StorageSetMembers, PeerLineageFailure> {
            NoPeers.root_register_candidate_set(network_id)
        }
        fn validated_peer_transition(
            &self,
            genesis: &[u8; 32],
            device_id: &[u8; 32],
            position: u64,
        ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
            NoPeers.validated_peer_transition(genesis, device_id, position)
        }
        fn native_reserve_release(
            &self,
            reserve_id: &[u8; 32],
            generation: u64,
        ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
            NoPeers.native_reserve_release(reserve_id, generation)
        }
        fn immutable_evidence(
            &self,
            namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
            addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            NoPeers.immutable_evidence(namespace, addr)
        }
        fn anchored_policy_bytes(
            &self,
            policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            assert_ne!(policy_commit_of(&self.0), *policy_commit);
            Ok(self.0.clone())
        }
    }
    let ak = [0xAB; 64];
    let context = ProvenanceContext {
        verified_operation: Some(&op),
        ..ctx(4, &ak)
    };
    let w = release_witness(pc, 1_000);
    assert!(matches!(
        verify_credit_source(&w.credit_sources[0], &w, &Wrong(other), &context),
        Err(ProvenanceError::GenesisReleasePolicy(
            PeerLineageFailure::Incomplete(_)
        ))
    ));
}
