// SPDX-License-Identifier: Apache-2.0

//! Credit provenance: **why** a credit may appear.
//!
//! A closed write set proves what changed. Every mutation in a self-crediting
//! write set is individually well-formed, so "what changed" cannot distinguish
//! a funded credit from an invented one. These tests are about the difference.

#![allow(clippy::disallowed_methods)]

use dsm::economic::credit::{
    CreditSource, CreditSourceAuthorizedIssuance, CreditSourceValidatedPeerDebit,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    validated_peer_debit_source_id, verify_credit_source, verify_transition_provenance,
    FaucetTicketWin, ProvenanceContext, ProvenanceError, PeerLineageFailure, ProvenanceResolver,
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
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, dsm::economic::provenance::PeerLineageFailure> {
        Ok(crate::beta_candidate_set())
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
    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
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

const NETWORK: &[u8] = b"dsm-testnet";

/// The context every provenance call in this suite verifies under. The AK is
/// per-test where a signed claim exists; these fixtures use a placeholder.
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

// ── SourceId derivation ────────────────────────────────────────────────────

// ── The arms ───────────────────────────────────────────────────────────────

/// Issuance is resolvable NOW — class `0x0029` exists — but only against the
/// authenticated operation it authorizes.
///
/// This used to assert `IssuancePredicateUndefined`, encoding the absence that
/// also made the accepting layer refuse builtin issuance outright. That
/// absence is gone. What remains, and what this pins, is that the arm reads
/// its issuance coordinates from the VERIFIED SUCCESSOR and from nowhere else:
/// with no verified operation in context there is nothing to authorize
/// against, and a descriptor pointing at an evidence address cannot supply one.
/// A caller cannot hand the arm an assertion in place of the operation.
///
/// The honest path, the k-of-N threshold and every refusal conjunct are proven
/// on a real fixture in `economic_authorized_issuance.rs`.
#[test]
fn issuance_resolves_only_against_the_authenticated_operation() {
    let w = witness(
        vec![mutation(None, Some(bal(ERA, 100)))],
        vec![CreditSource::AuthorizedIssuance(
            CreditSourceAuthorizedIssuance {
                credit_mutation_index: 0,
                issuance_authorization_addr: [0xC7; 32],
            },
        )],
    );
    match verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64]))
        .unwrap_err()
    {
        ProvenanceError::AuthorizedIssuanceInvalid(m) => assert!(
            m.contains("verified operation"),
            "the refusal must name the missing verified operation, got: {m}"
        ),
        other => panic!("expected an issuance refusal, got {other:?}"),
    }
}

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

// ── 2c-H H9: the 0x0035 arm, before it fetches anything ────────────────────
