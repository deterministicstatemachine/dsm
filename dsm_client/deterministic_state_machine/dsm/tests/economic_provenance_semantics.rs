// SPDX-License-Identifier: Apache-2.0

//! Credit provenance: **why** a credit may appear.
//!
//! A closed write set proves what changed. Every mutation in a self-crediting
//! write set is individually well-formed, so "what changed" cannot distinguish
//! a funded credit from an invented one. These tests are about the difference.

#![allow(clippy::disallowed_methods)]

use dsm::economic::credit::{
    CreditSource, CreditSourceAuthorizedIssuance, CreditSourceSameTransitionMove,
    CreditSourceValidatedPeerDebit,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    same_transition_move_source_id, validated_peer_debit_source_id, verify_credit_source,
    verify_transition_provenance, FaucetTicketWin, ProvenanceContext, ProvenanceError,
    ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState, EconomicVaultReserveState,
};
use dsm::economic::tree::ECONOMIC_SMT_HEIGHT;
use dsm::economic::witness::EconomicTransitionWitness;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const ERA: [u8; 32] = [0xAA; 32];
const SOFI: [u8; 32] = [0xBB; 32];
const OP_ID: [u8; 32] = [0x0E; 32];
const VAULT: [u8; 32] = [0xCC; 32];

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
    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
        None
    }
}

const NETWORK: &[u8] = b"mainnet";

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
    }
}

fn sibs() -> Vec<[u8; 32]> {
    vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT]
}

fn bal(pc: [u8; 32], amount: u64) -> EconomicLeafState {
    EconomicLeafState::Balance(EconomicBalanceState::new(pc, amount).expect("nonzero"))
}

fn reserve(vault_id: [u8; 32], pc: [u8; 32], amount: u64) -> EconomicLeafState {
    EconomicLeafState::VaultReserve(EconomicVaultReserveState {
        vault_id,
        policy_commit: pc,
        amount,
        vault_sequence: 0,
    })
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

/// Debit 30 ERA from the balance at index 0, credit it into a vault reserve
/// at index 1, funded by the same-transition move.
///
/// `SameTransitionMove` is a **move, not a swap**: it relocates the SAME asset
/// — the `DlvCreateFundedV2` shape, where balance becomes encumbered reserve.
/// A cross-asset "move" is refused, and that refusal has its own test below.
fn move_witness(credit_amount: u64) -> EconomicTransitionWitness {
    witness(
        vec![
            mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70))),
            mutation(None, Some(reserve(VAULT, ERA, credit_amount))),
        ],
        vec![CreditSource::SameTransitionMove(
            CreditSourceSameTransitionMove {
                credit_mutation_index: 1,
                debit_mutation_index: 0,
            },
        )],
    )
}

// ── SourceId derivation ────────────────────────────────────────────────────

#[test]
fn source_ids_are_derived_and_distinguish_what_they_should() {
    // Same inputs, same id — so one underlying debit yields one id however
    // often it is presented, which is what makes "no source funds two credits"
    // checkable at all.
    assert_eq!(
        same_transition_move_source_id(&OP_ID, 0),
        same_transition_move_source_id(&OP_ID, 0)
    );
    // Different debit inside one operation is a different source.
    assert_ne!(
        same_transition_move_source_id(&OP_ID, 0),
        same_transition_move_source_id(&OP_ID, 1)
    );
    // The SAME mutation index in a DIFFERENT operation is a different source.
    // Without operation scoping, two transitions would collide in the
    // consumed-source space.
    assert_ne!(
        same_transition_move_source_id(&OP_ID, 0),
        same_transition_move_source_id(&[0x0F; 32], 0)
    );

    // Peer coordinates name exactly one debit in exactly one validated
    // transition; every component must matter.
    let base = validated_peer_debit_source_id(&G, &DEV, 4, 1);
    assert_ne!(
        base,
        validated_peer_debit_source_id(&[0x99; 32], &DEV, 4, 1)
    );
    assert_ne!(base, validated_peer_debit_source_id(&G, &[0x99; 32], 4, 1));
    assert_ne!(base, validated_peer_debit_source_id(&G, &DEV, 5, 1));
    assert_ne!(base, validated_peer_debit_source_id(&G, &DEV, 4, 2));

    // And the two source classes never collide.
    assert_ne!(base, same_transition_move_source_id(&OP_ID, 1));
}

// ── The arms ───────────────────────────────────────────────────────────────

#[test]
fn an_intra_transition_move_is_funded_by_its_own_debit() {
    let w = move_witness(30);
    let funded = verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64]))
        .expect("the debit funds it");
    assert_eq!(funded.amount, 30);
    assert_eq!(funded.policy_commit, ERA);
    assert_eq!(
        funded.source_id,
        same_transition_move_source_id(&OP_ID, 0),
        "derived from the operation and the debit index, never supplied"
    );
}

#[test]
fn a_source_must_fund_this_credit_not_merely_exist() {
    // A real debit of 30 cannot fund a credit of 500. This is where a
    // plausible-looking provenance object stops being sufficient.
    let w = move_witness(500);
    assert_eq!(
        verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64])).unwrap_err(),
        ProvenanceError::AmountMismatch {
            source: 30,
            credit: 500
        }
    );

    // The negative control for the check above: same asset, same amount, so
    // it must succeed. Without this the AmountMismatch assertion could be
    // passing for some unrelated reason.
    let ok = move_witness(30);
    assert!(
        verify_credit_source(&ok.credit_sources[0], &ok, &NoPeers, &ctx(1, &[0xAB; 64])).is_ok()
    );
}

#[test]
fn an_asset_mismatch_is_refused() {
    // Debit SOFI, credit ERA, claiming the SOFI debit funds it.
    let w = witness(
        vec![
            mutation(Some(bal(SOFI, 100)), Some(bal(SOFI, 70))),
            mutation(None, Some(bal(ERA, 30))),
        ],
        vec![CreditSource::SameTransitionMove(
            CreditSourceSameTransitionMove {
                credit_mutation_index: 1,
                debit_mutation_index: 0,
            },
        )],
    );
    assert!(matches!(
        verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64])),
        Err(ProvenanceError::AssetMismatch { .. })
    ));
}

#[test]
fn authorized_issuance_cannot_be_resolved_by_anyone() {
    // The same absence that makes the accepting layer refuse builtin ERA/dBTC
    // issuance. Class 0x0029 stays reserved because writing its field table
    // would encode a "who may issue what" rule this protocol does not have —
    // and a credit is not funded by an object nobody can check.
    let w = witness(
        vec![mutation(None, Some(bal(ERA, 100)))],
        vec![CreditSource::AuthorizedIssuance(
            CreditSourceAuthorizedIssuance {
                credit_mutation_index: 0,
                issuance_authorization_addr: [0xC7; 32],
            },
        )],
    );
    assert_eq!(
        verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64])).unwrap_err(),
        ProvenanceError::IssuancePredicateUndefined
    );
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
    assert_eq!(
        verify_credit_source(&w.credit_sources[0], &w, &NoPeers, &ctx(1, &[0xAB; 64])).unwrap_err(),
        ProvenanceError::PeerTransitionNotValidated {
            peer_economic_position: 4
        }
    );
}

// ── Consumed-source records ────────────────────────────────────────────────

#[test]
fn an_intra_transition_move_needs_no_consumed_source_record() {
    // Its debit is inside the same write set, so it is consumed by
    // construction and could never be presented again. Demanding a record
    // would be bookkeeping for an impossibility.
    let w = move_witness(30);
    let funded = verify_transition_provenance(&w, &NoPeers, &ctx(1, &[0xAB; 64])).expect("funded");
    assert_eq!(funded.len(), 1);
}

#[test]
fn duplicate_source_ids_are_refused() {
    // Two credits, both claiming the SAME debit funds them. Each source is
    // individually well-formed and the amounts even match; only the derived
    // ids reveal that one debit is being spent twice.
    let w = witness(
        vec![
            mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70))),
            mutation(None, Some(reserve(VAULT, ERA, 30))),
            mutation(None, Some(reserve([0xDD; 32], ERA, 30))),
        ],
        vec![
            CreditSource::SameTransitionMove(CreditSourceSameTransitionMove {
                credit_mutation_index: 1,
                debit_mutation_index: 0,
            }),
            CreditSource::SameTransitionMove(CreditSourceSameTransitionMove {
                credit_mutation_index: 2,
                debit_mutation_index: 0,
            }),
        ],
    );
    assert_eq!(
        verify_transition_provenance(&w, &NoPeers, &ctx(1, &[0xAB; 64])).unwrap_err(),
        ProvenanceError::DuplicateSourceId
    );
}

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
