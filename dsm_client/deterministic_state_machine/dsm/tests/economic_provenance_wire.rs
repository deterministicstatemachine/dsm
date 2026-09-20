// SPDX-License-Identifier: Apache-2.0

//! Wire conformance for the provenance freeze: the six credit-source
//! descriptors, `0x001D`, and the manifest's derived provenance index.
//!
//! The rules under test are the ones a verifier can check **before fetching a
//! single provenance blob** — ordering, indices, and the credit/source
//! bijection. None of this asks whether a named source actually establishes
//! the units it claims; that is acceptance semantics and is not implemented.

#![allow(clippy::disallowed_methods)]

use dsm::ccb::decode::DecodeError;
use dsm::ccb::{CcbError, CcbObject};
use dsm::economic::credit::{CreditSource, CreditSourceVerifiedOfflineReentry};
use dsm::economic::decode::decode_leaf_state;
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::ECONOMIC_SMT_HEIGHT;
use dsm::economic::witness::EconomicTransitionWitness;

const ERA: [u8; 32] = [0xAA; 32];
const SOFI: [u8; 32] = [0xBB; 32];

fn sibs() -> Vec<[u8; 32]> {
    // The witness's structural rules are independent of Merkle paths; the
    // sequential verifier is what checks those, and it has its own suite.
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

/// debit ERA 100 -> 70 (index 0), credit SOFI 0 -> 25 (index 1).
fn debit_then_credit() -> Vec<EconomicLeafMutation> {
    vec![
        mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70))),
        mutation(None, Some(bal(SOFI, 25))),
    ]
}

fn witness(
    mutations: Vec<EconomicLeafMutation>,
    sources: Vec<CreditSource>,
) -> Result<EconomicTransitionWitness, CcbError> {
    EconomicTransitionWitness::new([1; 32], [2; 32], [3; 32], [4; 32], mutations, sources)
}

// ── The positive-credit predicate, which the bijection rests on ────────────

// ── The frozen structural rules ────────────────────────────────────────────

#[test]
fn a_credit_with_no_source_is_refused() {
    // THE property of this layer. The write set is internally fine — a debit
    // and a credit — and the credit is simply unfunded.
    assert_eq!(
        witness(debit_then_credit(), vec![]).unwrap_err(),
        CcbError::UnfundedCredit { mutation_index: 1 }
    );
}

#[test]
fn an_offline_reentry_cannot_consume_its_own_boundary() {
    // Deriving the source from the terminal state instead of the PRIOR
    // checkpoint is the inflation bug: two forks derive two ids and both
    // reenter. The wire refuses the degenerate form of that mistake.
    let source = CreditSource::VerifiedOfflineReentry(CreditSourceVerifiedOfflineReentry {
        credit_mutation_index: 1,
        prior_boundary_id: [0x5A; 32],
        unload_boundary_id: [0x5A; 32],
        branch_evidence_addr: [0x6B; 32],
    });
    let w = witness(debit_then_credit(), vec![source]).expect("structurally fine");
    assert_eq!(
        w.encode().unwrap_err(),
        CcbError::OfflineReentryBoundaryIsItsOwnParent
    );
}

#[test]
fn a_witness_with_no_mutations_is_not_a_witness() {
    assert_eq!(
        witness(vec![], vec![]).unwrap_err(),
        CcbError::WitnessHasNoMutations
    );
}

// ── Round trips ────────────────────────────────────────────────────────────

#[test]
fn the_decoder_refuses_states_the_encoder_could_never_emit() {
    // Hand-built bytes for a zero-amount balance leaf. The encoder cannot
    // produce this, and the decoder must not admit it through the back door —
    // otherwise "zero balance is the absence of the leaf" holds on one side of
    // the wire only, and one economic state gets two roots.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EconomicBalanceState::CLASS.to_be_bytes());
    bytes.extend_from_slice(&EconomicBalanceState::SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&ERA);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    match decode_leaf_state(&bytes) {
        Err(DecodeError::Invalid(msg)) => assert!(
            msg.contains("ABSENCE"),
            "expected the zero-balance refusal, got: {msg}"
        ),
        other => panic!("a zero-amount balance leaf must not decode, got {other:?}"),
    }
}

// ── The manifest's derived provenance index ────────────────────────────────

// ── The wire object and the verifier, end to end ───────────────────────────

// ── 3.6: the 0x0026/0x0027 schema burn ─────────────────────────────────────

// ── 2c-H H9: 0x0035, the route reserve consumption ─────────────────────────
