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
use dsm::economic::claim::{
    verify_manifest_provenance_index, AdmissionSubstrate, EconomicAdmissionManifest,
};
use dsm::economic::credit::{
    CreditSource, CreditSourceAuthorizedIssuance, CreditSourceDlvReserveConsumption,
    CreditSourceSameTransitionMove, CreditSourceValidatedDlvSettlementPayment,
    CreditSourceValidatedPeerDebit, CreditSourceVerifiedOfflineReentry,
};
use dsm::economic::decode::{decode_credit_source, decode_leaf_state, decode_transition_witness};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicSettlementReceiptState, EconomicVaultReserveState,
};
use dsm::economic::tree::ECONOMIC_SMT_HEIGHT;
use dsm::economic::witness::EconomicTransitionWitness;

const ERA: [u8; 32] = [0xAA; 32];
const SOFI: [u8; 32] = [0xBB; 32];
const VAULT: [u8; 32] = [0xCC; 32];

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

fn move_source(credit: u32, debit: u32) -> CreditSource {
    CreditSource::SameTransitionMove(CreditSourceSameTransitionMove {
        credit_mutation_index: credit,
        debit_mutation_index: debit,
    })
}

fn witness(
    mutations: Vec<EconomicLeafMutation>,
    sources: Vec<CreditSource>,
) -> Result<EconomicTransitionWitness, CcbError> {
    EconomicTransitionWitness::new([1; 32], [2; 32], [3; 32], [4; 32], mutations, sources)
}

// ── The positive-credit predicate, which the bijection rests on ────────────

#[test]
fn only_a_quantity_increase_is_a_credit() {
    // Insertion of a balance.
    assert!(mutation(None, Some(bal(SOFI, 25))).is_positive_credit());
    // Debit.
    assert!(!mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70))).is_positive_credit());
    // Removal.
    assert!(!mutation(Some(bal(ERA, 100)), None).is_positive_credit());
    // Reserve increase and reserve drain.
    let reserve = |amount, seq| {
        EconomicLeafState::VaultReserve(EconomicVaultReserveState {
            vault_id: VAULT,
            policy_commit: ERA,
            amount,
            vault_sequence: seq,
        })
    };
    assert!(mutation(Some(reserve(10, 4)), Some(reserve(60, 5))).is_positive_credit());
    assert!(!mutation(Some(reserve(60, 4)), Some(reserve(0, 5))).is_positive_credit());

    // Insertions that are RECORDS, not credits. Demanding a funding source for
    // a bookkeeping entry would be incoherent.
    let receipt = EconomicLeafState::SettlementReceipt(
        EconomicSettlementReceiptState::new(VAULT, [7; 32], 4, 5, ERA, 10, SOFI, 9).expect("valid"),
    );
    assert!(!mutation(None, Some(receipt)).is_positive_credit());
    let consumed = EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
        source_id: [9; 32],
        consumer_economic_operation_id: [8; 32],
    });
    assert!(!mutation(None, Some(consumed)).is_positive_credit());
}

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
fn a_source_for_a_debit_is_provenance_for_nothing() {
    // Index 0 is the debit. Funding it is not merely useless: accepting it
    // would let a producer satisfy the bijection by pointing sources at
    // whichever mutations happen to be convenient.
    assert_eq!(
        witness(debit_then_credit(), vec![move_source(0, 1)]).unwrap_err(),
        CcbError::SourceForNonCredit { mutation_index: 0 }
    );
}

#[test]
fn credit_sources_must_be_strictly_ascending() {
    // Three credits so there is room to disorder them.
    let muts = vec![
        mutation(Some(bal(ERA, 100)), Some(bal(ERA, 70))),
        mutation(None, Some(bal(SOFI, 25))),
        mutation(None, Some(bal([0xDD; 32], 5))),
    ];
    let descending = vec![move_source(2, 0), move_source(1, 0)];
    assert_eq!(
        witness(muts.clone(), descending).unwrap_err(),
        CcbError::CreditSourcesNotStrictlyAscending { index: 1 }
    );

    // A repeat is two sources funding one credit — the double-funding shape.
    let duplicated = vec![move_source(1, 0), move_source(1, 0)];
    assert_eq!(
        witness(muts, duplicated).unwrap_err(),
        CcbError::CreditSourcesNotStrictlyAscending { index: 1 }
    );
}

#[test]
fn a_source_cannot_name_a_mutation_the_witness_does_not_have() {
    assert_eq!(
        witness(debit_then_credit(), vec![move_source(7, 0)]).unwrap_err(),
        CcbError::CreditIndexOutOfRange {
            index: 7,
            mutations: 2
        }
    );
    // Also for the debit endpoint of an intra-transition move.
    assert_eq!(
        witness(debit_then_credit(), vec![move_source(1, 9)]).unwrap_err(),
        CcbError::CreditIndexOutOfRange {
            index: 9,
            mutations: 2
        }
    );
}

#[test]
fn a_mutation_cannot_fund_itself() {
    let muts = debit_then_credit();
    assert_eq!(
        witness(muts, vec![move_source(1, 1)]).unwrap_err(),
        CcbError::SameTransitionMoveIsSelfFunding { index: 1 }
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

fn all_six_sources() -> Vec<CreditSource> {
    vec![
        CreditSource::AuthorizedIssuance(CreditSourceAuthorizedIssuance {
            credit_mutation_index: 0,
            issuance_authorization_addr: [0x11; 32],
        }),
        CreditSource::SameTransitionMove(CreditSourceSameTransitionMove {
            credit_mutation_index: 1,
            debit_mutation_index: 0,
        }),
        CreditSource::ValidatedPeerDebit(CreditSourceValidatedPeerDebit {
            credit_mutation_index: 2,
            peer_genesis: [0x22; 32],
            peer_devid: [0x33; 32],
            peer_economic_position: 9,
            peer_debit_mutation_index: 4,
            acceptance_evidence_addr: [0x44; 32],
        }),
        CreditSource::DlvReserveConsumption(CreditSourceDlvReserveConsumption {
            credit_mutation_index: 3,
            vault_id: VAULT,
            parent_sequence: 12,
            x: [0x55; 32],
            owner_economic_position: 6,
            reserve_consumption_evidence_addr: [0x66; 32],
        }),
        CreditSource::ValidatedDlvSettlementPayment(CreditSourceValidatedDlvSettlementPayment {
            credit_mutation_index: 4,
            vault_id: VAULT,
            settlement_receipt_id: [0x77; 32],
            parent_sequence: 12,
            trader_genesis: [0x88; 32],
            trader_devid: [0x99; 32],
            trader_economic_position: 7,
            payment_evidence_addr: [0xAB; 32],
        }),
        CreditSource::VerifiedOfflineReentry(CreditSourceVerifiedOfflineReentry {
            credit_mutation_index: 5,
            prior_boundary_id: [0xCD; 32],
            unload_boundary_id: [0xEF; 32],
            branch_evidence_addr: [0xFE; 32],
        }),
    ]
}

/// Six credits, so every arm has something to fund.
fn six_credits() -> Vec<EconomicLeafMutation> {
    (0..6u8)
        .map(|i| mutation(None, Some(bal([i; 32], u64::from(i) + 1))))
        .collect()
}

#[test]
fn every_source_arm_round_trips_through_the_witness() {
    let w = witness(six_credits(), all_six_sources()).expect("valid");
    let bytes = w.encode().expect("encodable");
    let decoded = decode_transition_witness(&bytes).expect("decodable");
    assert_eq!(decoded, w);
    assert_eq!(decoded.encode().unwrap(), bytes, "encoding is canonical");
}

#[test]
fn each_source_arm_round_trips_standalone_and_is_self_describing() {
    // The envelope IS the discriminant: no side-channel tag is needed to tell
    // the arms apart, which is what makes an inline heterogeneous sequence
    // parseable at all.
    for source in all_six_sources() {
        let bytes = source.encode().expect("encodable");
        assert_eq!(
            u16::from_be_bytes([bytes[0], bytes[1]]),
            source.class(),
            "every element opens with its own class"
        );
        assert_eq!(decode_credit_source(&bytes).expect("decodable"), source);
    }
}

#[test]
fn a_decoded_witness_is_held_to_the_same_rules_as_a_constructed_one() {
    // Truncation and suffixes: a payload that decodes and then continues is
    // not a witness with a suffix, it is not a witness.
    let w = witness(debit_then_credit(), vec![move_source(1, 0)]).expect("valid");
    let bytes = w.encode().expect("encodable");

    let mut extended = bytes.clone();
    extended.push(0x00);
    assert!(matches!(
        decode_transition_witness(&extended),
        Err(DecodeError::TrailingBytes { extra: 1 })
    ));
    assert!(matches!(
        decode_transition_witness(&bytes[..bytes.len() - 1]),
        Err(DecodeError::Truncated)
    ));
}

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

#[test]
fn a_receipt_cannot_assert_a_receipt_id_its_contents_do_not_produce() {
    let real =
        EconomicSettlementReceiptState::new(VAULT, [7; 32], 4, 5, ERA, 10, SOFI, 9).expect("valid");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EconomicSettlementReceiptState::CLASS.to_be_bytes());
    bytes.extend_from_slice(&EconomicSettlementReceiptState::SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&real.vault_id);
    bytes.extend_from_slice(&[0xF0; 32]); // a receipt_id of the producer's choosing
    bytes.extend_from_slice(&real.x);
    bytes.extend_from_slice(&real.parent_sequence.to_be_bytes());
    bytes.extend_from_slice(&real.new_sequence.to_be_bytes());
    bytes.extend_from_slice(&real.input_policy_commit);
    bytes.extend_from_slice(&real.input_amount.to_be_bytes());
    bytes.extend_from_slice(&real.output_policy_commit);
    bytes.extend_from_slice(&real.output_amount.to_be_bytes());
    match decode_leaf_state(&bytes) {
        Err(DecodeError::Invalid(msg)) => assert!(
            msg.contains("derive"),
            "expected the derived-name refusal, got: {msg}"
        ),
        other => panic!("a forged receipt_id must not decode, got {other:?}"),
    }
}

// ── The manifest's derived provenance index ────────────────────────────────

fn manifest(addrs: Vec<[u8; 32]>) -> EconomicAdmissionManifest {
    EconomicAdmissionManifest::new(
        [1; 32],
        [2; 32],
        [3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: [4; 32],
        },
        addrs,
    )
    .expect("valid")
}

#[test]
fn the_manifest_index_must_equal_what_the_sources_reference() {
    let w = witness(six_credits(), all_six_sources()).expect("valid");
    let derived = w.derived_provenance_index();

    // Five arms carry an external address; SameTransitionMove carries none.
    assert_eq!(derived.len(), 5, "SameTransitionMove contributes nothing");
    assert!(verify_manifest_provenance_index(&manifest(derived.clone()), &w).is_ok());

    // An index that advertises an address the sources never reference.
    let mut extra = derived.clone();
    extra.push([0xEE; 32]);
    assert!(matches!(
        verify_manifest_provenance_index(&manifest(extra), &w),
        Err(CcbError::ManifestProvenanceIndexMismatch {
            manifest_count: 6,
            derived_count: 5
        })
    ));

    // An index that omits one the sources DO reference — the case that would
    // otherwise leave a verifier discovering a missing object after fetching.
    let short = derived[..4].to_vec();
    assert!(matches!(
        verify_manifest_provenance_index(&manifest(short), &w),
        Err(CcbError::ManifestProvenanceIndexMismatch {
            manifest_count: 4,
            derived_count: 5
        })
    ));
}

#[test]
fn a_transition_funded_only_by_internal_moves_has_an_empty_index() {
    // And that is correct, not a missing index: nothing external is referenced,
    // so nothing needs publishing before the admission is verifiable.
    let w = witness(debit_then_credit(), vec![move_source(1, 0)]).expect("valid");
    assert!(w.derived_provenance_index().is_empty());
    assert!(verify_manifest_provenance_index(&manifest(vec![]), &w).is_ok());
}

// ── The wire object and the verifier, end to end ───────────────────────────

#[test]
fn a_witness_that_survived_the_wire_still_verifies_against_a_real_tree() {
    // The only test crossing the wire/verifier boundary. Everything above
    // checks structure with dummy sibling paths; this proves a witness carries
    // paths that are still usable after a round trip, so the two halves of the
    // economic root are actually connected rather than merely adjacent.
    use dsm::economic::tree::EconomicSmt;
    use dsm::economic::witness::verify_mutation_sequence;

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];

    let mut tree = EconomicSmt::new();
    let opening = bal(ERA, 100);
    tree.insert(
        opening.leaf_key(&G, &DEV),
        opening.leaf_value().expect("encodable"),
    );
    let pre_root = tree.root();

    // Apply in canonical ascending key order, taking each path against the
    // root the previous step left.
    let debit = (Some(bal(ERA, 100)), Some(bal(ERA, 70)));
    let credit = (None, Some(bal(SOFI, 25)));
    let key_of = |c: &(Option<EconomicLeafState>, Option<EconomicLeafState>)| {
        c.0.as_ref().or(c.1.as_ref()).unwrap().leaf_key(&G, &DEV)
    };
    let mut changes = vec![debit, credit];
    changes.sort_by_key(key_of);

    let mut mutations = Vec::new();
    let mut credit_index = 0usize;
    for (i, (pre, post)) in changes.into_iter().enumerate() {
        let probe = pre.as_ref().or(post.as_ref()).expect("one state").clone();
        let key = probe.leaf_key(&G, &DEV);
        let siblings = tree.siblings(&key).to_vec();
        let m = EconomicLeafMutation::new(pre, post.clone(), siblings).expect("well-formed");
        if m.is_positive_credit() {
            credit_index = i;
        }
        match post {
            None => tree.remove(&key),
            Some(s) => tree.insert(key, s.leaf_value().expect("encodable")),
        }
        mutations.push(m);
    }
    let post_root = tree.root();

    let debit_index = 1 - credit_index;
    let w = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        [3; 32],
        [4; 32],
        mutations,
        vec![move_source(credit_index as u32, debit_index as u32)],
    )
    .expect("valid witness");

    let bytes = w.encode().expect("encodable");
    let decoded = decode_transition_witness(&bytes).expect("decodable");

    assert_eq!(
        verify_mutation_sequence(&decoded.mutation_sequence(), &G, &DEV).expect("verifies"),
        post_root,
        "a witness must still recompute its post-root after a wire round trip"
    );
}

// ── 3.6: the 0x0026/0x0027 schema burn ─────────────────────────────────────

/// Schema 1 of both DLV credit-source classes is BURNED (owner ruling
/// 2026-08-28): it carried no locator for the peer's validated economic
/// ancestry, and zero producers ever shipped it. The strict decoder must
/// refuse schema-1 bytes outright — one (class, schema), one meaning.
#[test]
fn the_burned_dlv_source_schemas_are_refused() {
    let consumption = CreditSource::DlvReserveConsumption(CreditSourceDlvReserveConsumption {
        credit_mutation_index: 1,
        vault_id: VAULT,
        parent_sequence: 12,
        x: [0x55; 32],
        owner_economic_position: 6,
        reserve_consumption_evidence_addr: [0x66; 32],
    });
    let payment =
        CreditSource::ValidatedDlvSettlementPayment(CreditSourceValidatedDlvSettlementPayment {
            credit_mutation_index: 2,
            vault_id: VAULT,
            settlement_receipt_id: [0x77; 32],
            parent_sequence: 12,
            trader_genesis: [0x88; 32],
            trader_devid: [0x99; 32],
            trader_economic_position: 7,
            payment_evidence_addr: [0xAB; 32],
        });
    for source in [consumption, payment] {
        let bytes = source.encode().expect("schema 2 encodes");
        // The envelope is class u16 BE ‖ schema u16 BE; verify schema 2 is
        // what shipped, then stamp the burned schema 1 over it.
        assert_eq!(&bytes[2..4], &2u16.to_be_bytes(), "schema 2 is canonical");
        assert_eq!(decode_credit_source(&bytes).expect("round trip"), source);
        let mut burned = bytes.clone();
        burned[2..4].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            decode_credit_source(&burned).is_err(),
            "burned schema-1 bytes must be refused"
        );
    }
}
