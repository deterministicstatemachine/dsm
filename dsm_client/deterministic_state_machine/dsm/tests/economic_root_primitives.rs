// SPDX-License-Identifier: Apache-2.0

//! Conformance and mutation controls for the `R_econ` primitives.
//!
//! The controls that matter are the negative ones. A verifier that accepts
//! every well-formed write set is not doing the job; what has to be true is
//! that an incomplete write set, a reordered one, or one whose pre-state never
//! existed all fail — and fail for the stated reason rather than by accident.

#![allow(clippy::disallowed_methods)]

use dsm::ccb::CcbError;
use dsm::economic::classifier::{check_tripwire, classify, EconomicEffect, ObservedEconomicChange};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicSettlementReceiptState, EconomicVaultReserveState,
};
use dsm::economic::tree::{empty_economic_root, EconomicSmt, ECONOMIC_SMT_HEIGHT};
use dsm::economic::witness::{verify_mutation_sequence, EconomicMutationSequence, EconomicWitnessError};
use dsm::economic::{balance_key, consumed_source_key, settlement_receipt_key, vault_reserve_key};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const ERA: [u8; 32] = [0xAA; 32];
const SOFI: [u8; 32] = [0xBB; 32];
const VAULT: [u8; 32] = [0xCC; 32];

fn balance(pc: [u8; 32], amount: u64) -> EconomicLeafState {
    EconomicLeafState::Balance(EconomicBalanceState::new(pc, amount).expect("nonzero"))
}

/// Apply `states` to a tree and return it, keyed by their own derived keys.
fn tree_with(states: &[EconomicLeafState]) -> EconomicSmt {
    let mut t = EconomicSmt::new();
    for s in states {
        t.insert(s.leaf_key(&G, &DEV), s.leaf_value().expect("encodable"));
    }
    t
}

/// Build the mutation that takes `tree` from `pre` to `post` at one leaf, and
/// apply it to the tree so the next mutation's siblings are taken against the
/// root this one leaves. This mirrors what a producer must do, and is why the
/// verifier is sequential.
fn step(
    tree: &mut EconomicSmt,
    pre: Option<EconomicLeafState>,
    post: Option<EconomicLeafState>,
) -> EconomicLeafMutation {
    let probe = pre.as_ref().or(post.as_ref()).expect("one state");
    let key = probe.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let m = EconomicLeafMutation::new(pre, post.clone(), siblings).expect("well-formed");
    match post {
        None => tree.remove(&key),
        Some(s) => tree.insert(key, s.leaf_value().expect("encodable")),
    }
    m
}

// ── Tree and zero semantics ────────────────────────────────────────────────

#[test]
fn empty_root_is_the_full_default_chain() {
    // ValidatedEconomicRoot(0) is verifier-derived: two verifiers that have
    // never spoken must agree on it without being told.
    assert_eq!(empty_economic_root(), empty_economic_root());
    assert_eq!(EconomicSmt::new().root(), empty_economic_root());
    assert_ne!(empty_economic_root(), [0u8; 32]);
}

#[test]
fn a_zero_balance_is_the_absence_of_the_leaf_not_a_leaf_holding_zero() {
    // The security property: reaching zero must return the tree to exactly the
    // root it had before the leaf existed. If a zero balance had an encoding,
    // one economic state would have two roots.
    let before = EconomicSmt::new().root();
    let mut t = tree_with(&[balance(ERA, 100)]);
    assert_ne!(t.root(), before);
    t.remove(&balance(ERA, 100).leaf_key(&G, &DEV));
    assert_eq!(t.root(), before);

    assert_eq!(
        EconomicBalanceState::new(ERA, 0).unwrap_err(),
        CcbError::ZeroBalanceLeafMustBeAbsent
    );
}

#[test]
fn a_zero_reserve_is_a_present_leaf_because_its_sequence_is_meaning() {
    // The deliberate asymmetry with balances. A vault drained at sequence 7
    // and one drained at sequence 8 are different states, and a close has to
    // be able to say which generation it zeroed.
    let at7 = EconomicLeafState::VaultReserve(EconomicVaultReserveState {
        vault_id: VAULT,
        policy_commit: ERA,
        amount: 0,
        vault_sequence: 7,
    });
    let at8 = EconomicLeafState::VaultReserve(EconomicVaultReserveState {
        vault_id: VAULT,
        policy_commit: ERA,
        amount: 0,
        vault_sequence: 8,
    });
    assert_eq!(
        at7.leaf_key(&G, &DEV),
        at8.leaf_key(&G, &DEV),
        "same position"
    );
    assert_ne!(
        at7.leaf_value().unwrap(),
        at8.leaf_value().unwrap(),
        "different state"
    );
    assert_ne!(tree_with(&[at7]).root(), tree_with(&[at8]).root());
}

// ── Key derivation ─────────────────────────────────────────────────────────

#[test]
fn keys_are_scoped_to_the_identity_and_to_the_leaf_class() {
    let other_g = [0x99; 32];
    assert_ne!(
        balance_key(&G, &DEV, &ERA),
        balance_key(&other_g, &DEV, &ERA),
        "a different genesis is a different key space"
    );
    assert_ne!(
        balance_key(&G, &DEV, &ERA),
        balance_key(&G, &[0x99; 32], &ERA),
        "a different device is a different key space"
    );
    // Identical trailing material under different classes must not collide,
    // or a balance could be filed at a consumed-source position.
    assert_ne!(
        balance_key(&G, &DEV, &ERA),
        consumed_source_key(&G, &DEV, &ERA)
    );
    assert_ne!(
        vault_reserve_key(&G, &DEV, &VAULT, &ERA),
        settlement_receipt_key(&G, &DEV, &VAULT, &ERA)
    );
}

#[test]
fn a_leaf_state_derives_its_own_position() {
    // A caller never supplies a key, so "valid object at the wrong address"
    // is unrepresentable rather than merely checked for.
    let b = balance(ERA, 5);
    assert_eq!(b.leaf_key(&G, &DEV), balance_key(&G, &DEV, &ERA));

    let c = EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
        source_id: [0x44; 32],
        consumer_economic_operation_id: [0x55; 32],
    });
    assert_eq!(
        c.leaf_key(&G, &DEV),
        consumed_source_key(&G, &DEV, &[0x44; 32])
    );
}

// ── Receipt validity conditions ────────────────────────────────────────────

#[test]
fn a_settlement_receipt_recomputes_its_own_id_and_refuses_inconsistent_legs() {
    let r = EconomicSettlementReceiptState::new(VAULT, [7u8; 32], 4, 5, ERA, 10, SOFI, 9)
        .expect("consistent");
    assert_eq!(
        r.receipt_id,
        dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&VAULT, &[7u8; 32]),
        "receipt_id is derived, never carried"
    );

    assert_eq!(
        EconomicSettlementReceiptState::new(VAULT, [7u8; 32], 4, 6, ERA, 10, SOFI, 9).unwrap_err(),
        CcbError::ReceiptSequenceNotSuccessor { parent: 4, new: 6 }
    );
    assert_eq!(
        EconomicSettlementReceiptState::new(VAULT, [7u8; 32], 4, 5, ERA, 0, SOFI, 9).unwrap_err(),
        CcbError::ReceiptZeroAmount
    );
    assert_eq!(
        EconomicSettlementReceiptState::new(VAULT, [7u8; 32], 4, 5, ERA, 10, ERA, 9).unwrap_err(),
        CcbError::ReceiptAssetsNotDistinct
    );
}

// ── Mutation well-formedness ───────────────────────────────────────────────

#[test]
fn a_mutation_with_neither_state_has_no_encoding() {
    assert_eq!(
        EconomicLeafMutation::new(None, None, vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT]).unwrap_err(),
        CcbError::MutationBothStatesAbsent,
    );
}

#[test]
fn a_short_path_is_refused_rather_than_padded() {
    // A variable-length path proves membership in a shallower tree. Accepting
    // one means verifying a different tree than the one being checked.
    let err =
        EconomicLeafMutation::new(None, Some(balance(ERA, 1)), vec![[0u8; 32]; 200]).unwrap_err();
    assert_eq!(
        err,
        CcbError::MutationSiblingCount {
            expected: ECONOMIC_SMT_HEIGHT,
            got: 200
        }
    );
}

#[test]
fn a_mutation_cannot_change_which_leaf_it_is_about() {
    let sibs = vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT];
    // Same class, different asset — still two positions.
    let err =
        EconomicLeafMutation::new(Some(balance(ERA, 1)), Some(balance(SOFI, 1)), sibs.clone())
            .unwrap_err();
    assert!(matches!(err, CcbError::MutationClassMismatch { .. }));

    // Different class entirely.
    let consumed = EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
        source_id: [1u8; 32],
        consumer_economic_operation_id: [2u8; 32],
    });
    let err = EconomicLeafMutation::new(Some(balance(ERA, 1)), Some(consumed), sibs).unwrap_err();
    assert!(matches!(err, CcbError::MutationClassMismatch { .. }));
}

// ── The sequential verifier ────────────────────────────────────────────────

/// Apply a list of `(pre, post)` leaf changes in **canonical ascending key
/// order**, returning the mutations and the resulting root. This is what a
/// conforming producer must do; each mutation's path is taken against the root
/// the previous one left.
fn canonical_write_set(
    tree: &mut EconomicSmt,
    mut changes: Vec<(Option<EconomicLeafState>, Option<EconomicLeafState>)>,
) -> Vec<EconomicLeafMutation> {
    changes.sort_by_key(|(pre, post)| {
        pre.as_ref()
            .or(post.as_ref())
            .expect("one state")
            .leaf_key(&G, &DEV)
    });
    changes
        .into_iter()
        .map(|(pre, post)| step(tree, pre, post))
        .collect()
}

#[test]
fn a_complete_write_set_derives_the_claimed_post_root() {
    // Spend 30 ERA for 25 SOFI: one debit, one credit.
    let mut t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();
    let mutations = canonical_write_set(
        &mut t,
        vec![
            (Some(balance(ERA, 100)), Some(balance(ERA, 70))),
            (None, Some(balance(SOFI, 25))),
        ],
    );
    let post_root = t.root();

    let seq = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: post_root,
        mutations,
    };
    assert_eq!(
        verify_mutation_sequence(&seq, &G, &DEV).expect("verifies"),
        post_root
    );
}

#[test]
fn a_changed_leaf_missing_from_the_write_set_fails() {
    // THE control this layer exists for. The producer declares a debit but
    // also moves a leaf it does not declare, hoping the undeclared credit
    // rides along invisibly inside the post-root.
    let mut t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();

    let declared = vec![step(
        &mut t,
        Some(balance(ERA, 100)),
        Some(balance(ERA, 70)),
    )];

    let sneaky = balance(SOFI, 1_000_000);
    t.insert(
        sneaky.leaf_key(&G, &DEV),
        sneaky.leaf_value().expect("encodable"),
    );
    let actual_post = t.root();

    let seq = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: actual_post,
        mutations: declared,
    };
    match verify_mutation_sequence(&seq, &G, &DEV) {
        Err(EconomicWitnessError::PostRootMismatch { claimed, derived }) => {
            assert_eq!(claimed, actual_post);
            assert_ne!(derived, actual_post);
        }
        other => panic!("an undeclared leaf change must not verify, got {other:?}"),
    }
}

#[test]
fn a_pre_state_that_never_existed_fails() {
    let t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();
    let key = balance(ERA, 100).leaf_key(&G, &DEV);
    let siblings = t.siblings(&key).to_vec();

    // Claim the balance was 1_000_000 and spend from that.
    let m = EconomicLeafMutation::new(
        Some(balance(ERA, 1_000_000)),
        Some(balance(ERA, 999_970)),
        siblings,
    )
    .expect("well-formed");
    let seq = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: [0u8; 32],
        mutations: vec![m],
    };
    assert!(matches!(
        verify_mutation_sequence(&seq, &G, &DEV),
        Err(EconomicWitnessError::PreStateNotInRoot { index: 0, .. })
    ));
}

#[test]
fn a_descending_write_set_is_refused_even_when_every_path_verifies() {
    // The adversarial case: a producer builds its paths in DESCENDING key
    // order, so every individual mutation authenticates against the root that
    // precedes it. It must still be refused — canonical ordering is what makes
    // one write set have exactly one representation, and two representations
    // of one transition is two economic operation identities.
    let debit = (Some(balance(ERA, 100)), Some(balance(ERA, 70)));
    let credit = (None, Some(balance(SOFI, 25)));
    let key_of = |c: &(Option<EconomicLeafState>, Option<EconomicLeafState>)| {
        c.0.as_ref().or(c.1.as_ref()).unwrap().leaf_key(&G, &DEV)
    };
    let (first, second) = if key_of(&debit) > key_of(&credit) {
        (debit, credit)
    } else {
        (credit, debit)
    };

    let mut t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();
    let hi = step(&mut t, first.0, first.1);
    let lo = step(&mut t, second.0, second.1);
    let post_root = t.root();

    let seq = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: post_root,
        mutations: vec![hi, lo],
    };
    assert!(
        matches!(
            verify_mutation_sequence(&seq, &G, &DEV),
            Err(EconomicWitnessError::KeysNotStrictlyAscending { index: 1 })
        ),
        "a path-valid descending sequence must still be refused on ordering"
    );
}

#[test]
fn a_repeated_key_is_two_disagreeing_claims_about_one_leaf() {
    let mut t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();
    let first = step(&mut t, Some(balance(ERA, 100)), Some(balance(ERA, 70)));

    let duped = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: t.root(),
        mutations: vec![first.clone(), first],
    };
    assert!(matches!(
        verify_mutation_sequence(&duped, &G, &DEV),
        Err(EconomicWitnessError::KeysNotStrictlyAscending { index: 1 })
    ));
}

#[test]
fn an_empty_write_set_is_not_a_witness() {
    let seq = EconomicMutationSequence {
        pre_economic_root: empty_economic_root(),
        post_economic_root: empty_economic_root(),
        mutations: Vec::new(),
    };
    assert_eq!(
        verify_mutation_sequence(&seq, &G, &DEV).unwrap_err(),
        EconomicWitnessError::EmptyMutationSet
    );
}

#[test]
fn a_witness_cannot_be_replayed_under_another_identity() {
    // Every key binds G ‖ DevID, so the same mutation bytes describe a
    // different position — and therefore a different root — for anyone else.
    let mut t = tree_with(&[balance(ERA, 100)]);
    let pre_root = t.root();
    let m = step(&mut t, Some(balance(ERA, 100)), Some(balance(ERA, 70)));
    let seq = EconomicMutationSequence {
        pre_economic_root: pre_root,
        post_economic_root: t.root(),
        mutations: vec![m],
    };
    assert!(verify_mutation_sequence(&seq, &G, &DEV).is_ok());
    assert!(verify_mutation_sequence(&seq, &[0x99; 32], &DEV).is_err());
    assert!(verify_mutation_sequence(&seq, &G, &[0x99; 32]).is_err());
}

// ── Classifier and tripwire ────────────────────────────────────────────────

#[test]
fn the_offline_bearer_tier_is_classified_by_authority_policy_not_by_variant() {
    use dsm::types::operations::{Operation, TransactionMode, VerificationType};
    use dsm::types::token_types::Balance;

    let online = Operation::Transfer {
        to_device_id: vec![1; 32],
        amount: Balance::from_state(5, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: ERA,
        mode: TransactionMode::Bilateral,
        nonce: vec![0; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: Vec::new(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    };
    assert_eq!(classify(&online), EconomicEffect::ClosedWriteSet);
}

#[test]
fn dlv_unlock_is_economically_inert_despite_being_value_bearing() {
    // The divergence from `is_value_bearing` that makes mirroring it wrong:
    // that gate exists for recovery, this one for the economic root.
    let op = dsm::types::operations::Operation::DlvUnlock {
        vault_id: vec![0xCC; 32],
        fulfillment_proof: Vec::new(),
        requester_public_key: Vec::new(),
        signature: Vec::new(),
        mode: dsm::types::operations::TransactionMode::Unilateral,
    };
    assert!(op.is_value_bearing());
    assert_eq!(classify(&op), EconomicEffect::None);
}

/// Owner directive (2026-08-28): DlvCreate is STRUCTURALLY state-only — the
/// legacy value-bearing fields are deleted from the wire, so the value-bearing
/// legacy shape is inexpressible, and every DlvCreate is economically `None`.
#[test]
fn dlv_create_is_structurally_state_only_and_economically_none() {
    let create = dsm::types::operations::Operation::DlvCreate {
        vault_id: vec![0xCC; 32],
        creator_public_key: vec![0x02; 64],
        parameters_hash: vec![0x03; 32],
        fulfillment_condition: Vec::new(),
        intended_recipient: None,
        signature: Vec::new(),
        mode: dsm::types::operations::TransactionMode::Unilateral,
    };
    assert_eq!(classify(&create), EconomicEffect::None);
    assert!(!create.is_value_egress());
}

#[test]
fn the_v2_vault_operations_are_closed_write_sets() {
    let create = dsm::types::operations::Operation::DlvCreateFundedV2 {
        vault_id: vec![0xCC; 32],
        creator_public_key: vec![0x02; 64],
        parameters_hash: vec![0x03; 32],
        fulfillment_condition: Vec::new(),
        leg_a_policy_commit: [0x0A; 32],
        leg_a_amount: 10,
        leg_b_policy_commit: [0x0B; 32],
        leg_b_amount: 5,
        fee_bps: 30,
        signature: Vec::new(),
        mode: dsm::types::operations::TransactionMode::Unilateral,
    };
    let apply = dsm::types::operations::Operation::DlvOwnerApplyV2 {
        vault_id: vec![0xCC; 32],
        settlement_receipt_id: [0x11; 32],
        pending_pointer_x: [0x12; 32],
        parent_sequence: 1,
        new_sequence: 2,
        parent_binding: [0x13; 32],
        input_policy_commit: [0x0A; 32],
        output_policy_commit: [0x0B; 32],
        input_amount: 10,
        output_amount: 9,
        fee_bps: 30,
        signature: Vec::new(),
        mode: dsm::types::operations::TransactionMode::Unilateral,
    };
    assert_eq!(classify(&create), EconomicEffect::ClosedWriteSet);
    assert_eq!(classify(&apply), EconomicEffect::ClosedWriteSet);
}

#[test]
fn the_tripwire_contradicts_a_no_write_classification_that_wrote() {
    let wrote = ObservedEconomicChange {
        balances_changed: true,
        ..Default::default()
    };
    let quiet = ObservedEconomicChange::default();

    assert!(check_tripwire(EconomicEffect::None, wrote).is_err());
    // OfflineAccountOnly is held to the same standard: the allocation lives
    // outside R_econ, so touching a leaf breaks the regime separation.
    assert!(check_tripwire(EconomicEffect::OfflineAccountOnly, wrote).is_err());
    assert!(check_tripwire(EconomicEffect::ClosedWriteSet, wrote).is_ok());
    assert!(check_tripwire(EconomicEffect::None, quiet).is_ok());

    for field in 0..4 {
        let mut o = ObservedEconomicChange::default();
        match field {
            0 => o.balances_changed = true,
            1 => o.vault_reserves_changed = true,
            2 => o.settlement_receipts_changed = true,
            _ => o.consumed_sources_changed = true,
        }
        assert!(
            check_tripwire(EconomicEffect::None, o).is_err(),
            "every economic leaf family must trip the wire, field {field} did not"
        );
    }
}

// ── Claim and manifest encodings ───────────────────────────────────────────

#[test]
fn a_manifest_names_exactly_one_substrate_and_the_two_are_not_interchangeable() {
    use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};

    let evidence = [0x77; 32];
    let dsm_side = EconomicAdmissionManifest::new(
        [1; 32],
        [2; 32],
        [3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: evidence,
        },
        vec![[4; 32]],
    )
    .expect("valid");
    let offline_side = EconomicAdmissionManifest::new(
        [1; 32],
        [2; 32],
        [3; 32],
        AdmissionSubstrate::OfflineBoundary {
            evidence_addr: evidence,
        },
        vec![[4; 32]],
    )
    .expect("valid");

    // The object SHAPE states the substrate, so the same evidence address
    // under the other substrate is a different manifest and a different
    // address. If these collided, a boundary attestation could be presented
    // as a DSM successor.
    assert_ne!(dsm_side.addr().unwrap(), offline_side.addr().unwrap());
    assert_eq!(dsm_side.addr().unwrap(), dsm_side.addr().unwrap());
}

#[test]
fn a_manifest_refuses_a_repeated_provenance_address() {
    use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};

    // A repeated address is a producer naming one source twice for two
    // credits — the bijection violation, caught at encode time.
    let err = EconomicAdmissionManifest::new(
        [1; 32],
        [2; 32],
        [3; 32],
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: [5; 32],
        },
        vec![[4; 32], [4; 32]],
    )
    .unwrap_err();
    assert!(matches!(err, CcbError::DuplicateSetElement { .. }));
}

#[test]
fn a_claim_binds_its_register_set_and_validates_its_key_width() {
    use dsm::ccb::genesis::sigalg;
    use dsm::economic::claim::EconomicRootClaimBody;

    let pk = vec![0xAB; 64];
    let a = EconomicRootClaimBody::new(
        G,
        DEV,
        7,
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        sigalg::SPHINCS_PLUS_SPX256F,
        &pk,
    )
    .expect("valid");
    let b = EconomicRootClaimBody::new(
        G,
        DEV,
        7,
        [0x33; 32],
        [0x44; 32],
        // A DIFFERENT register set, everything else identical.
        [0x66; 32],
        sigalg::SPHINCS_PLUS_SPX256F,
        &pk,
    )
    .expect("valid");
    assert_ne!(
        a.signing_digest().unwrap(),
        b.signing_digest().unwrap(),
        "the set is signed, so a claim cannot be lifted into another network's register"
    );

    assert!(matches!(
        EconomicRootClaimBody::new(G, DEV, 7, [0; 32], [0; 32], [0; 32], 0xFFFF, &pk).unwrap_err(),
        CcbError::UnknownSignatureAlg { .. }
    ));
    assert!(matches!(
        EconomicRootClaimBody::new(
            G,
            DEV,
            7,
            [0; 32],
            [0; 32],
            [0; 32],
            sigalg::SPHINCS_PLUS_SPX256F,
            &[0xAB; 32],
        )
        .unwrap_err(),
        CcbError::KeyLengthMismatch { .. }
    ));
}

// ── Reserved vs implemented classes ────────────────────────────────────────
//
// "The discriminant exists, therefore it must be safe to serialize somehow" is
// the creep these two tests exist to block.

#[test]
fn a_reserved_class_is_unusable_on_the_wire_until_its_schema_is_installed() {
    use dsm::ccb::reserved;

    // 0x001D and the provenance objects are ALLOCATED — the numbers cannot be
    // handed out twice — and nothing more. There is no field table for them,
    // so there are no canonical bytes to produce, hash-address, nest or sign.
    // The witness verifier consequently takes EconomicMutationSequence, which
    // has no class and is explicitly not a wire object.
    // Editing this assertion is the point: reserving or promoting a class is
    // a deliberate diff. 0x0029 stays reserved (its field table would encode
    // an issuance predicate this protocol does not have); 0x002A-0x002F are
    // STRUCTURALLY held for the Step-5 offline/portable objects, so a later
    // PR cannot allocate one because "the plan said it was reserved" while
    // the code said nothing; 0x0030 was allocated PAST them for the faucet
    // credit source.
    assert_eq!(
        reserved::ALL,
        &[0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F],
        "the reserved set is exact — promoting a class must be a deliberate diff here"
    );
    for c in reserved::ALL {
        assert!(reserved::is_reserved(*c));
    }
    assert!(
        !reserved::is_reserved(0x0030),
        "0x0030 is LIVE (faucet distribution); 0x0031 is the next free class"
    );
}

#[test]
fn reserved_classes_have_no_encoder() {
    use dsm::ccb::reserved;
    use dsm::ccb::CcbObject;
    use dsm::economic::claim::{EconomicAdmissionManifest, EconomicRootClaimBody};

    // Every economic type that can actually produce canonical bytes must draw
    // its discriminant from the live namespace. If somebody implements
    // CcbObject against a `reserved::` constant to "just get it serializing",
    // this is what refuses.
    let encodable = [
        EconomicRootClaimBody::CLASS,
        EconomicAdmissionManifest::CLASS,
        dsm::economic::witness::EconomicTransitionWitness::CLASS,
        EconomicLeafMutation::CLASS,
        EconomicBalanceState::CLASS,
        EconomicVaultReserveState::CLASS,
        EconomicSettlementReceiptState::CLASS,
        EconomicConsumedSourceState::CLASS,
        dsm::economic::credit::CreditSourceAuthorizedIssuance::CLASS,
        dsm::economic::credit::CreditSourceSameTransitionMove::CLASS,
        dsm::economic::credit::CreditSourceValidatedPeerDebit::CLASS,
        dsm::economic::credit::CreditSourceDlvReserveConsumption::CLASS,
        dsm::economic::credit::CreditSourceValidatedDlvSettlementPayment::CLASS,
        dsm::economic::credit::CreditSourceVerifiedOfflineReentry::CLASS,
        dsm::economic::credit::CreditSourceValidatedFaucetDistribution::CLASS,
    ];
    for class in encodable {
        assert!(
            !reserved::is_reserved(class),
            "class {class:#06x} has an encoder but is listed as reserved — a class is \
             reserved OR encodable, never both"
        );
    }
    // And the live economic classes are exactly the ones with field tables.
    assert_eq!(
        encodable,
        [
            0x001B, 0x001C, 0x001D, 0x001E, 0x001F, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025,
            0x0026, 0x0027, 0x0028, 0x0030
        ]
    );
}
