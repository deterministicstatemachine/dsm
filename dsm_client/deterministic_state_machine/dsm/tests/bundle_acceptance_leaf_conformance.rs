// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! CLASS-1 CONFORMANCE VECTOR FOR THE BUNDLE-ACCEPTANCE LEAF — amendment 2c-D,
//! class `0x0032` schema 1 (registry §5.41).
//!
//! Amendment 2c-C2 ruling D: a class-1 vector's expected bytes are produced
//! WITHOUT the production encoder, decoder or digest helpers. The bytes below
//! come from `common/indep_ccb.rs`, written from the registry text, and the
//! key and leaf value are computed by an independent `H_dom` — never by
//! `bundle_acceptance_key` or `leaf_value`. The literals were captured ONCE
//! from the independent encoder and frozen.
//!
//! **What this file does NOT establish.** A conformant leaf is a leaf whose
//! bytes and position are right. It says nothing about whether the bundle it
//! names is binding-final, accepted, or realized — those are 2c-D §7's seven
//! ordered conjuncts, and none of them can be discharged from a leaf alone.
//! The `economic_operation_id` equality against the enclosing witness is a
//! write-set and verifier obligation; it is deliberately not asserted here,
//! because this file has no witness and inventing one would test a fixture
//! rather than the encoding.
//!
//! Byte arrays throughout, never hex (C2 ruling D).

#[path = "common/indep_ccb.rs"]
mod indep;

use dsm::economic::keys::bundle_acceptance_key;
use dsm::economic::state::{EconomicBundleAcceptanceState, EconomicLeafState};

const G: [u8; 32] = [0x01; 32];
const DEV: [u8; 32] = [0x02; 32];
const B: [u8; 32] = [0xB0; 32];
const C_DSM_PLUS: [u8; 32] = [0xC5; 32];

const KEY_TAG: &[u8] = b"DSM/economic-bundle-acceptance-key/v1";
const OPERATION_ID_TAG: &[u8] = b"DSM/economic-operation-id/dsm/v2";
const LEAF_STATE_TAG: &[u8] = b"DSM/economic-leaf-state/v1";

/// The independent encoder for `0x0032` schema 1, written from registry §5.41:
/// the §2.1 envelope, then two bare `digest32` fields in table order.
fn indep_leaf(bundle: [u8; 32], economic_operation_id: [u8; 32]) -> Vec<u8> {
    [
        indep::envelope(0x0032, 1),
        bundle.to_vec(),
        economic_operation_id.to_vec(),
    ]
    .concat()
}

/// `economic_operation_id = H_dom(DSM/economic-operation-id/dsm/v2, G ‖ DevID ‖ C_dsm+)`,
/// recomputed here rather than taken from `dsm_economic_operation_id`.
fn indep_operation_id(genesis: [u8; 32], devid: [u8; 32], c_dsm_plus: [u8; 32]) -> [u8; 32] {
    indep::h_dom(
        OPERATION_ID_TAG,
        &[genesis.to_vec(), devid.to_vec(), c_dsm_plus.to_vec()].concat(),
    )
}

/// The 68 bytes registry §5.41 pins: 4 envelope + 32 `bundle` + 32
/// `economic_operation_id`.
///
/// Captured once from `indep_leaf` and frozen. A change here is a change to
/// the canonical identity of every acceptance leaf, so it must arrive with a
/// schema bump and a burn, never as a test edit.
const EXPECTED_LEAF: [u8; 68] = [
    0x00, 0x32, 0x00, 0x01, // envelope: class 0x0032, schema 1
    // field 1 — bundle (b)
    0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0,
    0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0,
    // field 2 — economic_operation_id
    0x32, 0xBD, 0xD4, 0x3F, 0x75, 0x6B, 0x63, 0x86, 0x65, 0x89, 0x2E, 0x47, 0x44, 0x8A, 0x7A, 0xED,
    0x66, 0xE4, 0xF2, 0x9A, 0x82, 0x65, 0x71, 0x4A, 0xD2, 0x92, 0xA7, 0x95, 0x4E, 0x59, 0x06, 0x08,
];

fn state() -> EconomicBundleAcceptanceState {
    EconomicBundleAcceptanceState {
        bundle: B,
        economic_operation_id: indep_operation_id(G, DEV, C_DSM_PLUS),
    }
}

/// The independent bytes are what the frozen literal says, and the production
/// encoder reproduces them.
///
/// Two assertions, deliberately separate: the first pins the SECOND
/// implementation against the constant, so a drifting independent encoder is
/// caught rather than silently agreeing with a drifting production one; the
/// second is the conformance claim.
#[test]
fn the_acceptance_leaf_encodes_to_its_frozen_class_1_bytes() {
    let expected = indep_leaf(B, indep_operation_id(G, DEV, C_DSM_PLUS));
    assert_eq!(
        expected.len(),
        68,
        "registry §5.41 pins 68 bytes: 4 envelope + two digest32"
    );
    assert_eq!(
        expected.as_slice(),
        EXPECTED_LEAF.as_slice(),
        "the independent encoder no longer produces the frozen vector"
    );

    let produced = EconomicLeafState::BundleAcceptance(state())
        .encode()
        .expect("encodable");
    assert_eq!(
        produced.as_slice(),
        EXPECTED_LEAF.as_slice(),
        "the production encoder disagrees with the independent one"
    );
}

/// The leaf value is `H_dom(DSM/economic-leaf-state/v1, CCB)`, the same rule
/// its four siblings follow.
#[test]
fn the_acceptance_leaf_value_is_the_family_derivation_over_its_own_ccb() {
    let expected = indep::h_dom(LEAF_STATE_TAG, &EXPECTED_LEAF);
    let produced = EconomicLeafState::BundleAcceptance(state())
        .leaf_value()
        .expect("encodable");
    assert_eq!(produced, expected);
}

/// The position is `H_dom(tag, G ‖ DevID ‖ economic_operation_id)` — derived,
/// never supplied.
#[test]
fn the_acceptance_leaf_derives_its_own_position() {
    let eoid = indep_operation_id(G, DEV, C_DSM_PLUS);
    let expected = indep::h_dom(KEY_TAG, &[G.to_vec(), DEV.to_vec(), eoid.to_vec()].concat());

    assert_eq!(bundle_acceptance_key(&G, &DEV, &eoid), expected);
    assert_eq!(
        EconomicLeafState::BundleAcceptance(state()).leaf_key(&G, &DEV),
        expected,
        "the family dispatch must reach the same derivation"
    );
}

/// **The property ruling D3 turns on.** A different accepted successor yields
/// a different operation id and therefore a different position — which is what
/// keeps one operation applied to two parents from colliding on one leaf.
///
/// Stated as a chain rather than a single inequality, because each link is a
/// separate claim: different `C_dsm+` → different id → different key.
#[test]
fn a_different_accepted_successor_lands_at_a_different_position() {
    let other_successor = [0xC6; 32];
    assert_ne!(C_DSM_PLUS, other_successor);

    let id_a = indep_operation_id(G, DEV, C_DSM_PLUS);
    let id_b = indep_operation_id(G, DEV, other_successor);
    assert_ne!(id_a, id_b, "the operation id must separate two successors");

    assert_ne!(
        bundle_acceptance_key(&G, &DEV, &id_a),
        bundle_acceptance_key(&G, &DEV, &id_b),
        "two accepted transitions must not share an acceptance position"
    );
}

/// The position does NOT depend on `b`. Two acceptances naming different
/// bundles under ONE transition are the same position holding different
/// values — a conflict the SMT surfaces, not two coexisting leaves.
///
/// This is the structural reason "exactly one bundle-acceptance leaf per
/// economic operation" is enforceable at all, so it is asserted rather than
/// left as a comment.
#[test]
fn two_bundles_under_one_transition_contend_for_the_same_position() {
    let eoid = indep_operation_id(G, DEV, C_DSM_PLUS);
    let one = EconomicLeafState::BundleAcceptance(EconomicBundleAcceptanceState {
        bundle: B,
        economic_operation_id: eoid,
    });
    let other = EconomicLeafState::BundleAcceptance(EconomicBundleAcceptanceState {
        bundle: [0xB1; 32],
        economic_operation_id: eoid,
    });

    assert_eq!(
        one.leaf_key(&G, &DEV),
        other.leaf_key(&G, &DEV),
        "content must not move the position"
    );
    assert_ne!(
        one.leaf_value().expect("encodable"),
        other.leaf_value().expect("encodable"),
        "…while still being distinguishable as values"
    );
    assert_eq!(
        one.position_material(),
        other.position_material(),
        "position material must agree, which is what makes the pair a conflict"
    );
}

/// The key space stays per-identity: the same acceptance under another
/// identity is a different position, so no identity can write into another's
/// tree by replaying a leaf.
#[test]
fn an_acceptance_cannot_be_replayed_into_another_identity() {
    let eoid = indep_operation_id(G, DEV, C_DSM_PLUS);
    let other_genesis = [0x0A; 32];
    let other_devid = [0x0B; 32];

    assert_ne!(
        bundle_acceptance_key(&G, &DEV, &eoid),
        bundle_acceptance_key(&other_genesis, &DEV, &eoid),
        "genesis must scope the position"
    );
    assert_ne!(
        bundle_acceptance_key(&G, &DEV, &eoid),
        bundle_acceptance_key(&G, &other_devid, &eoid),
        "devid must scope the position"
    );
}

/// The acceptance leaf is not a credit. It records that something happened; it
/// adds no spendable units, so demanding a funding source for it would be a
/// category error — the same reading its receipt and consumed-source siblings
/// already get.
#[test]
fn an_acceptance_is_an_insertion_not_a_credit() {
    assert_eq!(
        EconomicLeafState::BundleAcceptance(state()).credit_amount(),
        None
    );
}
