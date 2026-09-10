// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! CLASS-1 CONFORMANCE VECTOR FOR `TraderAcceptance` — amendment 2c-D §6,
//! class `0x0011` schema 1 (registry §5.40).
//!
//! Amendment 2c-C2 ruling D: the expected bytes come from `common/indep_ccb.rs`
//! and an independent `H_dom`, never from `TraderAcceptance::encode` or
//! `ta_b`. At 8,308 bytes the object is too large to pin as a byte literal, so
//! this follows the settlement-bundle vector's shape instead: the production
//! encoder must reproduce the independent bytes exactly, and the IDENTITY
//! `ta_B` must equal a pinned literal captured once from the independent
//! encoder.
//!
//! **What a conformant `TA_B` is not.** These vectors say the bytes and the
//! identity are right. They say nothing about whether the acceptance is true:
//! `G` is unauthenticated, the path folds to nothing in particular, and no
//! bundle has been shown binding-final. 2c-D §7's seven conjuncts do that work
//! and do not exist yet. A vector passing here is a serialization fact.
//!
//! Byte arrays throughout, never hex (C2 ruling D).

#[path = "common/indep_ccb.rs"]
mod indep;

use dsm::economic::state::EconomicBundleAcceptanceState;
use dsm::economic::trader_acceptance::{AcceptanceMalformed, TraderAcceptance, TRADER_ACCEPTANCE_LEN};

const G: [u8; 32] = [0x11; 32];
const B: [u8; 32] = [0xB0; 32];
const EOID: [u8; 32] = [0x50; 32];
const POSITION: u64 = 3;
const HEIGHT: usize = 256;

const TA_B_TAG: &[u8] = b"DSM/trader-settlement-acceptance/v2";

/// One sibling per depth, all distinct, so a vector that silently reordered or
/// truncated the path could not still pass.
fn path() -> Vec<[u8; 32]> {
    (0..HEIGHT)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0] = (i % 256) as u8;
            s[1] = (i / 256) as u8;
            s
        })
        .collect()
}

/// The independent encoder for `0x0032` schema 1 (registry §5.41): envelope,
/// then two bare `digest32` in table order.
fn indep_leaf(bundle: [u8; 32], eoid: [u8; 32]) -> Vec<u8> {
    [indep::envelope(0x0032, 1), bundle.to_vec(), eoid.to_vec()].concat()
}

/// The independent encoder for `0x0011` schema 1 (registry §5.40): envelope,
/// `digest32`, `u64`, the complete nested leaf CCB (§2.7), then a §2.5
/// sequence of siblings — `u32_be(count)` followed by the elements.
fn indep_acceptance(
    genesis: [u8; 32],
    position: u64,
    leaf: &[u8],
    siblings: &[[u8; 32]],
) -> Vec<u8> {
    let mut out = [
        indep::envelope(0x0011, 1),
        genesis.to_vec(),
        indep::u64be(position),
        leaf.to_vec(),
        indep::u32be(siblings.len() as u32),
    ]
    .concat();
    for s in siblings {
        out.extend_from_slice(s);
    }
    out
}

fn subject() -> TraderAcceptance {
    TraderAcceptance::new(
        G,
        POSITION,
        EconomicBundleAcceptanceState {
            bundle: B,
            economic_operation_id: EOID,
        },
        path(),
    )
    .expect("well formed")
}

/// `ta_B` for the fixture above, captured ONCE from the independent encoder
/// and frozen.
///
/// A change here is a change to the canonical identity of every trader
/// acceptance, so it must arrive with a schema bump and a burn, never as a
/// test edit.
const EXPECTED_TA_B: [u8; 32] = [
    0x75, 0x5A, 0x8E, 0x40, 0x2C, 0xAB, 0x39, 0x87, 0xD3, 0x30, 0x60, 0xDF, 0xAC, 0x3D, 0xCA, 0xFA,
    0x1B, 0xF7, 0xDB, 0x3F, 0xFD, 0x5F, 0x87, 0x93, 0x93, 0xEE, 0x8F, 0x72, 0x3A, 0xAE, 0xF1, 0x14,
];

/// The production encoder reproduces the independent bytes, and the length is
/// the one the registry pins.
#[test]
fn the_acceptance_encodes_to_the_independent_bytes_at_the_frozen_length() {
    let p = path();
    let expected = indep_acceptance(G, POSITION, &indep_leaf(B, EOID), &p);

    assert_eq!(
        expected.len(),
        8_308,
        "registry §5.40: 4 envelope + 32 G + 8 position + 68 nested leaf + 4 count + 256x32"
    );
    assert_eq!(
        expected.len(),
        TRADER_ACCEPTANCE_LEN,
        "the crate's own length constant must agree with the independent encoding"
    );
    assert_eq!(
        subject().encode().expect("encodable"),
        expected,
        "the production encoder disagrees with the independent one"
    );
}

/// `ta_B = H_dom(DSM/trader-settlement-acceptance/v2, CCB)` — asserted against
/// the INDEPENDENT bytes first, so a drifting second encoder is caught rather
/// than silently agreeing with a drifting production one, and then against the
/// frozen literal.
#[test]
fn the_acceptance_identity_is_the_frozen_literal() {
    let p = path();
    let expected_bytes = indep_acceptance(G, POSITION, &indep_leaf(B, EOID), &p);
    let independent = indep::h_dom(TA_B_TAG, &expected_bytes);

    assert_eq!(
        independent, EXPECTED_TA_B,
        "the independent encoder no longer produces the frozen identity"
    );
    assert_eq!(
        subject().ta_b().expect("identity"),
        EXPECTED_TA_B,
        "the production identity disagrees with the frozen one"
    );
}

/// The nested leaf is carried as a COMPLETE CCB (§2.7), envelope included —
/// not as a bare pair of digests. Asserted by locating the leaf's own envelope
/// inside the enclosing bytes at its exact offset.
#[test]
fn the_nested_leaf_carries_its_own_envelope() {
    let bytes = subject().encode().expect("encodable");
    let at = 4 + 32 + 8; // envelope, G, position
    assert_eq!(
        &bytes[at..at + 4],
        &[0x00, 0x32, 0x00, 0x01],
        "field 3 must begin with the 0x0032 schema-1 envelope"
    );
    assert_eq!(
        &bytes[at..at + 68],
        indep_leaf(B, EOID).as_slice(),
        "and the whole nested CCB must match the independent leaf encoding"
    );
}

/// The path is a §2.5 SEQUENCE: a `u32_be` count followed by the elements in
/// the order given. Reversing it is a different object, which is the property
/// a set encoding would destroy.
#[test]
fn the_path_is_an_ordered_sequence_with_a_count_prefix() {
    let bytes = subject().encode().expect("encodable");
    let at = 4 + 32 + 8 + 68;
    assert_eq!(
        &bytes[at..at + 4],
        &[0x00, 0x00, 0x01, 0x00],
        "u32_be(256) precedes the siblings"
    );

    let mut reversed = path();
    reversed.reverse();
    let other = TraderAcceptance::new(
        G,
        POSITION,
        EconomicBundleAcceptanceState {
            bundle: B,
            economic_operation_id: EOID,
        },
        reversed,
    )
    .expect("well formed");
    assert_ne!(
        other.ta_b().expect("identity"),
        EXPECTED_TA_B,
        "leaf-to-root order is meaning; reversing it must change the identity"
    );
}

/// The frozen rejections of registry §5.40, at the boundary rather than
/// inside the encoder: an invalid acceptance has no canonical bytes at all.
#[test]
fn the_frozen_rejections_refuse_before_any_bytes_exist() {
    let leaf = EconomicBundleAcceptanceState {
        bundle: B,
        economic_operation_id: EOID,
    };

    let mut short = path();
    short.pop();
    assert!(matches!(
        TraderAcceptance::new(G, POSITION, leaf.clone(), short),
        Err(AcceptanceMalformed::PathLength {
            expected: 256,
            got: 255
        })
    ));

    assert!(matches!(
        TraderAcceptance::new([0u8; 32], POSITION, leaf, path()),
        Err(AcceptanceMalformed::GenesisIsZero)
    ));
}
