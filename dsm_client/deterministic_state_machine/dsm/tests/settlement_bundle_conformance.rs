// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! CLASS-1 CONFORMANCE VECTORS FOR THE CANONICAL SETTLEMENT BUNDLE — amendment
//! 2c-A.1, both shapes.
//!
//! Amendment 2c-C2 ruling D: a class-1 vector's expected bytes are produced
//! WITHOUT the production encoder, decoder or digest helpers. Every byte below
//! comes from `common/indep_ccb.rs`, written from the registry text; `b`,
//! `addr(B)` and `c_{n+1}` are computed by an independent `H_dom`, never by
//! `bundle_digest` / `bundle_addr` / `vault_state_commitment`. The pinned
//! literals were captured ONCE from the independent encoder and frozen.
//!
//! The owner-close vector reproduces 2c-A's worked layout: 423-byte
//! `V_{n+1}`, 50,321-byte `T_v`, 50,330-byte `B`. The market vector is the
//! "2c-A + 2c-B closure test" 2c-A calls mandatory — the first complete market
//! byte vector — and it demonstrates the required property: same exact
//! prepared inputs -> identical `B` bytes -> identical `b`.
//!
//! Three things are checked per vector, and they are different checks:
//!   1. the production encoder reproduces the independent bytes (the encoding
//!      is frozen);
//!   2. the production decoder rebuilds the object and records the exact
//!      successor span (the operand of `VDS.COMMON.10.a` is the bytes on the
//!      wire, never a re-encoding);
//!   3. the identities `b`, `addr(B)`, `c_{n+1}` equal the pinned literals.
//!
//! Byte arrays throughout, never hex (C2 ruling D).

#[path = "common/indep_ccb.rs"]
mod indep;

use dsm::ccb::decode::{decode_settlement_bundle, decode_settlement_bundle_canonical, DecodeError};
use dsm::ccb::{
    Allocation, ConsumedDlvTransition, DsmSuccessorEvidence, EncumbranceSet, FeePolicy,
    MarketPolicy, MarketTerms, ReleasePolicy, Route, RouteLeg, SettlementBundle, StorageSetMembers,
    TradeIntent, VaultStateV2, SPX256F_SIGNATURE_LEN,
};

const NS: &[u8] = b"DSM/settlement-bundle";
const VAULT_STATE_TAG: &[u8] = b"DSM/vault-state";

// ── the shared fixture (2c-A's worked owner-close fixture) ───────────────────

const G_O: [u8; 32] = [0x01; 32];
const D_O: [u8; 32] = [0x02; 32];
const VAULT_ID: [u8; 32] = [0x03; 32];
const TOKEN_A: [u8; 32] = [0x10; 32];
const TOKEN_B: [u8; 32] = [0x20; 32];
const R_O: [u8; 32] = [0x0D; 32];
const PARENT: [u8; 32] = [0xC0; 32];
const FEE_BPS: u32 = 30;
const QUORUM: u32 = 2;
const GENERATION: u64 = 8;

fn members() -> Vec<(Vec<u8>, [u8; 32])> {
    vec![
        (b"node-1".to_vec(), [0x11; 32]),
        (b"node-2".to_vec(), [0x22; 32]),
        (b"node-3".to_vec(), [0x33; 32]),
    ]
}

fn sig_fixture() -> Vec<u8> {
    (0..SPX256F_SIGNATURE_LEN)
        .map(|i| (i % 251) as u8)
        .collect()
}

fn indep_successor(reserve_a: u64, reserve_b: u64) -> Vec<u8> {
    indep::vault_state(
        G_O,
        D_O,
        VAULT_ID,
        GENERATION,
        reserve_a,
        reserve_b,
        indep::market_policy(0x0001, 1, TOKEN_A, TOKEN_B),
        indep::release_policy(0x0001, 1),
        indep::fee_policy(FEE_BPS),
        indep::encumbrance_set(vec![]),
        None,
        PARENT,
        R_O,
        indep::storage_set(members()),
        QUORUM,
    )
}

fn prod_successor(reserve_a: u64, reserve_b: u64) -> VaultStateV2 {
    let m = members();
    let refs: Vec<(&[u8], [u8; 32])> = m.iter().map(|(id, inc)| (id.as_slice(), *inc)).collect();
    VaultStateV2 {
        owner_genesis_id: G_O,
        owner_device_id: D_O,
        vault_id: VAULT_ID,
        generation: GENERATION,
        reserve_a,
        reserve_b,
        market_policy: MarketPolicy::beta_constant_product(TOKEN_A, TOKEN_B).unwrap(),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(FEE_BPS).unwrap(),
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: None,
        parent_state_commitment: PARENT,
        owner_authority_transition_digest: R_O,
        storage_set: StorageSetMembers::new(&refs).unwrap(),
        quorum: QUORUM,
    }
}

// ── pinned identities (captured once from the independent encoder) ───────────

const CLOSE_B: [u8; 32] = [
    19, 14, 237, 145, 26, 180, 133, 226, 121, 53, 213, 205, 56, 229, 207, 161, 0, 225, 242, 44,
    228, 40, 86, 121, 181, 10, 25, 116, 218, 66, 113, 248,
];
const CLOSE_ADDR: [u8; 32] = [
    124, 202, 174, 159, 47, 228, 36, 49, 3, 140, 43, 39, 191, 199, 222, 150, 9, 155, 89, 142, 206,
    54, 134, 166, 123, 246, 141, 41, 235, 249, 213, 218,
];
const CLOSE_C_NEXT: [u8; 32] = [
    201, 10, 173, 167, 78, 52, 108, 26, 142, 80, 242, 142, 130, 112, 165, 122, 199, 234, 187, 148,
    211, 33, 203, 193, 77, 214, 102, 100, 101, 238, 21, 202,
];
const MARKET_B: [u8; 32] = [
    133, 132, 102, 202, 228, 107, 231, 91, 84, 220, 218, 237, 60, 4, 29, 208, 223, 11, 9, 23, 201,
    83, 169, 125, 122, 80, 39, 29, 254, 206, 84, 150,
];
const MARKET_ADDR: [u8; 32] = [
    116, 21, 183, 190, 111, 55, 90, 16, 14, 149, 176, 90, 11, 219, 75, 233, 134, 89, 129, 214, 49,
    198, 194, 240, 157, 89, 214, 215, 183, 186, 25, 161,
];
const MARKET_C_NEXT: [u8; 32] = [
    88, 81, 131, 194, 192, 135, 159, 196, 243, 15, 252, 230, 230, 74, 138, 88, 40, 172, 114, 12,
    214, 32, 187, 15, 162, 99, 253, 20, 36, 127, 221, 149,
];
const MARKET_LEN: usize = 51091;

// ── the owner-close vector ───────────────────────────────────────────────────

fn indep_close_bundle() -> Vec<u8> {
    indep::settlement_bundle(
        None,
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(0, 0),
            Some(&sig_fixture()),
        )],
    )
}

fn prod_close_bundle() -> SettlementBundle {
    SettlementBundle::owner_close(
        ConsumedDlvTransition::owner_close(PARENT, prod_successor(0, 0), sig_fixture()).unwrap(),
    )
    .unwrap()
}

#[test]
fn owner_close_reproduces_the_worked_layout_byte_for_byte() {
    let bytes = indep_close_bundle();
    assert_eq!(indep_successor(0, 0).len(), 423, "0x0001 schema 4 fixture");
    assert_eq!(bytes.len(), 50_330, "0x000E owner close, 2c-A worked total");
    // The framing 2c-A prints.
    assert_eq!(
        &bytes[..4],
        &[0x00, 0x0E, 0x00, 0x02],
        "0x000E SCHEMA 2 (2c-E)"
    );
    assert_eq!(
        bytes[4], 0x00,
        "field 1 ABSENT is EMITTED, and it is the discriminator"
    );
    assert_eq!(&bytes[5..9], &[0x00, 0x00, 0x00, 0x01], "one transition");
    assert_eq!(&bytes[9..13], &[0x00, 0x0F, 0x00, 0x01]);
    assert_eq!(
        &bytes[13..45],
        &PARENT,
        "parent_binding is a bare digest32, no length prefix"
    );
    assert_eq!(
        &bytes[45..49],
        &[0x00, 0x01, 0x00, 0x04],
        "successor nests 0x0001 SCHEMA 4"
    );
    let f3 = 45 + 423;
    assert_eq!(bytes[f3], 0x00, "proof_material absent");
    assert_eq!(bytes[f3 + 1], 0x01, "close_authorization present");
    assert_eq!(
        &bytes[f3 + 2..f3 + 6],
        &(SPX256F_SIGNATURE_LEN as u32).to_be_bytes(),
        "field 4 is `bytes`: u32 length then the signature"
    );
    // Linkage is checkable inside the bytes: field 12 of the successor.
    let f12 = 45 + 4 + 32 * 3 + 8 * 3 + 72 + 8 + 8 + 8 + 1;
    assert_eq!(&bytes[f12..f12 + 32], &PARENT);

    // 1. the production encoder agrees.
    assert_eq!(prod_close_bundle().encode().unwrap(), bytes);
}

#[test]
fn owner_close_identities_are_pinned_and_the_decoder_records_the_span() {
    let bytes = indep_close_bundle();
    let b = indep::h_dom(NS, &bytes);
    assert_eq!(b, CLOSE_B, "b = H_dom(DSM/settlement-bundle, CCB(B))");
    assert_eq!(indep::storage_addr(NS, &b), CLOSE_ADDR, "addr(B)");
    let c_next = indep::h_dom(VAULT_STATE_TAG, &indep_successor(0, 0));
    assert_eq!(
        c_next, CLOSE_C_NEXT,
        "c_{{n+1}} derived from the field-2 bytes"
    );

    // 2. the decoder rebuilds the object and the span IS the nested bytes.
    let d = decode_settlement_bundle_canonical(&bytes).unwrap();
    assert_eq!(d.bundle, prod_close_bundle());
    assert_eq!(d.successor_spans.len(), 1);
    assert_eq!(
        &bytes[d.successor_spans[0].clone()],
        indep_successor(0, 0).as_slice()
    );
    // Production identities agree with the independent ones.
    assert_eq!(dsm::dlv::settlement_bundle::bundle_digest(&bytes), b);
    assert_eq!(dsm::dlv::settlement_bundle::bundle_addr(&bytes), CLOSE_ADDR);
    assert_eq!(
        dsm::ccb::vault_state_commitment(&prod_successor(0, 0)).unwrap(),
        c_next
    );
}

// ── the market vector: the 2c-A + 2c-B closure test ──────────────────────────

const REL_KEY: [u8; 32] = [0x51; 32];
const TRADER_PARENT: [u8; 32] = [0x52; 32];
const TRADER_DEVID: [u8; 32] = [0x53; 32];
const ENTROPY: [u8; 32] = [0x55; 32];
const X: [u8; 32] = [0x58; 32];
const TRADER_SUCCESSOR: [u8; 32] = [0x59; 32];
const NONCE: [u8; 32] = [0x5E; 32];
const CLAIM: [u8; 32] = [0x00; 32];

fn op_bytes_fixture() -> Vec<u8> {
    (0..300u32)
        .map(|i| (i.wrapping_mul(7) % 256) as u8)
        .collect()
}

fn sigma_fixture() -> Vec<u8> {
    (0..SPX256F_SIGNATURE_LEN)
        .map(|i| ((i * 3) % 253) as u8)
        .collect()
}

fn indep_market_bundle() -> Vec<u8> {
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        TRADER_PARENT,
        TRADER_SUCCESSOR,
        indep::dsm_successor_evidence(
            REL_KEY,
            TRADER_PARENT,
            TRADER_DEVID,
            &op_bytes_fixture(),
            ENTROPY,
            &sigma_fixture(),
        ),
    );
    indep::settlement_bundle(
        Some(terms),
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(1_010_000, 495_065),
            None,
        )],
    )
}

fn prod_market_bundle() -> SettlementBundle {
    let terms = MarketTerms {
        intent: TradeIntent {
            token_in: TOKEN_A,
            amount_in: 10_000,
            token_out: TOKEN_B,
            exact_out: 4_935,
            fee_bps: FEE_BPS,
            nonce: NONCE,
        },
        route_set_commitment: X,
        selected_route: Route::new(vec![RouteLeg::Single(Allocation {
            parent_binding: PARENT,
            delta_in: 10_000,
            delta_out: 4_935,
            encumbrance_claim: CLAIM,
            fee_policy: FeePolicy::new(FEE_BPS).unwrap(),
        })])
        .unwrap(),
        trader_parent: TRADER_PARENT,
        trader_successor: TRADER_SUCCESSOR,
        recovery_material: DsmSuccessorEvidence::new(
            REL_KEY,
            TRADER_PARENT,
            TRADER_DEVID,
            op_bytes_fixture(),
            ENTROPY,
            sigma_fixture(),
        )
        .unwrap(),
    };
    SettlementBundle::market(
        terms,
        vec![ConsumedDlvTransition::market(PARENT, prod_successor(1_010_000, 495_065)).unwrap()],
    )
    .unwrap()
}

#[test]
fn the_market_vector_is_the_a_plus_b_closure_test() {
    let bytes = indep_market_bundle();
    assert_eq!(
        bytes.len(),
        MARKET_LEN,
        "the complete market byte vector's length"
    );
    assert!(
        bytes.len() < 512 * 1024,
        "under the storage node's ingress cap"
    );
    // The worked layout, as 2c-E leaves it: the 0x0033 header, then the intent
    // at 4, X at 124, the route at 156 — and field 6, which 2c-B closed,
    // following the two trader coordinates. X and the route each sit 16 bytes
    // earlier than the 2c-A layout because schema 2's intent is 120 bytes
    // rather than 136: `min_out` and `max_fee` (8 each) and `max_hops`,
    // `max_fanout`, `k` (4 each) left, and `fee_bps` (4) arrived.
    assert_eq!(
        &bytes[..5],
        &[0x00, 0x0E, 0x00, 0x02, 0x01],
        "field 1 PRESENT -> Market; 0x000E SCHEMA 2 (2c-E)"
    );
    assert_eq!(&bytes[5..9], &[0x00, 0x33, 0x00, 0x02], "0x0033 SCHEMA 2");
    assert_eq!(
        &bytes[9..13],
        &[0x00, 0x0B, 0x00, 0x02],
        "intent at MarketTerms offset 4, 0x000B SCHEMA 2"
    );
    assert_eq!(&bytes[5 + 124..5 + 156], &X, "X at offset 124");
    assert_eq!(
        &bytes[5 + 156..5 + 160],
        &[0x00, 0x0D, 0x00, 0x02],
        "route at 156, schema 2"
    );
    // The route: one Single leg, i.e. a 0x0015 schema-2 envelope right after
    // the count.
    assert_eq!(&bytes[5 + 164..5 + 168], &[0x00, 0x15, 0x00, 0x02]);

    // 1. the production encoder agrees.
    assert_eq!(prod_market_bundle().encode().unwrap(), bytes);

    // The property the closure test exists for: same exact prepared inputs
    // twice -> identical B bytes -> identical b.
    assert_eq!(indep_market_bundle(), bytes);
    assert_eq!(
        prod_market_bundle().encode().unwrap(),
        prod_market_bundle().encode().unwrap()
    );
}

#[test]
fn market_identities_are_pinned_and_the_decoder_records_the_span() {
    let bytes = indep_market_bundle();
    let b = indep::h_dom(NS, &bytes);
    assert_eq!(b, MARKET_B);
    assert_eq!(indep::storage_addr(NS, &b), MARKET_ADDR);
    let successor = indep_successor(1_010_000, 495_065);
    assert_eq!(indep::h_dom(VAULT_STATE_TAG, &successor), MARKET_C_NEXT);

    let d = decode_settlement_bundle_canonical(&bytes).unwrap();
    assert_eq!(d.bundle, prod_market_bundle());
    assert_eq!(&bytes[d.successor_spans[0].clone()], successor.as_slice());
    assert_eq!(dsm::dlv::settlement_bundle::bundle_digest(&bytes), b);
}

// ── shape and structure vectors: hand-built bytes the decoder must refuse ─────

#[test]
fn a_close_authorization_inside_a_market_bundle_is_refused() {
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        TRADER_PARENT,
        TRADER_SUCCESSOR,
        indep::dsm_successor_evidence(
            REL_KEY,
            TRADER_PARENT,
            TRADER_DEVID,
            &op_bytes_fixture(),
            ENTROPY,
            &sigma_fixture(),
        ),
    );
    // A retired successor with an authorization, riding under market terms.
    let bytes = indep::settlement_bundle(
        Some(terms),
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(0, 0),
            Some(&sig_fixture()),
        )],
    );
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("close authorization")
    ));
}

#[test]
fn an_owner_close_without_authorization_is_refused() {
    let bytes = indep::settlement_bundle(
        None,
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(0, 0),
            None,
        )],
    );
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("no close authorization")
    ));
}

#[test]
fn a_transposed_parent_linkage_is_refused_inside_the_bytes() {
    // field 1 names one parent, the successor's field 12 another.
    let bytes = indep::settlement_bundle(
        None,
        vec![indep::consumed_dlv_transition(
            [0xC9; 32],
            indep_successor(0, 0),
            Some(&sig_fixture()),
        )],
    );
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("parent_binding")
    ));
}

/// 2c-B's second chain-tip equality, at the boundary a FOREIGN bundle crosses:
/// field 4 names one trader parent and the nested `0x0031` field 2 another.
/// The independent encoder will happily emit it; the decoder must not accept
/// it. (Its sibling conjunct — the frozen `DlvSettleOperationPreimageV1`
/// grammar and the recomputed relationship chain tip — is NOT enforced yet and
/// waits on 5c-2 Step 2/3, so this vector's `operation_bytes` stay arbitrary.)
#[test]
fn market_terms_whose_evidence_names_another_trader_parent_are_refused_inside_the_bytes() {
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        TRADER_PARENT,
        TRADER_SUCCESSOR,
        indep::dsm_successor_evidence(
            REL_KEY,
            [0xEE; 32], // NOT TRADER_PARENT
            TRADER_DEVID,
            &op_bytes_fixture(),
            ENTROPY,
            &sigma_fixture(),
        ),
    );
    let bytes = indep::settlement_bundle(
        Some(terms),
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(1_010_000, 495_065),
            None,
        )],
    );
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("embedded_parent")
    ));
    // …and the honest vector still decodes, so the refusal is the mismatch and
    // not the fixture decaying.
    assert!(decode_settlement_bundle(&indep_market_bundle()).is_ok());
}

#[test]
fn a_close_whose_successor_holds_reserves_is_refused() {
    let bytes = indep::settlement_bundle(
        None,
        vec![indep::consumed_dlv_transition(
            PARENT,
            indep_successor(1, 0),
            Some(&sig_fixture()),
        )],
    );
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("drains both legs")
    ));
}

#[test]
fn a_bare_proof_material_envelope_is_refused() {
    let mut t = indep::consumed_dlv_transition(PARENT, indep_successor(0, 0), Some(&sig_fixture()));
    let f3 = 4 + 32 + 423;
    assert_eq!(t[f3], 0x00);
    t[f3] = 0x01;
    t.splice(f3 + 1..f3 + 1, [0x00, 0x10, 0x00, 0x01]);
    let bytes = indep::settlement_bundle(None, vec![t]);
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("proof_material")
    ));
}

#[test]
fn two_transitions_are_refused_in_beta() {
    let t = |p: [u8; 32]| {
        let mut v = indep_successor(0, 0);
        // field 12 of the successor must be this parent for the linkage check
        // to pass and the cardinality to be what is refused.
        let f12 = 4 + 32 * 3 + 8 * 3 + 72 + 8 + 8 + 8 + 1;
        v[f12..f12 + 32].copy_from_slice(&p);
        indep::consumed_dlv_transition(p, v, Some(&sig_fixture()))
    };
    let bytes = indep::settlement_bundle(None, vec![t([0xA1; 32]), t([0xA2; 32])]);
    assert!(matches!(
        decode_settlement_bundle(&bytes),
        Err(DecodeError::Invalid(m)) if m.contains("exactly one transition")
    ));
}

// ── the namespace is enforced for every registry number (2c-A.1 ruling 11) ──

#[test]
fn every_registry_number_is_in_exactly_one_namespace_set() {
    use dsm::ccb::{burned_class, declared_unencoded, reserved};
    let encodable: &[u16] = &[
        0x0001, 0x0002, 0x0004, 0x0005, 0x0007, 0x0009, 0x000A, 0x000B, 0x000D, 0x000E, 0x000F,
        0x0010, 0x0015, 0x0016, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
        0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x0030,
        0x0031, 0x0033,
    ];
    for n in 0x0001u16..=0x0033 {
        let sets = [
            encodable.contains(&n),
            reserved::is_reserved(n),
            declared_unencoded::is_declared_unencoded(n),
            burned_class::is_burned_class(n),
        ];
        assert_eq!(
            sets.iter().filter(|s| **s).count(),
            1,
            "{n:#06x} must be in exactly one of encodable / reserved / declared-unencoded / burned"
        );
    }
    // The nine the cut ships are encodable and nothing else.
    for n in [
        0x000B, 0x000D, 0x000E, 0x000F, 0x0010, 0x0015, 0x0016, 0x0031, 0x0033,
    ] {
        assert!(encodable.contains(&n));
        assert!(!declared_unencoded::is_declared_unencoded(n));
    }
    // And the route-family schema-1 burns are recorded.
    for n in [0x000C, 0x000D, 0x0015, 0x0016, 0x0017] {
        assert!(
            dsm::ccb::schema::is_burned(n, 1),
            "{n:#06x} schema 1 is burned"
        );
    }
    // 2c-E's burns: the intent cut, and the two classes it propagates through.
    // Recorded in the machine-readable table, not only in a comment, so a
    // schema-1 envelope classifies as BURNED rather than as an unknown schema —
    // the distinction registry §2.8 rests its never-re-assign guarantee on.
    for n in [0x000B, 0x0033, 0x000E] {
        assert!(
            dsm::ccb::schema::is_burned(n, 1),
            "{n:#06x} schema 1 is burned by 2c-E"
        );
        assert!(
            !dsm::ccb::schema::is_burned(n, 2),
            "{n:#06x} schema 2 is the LIVE form and must never be burned"
        );
    }
}
