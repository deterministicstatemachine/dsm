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
    ConsumedDlvTransition, EncumbranceSet, FeePolicy, MarketPolicy, MarketTerms, ReleasePolicy,
    SettlementBundle, StorageSetMembers, VaultStateV2, SPX256F_SIGNATURE_LEN,
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
    68, 52, 120, 79, 84, 123, 35, 29, 175, 100, 237, 100, 252, 89, 186, 147, 163, 132, 87, 245,
    129, 2, 27, 37, 41, 197, 72, 233, 140, 212, 7, 0,
];
const CLOSE_ADDR: [u8; 32] = [
    175, 230, 194, 114, 117, 120, 147, 124, 66, 209, 204, 213, 251, 0, 209, 50, 157, 141, 190, 103,
    120, 66, 195, 147, 145, 76, 15, 213, 193, 37, 216, 115,
];
const CLOSE_C_NEXT: [u8; 32] = [
    201, 10, 173, 167, 78, 52, 108, 26, 142, 80, 242, 142, 130, 112, 165, 122, 199, 234, 187, 148,
    211, 33, 203, 193, 77, 214, 102, 100, 101, 238, 21, 202,
];
const MARKET_B: [u8; 32] = [
    66, 119, 134, 40, 227, 147, 188, 196, 176, 185, 244, 239, 189, 113, 74, 92, 29, 62, 248, 100,
    123, 88, 79, 79, 193, 87, 144, 214, 150, 148, 4, 75,
];
const MARKET_ADDR: [u8; 32] = [
    52, 39, 123, 214, 8, 40, 189, 35, 55, 197, 250, 84, 207, 160, 84, 92, 86, 24, 106, 52, 104,
    146, 159, 139, 52, 3, 106, 129, 122, 176, 198, 151,
];
const MARKET_C_NEXT: [u8; 32] = [
    88, 81, 131, 194, 192, 135, 159, 196, 243, 15, 252, 230, 230, 74, 138, 88, 40, 172, 114, 12,
    214, 32, 187, 15, 162, 99, 253, 20, 36, 127, 221, 149,
];
// 5c-2 Step 2 doubled this, and the reason is worth stating: `operation_bytes`
// is now a REAL signed settle preimage, which embeds the settler's own 49,856-byte
// SPHINCS+ signature. A market bundle therefore carries TWO signatures — the
// settler's inside the preimage and `sigma_dsm` over the successor — where the
// old filler carried none. Still an order of magnitude under the node's
// 512 KiB ingress cap, which the closure test asserts directly.
const MARKET_LEN: usize = 101_186;

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
        &[0x00, 0x0E, 0x00, 0x03],
        "0x000E SCHEMA 3 (2c-H)"
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

const X: [u8; 32] = [0x58; 32];
const NONCE: [u8; 32] = [0x5E; 32];
const CLAIM: [u8; 32] = [0x00; 32];

// 5c-2 Step 2. The trader coordinates and the recovery material are no longer
// this file's to choose. `op_bytes_fixture` (300 filler bytes) and
// `sigma_fixture` (a byte pattern) are DELETED: they could not have satisfied
// 2c-B's `G1`-`G4`, and a vector whose operands cannot satisfy the rules it
// exists to pin is pinning the wrong thing.
//
// The vector is still CLASS-1. What changed is where its INPUTS come from, not
// where its expected bytes come from: the operands are genuine producer output,
// and `indep::` re-encodes them independently of the production encoder, so
// agreement remains evidence rather than a tautology.
fn produced_terms() -> MarketTerms {
    dsm::ccb::settlement::fixtures::market_terms(PARENT, X)
}

fn indep_market_bundle() -> Vec<u8> {
    let produced = produced_terms();
    let ev = &produced.recovery_material;
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        produced.trader_parent,
        produced.trader_successor,
        indep::dsm_successor_evidence(
            ev.rel_key,
            ev.embedded_parent,
            ev.counterparty_devid,
            &ev.operation_bytes,
            ev.entropy,
            ev.sigma_dsm(),
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
    // The producer's own output, not a hand-assembled copy of it. If these two
    // ever diverge the vector stops testing the thing that ships.
    dsm::ccb::settlement::fixtures::market_bundle(PARENT, prod_successor(1_010_000, 495_065), X)
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
        &[0x00, 0x0E, 0x00, 0x03, 0x01],
        "field 1 PRESENT -> Market; 0x000E SCHEMA 3 (2c-H)"
    );
    assert_eq!(&bytes[5..9], &[0x00, 0x33, 0x00, 0x03], "0x0033 SCHEMA 3");
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

// ── the route vector: amendment 2c-H, grammar 33 at N = 2 (H17) ─────────────

// Pinned from the independent encoder; the producer supplies the operands.
const ROUTE_B: [u8; 32] = [
    230, 102, 3, 151, 72, 94, 75, 158, 177, 32, 23, 158, 145, 30, 194, 170, 175, 240, 12, 27, 137,
    62, 126, 45, 146, 9, 36, 191, 235, 82, 136, 39,
];
const ROUTE_ADDR: [u8; 32] = [
    136, 85, 97, 43, 252, 245, 67, 138, 69, 68, 174, 91, 181, 173, 138, 185, 75, 119, 176, 173,
    159, 121, 134, 30, 102, 234, 178, 17, 86, 241, 54, 164,
];
const ROUTE_LEN: usize = 102_055;

const ROUTE_PARENTS: [[u8; 32]; 2] = [[0xE1; 32], [0xE2; 32]];
const TOKEN_MID: [u8; 32] = [0x30; 32];

/// Vault `k` of the route: vault 0 holds `TOKEN_A/TOKEN_MID`, vault 1 holds
/// `TOKEN_B/TOKEN_MID`; both under the one settlement domain (same set, same
/// quorum), each linked to its own route parent.
struct RouteVault {
    id: [u8; 32],
    pair: ([u8; 32], [u8; 32]),
    reserves: (u64, u64),
}

fn route_vault(k: usize) -> RouteVault {
    match k {
        0 => RouteVault {
            id: [0x03; 32],
            pair: (TOKEN_A, TOKEN_MID),
            reserves: (1_010_000, 495_065),
        },
        _ => RouteVault {
            id: [0x04; 32],
            pair: (TOKEN_B, TOKEN_MID),
            reserves: (500_000, 250_000),
        },
    }
}

fn indep_route_successor(k: usize) -> Vec<u8> {
    let RouteVault {
        id: vault,
        pair: (a, b),
        reserves: (ra, rb),
    } = route_vault(k);
    indep::vault_state(
        G_O,
        D_O,
        vault,
        GENERATION,
        ra,
        rb,
        indep::market_policy(0x0001, 1, a, b),
        indep::release_policy(0x0001, 1),
        indep::fee_policy(FEE_BPS),
        indep::encumbrance_set(vec![]),
        None,
        ROUTE_PARENTS[k],
        R_O,
        indep::storage_set(members()),
        QUORUM,
    )
}

fn prod_route_successor(k: usize) -> VaultStateV2 {
    let RouteVault {
        id: vault,
        pair: (a, b),
        reserves: (ra, rb),
    } = route_vault(k);
    let mut v = prod_successor(ra, rb);
    v.vault_id = vault;
    v.market_policy = MarketPolicy::beta_constant_product(a, b).unwrap();
    v.parent_state_commitment = ROUTE_PARENTS[k];
    v
}

/// GENUINE grammar-33 terms: a signed route settle prepared and assembled by
/// the real producer, which runs G1-G5 over its own output.
fn produced_route_terms() -> MarketTerms {
    dsm::ccb::settlement::fixtures::route_market_terms(ROUTE_PARENTS, X)
}

fn indep_route_bundle() -> Vec<u8> {
    let produced = produced_route_terms();
    let ev = &produced.recovery_material;
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 2_000, 2 * FEE_BPS, NONCE);
    let legs = vec![
        indep::allocation(
            ROUTE_PARENTS[0],
            10_000,
            4_935,
            CLAIM,
            indep::fee_policy(FEE_BPS),
        ),
        indep::allocation(
            ROUTE_PARENTS[1],
            4_935,
            2_000,
            CLAIM,
            indep::fee_policy(FEE_BPS),
        ),
    ];
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(legs),
        produced.trader_parent,
        produced.trader_successor,
        indep::dsm_successor_evidence(
            ev.rel_key,
            ev.embedded_parent,
            ev.counterparty_devid,
            &ev.operation_bytes,
            ev.entropy,
            ev.sigma_dsm(),
        ),
    );
    indep::settlement_bundle(
        Some(terms),
        (0..2)
            .map(|k| {
                indep::consumed_dlv_transition(ROUTE_PARENTS[k], indep_route_successor(k), None)
            })
            .collect(),
    )
}

fn prod_route_bundle() -> SettlementBundle {
    SettlementBundle::market(
        produced_route_terms(),
        (0..2)
            .map(|k| {
                ConsumedDlvTransition::market(ROUTE_PARENTS[k], prod_route_successor(k)).unwrap()
            })
            .collect(),
    )
    .unwrap()
}

/// The amendment's `MARKET_ROUTE` vector, cut once from the genuine producer at
/// `N = 2`: one bundle over both vaults, grammar 33 inside field 6, and H7's
/// length re-measured from real bytes.
#[test]
fn the_route_vector_is_one_bundle_over_both_vaults() {
    let bytes = indep_route_bundle();
    assert_eq!(
        bytes.len(),
        ROUTE_LEN,
        "the complete route byte vector's length"
    );
    assert!(
        bytes.len() < 512 * 1024,
        "under the storage node's ingress cap"
    );
    assert_eq!(
        &bytes[..5],
        &[0x00, 0x0E, 0x00, 0x03, 0x01],
        "Market, 0x000E SCHEMA 3"
    );
    assert_eq!(&bytes[5..9], &[0x00, 0x33, 0x00, 0x03], "0x0033 SCHEMA 3");

    let ev = produced_route_terms().recovery_material;
    assert_eq!(ev.operation_bytes[0], 33, "grammar 33");
    assert_eq!(
        ev.operation_bytes.len(),
        50_010 + 348 * 2 + 5,
        "H7: 50,010 + 348·N + |RC| at N = 2 with a 5-byte RouteCommit"
    );

    // 1. the production encoder agrees.
    assert_eq!(prod_route_bundle().encode().unwrap(), bytes);
    // 2. the decoder rebuilds the object and records both spans.
    let d = decode_settlement_bundle_canonical(&bytes).unwrap();
    assert_eq!(d.bundle, prod_route_bundle());
    assert_eq!(d.successor_spans.len(), 2);
    // 3. the identities are the pinned literals.
    let b = indep::h_dom(NS, &bytes);
    assert_eq!(b, ROUTE_B);
    assert_eq!(indep::storage_addr(NS, &b), ROUTE_ADDR);
    assert_eq!(dsm::dlv::settlement_bundle::bundle_digest(&bytes), b);
    // K(B) names both parents; the receipt carries both successors (§5.42, N-wise).
    assert_eq!(
        dsm::dlv::settlement_bundle::key_set(&prod_route_bundle())
            .unwrap()
            .len(),
        2
    );
    let receipt = dsm::dlv::sofi_receipt::SofiReceipt::project(&prod_route_bundle(), A_B)
        .expect("a route bundle has a receipt");
    assert_eq!(
        receipt.encode().len(),
        4 + 96 + 4 + 33 * 2,
        "170 bytes at N = 2"
    );
}

// ── the Def 14.2 receipt of the market vector (amendment 2c-F, §5.42) ─────────

/// `a_B` for the vector. The receipt binds the acceptance identity as a bare
/// digest, so any 32 bytes exercise the layout; the walk, not this vector, is
/// what says which acceptance a settlement has.
const A_B: [u8; 32] = [0xAB; 32];

#[test]
fn the_market_vector_projects_the_frozen_receipt() {
    // Expected bytes from the pinned identities and the independent encoder
    // alone: `b` and `c_{n+1}` are the literals pinned above, never recomputed
    // by the production helpers.
    let expected = [
        indep::envelope(0x0034, 1),
        MARKET_B.to_vec(),
        X.to_vec(),
        A_B.to_vec(),
        indep::u32be(1),
        MARKET_C_NEXT.to_vec(),
        vec![0x00], // witness_hash: absent in schema 1
    ]
    .concat();
    assert_eq!(expected.len(), 137, "registry §5.42 pins 137 bytes");

    let produced = dsm::dlv::sofi_receipt::SofiReceipt::project(&prod_market_bundle(), A_B)
        .expect("a market bundle has a receipt");
    assert_eq!(
        produced.encode(),
        expected,
        "the production projection is frozen"
    );

    const TAG: &[u8] = b"DSM/sofi-receipt/v1";
    let rho = indep::h_dom(TAG, &expected);
    assert_eq!(produced.digest(), rho);
    assert_eq!(produced.address(), indep::storage_addr(TAG, &rho));

    let decoded = dsm::dlv::sofi_receipt::decode_sofi_receipt(&expected).expect("decodes");
    assert_eq!(decoded, produced);
    assert_eq!(
        dsm::dlv::sofi_receipt::verify(&expected, &prod_market_bundle(), A_B),
        Ok(produced)
    );
}

// ── shape and structure vectors: hand-built bytes the decoder must refuse ─────

#[test]
fn a_close_authorization_inside_a_market_bundle_is_refused() {
    // The terms are genuine; what must be refused is the close authorization
    // riding under them, so nothing about the trade itself is weakened here.
    let produced = produced_terms();
    let ev = &produced.recovery_material;
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        produced.trader_parent,
        produced.trader_successor,
        indep::dsm_successor_evidence(
            ev.rel_key,
            ev.embedded_parent,
            ev.counterparty_devid,
            &ev.operation_bytes,
            ev.entropy,
            ev.sigma_dsm(),
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
/// it. Since 5c-2 Step 2 this vector's `operation_bytes` are a REAL signed
/// preimage and its successor a real recomputed chain tip, so the mutation
/// below is the only thing wrong with the bytes.
#[test]
fn market_terms_whose_evidence_names_another_trader_parent_are_refused_inside_the_bytes() {
    // Every operand is genuine producer output EXCEPT the embedded parent,
    // which is the single mutation under test.
    let produced = produced_terms();
    let ev = &produced.recovery_material;
    let intent = indep::trade_intent(TOKEN_A, 10_000, TOKEN_B, 4_935, FEE_BPS, NONCE);
    let leg = indep::allocation(PARENT, 10_000, 4_935, CLAIM, indep::fee_policy(FEE_BPS));
    let terms = indep::market_terms(
        intent,
        X,
        indep::route(vec![leg]),
        produced.trader_parent,
        produced.trader_successor,
        indep::dsm_successor_evidence(
            ev.rel_key,
            [0xEE; 32], // the ONE mutation: NOT the produced embedded parent
            ev.counterparty_devid,
            &ev.operation_bytes,
            ev.entropy,
            ev.sigma_dsm(),
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
        // 0x0011 is TraderAcceptance (amendment 2c-D §6): it left
        // `declared_unencoded` when its encoder landed, so it belongs here or
        // it belongs to no set at all.
        0x0001, 0x0002, 0x0004, 0x0005, 0x0007, 0x0009, 0x000A, 0x000B, 0x000D, 0x000E, 0x000F,
        0x0011, 0x0010, 0x0015, 0x0016, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E,
        0x001F, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029,
        0x0030,
        // 0x0032 is the bundle-acceptance leaf state (amendment 2c-D): it left
        // `declared_unencoded` when its encoder landed, so it belongs here or
        // it belongs to no set at all.
        0x0031, 0x0032, 0x0033,
        // 0x0034 is the Def 14.2 SofiReceipt (amendment 2c-F R4), allocated
        // with its encoder.
        0x0034,
        // 0x0035 is the route reserve-consumption credit source (amendment
        // 2c-H H9), allocated with its encoder.
        0x0035,
        // 0x0036..=0x0042 and 0x004A are the SoFi v8 wire objects
        // (`crate::sofi::wire`), allocated with their field tables and
        // encoders. 0x0043..=0x0049 were the resolution-record and
        // route-outcome family; the demolition burned them, so they belong to
        // `burned_class` and nowhere else.
        0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F, 0x0040,
        0x0041, 0x0042, 0x004A,
    ];
    for n in 0x0001u16..=0x004A {
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
    // 2c-F R1 ratified the shipped X, so `R` and `Q` have no encoder at ANY
    // schema: both classes are burned outright, never merely unencoded.
    for n in [0x000C, 0x0017] {
        assert!(
            burned_class::is_burned_class(n),
            "{n:#06x} burned by 2c-F R1"
        );
        assert!(!declared_unencoded::is_declared_unencoded(n));
    }
    // The machine-readable burn table, so a retired envelope classifies as
    // BURNED rather than as an unknown schema — the distinction registry §2.8
    // rests its never-re-assign guarantee on. 2c-E burned schema 1 of the
    // intent and of the two classes it propagates through. Amendment 2c-H H17
    // widened `0x0031` field 4 to grammar 33, burning `0x0031` schema 1 and, by
    // §2.7 nesting, `0x0033` and `0x000E` schema 2. The live schema is read
    // from each class's own constant, and a live schema is never burned.
    use dsm::ccb::{CcbObject, DsmSuccessorEvidence, TradeIntent};
    for (n, burned, live) in [
        (0x000B, &[1u16][..], TradeIntent::SCHEMA),
        (0x0031, &[1][..], DsmSuccessorEvidence::SCHEMA),
        (0x0033, &[1, 2][..], MarketTerms::SCHEMA),
        (0x000E, &[1, 2][..], SettlementBundle::SCHEMA),
    ] {
        for s in burned {
            assert!(
                dsm::ccb::schema::is_burned(n, *s),
                "{n:#06x} schema {s} is burned"
            );
        }
        assert!(
            !dsm::ccb::schema::is_burned(n, live),
            "{n:#06x} schema {live} is the LIVE form and must never be burned"
        );
    }
    assert_eq!(
        (
            TradeIntent::SCHEMA,
            DsmSuccessorEvidence::SCHEMA,
            MarketTerms::SCHEMA,
            SettlementBundle::SCHEMA
        ),
        (2, 2, 3, 3),
        "the live schemas after amendment 2c-H H17"
    );
}
