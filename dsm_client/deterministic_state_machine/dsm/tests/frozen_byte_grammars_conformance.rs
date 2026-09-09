// SPDX-License-Identifier: Apache-2.0

//! CLASS-1 CONFORMANCE FOR THE TWO FROZEN FOREIGN BYTE GRAMMARS (2c-B).
//!
//! 2c-B freezes `CloseAuthorizationPreimageV1` and `DlvSettleOperationPreimageV1`
//! as byte grammars and then states the authority rule that makes this file
//! necessary:
//!
//! > The shipping `Operation::to_bytes` is the CURRENT IMPLEMENTATION of these
//! > grammars and is byte-identical to them. It is evidence of the byte grammar,
//! > NEVER the normative authority. A future refactor that changes these bytes
//! > changes the protocol and requires an amendment.
//!
//! Nothing enforced that. The grammars appeared in the tree only inside doc
//! comments, so "byte-identical" was an unchecked claim about live signatures:
//! `dlv::close_authorization` signs `Operation::to_bytes()` directly, which means
//! a refactor that reorders a field, widens an integer or drops a length prefix
//! would silently invalidate every close signature ever produced, with no test
//! going red. That is the failure this file exists to make impossible.
//!
//! CLASS-1 (2c-C2 ruling D): the expected bytes below are built by a LOCAL
//! encoder written from the amendment's field tables. It never calls the
//! production encoder under test, so agreement is evidence rather than a
//! tautology. The local helpers deliberately mirror 2c-B's primitives, which are
//! the OPPOSITE of CCB's — every 32-byte value is length-prefixed here, never
//! bare, because these are foreign grammars and not CCB objects.
//!
//! What this file does NOT establish: that any producer emits a conforming
//! preimage. The market producer cannot until 5c-2 Step 2/3, and 2c-B's `G1`-`G4`
//! remain unenforced in production until then. This pins the grammar; it does
//! not lift the market refusal.

use dsm::types::operations::{Operation, TransactionMode};

// ── The local encoder: 2c-B "Shared primitives, stated once" ────────────────

/// `bytes(x) = u32_LE(len(x)) ‖ x`. EVERY 32-byte value uses this.
fn bytes(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_le_bytes());
    out.extend_from_slice(x);
}
fn u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn u8_(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// `mode`: Bilateral = 0, Unilateral = 1.
const UNILATERAL: u8 = 1;

// Distinct per-field fillers, so a reordering or a width change cannot survive
// by coincidence.
fn f32b(seed: u8) -> [u8; 32] {
    [seed; 32]
}
fn fvec(seed: u8, n: usize) -> Vec<u8> {
    vec![seed; n]
}

// ── DlvSettleOperationPreimageV1 — discriminator 26 ─────────────────────────

fn settle_operation(signature: Vec<u8>) -> Operation {
    Operation::DlvSettle {
        vault_id: f32b(0x01).to_vec(),
        owner_public_key: fvec(0x02, 64),
        owner_devid: f32b(0x03),
        owner_genesis: f32b(0x04),
        input_policy_commit: f32b(0x05),
        output_policy_commit: f32b(0x06),
        parent_sequence: 0x0707_0707_0707_0707,
        parent_binding: f32b(0x08),
        route_commit_bytes: fvec(0x09, 5),
        external_commitment_x: f32b(0x0A),
        input_amount: 0x0B0B_0B0B_0B0B_0B0B,
        output_amount: 0x0C0C_0C0C_0C0C_0C0C,
        fee_bps: 0x0D0D_0D0D,
        sigma: f32b(0x0E),
        settler_public_key: fvec(0x0F, 64),
        settler_devid: f32b(0x10),
        settlement_receipt_id: f32b(0x11),
        signature,
        mode: TransactionMode::Unilateral,
    }
}

/// The frozen table, transcribed field by field. Field 18 is whatever the
/// caller passes, because the settler signs with it CLEARED and then writes the
/// signature back into it.
fn expected_settle_preimage(signature: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    u8_(&mut e, 26); // discriminator
    bytes(&mut e, &f32b(0x01)); //  1 vault_id
    bytes(&mut e, &fvec(0x02, 64)); //  2 owner_public_key
    bytes(&mut e, &f32b(0x03)); //  3 owner_devid
    bytes(&mut e, &f32b(0x04)); //  4 owner_genesis
    bytes(&mut e, &f32b(0x05)); //  5 input_policy_commit
    bytes(&mut e, &f32b(0x06)); //  6 output_policy_commit
    u64_le(&mut e, 0x0707_0707_0707_0707); //  7 parent_sequence
    bytes(&mut e, &f32b(0x08)); //  8 parent_binding
    bytes(&mut e, &fvec(0x09, 5)); //  9 route_commit_bytes
    bytes(&mut e, &f32b(0x0A)); // 10 external_commitment_x
    u64_le(&mut e, 0x0B0B_0B0B_0B0B_0B0B); // 11 input_amount
    u64_le(&mut e, 0x0C0C_0C0C_0C0C_0C0C); // 12 output_amount
    u32_le(&mut e, 0x0D0D_0D0D); // 13 fee_bps
    bytes(&mut e, &f32b(0x0E)); // 14 sigma
    bytes(&mut e, &fvec(0x0F, 64)); // 15 settler_public_key
    bytes(&mut e, &f32b(0x10)); // 16 settler_devid
    bytes(&mut e, &f32b(0x11)); // 17 settlement_receipt_id
    bytes(&mut e, signature); // 18 signature
    u8_(&mut e, UNILATERAL); // 19 mode
    e
}

#[test]
fn dlv_settle_to_bytes_is_byte_identical_to_the_frozen_grammar() {
    let sig = fvec(0x12, 8);
    let produced = settle_operation(sig.clone()).to_bytes();
    let expected = expected_settle_preimage(&sig);
    assert_eq!(
        produced, expected,
        "Operation::to_bytes for tag 26 no longer matches DlvSettleOperationPreimageV1. \
         2c-B: changing these bytes CHANGES THE PROTOCOL and requires an amendment — \
         do not update this expectation to match the code."
    );
}

#[test]
fn the_settle_signature_field_is_cleared_as_four_zero_bytes() {
    // The settler signs with field 18 cleared, then writes the signature back.
    // A cleared `bytes` is its length prefix alone: four zero bytes.
    let cleared = settle_operation(Vec::new()).to_bytes();
    let expected = expected_settle_preimage(&[]);
    assert_eq!(cleared, expected);
    let signed = settle_operation(fvec(0x12, 8)).to_bytes();
    assert_ne!(
        cleared, signed,
        "clearing field 18 must change the preimage, or the signature would not cover itself"
    );
    assert_eq!(
        cleared.len() + 8,
        signed.len(),
        "an 8-byte signature must add exactly 8 bytes to the cleared preimage"
    );
}

#[test]
fn a_full_length_settle_signature_keeps_the_length_prefix_correct() {
    // SPX256F is 49,856 bytes; the u32_LE prefix must carry it without truncation.
    const SPX256F: usize = 49_856;
    let sig = fvec(0x12, SPX256F);
    let produced = settle_operation(sig.clone()).to_bytes();
    assert_eq!(produced, expected_settle_preimage(&sig));
    assert_eq!(
        produced.len(),
        expected_settle_preimage(&[]).len() + SPX256F
    );
}

// ── CloseAuthorizationPreimageV1 — discriminator 28 ─────────────────────────

fn close_operation(signature: Vec<u8>) -> Operation {
    Operation::DlvClose {
        vault_id: f32b(0x21).to_vec(),
        leg_a_policy_commit: f32b(0x22),
        leg_a_amount: 0x2323_2323_2323_2323,
        leg_b_policy_commit: f32b(0x24),
        leg_b_amount: 0x2525_2525_2525_2525,
        parent_sequence: 0x2626_2626_2626_2626,
        new_sequence: 0x2727_2727_2727_2727,
        fee_bps: 0x2828_2828,
        signature,
        mode: TransactionMode::Unilateral,
    }
}

fn expected_close_preimage(signature: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    u8_(&mut e, 28); // discriminator
    bytes(&mut e, &f32b(0x21)); // 1 vault_id
    bytes(&mut e, &f32b(0x22)); // 2 leg_a_policy_commit
    u64_le(&mut e, 0x2323_2323_2323_2323); // 3 leg_a_amount
    bytes(&mut e, &f32b(0x24)); // 4 leg_b_policy_commit
    u64_le(&mut e, 0x2525_2525_2525_2525); // 5 leg_b_amount
    u64_le(&mut e, 0x2626_2626_2626_2626); // 6 parent_sequence
    u64_le(&mut e, 0x2727_2727_2727_2727); // 7 new_sequence
    u32_le(&mut e, 0x2828_2828); // 8 fee_bps
    bytes(&mut e, signature); // 9 signature
    u8_(&mut e, UNILATERAL); // 10 mode
    e
}

#[test]
fn dlv_close_to_bytes_is_byte_identical_to_the_frozen_grammar() {
    let sig = fvec(0x29, 8);
    let produced = close_operation(sig.clone()).to_bytes();
    assert_eq!(
        produced,
        expected_close_preimage(&sig),
        "Operation::to_bytes for tag 28 no longer matches CloseAuthorizationPreimageV1. \
         `dlv::close_authorization` signs these exact bytes, so a change here invalidates \
         every close signature already produced — do not update this expectation."
    );
}

#[test]
fn the_close_cleared_signature_is_the_four_bytes_the_grammar_names() {
    // 2c-B, field 9: "cleared -> `bytes` of length 0 -> the four bytes 00 00 00 00".
    let cleared = close_operation(Vec::new()).to_bytes();
    let expected = expected_close_preimage(&[]);
    assert_eq!(cleared, expected);
    // The last five bytes are the cleared length prefix followed by `mode`.
    let tail = &cleared[cleared.len() - 5..];
    assert_eq!(
        tail,
        &[0x00, 0x00, 0x00, 0x00, UNILATERAL],
        "the cleared signature must serialize as exactly four zero bytes before mode"
    );
}

// ── Round trip: the decode side agrees with the frozen bytes ────────────────

#[test]
fn both_grammars_round_trip_through_from_bytes_consuming_every_byte() {
    for op in [
        settle_operation(fvec(0x12, 8)),
        close_operation(fvec(0x29, 8)),
    ] {
        let encoded = op.to_bytes();
        let decoded = Operation::from_bytes(&encoded)
            .unwrap_or_else(|e| panic!("frozen grammar failed to decode: {e:?}"));
        assert_eq!(
            decoded.to_bytes(),
            encoded,
            "re-encoding a decoded operation must reproduce the exact bytes"
        );
    }
}

#[test]
fn trailing_bytes_are_refused_rather_than_ignored() {
    // 2c-B `G1` requires the decode to consume ALL bytes. This asserts the
    // property at the operation layer; wiring it as a bundle-validity gate is
    // 5c-2 Step 2/3, and needs a producer that emits a real preimage first.
    let mut encoded = close_operation(fvec(0x29, 8)).to_bytes();
    encoded.push(0xFF);
    assert!(
        Operation::from_bytes(&encoded).is_err(),
        "a preimage with a trailing byte must be refused, or `consuming ALL bytes` is unchecked"
    );
}
