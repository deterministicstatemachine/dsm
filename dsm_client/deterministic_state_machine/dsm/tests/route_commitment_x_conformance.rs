// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! CLASS-1 CONFORMANCE VECTOR FOR `X` — amendment 2c-F R1, registry §2.10.
//!
//! R1 ratified the shipped route commitment:
//!
//! ```text
//! X = H_dom(DSM/ext, RC*)
//! RC* = the RouteCommitV1 (version 2) proto3 encoding with
//!       initiator_signature cleared: fields ascending, implicit-presence
//!       defaults omitted, hops in carried order, no unknown fields
//! ```
//!
//! `RC*` is a foreign grammar, not CCB, so a second implementation can only
//! reproduce `X` if the grammar is pinned by bytes. The expected bytes below
//! are written by hand from the proto definition — tag bytes, varint lengths,
//! field order — and never produced by `prost` (amendment 2c-C2 ruling D).
//! The production side must agree on both `RC*` and `X`, and must clear a
//! carried signature before hashing.
//!
//! Byte arrays throughout, never hex.

#[path = "common/indep_ccb.rs"]
mod indep;

use dsm::types::proto::{RouteCommitHopV1, RouteCommitV1};

const VAULT: [u8; 32] = [0x03; 32];
const TOKEN_IN: [u8; 32] = [0x10; 32];
const TOKEN_OUT: [u8; 32] = [0x20; 32];
const NONCE: [u8; 32] = [0x5E; 32];
const AD_DIGEST: [u8; 32] = [0xAD; 32];
const UNLOCK_SPEC: [u8; 32] = [0x05; 32];
const PARENT: [u8; 32] = [0xC0; 32];
const OWNER_PK: [u8; 64] = [0x0A; 64];
const INITIATOR_PK: [u8; 64] = [0x1A; 64];
const FEE_BPS: u32 = 30;

fn u128_be(v: u64) -> [u8; 16] {
    u128::from(v).to_be_bytes()
}

// ── an independent proto3 writer: only what RC* needs ────────────────────────

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A length-delimited field (wire type 2).
fn len_field(number: u64, bytes: &[u8]) -> Vec<u8> {
    [
        varint((number << 3) | 2),
        varint(bytes.len() as u64),
        bytes.to_vec(),
    ]
    .concat()
}

/// A varint field (wire type 0). proto3 omits a default; none here is zero.
fn varint_field(number: u64, v: u64) -> Vec<u8> {
    assert_ne!(v, 0, "a zero value would be omitted, not encoded");
    [varint(number << 3), varint(v)].concat()
}

fn indep_hop() -> Vec<u8> {
    [
        len_field(1, &VAULT),
        len_field(2, &TOKEN_IN),
        len_field(3, &TOKEN_OUT),
        len_field(4, &u128_be(1_000)),
        len_field(5, &u128_be(453)),
        varint_field(6, u64::from(FEE_BPS)),
        len_field(7, &AD_DIGEST),
        // 8 burned; 11-14 reserved.
        len_field(9, &UNLOCK_SPEC),
        len_field(10, &OWNER_PK),
        len_field(15, &PARENT),
    ]
    .concat()
}

/// `RC*`: field 10, `initiator_signature`, is cleared and therefore omitted.
fn indep_rc_star() -> Vec<u8> {
    [
        varint_field(1, 2),
        len_field(2, &NONCE),
        len_field(3, &TOKEN_IN),
        len_field(4, &TOKEN_OUT),
        len_field(5, &u128_be(1_000)),
        len_field(6, &u128_be(453)),
        varint_field(7, u64::from(FEE_BPS)),
        len_field(8, &indep_hop()),
        len_field(9, &INITIATOR_PK),
    ]
    .concat()
}

fn prod_signed_rc() -> RouteCommitV1 {
    RouteCommitV1 {
        version: 2,
        nonce: NONCE.to_vec(),
        input_token: TOKEN_IN.to_vec(),
        output_token: TOKEN_OUT.to_vec(),
        input_amount_u128: u128_be(1_000).to_vec(),
        expected_final_output_amount_u128: u128_be(453).to_vec(),
        total_fee_bps: u64::from(FEE_BPS),
        hops: vec![RouteCommitHopV1 {
            vault_id: VAULT.to_vec(),
            token_in: TOKEN_IN.to_vec(),
            token_out: TOKEN_OUT.to_vec(),
            input_amount_u128: u128_be(1_000).to_vec(),
            expected_output_amount_u128: u128_be(453).to_vec(),
            fee_bps: FEE_BPS,
            advertisement_digest: AD_DIGEST.to_vec(),
            unlock_spec_digest: UNLOCK_SPEC.to_vec(),
            owner_public_key: OWNER_PK.to_vec(),
            parent_binding: PARENT.to_vec(),
        }],
        initiator_public_key: INITIATOR_PK.to_vec(),
        // A carried signature: RC* and X must be blind to it.
        initiator_signature: vec![0x99; 128],
    }
}

#[test]
fn the_commitment_form_is_the_hand_written_grammar() {
    let expected = indep_rc_star();
    // The hop is longer than 127 bytes, so its length is a two-byte varint —
    // the first place a hand-rolled encoder and prost could part company.
    assert_eq!(indep_hop().len(), 308);
    assert_eq!(
        &expected[expected.len() - 66 - 311..][..3],
        &[0x42, 0xB4, 0x02]
    );
    assert_eq!(
        prost::Message::encode_to_vec(&dsm::dlv::route_commit::canonicalise_for_commitment(
            &prod_signed_rc()
        )),
        expected,
        "the production commitment form is the frozen RC*"
    );
}

#[test]
fn x_is_the_ext_domain_hash_of_the_commitment_form() {
    let x = indep::h_dom(b"DSM/ext", &indep_rc_star());
    assert_eq!(
        dsm::dlv::route_commit::compute_external_commitment(&prod_signed_rc()),
        x
    );
    // The signature is outside the preimage: a different one, the same X.
    let mut resigned = prod_signed_rc();
    resigned.initiator_signature = vec![0x42; 128];
    assert_eq!(
        dsm::dlv::route_commit::compute_external_commitment(&resigned),
        x
    );
    // Every committed byte is inside it: one hop field moved, a different X.
    let mut moved = prod_signed_rc();
    moved.hops[0].parent_binding[0] ^= 0x01;
    assert_ne!(
        dsm::dlv::route_commit::compute_external_commitment(&moved),
        x
    );
}
