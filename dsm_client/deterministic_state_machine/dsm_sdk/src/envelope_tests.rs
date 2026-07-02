// SPDX-License-Identifier: MIT OR Apache-2.0

//! Envelope v3 Roundtrip and Validation Tests
//!
//! Ensures protobuf serialization preserves all required fields
//! and validates envelope v3 compliance.

#![allow(clippy::disallowed_methods)]

use crate::generated::{Envelope, Headers};
use prost::Message;

#[test]
fn envelope_roundtrip_preserves_fields() {
    let input = Envelope {
        version: 3,
        headers: Some(Headers {
            device_id: vec![0x01; 32],
            chain_tip: vec![0x02; 32],
            genesis_hash: vec![0x03; 32],
            seq: 42,
        }),
        message_id: vec![0x04; 16],
        payload: None, // Test with minimal payload
    };

    let bytes = input.encode_to_vec();
    let parsed = crate::envelope::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(parsed.version, 3);
    assert_eq!(parsed.headers.as_ref().unwrap().device_id, &[0x01; 32]);
    assert_eq!(parsed.headers.as_ref().unwrap().chain_tip, &[0x02; 32]);
    assert_eq!(
        parsed.headers.as_ref().unwrap().genesis_hash.as_slice(),
        &[0x03; 32]
    );
    assert_eq!(parsed.headers.as_ref().unwrap().seq, 42);
    assert_eq!(parsed.message_id, vec![0x04; 16]);
}

#[test]
fn envelope_v3_validation() {
    let valid = Envelope {
        version: 3,
        headers: Some(Headers {
            device_id: vec![0x01; 32],
            chain_tip: vec![0x02; 32],
            genesis_hash: vec![0x03; 32],
            seq: 1,
        }),
        message_id: vec![0x04; 16],
        payload: None,
    };
    assert!(crate::envelope::from_canonical_bytes(&valid.encode_to_vec()).is_ok());

    let invalid_version = Envelope {
        version: 2,
        ..valid.clone()
    };
    assert!(crate::envelope::from_canonical_bytes(&invalid_version.encode_to_vec()).is_err());

    let missing_headers = Envelope {
        version: 3,
        headers: None,
        message_id: vec![0x04; 16],
        payload: None,
    };
    assert!(crate::envelope::from_canonical_bytes(&missing_headers.encode_to_vec()).is_err());

    let wrong_size = Envelope {
        version: 3,
        headers: Some(Headers {
            device_id: vec![0x01; 16],
            chain_tip: vec![0x02; 32],
            genesis_hash: vec![0x03; 32],
            seq: 1,
        }),
        message_id: vec![0x04; 16],
        payload: None,
    };
    assert!(crate::envelope::from_canonical_bytes(&wrong_size.encode_to_vec()).is_err());
}

/// Receiver-admit fold (Boot Fenced Fused Anchor): the enroll-request and disclosure piggybacks
/// must round-trip byte-exactly on the two bilateral messages they ride, including the
/// slot-absent encoding (`verifier_slot_present = false`) that keeps Path-B fail-closed.
#[test]
fn anchor_enroll_and_disclosure_roundtrip_on_bilateral_messages() {
    use crate::generated::{
        AnchorDisclosure, AnchorEnrollRequest, BilateralConfirmRequest, BilateralPrepareResponse,
    };

    let prep = BilateralPrepareResponse {
        commitment_hash: None,
        local_signature: Vec::new(),
        expires_iterations: 7,
        counterparty_state_hash: None,
        local_state_hash: None,
        responder_signing_public_key: Vec::new(),
        receiver_challenge: vec![0x5A; 32],
        anchor_enroll_request: Some(AnchorEnrollRequest {
            verifier_pairing_pubkey: vec![0xB0; 32],
        }),
    };
    let prep2 = BilateralPrepareResponse::decode(prep.encode_to_vec().as_slice()).unwrap();
    assert_eq!(
        prep2.anchor_enroll_request.unwrap().verifier_pairing_pubkey,
        vec![0xB0; 32]
    );

    // Pre-HW disclosure: slot + stpub absent (the fail-closed shape).
    let disclosure = AnchorDisclosure {
        bundle: vec![0xB1; 32],
        anchor_id: vec![0xA1; 32],
        enrolled_counter: 1_000_000,
        partition_pk: vec![0x07; 64],
        policy_hash: vec![0x9A; 32],
        verifier_slot: 0,
        verifier_slot_present: false,
        chip_static_pubkey: Vec::new(),
    };
    let confirm = BilateralConfirmRequest {
        commitment_hash: None,
        sender_signature: Vec::new(),
        sender_smt_root: vec![0; 32],
        rel_proof_parent: Vec::new(),
        rel_proof_child: Vec::new(),
        stitched_receipt: Vec::new(),
        shared_chain_tip_new: None,
        pre_entropy: Vec::new(),
        sender_smt_root_before: vec![0; 32],
        offline_release: Vec::new(),
        anchor_state_prev_proof: Vec::new(),
        anchor_state_next_proof: Vec::new(),
        anchor_disclosure: Some(disclosure),
    };
    let confirm2 = BilateralConfirmRequest::decode(confirm.encode_to_vec().as_slice()).unwrap();
    let d = confirm2.anchor_disclosure.unwrap();
    assert_eq!(d.bundle, vec![0xB1; 32]);
    assert_eq!(d.anchor_id, vec![0xA1; 32]);
    assert_eq!(d.enrolled_counter, 1_000_000);
    assert_eq!(d.partition_pk, vec![0x07; 64]);
    assert_eq!(d.policy_hash, vec![0x9A; 32]);
    assert!(
        !d.verifier_slot_present,
        "pre-HW disclosure carries no slot"
    );
    assert!(
        d.chip_static_pubkey.is_empty(),
        "pre-HW disclosure carries no stpub"
    );

    // Post-HW disclosure: slot + stpub present round-trip intact.
    let hw = AnchorDisclosure {
        verifier_slot: 2,
        verifier_slot_present: true,
        chip_static_pubkey: vec![0xCC; 32],
        ..AnchorDisclosure::decode(d.encode_to_vec().as_slice()).unwrap()
    };
    let hw2 = AnchorDisclosure::decode(hw.encode_to_vec().as_slice()).unwrap();
    assert_eq!(hw2.verifier_slot, 2);
    assert!(hw2.verifier_slot_present);
    assert_eq!(hw2.chip_static_pubkey, vec![0xCC; 32]);
}
