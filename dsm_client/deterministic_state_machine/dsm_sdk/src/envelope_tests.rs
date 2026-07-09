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

/// Receiver-admit fold (v2): the pin disclosure must round-trip byte-exactly on the confirm it
/// rides, including the required `pk_chip` (resident chip Ed25519 key).
#[test]
fn anchor_disclosure_roundtrips_on_bilateral_confirm() {
    use crate::generated::{AnchorDisclosure, BilateralConfirmRequest};

    let disclosure = AnchorDisclosure {
        bundle: vec![0xB1; 32],
        anchor_id: vec![0xA1; 32],
        enrolled_counter: 1_000_000,
        partition_pk: vec![0x07; 64],
        policy_hash: vec![0x9A; 32],
        pk_chip: vec![0xCC; 32],
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
        anchor_disclosure: Some(disclosure),
    };
    let confirm2 = BilateralConfirmRequest::decode(confirm.encode_to_vec().as_slice()).unwrap();
    let d = confirm2.anchor_disclosure.unwrap();
    assert_eq!(d.bundle, vec![0xB1; 32]);
    assert_eq!(d.anchor_id, vec![0xA1; 32]);
    assert_eq!(d.enrolled_counter, 1_000_000);
    assert_eq!(d.partition_pk, vec![0x07; 64]);
    assert_eq!(d.policy_hash, vec![0x9A; 32]);
    assert_eq!(d.pk_chip, vec![0xCC; 32]);
}
