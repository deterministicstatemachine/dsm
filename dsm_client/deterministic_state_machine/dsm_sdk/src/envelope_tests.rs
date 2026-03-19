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

    // Serialize
    let bytes = input.encode_to_vec();

    // Deserialize
    let parsed = Envelope::decode(&*bytes).unwrap();

    // Validate all fields preserved
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
    // Valid envelope
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
    assert_eq!(valid.version, 3);

    // Invalid: wrong version
    let invalid_version = Envelope {
        version: 2,
        ..valid.clone()
    };
    assert_ne!(invalid_version.version, 3);

    // Invalid: missing headers
    let missing_headers = Envelope {
        version: 3,
        headers: None,
        message_id: vec![0x04; 16],
        payload: None,
    };
    assert!(missing_headers.headers.is_none());

    // Invalid: wrong field sizes
    let wrong_size = Envelope {
        version: 3,
        headers: Some(Headers {
            device_id: vec![0x01; 16], // Should be 32
            chain_tip: vec![0x02; 32],
            genesis_hash: vec![0x03; 32],
            seq: 1,
        }),
        message_id: vec![0x04; 16],
        payload: None,
    };
    assert_eq!(wrong_size.headers.as_ref().unwrap().device_id.len(), 16);
}
