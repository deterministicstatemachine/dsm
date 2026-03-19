//! Canonical encoding/decoding functions for DSM envelopes
//!
//! This module provides canonical byte encoding and decoding for DSM envelopes
//! using the prost Message trait.

use crate::types::error::DsmError;
use crate::types::proto::Envelope;
use prost::Message;

/// Encode an Envelope to canonical protobuf bytes
pub fn to_canonical_bytes(envelope: &Envelope) -> Vec<u8> {
    envelope.encode_to_vec()
}

/// Decode canonical protobuf bytes to an Envelope
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    Envelope::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            format!("Failed to decode canonical bytes to envelope: {e}"),
            "Envelope",
            None::<String>,
            Some(e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::proto::{envelope, Error};

    #[test]
    fn test_canonical_roundtrip() {
        let original = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 42,
            }),
            message_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            payload: Some(envelope::Payload::Error(Error {
                code: 404,
                source_tag: 0,
                message: "Not found".to_string(),
                context: vec![],
                is_recoverable: false,
                debug_b32: "".to_string(),
            })),
        };

        let bytes = to_canonical_bytes(&original);
        let decoded = from_canonical_bytes(&bytes).expect("decoding should succeed");

        assert_eq!(original.version, decoded.version);
        assert_eq!(original.message_id, decoded.message_id);
        match (&original.payload, &decoded.payload) {
            (Some(envelope::Payload::Error(orig_err)), Some(envelope::Payload::Error(dec_err))) => {
                assert_eq!(orig_err.code, dec_err.code);
                assert_eq!(orig_err.message, dec_err.message);
            }
            _ => panic!("Payload mismatch"),
        }
    }
}
