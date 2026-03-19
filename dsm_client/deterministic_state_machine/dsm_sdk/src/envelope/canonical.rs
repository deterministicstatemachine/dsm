//! # Canonical Envelope Serialization
//!
//! Converts an `Envelope` to its canonical protobuf byte representation
//! for hashing, signing, and wire transmission.

use crate::generated::Envelope;
use prost::Message;

pub fn to_canonical_bytes(env: &Envelope) -> Vec<u8> {
    // Use prost to encode the protobuf envelope to canonical bytes
    env.encode_to_vec()
}

pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, String> {
    // Use prost to decode the protobuf envelope from canonical bytes
    Envelope::decode(bytes).map_err(|e| format!("Failed to decode envelope: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::Envelope;

    #[test]
    fn test_canonical_roundtrip() {
        // Create a test envelope
        let envelope = Envelope {
            version: 3,
            headers: Some(crate::generated::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: Some(vec![3; 32]),
                seq: 42,
            }),
            message_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            payload: None,
        };

        // Encode to canonical bytes
        let bytes = to_canonical_bytes(&envelope);

        // Decode back
        let decoded = match from_canonical_bytes(&bytes) {
            Ok(d) => d,
            Err(e) => panic!("Failed to decode envelope: {:?}", e),
        };

        // Verify they match
        assert_eq!(envelope.version, decoded.version);
        assert_eq!(envelope.headers, decoded.headers);
        assert_eq!(envelope.message_id, decoded.message_id);
        assert_eq!(envelope.payload, decoded.payload);
    }

    #[test]
    fn test_invalid_bytes() {
        let invalid_bytes = vec![0xff, 0xff, 0xff, 0xff];
        let result = from_canonical_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode envelope"));
    }

    #[test]
    fn test_sign_and_verify_canonical_bytes() {
        use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign, sphincs_verify};

        // Build a deterministic test envelope
        let envelope = Envelope {
            version: 3,
            headers: Some(crate::generated::Headers {
                device_id: vec![0x11; 32],
                chain_tip: vec![0x22; 32],
                genesis_hash: Some(vec![0x33; 32]),
                seq: 99,
            }),
            message_id: vec![0xAA; 16],
            payload: None,
        };

        // Canonicalize
        let bytes = to_canonical_bytes(&envelope);

        // Generate a fresh keypair and sign the canonical bytes
        let (pk, sk) = match generate_sphincs_keypair() {
            Ok(pair) => pair,
            Err(e) => panic!("generate keypair: {:?}", e),
        };
        let sig = match sphincs_sign(&sk, &bytes) {
            Ok(s) => s,
            Err(e) => panic!("signing failed: {:?}", e),
        };

        // Verify signature verifies with the exact same canonical bytes
        let ok = match sphincs_verify(&pk, &bytes, &sig) {
            Ok(o) => o,
            Err(e) => panic!("verify call failed: {:?}", e),
        };
        assert!(ok, "signature verification failed for canonical bytes");
    }
}
