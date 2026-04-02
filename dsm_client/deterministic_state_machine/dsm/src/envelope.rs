//! Envelope transport encoding/decoding functions (prost/protobuf only)
//!
//! This module provides transport byte encoding and decoding for DSM envelopes
//! using the prost Message trait. These bytes are for network/IPC transport, not
//! for canonical hashing or signing.

pub mod canonical;
pub mod transport;

use crate::types::error::DsmError;
use crate::types::proto::Envelope;
use prost::Message;
use crate::crypto::blake3::dsm_domain_hasher;

/// Encode an Envelope to transport protobuf bytes
pub fn to_canonical_bytes(envelope: &Envelope) -> Vec<u8> {
    // Back-compat: keep the function name but clarify semantics in docs
    envelope.encode_to_vec()
}

/// Decode transport protobuf bytes to an Envelope
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    Envelope::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            format!("Failed to decode transport bytes to envelope: {e}"),
            "Envelope",
            None::<String>,
            Some(e),
        )
    })
}

/// Compute canonical signing bytes for Envelope v3 transfers.
/// This ensures both sender and receiver use identical byte preimages for signing/verification.
///
/// Required invariants:
/// 1. The signed preimage must be derivable from received protobuf bytes without reconstruction
/// 2. Must include from_device_id (32 bytes) so receiver can select correct signer public key
/// 3. Must exclude signature fields (no self-referential encoding)
/// 4. Verification must fail with precise reasons (missing fields → REJECT_MISSING_SIGNING_CONTEXT)
#[allow(clippy::too_many_arguments)]
pub fn compute_transfer_signing_bytes_v3(
    from_device_id: &[u8; 32],
    to_device_id: &[u8; 32],
    token_id: &str,
    amount: u64,
    chain_tip: &[u8; 32],
    seq: u64,
    nonce: &[u8],
    memo: &str,
) -> Vec<u8> {
    // Domain separation for transfer signing
    let mut hasher = dsm_domain_hasher("DSM/transfer/v3");

    // Include all signing context in deterministic order
    hasher.update(from_device_id);
    hasher.update(to_device_id);
    hasher.update(token_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(chain_tip);
    hasher.update(&seq.to_le_bytes());
    hasher.update(nonce);
    hasher.update(memo.as_bytes());

    hasher.finalize().as_bytes().to_vec()
}

/// Compute canonical signing bytes for Envelope v3 online messages.
///
/// Required invariants mirror transfers:
/// 1. Preimage derivable from received protobuf bytes
/// 2. Includes from_device_id (signer selection)
/// 3. Excludes signature fields
#[allow(clippy::too_many_arguments)]
pub fn compute_online_message_signing_bytes_v3(
    from_device_id: &[u8; 32],
    to_device_id: &[u8; 32],
    chain_tip: &[u8; 32],
    seq: u64,
    nonce: &[u8],
    payload: &[u8],
    memo: &str,
) -> Vec<u8> {
    let mut hasher = dsm_domain_hasher("DSM/online-message/v3");
    hasher.update(from_device_id);
    hasher.update(to_device_id);
    hasher.update(chain_tip);
    hasher.update(&seq.to_le_bytes());
    hasher.update(nonce);
    hasher.update(payload);
    hasher.update(memo.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

/// Compute deterministic nonce for online messages (v3).
pub fn compute_online_message_nonce_v3(
    from_device_id: &[u8; 32],
    to_device_id: &[u8; 32],
    chain_tip: &[u8; 32],
    seq: u64,
    payload: &[u8],
    memo: &str,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/online-message/nonce/v3");
    hasher.update(from_device_id);
    hasher.update(to_device_id);
    hasher.update(chain_tip);
    hasher.update(&seq.to_le_bytes());
    hasher.update(payload);
    hasher.update(memo.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
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

    #[test]
    fn test_decode_corrupted_bytes() {
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
        let mut bytes = to_canonical_bytes(&original);
        // Corrupt the length prefix of device_id (first field in Headers)
        // Protobuf encoding: field tag + length + data
        // Corrupting early bytes is more likely to break structure
        if bytes.len() > 3 {
            bytes[3] ^= 0xFF; // Corrupt a byte in the field tag/length area
        }
        let result = from_canonical_bytes(&bytes);
        // Prost may succeed and return a default Envelope, so check required fields
        match result {
            Err(_) => {}
            Ok(env) => {
                // Accept prost's default output if headers are missing or required fields are invalid
                let invalid = env
                    .headers
                    .as_ref()
                    .is_none_or(|h| h.device_id.len() != 32 || h.chain_tip.len() != 32);
                assert!(invalid, "Corrupted bytes should not yield valid headers");
            }
        }
    }

    #[test]
    fn test_decode_truncated_bytes() {
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
        let mut bytes = to_canonical_bytes(&original);
        bytes.truncate(5); // Truncate to an invalid length
        let result = from_canonical_bytes(&bytes);
        match result {
            Err(_) => {}
            Ok(env) => {
                assert!(
                    env.headers.is_none(),
                    "Truncated bytes should not yield valid headers"
                );
            }
        }
    }

    #[test]
    fn test_decode_empty_bytes() {
        let bytes: Vec<u8> = vec![];
        let result = from_canonical_bytes(&bytes);
        match result {
            Err(_) => {}
            Ok(env) => {
                assert!(
                    env.headers.is_none(),
                    "Empty bytes should not yield valid headers"
                );
            }
        }
    }

    #[test]
    fn test_large_payload() {
        let large_message = "A".repeat(1024 * 1024); // 1MB payload
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
                code: 500,
                source_tag: 0,
                message: large_message,
                context: vec![],
                is_recoverable: false,
                debug_b32: "".to_string(),
            })),
        };
        let bytes = to_canonical_bytes(&original);
        let decoded = from_canonical_bytes(&bytes).expect("decoding large payload should succeed");
        assert_eq!(decoded.version, 3);
        match decoded.payload {
            Some(envelope::Payload::Error(ref err)) => {
                assert_eq!(err.code, 500);
                assert_eq!(err.message.len(), 1024 * 1024);
            }
            _ => panic!("Payload mismatch for large payload"),
        }
    }

    #[test]
    fn test_version_mismatch() {
        let original = Envelope {
            version: 99, // Unexpected version
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 42,
            }),
            message_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            payload: Some(envelope::Payload::Error(Error {
                code: 123,
                source_tag: 0,
                message: "Version mismatch".to_string(),
                context: vec![],
                is_recoverable: false,
                debug_b32: "".to_string(),
            })),
        };
        let bytes = to_canonical_bytes(&original);
        let decoded = from_canonical_bytes(&bytes)
            .expect("decoding should succeed even with version mismatch");
        assert_eq!(decoded.version, 99);
    }

    #[test]
    fn transfer_signing_bytes_v3_is_deterministic() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let tip = [3u8; 32];
        let a =
            compute_transfer_signing_bytes_v3(&from, &to, "tok", 100, &tip, 1, b"nonce", "memo");
        let b =
            compute_transfer_signing_bytes_v3(&from, &to, "tok", 100, &tip, 1, b"nonce", "memo");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn transfer_signing_bytes_v3_different_amounts_differ() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let tip = [3u8; 32];
        let a = compute_transfer_signing_bytes_v3(&from, &to, "tok", 100, &tip, 1, b"n", "");
        let b = compute_transfer_signing_bytes_v3(&from, &to, "tok", 200, &tip, 1, b"n", "");
        assert_ne!(a, b);
    }

    #[test]
    fn transfer_signing_bytes_v3_different_token_ids_differ() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let tip = [3u8; 32];
        let a = compute_transfer_signing_bytes_v3(&from, &to, "tok_a", 100, &tip, 1, b"n", "");
        let b = compute_transfer_signing_bytes_v3(&from, &to, "tok_b", 100, &tip, 1, b"n", "");
        assert_ne!(a, b);
    }

    #[test]
    fn online_message_signing_bytes_v3_is_deterministic() {
        let from = [10u8; 32];
        let to = [20u8; 32];
        let tip = [30u8; 32];
        let a = compute_online_message_signing_bytes_v3(
            &from, &to, &tip, 5, b"nonce", b"payload", "hi",
        );
        let b = compute_online_message_signing_bytes_v3(
            &from, &to, &tip, 5, b"nonce", b"payload", "hi",
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn online_message_signing_bytes_v3_different_payloads_differ() {
        let from = [10u8; 32];
        let to = [20u8; 32];
        let tip = [30u8; 32];
        let a = compute_online_message_signing_bytes_v3(&from, &to, &tip, 5, b"n", b"alpha", "");
        let b = compute_online_message_signing_bytes_v3(&from, &to, &tip, 5, b"n", b"beta", "");
        assert_ne!(a, b);
    }

    #[test]
    fn online_message_nonce_v3_is_deterministic() {
        let from = [0xAAu8; 32];
        let to = [0xBBu8; 32];
        let tip = [0xCCu8; 32];
        let a = compute_online_message_nonce_v3(&from, &to, &tip, 7, b"data", "m");
        let b = compute_online_message_nonce_v3(&from, &to, &tip, 7, b"data", "m");
        assert_eq!(a, b);
    }

    #[test]
    fn online_message_nonce_v3_different_seq_differ() {
        let from = [0xAAu8; 32];
        let to = [0xBBu8; 32];
        let tip = [0xCCu8; 32];
        let a = compute_online_message_nonce_v3(&from, &to, &tip, 1, b"d", "");
        let b = compute_online_message_nonce_v3(&from, &to, &tip, 2, b"d", "");
        assert_ne!(a, b);
    }

    #[test]
    fn minimal_envelope_roundtrip() {
        let env = Envelope {
            version: 3,
            headers: None,
            message_id: vec![],
            payload: None,
        };
        let bytes = to_canonical_bytes(&env);
        let decoded = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, 3);
        assert!(decoded.headers.is_none());
        assert!(decoded.payload.is_none());
    }

    #[test]
    fn transfer_and_online_message_signing_bytes_differ_same_inputs() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let tip = [3u8; 32];
        let transfer = compute_transfer_signing_bytes_v3(&from, &to, "", 0, &tip, 0, b"", "");
        let online = compute_online_message_signing_bytes_v3(&from, &to, &tip, 0, b"", b"", "");
        assert_ne!(
            transfer, online,
            "Different domain tags must produce different hashes"
        );
    }
}
