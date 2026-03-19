use prost::Message;

use crate::types::{
    error::DsmError,
    proto::{Envelope, UniversalRx},
};

/// Encode an `Envelope` to transport bytes (protobuf)
pub fn to_transport_bytes(env: &Envelope) -> Result<Vec<u8>, DsmError> {
    let mut buf = Vec::with_capacity(env.encoded_len());
    env.encode(&mut buf).map_err(|e| {
        DsmError::serialization_error(
            "Transport encode (prost)",
            "Envelope",
            None::<&str>,
            Some(e),
        )
    })?;
    Ok(buf)
}

/// Decode an `Envelope` from transport bytes (protobuf)
pub fn from_transport_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    Envelope::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            "Transport decode (prost)",
            "Envelope",
            None::<&str>,
            Some(e),
        )
    })
}

/// Helper: encode a `UniversalRx` result into an `Envelope` and then to transport bytes.
pub fn encode_universal_rx(
    env_headers: &crate::types::proto::Headers,
    rx: UniversalRx,
) -> Result<Vec<u8>, DsmError> {
    // Generate deterministic message ID from headers
    let msg_id_hash = crate::crypto::blake3::domain_hash(
        "DSM/msg-id",
        &[
            &env_headers.device_id[..],
            &env_headers.chain_tip[..],
            &env_headers.seq.to_le_bytes()[..],
        ]
        .concat(),
    );

    let envelope = Envelope {
        version: 3,
        headers: Some(env_headers.clone()),
        message_id: msg_id_hash.as_bytes()[0..16].to_vec(),
        payload: Some(crate::types::proto::envelope::Payload::UniversalRx(rx)),
    };
    to_transport_bytes(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::proto::{envelope, Error, Headers, UniversalRx};

    fn sample_headers() -> Headers {
        Headers {
            device_id: vec![1; 32],
            chain_tip: vec![2; 32],
            genesis_hash: vec![3; 32],
            seq: 42,
        }
    }

    #[test]
    fn test_transport_roundtrip() {
        let env = Envelope {
            version: 3,
            headers: Some(sample_headers()),
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
        let bytes = to_transport_bytes(&env).expect("encode");
        let decoded = from_transport_bytes(&bytes).expect("decode");
        assert_eq!(env.version, decoded.version);
        assert_eq!(env.message_id, decoded.message_id);
    }

    #[test]
    fn test_transport_decode_corrupted() {
        let env = Envelope {
            version: 3,
            headers: Some(sample_headers()),
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
        let mut bytes = to_transport_bytes(&env).expect("encode");
        if let Some(b) = bytes.get_mut(5) {
            *b ^= 0xAA;
        }
        let result = from_transport_bytes(&bytes);
        assert!(result.is_err(), "Corrupted bytes should fail");
    }

    #[test]
    fn test_transport_decode_truncated() {
        let env = Envelope {
            version: 3,
            headers: Some(sample_headers()),
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
        let mut bytes = to_transport_bytes(&env).expect("encode");
        bytes.truncate(3);
        let result = from_transport_bytes(&bytes);
        assert!(result.is_err(), "Truncated bytes should fail");
    }

    #[test]
    fn test_transport_decode_empty() {
        let bytes: Vec<u8> = vec![];
        let result = from_transport_bytes(&bytes);
        match result {
            Err(_) => {}
            Ok(env) => {
                // Accept prost's default output if headers are missing or device_id is not 32 bytes
                let invalid = env.headers.as_ref().is_none_or(|h| h.device_id.len() != 32);
                assert!(invalid, "Empty bytes should not yield valid headers");
            }
        }
    }

    #[test]
    fn test_encode_universal_rx() {
        let headers = sample_headers();
        let op_result = crate::types::proto::OpResult {
            op_id: Some(crate::types::proto::Hash32 { v: vec![1; 32] }),
            accepted: true,
            post_state_hash: Some(crate::types::proto::Hash32 { v: vec![2; 32] }),
            result: None,
            error: None,
        };
        let rx = UniversalRx {
            results: vec![op_result.clone()],
        };
        let bytes = encode_universal_rx(&headers, rx.clone()).expect("encode_universal_rx");
        let env = from_transport_bytes(&bytes).expect("decode");
        match env.payload {
            Some(envelope::Payload::UniversalRx(r)) => {
                assert_eq!(r.results.len(), 1);
                assert_eq!(r.results[0].op_id, op_result.op_id);
                assert_eq!(r.results[0].accepted, op_result.accepted);
                assert_eq!(r.results[0].post_state_hash, op_result.post_state_hash);
            }
            _ => panic!("Payload not UniversalRx"),
        }
    }
}
