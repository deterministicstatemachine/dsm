//! Envelope transport encoding/decoding functions (prost/protobuf only)
//!
//! This module provides transport byte encoding and decoding for DSM envelopes
//! using the prost Message trait. These bytes are for network/IPC transport, not
//! for canonical hashing or signing.

pub mod canonical;
pub mod transport;

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use crate::types::proto::Envelope;
use prost::Message;

const ENVELOPE_VERSION_TAG: u32 = 1;
const ENVELOPE_HEADERS_TAG: u32 = 2;
const ENVELOPE_MESSAGE_ID_TAG: u32 = 3;
const RESERVED_PAYLOAD_TAGS: &[u32] = &[13, 14, 33];
const ALLOWED_PAYLOAD_TAGS: &[u32] = &[
    10, 11, 12, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 31, 32, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
    63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
    87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
];

fn parsing_error(message: impl Into<String>) -> DsmError {
    DsmError::parsing(message.into(), None::<std::io::Error>)
}

fn require_envelope_v3(envelope: Envelope) -> Result<Envelope, DsmError> {
    if envelope.version != 3 {
        return Err(DsmError::parsing(
            format!("Envelope.version must be 3, got {}", envelope.version),
            None::<std::io::Error>,
        ));
    }

    Ok(envelope)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, DsmError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| parsing_error("truncated protobuf varint"))?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(parsing_error("protobuf varint exceeds 64 bits"))
}

fn read_len<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], DsmError> {
    let len = read_varint(bytes, cursor)?;
    let len = usize::try_from(len).map_err(|_| parsing_error("protobuf length overflow"))?;
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| parsing_error("protobuf length overflow"))?;
    if end > bytes.len() {
        return Err(parsing_error("truncated protobuf length-delimited field"));
    }
    let out = &bytes[*cursor..end];
    *cursor = end;
    Ok(out)
}

fn skip_field(bytes: &[u8], cursor: &mut usize, wire_type: u64) -> Result<(), DsmError> {
    match wire_type {
        0 => {
            read_varint(bytes, cursor)?;
            Ok(())
        }
        1 => {
            *cursor = cursor
                .checked_add(8)
                .ok_or_else(|| parsing_error("protobuf fixed64 overflow"))?;
            if *cursor > bytes.len() {
                return Err(parsing_error("truncated protobuf fixed64 field"));
            }
            Ok(())
        }
        2 => {
            read_len(bytes, cursor)?;
            Ok(())
        }
        5 => {
            *cursor = cursor
                .checked_add(4)
                .ok_or_else(|| parsing_error("protobuf fixed32 overflow"))?;
            if *cursor > bytes.len() {
                return Err(parsing_error("truncated protobuf fixed32 field"));
            }
            Ok(())
        }
        _ => Err(parsing_error(format!(
            "unsupported protobuf wire type {wire_type}"
        ))),
    }
}

#[derive(Default)]
struct HeaderScan {
    device_id_seen: bool,
    chain_tip_seen: bool,
}

fn validate_headers_wire(bytes: &[u8]) -> Result<HeaderScan, DsmError> {
    let mut cursor = 0usize;
    let mut seen = [false; 5];
    let mut scan = HeaderScan::default();

    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = u32::try_from(key >> 3).map_err(|_| parsing_error("field tag overflow"))?;
        let wire_type = key & 0x07;

        if !(1..=4).contains(&field) {
            return Err(parsing_error(format!(
                "unknown Envelope.headers field {field}"
            )));
        }
        if seen[field as usize] {
            return Err(parsing_error(format!(
                "duplicate Envelope.headers field {field}"
            )));
        }
        seen[field as usize] = true;

        match field {
            1..=3 => {
                if wire_type != 2 {
                    return Err(parsing_error(format!(
                        "Envelope.headers field {field} must be bytes"
                    )));
                }
                let value = read_len(bytes, &mut cursor)?;
                match field {
                    1 if value.len() != 32 => {
                        return Err(parsing_error(format!(
                            "Envelope.headers.device_id must be 32 bytes, got {}",
                            value.len()
                        )));
                    }
                    2 if value.len() != 32 => {
                        return Err(parsing_error(format!(
                            "Envelope.headers.chain_tip must be 32 bytes, got {}",
                            value.len()
                        )));
                    }
                    3 if value.len() != 32 => {
                        return Err(parsing_error(format!(
                            "Envelope.headers.genesis_hash must be 32 bytes, got {}",
                            value.len()
                        )));
                    }
                    _ => {}
                }
                if field == 1 {
                    scan.device_id_seen = true;
                } else if field == 2 {
                    scan.chain_tip_seen = true;
                }
            }
            4 => {
                if wire_type != 0 {
                    return Err(parsing_error("Envelope.headers.seq must be a varint"));
                }
                read_varint(bytes, &mut cursor)?;
            }
            _ => unreachable!(),
        }
    }

    if !scan.device_id_seen {
        return Err(parsing_error("Envelope.headers.device_id is required"));
    }
    if !scan.chain_tip_seen {
        return Err(parsing_error("Envelope.headers.chain_tip is required"));
    }

    Ok(scan)
}

/// Validate raw Envelope v3 protobuf bytes before prost decoding.
///
/// This catches unknown/deprecated fields and malformed required byte lengths
/// that prost would otherwise drop or coerce into defaults.
pub fn validate_canonical_envelope_v3_bytes(bytes: &[u8]) -> Result<(), DsmError> {
    let mut cursor = 0usize;
    let mut last_field = 0u32;
    let mut version_seen = false;
    let mut headers_seen = false;
    let mut message_id_seen = false;
    let mut payload_seen = false;

    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = u32::try_from(key >> 3).map_err(|_| parsing_error("field tag overflow"))?;
        let wire_type = key & 0x07;

        if field <= last_field {
            return Err(parsing_error(format!(
                "Envelope fields must be strictly increasing; saw {field} after {last_field}"
            )));
        }
        last_field = field;

        match field {
            ENVELOPE_VERSION_TAG => {
                if wire_type != 0 {
                    return Err(parsing_error("Envelope.version must be a varint"));
                }
                if version_seen {
                    return Err(parsing_error("duplicate Envelope.version field"));
                }
                version_seen = true;
                let version = read_varint(bytes, &mut cursor)?;
                if version != 3 {
                    return Err(parsing_error(format!(
                        "Envelope.version must be 3, got {version}"
                    )));
                }
            }
            ENVELOPE_HEADERS_TAG => {
                if wire_type != 2 {
                    return Err(parsing_error("Envelope.headers must be length-delimited"));
                }
                if headers_seen {
                    return Err(parsing_error("duplicate Envelope.headers field"));
                }
                headers_seen = true;
                let headers = read_len(bytes, &mut cursor)?;
                validate_headers_wire(headers)?;
            }
            ENVELOPE_MESSAGE_ID_TAG => {
                if wire_type != 2 {
                    return Err(parsing_error("Envelope.message_id must be bytes"));
                }
                if message_id_seen {
                    return Err(parsing_error("duplicate Envelope.message_id field"));
                }
                message_id_seen = true;
                let message_id = read_len(bytes, &mut cursor)?;
                if message_id.len() != 16 {
                    return Err(parsing_error(format!(
                        "Envelope.message_id must be 16 bytes, got {}",
                        message_id.len()
                    )));
                }
            }
            tag if RESERVED_PAYLOAD_TAGS.contains(&tag) => {
                return Err(parsing_error(format!(
                    "Envelope payload field {tag} is reserved"
                )));
            }
            tag if ALLOWED_PAYLOAD_TAGS.contains(&tag) => {
                if wire_type != 2 {
                    return Err(parsing_error(format!(
                        "Envelope payload field {tag} must be length-delimited"
                    )));
                }
                if payload_seen {
                    return Err(parsing_error("Envelope oneof payload has multiple fields"));
                }
                payload_seen = true;
                skip_field(bytes, &mut cursor, wire_type)?;
            }
            tag => {
                return Err(parsing_error(format!("unknown Envelope field {tag}")));
            }
        }
    }

    if !version_seen {
        return Err(parsing_error("Envelope.version is required"));
    }
    if !headers_seen {
        return Err(parsing_error("Envelope.headers is required"));
    }
    if !message_id_seen {
        return Err(parsing_error("Envelope.message_id is required"));
    }

    Ok(())
}

/// Encode an Envelope to transport protobuf bytes
pub fn to_canonical_bytes(envelope: &Envelope) -> Vec<u8> {
    // Back-compat: keep the function name but clarify semantics in docs
    envelope.encode_to_vec()
}

/// Decode transport protobuf bytes to an Envelope
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    validate_canonical_envelope_v3_bytes(bytes)?;

    let envelope = Envelope::decode(bytes).map_err(|e| {
        DsmError::parsing(
            format!("Failed to decode transport bytes to envelope: {e}"),
            Some(e),
        )
    })?;

    let reencoded = envelope.encode_to_vec();
    if reencoded != bytes {
        return Err(parsing_error(
            "Envelope bytes are not in canonical deterministic encoding",
        ));
    }

    require_envelope_v3(envelope)
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
        let err = from_canonical_bytes(&bytes)
            .expect_err("decoding should reject wrong envelope version");
        assert!(
            err.to_string().contains("Envelope.version must be 3"),
            "unexpected error: {err}"
        );
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
        let err = from_canonical_bytes(&bytes).expect_err("missing required fields must reject");
        assert!(
            err.to_string().contains("headers") || err.to_string().contains("message_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_decode_rejects_unknown_top_level_field() {
        let env = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 42,
            }),
            message_id: vec![4; 16],
            payload: None,
        };
        let mut bytes = to_canonical_bytes(&env);
        bytes.extend_from_slice(&[0xda, 0x06]);
        bytes.push(0);

        let err = from_canonical_bytes(&bytes).expect_err("unknown fields must reject");
        assert!(err.to_string().contains("unknown Envelope field 107"));
    }

    #[test]
    fn strict_decode_rejects_bad_header_lengths() {
        let env = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 31],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 42,
            }),
            message_id: vec![4; 16],
            payload: None,
        };

        let err = from_canonical_bytes(&to_canonical_bytes(&env))
            .expect_err("short device_id must reject");
        assert!(err.to_string().contains("device_id must be 32 bytes"));
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
