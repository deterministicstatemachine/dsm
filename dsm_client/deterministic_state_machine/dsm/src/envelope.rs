// SPDX-License-Identifier: MIT OR Apache-2.0

//! Envelope wire encoding/decoding for DSM (prost/protobuf only).
//!
//! Issue #161 cleanup: this module is the single source of truth for
//! `Envelope` byte handling. Two thin duplicate submodules (`envelope/canonical.rs`
//! and `envelope/transport.rs`) were removed — they each redefined
//! encode/decode helpers that just delegated back to the functions below,
//! and `encode_universal_rx` had zero callers outside its own self-tests.
//!
//! # Naming caveat: "canonical" here means "transport"
//!
//! The exported [`to_canonical_bytes`] / [`from_canonical_bytes`] functions
//! return / consume the **unframed protobuf transport bytes** of an
//! [`Envelope`]. They are NOT the canonical signing-preimage bytes used for
//! hashing — those live in the `compute_*_signing_bytes_v3` family below.
//! The historical name is retained because 100+ external call sites use it;
//! treat it as a transport-encoding identifier, not a signing-preimage one.
//! For receipts the analogous distinction is made cleanly by
//! [`crate::types::receipt_types::ReceiptCommit`]'s separate canonical-vs-wire
//! byte paths.
//!
//! # Three byte layers (in order of layering)
//!
//! 1. **Canonical signing-preimage bytes** — built by
//!    `compute_transfer_signing_bytes_v3` / `compute_online_message_signing_bytes_v3`.
//!    These are the deterministic preimages fed into BLAKE3/SPHINCS+; they
//!    bind to specific protocol fields, NOT to the proto wire format.
//! 2. **Unframed `Envelope` protobuf bytes** — produced by
//!    [`to_canonical_bytes`], consumed by [`from_canonical_bytes`]. Just
//!    `Envelope::encode_to_vec` with deterministic-encoding round-trip
//!    enforcement and a v3 version gate.
//! 3. **Framed wire bytes** — `[0x03][Envelope protobuf]`. Framing is added
//!    OUTSIDE this module (see `dsm_sdk::sdk::session_manager` at the
//!    transport boundary).

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use crate::types::proto::Envelope;
use prost::Message;

const ENVELOPE_VERSION_TAG: u32 = 1;
const ENVELOPE_HEADERS_TAG: u32 = 2;
const ENVELOPE_MESSAGE_ID_TAG: u32 = 3;
// The payload fields and reserved numbers of `dsm.Envelope`, and the tag of
// its sealed spool payload (DSM Amendment A7), generated from the proto by the
// build script. A sealed envelope has a version, a message id and the seal: no
// headers, which would name the sender.
include!(concat!(env!("OUT_DIR"), "/envelope_payload_tags.rs"));

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

/// Tags of `Envelope.headers` that were removed and must never be read again:
/// 2 was a chain tip and 4 a sequence counter, neither verified by a receiver.
const RESERVED_HEADER_TAGS: &[u32] = &[2, 4];
const HEADER_DEVICE_ID_TAG: u32 = 1;
const HEADER_GENESIS_HASH_TAG: u32 = 3;

/// `Envelope.headers` names the sender of an addressed envelope: exactly its
/// device id and genesis hash, 32 bytes each, both present.
fn validate_headers_wire(bytes: &[u8]) -> Result<(), DsmError> {
    let mut cursor = 0usize;
    let mut device_id_seen = false;
    let mut genesis_hash_seen = false;

    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = u32::try_from(key >> 3).map_err(|_| parsing_error("field tag overflow"))?;
        let wire_type = key & 0x07;

        if RESERVED_HEADER_TAGS.contains(&field) {
            return Err(parsing_error(format!(
                "Envelope.headers field {field} is reserved"
            )));
        }
        let (name, seen) = match field {
            HEADER_DEVICE_ID_TAG => ("device_id", &mut device_id_seen),
            HEADER_GENESIS_HASH_TAG => ("genesis_hash", &mut genesis_hash_seen),
            _ => {
                return Err(parsing_error(format!(
                    "unknown Envelope.headers field {field}"
                )))
            }
        };
        if *seen {
            return Err(parsing_error(format!(
                "duplicate Envelope.headers.{name} field"
            )));
        }
        *seen = true;
        if wire_type != 2 {
            return Err(parsing_error(format!(
                "Envelope.headers.{name} must be bytes"
            )));
        }
        let value = read_len(bytes, &mut cursor)?;
        if value.len() != 32 {
            return Err(parsing_error(format!(
                "Envelope.headers.{name} must be 32 bytes, got {}",
                value.len()
            )));
        }
    }

    if !device_id_seen {
        return Err(parsing_error("Envelope.headers.device_id is required"));
    }
    if !genesis_hash_seen {
        return Err(parsing_error("Envelope.headers.genesis_hash is required"));
    }
    Ok(())
}

/// Who an envelope is from, which decides what it must carry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvelopeForm {
    /// From a sender to a receiver: open with headers and a message id, or
    /// sealed (the headers then ride inside the seal).
    Addressed,
    /// This device's Core or SDK answering its own caller. It makes no sender
    /// claim and names no message: no headers, no message id, never sealed.
    LocalAnswer,
}

/// Validate the raw bytes of an addressed Envelope v3 before prost decoding.
///
/// This catches unknown or reserved fields and malformed required byte lengths
/// that prost would otherwise drop or coerce into defaults.
pub fn validate_canonical_envelope_v3_bytes(bytes: &[u8]) -> Result<(), DsmError> {
    validate_envelope_v3_wire(bytes, EnvelopeForm::Addressed)
}

/// Validate the raw bytes of a local answer before prost decoding: no
/// headers, no message id, never sealed, one payload.
pub fn validate_local_answer_v3_bytes(bytes: &[u8]) -> Result<(), DsmError> {
    validate_envelope_v3_wire(bytes, EnvelopeForm::LocalAnswer)
}

fn validate_envelope_v3_wire(bytes: &[u8], form: EnvelopeForm) -> Result<(), DsmError> {
    let mut cursor = 0usize;
    let mut last_field = 0u32;
    let mut version_seen = false;
    let mut headers_seen = false;
    let mut message_id_seen = false;
    let mut payload_seen = false;
    let mut sealed_seen = false;

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
            tag if ENVELOPE_RESERVED_TAGS.contains(&tag) => {
                return Err(parsing_error(format!(
                    "Envelope payload field {tag} is reserved"
                )));
            }
            tag if ENVELOPE_PAYLOAD_TAGS.contains(&tag) => {
                if wire_type != 2 {
                    return Err(parsing_error(format!(
                        "Envelope payload field {tag} must be length-delimited"
                    )));
                }
                if payload_seen {
                    return Err(parsing_error("Envelope oneof payload has multiple fields"));
                }
                payload_seen = true;
                sealed_seen = tag == SEALED_PAYLOAD_TAG;
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
    match form {
        EnvelopeForm::Addressed => {
            // A sealed envelope carries its headers inside the seal; an open
            // one carries them outside. Never both, never neither.
            if sealed_seen && headers_seen {
                return Err(parsing_error("a sealed Envelope must not carry headers"));
            }
            if !sealed_seen && !headers_seen {
                return Err(parsing_error("Envelope.headers is required"));
            }
            if !message_id_seen {
                return Err(parsing_error("Envelope.message_id is required"));
            }
        }
        EnvelopeForm::LocalAnswer => {
            if headers_seen {
                return Err(parsing_error("a local answer carries no headers"));
            }
            if message_id_seen {
                return Err(parsing_error("a local answer carries no message id"));
            }
            if sealed_seen {
                return Err(parsing_error("a local answer is never sealed"));
            }
            if !payload_seen {
                return Err(parsing_error("a local answer carries a payload"));
            }
        }
    }

    Ok(())
}

/// Encode an Envelope to transport protobuf bytes
pub fn to_canonical_bytes(envelope: &Envelope) -> Vec<u8> {
    envelope.encode_to_vec()
}

/// Decode the transport protobuf bytes of an addressed Envelope.
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    decode_envelope_v3(bytes, EnvelopeForm::Addressed)
}

/// Decode a local answer: the unframed Envelope v3 bytes this device's Core
/// or SDK returned to its own caller. An addressed envelope is not a local
/// answer, and a local answer is not an addressed envelope.
pub fn local_answer_from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, DsmError> {
    decode_envelope_v3(bytes, EnvelopeForm::LocalAnswer)
}

/// A local answer carrying `payload`: no headers, no message id.
pub fn local_answer(payload: crate::types::proto::envelope::Payload) -> Envelope {
    Envelope {
        version: 3,
        headers: None,
        message_id: Vec::new(),
        payload: Some(payload),
    }
}

fn decode_envelope_v3(bytes: &[u8], form: EnvelopeForm) -> Result<Envelope, DsmError> {
    validate_envelope_v3_wire(bytes, form)?;

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

/// Compute canonical signing bytes for Envelope v3 online messages.
///
/// Required invariants:
/// 1. Preimage derivable from received protobuf bytes
/// 2. Includes from_device_id (signer selection)
/// 3. Excludes signature fields
pub fn compute_online_message_signing_bytes_v3(
    from_device_id: &[u8; 32],
    to_device_id: &[u8; 32],
    chain_tip: &[u8; 32],
    nonce: &[u8],
    payload: &[u8],
    memo: &str,
) -> Vec<u8> {
    let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_ONLINE_MESSAGE_V3);
    hasher.update(from_device_id);
    hasher.update(to_device_id);
    hasher.update(chain_tip);
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
    payload: &[u8],
    memo: &str,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_ONLINE_MESSAGE_NONCE_V3);
    hasher.update(from_device_id);
    hasher.update(to_device_id);
    hasher.update(chain_tip);
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
                genesis_hash: vec![3; 32],
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
                genesis_hash: vec![3; 32],
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
        // bytes[3] is the length of Envelope.headers; flipping it breaks the
        // framing of everything after it.
        bytes[3] ^= 0xFF;
        from_canonical_bytes(&bytes).expect_err("a corrupted headers length is refused");
    }

    #[test]
    fn test_decode_truncated_bytes() {
        let original = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
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
                genesis_hash: vec![3; 32],
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
                genesis_hash: vec![3; 32],
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
    fn online_message_signing_bytes_v3_is_deterministic() {
        let from = [10u8; 32];
        let to = [20u8; 32];
        let tip = [30u8; 32];
        let a =
            compute_online_message_signing_bytes_v3(&from, &to, &tip, b"nonce", b"payload", "hi");
        let b =
            compute_online_message_signing_bytes_v3(&from, &to, &tip, b"nonce", b"payload", "hi");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn online_message_signing_bytes_v3_different_payloads_differ() {
        let from = [10u8; 32];
        let to = [20u8; 32];
        let tip = [30u8; 32];
        let a = compute_online_message_signing_bytes_v3(&from, &to, &tip, b"n", b"alpha", "");
        let b = compute_online_message_signing_bytes_v3(&from, &to, &tip, b"n", b"beta", "");
        assert_ne!(a, b);
    }

    #[test]
    fn online_message_nonce_v3_is_deterministic() {
        let from = [0xAAu8; 32];
        let to = [0xBBu8; 32];
        let tip = [0xCCu8; 32];
        let a = compute_online_message_nonce_v3(&from, &to, &tip, b"data", "m");
        let b = compute_online_message_nonce_v3(&from, &to, &tip, b"data", "m");
        assert_eq!(a, b);
    }

    #[test]
    fn online_message_nonce_v3_different_payloads_differ() {
        let from = [0xAAu8; 32];
        let to = [0xBBu8; 32];
        let tip = [0xCCu8; 32];
        let a = compute_online_message_nonce_v3(&from, &to, &tip, b"d1", "");
        let b = compute_online_message_nonce_v3(&from, &to, &tip, b"d2", "");
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
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: None,
        };
        // Field 200, wire type 2, empty: a number the proto does not define.
        let mut bytes = to_canonical_bytes(&env);
        bytes.extend_from_slice(&[0xc2, 0x0c]);
        bytes.push(0);

        let err = from_canonical_bytes(&bytes).expect_err("unknown fields must reject");
        assert!(
            err.to_string().contains("unknown Envelope field 200"),
            "{err}"
        );
    }

    /// Every payload the proto defines passes the strict validator. The list
    /// is read from the proto: a hand-kept one had drifted to refuse fourteen
    /// defined payloads (107-124) and admit five numbers the proto no longer
    /// has.
    #[test]
    fn a_payload_the_proto_defines_passes_the_strict_validator() {
        let env = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: Some(
                crate::types::proto::envelope::Payload::SofiVaultCreatedResponse(Default::default()),
            ),
        };
        from_canonical_bytes(&to_canonical_bytes(&env))
            .expect("a SofiVaultCreatedResponse (field 120) is a defined payload");
        assert!(ENVELOPE_PAYLOAD_TAGS.contains(&SEALED_PAYLOAD_TAG));
        for gone in [90, 103, 104, 105, 106] {
            assert!(
                !ENVELOPE_PAYLOAD_TAGS.contains(&gone),
                "{gone} is not a field of the proto's payload oneof"
            );
        }
    }

    #[test]
    fn strict_decode_rejects_removed_bearer_round_trip_tags() {
        // The v1 counter-era bearer round-trip payload tags (110/111) are reserved — a stale
        // peer emitting them must be rejected by the canonical validator, never routed.
        let mut env_bytes = to_canonical_bytes(&Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: None,
        });
        // Append field 110 (wire type 2, empty message body) — a minimal stale
        // bilateral_bearer_prepared payload.
        env_bytes.extend_from_slice(&[0xf2, 0x06, 0x00]);
        let err =
            from_canonical_bytes(&env_bytes).expect_err("removed bearer tag 110 must be rejected");
        assert!(
            err.to_string().contains("field 110 is reserved"),
            "unexpected error: {err}"
        );
    }

    /// The removed header tags (2, a chain tip; 4, a counter) are refused, so
    /// no sender can put either back on the wire and have it read.
    #[test]
    fn strict_decode_refuses_the_reserved_header_tags() {
        let open = |extra: &[u8]| {
            let mut headers = crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }
            .encode_to_vec();
            headers.extend_from_slice(extra);
            let mut bytes = vec![0x08, 0x03, 0x12, headers.len() as u8];
            bytes.extend_from_slice(&headers);
            bytes.extend_from_slice(&[0x1a, 0x10]);
            bytes.extend_from_slice(&[4u8; 16]);
            bytes
        };
        let mut tip = vec![0x12, 0x20];
        tip.extend_from_slice(&[2u8; 32]);
        let err = from_canonical_bytes(&open(&tip)).expect_err("header tag 2 is refused");
        assert!(
            err.to_string().contains("headers field 2 is reserved"),
            "{err}"
        );
        let err = from_canonical_bytes(&open(&[0x20, 0x2a])).expect_err("header tag 4 is refused");
        assert!(
            err.to_string().contains("headers field 4 is reserved"),
            "{err}"
        );
        from_canonical_bytes(&open(&[])).expect("the same headers without them decode");
    }

    #[test]
    fn strict_decode_requires_the_genesis_hash() {
        let env = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: Vec::new(),
            }),
            message_id: vec![4; 16],
            payload: None,
        };
        let err = from_canonical_bytes(&to_canonical_bytes(&env))
            .expect_err("headers without a genesis hash are refused");
        assert!(
            err.to_string().contains("genesis_hash is required"),
            "{err}"
        );
    }

    /// A local answer and an addressed envelope are different forms, and
    /// neither decoder takes the other's.
    #[test]
    fn a_local_answer_and_an_addressed_envelope_do_not_cross() {
        let answer = to_canonical_bytes(&local_answer(envelope::Payload::Error(Error {
            code: 7,
            ..Default::default()
        })));
        let decoded = local_answer_from_canonical_bytes(&answer).expect("a local answer decodes");
        assert!(decoded.headers.is_none() && decoded.message_id.is_empty());
        let err = from_canonical_bytes(&answer).expect_err("a local answer is not addressed");
        assert!(err.to_string().contains("headers is required"), "{err}");

        let addressed = to_canonical_bytes(&Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: Some(envelope::Payload::Error(Error {
                code: 7,
                ..Default::default()
            })),
        });
        from_canonical_bytes(&addressed).expect("an addressed envelope decodes");
        let err = local_answer_from_canonical_bytes(&addressed)
            .expect_err("an addressed envelope is not a local answer");
        assert!(err.to_string().contains("carries no headers"), "{err}");
    }

    #[test]
    fn strict_decode_rejects_bad_header_lengths() {
        let env = Envelope {
            version: 3,
            headers: Some(crate::types::proto::Headers {
                device_id: vec![1; 31],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: None,
        };

        let err = from_canonical_bytes(&to_canonical_bytes(&env))
            .expect_err("short device_id must reject");
        assert!(err.to_string().contains("device_id must be 32 bytes"));
    }
}
