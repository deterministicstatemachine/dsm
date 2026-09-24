// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport encoding helpers for SDK side (protobuf only)
//!
//! The SDK uses its own generated Envelope type and enforces the same strict
//! Envelope v3 contract as core on every decode path.

use crate::generated::Envelope;
use prost::Message;

pub fn to_canonical_bytes(env: &Envelope) -> Vec<u8> {
    env.encode_to_vec()
}

pub fn validate_envelope_v3(env: &Envelope) -> Result<(), String> {
    if env.version != 3 {
        return Err(format!("Envelope.version must be 3, got {}", env.version));
    }

    Ok(())
}

/// Decode the bytes of an addressed envelope (from a sender to a receiver).
pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, String> {
    dsm::envelope::validate_canonical_envelope_v3_bytes(bytes).map_err(|e| e.to_string())?;
    decode_validated(bytes)
}

/// Decode a local answer: unframed Envelope v3 bytes this device's Core or
/// SDK returned to its own caller, with no headers and no message id.
pub fn local_answer_from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, String> {
    dsm::envelope::validate_local_answer_v3_bytes(bytes).map_err(|e| e.to_string())?;
    decode_validated(bytes)
}

/// A local answer carrying `payload`. It makes no sender claim and names no
/// message, so it carries no headers and no message id.
pub fn local_answer(payload: crate::generated::envelope::Payload) -> Envelope {
    Envelope {
        version: 3,
        headers: None,
        message_id: Vec::new(),
        payload: Some(payload),
    }
}

fn decode_validated(bytes: &[u8]) -> Result<Envelope, String> {
    let env = Envelope::decode(bytes).map_err(|e| format!("Failed to decode envelope: {e}"))?;
    validate_envelope_v3(&env)?;
    if env.encode_to_vec() != bytes {
        return Err("Envelope bytes are not in canonical deterministic encoding".to_string());
    }
    Ok(env)
}

/// The error code carried by a local answer, or `None` for anything that is
/// not an Error local answer.
///
/// Envelopes cross the JNI boundary FRAMED: a leading `0x03` byte precedes the
/// canonical v3 bytes (`processEnvelopeV3` returns the ingress response framed,
/// and the bridge's error builders frame theirs the same way). The canonical
/// decoder refuses that byte, so a detector that decoded framed bytes as they
/// arrive reported every response as "not an error" — the on-device vector
/// suite found exactly that: a rejected proof-cap case read as ACCEPT. The
/// frame byte is stripped when present, as the request path strips it, so
/// framed and bare envelopes both decode.
pub fn error_code_of_transport_bytes(bytes: &[u8]) -> Option<u32> {
    let bytes = if bytes.first() == Some(&0x03) {
        &bytes[1..]
    } else {
        bytes
    };
    match local_answer_from_canonical_bytes(bytes) {
        Ok(env) => match env.payload {
            Some(crate::generated::envelope::Payload::Error(e)) => Some(e.code),
            _ => None,
        },
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::Headers;

    /// A framed error envelope and its bare form both report their code; an
    /// empty buffer and a lone frame byte never do.
    #[test]
    fn an_error_envelope_is_detected_framed_and_bare() {
        use crate::generated as pb;
        let error_env = local_answer(pb::envelope::Payload::Error(pb::Error {
            code: 470,
            message: "proof too large".to_string(),
            context: Vec::new(),
            source_tag: 0,
            is_recoverable: false,
            debug_b32: String::new(),
        }));
        let bare = to_canonical_bytes(&error_env);
        let mut framed = vec![0x03];
        framed.extend_from_slice(&bare);
        assert_eq!(
            error_code_of_transport_bytes(&framed),
            Some(470),
            "framed error"
        );
        assert_eq!(
            error_code_of_transport_bytes(&bare),
            Some(470),
            "bare error"
        );
        assert_eq!(
            error_code_of_transport_bytes(&[]),
            None,
            "empty is not an error"
        );
        assert_eq!(
            error_code_of_transport_bytes(&[0x03]),
            None,
            "a frame byte alone"
        );
    }

    #[test]
    fn sdk_envelope_roundtrip_preserves_fields() {
        let env = Envelope {
            version: 3,
            headers: Some(Headers {
                device_id: vec![0x01; 32],
                genesis_hash: vec![0x03; 32],
            }),
            message_id: vec![0x04; 16],
            payload: None,
        };

        let decoded = from_canonical_bytes(&to_canonical_bytes(&env)).expect("decode envelope");
        assert_eq!(decoded, env);
    }

    #[test]
    fn sdk_envelope_decode_rejects_wrong_version() {
        let env = Envelope {
            version: 2,
            headers: Some(Headers {
                device_id: vec![0x01; 32],
                genesis_hash: vec![0x03; 32],
            }),
            message_id: vec![0x04; 16],
            payload: None,
        };

        let err = from_canonical_bytes(&to_canonical_bytes(&env)).expect_err("wrong version");
        assert!(
            err.contains("Envelope.version must be 3"),
            "unexpected error: {err}"
        );
    }
}
