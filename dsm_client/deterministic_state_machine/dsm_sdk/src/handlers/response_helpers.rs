// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared response-building helpers for AppRouter dispatch handlers.
//!
//! All route handler modules delegate to these for consistent envelope framing.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::AppResult;

/// Wrap raw bytes into an ArgPack and return as AppResult success. The body
/// is raw bytes with no schema to name, so the pack names none.
pub(crate) fn pack_bytes_ok(body: Vec<u8>) -> AppResult {
    let arg = generated::ArgPack {
        schema_hash: None,
        codec: generated::Codec::Proto as i32,
        body,
    };
    AppResult {
        success: true,
        data: arg.encode_to_vec(),
        error_message: None,
    }
}

/// Decode a local answer this device built for itself — `[0x03]` framing, an
/// Envelope v3 in canonical bytes, with no sender headers and no message id
/// (see [`frame_local_envelope`]). A wire envelope from another party is not a
/// local answer; decode that with `dsm::envelope::from_canonical_bytes`.
pub(crate) fn decode_local_envelope(framed: &[u8]) -> Result<generated::Envelope, String> {
    let body = framed
        .strip_prefix(&[0x03])
        .ok_or_else(|| "a local answer is framed 0x03".to_string())?;
    let envelope = generated::Envelope::decode(body)
        .map_err(|e| format!("local answer does not decode: {e}"))?;
    if envelope.encode_to_vec() != body {
        return Err("local answer is not in canonical encoding".to_string());
    }
    if envelope.version != 3 {
        return Err(format!(
            "local answer is Envelope v{}, not v3",
            envelope.version
        ));
    }
    if envelope.headers.is_some() || !envelope.message_id.is_empty() {
        return Err("a local answer carries no sender headers and no message id".to_string());
    }
    Ok(envelope)
}

/// Build a strict Envelope v3 response.
/// Returns FramedEnvelopeV3: [0x03] || Envelope(version=3, payload=...).
///
/// A response to the local app is not a protocol message: it has no sender
/// chain position and no message identity, so it carries no headers and no
/// message id.
pub(crate) fn pack_envelope_ok(payload: generated::envelope::Payload) -> AppResult {
    AppResult {
        success: true,
        data: frame_local_envelope(payload),
        error_message: None,
    }
}

/// `[0x03][Envelope v3]` carrying `payload` for this device's own frontend:
/// a local answer, so no sender headers and no message id.
pub(crate) fn frame_local_envelope(payload: generated::envelope::Payload) -> Vec<u8> {
    let envelope = generated::Envelope {
        version: 3,
        headers: None,
        message_id: Vec::new(),
        payload: Some(payload),
    };
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03); // Framing byte for Envelope v3
    buf.extend_from_slice(&envelope.encode_to_vec());
    buf
}

/// Convenience: return an error AppResult with message.
/// Logs the error so it appears in Logcat (via android_logger) and Rust tracing.
pub(crate) fn err(msg: String) -> AppResult {
    log::error!("[AppRouter] {}", msg);
    AppResult {
        success: false,
        data: vec![],
        error_message: Some(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn pack_bytes_ok_success_flag() {
        let result = pack_bytes_ok(vec![1, 2, 3]);
        assert!(result.success);
        assert!(result.error_message.is_none());
        assert!(!result.data.is_empty());
    }

    #[test]
    fn pack_bytes_ok_roundtrip_argpack() {
        let body = vec![0xAA, 0xBB, 0xCC];
        let result = pack_bytes_ok(body.clone());

        let decoded = generated::ArgPack::decode(&*result.data).unwrap();
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.codec, generated::Codec::Proto as i32);
        assert!(decoded.schema_hash.is_none(), "raw bytes name no schema");
    }

    #[test]
    fn pack_bytes_ok_empty_body() {
        let result = pack_bytes_ok(vec![]);
        assert!(result.success);
        let decoded = generated::ArgPack::decode(&*result.data).unwrap();
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn pack_envelope_ok_framing_byte() {
        let payload = generated::envelope::Payload::AppStateResponse(generated::AppStateResponse {
            key: "test".into(),
            value: Some("val".into()),
        });
        let result = pack_envelope_ok(payload);
        assert!(result.success);
        assert!(result.error_message.is_none());
        assert_eq!(result.data[0], 0x03, "first byte must be v3 framing");
    }

    #[test]
    fn pack_envelope_ok_roundtrip() {
        let payload = generated::envelope::Payload::AppStateResponse(generated::AppStateResponse {
            key: "hello".into(),
            value: None,
        });
        let result = pack_envelope_ok(payload);
        let envelope = decode_local_envelope(&result.data).expect("a local answer");
        assert_eq!(envelope.version, 3);
        assert!(
            envelope.message_id.is_empty(),
            "a local response has no message id"
        );
        assert!(
            envelope.headers.is_none(),
            "a local response has no sender headers"
        );
        assert!(envelope.payload.is_some());
    }

    #[test]
    fn err_returns_failure() {
        let result = err("something went wrong".into());
        assert!(!result.success);
        assert!(result.data.is_empty());
        assert_eq!(
            result.error_message.as_deref(),
            Some("something went wrong")
        );
    }

    #[test]
    fn err_preserves_message() {
        let msg = "detailed error: code=404, reason=not found".to_string();
        let result = err(msg.clone());
        assert_eq!(result.error_message, Some(msg));
    }
}
