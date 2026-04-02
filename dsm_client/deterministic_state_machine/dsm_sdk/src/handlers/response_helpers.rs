// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared response-building helpers for AppRouter dispatch handlers.
//!
//! All route handler modules delegate to these for consistent envelope framing.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::AppResult;

/// Wrap raw bytes into an ArgPack and return as AppResult success.
/// RETIRED: Use pack_envelope_ok() for new responses.
pub(crate) fn pack_bytes_ok(body: Vec<u8>, schema_hash: generated::Hash32) -> AppResult {
    let arg = generated::ArgPack {
        schema_hash: Some(schema_hash),
        codec: generated::Codec::Proto as i32,
        body,
    };
    let mut buf = Vec::with_capacity(arg.encoded_len());
    arg.encode(&mut buf).unwrap_or(());
    AppResult {
        success: true,
        data: buf,
        error_message: None,
    }
}

/// NEW: Build Envelope with proper payload oneof (no ArgPack wrapper)
/// Returns FramedEnvelopeV3: [0x03] || Envelope(version=3, payload=...)
pub(crate) fn pack_envelope_ok(payload: generated::envelope::Payload) -> AppResult {
    let envelope = generated::Envelope {
        version: 3,
        headers: None,             // Router queries don't need full headers
        message_id: vec![0u8; 16], // Empty message_id for stateless queries
        payload: Some(payload),
    };
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03); // Framing byte for Envelope v3
    envelope.encode(&mut buf).unwrap_or(());
    AppResult {
        success: true,
        data: buf,
        error_message: None,
    }
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

    fn zero_hash32() -> generated::Hash32 {
        generated::Hash32 {
            v: vec![0u8; 32],
        }
    }

    #[test]
    fn pack_bytes_ok_success_flag() {
        let result = pack_bytes_ok(vec![1, 2, 3], zero_hash32());
        assert!(result.success);
        assert!(result.error_message.is_none());
        assert!(!result.data.is_empty());
    }

    #[test]
    fn pack_bytes_ok_roundtrip_argpack() {
        let body = vec![0xAA, 0xBB, 0xCC];
        let hash = zero_hash32();
        let result = pack_bytes_ok(body.clone(), hash);

        let decoded = generated::ArgPack::decode(&*result.data).unwrap();
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.codec, generated::Codec::Proto as i32);
        assert!(decoded.schema_hash.is_some());
    }

    #[test]
    fn pack_bytes_ok_empty_body() {
        let result = pack_bytes_ok(vec![], zero_hash32());
        assert!(result.success);
        let decoded = generated::ArgPack::decode(&*result.data).unwrap();
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn pack_envelope_ok_framing_byte() {
        let payload =
            generated::envelope::Payload::AppStateResponse(generated::AppStateResponse {
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
        let payload =
            generated::envelope::Payload::AppStateResponse(generated::AppStateResponse {
                key: "hello".into(),
                value: None,
            });
        let result = pack_envelope_ok(payload);
        let envelope = generated::Envelope::decode(&result.data[1..]).unwrap();
        assert_eq!(envelope.version, 3);
        assert_eq!(envelope.message_id, vec![0u8; 16]);
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
