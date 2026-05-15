// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared response-building helpers for AppRouter dispatch handlers.
//!
//! All route handler modules delegate to these for consistent envelope framing.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::AppResult;
use crate::sdk::app_state::AppState;

/// Wrap raw bytes into an ArgPack and return as AppResult success.
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

fn bytes32_or_zero(value: Option<Vec<u8>>) -> Vec<u8> {
    value
        .filter(|bytes| bytes.len() == 32)
        .unwrap_or_else(|| vec![0u8; 32])
}

fn app_state_bytes32_or_zero(load: fn() -> Option<Vec<u8>>) -> Vec<u8> {
    if crate::storage_utils::get_storage_base_dir().is_none() {
        return vec![0u8; 32];
    }
    bytes32_or_zero(load())
}

fn response_headers() -> generated::Headers {
    generated::Headers {
        device_id: app_state_bytes32_or_zero(AppState::get_device_id),
        chain_tip: vec![0u8; 32],
        genesis_hash: app_state_bytes32_or_zero(AppState::get_genesis_hash),
        seq: 0,
    }
}

/// Build a strict Envelope v3 response.
/// Returns FramedEnvelopeV3: [0x03] || Envelope(version=3, headers=..., payload=...)
pub(crate) fn pack_envelope_ok(payload: generated::envelope::Payload) -> AppResult {
    let envelope = generated::Envelope {
        version: 3,
        headers: Some(response_headers()),
        message_id: vec![0u8; 16],
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
        generated::Hash32 { v: vec![0u8; 32] }
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
        let envelope = dsm::envelope::from_canonical_bytes(&result.data[1..]).unwrap();
        assert_eq!(envelope.version, 3);
        assert_eq!(envelope.message_id, vec![0u8; 16]);
        assert!(envelope.headers.is_some());
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
