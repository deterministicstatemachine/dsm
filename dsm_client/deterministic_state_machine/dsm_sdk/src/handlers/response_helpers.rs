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
