//! iOS Transport Bridge - Protobuf-Native
//!
//! This module provides protobuf-native transport functions for iOS/Swift bridging.
//! Unlike the JSON-wrapped JNI bridge for Android, this provides direct protobuf
//! handling optimized for BLE and Swift interop.

use std::panic::{catch_unwind, AssertUnwindSafe};

use prost::Message;
use log::error;

use crate::generated::Envelope;
use crate::sdk::core_sdk::CoreSDK;
use crate::storage_utils;
use crate::util::deterministic_time;

/// Process envelope with protobuf-native transport (iOS/Swift optimized)
///
/// This function provides direct protobuf handling without JSON overhead,
/// making it suitable for BLE transport and Swift bridging where JSON
/// parsing would be too slow.
///
/// # Arguments
/// * `envelope_bytes` - Raw protobuf-encoded Envelope bytes
///
/// # Returns
/// Raw protobuf-encoded response Envelope bytes, or error envelope on failure
#[no_mangle]
pub extern "C" fn dsm_process_envelope_protobuf(
    envelope_bytes: *const u8,
    envelope_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    // Safety: This function is called from Swift/Objective-C FFI
    // We need to be extremely careful with memory safety

    if envelope_bytes.is_null() || out_len.is_null() {
        error!("iOS transport: null pointer provided");
        return std::ptr::null_mut();
    }

    // Convert raw bytes to slice safely
    let input_bytes = unsafe { std::slice::from_raw_parts(envelope_bytes, envelope_len) };

    // Process with panic safety
    let result_bytes = match catch_unwind(AssertUnwindSafe(|| process_envelope_native(input_bytes)))
    {
        Ok(bytes) => bytes,
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| *s)
                .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("panic in iOS protobuf transport");
            error!("iOS transport panic: {}", msg);
            create_error_envelope_bytes(&format!("panic: {}", msg))
        }
    };

    // Allocate and return result
    if result_bytes.is_empty() {
        unsafe { *out_len = 0 };
        return std::ptr::null_mut();
    }

    unsafe { *out_len = result_bytes.len() };
    let ptr = unsafe {
        let layout = std::alloc::Layout::from_size_align(result_bytes.len(), 1)
            .unwrap_or_else(|e| panic!("Invalid layout: {e}"));
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            error!("iOS transport: memory allocation failed");
            // out_len is already validated non-null above
            *out_len = 0;
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, result_bytes.len());
        ptr
    };

    ptr as *mut u8
}

/// Free memory allocated by dsm_process_envelope_protobuf
///
/// # Safety
/// This function must be called to free memory returned by dsm_process_envelope_protobuf
#[no_mangle]
pub extern "C" fn dsm_free_envelope_bytes(bytes: *mut u8, len: usize) {
    if !bytes.is_null() && len > 0 {
        unsafe {
            let layout = std::alloc::Layout::from_size_align_unchecked(len, 1);
            std::alloc::dealloc(bytes, layout);
        }
    }
}

/// Process envelope with native protobuf handling (internal function)
fn process_envelope_native(input_bytes: &[u8]) -> Vec<u8> {
    // 1) Decode Envelope from raw protobuf bytes
    let envelope_in = match Envelope::decode(input_bytes) {
        Ok(e) => e,
        Err(e) => {
            error!("iOS transport: Envelope decode failed: {}", e);
            return create_error_envelope_bytes(&format!("Envelope decode failed: {}", e));
        }
    };

    // 2) Ensure storage is loaded (critical for iOS)
    crate::sdk::app_state::AppState::ensure_storage_loaded();

    // 3) Extract message_id for error handling
    let message_id = envelope_in.message_id.clone();

    // 4) Forward to CORE dispatcher
    let envelope_out =
        match crate::jni::unified_protobuf_bridge::process_envelope_unified(envelope_in) {
            Ok(env_out) => {
                log::info!("iOS transport: processed envelope (deterministic timing)");
                env_out
            }
            Err(e) => {
                error!("iOS transport: core processing failed: {}", e);
                let tick = deterministic_time::tick_index();
                create_error_envelope(
                    message_id,
                    1,
                    &format!("core processing failed: {}", e),
                    tick,
                )
            }
        };

    // 5) Encode back to raw protobuf bytes
    match envelope_out.encode_to_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("iOS transport: Envelope encode failed: {}", e);
            create_error_envelope_bytes(&format!("Envelope encode failed: {}", e))
        }
    }
}

/// Create error envelope from message
fn create_error_envelope_bytes(message: &str) -> Vec<u8> {
    let (hash, tick) = deterministic_time::tick();
    let message_id = hash[..16].to_vec();
    let envelope = create_error_envelope(message_id, 1, message, tick);

    envelope.encode_to_vec().unwrap_or_else(|_| Vec::new())
}

/// Create error envelope with specified message ID and error details
fn create_error_envelope(message_id: Vec<u8>, code: u32, message: &str, tick: u64) -> Envelope {
    use prost::bytes::Bytes;

    Envelope {
        version: 3,
        tick,
        message_id,
        payload: Some(crate::generated::envelope::Payload::Error(
            crate::generated::Error {
                code,
                message: message.to_string(),
                context: Bytes::new().to_vec(),
                is_recoverable: false,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::{envelope, Envelope};

    #[test]
    fn test_error_envelope_creation() {
        let message_id = vec![1, 2, 3, 4];
        let envelope = create_error_envelope(message_id.clone(), 500, "test error", 42);

        assert_eq!(envelope.version, 3);
        assert_eq!(envelope.message_id, message_id);
        assert_eq!(envelope.tick, 42);

        if let Some(envelope::Payload::Error(err)) = envelope.payload {
            assert_eq!(err.code, 500);
            assert_eq!(err.message, "test error");
        } else {
            panic!("Expected error payload");
        }
    }

    #[test]
    fn test_process_envelope_native_error_handling() {
        // Test with invalid protobuf data
        let invalid_data = vec![0xff, 0xff, 0xff, 0xff];
        let result = process_envelope_native(&invalid_data);

        // Should return error envelope bytes
        assert!(!result.is_empty());

        // Should be decodable as an envelope
        let decoded = match Envelope::decode(&result[..]) {
            Ok(v) => v,
            Err(e) => panic!("Should decode to error envelope: {e}"),
        };
        assert_eq!(decoded.version, 3);

        if let Some(envelope::Payload::Error(_)) = decoded.payload {
            // Expected error payload
        } else {
            panic!("Expected error payload in response");
        }
    }
}
