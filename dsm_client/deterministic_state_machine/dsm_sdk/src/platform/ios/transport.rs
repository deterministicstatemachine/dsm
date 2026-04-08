//! iOS Transport Bridge - Protobuf-Native
//!
//! This module provides protobuf-native transport functions for iOS/Swift bridging.
//! Unlike the JSON-wrapped JNI bridge for Android, this provides direct protobuf
//! handling optimized for BLE and Swift interop.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use log::error;
use prost::Message;

use crate::generated::{
    ingress_request, ingress_response, startup_request, startup_response, ConfigureEnvOp, Envelope,
    IngressRequest, IngressResponse, InitializeIdentityContextOp, InitializeSdkOp, SetStorageBaseDirOp,
    StartupRequest, StartupResponse,
};
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

    allocate_response_buffer(result_bytes, out_len)
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

fn allocate_response_buffer(result_bytes: Vec<u8>, out_len: *mut usize) -> *mut u8 {
    if out_len.is_null() {
        error!("iOS transport: null out_len provided");
        return std::ptr::null_mut();
    }
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
            *out_len = 0;
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, result_bytes.len());
        ptr
    };

    ptr as *mut u8
}

fn ingress_error_response_bytes(code: u32, message: String) -> Vec<u8> {
    StartupOrIngressResponse::Ingress(IngressResponse {
        result: Some(ingress_response::Result::Error(crate::generated::Error {
            code,
            message,
            context: Vec::new(),
            source_tag: 0,
            is_recoverable: false,
            debug_b32: String::new(),
        })),
    })
    .encode()
}

fn startup_error_response_bytes(code: u32, message: String) -> Vec<u8> {
    StartupOrIngressResponse::Startup(StartupResponse {
        result: Some(startup_response::Result::Error(crate::generated::Error {
            code,
            message,
            context: Vec::new(),
            source_tag: 0,
            is_recoverable: false,
            debug_b32: String::new(),
        })),
    })
    .encode()
}

enum StartupOrIngressResponse {
    Startup(StartupResponse),
    Ingress(IngressResponse),
}

impl StartupOrIngressResponse {
    fn encode(self) -> Vec<u8> {
        match self {
            StartupOrIngressResponse::Startup(response) => response.encode_to_vec(),
            StartupOrIngressResponse::Ingress(response) => response.encode_to_vec(),
        }
    }
}

fn dispatch_bytes_ffi(
    request_bytes: *const u8,
    request_len: usize,
    out_len: *mut usize,
    dispatch: fn(&[u8]) -> Vec<u8>,
    null_response: fn(u32, String) -> Vec<u8>,
    operation_name: &str,
) -> *mut u8 {
    if out_len.is_null() {
        error!("iOS transport: null out_len provided for {operation_name}");
        return std::ptr::null_mut();
    }

    let response_bytes = if request_bytes.is_null() {
        null_response(1, format!("{operation_name}: null request bytes"))
    } else {
        let input_bytes = unsafe { std::slice::from_raw_parts(request_bytes, request_len) };
        match catch_unwind(AssertUnwindSafe(|| dispatch(input_bytes))) {
            Ok(bytes) => bytes,
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| *s)
                    .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("panic in iOS raw boundary transport");
                error!("iOS transport panic in {}: {}", operation_name, msg);
                null_response(2, format!("{operation_name}: panic: {msg}"))
            }
        }
    };

    allocate_response_buffer(response_bytes, out_len)
}

#[no_mangle]
pub extern "C" fn dsm_dispatch_startup_request(
    request_bytes: *const u8,
    request_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    dispatch_bytes_ffi(
        request_bytes,
        request_len,
        out_len,
        crate::ingress::dispatch_startup_bytes,
        startup_error_response_bytes,
        "startup request",
    )
}

#[no_mangle]
pub extern "C" fn dsm_dispatch_ingress_request(
    request_bytes: *const u8,
    request_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    dispatch_bytes_ffi(
        request_bytes,
        request_len,
        out_len,
        crate::ingress::dispatch_ingress_bytes,
        ingress_error_response_bytes,
        "ingress request",
    )
}

fn parse_nonempty_cstr(arg_name: &str, value: *const c_char) -> Option<String> {
    if value.is_null() {
        error!("iOS transport: null {} provided", arg_name);
        return None;
    }

    let value = unsafe { CStr::from_ptr(value) };
    match value.to_str() {
        Ok(v) if !v.is_empty() => Some(v.to_string()),
        Ok(_) => {
            error!("iOS transport: empty {} provided", arg_name);
            None
        }
        Err(e) => {
            error!("iOS transport: invalid UTF-8 {}: {}", arg_name, e);
            None
        }
    }
}

fn copy_required_bytes(arg_name: &str, bytes: *const u8, len: usize) -> Option<Vec<u8>> {
    if bytes.is_null() {
        error!("iOS transport: null {} provided", arg_name);
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec())
}

fn startup_ok(operation_name: &str, response: StartupResponse) -> bool {
    match response.result {
        Some(startup_response::Result::OkBytes(_)) => true,
        Some(startup_response::Result::Error(error_pb)) => {
            error!("iOS transport: {} failed: {}", operation_name, error_pb.message);
            false
        }
        None => {
            error!("iOS transport: {} returned empty response", operation_name);
            false
        }
    }
}

fn dispatch_startup_helper(operation_name: &str, operation: startup_request::Operation) -> bool {
    startup_ok(
        operation_name,
        crate::ingress::dispatch_startup(StartupRequest {
            operation: Some(operation),
        }),
    )
}

/// Configure the SDK storage base directory for iOS callers.
///
/// Returns `true` when the directory is configured or was already configured.
/// Returns `false` for null pointers, invalid UTF-8, or storage setup errors.
#[no_mangle]
pub extern "C" fn dsm_set_storage_base_dir(path_utf8: *const c_char) -> bool {
    let path = match parse_nonempty_cstr("storage path", path_utf8) {
        Some(path) => path,
        None => return false,
    };

    dispatch_startup_helper(
        "set storage base dir",
        startup_request::Operation::SetStorageBaseDir(SetStorageBaseDirOp { path_utf8: path }),
    )
}

/// Configure the authoritative env-config path for iOS callers.
#[no_mangle]
pub extern "C" fn dsm_configure_env(config_path_utf8: *const c_char) -> bool {
    let config_path = match parse_nonempty_cstr("env config path", config_path_utf8) {
        Some(path) => path,
        None => return false,
    };

    dispatch_startup_helper(
        "configure env",
        startup_request::Operation::ConfigureEnv(ConfigureEnvOp {
            config_path_utf8: config_path,
        }),
    )
}

/// Initialize the shared SDK runtime after storage/env configuration.
#[no_mangle]
pub extern "C" fn dsm_initialize_sdk() -> bool {
    dispatch_startup_helper(
        "initialize sdk",
        startup_request::Operation::InitializeSdk(InitializeSdkOp {}),
    )
}

/// Convenience bootstrap helper for iOS callers: configure env then initialize SDK.
#[no_mangle]
pub extern "C" fn dsm_init_dsm_sdk(config_path_utf8: *const c_char) -> bool {
    if !dsm_configure_env(config_path_utf8) {
        return false;
    }
    dsm_initialize_sdk()
}

/// Install canonical identity context using the validated C-DBRW binding key.
#[no_mangle]
pub extern "C" fn dsm_initialize_sdk_context(
    device_id: *const u8,
    device_id_len: usize,
    genesis_hash: *const u8,
    genesis_hash_len: usize,
    binding_key: *const u8,
    binding_key_len: usize,
) -> bool {
    let device_id = match copy_required_bytes("device_id", device_id, device_id_len) {
        Some(bytes) => bytes,
        None => return false,
    };
    let genesis_hash = match copy_required_bytes("genesis_hash", genesis_hash, genesis_hash_len) {
        Some(bytes) => bytes,
        None => return false,
    };
    let binding_key = match copy_required_bytes("binding_key", binding_key, binding_key_len) {
        Some(bytes) => bytes,
        None => return false,
    };

    dispatch_startup_helper(
        "initialize identity context",
        startup_request::Operation::InitializeIdentityContext(InitializeIdentityContextOp {
            device_id,
            genesis_hash,
            binding_key,
        }),
    )
}

/// Process envelope with native protobuf handling (internal function)
fn process_envelope_native(input_bytes: &[u8]) -> Vec<u8> {
    // 1) Decode Envelope from raw protobuf bytes
    let message_id = match Envelope::decode(input_bytes) {
        Ok(envelope_in) => envelope_in.message_id,
        Err(e) => {
            error!("iOS transport: Envelope decode failed: {}", e);
            return create_error_envelope_bytes(&format!("Envelope decode failed: {}", e));
        }
    };

    // 2) Ensure storage is loaded (critical for iOS)
    crate::sdk::app_state::AppState::ensure_storage_loaded();

    // 3) Forward to the shared ingress (platform-agnostic semantic boundary).
    //    Both the Android JNI shim and this iOS FFI shim use the same dispatch
    //    path after this point; no JNI-specific logic is involved here.
    let request = IngressRequest {
        operation: Some(ingress_request::Operation::Envelope(
            crate::generated::EnvelopeOp {
                envelope_bytes: input_bytes.to_vec(),
            },
        )),
    };

    match crate::ingress::dispatch_ingress(request).result {
        Some(ingress_response::Result::OkBytes(ok_bytes)) => {
            log::info!("iOS transport: processed envelope via shared ingress");
            if ok_bytes.first() == Some(&0x03) {
                ok_bytes[1..].to_vec()
            } else {
                error!("iOS transport: ingress returned unframed envelope payload");
                create_error_envelope_bytes("ingress returned unframed envelope payload")
            }
        }
        Some(ingress_response::Result::Error(err)) => {
            error!("iOS transport: ingress failed: {}", err.message);
            create_error_envelope(message_id, err.code, &err.message).encode_to_vec()
        }
        None => {
            error!("iOS transport: ingress returned empty response");
            create_error_envelope_bytes("ingress returned empty response")
        }
    }
}

/// Create error envelope from message
fn create_error_envelope_bytes(message: &str) -> Vec<u8> {
    let tick = deterministic_time::tick();
    let mut message_id = Vec::with_capacity(16);
    message_id.extend_from_slice(&tick.to_be_bytes());
    message_id.extend_from_slice(&tick.to_be_bytes());
    let envelope = create_error_envelope(message_id, 1, message);

    envelope.encode_to_vec()
}

/// Create error envelope with specified message ID and error details
fn create_error_envelope(message_id: Vec<u8>, code: u32, message: &str) -> Envelope {
    use prost::bytes::Bytes;

    Envelope {
        version: 3,
        headers: None,
        message_id,
        payload: Some(crate::generated::envelope::Payload::Error(
            crate::generated::Error {
                code,
                message: message.to_string(),
                context: Bytes::new().to_vec(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            },
        )),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::{envelope, Envelope};

    #[test]
    fn test_error_envelope_creation() {
        let message_id = vec![1, 2, 3, 4];
        let envelope = create_error_envelope(message_id.clone(), 500, "test error");

        assert_eq!(envelope.version, 3);
        assert_eq!(envelope.message_id, message_id);

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

    #[test]
    fn test_initialize_sdk_context_rejects_null_device_id() {
        assert!(!dsm_initialize_sdk_context(
            std::ptr::null(),
            32,
            [0u8; 32].as_ptr(),
            32,
            [1u8; 32].as_ptr(),
            32,
        ));
    }
}
