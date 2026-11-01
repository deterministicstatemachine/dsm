// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JNI exports' C twins: startup and ingress, identity, session state,
//! envelopes and balances. Each terminates where its Kotlin-called twin does.

use std::os::raw::c_char;
use std::sync::atomic::Ordering;

use prost::Message;

use crate::ffi::{bytes_from, d32_from, str_from, DsmBytes};
use crate::generated as pb;
use crate::sdk::session_manager::SDK_READY;

/// The same taxonomy the JNI exports report in error envelopes.
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    InvalidInput = 1,
    ProcessingFailed = 2,
    EncodingFailed = 3,
    RuntimeError = 4,
    NotReady = 5,
    BridgeCallFailed = 6,
}

/// A framed error envelope: `0x03 ‖ Envelope(Error)`, as the page decodes
/// one and as the JNI exports answer one.
pub fn error_envelope(code: ErrorCode, message: &str) -> Vec<u8> {
    let mut error = pb::Error {
        code: code as u32,
        message: message.to_string(),
        ..Default::default()
    };
    error.debug_b32 = base32::encode(base32::Alphabet::Crockford, &error.encode_to_vec());
    crate::host::framed_local_answer(pb::envelope::Payload::Error(error))
}

fn error_bytes(code: ErrorCode, message: &str) -> DsmBytes {
    DsmBytes::from_vec(error_envelope(code, message))
}

/// Route one startup operation and reduce its answer to nothing-or-why.
fn startup(operation: pb::startup_request::Operation) -> Result<(), String> {
    let response = crate::ingress::dispatch_startup(pb::StartupRequest {
        operation: Some(operation),
    });
    match response.result {
        Some(pb::startup_response::Result::OkBytes(_)) => Ok(()),
        Some(pb::startup_response::Result::Error(error)) => Err(error.message),
        None => Err("startup answered nothing".to_string()),
    }
}

/// `dispatchStartup`: a `StartupRequest`, answered with `StartupResponse` bytes.
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_startup(request: *const u8, len: usize) -> DsmBytes {
    DsmBytes::from_vec(crate::ingress::dispatch_startup_bytes(bytes_from(
        request, len,
    )))
}

/// `dispatchIngress`: an `IngressRequest`, answered with `IngressResponse` bytes.
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ingress(request: *const u8, len: usize) -> DsmBytes {
    DsmBytes::from_vec(crate::ingress::dispatch_ingress_bytes(bytes_from(
        request, len,
    )))
}

/// `initStorageBaseDir`: where the SDK keeps its files. Nothing, or why not.
///
/// # Safety
/// `path` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_init_storage_base_dir(path: *const c_char) -> DsmBytes {
    DsmBytes::outcome(str_from(path, "the storage base dir").and_then(|path| {
        startup(pb::startup_request::Operation::SetStorageBaseDir(
            pb::SetStorageBaseDirOp {
                path_utf8: path.to_string(),
            },
        ))
    }))
}

/// `initDsmSdk`: the environment config, then shared startup. Nothing, or why not.
///
/// # Safety
/// `config_path` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_init_dsm_sdk(config_path: *const c_char) -> DsmBytes {
    DsmBytes::outcome(
        str_from(config_path, "the env config path").and_then(|path| {
            startup(pb::startup_request::Operation::ConfigureEnv(
                pb::ConfigureEnvOp {
                    config_path_utf8: path.to_string(),
                },
            ))?;
            startup(pb::startup_request::Operation::InitializeSdk(
                pb::InitializeSdkOp {},
            ))
        }),
    )
}

/// `initSdk`: the storage base dir, then shared startup. Nothing, or why not.
///
/// # Safety
/// `base_dir` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_init_sdk(base_dir: *const c_char) -> DsmBytes {
    DsmBytes::outcome(str_from(base_dir, "the base dir").and_then(|base| {
        if base.is_empty() {
            return Err("the base dir is empty".to_string());
        }
        startup(pb::startup_request::Operation::SetStorageBaseDir(
            pb::SetStorageBaseDirOp {
                path_utf8: base.to_string(),
            },
        ))?;
        startup(pb::startup_request::Operation::InitializeSdk(
            pb::InitializeSdkOp {},
        ))
    }))
}

/// Whether this device has a 32-byte identity in readable state.
fn has_identity() -> bool {
    crate::sdk::app_state::AppState::readable()
        && matches!(crate::sdk::app_state::AppState::get_device_id(), Some(id) if id.len() == 32)
        && matches!(crate::sdk::app_state::AppState::get_genesis_hash(), Some(g) if g.len() == 32)
}

/// `getTransportHeadersV3Status`: 0 no identity, 1 identity but the runtime
/// is not ready, 3 ready.
#[no_mangle]
pub extern "C" fn dsm_ffi_transport_headers_status() -> i32 {
    if !has_identity() {
        return 0;
    }
    if SDK_READY.load(Ordering::SeqCst) && crate::is_sdk_fully_ready() {
        3
    } else {
        1
    }
}

/// `getTransportHeadersV3`: the headers' bytes, or an error envelope.
#[no_mangle]
pub extern "C" fn dsm_ffi_transport_headers() -> DsmBytes {
    match crate::get_transport_headers_v3_bytes() {
        Ok(bytes) => DsmBytes::from_vec(bytes),
        Err(e) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("getTransportHeaders failed: {e}"),
        ),
    }
}

/// `getDeviceIdBin`: this device's 32-byte id, or no bytes before there is one.
#[no_mangle]
pub extern "C" fn dsm_ffi_device_id() -> DsmBytes {
    identity_part(crate::sdk::app_state::AppState::get_device_id)
}

/// `getGenesisHashBin`: this device's 32-byte genesis, or no bytes before there is one.
#[no_mangle]
pub extern "C" fn dsm_ffi_genesis_hash() -> DsmBytes {
    identity_part(crate::sdk::app_state::AppState::get_genesis_hash)
}

/// Identity can be asked for before startup set the storage base dir: that
/// answers "none" instead of reaching AppState's missing-base-dir panic.
fn identity_part(read: fn() -> Option<Vec<u8>>) -> DsmBytes {
    if !crate::sdk::app_state::AppState::readable() {
        return DsmBytes::none();
    }
    match read() {
        Some(part) if part.len() == 32 => DsmBytes::from_vec(part),
        Some(part) => {
            log::warn!("an identity part of {} bytes, not 32", part.len());
            DsmBytes::none()
        }
        None => DsmBytes::none(),
    }
}

/// The code `dsm_ffi_error_code_of` answers for bytes that are not an Error
/// envelope: no DSM error code is 0, as Kotlin's `isErrorEnvelope` reads it.
pub const NOT_AN_ERROR_ENVELOPE: u32 = 0;

/// `isErrorEnvelope`: the code of a framed or bare Error envelope, else
/// `NOT_AN_ERROR_ENVELOPE`.
///
/// # Safety
/// `envelope` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_error_code_of(envelope: *const u8, len: usize) -> u32 {
    match crate::envelope::transport::error_code_of_transport_bytes(bytes_from(envelope, len)) {
        Some(code) => code,
        None => NOT_AN_ERROR_ENVELOPE,
    }
}

/// `processEnvelopeV3`: an Envelope v3 this device's own app built (never a
/// peer's bytes), answered framed, or an error envelope.
///
/// # Safety
/// `envelope` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_process_envelope_v3(envelope: *const u8, len: usize) -> DsmBytes {
    let request = bytes_from(envelope, len);
    let raw = match request.first() {
        Some(0x03) => &request[1..],
        _ => request,
    };
    let response = crate::ingress::dispatch_ingress(pb::IngressRequest {
        operation: Some(pb::ingress_request::Operation::Envelope(pb::EnvelopeOp {
            envelope_bytes: raw.to_vec(),
        })),
    });
    match response.result {
        Some(pb::ingress_response::Result::OkBytes(bytes)) if bytes.first() == Some(&0x03) => {
            DsmBytes::from_vec(bytes)
        }
        Some(pb::ingress_response::Result::OkBytes(_)) => error_bytes(
            ErrorCode::ProcessingFailed,
            "ingress returned unframed envelope payload",
        ),
        Some(pb::ingress_response::Result::Error(error)) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("processEnvelopeV3 failed: {}", error.message),
        ),
        None => error_bytes(
            ErrorCode::ProcessingFailed,
            "processEnvelopeV3: ingress returned empty response",
        ),
    }
}

/// `getAllBalancesStrict`: `0x03 ‖ Envelope(BalancesListResponse)`, or an error envelope.
#[no_mangle]
pub extern "C" fn dsm_ffi_balances_strict() -> DsmBytes {
    if !SDK_READY.load(Ordering::SeqCst) || !crate::is_sdk_context_initialized() {
        return error_bytes(ErrorCode::RuntimeError, "SDK not ready");
    }
    if let Err(locked) = crate::sdk::session_manager::refuse_while_locked("getAllBalancesStrict") {
        return error_bytes(ErrorCode::ProcessingFailed, &locked);
    }
    match crate::bridge::get_all_balances_strict() {
        Ok(balances) => DsmBytes::from_vec(crate::host::framed_local_answer(
            pb::envelope::Payload::BalancesListResponse(pb::BalancesListResponse { balances }),
        )),
        Err(e) => error_bytes(
            ErrorCode::BridgeCallFailed,
            &format!("get_all_balances_strict failed: {e}"),
        ),
    }
}

/// `onAppBackgrounded`: Rust stops the inbox poller unless something is still
/// owed or listening. Answers 1 when the host must keep running for it, 0
/// when it may stop.
#[no_mangle]
pub extern "C" fn dsm_ffi_on_app_backgrounded() -> i32 {
    use crate::sdk::inbox_poller::Backgrounded;
    match crate::sdk::inbox_poller::stop_poller_for_lifecycle() {
        Ok(Backgrounded::Stopped) => 0,
        Ok(Backgrounded::Settling | Backgrounded::Listening | Backgrounded::Serving) => 1,
        Err(e) => {
            log::error!("onAppBackgrounded: settlement state unreadable, keeping alive: {e}");
            1
        }
    }
}

/// `ensureAppRouterInstalled`: 1 when the full AppRouter is ready, else 0.
#[no_mangle]
pub extern "C" fn dsm_ffi_ensure_app_router_installed() -> i32 {
    match crate::init::install_full_app_router_self_config() {
        Ok(installed) => i32::from(installed),
        Err(e) => {
            log::error!("ensureAppRouterInstalled: {e}");
            0
        }
    }
}

/// `getAppRouterStatus`: 0 no genesis, 1 router not ready (or locked), 2 installed.
#[no_mangle]
pub extern "C" fn dsm_ffi_app_router_status() -> i32 {
    if crate::bridge::full_app_router_installed() {
        return 2;
    }
    if !crate::sdk::app_state::AppState::readable() {
        return 1;
    }
    if crate::sdk::app_state::AppState::get_genesis_hash().is_none() {
        return 0;
    }
    // Genesis exists; the device key re-derives from the unlocked wallet
    // seed, so a locked wallet is not ready either.
    1
}

/// `getSessionSnapshot`: `0x03 ‖ Envelope(SessionStateResponse)`, or an error envelope.
#[no_mangle]
pub extern "C" fn dsm_ffi_session_snapshot() -> DsmBytes {
    match crate::sdk::session_manager::get_session_snapshot_bytes() {
        Ok(bytes) => DsmBytes::from_vec(bytes),
        Err(e) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("getSessionSnapshot: {e}"),
        ),
    }
}

/// What the host measured of the phone, each flag 0 or not: the fields of
/// `SessionHardwareFactsProto`, which Rust builds from them.
#[repr(C)]
pub struct DsmHardwareFacts {
    pub app_foreground: i32,
    pub ble_enabled: i32,
    pub ble_permissions: i32,
    pub ble_scanning: i32,
    pub ble_advertising: i32,
    pub qr_available: i32,
    pub qr_active: i32,
    pub camera_permission: i32,
    pub battery_charging: i32,
    pub battery_level_percent: u32,
}

/// `updateSessionHardwareFacts`: the host's facts applied; answers the
/// session snapshot as above. The host measures; Rust decides.
#[no_mangle]
pub extern "C" fn dsm_ffi_update_session_hardware_facts(facts: DsmHardwareFacts) -> DsmBytes {
    let facts = pb::SessionHardwareFactsProto {
        app_foreground: facts.app_foreground != 0,
        ble_enabled: facts.ble_enabled != 0,
        ble_permissions: facts.ble_permissions != 0,
        ble_scanning: facts.ble_scanning != 0,
        ble_advertising: facts.ble_advertising != 0,
        qr_available: facts.qr_available != 0,
        qr_active: facts.qr_active != 0,
        camera_permission: facts.camera_permission != 0,
        battery_charging: facts.battery_charging != 0,
        battery_level_percent: facts.battery_level_percent.min(100),
    };
    let response = crate::ingress::dispatch_ingress(pb::IngressRequest {
        operation: Some(pb::ingress_request::Operation::HardwareFacts(
            pb::HardwareFactsOp { facts: Some(facts) },
        )),
    });
    match response.result {
        Some(pb::ingress_response::Result::OkBytes(bytes)) => DsmBytes::from_vec(bytes),
        Some(pb::ingress_response::Result::Error(error)) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("updateSessionHardwareFacts: {}", error.message),
        ),
        None => error_bytes(
            ErrorCode::ProcessingFailed,
            "updateSessionHardwareFacts: ingress returned empty response",
        ),
    }
}

/// `setSessionFatalError`: the reason startup cannot go on, and the snapshot after it.
///
/// # Safety
/// `message` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_set_session_fatal_error(message: *const c_char) -> DsmBytes {
    let message = match str_from(message, "the fatal error") {
        Ok(message) => message,
        Err(e) => return error_bytes(ErrorCode::InvalidInput, &e),
    };
    match crate::sdk::session_manager::set_fatal_error_and_snapshot(message) {
        Ok(bytes) => DsmBytes::from_vec(bytes),
        Err(e) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("setSessionFatalError: {e}"),
        ),
    }
}

/// `clearSessionFatalError`: the snapshot after the fatal error is cleared.
#[no_mangle]
pub extern "C" fn dsm_ffi_clear_session_fatal_error() -> DsmBytes {
    match crate::sdk::session_manager::clear_fatal_error_and_snapshot() {
        Ok(bytes) => DsmBytes::from_vec(bytes),
        Err(e) => error_bytes(
            ErrorCode::ProcessingFailed,
            &format!("clearSessionFatalError: {e}"),
        ),
    }
}

/// `restore_identity_context`, as the Kotlin identity handler crosses it on a
/// cold start: the persisted 32-byte device id and genesis. Nothing, or why
/// the identity is not restorable (the wallet is locked, most often).
///
/// # Safety
/// `device_id` and `genesis_hash` must each point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_restore_identity_context(
    device_id: *const u8,
    genesis_hash: *const u8,
) -> DsmBytes {
    DsmBytes::outcome((|| {
        let device_id = d32_from(device_id, "the device id")?;
        let genesis_hash = d32_from(genesis_hash, "the genesis hash")?;
        startup(pb::startup_request::Operation::RestoreIdentityContext(
            pb::RestoreIdentityContextOp {
                device_id: device_id.to_vec(),
                genesis_hash: genesis_hash.to_vec(),
            },
        ))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_envelope_is_framed_and_names_its_code() {
        let framed = error_envelope(ErrorCode::NotReady, "the BLE stack is not live yet");
        assert_eq!(framed[0], 0x03);
        let code = unsafe { dsm_ffi_error_code_of(framed.as_ptr(), framed.len()) };
        assert_eq!(code, ErrorCode::NotReady as u32);
        let envelope = pb::Envelope::decode(&framed[1..]).expect("decodes");
        match envelope.payload {
            Some(pb::envelope::Payload::Error(error)) => {
                assert_eq!(error.message, "the BLE stack is not live yet");
                assert!(!error.debug_b32.is_empty());
            }
            other => panic!("not an error payload: {other:?}"),
        }
    }

    #[test]
    fn a_success_envelope_has_no_error_code() {
        let framed = crate::host::framed_local_answer(pb::envelope::Payload::UniversalRx(
            pb::UniversalRx::default(),
        ));
        assert_eq!(
            unsafe { dsm_ffi_error_code_of(framed.as_ptr(), framed.len()) },
            0
        );
    }

    #[test]
    fn a_null_path_is_refused_with_its_reason() {
        let answer = unsafe { dsm_ffi_init_storage_base_dir(std::ptr::null()) };
        let why = unsafe { bytes_from(answer.ptr, answer.len) }.to_vec();
        unsafe { crate::ffi::dsm_bytes_free(answer) };
        assert_eq!(
            String::from_utf8(why).expect("utf-8"),
            "the storage base dir is null"
        );
    }
}
