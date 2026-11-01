// SPDX-License-Identifier: MIT OR Apache-2.0

//! # JNI Unified Protobuf Bridge — APP INTEGRATION BOUNDARY
//!
//! This module contains all 87+ `#[no_mangle] pub extern "system"` JNI exports
//! that Android (Kotlin) calls into. It is the Rust side of the JNI boundary.
//!
//! ## For Custom Native App Developers
//!
//! If you are building a native Android app (Jetpack Compose, no WebView),
//! your primary entry points are:
//!
//! - `dispatchStartup(jbyteArray) -> jbyteArray`
//!   Startup bootstrap and early identity initialization.
//! - `dispatchIngress(jbyteArray) -> jbyteArray`
//!   Shared semantic router/envelope boundary for queries and invokes.
//! - `processEnvelopeV3(jbyteArray) -> jbyteArray`
//!   Envelope v3 processing for an envelope your own app layer built. Never
//!   hand it a peer's bytes: BLE writes enter at `processIncomingBleData`,
//!   through the link session.
//!
//! ## Wire Format
//!
//! - Input: raw protobuf bytes (no framing prefix on request).
//! - Output: `[0x03][Envelope v3 protobuf bytes]` — always framed.
//! - Decode responses with `strip 0x03 prefix -> strict Envelope v3 decode`.
//!
//! ## Safety
//!
//! - Every JNI function wraps in `jni_catch_unwind_*` to prevent panics from
//!   crashing the JVM. Panics are converted to error envelopes.
//! - `SDK_READY` atomic flag gates all post-bootstrap operations. If the SDK
//!   has not been bootstrapped, functions return an error envelope.
//! - JNI class: `UnifiedNativeApi` (NOT `Unified` — verify with
//!   `nm -gU libdsm_sdk.so | grep -c Java_` -> expect 87+).
//!
//! See `docs/INTEGRATION_GUIDE.md` for the full developer onboarding guide.
//!
//! ---
//!
//! Central RPC dispatcher for all Android JNI calls. Each `extern "system"`
//! function maps to a `Java_com_dsm_wallet_bridge_UnifiedNativeApi_*` symbol
//! and accepts/returns raw `jbyteArray` (prost-encoded protobuf). The
//! `SDK_READY` atomic flag gates all post-bootstrap operations.

use crate::generated as pb;
use crate::jni::helpers;
use jni::objects::{JByteArray, JClass, JString};
use jni::JNIEnv;
use prost::Message;
use std::sync::atomic::Ordering;
use crate::sdk::session_manager::SDK_READY;
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::jni::state::BILATERAL_INIT_POLL_STARTED;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::jni::bilateral_poll::{
    run_bilateral_poll, PollConfig, POLL_ATTEMPTS_STARTED, POLL_ATTEMPTS_SUCCESS,
    POLL_ATTEMPTS_TIMEOUT, POLL_TOTAL_ITERATIONS,
};
// Symbols used only on the Android BLE path (moved during the domain-tags / jni-state refactor;
// these `use`s restore the android+bluetooth build, which had not been recompiled since).
use crate::bluetooth::frame_classify::detect_ble_frame_type_from_bytes;
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use jni::objects::{JObject, JValue};
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use tokio::runtime::Handle;

// --- Helpers to convert raw JNI handles ---
/// Convert raw JNIEnv pointer to safe wrapper.
/// Returns None on failure instead of aborting the process.
#[inline]
unsafe fn env_from(raw: jni::sys::JNIEnv) -> Option<jni::JNIEnv<'static>> {
    match JNIEnv::from_raw(raw as *mut _) {
        Ok(env) => Some(env),
        Err(e) => {
            log::error!("env_from failed: {e} (FFI contract violation)");
            None
        }
    }
}
#[inline]
unsafe fn jstr_from(raw: jni::sys::jstring) -> JString<'static> {
    JString::from_raw(raw)
}
#[inline]
unsafe fn jba_from(raw: jni::sys::jbyteArray) -> JByteArray<'static> {
    JByteArray::from_raw(raw)
}

#[inline]
fn empty_byte_array_or_empty<'a>(env: &'a JNIEnv<'a>) -> JByteArray<'a> {
    env.new_byte_array(0).unwrap_or_else(|e| {
        log::error!("JVM failed to allocate empty byte array: {e} - returning null");
        unsafe { JByteArray::from_raw(std::ptr::null_mut()) }
    })
}

#[inline]
fn error_byte_array<'a>(env: &'a JNIEnv<'a>, code: u32, msg: &str) -> JByteArray<'a> {
    let env_pb = crate::jni::helpers::encode_error_transport(code, msg);
    let mut out = Vec::new();
    if let Err(e) = env_pb.encode(&mut out) {
        log::error!("JVM failed to encode error envelope: {}", e);
        return empty_byte_array_or_empty(env);
    }
    // Prepend 0x03 framing byte (Envelope v3) so the response matches
    // the canonical FramedEnvelopeV3 contract expected by the frontend.
    // Without this, error responses from JNI-level validation or panic
    // handlers arrive as raw protobuf (first byte 0x08 = version tag),
    // causing decodeFramedEnvelopeV3 to reject them.
    let mut framed = Vec::with_capacity(1 + out.len());
    framed.push(0x03);
    framed.extend_from_slice(&out);
    match env.byte_array_from_slice(&framed) {
        Ok(arr) => arr,
        Err(e) => {
            log::error!("JVM failed to allocate error byte array: {}", e);
            empty_byte_array_or_empty(env)
        }
    }
}

fn framed_payload_byte_array<'a>(
    env: &'a JNIEnv<'a>,
    payload: pb::envelope::Payload,
) -> JByteArray<'a> {
    let envelope = crate::jni::helpers::encode_payload_transport(payload);
    let mut out = Vec::new();
    out.push(0x03);
    if let Err(e) = envelope.encode(&mut out) {
        log::error!("JVM failed to encode response envelope: {}", e);
        return empty_byte_array_or_empty(env);
    }
    match env.byte_array_from_slice(&out) {
        Ok(arr) => arr,
        Err(e) => {
            log::error!("JVM failed to allocate response byte array: {}", e);
            empty_byte_array_or_empty(env)
        }
    }
}

#[derive(Debug, Clone)]
struct IngressShimError {
    code: u32,
    message: String,
}

impl IngressShimError {
    fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for IngressShimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IngressShimError {}

#[inline]
fn map_ingress_error_code_to_jni(code: u32) -> u32 {
    match code {
        crate::ingress::ERROR_CODE_INVALID_INPUT => helpers::JniErrorCode::InvalidInput as u32,
        crate::ingress::ERROR_CODE_NOT_READY => helpers::JniErrorCode::NotReady as u32,
        _ => helpers::JniErrorCode::ProcessingFailed as u32,
    }
}

#[inline]
fn ingress_ok_bytes(response: pb::IngressResponse) -> Result<Vec<u8>, IngressShimError> {
    match response.result {
        Some(pb::ingress_response::Result::OkBytes(bytes)) => Ok(bytes),
        Some(pb::ingress_response::Result::Error(error)) => Err(IngressShimError::new(
            map_ingress_error_code_to_jni(error.code),
            error.message,
        )),
        None => Err(IngressShimError::new(
            helpers::JniErrorCode::ProcessingFailed as u32,
            "ingress returned empty response",
        )),
    }
}

#[inline]
fn startup_ok_bytes(response: pb::StartupResponse) -> Result<Vec<u8>, IngressShimError> {
    match response.result {
        Some(pb::startup_response::Result::OkBytes(bytes)) => Ok(bytes),
        Some(pb::startup_response::Result::Error(error)) => Err(IngressShimError::new(
            map_ingress_error_code_to_jni(error.code),
            error.message,
        )),
        None => Err(IngressShimError::new(
            helpers::JniErrorCode::ProcessingFailed as u32,
            "startup ingress returned empty response",
        )),
    }
}

#[inline]
fn dispatch_envelope_via_ingress(envelope_bytes: &[u8]) -> Result<Vec<u8>, IngressShimError> {
    let response = crate::ingress::dispatch_ingress(pb::IngressRequest {
        operation: Some(pb::ingress_request::Operation::Envelope(pb::EnvelopeOp {
            envelope_bytes: envelope_bytes.to_vec(),
        })),
    });
    let ok_bytes = ingress_ok_bytes(response)?;
    if ok_bytes.first() != Some(&0x03) {
        return Err(IngressShimError::new(
            helpers::JniErrorCode::ProcessingFailed as u32,
            "ingress returned unframed envelope payload",
        ));
    }
    Ok(ok_bytes)
}

#[inline]
fn route_hardware_facts_via_ingress(
    facts: pb::SessionHardwareFactsProto,
) -> Result<Vec<u8>, IngressShimError> {
    let response = crate::ingress::dispatch_ingress(pb::IngressRequest {
        operation: Some(pb::ingress_request::Operation::HardwareFacts(
            pb::HardwareFactsOp { facts: Some(facts) },
        )),
    });
    ingress_ok_bytes(response)
}

#[inline]
fn route_startup_via_ingress(
    operation: pb::startup_request::Operation,
) -> Result<Vec<u8>, IngressShimError> {
    startup_ok_bytes(crate::ingress::dispatch_startup(pb::StartupRequest {
        operation: Some(operation),
    }))
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_dispatchStartup(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    jrequest: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "dispatchStartup",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jrequest = unsafe { jba_from(jrequest) };
            let request_bytes = match env.convert_byte_array(&jrequest) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("dispatchStartup: failed to read request bytes: {e}");
                    return empty_byte_array_or_empty(&env).into_raw();
                }
            };
            let response_bytes = crate::ingress::dispatch_startup_bytes(&request_bytes);
            match env.byte_array_from_slice(&response_bytes) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!("dispatchStartup: failed to allocate response bytes: {e}");
                    empty_byte_array_or_empty(&env).into_raw()
                }
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_dispatchIngress(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    jrequest: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "dispatchIngress",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jrequest = unsafe { jba_from(jrequest) };
            let request_bytes = match env.convert_byte_array(&jrequest) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("dispatchIngress: failed to read request bytes: {e}");
                    return empty_byte_array_or_empty(&env).into_raw();
                }
            };
            let response_bytes = crate::ingress::dispatch_ingress_bytes(&request_bytes);
            match env.byte_array_from_slice(&response_bytes) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!("dispatchIngress: failed to allocate response bytes: {e}");
                    empty_byte_array_or_empty(&env).into_raw()
                }
            }
        }),
    )
}

fn fetch_transport_headers_bytes() -> Result<Vec<u8>, String> {
    crate::get_transport_headers_v3_bytes().map_err(|e| format!("headers fetch failed: {e}"))
}

// JNI export for getAllBalancesStrict (top-level, not nested)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getAllBalancesStrict(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getAllBalancesStrict",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let respond_envelope =
                |payload: pb::envelope::Payload, env: &mut JNIEnv| -> jni::sys::jbyteArray {
                    framed_payload_byte_array(env, payload).into_raw()
                };

            let respond_error = |env: &mut JNIEnv, code: u32, msg: &str| -> jni::sys::jbyteArray {
                let envelope = crate::jni::helpers::encode_error_transport(code, msg);
                let mut out = Vec::new();
                out.push(0x03);
                envelope.encode(&mut out).unwrap_or_default();
                env.byte_array_from_slice(&out)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(env).into_raw())
            };

            if !SDK_READY.load(Ordering::SeqCst) {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                );
            }

            if !SDK_READY.load(Ordering::SeqCst) || !crate::is_sdk_context_initialized() {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                );
            }

            // Nothing the app asks runs while the wallet is locked (S-LOCK).
            if let Err(locked) =
                crate::sdk::session_manager::refuse_while_locked("getAllBalancesStrict")
            {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &locked,
                );
            }

            // WebView contract: return raw `BalancesListResponse` bytes on success.
            // This JNI export i now migrated to return FramedEnvelopeV3 (0x03 + Envelope).
            let result = crate::bridge::get_all_balances_strict();
            match result {
                Ok(balances) => {
                    // Canonical rows straight through — no re-inflation.
                    // Rebuilding them here with ..Default::default() is what
                    // blanked symbol/decimals on their way to the WebView.
                    let list = pb::BalancesListResponse { balances };
                    respond_envelope(pb::envelope::Payload::BalancesListResponse(list), &mut env)
                }
                Err(e) => {
                    log::error!("getAllBalancesStrict: failed: {}", e);
                    respond_error(
                        &mut env,
                        helpers::JniErrorCode::BridgeCallFailed as u32,
                        &format!("get_all_balances_strict failed: {}", e),
                    )
                }
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_initSdk(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    jbase: jni::sys::jstring,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "initSdk",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            let jbase = unsafe { jstr_from(jbase) };
            let base: String = match env.get_string(&jbase) {
                Ok(s) => s.into(),
                Err(_) => String::new(),
            };
            if base.is_empty() {
                return jni::sys::JNI_FALSE;
            }
            match route_startup_via_ingress(pb::startup_request::Operation::SetStorageBaseDir(
                pb::SetStorageBaseDirOp { path_utf8: base },
            )) {
                Ok(_) => match route_startup_via_ingress(
                    pb::startup_request::Operation::InitializeSdk(pb::InitializeSdkOp {}),
                ) {
                    Ok(_) => jni::sys::JNI_TRUE,
                    Err(error) => {
                        log::warn!("initSdk: shared startup init failed: {}", error.message);
                        jni::sys::JNI_FALSE
                    }
                },
                Err(error) => {
                    log::error!("initSdk: failed to set storage base dir: {}", error.message);
                    jni::sys::JNI_FALSE
                }
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_initStorageBaseDir(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    jpath: jni::sys::jbyteArray,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "initStorageBaseDir",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return,
            };
            let jpath = unsafe { jba_from(jpath) };
            let path_bytes = match env.convert_byte_array(jpath) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("initStorageBaseDir: failed to convert byte array: {}", e);
                    return;
                }
            };
            let path_str = match std::str::from_utf8(&path_bytes) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("initStorageBaseDir: invalid UTF-8 in path: {}", e);
                    return;
                }
            };
            let path = std::path::PathBuf::from(path_str);
            match route_startup_via_ingress(pb::startup_request::Operation::SetStorageBaseDir(
                pb::SetStorageBaseDirOp {
                    path_utf8: path.to_string_lossy().to_string(),
                },
            )) {
                Ok(_) => log::info!("initStorageBaseDir: storage base directory ready"),
                Err(error) => {
                    log::error!("initStorageBaseDir: {}", error.message);
                }
            }
        }),
    );
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_initDsmSdk(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    jconfig_path: jni::sys::jstring,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "initDsmSdk",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return,
            };
            let jconfig_path = unsafe { jstr_from(jconfig_path) };
            let config_path = match env.get_string(&jconfig_path) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("initDsmSdk: failed to get config path string: {}", e);
                    return;
                }
            };
            match route_startup_via_ingress(pb::startup_request::Operation::ConfigureEnv(
                pb::ConfigureEnvOp {
                    config_path_utf8: config_path,
                },
            )) {
                Ok(_) => log::info!(
                    "initDsmSdk: environment config path set to: {}",
                    crate::network::get_env_config_path().unwrap_or("none")
                ),
                Err(error) => {
                    log::error!(
                        "initDsmSdk: failed to configure env path: {}",
                        error.message
                    );
                    return;
                }
            }

            match route_startup_via_ingress(pb::startup_request::Operation::InitializeSdk(
                pb::InitializeSdkOp {},
            )) {
                Ok(_) => log::info!("initDsmSdk: shared startup initialization succeeded"),
                Err(error) => {
                    log::error!(
                        "initDsmSdk: shared startup initialization failed: {}",
                        error.message
                    );
                }
            }
        }),
    );
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getTransportHeadersV3Status(
    _env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) -> jni::sys::jbyte {
    crate::jni::bridge_utils::jni_catch_unwind_jbyte(
        "getTransportHeadersV3Status",
        std::panic::AssertUnwindSafe(|| {
            // Three-state readiness gate for UI:
            // 0 = NO_IDENTITY (no persisted device_id/genesis)
            // 1 = RUNTIME_NOT_READY (identity present, but runtime not fully ready yet)
            // 3 = READY (identity + SDK fully ready)
            // Before storage init nothing is readable: NO_IDENTITY, the fail-closed answer.
            let has_identity = crate::sdk::app_state::AppState::readable()
                && crate::sdk::app_state::AppState::get_device_id()
                    .map(|v| v.len() == 32)
                    .unwrap_or(false)
                && crate::sdk::app_state::AppState::get_genesis_hash()
                    .map(|v| v.len() == 32)
                    .unwrap_or(false);

            if !has_identity {
                return 0; // NO_IDENTITY
            }

            if SDK_READY.load(Ordering::SeqCst) && crate::is_sdk_fully_ready() {
                3 // READY
            } else {
                1 // RUNTIME_NOT_READY (identity exists but runtime not fully ready)
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getTransportHeadersV3(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getTransportHeadersV3",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            // Do not gate header fetch on SDK_READY. Headers may be required immediately
            // after genesis to avoid "identity not initialized" UI states. If the SDK context
            // isn't initialized yet, crate::get_transport_headers_v3_bytes will attempt to
            // bootstrap it from persisted AppState.
            let bytes = match fetch_transport_headers_bytes() {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &format!("getTransportHeaders failed: {}", e),
                    )
                    .into_raw()
                }
            };
            env.byte_array_from_slice(&bytes)
                .map(|a| a.into_raw())
                .unwrap_or(
                    error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::EncodingFailed as u32,
                        "failed to allocate return bytes",
                    )
                    .into_raw(),
                )
        }),
    )
}

/// App-backgrounded lifecycle transition. Rust performs the ENTIRE decision:
/// it stops the inbox poller unless a §16.6 settlement step is still owed (a
/// sender-side pending gate, or a countersigned reply not yet delivered), a
/// contact can send to this device, or an application is connected (its
/// requests are answered only while the wallet runs), and returns the single
/// directive the platform layer must obey.
///
/// Returns TRUE when the host MUST keep its foreground service alive: killing
/// the service kills the poller with it, stranding money in flight until the
/// user happens to reopen the app, and leaving what a contact sends unread
/// until then. The caller performs no protocol reasoning of its own — it
/// relays this directive and nothing else.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_onAppBackgrounded(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    // Only a readable "nothing owed, nobody to hear from" lets the host go:
    // the poller was stopped. Outstanding work, a contact, an unreadable
    // store, or a panic keep it alive.
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::logging::init_android_device_logging();
        crate::sdk::inbox_poller::stop_poller_for_lifecycle()
    }));
    match stopped {
        Ok(Ok(crate::sdk::inbox_poller::Backgrounded::Stopped)) => 0,
        Ok(Ok(
            crate::sdk::inbox_poller::Backgrounded::Settling
            | crate::sdk::inbox_poller::Backgrounded::Listening
            | crate::sdk::inbox_poller::Backgrounded::Serving,
        )) => 1,
        Ok(Err(e)) => {
            log::error!("onAppBackgrounded: settlement state unreadable, keeping alive: {e}");
            1
        }
        Err(_) => {
            log::error!("onAppBackgrounded: the lifecycle stop panicked, keeping alive");
            1
        }
    }
}

/// Returns the local device id as raw bytes (32 bytes) when available.
///
/// Kotlin expects this exact symbol for `Unified.getDeviceIdBin()`.
/// If identity has not been created yet, returns an empty byte array.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getDeviceIdBin(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getDeviceIdBin",
        std::panic::AssertUnwindSafe(|| {
            crate::logging::init_android_device_logging();

            // Keep JNI handling consistent with all other exports in this file.
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            // Identity can be asked for before startup has set the storage base dir (an
            // Android lifecycle callback, a restarted background service): answer "not
            // available" instead of reaching AppState's missing-base-dir panic.
            match crate::sdk::app_state::AppState::readable()
                .then(crate::sdk::app_state::AppState::get_device_id)
                .flatten()
            {
                Some(id) => {
                    // Expect 32 bytes; if not, fail-closed returning empty.
                    if id.len() != 32 {
                        log::warn!(
                            "getDeviceIdBin: unexpected length {} (expected 32)",
                            id.len()
                        );
                        return env
                            .new_byte_array(0)
                            .map(|a| a.into_raw())
                            .unwrap_or(std::ptr::null_mut());
                    }
                    env.byte_array_from_slice(&id)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|e| {
                            log::error!("getDeviceIdBin: failed to create jbyteArray: {}", e);
                            env.new_byte_array(0)
                                .map(|a| a.into_raw())
                                .unwrap_or(std::ptr::null_mut())
                        })
                }
                None => env
                    .new_byte_array(0)
                    .map(|a| a.into_raw())
                    .unwrap_or(std::ptr::null_mut()),
            }
        }),
    )
}

/// Returns the local genesis hash as raw bytes (32 bytes) when available.
///
/// Kotlin expects this exact symbol for `Unified.getGenesisHashBin()`.
/// If identity has not been created yet, returns an empty byte array.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getGenesisHashBin(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getGenesisHashBin",
        std::panic::AssertUnwindSafe(|| {
            crate::logging::init_android_device_logging();

            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            // Identity can be asked for before startup has set the storage base dir (an
            // Android lifecycle callback, a restarted background service): answer "not
            // available" instead of reaching AppState's missing-base-dir panic.
            match crate::sdk::app_state::AppState::readable()
                .then(crate::sdk::app_state::AppState::get_genesis_hash)
                .flatten()
            {
                Some(hash) => {
                    if hash.len() != 32 {
                        log::warn!(
                            "getGenesisHashBin: unexpected length {} (expected 32)",
                            hash.len()
                        );
                        return env
                            .new_byte_array(0)
                            .map(|a| a.into_raw())
                            .unwrap_or(std::ptr::null_mut());
                    }
                    env.byte_array_from_slice(&hash)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|e| {
                            log::error!("getGenesisHashBin: failed to create jbyteArray: {}", e);
                            env.new_byte_array(0)
                                .map(|a| a.into_raw())
                                .unwrap_or(std::ptr::null_mut())
                        })
                }
                None => env
                    .new_byte_array(0)
                    .map(|a| a.into_raw())
                    .unwrap_or(std::ptr::null_mut()),
            }
        }),
    )
}

/// The error code of a framed or bare Error envelope, or `None` — see
/// `crate::envelope::transport::error_code_of_transport_bytes` for why the
/// frame byte must be stripped here.
fn is_error_envelope_bytes(bytes: &[u8]) -> Option<u32> {
    crate::envelope::transport::error_code_of_transport_bytes(bytes)
}

/// JNI helper: return error code (>0) if envelope is an Error envelope, otherwise 0.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isErrorEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jint {
    crate::jni::bridge_utils::jni_catch_unwind_jint(
        "isErrorEnvelope",
        crate::jni::helpers::JniErrorCode::InvalidInput as i32,
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return crate::jni::helpers::JniErrorCode::InvalidInput as i32,
            };
            let jba = unsafe { jba_from(envelope_bytes) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return crate::jni::helpers::JniErrorCode::InvalidInput as i32,
            };

            match is_error_envelope_bytes(&bytes) {
                Some(code) => code as i32,
                None => 0,
            }
        }),
    )
}

/* =============================================================================
Strict Envelope v3 processing (JNI export)
============================================================================= */

/// The local envelope entry: an Envelope v3 this device's own app layer built
/// (Kotlin, or the JNI exports that build one). A `BleEvent` is this device's
/// BLE stack reporting what happened to it and is handled here; every other
/// envelope goes through the shared ingress, so the semantic path is the same
/// for Android JNI and iOS FFI.
///
/// Never a peer's bytes. Those enter at `processIncomingBleData`, through
/// the link session (`crate::bluetooth::link_session`), and only a unit a
/// link opened reaches `crate::bluetooth::radio_ingress`.
fn process_envelope_v3(req: &[u8]) -> Result<Vec<u8>, IngressShimError> {
    let raw = if req.first() == Some(&0x03) {
        &req[1..]
    } else {
        req
    };
    if let Ok(env) = crate::envelope::from_canonical_bytes(raw) {
        if let Some(pb::envelope::Payload::BleEvent(ref ble)) = env.payload {
            return match &ble.ev {
                Some(_) => dispatch_ble_event_to_bridge(ble),
                None => Err(IngressShimError::new(
                    helpers::JniErrorCode::InvalidInput as u32,
                    "a BleEvent envelope names no event",
                )),
            };
        }
    }

    dispatch_envelope_via_ingress(raw).map_err(|error| {
        IngressShimError::new(
            error.code,
            format!("processEnvelopeV3 failed: {}", error.message),
        )
    })
}

/// Hand a BLE lifecycle event to the Android BLE bridge, whose
/// `handle_ble_event_bytes` is the one handler that classifies and acts on
/// each variant. With no bridge the event has nowhere to go: an error, never
/// an acknowledgement.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn dispatch_ble_event_to_bridge(ble: &pb::BleEvent) -> Result<Vec<u8>, IngressShimError> {
    let Some(bridge) = crate::bluetooth::android_ble_bridge::get_global_android_bridge() else {
        return Err(IngressShimError::new(
            helpers::JniErrorCode::NotReady as u32,
            "the BLE bridge is not initialized; the event was not handled",
        ));
    };
    crate::runtime::get_runtime()
        .block_on(async { bridge.handle_ble_event_bytes(&ble.encode_to_vec()).await })
        .map(Option::unwrap_or_default)
        .map_err(|e| {
            IngressShimError::new(
                helpers::JniErrorCode::ProcessingFailed as u32,
                format!("BLE event not handled: {e}"),
            )
        })
}

/// Off the Android BLE build there is no BLE stack to hand the event to.
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
fn dispatch_ble_event_to_bridge(ble: &pb::BleEvent) -> Result<Vec<u8>, IngressShimError> {
    Err(IngressShimError::new(
        helpers::JniErrorCode::NotReady as u32,
        format!(
            "BLE event {:?} arrived on a build without the Android BLE bridge",
            ble.ev
        ),
    ))
}

/// UnifiedNativeApi JNI entry for processEnvelopeV3: the local envelope entry
/// (`process_envelope_v3`). The BLE layer never calls it: a peer's bytes go to
/// `processIncomingBleData`.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processEnvelopeV3(
    mut env: JNIEnv<'_>,
    _clazz: JClass<'_>,
    envelope: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let req = match env.convert_byte_array(&envelope) {
            Ok(v) => v,
            Err(e) => {
                match env.exception_check() {
                    Ok(pending) if pending => return std::ptr::null_mut(),
                    Ok(_) => {}
                    Err(check_error) => {
                        log::error!("processEnvelopeV3: exception check failed: {check_error}");
                        return std::ptr::null_mut();
                    }
                }
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid envelope bytes: {e}"),
                )
                .into_raw();
            }
        };

        let resp = match process_envelope_v3(&req) {
            Ok(bytes) => bytes,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("processEnvelopeV3 failed: {e}"),
                )
                .into_raw();
            }
        };

        match env.byte_array_from_slice(&resp) {
            Ok(array) => array.into_raw(),
            Err(e) => {
                // Preserve a pending JVM allocation exception; JNI calls that
                // allocate again are not valid exception recovery.
                log::error!("processEnvelopeV3: response allocation failed: {e}");
                std::ptr::null_mut()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processEnvelopeV3: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            match env.exception_check() {
                Ok(pending) if pending => return std::ptr::null_mut(),
                Ok(_) => {}
                Err(check_error) => {
                    log::error!("processEnvelopeV3: exception check failed: {check_error}");
                    return std::ptr::null_mut();
                }
            }
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processEnvelopeV3",
            )
            .into_raw()
        }
    }
}

/// Initialize bilateral SDK preconditions (context + handler + calibration).
/// Call this after genesis creation and SDK context initialization.
/// Returns true on success, false on failure.
/// Note: JNI symbol name retained for the Kotlin entry point.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_native_DsmNative_initializeBilateralSdk(
    _env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "initializeBilateralSdk",
        std::panic::AssertUnwindSafe(|| {
            // Idempotent fast-path
            if crate::is_bilateral_ready() {
                return jni::sys::JNI_TRUE;
            }

            // Defer if the context or the BLE stack is not there yet
            if !crate::is_sdk_context_initialized()
                || crate::bluetooth::get_global_bluetooth_manager().is_none()
            {
                if !BILATERAL_INIT_POLL_STARTED.swap(true, Ordering::SeqCst) {
                    log::info!("initializeBilateralSdk: preconditions missing – spawning poller");
                    // Spawn runtime task with adaptive backoff & telemetry.
                    std::thread::spawn(|| {
                        let cfg = PollConfig::default();
                        let success = run_bilateral_poll(
                            || {
                                (
                                    crate::is_sdk_context_initialized(),
                                    crate::bluetooth::get_global_bluetooth_manager().is_some(),
                                )
                            },
                            || {
                                // Use global runtime to avoid runtime drop panics
                                crate::runtime::get_runtime()
                                    .block_on(crate::initialize_bilateral_sdk())
                            },
                            cfg,
                        );
                        if !success {
                            BILATERAL_INIT_POLL_STARTED.store(false, Ordering::SeqCst);
                            log::debug!(
                                "Bilateral poller timed out; allowing retry on next JNI call"
                            );
                        }
                        log::info!(
                    "bilateral_poll telemetry: started={} success={} timeout={} iterations={}",
                    POLL_ATTEMPTS_STARTED.load(Ordering::SeqCst),
                    POLL_ATTEMPTS_SUCCESS.load(Ordering::SeqCst),
                    POLL_ATTEMPTS_TIMEOUT.load(Ordering::SeqCst),
                    POLL_TOTAL_ITERATIONS.load(Ordering::SeqCst)
                );
                    });
                } else {
                    log::debug!("initializeBilateralSdk: poller already active");
                }
                return jni::sys::JNI_FALSE;
            }

            // Immediate initialization (all preconditions satisfied) - use global runtime
            match crate::runtime::get_runtime().block_on(crate::initialize_bilateral_sdk()) {
                Ok(()) => {
                    log::info!("Bilateral SDK initialized (immediate path)");
                    jni::sys::JNI_TRUE
                }
                Err(e) => {
                    log::error!("Immediate bilateral init failed: {}", e);
                    jni::sys::JNI_FALSE
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub extern "system" fn Java_com_dsm_native_DsmNative_initializeBilateralSdk(
    _env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "initializeBilateralSdk",
        std::panic::AssertUnwindSafe(|| {
            // No-op on non-Android platforms
            jni::sys::JNI_TRUE
        }),
    )
}

// -------------------- BLE helpers (non-envelope) --------------------

/// A GATT link came up at `address`, this device on it as `role` (1 client,
/// 2 server). The client names the contact it reached for in `target` (empty
/// when it connected to any DSM device). Returns the radio bytes to write on
/// the link: the client's first Hello (DSM Amendment A27), nothing for the
/// server. A target contact's pairing moves to its handshake.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bleLinkOpened<'a>(
    mut env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    jaddress: JString<'a>,
    role: jni::sys::jint,
    jtarget: JByteArray<'a>,
) -> jni::sys::jobjectArray {
    let opened = (|| -> Result<Vec<Vec<u8>>, String> {
        let address: String = env
            .get_string(&jaddress)
            .map_err(|e| format!("the link's address: {e}"))?
            .into();
        let role =
            crate::bluetooth::link_session::GattRole::from_wire(role).map_err(|e| e.to_string())?;
        let target_bytes = env
            .convert_byte_array(&jtarget)
            .map_err(|e| format!("the link's target: {e}"))?;
        let target = match target_bytes.as_slice() {
            [] => None,
            bytes => {
                Some(<[u8; 32]>::try_from(bytes).map_err(|e| format!("the link's target: {e}"))?)
            }
        };
        if let Some(contact) = target {
            crate::runtime::get_runtime().block_on(
                crate::bluetooth::get_pairing_orchestrator().link_opened(contact, &address),
            );
        }
        crate::bluetooth::link_session::links()
            .opened(
                crate::bluetooth::link_session::Link { address, role },
                target,
                &crate::bluetooth::link_session::WalletKeys,
            )
            .map_err(|e| e.to_string())
    })();
    match opened.and_then(|frames| build_chunk_array(&mut env, &frames)) {
        Ok(array) => array.into_raw(),
        Err(why) => {
            throw_link_error(&mut env, &why);
            std::ptr::null_mut()
        }
    }
}

/// Raise `why` in Kotlin as an `IllegalStateException`: the link is not
/// opened, and the platform closes it.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn throw_link_error(env: &mut JNIEnv<'_>, why: &str) {
    if let Err(thrown) = env.throw_new(
        "java/lang/IllegalStateException",
        format!("BLE link: {why}"),
    ) {
        log::error!("[BLE link] {why}; and raising it failed: {thrown}");
    }
}

/// The GATT link at `address`, this device on it as `role`, closed: its
/// session is dropped. A paired link's contact is reached for again by the
/// owed-frame driver, and an unfinished pairing on it is retried.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bleLinkClosed<'a>(
    mut env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    jaddress: JString<'a>,
    role: jni::sys::jint,
) {
    let address: String = match env.get_string(&jaddress) {
        Ok(address) => address.into(),
        Err(e) => {
            log::error!("[BLE link] a closed link's address is unreadable: {e}");
            return;
        }
    };
    let role = match crate::bluetooth::link_session::GattRole::from_wire(role) {
        Ok(role) => role,
        Err(e) => {
            log::error!("[BLE link] a closed link's role: {e}");
            return;
        }
    };
    let paired =
        crate::bluetooth::link_session::links().closed(&crate::bluetooth::link_session::Link {
            address: address.clone(),
            role,
        });
    if let Some(peer) = paired {
        crate::bluetooth::owed_frame_driver::link_down(&peer.device_id);
    }
    crate::runtime::get_runtime()
        .block_on(crate::bluetooth::get_pairing_orchestrator().handle_peer_disconnected(&address));
}

/// Deliver every frame this device owes `counterparty`, reaching for it at
/// `address_hint` first; returns the frames delivered. A frame that cannot be
/// sent now stays owed; the next link-up, or the owed-frame driver, delivers
/// it again.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub(crate) fn deliver_owed_frames(
    env: &mut jni::JNIEnv,
    counterparty: &[u8; 32],
    address_hint: Option<&str>,
) -> Vec<crate::bluetooth::owed_frame_driver::FrameKey> {
    let rt = crate::runtime::get_runtime();
    let (coord, adapter) = match (
        rt.block_on(crate::bridge::get_ble_coordinator()),
        rt.block_on(crate::bridge::get_ble_transport_adapter()),
    ) {
        (Ok(coord), Ok(adapter)) => (coord, adapter),
        _ => {
            log::warn!("[BLE link] owed frames not delivered: the BLE transport is not ready");
            return Vec::new();
        }
    };
    let owed = rt.block_on(adapter.bilateral_handler().frames_owed_to(counterparty));
    let counterparty_b32 = crate::util::text_id::encode_base32_crockford(counterparty);
    let counterparty_short = counterparty_b32.get(..8).unwrap_or("?");
    let mut delivered = Vec::new();
    for frame in owed {
        let sent = coord
            .encode_message(owed_frame_type(frame.kind), &frame.bytes)
            .map_err(|e| e.to_string())
            .and_then(|chunks| {
                send_ble_chunks_via_unified(env, counterparty, address_hint, &chunks)
            });
        let step = crate::util::text_id::encode_base32_crockford(&frame.commitment_hash[..8]);
        match sent {
            Ok(true) => {
                log::info!(
                    "[BLE link] delivered owed {:?} for step {step} to {counterparty_short}",
                    frame.kind
                );
                delivered.push((frame.commitment_hash, frame.kind));
            }
            Ok(false) | Err(_) => {
                log::warn!(
                    "[BLE link] owed {:?} for step {step} not delivered to {counterparty_short}; it stays owed",
                    frame.kind
                );
            }
        }
    }
    delivered
}

/// The BLE frame type an owed offline frame travels as.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn owed_frame_type(
    kind: crate::bluetooth::bilateral_session::OfflineFrameKind,
) -> pb::BleFrameType {
    match kind {
        crate::bluetooth::bilateral_session::OfflineFrameKind::Prepare => {
            pb::BleFrameType::BilateralPrepare
        }
        crate::bluetooth::bilateral_session::OfflineFrameKind::PrepareResponse => {
            pb::BleFrameType::BilateralPrepareResponse
        }
        crate::bluetooth::bilateral_session::OfflineFrameKind::Confirm => {
            pb::BleFrameType::BilateralConfirm
        }
    }
}

/// Every frame this device owes `counterparty`, chunked and sealed on
/// `link`, the link that just paired with it (DSM Amendment A27), to be
/// written behind the answer that paired it. Each is marked delivered; one
/// the link drops before it is written goes again on the next link.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn owed_frames_on(
    link: &crate::bluetooth::link_session::Link,
    counterparty: &[u8; 32],
) -> Vec<Vec<u8>> {
    let rt = crate::runtime::get_runtime();
    let (coord, adapter) = match (
        rt.block_on(crate::bridge::get_ble_coordinator()),
        rt.block_on(crate::bridge::get_ble_transport_adapter()),
    ) {
        (Ok(coord), Ok(adapter)) => (coord, adapter),
        _ => {
            log::warn!("[BLE link] owed frames not delivered: the BLE transport is not ready");
            return Vec::new();
        }
    };
    let owed = rt.block_on(adapter.bilateral_handler().frames_owed_to(counterparty));
    let mut sealed = Vec::new();
    let mut delivered = Vec::new();
    for frame in owed {
        let on_link = coord
            .encode_message(owed_frame_type(frame.kind), &frame.bytes)
            .and_then(|chunks| crate::bluetooth::link_session::links().seal_on(link, &chunks));
        match on_link {
            Ok(records) => {
                sealed.extend(records);
                delivered.push((frame.commitment_hash, frame.kind));
            }
            Err(e) => log::error!(
                "[BLE link] an owed {:?} was not sealed on the link: {e}; it stays owed",
                frame.kind
            ),
        }
    }
    crate::bluetooth::owed_frame_driver::delivered(*counterparty, &delivered);
    sealed
}

// BLE coordinator helpers: availability checks and late-initialization attempt.
// These functions are intentionally lightweight: they query the bridge for an
// injected coordinator and return a boolean to the Java layer. If the SDK
// runtime is not available, they return false.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isBleCoordinatorReady(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "isBleCoordinatorReady",
        std::panic::AssertUnwindSafe(|| {
            let _env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            // Query bridge.get_ble_coordinator() synchronously via runtime
            let ok = if Handle::try_current().is_ok() {
                Handle::current()
                    .block_on(crate::bridge::get_ble_coordinator())
                    .is_ok()
            } else {
                crate::runtime::get_runtime()
                    .block_on(crate::bridge::get_ble_coordinator())
                    .is_ok()
            };
            if ok {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }),
    )
}

// ----------------------------------------------------------------------------
// BLE chunk processing + envelope chunking (JNI exports)
// ----------------------------------------------------------------------------

#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn build_chunk_array<'a>(
    env: &mut JNIEnv<'a>,
    chunks: &[Vec<u8>],
) -> Result<jni::objects::JObjectArray<'a>, String> {
    let byte_array_class = env
        .find_class("[B")
        .map_err(|e| format!("find_class([B) failed: {e}"))?;
    let arr = env
        .new_object_array(chunks.len() as i32, &byte_array_class, JObject::null())
        .map_err(|e| format!("new_object_array failed: {e}"))?;

    for (i, chunk) in chunks.iter().enumerate() {
        let jba = env
            .byte_array_from_slice(chunk)
            .map_err(|e| format!("byte_array_from_slice failed for chunk {i}: {e}"))?;
        env.set_object_array_element(&arr, i as i32, jba)
            .map_err(|e| format!("set_object_array_element failed for chunk {i}: {e}"))?;
    }
    Ok(arr)
}

#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn empty_byte_array_2d<'a>(env: &mut JNIEnv<'a>) -> jni::objects::JObjectArray<'a> {
    let byte_array_class = env.find_class("[B").ok();
    match byte_array_class {
        Some(cls) => env
            .new_object_array(0, cls, JObject::null())
            .unwrap_or_else(|_| unsafe {
                jni::objects::JObjectArray::from_raw(std::ptr::null_mut())
            }),
        None => unsafe { jni::objects::JObjectArray::from_raw(std::ptr::null_mut()) },
    }
}

/// What sending on a link came to.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// Kotlin wrote every chunk on the link.
    Sent,
    /// Not delivered now: no paired link, or the link is gone or refused a
    /// write. The caller's frame stays owed.
    NotNow,
}

/// Send one message's chunks to the contact `device_id` over BLE (DSM
/// Amendment A27, the owner's choice of 2026-11-01: "Rust chooses the link"):
/// sealed on the link this device is paired with it on, and handed to Kotlin
/// to write on exactly that link. With no paired link, Kotlin is asked to
/// connect, reaching for `address_hint` first, and the frame is not delivered
/// now: the link's handshake delivers what is owed once it pairs. Whether it
/// was sent; the frame of one not sent stays owed.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub(crate) fn send_ble_chunks_via_unified<'a>(
    env: &mut JNIEnv<'a>,
    device_id: &[u8; 32],
    address_hint: Option<&str>,
    chunks: &[Vec<u8>],
) -> Result<bool, String> {
    let links = crate::bluetooth::link_session::links();
    let delivery = match links.link_of(device_id) {
        Some(link) => {
            let sealed = links.seal_on(&link, chunks).map_err(|e| e.to_string())?;
            dispatch_on_link(env, &link, &sealed)?
        }
        None => {
            request_gatt_connect(env, device_id, address_hint)?;
            Delivery::NotNow
        }
    };
    Ok(delivery == Delivery::Sent)
}

/// Send a reply on the link at `address` the frame it answers arrived on,
/// sealed for that link's session. Nothing reconnects for it: a reply whose
/// link is gone is answered again when the counterparty sends its frame
/// again. Whether it was sent.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub(crate) fn send_ble_reply_on_link<'a>(
    env: &mut JNIEnv<'a>,
    address: &str,
    chunks: &[Vec<u8>],
) -> Result<bool, String> {
    let links = crate::bluetooth::link_session::links();
    let delivery = match links.at_address(address).into_iter().next() {
        Some(link) => {
            let sealed = links.seal_on(&link, chunks).map_err(|e| e.to_string())?;
            dispatch_on_link(env, &link, &sealed)?
        }
        None => Delivery::NotNow,
    };
    Ok(delivery == Delivery::Sent)
}

/// Hand `sealed` to Kotlin to write on exactly `link`: not delivered now when
/// that link is gone or refused a write, and nothing switches to another
/// link.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn dispatch_on_link<'a>(
    env: &mut JNIEnv<'a>,
    link: &crate::bluetooth::link_session::Link,
    sealed: &[Vec<u8>],
) -> Result<Delivery, String> {
    let addr_j = env
        .new_string(&link.address)
        .map_err(|e| format!("new_string failed: {e}"))?;
    let chunks_arr = build_chunk_array(env, sealed)?;
    let unified_cls =
        crate::jni::jni_common::find_class_with_app_loader(env, "com/dsm/wallet/bridge/Unified")?;
    let addr_obj = JObject::from(addr_j);
    let chunks_obj = JObject::from(chunks_arr);
    let args = [
        JValue::Object(&addr_obj),
        JValue::Int(link.role.to_wire()),
        JValue::Object(&chunks_obj),
    ];
    let result = env
        .call_static_method(
            &unified_cls,
            "dispatchRustBleFollowUp",
            "(Ljava/lang/String;I[[B)Z",
            &args,
        )
        .map_err(|e| format!("call_static_method dispatchRustBleFollowUp failed: {e}"))?;
    let written = result
        .z()
        .map_err(|e| format!("dispatchRustBleFollowUp answered no boolean: {e}"))?;
    Ok(if written {
        Delivery::Sent
    } else {
        Delivery::NotNow
    })
}

/// Ask Kotlin to connect for the contact `device_id`, reaching for
/// `address_hint` first: the link it opens names that contact as its target,
/// so the handshake says Hello to it first.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn request_gatt_connect<'a>(
    env: &mut JNIEnv<'a>,
    device_id: &[u8; 32],
    address_hint: Option<&str>,
) -> Result<(), String> {
    let device_id_j = env
        .byte_array_from_slice(device_id)
        .map_err(|e| format!("byte_array_from_slice failed: {e}"))?;
    let hint_j = env
        .new_string(address_hint.unwrap_or(""))
        .map_err(|e| format!("new_string failed: {e}"))?;
    let unified_cls =
        crate::jni::jni_common::find_class_with_app_loader(env, "com/dsm/wallet/bridge/Unified")?;
    let device_id_obj = JObject::from(device_id_j);
    let hint_obj = JObject::from(hint_j);
    env.call_static_method(
        &unified_cls,
        "requestGattConnect",
        "([BLjava/lang/String;)V",
        &[JValue::Object(&device_id_obj), JValue::Object(&hint_obj)],
    )
    .map_err(|e| format!("call_static_method requestGattConnect failed: {e}"))?;
    Ok(())
}

// BLE frame-type classification (`detect_ble_frame_type_from_bytes`) lives in the
// host-compiled `crate::bluetooth::frame_classify` module so it is unit tested in host CI
// (this JNI shim only compiles for `target_os = "android"`). It is imported at the top of
// this module; this shim only routes and frames.

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_detectEnvelopeFrameType(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jint {
    crate::jni::bridge_utils::jni_catch_unwind_jint(
        "detectEnvelopeFrameType",
        -1,
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return pb::BleFrameType::Unspecified as i32,
            };
            let jba = unsafe { jba_from(envelope_bytes) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return pb::BleFrameType::Unspecified as i32,
            };
            detect_ble_frame_type_from_bytes(&bytes)
        }),
    )
}

/// The radio's entry: bytes a peer wrote over BLE (a TX_REQUEST write, or a
/// TX_RESPONSE notification) on the link at `device_address`, this device on
/// it as `role` (1 client, 2 server). Kotlin MUST call this instead of
/// inspecting the bytes. They go first to the link session
/// (`crate::bluetooth::link_session`, DSM Amendment A27): a handshake
/// fragment is answered on the link, and a sealed record is opened. Only a
/// unit a link opened reaches `crate::bluetooth::radio_ingress`, which hands
/// a bilateral frame to the bilateral transport and refuses everything else;
/// what the transport answers is sealed on the same link. When a write pairs
/// the link, the contact's pairing completes and the frames owed to it are
/// sealed behind the answer. Returns a serialized `BleIncomingDataResponse`
/// (not Envelope v3 framed) whose `response_chunks` are written back verbatim
/// on the link, or an error envelope naming why the bytes were refused.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processIncomingBleData(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_address: jni::sys::jstring,
    role: jni::sys::jint,
    data: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let addr_raw = device_address;
    let data_raw = data;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jaddr = unsafe { jstr_from(addr_raw) };
        let addr: String = match env.get_string(&jaddr) {
            Ok(s) => s.into(),
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("processIncomingBleData: bad address: {e}"),
                )
                .into_raw();
            }
        };
        let jba = unsafe { jba_from(data_raw) };
        let bytes = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("processIncomingBleData: bad data: {e}"),
                )
                .into_raw();
            }
        };
        match radio_write(&addr, role, &bytes) {
            Ok(response_chunks) => {
                let out = crate::generated::BleIncomingDataResponse {
                    use_reliable_write: response_chunks.iter().any(|chunk| chunk.len() > 20),
                    response_chunks,
                };
                let encoded = prost::Message::encode_to_vec(&out);
                env.byte_array_from_slice(&encoded)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
            }
            Err((code, why)) => {
                log::error!("processIncomingBleData: refused bytes from {addr}: {why}");
                error_byte_array(
                    &mut env,
                    code as u32,
                    &format!("processIncomingBleData: {why}"),
                )
                .into_raw()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processIncomingBleData: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processIncomingBleData",
            )
            .into_raw()
        }
    }
}

/// One write from the radio on the link at `address`, as `role`: the radio
/// bytes to write back on that link.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn radio_write(
    address: &str,
    role: jni::sys::jint,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, (helpers::JniErrorCode, String)> {
    use crate::bluetooth::link_session::{links, GattRole, Link, WalletKeys};
    let refused = |e: &dyn core::fmt::Display| (helpers::JniErrorCode::InvalidInput, e.to_string());
    let link = Link {
        address: address.to_string(),
        role: GattRole::from_wire(role).map_err(|e| refused(&e))?,
    };
    let inbound = links()
        .inbound(&link, bytes, &WalletKeys)
        .map_err(|e| refused(&e))?;
    let mut response_chunks = inbound.reply;
    let rt = crate::runtime::get_runtime();
    if let Some(peer) = inbound.paired {
        if let Err(why) =
            rt.block_on(crate::bluetooth::get_pairing_orchestrator().link_paired(&peer, address))
        {
            return Err((helpers::JniErrorCode::ProcessingFailed, why));
        }
        crate::bluetooth::peer_address::record_sighting(&peer.device_id, address);
        response_chunks.extend(owed_frames_on(&link, &peer.device_id));
    }
    let Some(unit) = inbound.unit else {
        return Ok(response_chunks);
    };
    let not_ready = |e: &dyn core::fmt::Display| (helpers::JniErrorCode::NotReady, e.to_string());
    let coord = rt
        .block_on(crate::bridge::get_ble_coordinator())
        .map_err(|e| not_ready(&e))?;
    let adapter = rt
        .block_on(crate::bridge::get_ble_transport_adapter())
        .map_err(|e| not_ready(&e))?;
    let received = rt.block_on(crate::bluetooth::radio_ingress::receive_from_radio(
        &coord,
        adapter.as_ref(),
        address,
        &unit,
    ));
    let outbounds = match received {
        Ok(outbound) => outbound,
        Err(crate::bluetooth::radio_ingress::RadioError::Refused(refusal)) => {
            return Err(refused(&refusal))
        }
        Err(crate::bluetooth::radio_ingress::RadioError::Bilateral(e)) => {
            return Err((helpers::JniErrorCode::ProcessingFailed, e.to_string()))
        }
    };
    // Every answer is chunked, so each chunk fits one sealed record.
    let mut units = Vec::new();
    for outbound in outbounds.into_iter().flatten() {
        if outbound.payload.is_empty() {
            continue;
        }
        units.extend(
            coord
                .encode_message(outbound.frame_type, &outbound.payload)
                .map_err(|e| (helpers::JniErrorCode::ProcessingFailed, e.to_string()))?,
        );
    }
    response_chunks.extend(
        links()
            .seal_on(&link, &units)
            .map_err(|e| (helpers::JniErrorCode::ProcessingFailed, e.to_string()))?,
    );
    Ok(response_chunks)
}

/// Extract `response_chunks` from a `BleIncomingDataResponse` proto.
/// Kotlin calls this to get the pre-chunked byte arrays to write over BLE.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bleDataResponseExtractChunks(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "bleDataResponseExtractChunks",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => {
                    return empty_byte_array_2d(&mut env).into_raw();
                }
            };
            let resp: crate::generated::BleIncomingDataResponse =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => {
                        return empty_byte_array_2d(&mut env).into_raw();
                    }
                };
            let byte_class = match env.find_class("[B") {
                Ok(c) => c,
                Err(_) => return std::ptr::null_mut(),
            };
            let arr = match env.new_object_array(
                resp.response_chunks.len() as i32,
                &byte_class,
                &jni::objects::JObject::null(),
            ) {
                Ok(a) => a,
                Err(_) => return std::ptr::null_mut(),
            };
            for (i, chunk) in resp.response_chunks.iter().enumerate() {
                if let Ok(jba) = env.byte_array_from_slice(chunk) {
                    let _ = env.set_object_array_element(&arr, i as i32, &jba);
                }
            }
            arr.into_raw()
        }),
    )
}

/// Extract `use_reliable_write` from a `BleIncomingDataResponse` proto.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bleDataResponseUsesReliableWrite(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "bleDataResponseUsesReliableWrite",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return jni::sys::JNI_FALSE,
            };
            let resp: crate::generated::BleIncomingDataResponse =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => return jni::sys::JNI_FALSE,
                };
            if resp.use_reliable_write {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }),
    )
}

#[cfg(test)]
mod unified_protobuf_bridge_tests {
    use std::sync::Mutex;

    use crate::generated as pb;
    use once_cell::sync::Lazy;
    use prost::Message;
    use super::{
        detect_ble_frame_type_from_bytes, dispatch_envelope_via_ingress, is_error_envelope_bytes,
        route_hardware_facts_via_ingress,
    };
    use crate::bluetooth::frame_classify::strip_envelope_v3_framing;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn setup_test_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::economic_fixtures::use_test_storage_dir();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::ensure_storage_loaded();
        unsafe { crate::bridge::reset_bridge_handlers_for_tests() };
        guard
    }

    fn build_bilateral_confirm_envelope() -> Vec<u8> {
        let envelope = pb::Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: Some(pb::envelope::Payload::UniversalTx(pb::UniversalTx {
                ops: vec![pb::UniversalOp {
                    op_id: Some(pb::Hash32 { v: vec![5; 32] }),
                    actor: vec![1; 32],
                    kind: Some(pb::universal_op::Kind::Invoke(pb::Invoke {
                        method: "bilateral.confirm".to_string(),
                        args: Some(pb::ArgPack {
                            body: vec![9, 9, 9],
                            ..Default::default()
                        }),
                        ..Default::default()
                    })),
                }],
                atomic: true,
            })),
        };

        let mut bytes = Vec::new();
        envelope
            .encode(&mut bytes)
            .expect("encode confirm envelope");
        bytes
    }

    #[test]
    fn detects_bilateral_confirm_for_raw_and_framed_envelopes() {
        let raw = build_bilateral_confirm_envelope();
        let mut framed = vec![0x03];
        framed.extend_from_slice(&raw);

        assert_eq!(
            detect_ble_frame_type_from_bytes(&raw),
            pb::BleFrameType::BilateralConfirm as i32
        );
        assert_eq!(
            detect_ble_frame_type_from_bytes(&framed),
            pb::BleFrameType::BilateralConfirm as i32
        );
    }

    #[test]
    fn strips_envelope_v3_framing_only_when_present() {
        let raw = build_bilateral_confirm_envelope();
        let mut framed = vec![0x03];
        framed.extend_from_slice(&raw);

        assert_eq!(strip_envelope_v3_framing(&raw), raw.as_slice());
        assert_eq!(strip_envelope_v3_framing(&framed), raw.as_slice());
    }

    #[test]
    fn wrong_version_ble_frame_is_unspecified() {
        let mut env =
            crate::envelope::from_canonical_bytes(build_bilateral_confirm_envelope().as_slice())
                .expect("decode bilateral confirm envelope");
        env.version = 4;
        let raw = env.encode_to_vec();

        assert_eq!(
            detect_ble_frame_type_from_bytes(&raw),
            pb::BleFrameType::Unspecified as i32
        );
        assert_eq!(is_error_envelope_bytes(&raw), None);
    }

    #[test]
    #[serial_test::serial]
    fn hardware_facts_wrapper_matches_session_manager_bytes() {
        let _guard = setup_test_env();
        let facts = pb::SessionHardwareFactsProto {
            app_foreground: true,
            ble_enabled: true,
            ble_permissions: true,
            ble_scanning: false,
            ble_advertising: true,
            qr_available: true,
            qr_active: false,
            camera_permission: true,
            battery_charging: false,
            battery_level_percent: 77,
        };
        let expected =
            crate::sdk::session_manager::update_hardware_and_snapshot(&facts.encode_to_vec())
                .expect("session snapshot bytes");
        let actual = route_hardware_facts_via_ingress(facts).expect("ingress snapshot bytes");
        assert_eq!(actual, expected);
    }

    #[test]
    #[serial_test::serial]
    fn envelope_wrapper_preserves_framed_response_behavior() {
        let _guard = setup_test_env();
        let request = pb::Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                genesis_hash: vec![3; 32],
            }),
            message_id: vec![4; 16],
            payload: Some(pb::envelope::Payload::Error(pb::Error {
                code: 123,
                message: "already a response".to_string(),
                context: Vec::new(),
                source_tag: 0,
                is_recoverable: false,
                debug_b32: String::new(),
            })),
            ..Default::default()
        };
        let response =
            dispatch_envelope_via_ingress(&request.encode_to_vec()).expect("dispatch via ingress");
        assert_eq!(response.first(), Some(&0x03));
        let decoded =
            crate::envelope::from_canonical_bytes(&response[1..]).expect("decode response");
        assert_eq!(decoded.version, 3);
    }
}

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_acceptBilateralByCommitment(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    commitment_hash: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let commitment_hash_raw = commitment_hash;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        // Nothing the app asks runs while the wallet is locked (S-LOCK).
        if let Err(locked) =
            crate::sdk::session_manager::refuse_while_locked("acceptBilateralByCommitment")
        {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                &locked,
            )
            .into_raw();
        }
        let jba = unsafe { jba_from(commitment_hash_raw) };
        let bytes = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid commitment_hash: {e}"),
                )
                .into_raw();
            }
        };
        if bytes.len() != 32 {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::InvalidInput as u32,
                "commitment_hash must be 32 bytes",
            )
            .into_raw();
        }

        let mut ch = [0u8; 32];
        ch.copy_from_slice(&bytes);

        let coord =
            match crate::runtime::get_runtime().block_on(crate::bridge::get_ble_coordinator()) {
                Ok(c) => c,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        &format!("BLE coordinator not ready: {e}"),
                    )
                    .into_raw();
                }
            };

        let transport_adapter = match crate::runtime::get_runtime()
            .block_on(crate::bridge::get_ble_transport_adapter())
        {
            Ok(adapter) => adapter,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::NotReady as u32,
                    &format!("BLE transport adapter not ready: {e}"),
                )
                .into_raw();
            }
        };

        let (envelope_bytes, counterparty_device_id) = match crate::runtime::get_runtime()
            .block_on(transport_adapter.create_prepare_accept_envelope_with_counterparty(ch))
        {
            Ok(v) => v,
            // Nothing was accepted: the proposal still awaits its user.
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("acceptBilateralByCommitment failed: {e}"),
                )
                .into_raw();
            }
        };

        // Where to look for the sender first: the link its prepare arrived
        // on, else where its appliance was last seen.
        let address_hint = crate::runtime::get_runtime()
            .block_on(transport_adapter.sender_ble_address_for_commitment(ch))
            .or_else(|| {
                crate::bluetooth::peer_address::counterparty_address(&counterparty_device_id)
                    .ok()
                    .flatten()
            });

        let chunks = match coord
            .encode_message(pb::BleFrameType::BilateralPrepareResponse, &envelope_bytes)
        {
            Ok(c) => c,
            // The acceptance is kept, and its response is owed: it is sent
            // again when the link returns.
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("chunking accept envelope failed: {e}"),
                )
                .into_raw();
            }
        };

        match send_ble_chunks_via_unified(
            &mut env,
            &counterparty_device_id,
            address_hint.as_deref(),
            &chunks,
        ) {
            Ok(true) => crate::bluetooth::owed_frame_driver::delivered(
                counterparty_device_id,
                &[(
                    ch,
                    crate::bluetooth::bilateral_session::OfflineFrameKind::PrepareResponse,
                )],
            ),
            // A send that did not complete fails nothing: the acceptance is
            // kept and its response is sent again when the link returns.
            Ok(false) => {
                crate::bluetooth::owed_frame_driver::kick();
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    "the response was not delivered now; it is sent again when the link returns",
                )
                .into_raw();
            }
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("BLE send failed: {e}"),
                )
                .into_raw();
            }
        }

        let mut framed_bytes = Vec::with_capacity(1 + envelope_bytes.len());
        framed_bytes.push(0x03);
        framed_bytes.extend_from_slice(&envelope_bytes);

        env.byte_array_from_slice(&framed_bytes)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "acceptBilateralByCommitment: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in acceptBilateralByCommitment",
            )
            .into_raw()
        }
    }
}

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_rejectBilateralByCommitment(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    commitment_hash: jni::sys::jbyteArray,
    reason: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "rejectBilateralByCommitment",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            // Nothing the app asks runs while the wallet is locked (S-LOCK).
            if let Err(locked) =
                crate::sdk::session_manager::refuse_while_locked("rejectBilateralByCommitment")
            {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &locked,
                )
                .into_raw();
            }
            let jba = unsafe { jba_from(commitment_hash) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::InvalidInput as u32,
                        &format!("invalid commitment_hash: {e}"),
                    )
                    .into_raw();
                }
            };
            if bytes.len() != 32 {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "commitment_hash must be 32 bytes",
                )
                .into_raw();
            }
            let jreason = unsafe { jstr_from(reason) };
            let reason_str: String = match env.get_string(&jreason) {
                Ok(s) => s.into(),
                Err(_) => String::new(),
            };

            let mut ch = [0u8; 32];
            ch.copy_from_slice(&bytes);

            let coord = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_coordinator())
            {
                Ok(c) => c,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        &format!("BLE coordinator not ready: {e}"),
                    )
                    .into_raw();
                }
            };

            let transport_adapter = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_transport_adapter())
            {
                Ok(adapter) => adapter,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        &format!("BLE transport adapter not ready: {e}"),
                    )
                    .into_raw();
                }
            };

            let envelope_bytes = match crate::runtime::get_runtime().block_on(
                transport_adapter
                    .create_prepare_reject_envelope_with_cleanup(ch, reason_str.clone()),
            ) {
                Ok(v) => v,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &format!("rejectBilateralByCommitment failed: {e}"),
                    )
                    .into_raw();
                }
            };

            let Some(counterparty) = crate::runtime::get_runtime()
                .block_on(transport_adapter.counterparty_for_commitment(ch))
            else {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    "rejectBilateralByCommitment: the step names no counterparty",
                )
                .into_raw();
            };
            // Where to look for the sender first: the link its prepare arrived
            // on, else where its appliance was last seen.
            let address_hint = crate::runtime::get_runtime()
                .block_on(transport_adapter.sender_ble_address_for_commitment(ch))
                .or_else(|| {
                    crate::bluetooth::peer_address::counterparty_address(&counterparty)
                        .ok()
                        .flatten()
                });

            let chunks = match coord
                .chunk_message(pb::BleFrameType::BilateralPrepareReject, &envelope_bytes)
            {
                Ok(c) => c,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &format!("chunking reject envelope failed: {e}"),
                    )
                    .into_raw();
                }
            };

            match send_ble_chunks_via_unified(
                &mut env,
                &counterparty,
                address_hint.as_deref(),
                &chunks,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        "the frame was not delivered now",
                    )
                    .into_raw();
                }
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &format!("BLE send failed: {e}"),
                    )
                    .into_raw();
                }
            }

            let mut framed_bytes = Vec::with_capacity(1 + envelope_bytes.len());
            framed_bytes.push(0x03);
            framed_bytes.extend_from_slice(&envelope_bytes);

            env.byte_array_from_slice(&framed_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
        }),
    )
}

/// The proposer cancels a proposal it has not confirmed
/// (`BilateralBleHandler::cancel_proposal`) and sends the signed cancellation
/// to the counterparty. The cancellation holds whether or not this send
/// completes: it is also the answer to the counterparty's next frame for the
/// step.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cancelBilateralByCommitment(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    commitment_hash: jni::sys::jbyteArray,
    reason: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "cancelBilateralByCommitment",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            // Nothing the app asks runs while the wallet is locked (S-LOCK).
            if let Err(locked) =
                crate::sdk::session_manager::refuse_while_locked("cancelBilateralByCommitment")
            {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &locked,
                )
                .into_raw();
            }
            let jba = unsafe { jba_from(commitment_hash) };
            let ch: [u8; 32] = match env
                .convert_byte_array(&jba)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            {
                Some(ch) => ch,
                None => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::InvalidInput as u32,
                        "commitment_hash must be 32 bytes",
                    )
                    .into_raw();
                }
            };
            let jreason = unsafe { jstr_from(reason) };
            let reason: String = match env.get_string(&jreason) {
                Ok(s) => s.into(),
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::InvalidInput as u32,
                        &format!("invalid reason: {e}"),
                    )
                    .into_raw();
                }
            };
            let rt = crate::runtime::get_runtime();
            let (coord, adapter) = match (
                rt.block_on(crate::bridge::get_ble_coordinator()),
                rt.block_on(crate::bridge::get_ble_transport_adapter()),
            ) {
                (Ok(coord), Ok(adapter)) => (coord, adapter),
                _ => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        "BLE transport not ready",
                    )
                    .into_raw();
                }
            };
            let counterparty = rt.block_on(adapter.counterparty_for_commitment(ch));
            let cancellation =
                match rt.block_on(adapter.bilateral_handler().cancel_proposal(ch, reason)) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return error_byte_array(
                            &mut env,
                            helpers::JniErrorCode::ProcessingFailed as u32,
                            &format!("cancelBilateralByCommitment failed: {e}"),
                        )
                        .into_raw();
                    }
                };
            if let Some(counterparty) = counterparty {
                let address_hint =
                    crate::bluetooth::peer_address::counterparty_address(&counterparty)
                        .ok()
                        .flatten();
                let sent = coord
                    .chunk_message(pb::BleFrameType::BilateralPrepareReject, &cancellation)
                    .map_err(|e| e.to_string())
                    .and_then(|chunks| {
                        send_ble_chunks_via_unified(
                            &mut env,
                            &counterparty,
                            address_hint.as_deref(),
                            &chunks,
                        )
                    });
                if !matches!(sent, Ok(true)) {
                    log::warn!(
                        "[BLE] cancellation not delivered now; it answers the counterparty's next frame"
                    );
                }
            }
            let mut framed_bytes = Vec::with_capacity(1 + cancellation.len());
            framed_bytes.push(0x03);
            framed_bytes.extend_from_slice(&cancellation);
            env.byte_array_from_slice(&framed_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
        }),
    )
}

/* =============================================================================
Unified init/status + header fetch (stable surface for Activity gating)
============================================================================= */

/// Create a transaction error envelope for BLE operations
/// Returns protobuf-encoded envelope with Error payload
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createTransactionErrorEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    address: jni::sys::jstring,
    code: jni::sys::jint,
    message: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createTransactionErrorEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jaddr = unsafe { jstr_from(address) };
            let jmsg = unsafe { jstr_from(message) };

            let addr: String = match env.get_string(&jaddr) {
                Ok(s) => s.into(),
                Err(_) => return empty_byte_array_or_empty(&mut env).into_raw(),
            };

            let msg: String = match env.get_string(&jmsg) {
                Ok(s) => s.into(),
                Err(_) => return empty_byte_array_or_empty(&mut env).into_raw(),
            };

            // Create error message with device address context
            let error_msg = format!("BLE transaction error for {}: {}", addr, msg);

            // Use the existing error transport encoder
            let envelope = crate::jni::helpers::encode_error_transport(code as u32, &error_msg);

            let mut out = Vec::new();
            if let Err(e) = envelope.encode(&mut out) {
                log::error!("Failed to encode transaction error envelope: {}", e);
                return empty_byte_array_or_empty(&mut env).into_raw();
            }

            match env.byte_array_from_slice(&out) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!(
                        "Failed to create byte array for transaction error envelope: {}",
                        e
                    );
                    empty_byte_array_or_empty(&mut env).into_raw()
                }
            }
        }),
    )
}

/// Ensure the AppRouter is installed (idempotent; safe to call multiple times).
/// This should be called after SDK context initialization to enable wallet/contacts screens.
/// Returns true if AppRouter is available, false otherwise.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_ensureAppRouterInstalled(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "ensureAppRouterInstalled",
        std::panic::AssertUnwindSafe(|| {
            // Ensure logging is initialized first
            crate::logging::init_android_device_logging();

            log::info!("ensureAppRouterInstalled: START - function called");

            // Upgrade the MinimalBootstrapRouter to the full AppRouter when the canonical identity is
            // ready (device_id + unlocked wallet seed). This funnels through the single warm-swap
            // helper shared with `system.createGenesisV2`; it is idempotent (keyed off
            // `full_app_router_installed`, NOT `app_router().is_some()` — the latter is true for the
            // bootstrap router and used to short-circuit the upgrade, leaving post-genesis routes
            // failing with "requires genesis").
            match crate::init::install_full_app_router_self_config() {
                Ok(true) => {
                    log::info!("ensureAppRouterInstalled: full AppRouter ready - SUCCESS");
                    1 // true
                }
                Ok(false) => {
                    log::error!(
                        "ensureAppRouterInstalled: canonical identity not ready (need device identity + unlocked wallet seed)"
                    );
                    0 // false
                }
                Err(e) => {
                    log::error!("ensureAppRouterInstalled: {e}");
                    0 // false
                }
            }
        }),
    )
}

/// Return an integer status code describing why AppRouter may not be available.
/// Codes:
/// 0 = NOT_READY_NO_GENESIS
/// 1 = ROUTER_NOT_READY
/// 2 = INSTALLED
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getAppRouterStatus(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jint {
    crate::jni::bridge_utils::jni_catch_unwind_jint(
        "getAppRouterStatus",
        -1,
        std::panic::AssertUnwindSafe(|| {
            crate::logging::init_android_device_logging();

            log::info!("getAppRouterStatus: START");

            // INSTALLED means the FULL AppRouter. `app_router().is_some()` would also be true for
            // the MinimalBootstrapRouter and mask the locked/needs-genesis states below.
            if crate::bridge::full_app_router_installed() {
                log::info!("getAppRouterStatus: INSTALLED");
                return 2;
            }

            // Before storage init AppState is not readable: startup is incomplete, which is
            // ROUTER_NOT_READY (not NO_GENESIS: nothing is known about genesis yet).
            if !crate::sdk::app_state::AppState::readable() {
                log::info!("getAppRouterStatus: ROUTER_NOT_READY - storage not initialized");
                return 1;
            }

            // Not installed -> check genesis presence
            let has_genesis = crate::sdk::app_state::AppState::get_genesis_hash().is_some();
            if !has_genesis {
                log::info!("getAppRouterStatus: NOT_READY_NO_GENESIS");
                return 0;
            }

            // Genesis exists; the device signing key re-derives from the unlocked wallet seed
            // (no persisted key). If the wallet is locked, report NOT_READY (reusing the
            // legacy status code) so the platform prompts an unlock before router install.
            let wallet_unlocked =
                crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().is_some();
            if !wallet_unlocked {
                log::info!("getAppRouterStatus: NOT_READY - wallet locked");
                return 1;
            }

            // Conservative status: genesis and canonical binding are ready, but AppRouter still
            // is not installed. Return ROUTER_NOT_READY to indicate startup/router initialization is
            // still incomplete.
            log::warn!(
                "getAppRouterStatus: genesis present and canonical binding ready but AppRouter missing; returning ROUTER_NOT_READY"
            );
            1
        }),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session state JNI exports
//
// Returns naked AppSessionStateProto bytes (no envelope wrapping).
// Kotlin relays these bytes straight through to WebView untouched.
// ═══════════════════════════════════════════════════════════════════════════════

/// Return the current session state as FramedEnvelopeV3: `[0x03][Envelope(SessionStateResponse)]`.
/// Kotlin relays these bytes untouched to WebView via MessagePort — Invariant #1 + #7.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getSessionSnapshot(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getSessionSnapshot",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            match crate::sdk::session_manager::get_session_snapshot_bytes() {
                Ok(bytes) => env
                    .byte_array_from_slice(&bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                Err(e) => error_byte_array(
                    &env,
                    crate::jni::helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("getSessionSnapshot: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Accept `SessionHardwareFactsProto` bytes from Kotlin, apply to SessionManager,
/// return FramedEnvelopeV3: `[0x03][Envelope(SessionStateResponse)]`.
/// Kotlin relays these bytes untouched to WebView — Invariant #1 + #7.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_updateSessionHardwareFacts(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    facts_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "updateSessionHardwareFacts",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let input = unsafe { jni::objects::JByteArray::from_raw(facts_bytes) };
            let bytes: Vec<u8> = match env.convert_byte_array(&input) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("updateSessionHardwareFacts: convert_byte_array failed: {e}");
                    return empty_byte_array_or_empty(&env).into_raw();
                }
            };
            let facts = match pb::SessionHardwareFactsProto::decode(bytes.as_slice()) {
                Ok(facts) => facts,
                Err(e) => {
                    log::error!("updateSessionHardwareFacts: decode failed: {e}");
                    return error_byte_array(
                        &env,
                        helpers::JniErrorCode::InvalidInput as u32,
                        &format!("decode SessionHardwareFactsProto failed: {e}"),
                    )
                    .into_raw();
                }
            };

            match route_hardware_facts_via_ingress(facts) {
                Ok(snapshot_bytes) => env
                    .byte_array_from_slice(&snapshot_bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                Err(e) => {
                    log::error!("updateSessionHardwareFacts: {}", e.message);
                    error_byte_array(&env, e.code, &e.message).into_raw()
                }
            }
        }),
    )
}

/// Set a fatal error on the session manager and return updated snapshot bytes.
/// Used by Kotlin to report pre-bootstrap failures (env config errors) that
/// happen before SDK_READY is true and the app-router is available.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_setSessionFatalError(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    message: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "setSessionFatalError",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let input = unsafe { jni::objects::JByteArray::from_raw(message) };
            let bytes: Vec<u8> = match env.convert_byte_array(&input) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("setSessionFatalError: convert_byte_array failed: {e}");
                    return empty_byte_array_or_empty(&env).into_raw();
                }
            };

            let msg = String::from_utf8_lossy(&bytes);
            match crate::sdk::session_manager::set_fatal_error_and_snapshot(&msg) {
                Ok(snapshot_bytes) => env
                    .byte_array_from_slice(&snapshot_bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                Err(e) => error_byte_array(
                    &env,
                    crate::jni::helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("setSessionFatalError: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Clear the fatal error and return updated snapshot bytes.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_clearSessionFatalError(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "clearSessionFatalError",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            match crate::sdk::session_manager::clear_fatal_error_and_snapshot() {
                Ok(snapshot_bytes) => env
                    .byte_array_from_slice(&snapshot_bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                Err(e) => error_byte_array(
                    &env,
                    crate::jni::helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("clearSessionFatalError: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}
