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
//! - `appRouterQueryFramed(jbyteArray) -> jbyteArray`
//!   Read-only queries: balance, history, contacts, system tick, etc.
//! - `appRouterInvokeFramed(jbyteArray) -> jbyteArray`
//!   State-mutating operations: send tokens, create tokens, claim faucet, etc.
//! - `processEnvelopeV3(jbyteArray) -> jbyteArray`
//!   Generic Envelope v3 processing (BLE messages, bilateral protocol).
//!
//! ## Wire Format
//!
//! - Input: raw protobuf bytes (no framing prefix on request).
//! - Output: `[0x03][Envelope v3 protobuf bytes]` — always framed.
//! - Decode responses with `strip 0x03 prefix -> Envelope::decode()`.
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

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::generated as pb;
use crate::bluetooth::bilateral_transport_adapter::BleTransportDelegate;
use crate::jni::helpers;
use jni::objects::{JByteArray, JString, JObject, JValue};
use jni::JNIEnv;
use prost::Message;
use tokio::runtime::Handle;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::utils::deterministic_time as dt;
use crate::storage::client_db::{get_contact_by_device_id, get_contact_chain_tip};
use crate::sdk::session_manager::SDK_READY;
use crate::jni::state::{DEVICE_ID_TO_ADDR, parse_hex_32, register_ble_address_mapping};
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::jni::state::BILATERAL_INIT_POLL_STARTED;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::jni::bilateral_poll::{
    run_bilateral_poll, PollConfig, POLL_ATTEMPTS_STARTED, POLL_ATTEMPTS_SUCCESS,
    POLL_ATTEMPTS_TIMEOUT, POLL_TOTAL_ITERATIONS,
};

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

#[inline]
fn error_transport_bytes(code: u32, msg: &str) -> Vec<u8> {
    let env_pb = crate::jni::helpers::encode_error_transport(code, msg);
    let mut out = Vec::new();
    if let Err(e) = env_pb.encode(&mut out) {
        log::error!("failed to encode error envelope: {}", e);
        Vec::new()
    } else {
        let mut framed = Vec::with_capacity(1 + out.len());
        framed.push(0x03); // Framing byte for Envelope v3
        framed.extend_from_slice(&out);
        framed
    }
}

#[inline]
fn ensure_bootstrap() {
    // This function is intentionally side-effect free: it does NOT bootstrap.
    // Platform layers (Android/Kotlin) may choose to bootstrap from prefs before
    // calling JNI exports, but the Rust SDK itself stays deterministic and inert here.
    if !crate::is_sdk_context_initialized() {
        log::info!("ensure_bootstrap: SDK context not initialized (bootstrap is platform-managed)");
    }

    if SDK_READY.load(Ordering::SeqCst) {
        let dbrw_ok = crate::jni::cdbrw::get_cdbrw_binding_key()
            .map(|k| k.len() == 32)
            .unwrap_or(false);
        if !dbrw_ok {
            // Beta policy: DBRW is collect-only telemetry and MUST NOT gate readiness.
            log::info!(
                "ensure_bootstrap: DBRW not initialized (or invalid); continuing (beta collect-only mode)."
            );
        }
    }
}

fn fetch_transport_headers_bytes() -> Result<Vec<u8>, String> {
    crate::get_transport_headers_v3_bytes().map_err(|e| format!("headers fetch failed: {e}"))
}

fn build_transport_headers_pack() -> Result<Vec<u8>, String> {
    let body = fetch_transport_headers_bytes()
        .map_err(|e| format!("fetch_transport_headers_bytes failed: {}", e))?;
    let pack = pb::ResultPack {
        schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        codec: pb::Codec::Proto as i32,
        body,
    };
    let mut out = Vec::new();
    pack.encode(&mut out)
        .map_err(|e| format!("ResultPack encode failed: {}", e))?;
    Ok(out)
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
                    let envelope = pb::Envelope {
                        version: 3,
                        headers: Some(pb::Headers {
                            device_id: vec![0u8; 32],
                            chain_tip: vec![0u8; 32],
                            genesis_hash: vec![],
                            seq: 0,
                        }),
                        message_id: vec![],
                        payload: Some(payload),
                    };
                    let mut out = Vec::new();
                    out.push(0x03);
                    if envelope.encode(&mut out).is_err() {
                        return empty_byte_array_or_empty(env).into_raw();
                    }
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(env).into_raw())
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

            ensure_bootstrap();
            if !SDK_READY.load(Ordering::SeqCst) {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                );
            }

            // Defensive: ensure the bilateral handler is installed.
            // Offline BLE transfers need no storage endpoints — contact was already
            // verified against storage nodes during the add-contact (QR scan) phase.
            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            {
                if crate::bridge::bilateral_handler().is_none() {
                    use crate::init::SdkConfig;
                    let cfg = SdkConfig {
                        node_id: "default".to_string(),
                        storage_endpoints: Vec::new(),
                        enable_offline: true,
                    };
                    log::warn!("bilateral handler missing – attempting offline-only SDK init");
                    match crate::init::init_dsm_sdk(&cfg) {
                        Ok(()) => {
                            log::info!(
                                "offline-only SDK init completed; bilateral handler installed"
                            )
                        }
                        Err(e) => log::error!("offline-only SDK init failed: {}", e),
                    }
                }
            }
            if !SDK_READY.load(Ordering::SeqCst) || !crate::is_sdk_context_initialized() {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                );
            }

            // WebView contract: return raw `BalancesListResponse` bytes on success.
            // This JNI export i now migrated to return FramedEnvelopeV3 (0x03 + Envelope).
            let result = crate::bridge::get_all_balances_strict();
            match result {
                Ok(balances) => {
                    // Encode as the canonical BalancesListResponse payload
                    let list = pb::BalancesListResponse {
                        balances: balances
                            .into_iter()
                            .map(|e| pb::BalanceGetResponse {
                                token_id: e.token_id,
                                available: e
                                    .amount
                                    .and_then(|a| {
                                        if a.le.len() != 16 {
                                            return None;
                                        }
                                        let mut buf = [0u8; 16];
                                        buf.copy_from_slice(&a.le);
                                        Some(u128::from_le_bytes(buf))
                                    })
                                    .unwrap_or(0)
                                    .try_into()
                                    .unwrap_or(u64::MAX),
                                locked: 0,
                                ..Default::default()
                            })
                            .collect(),
                    };
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

/// Protobuf-first init entrypoint.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_initSdkV3(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    jbase: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "initSdkV3",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jbase = unsafe { jstr_from(jbase) };
            let base: String = match env.get_string(&jbase) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("initSdkV3: failed to read baseDir: {}", e);
                    String::new()
                }
            };

            let respond =
                |payload: pb::envelope::Payload, env: &mut JNIEnv| -> jni::sys::jbyteArray {
                    let envelope = pb::Envelope {
                        version: 3,
                        headers: Some(pb::Headers {
                            device_id: vec![0u8; 32],
                            chain_tip: vec![0u8; 32],
                            genesis_hash: vec![],
                            seq: 0,
                        }),
                        message_id: vec![],
                        payload: Some(payload),
                    };
                    let mut out = Vec::new();
                    out.push(0x03); // Canonical framing byte for FramedEnvelopeV3
                    if envelope.encode(&mut out).is_err() {
                        return error_byte_array(
                            env,
                            helpers::JniErrorCode::EncodingFailed as u32,
                            "failed to encode envelope",
                        )
                        .into_raw();
                    }
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or(
                            error_byte_array(
                                env,
                                helpers::JniErrorCode::EncodingFailed as u32,
                                "failed to allocate return bytes",
                            )
                            .into_raw(),
                        )
                };

            if base.is_empty() {
                SDK_READY.store(false, Ordering::SeqCst);
                return respond(
                    pb::envelope::Payload::InitFailed(pb::InitFailed {
                        reason: pb::init_failed::Reason::InvalidInput as i32,
                        message: "baseDir is empty".to_string(),
                    }),
                    &mut env,
                );
            }

            let _ =
                crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(base.clone()));

            let dbrw_ok = crate::jni::cdbrw::get_cdbrw_binding_key()
                .map(|k| k.len() == 32)
                .unwrap_or(false);
            if !dbrw_ok {
                SDK_READY.store(false, Ordering::SeqCst);
                return respond(
                    pb::envelope::Payload::InitFailed(pb::InitFailed {
                        reason: pb::init_failed::Reason::CdbrwNotReady as i32,
                        message: "C-DBRW not initialized (or invalid). Call sdkBootstrap first."
                            .to_string(),
                    }),
                    &mut env,
                );
            }

            SDK_READY.store(true, Ordering::SeqCst);
            respond(
                pb::envelope::Payload::AppStateResponse(pb::AppStateResponse {
                    key: "sdk.init".to_string(),
                    value: Some("ok".to_string()),
                }),
                &mut env,
            )
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getWalletHistoryStrict(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getWalletHistoryStrict",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let respond_envelope =
                |payload: pb::envelope::Payload, env: &mut JNIEnv| -> jni::sys::jbyteArray {
                    let envelope = pb::Envelope {
                        version: 3,
                        headers: Some(pb::Headers {
                            device_id: vec![0u8; 32],
                            chain_tip: vec![0u8; 32],
                            genesis_hash: vec![],
                            seq: 0,
                        }),
                        message_id: vec![],
                        payload: Some(payload),
                    };
                    let mut out = Vec::new();
                    out.push(0x03);
                    if envelope.encode(&mut out).is_err() {
                        return empty_byte_array_or_empty(env).into_raw();
                    }
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(env).into_raw())
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

            ensure_bootstrap();
            if !SDK_READY.load(Ordering::SeqCst) {
                return respond_error(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                );
            }

            let result = crate::bridge::get_wallet_history_strict();
            match result {
                Ok(history) => {
                    // Encode as the canonical WalletHistoryResponse payload
                    respond_envelope(
                        pb::envelope::Payload::WalletHistoryResponse(history),
                        &mut env,
                    )
                }
                Err(e) => {
                    log::error!("getWalletHistoryStrict: failed: {}", e);
                    respond_error(
                        &mut env,
                        helpers::JniErrorCode::BridgeCallFailed as u32,
                        &format!("get_wallet_history_strict failed: {}", e),
                    )
                }
            }
        }),
    )
}

/// Remove a contact by contact_id.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_removeContact(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    jcontact_id: jni::sys::jstring,
) -> jni::sys::jbyte {
    crate::jni::bridge_utils::jni_catch_unwind_jbyte(
        "removeContact",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return 0,
            };
            let jcontact_id = unsafe { jstr_from(jcontact_id) };
            let contact_id: String = match env.get_string(&jcontact_id) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("removeContact: failed to read contact_id: {}", e);
                    return 0;
                }
            };

            if contact_id.trim().is_empty() {
                log::warn!("removeContact: empty contact_id");
                return 0;
            }

            match crate::storage::client_db::delete_contact_by_id(&contact_id) {
                Ok(_) => 1,
                Err(e) => {
                    log::error!("removeContact: delete failed: {}", e);
                    0
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
            let _ =
                crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(base.clone()));
            let dbrw_ok = crate::jni::cdbrw::get_cdbrw_binding_key()
                .map(|k| k.len() == 32)
                .unwrap_or(false);
            if !dbrw_ok {
                log::info!("initSdk: DBRW binding key not available (pre-genesis device)");
            }
            // SDK_READY gates SessionManager phase computation.
            // Must be true even without DBRW so fresh devices get "needs_genesis"
            // instead of being stuck on "runtime_loading". DBRW key is created
            // during genesis enrollment; its absence is expected pre-genesis.
            SDK_READY.store(true, Ordering::SeqCst);
            if dbrw_ok {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
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
            match crate::storage_utils::set_storage_base_dir(path) {
                Ok(success) => {
                    if success {
                        log::info!("initStorageBaseDir: storage base directory set successfully");
                    } else {
                        log::warn!("initStorageBaseDir: storage base directory already set");
                    }
                }
                Err(e) => {
                    log::error!(
                        "initStorageBaseDir: failed to set storage base directory: {}",
                        e
                    );
                }
            }
        }),
    );
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_computeB0xAddress(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
    jgenesis: jni::sys::jbyteArray,
    jdevice: jni::sys::jbyteArray,
    jtip: jni::sys::jbyteArray,
) -> jni::sys::jstring {
    // jstring and jbyteArray are both *mut _jobject; catch_unwind_jbytearray returns null_mut() on panic.
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "computeB0xAddress",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jgen = unsafe { jba_from(jgenesis) };
            let jdev = unsafe { jba_from(jdevice) };
            let jtip = unsafe { jba_from(jtip) };

            let genesis = match env.convert_byte_array(jgen) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("computeB0xAddress: failed to convert genesis bytes: {}", e);
                    return env
                        .new_string("")
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut());
                }
            };
            let device = match env.convert_byte_array(jdev) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("computeB0xAddress: failed to convert device bytes: {}", e);
                    return env
                        .new_string("")
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut());
                }
            };
            let tip = match env.convert_byte_array(jtip) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("computeB0xAddress: failed to convert tip bytes: {}", e);
                    return env
                        .new_string("")
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut());
                }
            };

            if genesis.len() != 32 || device.len() != 32 || tip.len() != 32 {
                log::warn!(
                    "computeB0xAddress: inputs must be 32 bytes each (got {}, {}, {})",
                    genesis.len(),
                    device.len(),
                    tip.len()
                );
                return env
                    .new_string("")
                    .map(|s| s.into_raw())
                    .unwrap_or(std::ptr::null_mut());
            }

            match crate::sdk::b0x_sdk::B0xSDK::compute_b0x_address(&genesis, &device, &tip) {
                Ok(addr) => env
                    .new_string(addr)
                    .map(|s| s.into_raw())
                    .unwrap_or(std::ptr::null_mut()),
                Err(e) => {
                    log::error!("computeB0xAddress: internal error: {}", e);
                    env.new_string("")
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut())
                }
            }
        }),
    )
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
            crate::network::set_env_config_path(config_path);
            log::info!(
                "initDsmSdk: environment config path set to: {}",
                crate::network::get_env_config_path().unwrap_or("none")
            );
            // Dev convenience: allow localhost endpoints on Android when using adb reverse.
            // Only allow localhost endpoints in debug builds. Production/release builds
            // must use real network endpoints.
            #[cfg(debug_assertions)]
            {
                std::env::set_var("DSM_ALLOW_LOCALHOST", "1");
                log::info!("initDsmSdk: DSM_ALLOW_LOCALHOST=1 set (debug build)");
            }
            #[cfg(not(debug_assertions))]
            log::info!("initDsmSdk: DSM_ALLOW_LOCALHOST not set (release build)");
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
            ensure_bootstrap();
            // Three-state readiness gate for UI:
            // 0 = NO_IDENTITY (no persisted device_id/genesis)
            // 1 = RUNTIME_NOT_READY (identity present, but runtime not fully ready yet)
            // 3 = READY (DBRW + SDK fully ready)
            let has_identity = crate::sdk::app_state::AppState::get_device_id()
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
            ensure_bootstrap();
            // Do not gate header fetch on DBRW/SDK_READY. Headers may be required immediately
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

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getTransportHeadersV3Pack(
    env: jni::sys::JNIEnv,
    _class: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getTransportHeadersV3Pack",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();
            // Same policy as getTransportHeadersV3: allow header pack retrieval as soon as
            // identity exists and the SDK context can be bootstrapped from AppState.
            let out = match build_transport_headers_pack() {
                Ok(v) => v,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &e,
                    )
                    .into_raw()
                }
            };
            env.byte_array_from_slice(&out)
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
            ensure_bootstrap();

            match crate::sdk::app_state::AppState::get_device_id() {
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
            ensure_bootstrap();

            match crate::sdk::app_state::AppState::get_genesis_hash() {
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

/// Returns the local signing public key as raw bytes (64 bytes for SPHINCS+ SPX256s) when available.
///
/// Kotlin expects this exact symbol for `Unified.getSigningPublicKeyBin()`.
/// If identity has not been created yet, returns an empty byte array.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getSigningPublicKeyBin(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getSigningPublicKeyBin",
        std::panic::AssertUnwindSafe(|| {
            crate::logging::init_android_device_logging();

            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();

            match crate::sdk::app_state::AppState::get_public_key() {
                Some(pk) => {
                    log::info!("getSigningPublicKeyBin: returning {} bytes", pk.len());
                    env.byte_array_from_slice(&pk)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|e| {
                            log::error!(
                                "getSigningPublicKeyBin: failed to create jbyteArray: {}",
                                e
                            );
                            env.new_byte_array(0)
                                .map(|a| a.into_raw())
                                .unwrap_or(std::ptr::null_mut())
                        })
                }
                None => {
                    log::warn!("getSigningPublicKeyBin: no public key available");
                    env.new_byte_array(0)
                        .map(|a| a.into_raw())
                        .unwrap_or(std::ptr::null_mut())
                }
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_getTransportHeadersV3(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "DsmNative_getTransportHeadersV3",
        std::panic::AssertUnwindSafe(|| {
            Java_com_dsm_wallet_bridge_UnifiedNativeApi_getTransportHeadersV3(env, _clazz)
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_getTransportHeadersV3Pack(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "DsmNative_getTransportHeadersV3Pack",
        std::panic::AssertUnwindSafe(|| {
            Java_com_dsm_wallet_bridge_UnifiedNativeApi_getTransportHeadersV3Pack(env, _clazz)
        }),
    )
}

fn is_error_envelope_bytes(bytes: &[u8]) -> Option<u32> {
    match pb::Envelope::decode(bytes) {
        Ok(env) => match env.payload {
            Some(pb::envelope::Payload::Error(e)) => Some(e.code),
            _ => None,
        },
        Err(_) => None,
    }
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

/// Backward-compatible wrapper — existing call sites (diagnostics, pairing) use this.
#[inline]
fn process_envelope_v3(req: &[u8]) -> Result<Vec<u8>, String> {
    process_envelope_v3_impl(req, None)
}

/// Process a v3 envelope with optional BLE device address context.
///
/// Routes bilateral response/reject payloads to the BLE coordinator (instead of
/// the core bridge which rejects them with error 409). The `device_address`
/// parameter enables session routing for bilateral messages received as complete
/// 0x03 envelopes rather than BLE chunks.
fn process_envelope_v3_impl(req: &[u8], device_address: Option<&str>) -> Result<Vec<u8>, String> {
    ensure_bootstrap();

    // Intercept BleEvent.identity_observed at SDK layer before forwarding to core.
    // Core returns an error for BleEvent payloads ("handled at bridge level").
    let raw = if req.first() == Some(&0x03) {
        &req[1..]
    } else {
        req
    };
    if let Ok(env) = pb::Envelope::decode(raw) {
        if let Some(pb::envelope::Payload::BleEvent(ref ble)) = env.payload {
            if let Some(pb::ble_event::Ev::IdentityObserved(ref obs)) = ble.ev {
                return handle_ble_identity_observed_from_envelope(obs);
            }
            // Other BleEvent variants: return empty ack (not an error)
            log::debug!("process_envelope_v3: BleEvent variant handled (non-identity)");
            return Ok(Vec::new());
        }

        // Intercept bilateral response/reject envelopes — route to BLE coordinator
        // instead of core bridge (which rejects them with error 409).
        #[cfg(all(target_os = "android", feature = "bluetooth"))]
        {
            let bilateral_frame_type = match &env.payload {
                Some(pb::envelope::Payload::BilateralPrepareResponse(_)) => {
                    Some(pb::BleFrameType::BilateralPrepareResponse)
                }
                Some(pb::envelope::Payload::BilateralPrepareReject(_)) => {
                    Some(pb::BleFrameType::BilateralPrepareReject)
                }
                Some(pb::envelope::Payload::BilateralCommitResponse(_)) => {
                    Some(pb::BleFrameType::BilateralCommitResponse)
                }
                Some(pb::envelope::Payload::UniversalTx(tx)) => {
                    // Detect bilateral.confirm invoke for 3-step protocol
                    tx.ops.first().and_then(|op| {
                        if let Some(pb::universal_op::Kind::Invoke(inv)) = op.kind.as_ref() {
                            if inv.method == "bilateral.confirm" {
                                return Some(pb::BleFrameType::BilateralConfirm);
                            }
                        }
                        None
                    })
                }
                _ => None,
            };
            if let Some(frame_type) = bilateral_frame_type {
                log::info!(
                    "process_envelope_v3: intercepting bilateral {:?} via BLE coordinator",
                    frame_type
                );
                let adapter = crate::runtime::get_runtime()
                    .block_on(crate::bridge::get_ble_transport_adapter())
                    .map_err(|e| format!("BLE transport adapter not ready: {e}"))?;
                let result = crate::runtime::get_runtime()
                    .block_on(adapter.on_transport_message(
                        crate::bluetooth::TransportInboundMessage {
                            peer_address: device_address.unwrap_or_default().to_string(),
                            frame_type,
                            payload: raw.to_vec(),
                        },
                    ))
                    .map_err(|e| format!("bilateral via envelope: {e}"))?;
                return Ok(result
                    .into_iter()
                    .next()
                    .map(|outbound| outbound.payload)
                    .unwrap_or_default());
            }
        }
    }

    let out = dsm::core::bridge::handle_envelope_universal(raw);
    if out.is_empty() || out.first() == Some(&0x03) {
        Ok(out)
    } else {
        let mut framed = Vec::with_capacity(1 + out.len());
        framed.push(0x03);
        framed.extend_from_slice(&out);
        Ok(framed)
    }
}

/// Handle a BleEvent.identity_observed extracted from a protobuf Envelope.
/// Uses the address from the proto message (set by the caller).
pub(crate) fn handle_ble_identity_observed_from_envelope(
    obs: &pb::BleIdentityObserved,
) -> Result<Vec<u8>, String> {
    if obs.genesis_hash.len() != 32 || obs.device_id.len() != 32 {
        return Err(format!(
            "identity_observed: invalid lengths genesis={} device_id={}",
            obs.genesis_hash.len(),
            obs.device_id.len()
        ));
    }

    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&obs.genesis_hash);
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&obs.device_id);
    let address = obs.address.clone();

    log::info!(
        "handle_ble_identity_observed_from_envelope: addr={}, genesis={:02x}{:02x}..., device={:02x}{:02x}...",
        address, genesis_hash[0], genesis_hash[1], device_id[0], device_id[1]
    );

    // Strict gate: pairing/identity mapping must only proceed for existing contacts.
    // Missing contacts are treated as hard failures.
    let contact_opt = match get_contact_by_device_id(&device_id) {
        Ok(Some(c)) => Some(c),
        Ok(None) => {
            return Err(format!(
                "identity_observed: contact missing in SQLite for {:02x}{:02x}...",
                device_id[0], device_id[1]
            ));
        }
        Err(e) => {
            return Err(format!(
                "identity_observed: SQLite lookup failed for {:02x}{:02x}...: {}",
                device_id[0], device_id[1], e
            ));
        }
    };

    if let Some(contact) = contact_opt {
        if contact.genesis_hash != genesis_hash {
            return Err(format!(
                "identity_observed: genesis mismatch for {:02x}{:02x}...",
                device_id[0], device_id[1]
            ));
        }

        if contact.ble_address.as_ref() != Some(&address) && !address.is_empty() {
            let _ = crate::storage::client_db::update_contact_ble_status(
                &device_id,
                None,
                Some(&address),
            );
            // Register in in-memory resolution map
            register_ble_address_mapping(&device_id, &address);
            // Verify persistence
            match get_contact_by_device_id(&device_id) {
                Ok(Some(re_read)) if re_read.ble_address.as_ref() == Some(&address) => {
                    log::info!(
                        "handle_ble_identity_observed: BLE address CONFIRMED persisted for {:02x}{:02x}...",
                        device_id[0], device_id[1]
                    );
                }
                _ => {
                    log::error!(
                        "handle_ble_identity_observed: BLE address persistence verification FAILED for {:02x}{:02x}...",
                        device_id[0], device_id[1]
                    );
                }
            }
        }
    }

    // Notify orchestrator
    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
    let rt = crate::runtime::get_runtime();
    match rt.block_on(orchestrator.handle_identity_observed(address, genesis_hash, device_id)) {
        Ok(()) => log::info!("handle_ble_identity_observed_from_envelope: orchestrator ok"),
        Err(e) => log::warn!(
            "handle_ble_identity_observed_from_envelope: orchestrator: {}",
            e
        ),
    }

    Ok(Vec::new())
}

// ==================== MCP JNI externs ====================
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_mcp_McpServiceBus_jniSubmitEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let envelope_raw = envelope;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jba = unsafe { jba_from(envelope_raw) };

        let req = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
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

        env.byte_array_from_slice(&resp)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "jniSubmitEnvelope: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in jniSubmitEnvelope",
            )
            .into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_mcp_McpServiceBus_jniGetDeviceId(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        ensure_bootstrap();

        match crate::sdk::app_state::AppState::get_device_id() {
            Some(id) if id.len() == 32 => env
                .byte_array_from_slice(&id)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw()),
            _ => env
                .new_byte_array(0)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw()),
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "jniGetDeviceId: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in jniGetDeviceId",
            )
            .into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_mcp_McpServiceBus_jniGetTransportHeaders(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        ensure_bootstrap();
        let bytes = match fetch_transport_headers_bytes() {
            Ok(b) => b,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("getTransportHeaders failed: {e}"),
                )
                .into_raw();
            }
        };
        env.byte_array_from_slice(&bytes)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "jniGetTransportHeaders: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in jniGetTransportHeaders",
            )
            .into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_mcp_McpServiceBus_jniSendBleProto(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    bytes: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "jniSendBleProto",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            let jba = unsafe { jba_from(bytes) };
            let payload = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return jni::sys::JNI_FALSE,
            };
            if payload.is_empty() {
                return jni::sys::JNI_FALSE;
            }

            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            {
                if let Some(bridge) =
                    crate::bluetooth::android_ble_bridge::get_global_android_bridge()
                {
                    let res = crate::runtime::get_runtime()
                        .block_on(async { bridge.handle_ble_event_bytes(&payload).await });
                    match res {
                        Ok(_) => return jni::sys::JNI_TRUE,
                        Err(e) => {
                            log::warn!("jniSendBleProto: handle_ble_event_bytes failed: {e}");
                            return jni::sys::JNI_FALSE;
                        }
                    }
                }
            }

            jni::sys::JNI_FALSE
        }),
    )
}

/// UnifiedNativeApi JNI entry for processEnvelopeV3.
/// Delegates to the internal `process_envelope_v3()` helper (line 846).
/// Kotlin BLE layer (GattServerHost, GattClientSession, BleCoordinator) calls
/// Unified.processEnvelopeV3() which routes here.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processEnvelopeV3(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let envelope_raw = envelope;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jba = unsafe { jba_from(envelope_raw) };

        let req = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
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

        env.byte_array_from_slice(&resp)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processEnvelopeV3: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processEnvelopeV3",
            )
            .into_raw()
        }
    }
}

/// Process a v3 envelope with BLE device address context.
/// Routes bilateral response/reject payloads to the BLE coordinator instead of
/// the core bridge. Used by BleCoordinator and GattServerHost when receiving
/// complete 0x03-prefixed envelopes over BLE.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processEnvelopeV3WithAddress(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope: jni::sys::jbyteArray,
    device_address: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let envelope_raw = envelope;
    let device_address_raw = device_address;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };

        let jaddr = unsafe { jstr_from(device_address_raw) };
        let addr: String = match env.get_string(&jaddr) {
            Ok(s) => s.into(),
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid device address: {e}"),
                )
                .into_raw();
            }
        };

        let jba = unsafe { jba_from(envelope_raw) };
        let req = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid envelope bytes: {e}"),
                )
                .into_raw();
            }
        };

        let resp = match process_envelope_v3_impl(&req, Some(&addr)) {
            Ok(bytes) => bytes,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("processEnvelopeV3WithAddress failed: {e}"),
                )
                .into_raw();
            }
        };

        env.byte_array_from_slice(&resp)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processEnvelopeV3WithAddress: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processEnvelopeV3WithAddress",
            )
            .into_raw()
        }
    }
}

/// UnifiedNativeApi JNI entry for extractGenesisIdentity.
/// Thin delegate to the existing DsmNative implementation.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_extractGenesisIdentity(
    env: jni::sys::JNIEnv,
    clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "extractGenesisIdentity",
        std::panic::AssertUnwindSafe(|| {
            Java_com_dsm_native_DsmNative_extractGenesisIdentity(env, clazz, envelope_bytes)
        }),
    )
}

/* ====================================================================================
Manual Accept Toggle (BLE deterministic gate)
==================================================================================== */

/// Process raw NFC tag bytes by wrapping them in a UniversalOp::ExternalCommit
/// and routing through the standard envelope processor.
#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_processNfcTag(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    tag_data: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let tag_data_raw = tag_data;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jba = unsafe { jba_from(tag_data_raw) };

        let payload = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                log::error!("[JNI] processNfcTag: failed to read bytes: {}", e);
                return error_byte_array(
                    &mut env,
                    crate::jni::helpers::JniErrorCode::InvalidInput as u32,
                    &format!("failed to read bytes: {}", e),
                )
                .into_raw();
            }
        };

        // Construct ExternalCommit with source "nfc:recovery"
        let source = "nfc:recovery";
        let source_id = dsm::commitments::external_source_id(source);
        let evidence_hash = dsm::commitments::external_evidence_hash(&[]);
        let commit_id =
            dsm::commitments::create_external_commitment(&payload, &source_id, &evidence_hash);
        let op = pb::UniversalOp {
            op_id: None,
            actor: vec![],
            genesis_hash: vec![],
            kind: Some(pb::universal_op::Kind::ExternalCommit(pb::ExternalCommit {
                source_id: Some(pb::Hash32 {
                    v: source_id.to_vec(),
                }),
                payload,
                evidence: None,
                commit_id: Some(pb::Hash32 {
                    v: commit_id.to_vec(),
                }),
            })),
        };

        // Construct UniversalTx
        let tx = pb::UniversalTx {
            ops: vec![op],
            atomic: true,
        };

        // Construct Envelope
        let envelope = pb::Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![0; 32], // Dummy
                chain_tip: vec![0; 32], // Dummy
                genesis_hash: vec![],
                seq: 0,
            }),
            message_id: vec![],
            payload: Some(pb::envelope::Payload::UniversalTx(tx)),
        };

        let mut env_bytes = Vec::new();
        env_bytes.push(0x03); // Canonical framing byte for FramedEnvelopeV3
        if let Err(e) = envelope.encode(&mut env_bytes) {
            log::error!("[JNI] processNfcTag: failed to encode envelope: {}", e);
            return error_byte_array(
                &mut env,
                crate::jni::helpers::JniErrorCode::EncodingFailed as u32,
                &format!("failed to encode envelope: {}", e),
            )
            .into_raw();
        }

        // Process via core bridge
        let resp_bytes = match process_envelope_v3(&env_bytes) {
            Ok(b) => b,
            Err(e) => {
                log::error!("[JNI] processNfcTag: process_envelope_v3 failed: {}", e);
                return error_byte_array(
                    &mut env,
                    crate::jni::helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("process_envelope_v3 failed: {}", e),
                )
                .into_raw();
            }
        };
        match env.byte_array_from_slice(&resp_bytes) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                log::error!("processNfcTag: failed to allocate return bytes: {}", e);
                error_byte_array(
                    &mut env,
                    crate::jni::helpers::JniErrorCode::EncodingFailed as u32,
                    "failed to allocate return bytes",
                )
                .into_raw()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processNfcTag: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processNfcTag",
            )
            .into_raw()
        }
    }
}

/// Initialize bilateral SDK preconditions (context + handler + calibration).
/// Call this after genesis creation and SDK context initialization.
/// Returns true on success, false on failure.
/// Note: JNI symbol name retained for Kotlin ABI compatibility.
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

            // Defensive: Just-in-Time init to ensure handler exists for background services
            if crate::bridge::bilateral_handler().is_none() {
                use crate::init::SdkConfig;
                let cfg = SdkConfig {
                    node_id: "default".to_string(),
                    storage_endpoints: Vec::new(),
                    enable_offline: true,
                };
                log::warn!(
            "initializeBilateralSdk: bilateral handler missing – attempting offline-only SDK init"
        );
                match crate::init::init_dsm_sdk(&cfg) {
                    Ok(()) => log::info!("initializeBilateralSdk: offline-only SDK init completed"),
                    Err(e) => log::error!(
                        "initializeBilateralSdk: offline-only SDK init failed: {}",
                        e
                    ),
                }
            }

            // Defer if context or handler not available yet
            if !crate::is_sdk_context_initialized() || crate::bridge::bilateral_handler().is_none()
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
                                    crate::bridge::bilateral_handler().is_some(),
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

/* ====================================================================================
Manual Accept Toggle (BLE deterministic gate)
==================================================================================== */
#[cfg(all(target_os = "android", feature = "bluetooth"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_setManualAcceptEnabled(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    enabled: jni::sys::jboolean,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "setManualAcceptEnabled",
        std::panic::AssertUnwindSafe(|| {
            crate::bluetooth::set_manual_accept_enabled(enabled != 0);
            log::info!("[JNI] setManualAcceptEnabled: {}", enabled != 0);
        }),
    );
}

#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_setManualAcceptEnabled(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    _enabled: jni::sys::jboolean,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "setManualAcceptEnabled",
        std::panic::AssertUnwindSafe(|| {
            // No-op on non-Android/non-BLE builds.
        }),
    );
}

// Readiness query exports for UI polling (aggregate readiness includes bilateral on bluetooth builds)
#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_isSdkFullyReady(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "DsmNative_isSdkFullyReady",
        std::panic::AssertUnwindSafe(|| {
            if SDK_READY.load(Ordering::SeqCst) && crate::is_sdk_fully_ready() {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }),
    )
}
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isSdkFullyReady(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "UnifiedNativeApi_isSdkFullyReady",
        std::panic::AssertUnwindSafe(|| {
            if SDK_READY.load(Ordering::SeqCst) && crate::is_sdk_fully_ready() {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }),
    )
}

/// Route a framed query through the installed SDK AppRouter.
/// This is the primary JNI entrypoint for appRouterQuery - handles full framing.
///
/// Input frame format: [8-byte reqId][AppRouterPayload protobuf bytes]
/// Output frame format: [8-byte reqId][payload]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_appRouterQueryFramed(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    jframed: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let jframed_raw = jframed;
    // Shared slot so the panic handler can report which query path was executing.
    let query_path_for_panic = std::sync::Mutex::new(String::new());
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jframed = unsafe { jba_from(jframed_raw) };
        let raw: Vec<u8> = match env.convert_byte_array(&jframed) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

        // Parse frame: [8-byte reqId][AppRouterPayload protobuf bytes]
        if raw.len() < 9 {
            log::error!("appRouterQueryFramed: frame too short: {} bytes", raw.len());
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::InvalidInput as u32,
                "frame too short",
            )
            .into_raw();
        }

        let req_id = &raw[0..8];
        let payload = match pb::AppRouterPayload::decode(&raw[8..]) {
            Ok(v) => v,
            Err(e) => {
                log::error!("appRouterQueryFramed: invalid AppRouterPayload: {}", e);
                return frame_error_response(
                    &mut env,
                    req_id,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "invalid app router payload",
                );
            }
        };

        let path = payload.method_name;
        if path.is_empty() {
            log::error!("appRouterQueryFramed: empty path in AppRouterPayload");
            return frame_error_response(
                &mut env,
                req_id,
                helpers::JniErrorCode::InvalidInput as u32,
                "empty path",
            );
        }
        // Record query path for the panic handler before any panicking code runs.
        if let Ok(mut g) = query_path_for_panic.lock() {
            *g = path.clone();
        }

        let params = payload.args;
        log::info!(
            "appRouterQueryFramed: path={} params_len={}",
            path,
            params.len()
        );

        ensure_bootstrap();

        let router = match crate::bridge::app_router() {
            Some(r) => r,
            None => {
                log::warn!("appRouterQueryFramed: AppRouter not installed");
                return frame_error_response(
                    &mut env,
                    req_id,
                    helpers::JniErrorCode::NotReady as u32,
                    "router not ready",
                );
            }
        };

        // Build AppQuery and block on router.query
        let q = crate::bridge::AppQuery { path, params };
        let res = crate::runtime::get_runtime().block_on(router.query(q));

        if !res.success {
            let msg = res
                .error_message
                .unwrap_or_else(|| "appRouterQueryFramed failed".to_string());
            return frame_error_response(
                &mut env,
                req_id,
                helpers::JniErrorCode::ProcessingFailed as u32,
                &msg,
            );
        }

        // Return framed response: [8-byte reqId][payload]
        let mut out = Vec::with_capacity(8 + res.data.len());
        out.extend_from_slice(req_id);
        out.extend_from_slice(&res.data);

        log::debug!(
            "appRouterQueryFramed: returning {} bytes total (8-byte reqId + {} payload bytes)",
            out.len(),
            res.data.len(),
        );

        match env.byte_array_from_slice(&out) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                log::error!(
                    "appRouterQueryFramed: failed to create return byte array: {}",
                    e
                );
                error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::EncodingFailed as u32,
                    "failed to create return bytes",
                )
                .into_raw()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            let panic_msg = crate::jni::bridge_utils::panic_message(&panic);
            let qpath = query_path_for_panic
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            log::error!(
                "appRouterQueryFramed: panic captured: path={} panic={}",
                qpath,
                panic_msg
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let detail = format!(
                "panic in appRouterQueryFramed: path={} panic={}",
                qpath, panic_msg
            );
            frame_error_response(
                &mut env,
                &[0u8; 8],
                helpers::JniErrorCode::ProcessingFailed as u32,
                &detail,
            )
        }
    }
}

/// Helper to frame an error response with reqId prefix
#[cfg(target_os = "android")]
fn frame_error_response(
    env: &mut jni::JNIEnv,
    req_id: &[u8],
    code: u32,
    msg: &str,
) -> jni::sys::jbyteArray {
    let err_bytes = error_transport_bytes(code, msg);
    let mut out = Vec::with_capacity(8 + err_bytes.len());
    out.extend_from_slice(if req_id.len() >= 8 {
        &req_id[0..8]
    } else {
        &[0u8; 8]
    });
    out.extend_from_slice(&err_bytes);
    env.byte_array_from_slice(&out)
        .unwrap_or_else(|_| empty_byte_array_or_empty(env))
        .into_raw()
}

/// Invoke a method on the installed AppRouter with full framed request.
/// This is the primary JNI entrypoint for appRouterInvoke - handles full framing.
///
/// Input frame format: [AppRouterPayload protobuf bytes]
/// Output frame format: [payload] (no reqId for invoke - it's embedded in the frame)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_appRouterInvokeFramed(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    jframed: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let jframed_raw = jframed;
    // Shared slot so the panic handler can report which method was executing.
    let invoke_method_for_panic = std::sync::Mutex::new(String::new());
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jframed = unsafe { jba_from(jframed_raw) };
        let raw: Vec<u8> = match env.convert_byte_array(&jframed) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

        // Parse frame: [AppRouterPayload protobuf bytes]
        if raw.is_empty() {
            log::error!(
                "appRouterInvokeFramed: frame too short: {} bytes",
                raw.len()
            );
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::InvalidInput as u32,
                "frame too short",
            )
            .into_raw();
        }

        let payload = match pb::AppRouterPayload::decode(raw.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                let preview_len = std::cmp::min(raw.len(), 24);
                let preview_b32 =
                    crate::util::text_id::encode_base32_crockford(&raw[0..preview_len]);
                log::error!(
                "appRouterInvokeFramed: invalid AppRouterPayload (frame size: {}) preview_b32={} err={}",
                raw.len(),
                preview_b32,
                e
            );
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "invalid app router payload",
                )
                .into_raw();
            }
        };

        let method = payload.method_name;
        // Record method name for the panic handler before any panicking code runs.
        if let Ok(mut g) = invoke_method_for_panic.lock() {
            *g = method.clone();
        }
        if method.is_empty() {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::InvalidInput as u32,
                "empty method",
            )
            .into_raw();
        }

        let args = payload.args;
        log::info!(
            "appRouterInvokeFramed: method={} args_len={}",
            method,
            args.len()
        );

        ensure_bootstrap();

        // Defensive: make sure the core bilateral handler is installed before invoking
        // router methods that may route into the offline send path. Some app restarts
        // or partial initializations can leave the handler unset, which triggers the
        // core warning "Bilateral handler not installed". We attempt a minimal SDK
        // init here to idempotently install handlers without depending on full env
        // configuration. This is safe for both offline and online operations.
        #[cfg(all(target_os = "android", feature = "bluetooth"))]
        {
            if crate::bridge::bilateral_handler().is_none() {
                use crate::init::SdkConfig;
                let cfg = SdkConfig {
                    node_id: "default".to_string(),
                    storage_endpoints: Vec::new(),
                    enable_offline: true,
                };
                log::warn!("appRouterInvokeFramed: bilateral handler missing – attempting offline-only SDK init");
                match crate::init::init_dsm_sdk(&cfg) {
                    Ok(()) => {
                        log::info!("appRouterInvokeFramed: offline-only SDK init completed")
                    }
                    Err(e) => {
                        log::error!("appRouterInvokeFramed: offline-only SDK init failed: {}", e)
                    }
                }
            }
        }

        let router = match crate::bridge::app_router() {
            Some(r) => r,
            None => {
                log::warn!("appRouterInvokeFramed: AppRouter not installed");
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::NotReady as u32,
                    "router not ready",
                )
                .into_raw();
            }
        };

        let invoke = crate::bridge::AppInvoke { method, args };
        let res = crate::runtime::get_runtime().block_on(router.invoke(invoke));

        if !res.success {
            let msg = res
                .error_message
                .unwrap_or_else(|| "appRouterInvokeFramed failed".to_string());
            let err_bytes =
                error_transport_bytes(helpers::JniErrorCode::ProcessingFailed as u32, &msg);
            return env
                .byte_array_from_slice(&err_bytes)
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env))
                .into_raw();
        }

        // Return raw response bytes
        match env.byte_array_from_slice(&res.data) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                log::error!(
                    "appRouterInvokeFramed: failed to create return byte array: {}",
                    e
                );
                error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::EncodingFailed as u32,
                    "failed to create return bytes",
                )
                .into_raw()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            let panic_msg = crate::jni::bridge_utils::panic_message(&panic);
            let method_name = invoke_method_for_panic
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            log::error!(
                "appRouterInvokeFramed: panic captured: method={} panic={}",
                method_name,
                panic_msg
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let detail = format!(
                "panic in appRouterInvokeFramed: method={} panic={}",
                method_name, panic_msg
            );
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                &detail,
            )
            .into_raw()
        }
    }
}

/// Canonical offline send validation + response generation.
///
/// This is a strict, protobuf-bytes JNI surface used by the Android MessagePort
/// router for BLE bilateral flows.
///
/// NOTE: There is intentionally no hex/base64/binary-string transcoding here.
/// The caller must pass the v3 Envelope bytes verbatim.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bilateralOfflineSend(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
    jble_address: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let envelope_bytes_raw = envelope_bytes;
    let jble_address_raw = jble_address;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jba = unsafe { jba_from(envelope_bytes_raw) };
        let bytes: Vec<u8> = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                log::error!("bilateralOfflineSend: failed to read envelope bytes: {}", e);
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "invalid envelope bytes",
                )
                .into_raw();
            }
        };

        let jble_address = unsafe { jstr_from(jble_address_raw) };
        let ble_address: String = match env.get_string(&jble_address) {
            Ok(s) => s.into(),
            Err(e) => {
                log::error!("bilateralOfflineSend: failed to read bleAddress: {}", e);
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "invalid bleAddress",
                )
                .into_raw();
            }
        };

        ensure_bootstrap();

        // Route bilateral send through the SDK's global BluetoothManager directly.
        // This ensures we use the SAME contact manager that QR-code contact add writes to,
        // avoiding the dual-manager bug where core bridge has a separate handler chain.
        let raw = crate::runtime::get_runtime().block_on(async move {
        use prost::Message;
        use dsm::types::proto as gp;

        // 1. Decode envelope
        let envelope = match gp::Envelope::decode(&*bytes) {
            Ok(env) => env,
            Err(e) => {
                log::error!("[bilateralOfflineSend] envelope decode failed: {e}");
                return gp::Envelope {
                    version: 3, headers: None, message_id: vec![],
                    payload: Some(gp::envelope::Payload::Error(gp::Error {
                        code: 460, message: format!("invalid envelope: {e}"), ..Default::default()
                    })),
                }.encode_to_vec();
            }
        };

        // 2. Validate headers
        let headers = match envelope.headers.as_ref() {
            Some(h) if h.device_id.len() == 32 && !h.device_id.iter().all(|b| *b == 0) => h,
            _ => {
                return gp::Envelope {
                    version: 3, headers: None, message_id: vec![],
                    payload: Some(gp::envelope::Payload::Error(gp::Error {
                        code: 461, message: "missing or invalid headers".into(), ..Default::default()
                    })),
                }.encode_to_vec();
            }
        };

        // 3. Extract UniversalTx
        let uni_tx = match envelope.payload.as_ref() {
            Some(gp::envelope::Payload::UniversalTx(tx)) => tx,
            _ => {
                return gp::Envelope {
                    version: 3, headers: None, message_id: vec![],
                    payload: Some(gp::envelope::Payload::Error(gp::Error {
                        code: 464, message: "payload must be UniversalTx".into(), ..Default::default()
                    })),
                }.encode_to_vec();
            }
        };

        // 4. Get the BLE coordinator from BiImpl — the SINGLE source of truth
        //    CRITICAL: Must use bridge::get_ble_coordinator() (same as processBleChunk
        //    and acceptBilateralByCommitment) so that sessions created here are visible
        //    to handle_prepare_response when the accept arrives via BLE chunks.
        //    Using get_global_bluetooth_manager().frame_coordinator() would use a
        //    DIFFERENT BilateralBleHandler instance after genesis, causing session
        //    lookup failures ("NO SESSION FOUND for commitment=...").
        let coordinator = match crate::bridge::get_ble_coordinator().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("[bilateralOfflineSend] BLE coordinator not ready: {e}");
                return gp::Envelope {
                    version: 3,
                    headers: None,
                    message_id: vec![],
                    payload: Some(gp::envelope::Payload::Error(gp::Error {
                        code: 503,
                        message: format!("BLE coordinator not ready: {e}"),
                        ..Default::default()
                    })),
                }
                .encode_to_vec();
            }
        };

        // 5. Process each bilateral.prepare op through the coordinator
        let mut results: Vec<gp::OpResult> = Vec::with_capacity(uni_tx.ops.len());
        for op in uni_tx.ops.iter() {
            let op_id = op.op_id.clone();
            match op.kind.as_ref() {
                Some(gp::universal_op::Kind::Invoke(invoke))
                    if invoke.method == "bilateral.prepare" =>
                {
                    let args_bytes = invoke.args.as_ref().map(|a| a.body.clone()).unwrap_or_default();
                    match gp::BilateralPrepareRequest::decode(args_bytes.as_slice()) {
                        Ok(req) => {
                            // Build operation bytes: use supplied operation_data if present;
                            // otherwise synthesise an Operation::Transfer from intent hint fields
                            // (display amount or base-unit amount + token_id_hint + memo_hint). This removes the
                            // requirement for the frontend to perform canonical serialisation.
                            let operation_data_bytes: Vec<u8> = if !req.operation_data.is_empty() {
                                req.operation_data.clone()
                            } else if (!req.transfer_amount_display.trim().is_empty()
                                || req.transfer_amount > 0)
                                && !req.token_id_hint.is_empty()
                            {
                                // Validate counterparty_device_id early so we can use it here
                                if req.counterparty_device_id.len() != 32 {
                                    results.push(gp::OpResult {
                                        op_id, accepted: false,
                                        error: Some(gp::Error { code: 468, message: "counterparty_device_id must be 32 bytes (hint-build path)".into(), ..Default::default() }),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                                let cid_arr: [u8; 32] = req.counterparty_device_id.as_slice().try_into()
                                    .expect("length checked above");
                                let token_id = crate::handlers::wallet_routes::canonicalize_token_id(
                                    &req.token_id_hint,
                                );
                                let transfer_amount = if req.transfer_amount_display.trim().is_empty() {
                                    req.transfer_amount
                                } else {
                                    let decimals = crate::handlers::wallet_routes::resolve_token_decimals(&token_id);
                                    match crate::handlers::wallet_routes::parse_display_amount_to_base_units(
                                        &req.transfer_amount_display,
                                        decimals,
                                    ) {
                                        Ok(amount) => amount,
                                        Err(e) => {
                                            results.push(gp::OpResult {
                                                op_id,
                                                accepted: false,
                                                error: Some(gp::Error {
                                                    code: 469,
                                                    message: format!(
                                                        "invalid bilateral.prepare display amount: {e}"
                                                    ),
                                                    ..Default::default()
                                                }),
                                                ..Default::default()
                                            });
                                            continue;
                                        }
                                    }
                                };
                                // Deterministic balance anchor — same derivation as wallet.send path
                                let balance_anchor = dsm::crypto::blake3::domain_hash(
                                    "DSM/balance-anchor", &[],
                                );
                                let hint_op = dsm::types::operations::Operation::Transfer {
                                    to_device_id: cid_arr.to_vec(),
                                    amount: dsm::types::token_types::Balance::from_state(
                                        transfer_amount,
                                        *balance_anchor.as_bytes(),
                                        0,
                                    ),
                                    token_id: token_id.as_bytes().to_vec(),
                                    mode: dsm::types::operations::TransactionMode::Bilateral,
                                    nonce: vec![],
                                    verification: dsm::types::operations::VerificationType::Bilateral,
                                    pre_commit: None,
                                    recipient: cid_arr.to_vec(),
                                    to: crate::util::text_id::encode_base32_crockford(&cid_arr)
                                        .as_bytes()
                                        .to_vec(),
                                    message: req.memo_hint.clone(),
                                    signature: vec![],
                                };
                                hint_op.to_bytes()
                            } else {
                                results.push(gp::OpResult {
                                    op_id, accepted: false,
                                            error: Some(gp::Error { code: 465, message: "operation_data empty and no intent hint fields provided".into(), ..Default::default() }),
                                    ..Default::default()
                                });
                                continue;
                            };
                            if ble_address.is_empty() || req.ble_address != ble_address {
                                results.push(gp::OpResult {
                                    op_id, accepted: false,
                                    error: Some(gp::Error { code: 467, message: "ble_address mismatch or missing".into(), ..Default::default() }),
                                    ..Default::default()
                                });
                                continue;
                            }
                            if req.counterparty_device_id.len() != 32 {
                                results.push(gp::OpResult {
                                    op_id, accepted: false,
                                    error: Some(gp::Error { code: 468, message: "counterparty_device_id must be 32 bytes".into(), ..Default::default() }),
                                    ..Default::default()
                                });
                                continue;
                            }
                            // Parse operation (from hint-built bytes or caller-supplied bytes)
                            let operation = match dsm::types::operations::Operation::from_bytes(&operation_data_bytes) {
                                Ok(op) => op,
                                Err(e) => {
                                    results.push(gp::OpResult {
                                        op_id, accepted: false,
                                        error: Some(gp::Error { code: 400, message: format!("Failed to parse Operation: {e}"), ..Default::default() }),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                            };
                            let counterparty_id: [u8; 32] = match req.counterparty_device_id.as_slice().try_into() {
                                Ok(id) => id,
                                Err(_) => {
                                    log::error!("[bilateralOfflineSend] counterparty_device_id must be exactly 32 bytes, got {}", req.counterparty_device_id.len());
                                    results.push(gp::OpResult {
                                        op_id, accepted: false,
                                        error: Some(gp::Error { code: 400, message: format!("counterparty_device_id must be exactly 32 bytes, got {}", req.counterparty_device_id.len()), ..Default::default() }),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                            };

                            let transport_adapter = match crate::bridge::get_ble_transport_adapter().await {
                                Ok(adapter) => adapter,
                                Err(e) => {
                                    results.push(gp::OpResult {
                                        op_id, accepted: false,
                                        error: Some(gp::Error { code: 503, message: format!("BLE transport adapter not ready: {e}"), ..Default::default() }),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                            };

                            match transport_adapter.create_prepare_message_with_commitment(
                                counterparty_id, operation, req.validity_iterations,
                            ).await {
                                Ok((prepare_envelope, commitment_hash)) => {
                                    let chunks = match coordinator.encode_message(
                                        crate::bluetooth::BleFrameType::BilateralPrepare,
                                        &prepare_envelope,
                                    ) {
                                        Ok(chunks) => chunks,
                                        Err(e) => {
                                            transport_adapter.cancel_prepared_session_for_counterparty(counterparty_id).await;
                                            results.push(gp::OpResult {
                                                op_id, accepted: false,
                                                error: Some(gp::Error { code: 500, message: format!("Failed to frame BLE prepare payload: {e}"), ..Default::default() }),
                                                ..Default::default()
                                            });
                                            continue;
                                        }
                                    };
                                    log::info!("[bilateralOfflineSend] prepare OK: {} chunks, commitment={:02x}{:02x}{:02x}{:02x}",
                                        chunks.len(), commitment_hash[0], commitment_hash[1], commitment_hash[2], commitment_hash[3]);

                                    // Send chunks via BLE. Prime the transport first so the peer can reconnect
                                    // if the GATT session dropped after pairing, then send the actual chunks.
                                    let ble_send_ok;
                                    #[cfg(not(all(target_os = "android", feature = "jni")))]
                                    { ble_send_ok = true; }
                                    #[cfg(all(target_os = "android", feature = "jni"))]
                                    {
                                        use crate::jni::jni_common::get_java_vm_borrowed;
                                        ble_send_ok = if let Some(vm) = get_java_vm_borrowed() {
                                            if let Ok(mut jni_env) = vm.attach_current_thread() {
                                                match crate::jni::unified_protobuf_bridge::send_ble_chunks_via_unified(
                                                    &mut jni_env, &ble_address, &chunks,
                                                ) {
                                                    Ok(sent) => sent,
                                                    Err(e) => {
                                                        log::error!("[bilateralOfflineSend] BLE send error: {e}");
                                                        false
                                                    }
                                                }
                                            } else { false }
                                        } else { false };
                                    }

                                    if !ble_send_ok {
                                        // BLE send failed — cancel the Prepared session so the next
                                        // attempt is not blocked by this stale session.
                                        log::warn!(
                                            "[bilateralOfflineSend] BLE send failed for commitment={:02x}{:02x}{:02x}{:02x} — cancelling prepared session",
                                            commitment_hash[0], commitment_hash[1], commitment_hash[2], commitment_hash[3]
                                        );
                                        transport_adapter.cancel_prepared_session_for_counterparty(counterparty_id).await;
                                        results.push(gp::OpResult {
                                            op_id, accepted: false,
                                            error: Some(gp::Error {
                                                code: 503,
                                                message: "BLE send failed — peer unreachable, session cancelled; retry is safe".into(),
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        });
                                        continue;
                                    }

                                    let resp = gp::BilateralPrepareResponse {
                                        commitment_hash: Some(gp::Hash32 { v: commitment_hash.to_vec() }),
                                        expires_iterations: req.validity_iterations,
                                        ..Default::default()
                                    };
                                    results.push(gp::OpResult {
                                        op_id, accepted: true,
                                        post_state_hash: Some(gp::Hash32 { v: vec![0u8; 32] }),
                                        result: Some(gp::ResultPack {
                                            schema_hash: Some(gp::Hash32 { v: vec![0u8; 32] }),
                                            codec: gp::Codec::Proto as i32,
                                            body: resp.encode_to_vec(),
                                        }),
                                        error: None,
                                    });
                                }
                                Err(e) => {
                                    log::error!("[bilateralOfflineSend] prepare failed: {e}");
                                    results.push(gp::OpResult {
                                        op_id, accepted: false,
                                        error: Some(gp::Error { code: 500, message: format!("Failed to create bilateral prepare: {e}"), ..Default::default() }),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            results.push(gp::OpResult {
                                op_id, accepted: false,
                                error: Some(gp::Error { code: 400, message: format!("Failed to decode BilateralPrepareRequest: {e}"), ..Default::default() }),
                                ..Default::default()
                            });
                        }
                    }
                }
                _ => {
                    results.push(gp::OpResult {
                        op_id, accepted: false,
                        error: Some(gp::Error { code: 501, message: "unsupported op kind for offline send".into(), ..Default::default() }),
                        ..Default::default()
                    });
                }
            }
        }

        let response_env = gp::Envelope {
            version: 3,
            headers: Some(gp::Headers {
                device_id: headers.device_id.clone(),
                chain_tip: headers.chain_tip.clone(),
                genesis_hash: headers.genesis_hash.clone(),
                seq: headers.seq,
            }),
            message_id: envelope.message_id.clone(),
            payload: Some(gp::envelope::Payload::UniversalRx(gp::UniversalRx { results })),
        };
        response_env.encode_to_vec()
    });

        // Prepend Envelope v3 framing byte so all return paths are [0x03][proto].
        // The AppRouter path does this via pack_envelope_ok; the bilateral BLE
        // direct path previously delegated to Kotlin BridgeRouterHandler, but
        // content inspection (adding a protocol byte) must live in Rust.
        let mut framed = Vec::with_capacity(1 + raw.len());
        framed.push(0x03);
        framed.extend_from_slice(&raw);

        match env.byte_array_from_slice(&framed) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                log::error!(
                    "bilateralOfflineSend: failed to allocate return bytes: {}",
                    e
                );
                error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::EncodingFailed as u32,
                    "failed to allocate return bytes",
                )
                .into_raw()
            }
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "bilateralOfflineSend: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in bilateralOfflineSend",
            )
            .into_raw()
        }
    }
}

// -------------------- BLE helpers (non-envelope) --------------------

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bleNotifyConnectionState(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    _jaddress: jni::sys::jstring,
    _connected: jni::sys::jboolean,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "bleNotifyConnectionState",
        std::panic::AssertUnwindSafe(|| {
            // No-op: the app may call this to inform native layer of BLE state.
            // When BLE coordinator is not compiled in, silently ignore.
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_nowTick(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jlong {
    crate::jni::bridge_utils::jni_catch_unwind_jlong(
        "nowTick",
        std::panic::AssertUnwindSafe(|| {
            // Return current logical tick counter (deterministic time)
            let (_, tick) = dt::peek();
            tick as jni::sys::jlong
        }),
    )
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

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_forceBleCoordinatorInit(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "forceBleCoordinatorInit",
        std::panic::AssertUnwindSafe(|| {
            let _env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            // Attempt to get the coordinator; if present, return true. We do not attempt
            // to construct or inject a coordinator here — injection is performed by
            // create_genesis when appropriate. This keeps the function safe and idempotent.
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
fn ble_frame_type_from_i32(v: i32) -> pb::BleFrameType {
    pb::BleFrameType::try_from(v).unwrap_or(pb::BleFrameType::Unspecified)
}

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

#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub(crate) fn send_ble_chunks_via_unified<'a>(
    env: &mut JNIEnv<'a>,
    device_address: &str,
    chunks: &[Vec<u8>],
) -> Result<bool, String> {
    let addr_j = env
        .new_string(device_address)
        .map_err(|e| format!("new_string failed: {e}"))?;
    let chunks_arr = build_chunk_array(env, chunks)?;

    let unified_cls =
        crate::jni::jni_common::find_class_with_app_loader(env, "com/dsm/wallet/bridge/Unified")?;
    let addr_obj = JObject::from(addr_j);
    let chunks_obj = JObject::from(chunks_arr);
    let args = [JValue::Object(&addr_obj), JValue::Object(&chunks_obj)];

    let result = env
        .call_static_method(
            &unified_cls,
            "requestGattWriteChunks",
            "(Ljava/lang/String;[[B)Z",
            &args,
        )
        .map_err(|e| format!("call_static_method requestGattWriteChunks failed: {e}"))?;
    Ok(result.z().unwrap_or(false))
}

fn strip_envelope_v3_framing(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0x03) {
        &bytes[1..]
    } else {
        bytes
    }
}

fn detect_ble_frame_type_from_bytes(bytes: &[u8]) -> i32 {
    let raw = strip_envelope_v3_framing(bytes);

    if let Ok(env) = pb::Envelope::decode(raw) {
        return match env.payload {
            Some(pb::envelope::Payload::BilateralPrepareResponse(_)) => {
                pb::BleFrameType::BilateralPrepareResponse as i32
            }
            Some(pb::envelope::Payload::BilateralPrepareReject(_)) => {
                pb::BleFrameType::BilateralPrepareReject as i32
            }
            Some(pb::envelope::Payload::BilateralCommitResponse(_)) => {
                pb::BleFrameType::BilateralCommitResponse as i32
            }
            Some(pb::envelope::Payload::UniversalTx(tx)) => {
                if let Some(op) = tx.ops.first() {
                    if let Some(pb::universal_op::Kind::Invoke(inv)) = op.kind.as_ref() {
                        if inv.method == "bilateral.prepare" {
                            return pb::BleFrameType::BilateralPrepare as i32;
                        }
                        if inv.method == "bilateral.confirm" {
                            return pb::BleFrameType::BilateralConfirm as i32;
                        }
                        if inv.method == "bilateral.commit" {
                            return pb::BleFrameType::BilateralCommit as i32;
                        }
                    }
                }
                pb::BleFrameType::Unspecified as i32
            }
            _ => pb::BleFrameType::Unspecified as i32,
        };
    }

    if let Ok(env) = pb::BilateralMessageEnvelope::decode(raw) {
        if let Some(msg) = env.msg {
            return match msg {
                pb::bilateral_message_envelope::Msg::ChainHistoryRequest(_) => {
                    pb::BleFrameType::ChainHistoryRequest as i32
                }
                pb::bilateral_message_envelope::Msg::ChainHistoryResponse(_) => {
                    pb::BleFrameType::ChainHistoryResponse as i32
                }
                pb::bilateral_message_envelope::Msg::ReconciliationRequest(_) => {
                    pb::BleFrameType::ReconciliationRequest as i32
                }
                pb::bilateral_message_envelope::Msg::ReconciliationResponse(_) => {
                    pb::BleFrameType::ReconciliationResponse as i32
                }
                _ => pb::BleFrameType::Unspecified as i32,
            };
        }
    }

    pb::BleFrameType::Unspecified as i32
}

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

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processBleChunk(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_address: jni::sys::jstring,
    chunk_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let env_raw = env;
    let device_address_raw = device_address;
    let chunk_bytes_raw = chunk_bytes;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = match unsafe { env_from(env_raw) } {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };
        let jaddr = unsafe { jstr_from(device_address_raw) };
        let addr: String = match env.get_string(&jaddr) {
            Ok(s) => s.into(),
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid device address: {e}"),
                )
                .into_raw();
            }
        };

        let jba = unsafe { jba_from(chunk_bytes_raw) };
        let bytes = match env.convert_byte_array(&jba) {
            Ok(v) => v,
            Err(e) => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    &format!("invalid chunk bytes: {e}"),
                )
                .into_raw();
            }
        };

        if bytes.is_empty() {
            return empty_byte_array_or_empty(&mut env).into_raw();
        }

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
        let adapter = match crate::runtime::get_runtime()
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

        let result: Result<Option<Vec<u8>>, dsm::types::error::DsmError> =
            crate::runtime::get_runtime().block_on(async {
                match coord.ingest_chunk(&bytes).await? {
                    crate::bluetooth::FrameIngressResult::NeedMoreChunks => Ok(None),
                    crate::bluetooth::FrameIngressResult::ProtocolControl(_) => Ok(None),
                    crate::bluetooth::FrameIngressResult::MessageComplete { message } => {
                        let outbound = adapter
                            .on_transport_message(crate::bluetooth::TransportInboundMessage {
                                peer_address: addr.clone(),
                                frame_type: message.frame_type,
                                payload: message.payload,
                            })
                            .await?;
                        Ok(outbound.into_iter().next().map(|item| item.payload))
                    }
                }
            });

        match result {
            Ok(Some(payload)) => env
                .byte_array_from_slice(&payload)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw()),
            Ok(None) => empty_byte_array_or_empty(&mut env).into_raw(),
            Err(e) => error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                &format!("processBleChunk failed: {e}"),
            )
            .into_raw(),
        }
    })) {
        Ok(result) => result,
        Err(panic) => {
            log::error!(
                "processBleChunk: panic captured: {}",
                crate::jni::bridge_utils::panic_message(&panic)
            );
            let mut env = match unsafe { env_from(env_raw) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                "panic in processBleChunk",
            )
            .into_raw()
        }
    }
}

/// Returns `true` if `payload_bytes` is a framed Envelope v3 (`0x03` prefix),
/// meaning the BLE write expects a protocol acknowledgment before the transaction
/// is marked complete. Kotlin MUST NOT inspect `payload[0]` directly.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_requiresBleAck(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    payload_bytes: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "requiresBleAck",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return 0,
            };
            let jba = unsafe { jba_from(payload_bytes) };
            match env.convert_byte_array(&jba) {
                Ok(bytes) => {
                    if bytes.first() == Some(&0x03) {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => 0,
            }
        }),
    )
}

/// Unified BLE incoming data router — Kotlin MUST call this instead of inspecting
/// `data[0]` to decide routing. Returns a serialized `BleIncomingDataResponse`
/// (not Envelope v3 framed) whose `response_chunks` field contains zero or more
/// pre-chunked byte arrays to write back verbatim over the BLE characteristic.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processIncomingBleData(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_address: jni::sys::jstring,
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

        if bytes.is_empty() {
            let out = crate::generated::BleIncomingDataResponse::default();
            let encoded = prost::Message::encode_to_vec(&out);
            return env
                .byte_array_from_slice(&encoded)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw());
        }

        // Data routing: 0x03 prefix = complete Envelope v3; anything else = BLE chunk.
        let is_chunk = bytes.first() != Some(&0x03);
        let maybe_response: Option<Vec<crate::bluetooth::TransportOutbound>> = if is_chunk {
            let coord = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_coordinator())
            {
                Ok(c) => c,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        &format!("processIncomingBleData: BLE coordinator not ready: {e}"),
                    )
                    .into_raw();
                }
            };
            let adapter = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_transport_adapter())
            {
                Ok(adapter) => adapter,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        &format!("processIncomingBleData: BLE transport adapter not ready: {e}"),
                    )
                    .into_raw();
                }
            };
            let inbound_result: Result<
                Option<Vec<crate::bluetooth::TransportOutbound>>,
                dsm::types::error::DsmError,
            > = crate::runtime::get_runtime().block_on(async {
                match coord.ingest_chunk(&bytes).await? {
                    crate::bluetooth::FrameIngressResult::NeedMoreChunks => {
                        Ok::<
                            Option<Vec<crate::bluetooth::TransportOutbound>>,
                            dsm::types::error::DsmError,
                        >(None)
                    }
                    crate::bluetooth::FrameIngressResult::ProtocolControl(_) => {
                        Ok::<
                            Option<Vec<crate::bluetooth::TransportOutbound>>,
                            dsm::types::error::DsmError,
                        >(None)
                    }
                    crate::bluetooth::FrameIngressResult::MessageComplete { message } => {
                        let outbound = adapter
                            .on_transport_message(crate::bluetooth::TransportInboundMessage {
                                peer_address: addr.clone(),
                                frame_type: message.frame_type,
                                payload: message.payload,
                            })
                            .await?;
                        if outbound.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(outbound))
                        }
                    }
                }
            });
            match inbound_result {
                Ok(v) => v,
                Err(e) => {
                    log::error!(
                        "processIncomingBleData: bilateral handler error for {}: {} — response lost (chunks=0 to Kotlin)",
                        addr, e
                    );
                    None
                }
            }
        } else {
            process_envelope_v3_impl(&bytes, Some(&addr))
                .ok()
                .filter(|b| !b.is_empty())
                .map(|payload| {
                    vec![crate::bluetooth::TransportOutbound::new(
                        ble_frame_type_from_i32(detect_ble_frame_type_from_bytes(&payload)),
                        payload,
                    )]
                })
        };

        let mut response_chunks: Vec<Vec<u8>> = Vec::new();
        let mut use_reliable_write = false;

        if let Some(outbounds) = maybe_response {
            for outbound in outbounds {
                if outbound.payload.is_empty() {
                    continue;
                }
                let frame_type = outbound.frame_type as i32;
                let needs_chunking = frame_type
                    == crate::generated::BleFrameType::BilateralPrepareReject as i32
                    || frame_type == crate::generated::BleFrameType::BilateralCommit as i32
                    || frame_type == crate::generated::BleFrameType::BilateralCommitResponse as i32
                    || frame_type == crate::generated::BleFrameType::BilateralConfirm as i32;

                if needs_chunking {
                    use_reliable_write = true;
                    match crate::runtime::get_runtime()
                        .block_on(crate::bridge::get_ble_coordinator())
                    {
                        Ok(coord) => {
                            match coord.encode_message(outbound.frame_type, &outbound.payload) {
                                Ok(chunks) => response_chunks.extend(chunks),
                                Err(e) => {
                                    log::error!(
                                        "processIncomingBleData: encode_message failed: {e}"
                                    );
                                    response_chunks.push(outbound.payload);
                                }
                            }
                        }
                        Err(_) => {
                            // Coordinator unavailable — pass through unframed
                            response_chunks.push(outbound.payload);
                        }
                    }
                } else {
                    response_chunks.push(outbound.payload);
                }
            }
        }

        let out = crate::generated::BleIncomingDataResponse {
            response_chunks,
            use_reliable_write,
        };
        let encoded = prost::Message::encode_to_vec(&out);
        env.byte_array_from_slice(&encoded)
            .map(|a| a.into_raw())
            .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
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

/// Extract `success` flag from a `BleGattIdentityReadResult` proto.
/// Returns 1 if success, 0 if failure or decode error.
/// Kotlin uses this instead of proto-java codegen (which is not available).
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_identityReadResultGetSuccess(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "identityReadResultGetSuccess",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return 0,
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            let resp: crate::generated::BleGattIdentityReadResult =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => return 0,
                };
            if resp.success {
                1
            } else {
                0
            }
        }),
    )
}

/// Extract `write_back_envelope` from a `BleGattIdentityReadResult` proto.
/// Returns the raw envelope bytes, or empty array on decode error / no envelope.
/// Kotlin uses this instead of proto-java codegen (which is not available).
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_identityReadResultExtractWriteBack(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "identityReadResultExtractWriteBack",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return std::ptr::null_mut(),
            };
            let resp: crate::generated::BleGattIdentityReadResult =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => return std::ptr::null_mut(),
                };
            if resp.write_back_envelope.is_empty() {
                return std::ptr::null_mut();
            }
            match env.byte_array_from_slice(&resp.write_back_envelope) {
                Ok(out) => out.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }),
    )
}

/// Extract `peer_device_id` from a `BleGattIdentityReadResult` proto.
/// Returns the 32-byte device ID, or empty array on decode error.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_identityReadResultExtractPeerDeviceId(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "identityReadResultExtractPeerDeviceId",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return std::ptr::null_mut(),
            };
            let resp: crate::generated::BleGattIdentityReadResult =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => return std::ptr::null_mut(),
                };
            if resp.peer_device_id.is_empty() {
                return std::ptr::null_mut();
            }
            match env.byte_array_from_slice(&resp.peer_device_id) {
                Ok(out) => out.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }),
    )
}

/// Extract `peer_genesis_hash` from a `BleGattIdentityReadResult` proto.
/// Returns the 32-byte genesis hash, or empty array on decode error.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_identityReadResultExtractPeerGenesisHash(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    response_proto: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "identityReadResultExtractPeerGenesisHash",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(response_proto) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return std::ptr::null_mut(),
            };
            let resp: crate::generated::BleGattIdentityReadResult =
                match prost::Message::decode(bytes.as_slice()) {
                    Ok(r) => r,
                    Err(_) => return std::ptr::null_mut(),
                };
            if resp.peer_genesis_hash.is_empty() {
                return std::ptr::null_mut();
            }
            match env.byte_array_from_slice(&resp.peer_genesis_hash) {
                Ok(out) => out.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }),
    )
}

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_chunkEnvelopeForBle(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
    frame_type: jni::sys::jint,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "chunkEnvelopeForBle",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(envelope_bytes) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => {
                    return empty_byte_array_2d(&mut env).into_raw();
                }
            };
            let raw_bytes = strip_envelope_v3_framing(&bytes);

            let coord = match crate::runtime::get_runtime()
                .block_on(crate::bridge::get_ble_coordinator())
            {
                Ok(c) => c,
                Err(_) => {
                    return empty_byte_array_2d(&mut env).into_raw();
                }
            };

            let ft = ble_frame_type_from_i32(frame_type as i32);
            let chunks = match coord.chunk_message(ft, raw_bytes) {
                Ok(c) => c,
                Err(_) => {
                    return empty_byte_array_2d(&mut env).into_raw();
                }
            };

            match build_chunk_array(&mut env, &chunks) {
                Ok(arr) => arr.into_raw(),
                Err(_) => empty_byte_array_2d(&mut env).into_raw(),
            }
        }),
    )
}

#[cfg(test)]
mod unified_protobuf_bridge_tests {
    use super::{detect_ble_frame_type_from_bytes, strip_envelope_v3_framing};
    use crate::generated as pb;
    use prost::Message;

    fn build_bilateral_confirm_envelope() -> Vec<u8> {
        let envelope = pb::Envelope {
            version: 3,
            headers: Some(pb::Headers {
                device_id: vec![1; 32],
                chain_tip: vec![2; 32],
                genesis_hash: vec![3; 32],
                seq: 0,
            }),
            message_id: vec![4; 16],
            payload: Some(pb::envelope::Payload::UniversalTx(pb::UniversalTx {
                ops: vec![pb::UniversalOp {
                    op_id: Some(pb::Hash32 { v: vec![5; 32] }),
                    actor: vec![1; 32],
                    genesis_hash: vec![3; 32],
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
}

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_chunkEnvelopeForBleWithCounterparty(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
    frame_type: jni::sys::jint,
    _counterparty_device_id: jni::sys::jbyteArray,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "chunkEnvelopeForBleWithCounterparty",
        std::panic::AssertUnwindSafe(|| {
            Java_com_dsm_wallet_bridge_UnifiedNativeApi_chunkEnvelopeForBle(
                env,
                _clazz,
                envelope_bytes,
                frame_type,
            )
        }),
    )
}

#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_sendBleChunks(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_address: jni::sys::jstring,
    chunks: jni::sys::jobjectArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "sendBleChunks",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            let jaddr = unsafe { jstr_from(device_address) };
            let addr: String = match env.get_string(&jaddr) {
                Ok(s) => s.into(),
                Err(_) => return jni::sys::JNI_FALSE,
            };

            // Convert Java byte[][] to Vec<Vec<u8>>
            let arr = unsafe { jni::objects::JObjectArray::from_raw(chunks) };
            let len = env.get_array_length(&arr).unwrap_or(0);
            let mut out: Vec<Vec<u8>> = Vec::with_capacity(len as usize);
            for i in 0..len {
                let elem = match env.get_object_array_element(&arr, i) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let jba = JByteArray::from(elem);
                if let Ok(bytes) = env.convert_byte_array(jba) {
                    out.push(bytes);
                }
            }

            match send_ble_chunks_via_unified(&mut env, &addr, &out) {
                Ok(true) => jni::sys::JNI_TRUE,
                _ => jni::sys::JNI_FALSE,
            }
        }),
    )
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
            Err(e) => {
                eprintln!("create_prepare_accept_envelope_with_counterparty failed: {e}");
                crate::runtime::get_runtime().block_on(async {
                    let _ = transport_adapter
                        .fail_session_by_commitment(
                            ch,
                            "The connection was interrupted before the other device could respond.",
                        )
                        .await;
                });
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("acceptBilateralByCommitment failed: {e}"),
                )
                .into_raw();
            }
        };

        let sender_ble_address = crate::runtime::get_runtime()
            .block_on(transport_adapter.sender_ble_address_for_commitment(ch));

        let mut addr = sender_ble_address;
        if addr.is_none() {
            if let Ok(Some(contact)) = get_contact_by_device_id(&counterparty_device_id) {
                addr = contact.ble_address;
            }
        }

        let addr = match addr {
            Some(a) if !a.is_empty() => a,
            _ => {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    "sender BLE address unavailable for accept",
                )
                .into_raw();
            }
        };

        let chunks = match coord
            .encode_message(pb::BleFrameType::BilateralPrepareResponse, &envelope_bytes)
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("chunking accept envelope failed: {e}");
                crate::runtime::get_runtime().block_on(async {
                    let _ = transport_adapter
                        .fail_session_by_commitment(
                            ch,
                            "Transfer failed due to a protocol error. Please try again.",
                        )
                        .await;
                });
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("chunking accept envelope failed: {e}"),
                )
                .into_raw();
            }
        };

        match send_ble_chunks_via_unified(&mut env, &addr, &chunks) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("requestGattWriteChunks returned false — BLE send incomplete");
                crate::runtime::get_runtime().block_on(async {
                    let _ = transport_adapter
                        .fail_session_by_commitment(
                            ch,
                            "BLE send failed. Please move closer and try again.",
                        )
                        .await;
                });
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    "requestGattWriteChunks returned false",
                )
                .into_raw();
            }
            Err(e) => {
                eprintln!("BLE send failed: {e}");
                crate::runtime::get_runtime().block_on(async {
                    let _ = transport_adapter
                        .fail_session_by_commitment(
                            ch,
                            "BLE send failed. Please move closer and try again.",
                        )
                        .await;
                });
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

            let sender_ble_address = crate::runtime::get_runtime()
                .block_on(transport_adapter.sender_ble_address_for_commitment(ch));

            let mut addr = sender_ble_address;
            if addr.is_none() {
                let counterparty = crate::runtime::get_runtime()
                    .block_on(async { transport_adapter.counterparty_for_commitment(ch).await });
                if let Some(dev_id) = counterparty {
                    if let Ok(Some(contact)) = get_contact_by_device_id(&dev_id) {
                        addr = contact.ble_address;
                    }
                }
            }

            let addr = match addr {
                Some(a) if !a.is_empty() => a,
                _ => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        "sender BLE address unavailable for reject",
                    )
                    .into_raw();
                }
            };

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

            match send_ble_chunks_via_unified(&mut env, &addr, &chunks) {
                Ok(true) => {}
                Ok(false) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        "requestGattWriteChunks returned false",
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

/// Extract device_id and genesis_hash from a GenesisCreated envelope
/// Returns byte array: [device_id 32 bytes][genesis_hash 32 bytes] or empty on error
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_native_DsmNative_extractGenesisIdentity(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "DsmNative_extractGenesisIdentity",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(envelope_bytes) };
            let bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return empty_byte_array_or_empty(&mut env).into_raw(),
            };

            // Require FramedEnvelopeV3 (0x03 + Envelope). Any other framing is rejected.
            let mut raw: &[u8] = &bytes[..];
            if !raw.is_empty() {
                let lead = raw[0];
                if lead == 0x03 {
                    log::info!(
                        "extractGenesisIdentity: detected framing byte 0x{:02x}",
                        lead
                    );
                    raw = &raw[1..];
                } else {
                    log::error!(
                        "extractGenesisIdentity: invalid framing byte 0x{:02x}",
                        lead
                    );
                    return empty_byte_array_or_empty(&mut env).into_raw();
                }
            }
            if raw.is_empty() {
                log::error!("extractGenesisIdentity: empty payload after unframing");
                return empty_byte_array_or_empty(&mut env).into_raw();
            }

            let envelope = match pb::Envelope::decode(raw) {
                Ok(e) => e,
                Err(e) => {
                    log::error!(
                        "extractGenesisIdentity: failed to decode envelope: {} (len={})",
                        e,
                        raw.len()
                    );
                    return empty_byte_array_or_empty(&mut env).into_raw();
                }
            };

            log::info!(
                "extractGenesisIdentity: envelope version={}, has_payload={}",
                envelope.version,
                envelope.payload.is_some()
            );

            // The genesis envelope is canonical as:
            // - payload: GenesisCreatedResponse(GenesisCreated)
            // - headers: Headers { device_id, genesis_hash, ... }
            // But we accept either source to be resilient to older/newer envelope variants.
            let payload = match envelope.payload {
                Some(p) => p,
                None => return empty_byte_array_or_empty(&mut env).into_raw(),
            };

            let (payload_device_id, payload_genesis_hash) = match payload {
                pb::envelope::Payload::GenesisCreatedResponse(gc) => {
                    let device_id = gc.device_id;
                    let genesis_hash = match gc.genesis_hash {
                        Some(h) => h.v,
                        None => Vec::new(),
                    };
                    (device_id, genesis_hash)
                }
                other => {
                    log::error!(
                        "extractGenesisIdentity: unexpected payload type: {:?}",
                        other
                    );
                    (Vec::new(), Vec::new())
                }
            };

            let (headers_device_id, headers_genesis_hash) = match envelope.headers {
                Some(h) => (h.device_id, h.genesis_hash),
                None => (Vec::new(), Vec::new()),
            };

            let device_id = if payload_device_id.len() == 32 {
                payload_device_id
            } else {
                headers_device_id
            };

            let genesis_hash = if payload_genesis_hash.len() == 32 {
                payload_genesis_hash
            } else {
                headers_genesis_hash
            };

            if device_id.len() != 32 || genesis_hash.len() != 32 {
                return empty_byte_array_or_empty(&mut env).into_raw();
            }

            let mut result = Vec::with_capacity(64);
            result.extend_from_slice(&device_id);
            result.extend_from_slice(&genesis_hash);

            match env.byte_array_from_slice(&result) {
                Ok(arr) => arr.into_raw(),
                Err(_) => empty_byte_array_or_empty(&mut env).into_raw(),
            }
        }),
    )
}

// Telemetry accessor (simple 4-counter pack) for diagnostics
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_native_DsmNative_getBilateralPollTelemetry(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getBilateralPollTelemetry",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            use prost::Message;
            let pack = pb::ResultPack {
                schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                codec: pb::Codec::Proto as i32,
                body: vec![
                    (POLL_ATTEMPTS_STARTED.load(Ordering::SeqCst) as u64)
                        .to_le_bytes()
                        .as_slice(),
                    (POLL_ATTEMPTS_SUCCESS.load(Ordering::SeqCst) as u64)
                        .to_le_bytes()
                        .as_slice(),
                    (POLL_ATTEMPTS_TIMEOUT.load(Ordering::SeqCst) as u64)
                        .to_le_bytes()
                        .as_slice(),
                    (POLL_TOTAL_ITERATIONS.load(Ordering::SeqCst) as u64)
                        .to_le_bytes()
                        .as_slice(),
                ]
                .concat(),
            };
            let mut out = Vec::new();
            let _ = pack.encode(&mut out);
            match env.byte_array_from_slice(&out) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!(
                        "getBilateralPollTelemetry: failed to allocate return bytes: {}",
                        e
                    );
                    error_byte_array(
                        &mut env,
                        crate::jni::helpers::JniErrorCode::EncodingFailed as u32,
                        "failed to allocate telemetry bytes",
                    )
                    .into_raw()
                }
            }
        }),
    )
}

/* =============================================================================
MPC shim (matches handler call-site; stays fail-closed until enabled)
============================================================================= */

pub fn create_genesis_mpc<A, B, C>(
    _locale: &A,
    _network_id: &B,
    _entropy: &C,
) -> Result<pb::Envelope, String> {
    Err("MPC-over-JNI is disabled in Unified Bridge".to_string())
}

/* =============================================================================
Preview hooks expected by sdk/preview.rs (no Option in return type)
============================================================================= */

pub trait PostStatePredictor: Send + Sync + 'static {
    fn predict(&self, pre: &[u8], program_id: &str, method: &str, args: &[u8]) -> Vec<u8>;
}

impl<T: ?Sized + PostStatePredictor> PostStatePredictor for Arc<T> {
    fn predict(&self, pre: &[u8], program_id: &str, method: &str, args: &[u8]) -> Vec<u8> {
        (**self).predict(pre, program_id, method, args)
    }
}

pub fn register_post_state_predictor(_p: Arc<dyn PostStatePredictor>) -> bool {
    true
}

/* =============================================================================
Unified init/status + header fetch (stable surface for Activity gating)
============================================================================= */

/// Record peer identity mapping: address -> device_id (last 32 bytes of identity payload)
/// identity can be 64 bytes (genesis_hash||device_id) or 32 bytes (device_id only)
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_recordPeerIdentity(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    address: jni::sys::jstring,
    identity: jni::sys::jbyteArray,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "recordPeerIdentity",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return,
            };
            let jaddr = unsafe { jstr_from(address) };
            let addr: String = match env.get_string(&jaddr) {
                Ok(s) => s.into(),
                Err(_) => return,
            };
            let jba = unsafe { jba_from(identity) };
            let id_bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return,
            };
            let dev_key: [u8; 32] = if id_bytes.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&id_bytes[id_bytes.len() - 32..]);
                key
            } else {
                return;
            };
            if !addr.is_empty() {
                if let Ok(mut map) = DEVICE_ID_TO_ADDR.try_lock() {
                    map.insert(dev_key, addr);
                } else {
                    log::warn!("DEVICE_ID_TO_ADDR lock contention, skipping");
                }
            }
        }),
    )
}

/// Resolve current BLE address for a given raw 32-byte device ID.
/// Returns UTF-8 BLE MAC address bytes or empty array.
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_resolveBleAddressForDeviceIdBin(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_id: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "resolveBleAddressForDeviceIdBin",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jba = unsafe { jba_from(device_id) };
            let id_bytes = match env.convert_byte_array(&jba) {
                Ok(v) => v,
                Err(_) => return empty_byte_array_or_empty(&mut env).into_raw(),
            };
            if id_bytes.len() != 32 {
                return empty_byte_array_or_empty(&mut env).into_raw();
            }
            let mut dev_key = [0u8; 32];
            dev_key.copy_from_slice(&id_bytes);

            let addr = DEVICE_ID_TO_ADDR
                .try_lock()
                .ok()
                .and_then(|map| map.get(&dev_key).cloned())
                .unwrap_or_default();

            // Cache miss: resolve from the persisted contact record and repopulate the map.
            let final_addr = if addr.is_empty() {
                match crate::storage::client_db::get_contact_by_device_id(&dev_key) {
                    Ok(Some(contact)) if contact.ble_address.is_some() => {
                        let resolved = contact.ble_address.expect("guarded by is_some()");
                        if let Ok(mut map) = DEVICE_ID_TO_ADDR.try_lock() {
                            map.insert(dev_key, resolved.clone());
                        } else {
                            log::warn!("DEVICE_ID_TO_ADDR lock contention, skipping cache insert");
                        }
                        log::info!(
                            "resolveBleAddressForDeviceIdBin: hydrated persisted BLE address {:02x}{:02x}... -> {}",
                            dev_key[0], dev_key[1], resolved
                        );
                        resolved
                    }
                    _ => String::new(),
                }
            } else {
                addr
            };

            let addr_bytes = final_addr.as_bytes();
            env.byte_array_from_slice(addr_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
        }),
    )
}

/// Retrieve 32-byte local chain tip for a remote device (by BLE MAC or device ID hex).
#[no_mangle]
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getLocalChainTipBin(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_address: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getLocalChainTipBin",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jaddr = unsafe { jstr_from(device_address) };
            let addr: String = match env.get_string(&jaddr) {
                Ok(s) => s.into(),
                Err(_) => String::new(),
            };

            let addr_lc = addr.to_lowercase();
            let mut dev_bytes: Option<[u8; 32]> = None;

            if addr_lc.len() == 64 && addr_lc.chars().all(|c| c.is_ascii_hexdigit()) {
                // 64-char hex device ID → parse to bytes at boundary
                dev_bytes = parse_hex_32(&addr_lc);
            } else if addr_lc.contains(':') || addr_lc.contains('-') || addr_lc.len() <= 17 {
                // Treat as BLE MAC address; reverse-lookup device ID bytes
                if let Ok(map) = DEVICE_ID_TO_ADDR.try_lock() {
                    for (dev_key, mac) in map.iter() {
                        if mac.eq_ignore_ascii_case(&addr_lc) {
                            dev_bytes = Some(*dev_key);
                            break;
                        }
                    }
                } else {
                    log::warn!("DEVICE_ID_TO_ADDR lock contention, skipping reverse lookup");
                }
            }

            let dev_bytes = dev_bytes.unwrap_or([0u8; 32]);

            let tip = get_contact_chain_tip(&dev_bytes);
            let out = tip.unwrap_or([0u8; 32]);
            env.byte_array_from_slice(&out)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
        }),
    )
}

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

/// Initialize SDK context with device identity
/// Returns true on success, false on failure
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_initializeSdkContext(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    device_id: jni::sys::jbyteArray,
    genesis_hash: jni::sys::jbyteArray,
    entropy: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "initializeSdkContext",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return jni::sys::JNI_FALSE,
            };
            let jdev = unsafe { jba_from(device_id) };
            let jgen = unsafe { jba_from(genesis_hash) };
            let jent = unsafe { jba_from(entropy) };

            let dev_bytes = match env.convert_byte_array(&jdev) {
                Ok(v) => v,
                Err(_) => return 0, // false
            };

            let gen_bytes = match env.convert_byte_array(&jgen) {
                Ok(v) => v,
                Err(_) => return 0, // false
            };

            let ent_bytes = match env.convert_byte_array(&jent) {
                Ok(v) => v,
                Err(_) => return 0, // false
            };

            // Validate input lengths
            if dev_bytes.len() != 32 || gen_bytes.len() != 32 {
                log::error!(
                    "initializeSdkContext: invalid input lengths - device_id: {}, genesis_hash: {}",
                    dev_bytes.len(),
                    gen_bytes.len()
                );
                return 0; // false
            }

            match crate::initialize_sdk_context(dev_bytes.clone(), gen_bytes.clone(), ent_bytes) {
                Ok(_) => {
                    log::info!("initializeSdkContext: SDK context initialized successfully");

                    // Run device performance calibration for dynamic timeouts
                    // This must happen after SDK context is ready but before BLE operations
                    let runtime = crate::runtime::get_runtime();
                    let calibration_result = runtime.block_on(async {
                        dsm::utils::timeout::calibrate_device_performance().await
                    });

                    match calibration_result {
                        Ok(calibration) => {
                            log::info!(
                        "initializeSdkContext: Device calibration completed - performance_factor: {:.3}",
                        calibration.performance_factor
                    );

                            // Beta Instruction: Warn on outlier hardware
                            // Thresholds: < 0.2 (extremely slow) or > 5.0 (extremely fast) relative to baseline
                            if calibration.performance_factor < 0.2
                                || calibration.performance_factor > 5.0
                            {
                                log::warn!("DSM_HARDWARE_WARNING: Device performance outlier (factor {:.3}). Tick drift may occur.", calibration.performance_factor);
                            }
                        }
                        Err(e) => {
                            log::warn!(
                        "initializeSdkContext: Device calibration failed (using defaults): {}",
                        e
                    );
                        }
                    }

                    // Also set AppState for bootstrap compatibility (deterministic key generation)
                    // Generate deterministic public key from device ID (same as bootstrap adapter)
                    let mut hasher = dsm_domain_hasher("DSM/device-key");
                    hasher.update(&dev_bytes);
                    let seed = hasher.finalize();
                    let public_key = seed.as_bytes()[0..32].to_vec();

                    // Use the canonical empty SMT root (same as bootstrap adapter)
                    let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
                        dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
                    )
                    .to_vec();

                    // Set identity info in AppState (idempotent)
                    crate::sdk::app_state::AppState::set_identity_info_if_empty(
                        dev_bytes, public_key, gen_bytes, smt_root,
                    );
                    crate::sdk::app_state::AppState::set_has_identity(true);

                    log::info!("initializeSdkContext: AppState identity info set successfully");
                    1 // true
                }
                Err(e) => {
                    log::error!(
                        "initializeSdkContext: failed to initialize SDK context: {}",
                        e
                    );
                    0 // false
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

            // Check if already installed
            if crate::bridge::app_router().is_some() {
                log::info!("ensureAppRouterInstalled: AppRouter is available - SUCCESS");
                return 1; // true
            }

            // AppRouter not installed - try to install it if device identity is available
            log::info!(
                "ensureAppRouterInstalled: AppRouter not available, attempting to install..."
            );

            // Check if we have device identity (required for full AppRouter)
            if crate::sdk::app_state::AppState::get_device_id().is_some() {
                log::info!(
                    "ensureAppRouterInstalled: Device identity available, installing AppRouter"
                );

                // Get storage endpoints: try registry first, fall back to env config
                let endpoints = match crate::network::list_storage_endpoints() {
                    Ok(list) if !list.is_empty() => list,
                    _ => match crate::network::NetworkConfigLoader::load_env_config() {
                        Ok(env) => env.nodes.into_iter().map(|n| n.endpoint).collect(),
                        Err(_) => Vec::new(),
                    },
                };
                let cfg = crate::init::SdkConfig {
                    node_id: "default".to_string(),
                    storage_endpoints: endpoints,
                    enable_offline: false,
                };

                // Install full AppRouter (same logic as init.rs)
                let app_router = match crate::handlers::AppRouterImpl::new(cfg) {
                    Ok(router) => std::sync::Arc::new(router),
                    Err(e) => {
                        log::error!(
                            "ensureAppRouterInstalled: Failed to create AppRouter: {:?}",
                            e
                        );
                        return 0; // false
                    }
                };
                if let Err(e) = crate::bridge::install_app_router(app_router) {
                    log::error!(
                        "ensureAppRouterInstalled: Failed to install AppRouter: {:?}",
                        e
                    );
                    return 0; // false
                }
                crate::handlers::install_app_router_adapter(
                    crate::runtime::get_runtime().handle().clone(),
                );

                log::info!("ensureAppRouterInstalled: AppRouter installed successfully");
                return 1; // true
            }

            log::error!(
                "ensureAppRouterInstalled: Cannot install AppRouter - no device identity available"
            );
            0 // false
        }),
    )
}

/// Return an integer status code describing why AppRouter may not be available.
/// Codes:
/// 0 = NOT_READY_NO_GENESIS
/// 1 = DBRW_NOT_READY
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

            // If AppRouter is installed, report INSTALLED
            if crate::bridge::app_router().is_some() {
                log::info!("getAppRouterStatus: INSTALLED");
                return 2;
            }

            // Not installed -> check genesis presence
            let has_genesis = crate::sdk::app_state::AppState::get_genesis_hash().is_some();
            if !has_genesis {
                log::info!("getAppRouterStatus: NOT_READY_NO_GENESIS");
                return 0;
            }

            // Genesis exists, check C-DBRW binding key; if C-DBRW does not have a usable binding key,
            // signal CDBRW_NOT_READY. Otherwise, conservatively report CDBRW_NOT_READY as well
            // (SDK init step still outstanding).
            let has_binding_key = crate::jni::cdbrw::get_cdbrw_binding_key()
                .map(|k| k.len() == 32)
                .unwrap_or(false);
            if !has_binding_key {
                log::info!("getAppRouterStatus: CDBRW_NOT_READY - no binding key");
                return 1;
            }

            // Conservative status: genesis present and DBRW has a key, but AppRouter still not installed.
            // Return DBRW_NOT_READY to indicate SDK initialization incomplete.
            log::warn!("getAppRouterStatus: genesis present and DBRW has key but AppRouter missing; returning DBRW_NOT_READY");
            1
        }),
    )
}

/// Handle ContactQrV3 protobuf for QR-based contact addition.
/// This processes the ContactQrV3 protobuf bytes received from the frontend
/// and adds the contact using the contact manager.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_handleContactQrV3(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    contact_qr_v3_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "handleContactQrV3",
        std::panic::AssertUnwindSafe(|| {
            crate::logging::init_android_device_logging();

            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let jbytes = unsafe { jba_from(contact_qr_v3_bytes) };

            let raw_bytes: Vec<u8> = match env.convert_byte_array(&jbytes) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("handleContactQrV3: failed to convert byte array: {}", e);
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::InvalidInput as u32,
                        "failed to convert byte array",
                    )
                    .into_raw();
                }
            };

            // Parse ContactQrV3 protobuf
            let contact_qr: crate::generated::ContactQrV3 =
                match prost::Message::decode(&raw_bytes[..]) {
                    Ok(qr) => qr,
                    Err(e) => {
                        log::error!(
                            "handleContactQrV3: failed to decode ContactQrV3 protobuf: {}",
                            e
                        );
                        return error_byte_array(
                            &mut env,
                            helpers::JniErrorCode::InvalidInput as u32,
                            "failed to decode ContactQrV3 protobuf",
                        )
                        .into_raw();
                    }
                };

            // Get app router for contact handling
            let router = match crate::bridge::app_router() {
                Some(r) => r,
                None => {
                    log::error!("handleContactQrV3: app router not available");
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::NotReady as u32,
                        "app router not available",
                    )
                    .into_raw();
                }
            };

            // Basic field validation before dispatch
            if contact_qr.device_id.is_empty() {
                log::error!("handleContactQrV3: device_id is required");
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "device_id is required",
                )
                .into_raw();
            }
            if contact_qr.genesis_hash.is_empty() {
                log::error!("handleContactQrV3: genesis_hash is required");
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::InvalidInput as u32,
                    "genesis_hash is required",
                )
                .into_raw();
            }
            // Build ArgPack (PROTO) to route through AppRouter handler
            let pack = crate::generated::ArgPack {
                schema_hash: Some(crate::generated::Hash32 { v: vec![0u8; 32] }),
                codec: crate::generated::Codec::Proto as i32,
                body: raw_bytes.clone(),
            };
            let mut pack_bytes = Vec::new();
            if pack.encode(&mut pack_bytes).is_err() {
                log::error!("handleContactQrV3: failed to encode ArgPack");
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::EncodingFailed as u32,
                    "failed to encode ArgPack",
                )
                .into_raw();
            }

            let invoke = crate::bridge::AppInvoke {
                method: "contacts.handle_contact_qr_v3".to_string(),
                args: pack_bytes,
            };

            // Spawn async task to add contact via AppRouter
            let runtime = crate::runtime::get_runtime();
            let (tx, rx) = std::sync::mpsc::channel();

            runtime.spawn(async move {
                let result = router.invoke(invoke).await;
                let _ = tx.send(result);
            });

            // Wait for result with timeout
            match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                Ok(result) => {
                    if !result.success {
                        let msg = result
                            .error_message
                            .unwrap_or_else(|| "contact addition failed".to_string());
                        log::error!("handleContactQrV3: contact addition failed: {}", msg);
                        return error_byte_array(
                            &mut env,
                            helpers::JniErrorCode::ProcessingFailed as u32,
                            &msg,
                        )
                        .into_raw();
                    }

                    // Return the framed envelope directly (router already framed with 0x03 + Envelope)
                    env.byte_array_from_slice(&result.data)
                        .map(|arr| arr.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(&mut env).into_raw())
                }
                Err(_) => {
                    log::error!("handleContactQrV3: timeout waiting for contact addition");
                    error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        "timeout waiting for contact addition",
                    )
                    .into_raw()
                }
            }
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getPendingBilateralProposalsStrict(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "getPendingBilateralProposalsStrict",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();
            // Defensive: ensure handler is installed (offline — no storage endpoints needed)
            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            {
                if crate::bridge::bilateral_handler().is_none() {
                    use crate::init::SdkConfig;
                    let cfg = SdkConfig {
                        node_id: "default".to_string(),
                        storage_endpoints: Vec::new(),
                        enable_offline: true,
                    };
                    let _ = crate::init::init_dsm_sdk(&cfg);
                }
            }

            let result = crate::bridge::get_pending_bilateral_proposals_strict();
            match result {
                Ok(proposals) => {
                    let byte_array_cls = match env.find_class("[B") {
                        Ok(c) => c,
                        Err(e) => {
                            log::error!("JNI: Failed to find [B class: {:?}", e);
                            return std::ptr::null_mut();
                        }
                    };
                    let empty_arr = match env.new_byte_array(0) {
                        Ok(a) => a,
                        Err(_) => return std::ptr::null_mut(),
                    };
                    let output_array = match env.new_object_array(
                        proposals.len() as i32,
                        &byte_array_cls,
                        &empty_arr,
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            log::error!("JNI: Failed to allocate object array: {:?}", e);
                            return std::ptr::null_mut();
                        }
                    };
                    for (i, bytes) in proposals.iter().enumerate() {
                        let row = match env.byte_array_from_slice(bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                log::error!("JNI: Failed to create row bytes: {:?}", e);
                                continue;
                            }
                        };
                        if let Err(e) = env.set_object_array_element(&output_array, i as i32, &row)
                        {
                            log::error!("JNI: Failed to set array element {}: {:?}", i, e);
                        }
                    }
                    output_array.into_raw()
                }
                Err(e) => {
                    log::error!("getPendingBilateralProposalsStrict failed: {}", e);
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

/* =============================================================================
Bitcoin Tap — Deposit / Withdrawal JNI Exports
============================================================================= */

/// Initiate a Bitcoin deposit (BTC → dBTC).
/// Input: protobuf-encoded DepositRequest
/// Output: protobuf-encoded DepositResponse (framed V3 envelope)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinSwapInitiate(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "bitcoinSwapInitiate",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();

            if !SDK_READY.load(Ordering::SeqCst) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                )
                .into_raw();
            }

            let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapInitiate: bad input: {e}"),
                    )
                    .into_raw();
                }
            };

            let deposit_req = match pb::DepositRequest::decode(req.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapInitiate: decode failed: {e}"),
                    )
                    .into_raw();
                }
            };

            // Build response — actual deposit initiation happens via process_envelope_v3
            // For now, encode as an envelope and route through the universal handler.
            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![],
                payload: Some(pb::envelope::Payload::DepositRequest(deposit_req)),
            };
            let mut env_bytes = Vec::new();
            if let Err(e) = envelope.encode(&mut env_bytes) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapInitiate: encode failed: {e}"),
                )
                .into_raw();
            }

            match process_envelope_v3(&env_bytes) {
                Ok(resp) => {
                    let mut out = Vec::with_capacity(1 + resp.len());
                    out.push(0x03);
                    out.extend_from_slice(&resp);
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
                }
                Err(e) => error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapInitiate failed: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Complete a Bitcoin deposit with preimage + SPV proof.
/// Input: protobuf-encoded DepositCompleteRequest
/// Output: protobuf-encoded DepositResponse (framed V3 envelope)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinSwapComplete(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "bitcoinSwapComplete",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();

            if !SDK_READY.load(Ordering::SeqCst) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                )
                .into_raw();
            }

            let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapComplete: bad input: {e}"),
                    )
                    .into_raw();
                }
            };

            let complete_req = match pb::DepositCompleteRequest::decode(req.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapComplete: decode failed: {e}"),
                    )
                    .into_raw();
                }
            };

            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![],
                payload: Some(pb::envelope::Payload::DepositCompleteRequest(complete_req)),
            };
            let mut env_bytes = Vec::new();
            if let Err(e) = envelope.encode(&mut env_bytes) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapComplete: encode failed: {e}"),
                )
                .into_raw();
            }

            match process_envelope_v3(&env_bytes) {
                Ok(resp) => {
                    let mut out = Vec::with_capacity(1 + resp.len());
                    out.push(0x03);
                    out.extend_from_slice(&resp);
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
                }
                Err(e) => error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapComplete failed: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Refund an expired Bitcoin deposit.
/// Input: protobuf-encoded DepositRefundRequest
/// Output: protobuf-encoded DepositResponse (framed V3 envelope)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinSwapRefund(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "bitcoinSwapRefund",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();

            if !SDK_READY.load(Ordering::SeqCst) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                )
                .into_raw();
            }

            let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapRefund: bad input: {e}"),
                    )
                    .into_raw();
                }
            };

            let refund_req = match pb::DepositRefundRequest::decode(req.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapRefund: decode failed: {e}"),
                    )
                    .into_raw();
                }
            };

            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![],
                payload: Some(pb::envelope::Payload::DepositRefundRequest(refund_req)),
            };
            let mut env_bytes = Vec::new();
            if let Err(e) = envelope.encode(&mut env_bytes) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapRefund: encode failed: {e}"),
                )
                .into_raw();
            }

            match process_envelope_v3(&env_bytes) {
                Ok(resp) => {
                    let mut out = Vec::with_capacity(1 + resp.len());
                    out.push(0x03);
                    out.extend_from_slice(&resp);
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
                }
                Err(e) => error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapRefund failed: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Query the status of a Bitcoin deposit.
/// Input: protobuf-encoded DepositStatusRequest
/// Output: protobuf-encoded DepositResponse (framed V3 envelope)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinSwapStatus(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "bitcoinSwapStatus",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            ensure_bootstrap();

            if !SDK_READY.load(Ordering::SeqCst) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::RuntimeError as u32,
                    "SDK not ready",
                )
                .into_raw();
            }

            let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapStatus: bad input: {e}"),
                    )
                    .into_raw();
                }
            };

            let status_req = match pb::DepositStatusRequest::decode(req.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinSwapStatus: decode failed: {e}"),
                    )
                    .into_raw();
                }
            };

            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![],
                payload: Some(pb::envelope::Payload::DepositStatusRequest(status_req)),
            };
            let mut env_bytes = Vec::new();
            if let Err(e) = envelope.encode(&mut env_bytes) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapStatus: encode failed: {e}"),
                )
                .into_raw();
            }

            match process_envelope_v3(&env_bytes) {
                Ok(resp) => {
                    let mut out = Vec::with_capacity(1 + resp.len());
                    out.push(0x03);
                    out.extend_from_slice(&resp);
                    env.byte_array_from_slice(&out)
                        .map(|a| a.into_raw())
                        .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
                }
                Err(e) => error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinSwapStatus failed: {e}"),
                )
                .into_raw(),
            }
        }),
    )
}

/// Verify a Bitcoin SPV proof independently.
/// Input: protobuf-encoded BitcoinHTLCProof (txid + spv_proof + block_header)
/// Output: framed V3 envelope with DepositResponse (status = "verified" or "invalid")
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinVerifyPayment(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "bitcoinVerifyPayment",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
                Ok(b) => b,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinVerifyPayment: bad input: {e}"),
                    )
                    .into_raw();
                }
            };

            let proof = match pb::BitcoinHtlcProof::decode(req.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::DeserializeError as u32,
                        &format!("bitcoinVerifyPayment: decode failed: {e}"),
                    )
                    .into_raw();
                }
            };

            // Validate field lengths
            if proof.bitcoin_txid.len() != 32 || proof.block_header.len() != 80 {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    "bitcoinVerifyPayment: txid must be 32 bytes, block_header must be 80 bytes",
                )
                .into_raw();
            }

            let mut txid = [0u8; 32];
            txid.copy_from_slice(&proof.bitcoin_txid);
            let mut header = [0u8; 80];
            header.copy_from_slice(&proof.block_header);

            let verified = match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::verify_bitcoin_payment(
                &txid,
                &proof.spv_proof,
                &header,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return error_byte_array(
                        &mut env,
                        helpers::JniErrorCode::ProcessingFailed as u32,
                        &format!("bitcoinVerifyPayment: SPV verification error: {e}"),
                    )
                    .into_raw();
                }
            };

            let status = if verified { "verified" } else { "invalid" };
            let response = pb::DepositResponse {
                vault_op_id: String::new(),
                status: status.to_string(),
                vault_id: String::new(),
                external_commitment: vec![],
                hash_lock: vec![],
                htlc_script: vec![],
                htlc_address: String::new(),
                message: format!("SPV proof {status}"),
                funding_txid: String::new(),
            };

            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![],
                payload: Some(pb::envelope::Payload::DepositResponse(response)),
            };

            let mut out = Vec::new();
            out.push(0x03);
            if let Err(e) = envelope.encode(&mut out) {
                return error_byte_array(
                    &mut env,
                    helpers::JniErrorCode::ProcessingFailed as u32,
                    &format!("bitcoinVerifyPayment: encode failed: {e}"),
                )
                .into_raw();
            }

            env.byte_array_from_slice(&out)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

/// Generate a Bitcoin HTLC P2WSH address for a deposit.
/// Input: protobuf-encoded DepositRequest (hash_lock + btc_pubkey fields used)
/// Output: framed V3 envelope with DepositResponse (htlc_script + htlc_address)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_bitcoinGenerateAddress(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    request_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let mut env = match unsafe { env_from(env) } {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let req = match unsafe { env.convert_byte_array(&jba_from(request_bytes)) } {
        Ok(b) => b,
        Err(e) => {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::DeserializeError as u32,
                &format!("bitcoinGenerateAddress: bad input: {e}"),
            )
            .into_raw();
        }
    };

    let deposit_req = match pb::DepositRequest::decode(req.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::DeserializeError as u32,
                &format!("bitcoinGenerateAddress: decode failed: {e}"),
            )
            .into_raw();
        }
    };

    if deposit_req.hash_lock.len() != 32 {
        return error_byte_array(
            &mut env,
            helpers::JniErrorCode::ProcessingFailed as u32,
            "bitcoinGenerateAddress: hash_lock must be 32 bytes",
        )
        .into_raw();
    }

    let mut hash_lock = [0u8; 32];
    hash_lock.copy_from_slice(&deposit_req.hash_lock);

    // Derive refund hash lock for address generation
    let refund_iterations: u64 = deposit_req.refund_iterations.max(1);
    let refund_key = dsm::crypto::blake3::domain_hash_bytes(
        "DSM/dlv-refund",
        &[&hash_lock[..], &refund_iterations.to_le_bytes()].concat(),
    );
    let refund_hash_lock = dsm::bitcoin::script::sha256_hash_lock(&refund_key);

    // Use testnet by default for address generation; the counterparty verifies the script
    let network = dsm::bitcoin::types::BitcoinNetwork::Testnet;

    // btc_pubkey serves as both claimer and refund for address generation
    // (counterparty will construct the full HTLC with proper pubkeys)
    let result = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::generate_htlc_address(
        &hash_lock,
        &refund_hash_lock,
        &deposit_req.btc_pubkey,
        &deposit_req.btc_pubkey, // placeholder refund key
        network,
    );

    let (script, address) = match result {
        Ok(r) => r,
        Err(e) => {
            return error_byte_array(
                &mut env,
                helpers::JniErrorCode::ProcessingFailed as u32,
                &format!("bitcoinGenerateAddress: HTLC build failed: {e}"),
            )
            .into_raw();
        }
    };

    let response = pb::DepositResponse {
        vault_op_id: String::new(),
        status: "address_generated".to_string(),
        vault_id: String::new(),
        external_commitment: vec![],
        hash_lock: hash_lock.to_vec(),
        htlc_script: script,
        htlc_address: address,
        message: String::new(),
        funding_txid: String::new(),
    };

    let envelope = pb::Envelope {
        version: 3,
        headers: None,
        message_id: vec![],
        payload: Some(pb::envelope::Payload::DepositResponse(response)),
    };

    let mut out = Vec::new();
    out.push(0x03);
    if let Err(e) = envelope.encode(&mut out) {
        return error_byte_array(
            &mut env,
            helpers::JniErrorCode::ProcessingFailed as u32,
            &format!("bitcoinGenerateAddress: encode failed: {e}"),
        )
        .into_raw();
    }

    env.byte_array_from_slice(&out)
        .map(|a| a.into_raw())
        .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
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

            let bytes = crate::sdk::session_manager::get_session_snapshot_bytes();

            env.byte_array_from_slice(&bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
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

            match crate::sdk::session_manager::update_hardware_and_snapshot(&bytes) {
                Ok(snapshot_bytes) => env
                    .byte_array_from_slice(&snapshot_bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                Err(e) => {
                    log::error!("updateSessionHardwareFacts: {e}");
                    empty_byte_array_or_empty(&env).into_raw()
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
            let snapshot_bytes = crate::sdk::session_manager::set_fatal_error_and_snapshot(&msg);

            env.byte_array_from_slice(&snapshot_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
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

            let snapshot_bytes = crate::sdk::session_manager::clear_fatal_error_and_snapshot();

            env.byte_array_from_slice(&snapshot_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

// ========================= NFC Ring Backup JNI Exports =========================

/// Get the latest pending recovery capsule bytes for NFC write.
/// Returns the encrypted capsule bytes, or an empty array if no capsule is pending.
/// Kotlin calls this to check if there's a capsule to write when an NFC tag is detected.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getPendingRecoveryCapsule(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getPendingRecoveryCapsule",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            match crate::sdk::recovery_sdk::RecoverySDK::get_pending_capsule() {
                Some((_index, bytes)) => env
                    .byte_array_from_slice(&bytes)
                    .map(|a| a.into_raw())
                    .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw()),
                None => empty_byte_array_or_empty(&env).into_raw(),
            }
        }),
    )
}

/// Prepare NFC write payload: wraps capsule bytes into an NDEF-compatible record.
/// Input: raw encrypted capsule bytes.
/// Output: NDEF message bytes ready for `Ndef.writeNdefMessage()`.
///
/// The NDEF record uses MIME type `application/vnd.dsm.recovery` so that
/// Android's NFC dispatch can route it to NfcRecoveryActivity on read.
/// Rust decides the record structure; Kotlin writes raw bytes to the tag.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_prepareNfcWritePayload(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    capsule_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "prepareNfcWritePayload",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let capsule = {
                let jb = unsafe { jni::objects::JByteArray::from_raw(capsule_bytes) };
                match env.convert_byte_array(jb) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("prepareNfcWritePayload: convert_byte_array: {e}");
                        return empty_byte_array_or_empty(&env).into_raw();
                    }
                }
            };

            // Build NDEF record:
            //   TNF = 0x02 (MIME type)
            //   Type = "application/vnd.dsm.recovery"
            //   Payload = capsule bytes
            //
            // NDEF message format (single record, MB+ME flags set):
            //   [flags:1][type_len:1][payload_len:4][type:N][payload:M]
            let mime_type = b"application/vnd.dsm.recovery";
            let type_len = mime_type.len();
            let payload_len = capsule.len();

            // Flags: MB=1, ME=1, CF=0, SR=0 (long record), IL=0, TNF=0x02
            // = 0b1100_0010 = 0xC2
            // If payload fits in 1 byte (<=255), use SR=1: 0b1101_0010 = 0xD2
            let (flags, header_size) = if payload_len <= 255 {
                (0xD2u8, 1 + 1 + 1 + type_len + payload_len) // SR record
            } else {
                (0xC2u8, 1 + 1 + 4 + type_len + payload_len) // Long record
            };

            let mut ndef = Vec::with_capacity(header_size);
            ndef.push(flags);
            ndef.push(type_len as u8);
            if payload_len <= 255 {
                ndef.push(payload_len as u8);
            } else {
                ndef.extend_from_slice(&(payload_len as u32).to_be_bytes());
            }
            ndef.extend_from_slice(mime_type);
            ndef.extend_from_slice(&capsule);

            env.byte_array_from_slice(&ndef)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

/// Clear the pending recovery capsule after a successful NFC write.
/// Called by Kotlin after `Ndef.writeNdefMessage()` succeeds.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_clearPendingRecoveryCapsule(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) {
    if let Err(e) = crate::storage::client_db::recovery::clear_pending_recovery_capsule() {
        log::warn!("[NFC_BACKUP] Failed to clear pending capsule marker: {e}");
    } else {
        log::info!("[NFC_BACKUP] Pending capsule cleared after successful NFC write");
    }
}

/// Derive a 4-byte NFC hardware password from device identity.
/// Used by Kotlin to set write-protection on NTAG216 rings.
/// Anyone can read the tag, but only this device's app can overwrite it.
/// Password = first 4 bytes of BLAKE3("DSM/nfc-tag-pwd\0" || device_id).
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getNfcRingPassword(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getNfcRingPassword",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let device_id = match crate::sdk::app_state::AppState::get_device_id() {
                Some(id) if id.len() == 32 => id,
                _ => {
                    log::warn!("getNfcRingPassword: device_id not available");
                    return empty_byte_array_or_empty(&env).into_raw();
                }
            };

            let hash = dsm::crypto::blake3::domain_hash("DSM/nfc-tag-pwd", &device_id);
            let pwd = &hash.as_bytes()[..4];

            env.byte_array_from_slice(pwd)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

/// Silently refresh the pending NFC capsule if backup is enabled and a key is cached.
/// Called by Kotlin after every state-mutating operation (processEnvelopeV3, appRouterInvoke).
/// Rust decides whether to actually create a capsule. No-op if backup disabled or no key.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_maybeRefreshNfcCapsule(
    _env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) {
    crate::sdk::recovery_sdk::RecoverySDK::maybe_refresh_nfc_capsule();
}
