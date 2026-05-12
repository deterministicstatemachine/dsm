//! # JNI Bridge Utility Functions
//!
//! Shared helpers for JNI entry points: `SDK_READY` gate checks,
//! protobuf request/response marshalling, and error-to-`OpResult`
//! conversion.

// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::generated as pb;
use crate::sdk::session_manager::SDK_READY;
use jni::objects::{JByteArray, JString};
use jni::JNIEnv;
use prost::Message;
use std::sync::atomic::Ordering;

// ═══════════════════════════════════════════════════════════════════════════════
// FFI panic safety: catch_unwind wrappers for JNI export functions.
//
// Panics that unwind across an `extern "system"` FFI boundary cause undefined
// behavior (typically a JVM crash). These helpers capture panics and return
// safe default values instead.
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract a human-readable message from a panic payload.
pub fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Wrap a closure that returns `jni::sys::jbyteArray` with panic::catch_unwind.
/// On panic, logs the error and returns `null_mut()` (which Java sees as `null`).
#[inline]
pub fn jni_catch_unwind_jbytearray<F>(name: &str, f: F) -> jni::sys::jbyteArray
where
    F: FnOnce() -> jni::sys::jbyteArray + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            std::ptr::null_mut()
        }
    }
}

/// Wrap a closure that returns `jni::sys::jboolean` with panic::catch_unwind.
/// On panic, returns 0 (JNI_FALSE).
#[inline]
pub fn jni_catch_unwind_jboolean<F>(name: &str, f: F) -> jni::sys::jboolean
where
    F: FnOnce() -> jni::sys::jboolean + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            0 // JNI_FALSE
        }
    }
}

/// Wrap a closure that returns `jni::sys::jint` with panic::catch_unwind.
/// On panic, returns the provided default value.
#[inline]
pub fn jni_catch_unwind_jint<F>(name: &str, default: jni::sys::jint, f: F) -> jni::sys::jint
where
    F: FnOnce() -> jni::sys::jint + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            default
        }
    }
}

/// Wrap a closure that returns `jni::sys::jlong` with panic::catch_unwind.
/// On panic, returns 0.
#[inline]
pub fn jni_catch_unwind_jlong<F>(name: &str, f: F) -> jni::sys::jlong
where
    F: FnOnce() -> jni::sys::jlong + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            0
        }
    }
}

/// Wrap a closure that returns `jni::sys::jbyte` with panic::catch_unwind.
/// On panic, returns 0.
#[inline]
pub fn jni_catch_unwind_jbyte<F>(name: &str, f: F) -> jni::sys::jbyte
where
    F: FnOnce() -> jni::sys::jbyte + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            0
        }
    }
}

/// Wrap a closure that returns `jni::sys::jobjectArray` with panic::catch_unwind.
/// On panic, returns `null_mut()`.
#[inline]
pub fn jni_catch_unwind_jobjectarray<F>(name: &str, f: F) -> jni::sys::jobjectArray
where
    F: FnOnce() -> jni::sys::jobjectArray + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            log::error!("{}: panic captured: {}", name, panic_message(&panic));
            std::ptr::null_mut()
        }
    }
}

/// Wrap a void JNI closure with panic::catch_unwind.
/// On panic, logs and silently returns.
#[inline]
pub fn jni_catch_unwind_void<F>(name: &str, f: F)
where
    F: FnOnce() + std::panic::UnwindSafe,
{
    if let Err(panic) = std::panic::catch_unwind(f) {
        log::error!("{}: panic captured: {}", name, panic_message(&panic));
    }
}

// --- Helpers to convert raw JNI handles ---
#[inline]
pub unsafe fn env_from(raw: jni::sys::JNIEnv) -> Option<jni::JNIEnv<'static>> {
    match JNIEnv::from_raw(raw as *mut _) {
        Ok(env) => Some(env),
        Err(e) => {
            log::error!("env_from failed: {e}");
            None
        }
    }
}
#[inline]
pub unsafe fn jstr_from(raw: jni::sys::jstring) -> JString<'static> {
    JString::from_raw(raw)
}
#[inline]
pub unsafe fn jba_from(raw: jni::sys::jbyteArray) -> JByteArray<'static> {
    JByteArray::from_raw(raw)
}

#[inline]
pub fn empty_byte_array_or_empty<'a>(env: &'a JNIEnv<'a>) -> JByteArray<'a> {
    env.new_byte_array(0).unwrap_or_else(|e| {
        log::error!("JVM failed to allocate empty byte array: {e} - returning null");
        unsafe { JByteArray::from_raw(std::ptr::null_mut()) }
    })
}

#[inline]
pub fn error_byte_array<'a>(env: &'a JNIEnv<'a>, code: u32, msg: &str) -> JByteArray<'a> {
    let env_pb = crate::jni::helpers::encode_error_transport(code, msg);
    let mut out = Vec::new();
    if let Err(e) = env_pb.encode(&mut out) {
        log::error!("JVM failed to encode error envelope: {}", e);
        return empty_byte_array_or_empty(env);
    }
    match env.byte_array_from_slice(&out) {
        Ok(arr) => arr,
        Err(e) => {
            log::error!("JVM failed to allocate error byte array: {}", e);
            empty_byte_array_or_empty(env)
        }
    }
}

#[inline]
pub fn error_transport_bytes(code: u32, msg: &str) -> Vec<u8> {
    let env_pb = crate::jni::helpers::encode_error_transport(code, msg);
    let mut out = Vec::new();
    if let Err(e) = env_pb.encode(&mut out) {
        log::error!("failed to encode error envelope: {}", e);
        Vec::new()
    } else {
        out
    }
}

#[inline]
pub fn ensure_bootstrap() {
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
            SDK_READY.store(false, Ordering::SeqCst);
            log::warn!(
                "ensure_bootstrap: C-DBRW binding key missing or invalid after readiness; failing closed."
            );
        }
    }
}

pub fn fetch_transport_headers_bytes() -> Result<Vec<u8>, String> {
    crate::get_transport_headers_v3_bytes().map_err(|e| format!("headers fetch failed: {e}"))
}

pub fn build_transport_headers_pack() -> Result<Vec<u8>, String> {
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
