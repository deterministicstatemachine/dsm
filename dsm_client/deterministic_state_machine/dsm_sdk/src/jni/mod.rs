//! ──────────────────────────────────────────────────────────
//! LAYER: SDK
//! PURPOSE: JNI module organization and exports.
//! USES: Refactored modules (identity, transport, ble, wallet)
//! ──────────────────────────────────────────────────────────

#![allow(unsafe_code)]

/// Common JNI utilities (Android only)
#[cfg(target_os = "android")]
pub mod jni_common;
#[cfg(target_os = "android")]
pub mod jni_error;
#[cfg(target_os = "android")]
pub mod jni_result;

/// Helper utilities shared by the JNI bridge (Android only)
#[cfg(target_os = "android")]
pub mod helpers;

// --- Refactored Modules ---
#[cfg(target_os = "android")]
pub mod bridge_utils;
#[cfg(target_os = "android")]
pub mod state;

#[cfg(target_os = "android")]
pub mod identity;
#[cfg(target_os = "android")]
pub mod transport;
#[cfg(target_os = "android")]
pub mod wallet;

/// Bilateral adaptive poller (Android + bluetooth only)
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub mod bilateral_poll;

/// BLE event envelope creators (Android only)
#[cfg(target_os = "android")]
pub mod ble_events;

/// C-DBRW JNI implementation (Android only)
#[cfg(target_os = "android")]
pub mod cdbrw;

/// Generic Rust→WebView event dispatch (Android only)
#[cfg(target_os = "android")]
pub mod event_dispatch;

/// Unified protobuf bridge (Android only)
#[cfg(target_os = "android")]
pub mod unified_protobuf_bridge;

/// Create genesis via MPC (Android only)
#[cfg(target_os = "android")]
pub mod create_genesis;
#[cfg(target_os = "android")]
pub mod secondary_device;

/// BLE bridge JNI entrypoints (Android + bluetooth only)
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub mod ble_bridge;

// Re-export SDK_READY from its canonical home (always compiled, not cfg-gated).
pub use crate::sdk::session_manager::set_sdk_ready;

#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::create_genesis::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::secondary_device::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::cdbrw::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::ble_events::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::identity::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::transport::*;
#[cfg(target_os = "android")]
#[allow(unused_imports)]
pub use self::wallet::*;

// Unit tests for JNI-adjacent helpers (runs on host; does not require Android runtime).
#[cfg(test)]
mod tests;

// Re-export utilities
#[cfg(target_os = "android")]
pub use self::jni_common::{get_java_vm_ptr, set_java_vm};
#[cfg(target_os = "android")]
pub use self::jni_error::JniErrorCode;
#[cfg(target_os = "android")]
pub use self::jni_result::*;

/// Install JavaVM pointer at library load time so background JNI calls can attach threads safely.
/// Also caches the app's ClassLoader for use by worker threads.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut core::ffi::c_void,
) -> jni::sys::jint {
    // Prevent linker from dead-code eliminating JNI entry points by taking their addresses.
    // Cast to `*const ()` (not `usize`) — direct fn-item-to-integer casts are rejected by
    // recent Rust toolchains (E0606 / "direct cast of function item into an integer").
    let _ = unified_protobuf_bridge::Java_com_dsm_wallet_bridge_UnifiedNativeApi_getSessionSnapshot
        as *const ();
    let _ = unified_protobuf_bridge::Java_com_dsm_wallet_bridge_UnifiedNativeApi_updateSessionHardwareFacts as *const ();
    let _ =
        unified_protobuf_bridge::Java_com_dsm_wallet_bridge_UnifiedNativeApi_setSessionFatalError
            as *const ();
    let _ =
        unified_protobuf_bridge::Java_com_dsm_wallet_bridge_UnifiedNativeApi_clearSessionFatalError
            as *const ();
    // The six `cdbrw*` JNI exports were removed when Protocol 6.2 collapsed
    // into the single-path router. Kotlin only reaches C-DBRW through the
    // `cdbrw.*` router-query family in `misc_routes.rs` now; there is no
    // JNI surface left to keep alive here.

    // Initialize Rust logging early so all JNI functions produce logcat output.
    crate::logging::init_android_device_logging();
    crate::logging::init_panic_handler();

    // Safety: VM pointer is provided by the JVM and remains valid for process lifetime.
    let ok = unsafe { jni::JavaVM::from_raw(vm) };
    match ok {
        Ok(java_vm) => {
            // Store globally; subsequent calls to get_java_vm_borrowed() will succeed.
            let _ = self::jni_common::set_java_vm(java_vm);

            // CRITICAL: Cache the app's ClassLoader from the current thread (main thread).
            // Get the stored JavaVM reference and attach to get JNIEnv
            if let Some(vm_ref) = self::jni_common::get_java_vm_borrowed() {
                if let Ok(mut env) = vm_ref.get_env() {
                    if let Err(e) =
                        self::jni_common::init_app_class_loader_from_current_thread(&mut env)
                    {
                        #[cfg(feature = "jni")]
                        {
                            let _ = e;
                        }
                    }
                }
            }

            // Use JNI 1.6 minimum unless the app requires newer API.
            jni::sys::JNI_VERSION_1_6
        }
        Err(_) => jni::sys::JNI_ERR,
    }
}
