// SPDX-License-Identifier: MIT OR Apache-2.0
//! C-DBRW binding-key slot.
//!
//! All six Kotlin-facing `cdbrw*` JNI exports were removed when Protocol 6.2
//! collapsed into the single-path router — the only C-DBRW surface Kotlin
//! can reach now is the `cdbrw.*` router query family in `misc_routes.rs`,
//! which goes through `router_query` / `UnifiedNativeApi.routerQuery`.
//!
//! This module retains only the global slot that holds `K_DBRW`, populated
//! during `bootstrap_finalize` so that the router / responder / verifier
//! can look it up without taking a fresh dependency on the JNI layer.
//!
//! Rust consumers should use [`crate::binding_key::get_binding_key`] when
//! possible — that slot is populated for both Android and host builds. This
//! module exists only because `ingress::finalize_bootstrap_core` also wants
//! to stage the key into a target-specific slot, and a few existing call
//! sites still read from it. It will be collapsed entirely once those call
//! sites migrate to the canonical slot.

#[cfg(target_os = "android")]
use std::sync::OnceLock;

/// Global C-DBRW binding key, set once during bootstrap.
#[cfg(target_os = "android")]
static CDBRW_BINDING_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Store the C-DBRW binding key (called from bootstrap).
#[cfg(target_os = "android")]
pub fn set_cdbrw_binding_key(key: Vec<u8>) {
    let _ = CDBRW_BINDING_KEY.set(key);
}

/// Retrieve the C-DBRW binding key. Returns `None` if not yet bootstrapped.
#[cfg(target_os = "android")]
pub fn get_cdbrw_binding_key() -> Option<Vec<u8>> {
    CDBRW_BINDING_KEY.get().cloned()
}

// Non-android stubs for compilation on host.
#[cfg(not(target_os = "android"))]
fn host_binding_slot() -> &'static std::sync::Mutex<Option<Vec<u8>>> {
    static HOST_CDBRW_BINDING_KEY: std::sync::OnceLock<std::sync::Mutex<Option<Vec<u8>>>> =
        std::sync::OnceLock::new();
    HOST_CDBRW_BINDING_KEY.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(not(target_os = "android"))]
pub fn set_cdbrw_binding_key(key: Vec<u8>) {
    let mut guard = host_binding_slot().lock().unwrap_or_else(|p| p.into_inner());
    *guard = Some(key);
}

#[cfg(not(target_os = "android"))]
pub fn get_cdbrw_binding_key() -> Option<Vec<u8>> {
    host_binding_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

#[cfg(all(not(target_os = "android"), test))]
pub fn clear_cdbrw_binding_key_for_testing() {
    let mut guard = host_binding_slot().lock().unwrap_or_else(|p| p.into_inner());
    *guard = None;
}
