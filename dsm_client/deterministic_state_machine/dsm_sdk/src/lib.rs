//! # DSM SDK — Platform Integration Layer
//!
//! The `dsm_sdk` crate bridges the pure, deterministic [`dsm`] core library to
//! platform-specific runtimes (Android/JNI, iOS/FFI, desktop test harnesses).
//!
//! ## Architecture: One Agnostic Ingress
//!
//! The crate is organised into three tiers:
//!
//! 1. **ABI shims** - platform-specific marshalling only, no semantic logic:
//!    - Android: `jni/unified_protobuf_bridge.rs` - `extern "system"` JNI exports
//!    - iOS: `platform/ios/transport.rs` - `extern "C"` FFI exports
//!
//! 2. **Shared ingress** (`ingress`) - the single semantic boundary:
//!    - Both shims translate ABI inputs into [`generated::IngressRequest`] and
//!      call [`ingress::dispatch_ingress`].
//!    - Equivalent Android and iOS operations map to the same `IngressRequest`
//!      and produce the same `IngressResponse`.
//!
//! 3. **SDK internals** - `sdk`, `handlers`, `bluetooth`, `bridge`, etc.
//!
//! The canonical contract is expressed in `proto/dsm_app.proto`:
//! `IngressRequest` / `IngressResponse`. No platform-specific semantics are
//! permitted past the ABI shim.
//!
//! ## Authoritative Data Paths
//!
//! ```text
//! Android: UI -> MessagePort -> Kotlin Bridge -> JNI shim
//!                                              |
//!                                              v
//!                                        IngressRequest
//!                                              |
//! iOS:     Swift caller -> FFI shim -----------+
//!                                              |
//!                                              v
//!                              ingress::dispatch_ingress
//!                                              |
//!                                              v
//!                                       SDK / Core
//! ```
//!
//! ## Crate Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`ingress`] | Shared platform-agnostic ingress dispatch |
//! | [`sdk`] | High-level SDK facades (wallet, token, bilateral, DLV, Bitcoin tap) |
//! | `jni` | Android JNI ABI shim (87+ `extern "system"` functions, cfg-gated) |
//! | [`handlers`] | `AppRouter`, `BilateralHandler`, `UnilateralHandler` implementations |
//! | [`bluetooth`] | BLE bilateral sessions, frame chunking, pairing orchestration |
//! | [`bridge`] | Trait-object dispatch layer connecting handlers to core |
//! | [`envelope`] | Envelope v3 construction, framing (`0x03` prefix), guard rails |
//! | [`security`] | DBRW clone-detection validation at the SDK boundary |
//! | [`storage`] | SQLite-backed client database for contacts, chain tips, bilateral state |
//! | [`network`] | Multi-node storage endpoint registry and env-config loader |
//! | [`event`] | Protobuf-encoded broadcast event stream for UI subscriptions |
//! | [`recovery`] | Capsule, tombstone, and rollup recovery flows |
//! | [`vault`] | DLV (Deterministic Limbo Vault) SDK operations |
//!
//! ## Readiness Lifecycle
//!
//! The SDK uses a two-phase readiness model gated by atomic flags:
//!
//! 1. **Core ready** (`SDK_READY` in `unified_protobuf_bridge`) — set after
//!    `sdkBootstrap` completes PBI (Platform Boundary Interface) initialization
//!    with device_id, genesis_hash, and DBRW entropy.
//! 2. **Bilateral ready** (`BILATERAL_READY`) — set after
//!    [`initialize_bilateral_sdk`] verifies that the SDK context and bilateral
//!    handler are installed, and device performance calibration succeeds.
//!
//! All post-bootstrap JNI calls are gated on `SDK_READY`. Bilateral BLE
//! operations additionally require `BILATERAL_READY`.
//!
//! ## Wire Format
//!
//! All data crosses the JNI/FFI boundary as **protobuf bytes** (prost-encoded).
//! No JSON, no hex encoding in protocol paths. Display-only formatting is
//! permitted at UI edges.
//!
//! ## Feature Flags
//!
//! - `jni` — Enables Android JNI entry points (`extern "system"` functions).
//! - `bluetooth` — Enables BLE bilateral transport and pairing orchestration.
//! - `storage` — Enables storage-node sync SDK and genesis publisher.
//! - `dev-discovery` — Enables mDNS/network auto-discovery (development only).

// DSM SDK Library – strict, fail-closed posture.
#![deny(warnings)]
// Allows clippy::disallowed_methods for JNI boundary and legacy API surface.
// Unwrap/expect calls are being systematically replaced with proper Result handling.
#![allow(clippy::disallowed_methods)]
// JNI is a pure pass-through. No auto-discovery anywhere.
//
// Clippy policy: minimal allows for legitimate reasons only.
#![allow(clippy::module_inception)] // Style preference for mod naming
#![allow(non_snake_case)] // Required: JNI function naming convention
#![allow(dead_code)] // SDK surface area includes pre-wired handlers
#![allow(clippy::type_complexity)] // Complex JNI/trait object signatures
#![allow(clippy::macro_use_imports)] // Workaround for nightly clippy ICE on prost-generated repr attrs

// Expose policy module and enforce builtin integrity at library load.
pub mod policy;

#[allow(dead_code)]
#[ctor::ctor]
fn _dsm_builtins_guard() {
    // Zero-cost unless placeholder commit replaced; hash runs once on load.
    crate::policy::builtins::assert_builtins_sound();
}

pub mod prelude;

#[cfg(all(target_os = "android", feature = "jni"))]
pub mod jni;

pub mod bridge;
mod binding_key;
pub mod ingress;
pub mod crypto_performance;
pub mod envelope;
pub mod event;
pub mod handlers;
pub mod init;
pub mod logging;
pub mod network;
pub mod sdk;
pub mod security;
pub mod storage_utils;
pub mod vault;
pub mod wire;

// Expose the file-based storage module (storage/mod.rs) so that `crate::storage::*`
// works everywhere. Do not shadow it with an inline module.
pub mod storage;
// BLE backend registry (simple trait + OnceCell) for platform integration
pub mod ble;
#[cfg(test)]
mod comprehensive_validation;
#[cfg(test)]
mod crypto_performance_tests;
#[cfg(test)]
mod device_id_tests;
#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;
// encoding module removed per binary-only policy (no Base64/hex helpers in SDK)
// b64 re-export removed per binary-only policy

// Generated protobuf types
pub mod generated;
pub mod util;

// Re-exports of core DSM crates
pub use dsm;
pub use dsm::core;
pub use dsm::crypto;
pub use dsm::types;
pub use dsm::commitments;

pub use logging::*;
pub mod bluetooth;
pub mod platform;

// iOS protobuf-native transport functions (extern "C" for Swift bridging)
#[cfg(target_os = "ios")]
pub use platform::ios::transport::{
    dsm_free_envelope_bytes, dsm_init_dsm_sdk, dsm_initialize_sdk_context,
    dsm_process_envelope_protobuf, dsm_set_storage_base_dir,
};

pub mod runtime;

// #[cfg(feature = "ffi")]
// pub use runtime::dsm_init_runtime;
use crate::storage_utils::ensure_storage_base_dir;
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use std::sync::atomic::{AtomicBool, Ordering};

// Readiness flags (core + bilateral). Core readiness lives in unified_protobuf_bridge (SDK_READY)
// but we expose bilateral readiness here after preconditions succeed so JNI / UI can query
// deterministically without racing the initialization sequence.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
static BILATERAL_READY: AtomicBool = AtomicBool::new(false);

/// STRICT init (default): requires storage dir + explicit env config.
/// Allowed bypass ONLY when DSM_SDK_TEST_MODE=1 (hermetic tests).
pub async fn init_dsm_sdk() -> Result<(), dsm::types::error::DsmError> {
    logging::init_android_device_logging();
    logging::init_panic_handler();

    // Enforce storage base dir first.
    let base = ensure_storage_base_dir()?;
    log::info!("DSM storage base: {base:?}");

    // Load strict network config (or hermetic test config),
    // then install the multi-node registry.
    let cfg = crate::network::NetworkConfigLoader::load_env_config()?;
    crate::network::install_registry(cfg)?;

    // Emit configured endpoints once for observability (no probing).
    let endpoints = if let Ok(list) = crate::network::list_storage_endpoints() {
        log::info!("DSM storage nodes (configured): {}", list.join(", "));
        list
    } else {
        vec![]
    };

    // Install handlers for query/invoke operations
    let sdk_cfg = crate::init::SdkConfig {
        node_id: "default".to_string(),
        storage_endpoints: endpoints,
        enable_offline: false,
    };
    crate::init::init_dsm_sdk(&sdk_cfg).map_err(|e| {
        dsm::types::error::DsmError::internal(e, Some("Failed to initialize DSM SDK"))
    })?;

    // CRITICAL: Initialize SDK context from persisted AppState if available
    // This ensures the SDK is operational immediately on app restart
    if !is_sdk_context_initialized() {
        log::info!("SDK context not initialized, checking persisted AppState...");
        match (
            crate::sdk::app_state::AppState::get_device_id(),
            crate::sdk::app_state::AppState::get_genesis_hash(),
        ) {
            (Some(dev), Some(gen)) => {
                log::info!(
                    "Found persisted identity: device_id={} bytes, genesis={} bytes",
                    dev.len(),
                    gen.len()
                );
                if dev.len() == 32 && gen.len() == 32 {
                    log::info!("Initializing SDK context from persisted AppState");
                    let dbrw = fetch_dbrw_binding_key()?;
                    let entropy = derive_production_entropy(&dev, &gen, &dbrw);
                    initialize_sdk_context(dev, gen.clone(), entropy)?;
                } else {
                    return Err(dsm::types::error::DsmError::invalid_parameter(format!(
                        "Invalid persisted identity sizes: device_id={}, genesis={}",
                        dev.len(),
                        gen.len()
                    )));
                }
            }
            (dev, gen) => {
                log::info!(
                    "No persisted identity found: device_id={}, genesis={}",
                    dev.is_some(),
                    gen.is_some()
                );
            }
        }
    } else {
        log::info!("SDK context already initialized");
    }

    log::info!("DSM SDK initialized (STRICT, multi-node).");
    Ok(())
}

// Global SDK context instance (lives under crate::sdk)
use crate::sdk::SdkContext;
static SDK_CONTEXT: once_cell::sync::Lazy<SdkContext> = once_cell::sync::Lazy::new(SdkContext::new);

/// Get a reference to the global SDK context
pub fn get_sdk_context() -> &'static SdkContext {
    &SDK_CONTEXT
}

/// Initialize the global SDK context with device-specific values
pub fn initialize_sdk_context(
    device_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    initial_entropy: Vec<u8>,
) -> Result<(), dsm::types::error::DsmError> {
    // Avoid noisy re-initialization: if already initialized, skip
    if is_sdk_context_initialized() {
        log::debug!("initialize_sdk_context: SDK context already initialized; skipping re-init");
        return Ok(());
    }
    get_sdk_context().initialize(device_id, genesis_hash, initial_entropy)
}

/// Production entropy derivation (deterministic, DBRW-bound).
///
/// This replaces the previous placeholder of reusing the genesis hash as entropy.
///
/// Domain: "DSM/SDK/ENTROPY/v2".
///
/// Inputs are expected to be 32 bytes for `device_id` and `genesis_hash`. `dbrw_binding`
/// Derive production entropy from device identity + C-DBRW binding.
pub(crate) fn derive_production_entropy(
    device_id: &[u8],
    genesis_hash: &[u8],
    cdbrw_binding: &[u8],
) -> Vec<u8> {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/sdk-hash");
    h.update(device_id);
    h.update(genesis_hash);
    h.update(cdbrw_binding);
    h.finalize().as_bytes().to_vec()
}

pub(crate) fn fetch_dbrw_binding_key() -> Result<Vec<u8>, dsm::types::error::DsmError> {
    crate::binding_key::get_binding_key().ok_or_else(|| {
        dsm::types::error::DsmError::invalid_parameter(
            "C-DBRW binding key unavailable; initialize startup/bootstrap before SDK context",
        )
    })
}

pub(crate) fn install_canonical_binding_key(
    binding_key: Vec<u8>,
) -> Result<(), dsm::types::error::DsmError> {
    crate::binding_key::install_binding_key(binding_key)
}

#[cfg(not(target_os = "android"))]
pub fn set_cdbrw_binding_key_for_testing(key: Vec<u8>) {
    let _ = crate::binding_key::install_binding_key(key);
}

/// Check if the global SDK context is properly initialized
pub fn is_sdk_context_initialized() -> bool {
    get_sdk_context().is_initialized()
}

/// Reset the global SDK context (for testing only)
#[cfg(any(test, feature = "test-utils"))]
pub fn reset_sdk_context_for_testing() {
    get_sdk_context().reset_for_testing();
    crate::binding_key::clear_binding_key_for_testing();
}

/// Get transport headers from SDK context for envelope v3
/// Returns raw protobuf-encoded Headers bytes; callers at UI/bridge edges may encode if needed.
pub fn get_transport_headers_v3_bytes() -> Result<Vec<u8>, dsm::types::error::DsmError> {
    use crate::generated::Headers;
    use prost::Message;

    if !SDK_CONTEXT.is_initialized() {
        // Attempt to bootstrap from persisted AppState if available
        // This allows header fetches to succeed after genesis without a separate JNI call.
        if let (Some(dev), Some(gen)) = (
            crate::sdk::app_state::AppState::get_device_id(),
            crate::sdk::app_state::AppState::get_genesis_hash(),
        ) {
            if dev.len() == 32 && gen.len() == 32 {
                let dbrw = fetch_dbrw_binding_key()?;
                let entropy = derive_production_entropy(&dev, &gen, &dbrw);
                initialize_sdk_context(dev, gen.clone(), entropy)?;
            }
        }
        if !SDK_CONTEXT.is_initialized() {
            return Err(dsm::types::error::DsmError::invalid_parameter(
                "SDK context not initialized - call initialize_sdk_context first",
            ));
        }
    }

    let device_id = SDK_CONTEXT.device_id();
    let genesis_hash = SDK_CONTEXT.genesis_hash();
    let seq = SDK_CONTEXT.sequence_number();

    // chain_tip is a bilateral relationship-specific value owned entirely by the SDK.
    // It must never be sent to the frontend or accepted back from it — doing so
    // confuses the global device tip with the per-relationship h_n (§4 spec).
    // The Headers.chain_tip field is reserved/ignored; always emit zeros.
    let chain_tip = vec![0u8; 32];

    // Validate field lengths
    if device_id.len() != 32 {
        return Err(dsm::types::error::DsmError::invalid_parameter(format!(
            "device_id must be 32 bytes, got {}",
            device_id.len()
        )));
    }

    let headers = Headers {
        device_id,
        chain_tip,
        genesis_hash,
        seq,
    };

    let mut buf = Vec::new();
    headers
        .encode(&mut buf)
        .map_err(|_| dsm::types::error::DsmError::invalid_operation("Failed to encode Headers"))?;

    Ok(buf)
}

/// Initialize bilateral SDK preconditions.
///
/// Enforces that SDK context and bilateral handler are installed,
/// then performs device calibration for tick-rate normalization.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn initialize_bilateral_sdk() -> Result<(), dsm::types::error::DsmError> {
    use dsm::types::error::DsmError;

    if !is_sdk_context_initialized() {
        return Err(DsmError::invalid_operation(
            "SDK context must be initialized before bilateral SDK",
        ));
    }

    if crate::bridge::bilateral_handler().is_none() {
        return Err(DsmError::invalid_operation(
            "Bilateral handler not installed (BiImpl)",
        ));
    }

    // Calibration: Hardware-specific tick rate normalization (Anti-Tick Drift)
    // We force a calibration run to ensure the tick rate is adapted to the current device speed.
    // This protects against "fast phone bans slow phone" scenarios.
    log::info!("Running initialization calibration...");
    let _ = dsm::utils::timeout::calibrate_device_performance().await;

    log::info!(
        "Bilateral SDK preconditions satisfied (context + handler). Marking bilateral ready."
    );
    BILATERAL_READY.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub async fn initialize_bilateral_sdk() -> Result<(), dsm::types::error::DsmError> {
    log::debug!("initialize_bilateral_sdk: not available on this platform");
    Ok(())
}

/// Returns true once bilateral preconditions have been verified (context + handler).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub fn is_bilateral_ready() -> bool {
    BILATERAL_READY.load(Ordering::SeqCst)
}

/// Convenience aggregate readiness – usable by UI gating logic.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub fn is_sdk_fully_ready() -> bool {
    is_sdk_context_initialized() && is_bilateral_ready()
}

#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub fn is_bilateral_ready() -> bool {
    true
}

#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub fn is_sdk_fully_ready() -> bool {
    is_sdk_context_initialized()
}
