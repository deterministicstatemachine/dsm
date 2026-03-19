//! BLE backend bridge for handling platform BLE commands via SDK (protobuf-only).
//!
//! Policy:
//! - Transport strictly uses Envelope v3 with ArgPack CODEC_PROTO as defined in
//!   `proto/dsm_app.proto` and the public protocol reference
//! - Core/SDK never touches platform APIs directly; platforms register a backend here.
//! - If no backend is registered, the router must return a deterministic, explicit error.

use std::sync::Arc;
#[cfg(any(test, debug_assertions))]
use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::OnceCell;

// Re-export prost-generated protobuf types as `pb` using the same canonical
// module the router uses (`dsm::types::proto`). This keeps type identities
// consistent across the SDK router and the backend trait.
pub use dsm::types::proto as pb;

/// Trait implemented by the platform (Android/iOS/WASM host) to perform BLE commands.
pub trait BleBackend: Send + Sync + 'static {
    /// Handle a BLE command and synchronously return a response payload.
    fn handle_command(&self, cmd: pb::BleCommand) -> pb::BleCommandResponse;
}

static BLE_BACKEND: OnceCell<Arc<dyn BleBackend>> = OnceCell::new();

// Test-only flag: when set, pretend no backend is installed even if registered.
// Default is false; only tests should toggle this.
// NOTE: This flag is only available in debug/test builds for safety.
#[cfg(any(test, debug_assertions))]
static FORCE_NO_BACKEND: AtomicBool = AtomicBool::new(false);

/// Register the platform BLE backend. This is a one-shot installer; subsequent calls are ignored.
pub fn register_ble_backend<B: BleBackend>(backend: B) {
    let _ = BLE_BACKEND.set(Arc::new(backend));
}

/// Try to get a reference to the registered backend.
pub fn get_ble_backend() -> Option<&'static Arc<dyn BleBackend>> {
    #[cfg(any(test, debug_assertions))]
    if FORCE_NO_BACKEND.load(Ordering::Relaxed) {
        return None;
    }
    BLE_BACKEND.get()
}

/// Test/helper: force the registry to behave as if no backend is installed.
/// This does not mutate the underlying OnceCell; it only gates access until toggled back.
/// Only available in test/debug builds.
#[cfg(any(test, debug_assertions))]
pub fn force_no_backend_for_tests(v: bool) {
    FORCE_NO_BACKEND.store(v, Ordering::Relaxed);
}

#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub mod android_backend {
    use super::{BleBackend, pb};
    use crate::bluetooth::android_ble_bridge::get_global_android_bridge;

    /// Minimal Android BLE backend that delegates to the platform service.
    /// Scanning/advertising/connection lifecycle are handled in Kotlin; this backend
    /// primarily exists to acknowledge commands and keep the router integration uniform.
    pub struct AndroidBleBackend;

    impl AndroidBleBackend {
        pub fn new() -> Self {
            Self
        }
        fn ok(msg: &str, payload: Vec<u8>) -> pb::BleCommandResponse {
            pb::BleCommandResponse {
                ok: true,
                message: msg.to_string(),
                payload,
            }
        }
        fn err(msg: &str) -> pb::BleCommandResponse {
            pb::BleCommandResponse {
                ok: false,
                message: msg.to_string(),
                payload: vec![],
            }
        }
    }

    impl BleBackend for AndroidBleBackend {
        fn handle_command(&self, cmd: pb::BleCommand) -> pb::BleCommandResponse {
            use pb::ble_command::Cmd;
            match cmd.cmd {
                Some(Cmd::StartScan(_)) => Self::ok("scan handled by Kotlin", vec![]),
                Some(Cmd::StopScan(_)) => Self::ok("stop scan handled by Kotlin", vec![]),
                Some(Cmd::StartAdvertising(_)) => Self::ok("advertising handled by Kotlin", vec![]),
                Some(Cmd::StopAdvertising(_)) => {
                    Self::ok("stop advertising handled by Kotlin", vec![])
                }
                Some(Cmd::ConnectDevice(_)) => Self::ok("connect handled by Kotlin", vec![]),
                Some(Cmd::DisconnectDevice(_)) => Self::ok("disconnect handled by Kotlin", vec![]),
                Some(Cmd::WriteCharacteristic(w)) => {
                    // Optionally, if a global bridge is present, we can treat payload as pre-framed
                    if let Some(_bridge) = get_global_android_bridge() { /* no-op for now */ }
                    Self::ok("write queued to platform", w.data)
                }
                Some(Cmd::ReadCharacteristic(_)) => Self::ok("read handled by Kotlin", vec![]),
                None => Self::err("empty BleCommand"),
            }
        }
    }
}

#[cfg(test)]
/// Reset the BLE backend singleton for testing.
///
/// # Safety
/// This function is UNSAFE and should ONLY be called in single-threaded test contexts.
/// Calling this while the backend is in use will cause undefined behavior.
///
/// Use `#[serial_test]` attribute to ensure tests run sequentially.
pub unsafe fn reset_ble_backend_for_tests() {
    // SAFETY: Caller guarantees single-threaded context and no active references
    std::ptr::write(
        std::ptr::addr_of!(BLE_BACKEND) as *mut OnceCell<Arc<dyn BleBackend>>,
        OnceCell::new(),
    );
    FORCE_NO_BACKEND.store(false, Ordering::Relaxed);
}
