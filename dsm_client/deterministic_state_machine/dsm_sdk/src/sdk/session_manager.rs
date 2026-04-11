// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Session Manager
//!
//! Read-model / projection over existing Rust sources of truth.
//! `SessionManager` never duplicates state that already lives in `AppState`,
//! `SDK_READY`, or other Rust components. It reads from them and computes
//! the projection on every `compute_snapshot()` call.
//!
//! **Owned state** (things with no other Rust home):
//! - Lock state (enabled, locked, method, lock_on_pause)
//! - Hardware facts (fed from Kotlin via JNI)
//! - Fatal error
//! - Wallet refresh hint
//! - SDK readiness flag (set by JNI bootstrap, read by all layers)
//!
//! **Projection inputs** (read from existing Rust truth):
//! - `SDK_READY` atomic (owned here, set by bootstrap)
//! - `HAS_IDENTITY` from `AppState::get_has_identity()`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use dsm::types::proto as generated;
use once_cell::sync::Lazy;
use prost::Message;

use crate::sdk::app_state::AppState;

/// SDK readiness flag — set by bootstrap, read by session manager and JNI guards.
/// Lives here (always compiled) rather than in the JNI module (cfg-gated).
pub static SDK_READY: AtomicBool = AtomicBool::new(false);

/// Set SDK readiness flag.
pub fn set_sdk_ready(ready: bool) {
    SDK_READY.store(ready, Ordering::SeqCst);
    log::info!("session_manager::set_sdk_ready: SDK_READY={}", ready);
}

/// Process-global session manager instance.
pub static SESSION_MANAGER: Lazy<Mutex<SessionManager>> =
    Lazy::new(|| Mutex::new(SessionManager::default()));

const LOCK_ENABLED_KEY: &str = "lock_enabled";
const LOCK_METHOD_KEY: &str = "lock_method";
const LOCK_ON_PAUSE_KEY: &str = "lock_on_pause";
const LOCK_LOCKED_KEY: &str = "lock_locked";

/// Hardware facts reported by Kotlin (no other Rust source for these).
#[derive(Debug, Clone, Default)]
pub struct HardwareFacts {
    pub app_foreground: bool,
    pub ble_enabled: bool,
    pub ble_permissions: bool,
    pub ble_scanning: bool,
    pub ble_advertising: bool,
    pub qr_available: bool,
    pub qr_active: bool,
    pub camera_permission: bool,
    pub battery_charging: bool,
    pub battery_level_percent: u32,
}

/// Session manager — sole authority for session state projection.
#[derive(Debug, Clone)]
pub struct SessionManager {
    // --- Owned state (no other Rust home) ---
    pub lock_enabled: bool,
    pub lock_locked: bool,
    pub lock_method: String,
    pub lock_on_pause: bool,
    pub fatal_error: Option<String>,
    pub wallet_refresh_hint: u64,
    pub hardware: HardwareFacts,
    pub lock_state_initialized: bool,
    /// Set true while DBRW silicon-fingerprint enrollment + sdkBootstrapStrict
    /// are running. Cleared by mark_securing_complete or mark_securing_aborted.
    /// compute_phase exposes this as the `securing_device` phase, beating
    /// `needs_genesis` so external `publishSessionState` calls during the
    /// 100-500ms securing window cannot bounce the UI back to INITIALIZE.
    pub securing_in_progress: bool,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            lock_enabled: false,
            lock_locked: false,
            lock_method: "none".to_string(),
            lock_on_pause: true,
            fatal_error: None,
            wallet_refresh_hint: 0,
            hardware: HardwareFacts::default(),
            lock_state_initialized: false,
            securing_in_progress: false,
        }
    }
}

impl SessionManager {
    fn read_pref(key: &str) -> String {
        AppState::ensure_storage_loaded();
        AppState::handle_app_state_request(key, "get", "")
    }

    fn write_pref(key: &str, value: &str) {
        AppState::ensure_storage_loaded();
        let _ = AppState::handle_app_state_request(key, "set", value);
    }

    fn parse_pref_bool(raw: &str, default: bool) -> bool {
        match raw {
            "true" => true,
            "false" => false,
            _ => default,
        }
    }

    fn sanitize_lock_method(enabled: bool, method: &str) -> String {
        match method {
            "pin" | "combo" | "biometric" => method.to_string(),
            "none" if !enabled => "none".to_string(),
            _ if enabled => "pin".to_string(),
            _ => "none".to_string(),
        }
    }

    pub fn configure_lock(&mut self, enabled: bool, method: &str, lock_on_pause: bool) {
        self.lock_enabled = enabled;
        self.lock_method = Self::sanitize_lock_method(enabled, method);
        self.lock_on_pause = lock_on_pause;
        if !enabled {
            self.lock_locked = false;
            self.persist_lock_state_to_app_state();
        }
    }

    pub fn set_locked(&mut self, locked: bool) {
        self.lock_locked = self.lock_enabled && locked;
        self.persist_lock_state_to_app_state();
    }

    pub fn lock_now(&mut self) {
        self.set_locked(true);
    }

    pub fn unlock_now(&mut self) {
        self.set_locked(false);
    }

    pub fn sync_lock_config_from_app_state(&mut self) {
        let enabled = Self::parse_pref_bool(&Self::read_pref(LOCK_ENABLED_KEY), self.lock_enabled);
        let method_raw = Self::read_pref(LOCK_METHOD_KEY);
        let method = if method_raw.is_empty() {
            self.lock_method.clone()
        } else {
            method_raw
        };
        let lock_on_pause =
            Self::parse_pref_bool(&Self::read_pref(LOCK_ON_PAUSE_KEY), self.lock_on_pause);
        self.configure_lock(enabled, &method, lock_on_pause);
        if !self.lock_state_initialized {
            self.lock_state_initialized = true;
            if self.lock_enabled {
                // Fresh process start: an enabled lock must come back locked instead of
                // silently inheriting an unlocked in-memory session from a dead process.
                self.lock_now();
            } else {
                self.unlock_now();
            }
            return;
        }
        let persisted_locked =
            Self::parse_pref_bool(&Self::read_pref(LOCK_LOCKED_KEY), self.lock_locked);
        self.lock_locked = self.lock_enabled && persisted_locked;
    }

    pub fn persist_lock_config_to_app_state(&self) {
        Self::write_pref(
            LOCK_ENABLED_KEY,
            if self.lock_enabled { "true" } else { "false" },
        );
        Self::write_pref(LOCK_METHOD_KEY, &self.lock_method);
        Self::write_pref(
            LOCK_ON_PAUSE_KEY,
            if self.lock_on_pause { "true" } else { "false" },
        );
        self.persist_lock_state_to_app_state();
    }

    pub fn persist_lock_state_to_app_state(&self) {
        Self::write_pref(
            LOCK_LOCKED_KEY,
            if self.lock_locked { "true" } else { "false" },
        );
    }

    /// Mark the start of the DBRW silicon-fingerprint enrollment + sdkBootstrapStrict
    /// window. `compute_phase` will report `securing_device` until cleared.
    pub fn mark_securing_started(&mut self) {
        self.securing_in_progress = true;
        log::info!("SessionManager: mark_securing_started");
    }

    /// Mark successful completion of the securing window.
    pub fn mark_securing_complete(&mut self) {
        self.securing_in_progress = false;
        log::info!("SessionManager: mark_securing_complete");
    }

    /// Mark the securing window as aborted (failure path). Same flag effect as
    /// `mark_securing_complete`; the wipe/recovery happens in Kotlin.
    pub fn mark_securing_aborted(&mut self) {
        self.securing_in_progress = false;
        log::warn!("SessionManager: mark_securing_aborted");
    }

    /// Compute the current session phase by reading from authoritative Rust sources.
    /// Called on every snapshot — never caches `sdk_ready` or `has_identity`.
    fn compute_phase(&self) -> &'static str {
        if self.fatal_error.is_some() {
            return "error";
        }
        if !SDK_READY.load(Ordering::SeqCst) {
            return "runtime_loading";
        }
        if self.securing_in_progress {
            return "securing_device";
        }
        if !AppState::get_has_identity() {
            return "needs_genesis";
        }
        if self.lock_locked {
            return "locked";
        }
        "wallet_ready"
    }

    /// Compute identity status from existing Rust truth.
    fn compute_identity_status(&self) -> &'static str {
        if !SDK_READY.load(Ordering::SeqCst) {
            return "runtime_not_ready";
        }
        if AppState::get_has_identity() {
            return "ready";
        }
        "missing"
    }

    /// Compute env config status.
    fn compute_env_config_status(&self) -> &'static str {
        if !SDK_READY.load(Ordering::SeqCst) {
            return "loading";
        }
        "ready"
    }

    /// Apply hardware facts from Kotlin's `SessionHardwareFactsProto`.
    pub fn apply_hardware_facts(&mut self, facts: &generated::SessionHardwareFactsProto) {
        self.hardware.app_foreground = facts.app_foreground;
        self.hardware.ble_enabled = facts.ble_enabled;
        self.hardware.ble_permissions = facts.ble_permissions;
        self.hardware.ble_scanning = facts.ble_scanning;
        self.hardware.ble_advertising = facts.ble_advertising;
        self.hardware.qr_available = facts.qr_available;
        self.hardware.qr_active = facts.qr_active;
        self.hardware.camera_permission = facts.camera_permission;
        self.hardware.battery_charging = facts.battery_charging;
        self.hardware.battery_level_percent = facts.battery_level_percent.min(100);

        // Lock policy: if app went to background and lock_on_pause is set, lock,
        // except while the native QR/camera flow is actively running.
        if !facts.app_foreground && self.lock_on_pause && self.lock_enabled && !self.lock_locked {
            if facts.qr_active {
                log::info!(
                    "SessionManager: skipped auto-lock on app background because QR scanner is active"
                );
            } else {
                self.lock_now();
                log::info!("SessionManager: auto-locked on app background (lock_on_pause policy)");
            }
        }
    }

    /// Build the full `AppSessionStateProto` snapshot.
    /// Reads from existing Rust truth on every call — no caching of projection inputs.
    pub fn compute_snapshot(&self) -> generated::AppSessionStateProto {
        generated::AppSessionStateProto {
            phase: self.compute_phase().to_string(),
            identity_status: self.compute_identity_status().to_string(),
            env_config_status: self.compute_env_config_status().to_string(),
            lock_status: Some(generated::AppSessionLockStatusProto {
                enabled: self.lock_enabled,
                locked: self.lock_locked,
                method: self.lock_method.clone(),
                lock_on_pause: self.lock_on_pause,
            }),
            hardware_status: Some(generated::AppSessionHardwareStatusProto {
                app_foreground: self.hardware.app_foreground,
                ble: Some(generated::AppSessionBleHardwareStatusProto {
                    enabled: self.hardware.ble_enabled,
                    permissions_granted: self.hardware.ble_permissions,
                    scanning: self.hardware.ble_scanning,
                    advertising: self.hardware.ble_advertising,
                }),
                qr: Some(generated::AppSessionQrHardwareStatusProto {
                    available: self.hardware.qr_available,
                    active: self.hardware.qr_active,
                    camera_permission: self.hardware.camera_permission,
                }),
                battery: Some(generated::AppSessionBatteryHardwareStatusProto {
                    charging: self.hardware.battery_charging,
                    level_percent: self.hardware.battery_level_percent,
                }),
            }),
            fatal_error: self.fatal_error.clone().unwrap_or_default(),
            wallet_refresh_hint: self.wallet_refresh_hint,
        }
    }
}

/// Encode an `AppSessionStateProto` as FramedEnvelopeV3: `[0x03][Envelope(payload=SessionStateResponse)]`.
/// All session state bytes leaving Rust are envelope-wrapped — Invariant #1.
fn envelope_wrap_snapshot(snapshot: generated::AppSessionStateProto) -> Vec<u8> {
    let envelope = generated::Envelope {
        version: 3,
        headers: None,
        message_id: vec![0u8; 16],
        payload: Some(generated::envelope::Payload::SessionStateResponse(snapshot)),
    };
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03); // Framing byte for Envelope v3
    envelope.encode(&mut buf).unwrap_or(());
    buf
}

/// Acquire the global session manager lock and return envelope-wrapped snapshot bytes.
/// Returns `[0x03][Envelope(SessionStateResponse)]` — Kotlin relays untouched to WebView.
pub fn get_session_snapshot_bytes() -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    envelope_wrap_snapshot(mgr.compute_snapshot())
}

/// Update hardware facts and return the new envelope-wrapped snapshot bytes.
/// Returns `[0x03][Envelope(SessionStateResponse)]` — Kotlin relays untouched to WebView.
pub fn update_hardware_and_snapshot(facts_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let facts = generated::SessionHardwareFactsProto::decode(facts_bytes)
        .map_err(|e| format!("decode SessionHardwareFactsProto failed: {e}"))?;
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.apply_hardware_facts(&facts);
    Ok(envelope_wrap_snapshot(mgr.compute_snapshot()))
}

/// Set a fatal error on the session manager and return envelope-wrapped snapshot bytes.
/// Used by Kotlin to report pre-bootstrap failures (env config errors).
pub fn set_fatal_error_and_snapshot(message: &str) -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.fatal_error = Some(message.to_string());
    log::error!("session_manager::set_fatal_error: {message}");
    envelope_wrap_snapshot(mgr.compute_snapshot())
}

/// Clear fatal error and return envelope-wrapped snapshot bytes.
pub fn clear_fatal_error_and_snapshot() -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.fatal_error = None;
    log::info!("session_manager::clear_fatal_error");
    envelope_wrap_snapshot(mgr.compute_snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that touch shared global state (SDK_READY, HAS_IDENTITY).
    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    /// Helper: set up test mode, acquire the global lock, and reset shared state.
    fn setup_test_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        let _ =
            crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
        AppState::reset_memory_for_testing();
        AppState::ensure_storage_loaded();
        SDK_READY.store(false, Ordering::SeqCst);
        guard
    }

    #[test]
    fn default_phase_is_runtime_loading() {
        let _g = setup_test_env();
        // SDK_READY already reset to false by setup_test_env
        let mgr = SessionManager::default();
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "runtime_loading");
        assert_eq!(snap.identity_status, "runtime_not_ready");
    }

    #[test]
    fn phase_needs_genesis_when_ready_but_no_identity() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let mgr = SessionManager::default();
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "needs_genesis");
        assert_eq!(snap.identity_status, "missing");
    }

    #[test]
    fn phase_locked_when_lock_set() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);
        AppState::set_has_identity(true);

        let mgr = SessionManager {
            lock_locked: true,
            ..SessionManager::default()
        };
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "locked");
        assert_eq!(snap.identity_status, "ready");
    }

    #[test]
    fn securing_in_progress_takes_precedence_over_needs_genesis() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);
        // has_identity is false by default — normally computes needs_genesis.

        let mut mgr = SessionManager::default();
        let snap_before = mgr.compute_snapshot();
        assert_eq!(
            snap_before.phase, "needs_genesis",
            "precondition: without the securing flag, phase must be needs_genesis"
        );

        mgr.mark_securing_started();
        assert!(mgr.securing_in_progress);
        let snap_during = mgr.compute_snapshot();
        assert_eq!(
            snap_during.phase, "securing_device",
            "with securing_in_progress=true, phase must beat needs_genesis"
        );

        mgr.mark_securing_complete();
        assert!(!mgr.securing_in_progress);
        let snap_after = mgr.compute_snapshot();
        assert_eq!(
            snap_after.phase, "needs_genesis",
            "after mark_securing_complete, phase falls back to needs_genesis"
        );
    }

    #[test]
    fn securing_in_progress_yields_to_fatal_error() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let mut mgr = SessionManager {
            fatal_error: Some("boot failure".to_string()),
            ..SessionManager::default()
        };
        mgr.mark_securing_started();

        let snap = mgr.compute_snapshot();
        assert_eq!(
            snap.phase, "error",
            "fatal_error must take priority over securing_device"
        );
        assert_eq!(snap.fatal_error, "boot failure");
    }

    #[test]
    fn securing_aborted_clears_flag() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let mut mgr = SessionManager::default();
        mgr.mark_securing_started();
        assert!(mgr.securing_in_progress);
        assert_eq!(mgr.compute_snapshot().phase, "securing_device");

        mgr.mark_securing_aborted();
        assert!(
            !mgr.securing_in_progress,
            "mark_securing_aborted must clear the flag"
        );
        assert_eq!(
            mgr.compute_snapshot().phase,
            "needs_genesis",
            "after abort, phase falls back to needs_genesis"
        );
    }

    #[test]
    fn fatal_error_overrides_phase() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);
        let mgr = SessionManager {
            fatal_error: Some("test error".to_string()),
            ..SessionManager::default()
        };
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "error");
        assert_eq!(snap.fatal_error, "test error");
    }

    #[test]
    fn auto_lock_on_background() {
        let _g = setup_test_env();
        let mut mgr = SessionManager {
            lock_enabled: true,
            lock_on_pause: true,
            ..SessionManager::default()
        };

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: false,
            ..Default::default()
        };
        mgr.apply_hardware_facts(&facts);
        assert!(mgr.lock_locked);
    }

    #[test]
    fn no_auto_lock_when_policy_disabled() {
        let _g = setup_test_env();
        let mut mgr = SessionManager {
            lock_enabled: true,
            lock_on_pause: false,
            ..SessionManager::default()
        };

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: false,
            ..Default::default()
        };
        mgr.apply_hardware_facts(&facts);
        assert!(!mgr.lock_locked);
    }

    #[test]
    fn no_auto_lock_while_qr_scanner_active() {
        let _g = setup_test_env();
        let mut mgr = SessionManager {
            lock_enabled: true,
            lock_on_pause: true,
            ..SessionManager::default()
        };

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: false,
            qr_active: true,
            ..Default::default()
        };
        mgr.apply_hardware_facts(&facts);
        assert!(!mgr.lock_locked);
    }

    #[test]
    fn hardware_facts_round_trip() {
        let _g = setup_test_env();
        // SDK_READY already reset to false by setup_test_env

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: true,
            ble_enabled: true,
            ble_permissions: true,
            ble_scanning: false,
            ble_advertising: true,
            qr_available: true,
            qr_active: false,
            camera_permission: true,
            battery_charging: false,
            battery_level_percent: 100,
        };
        let bytes = facts.encode_to_vec();
        let result = update_hardware_and_snapshot(&bytes);
        assert!(result.is_ok());

        // Return is envelope-wrapped: [0x03][Envelope(SessionStateResponse)]
        let envelope_bytes = result.unwrap();
        assert_eq!(envelope_bytes[0], 0x03, "must have 0x03 framing byte");
        let envelope = generated::Envelope::decode(&envelope_bytes[1..]).unwrap();
        let snap = match envelope.payload {
            Some(generated::envelope::Payload::SessionStateResponse(s)) => s,
            other => panic!("expected SessionStateResponse, got {:?}", other),
        };
        let hw = snap.hardware_status.unwrap();
        assert!(hw.app_foreground);
        let ble = hw.ble.unwrap();
        assert!(ble.enabled);
        assert!(ble.advertising);
        assert!(!ble.scanning);
    }

    #[test]
    fn sync_lock_config_reads_native_prefs() {
        let _g = setup_test_env();
        AppState::handle_app_state_request(LOCK_ENABLED_KEY, "set", "true");
        AppState::handle_app_state_request(LOCK_METHOD_KEY, "set", "combo");
        AppState::handle_app_state_request(LOCK_ON_PAUSE_KEY, "set", "false");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state();

        assert!(mgr.lock_enabled);
        assert_eq!(mgr.lock_method, "combo");
        assert!(!mgr.lock_on_pause);
        assert!(mgr.lock_locked);
    }

    #[test]
    fn cold_start_with_enabled_lock_defaults_to_locked() {
        let _g = setup_test_env();
        AppState::handle_app_state_request(LOCK_ENABLED_KEY, "set", "true");
        AppState::handle_app_state_request(LOCK_METHOD_KEY, "set", "pin");
        AppState::handle_app_state_request(LOCK_ON_PAUSE_KEY, "set", "true");
        AppState::handle_app_state_request(LOCK_LOCKED_KEY, "set", "false");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state();

        assert!(mgr.lock_enabled);
        assert!(mgr.lock_locked);
        assert_eq!(
            AppState::handle_app_state_request(LOCK_LOCKED_KEY, "get", ""),
            "true"
        );
    }

    #[test]
    fn runtime_unlock_persists_until_next_process_start() {
        let _g = setup_test_env();
        AppState::handle_app_state_request(LOCK_ENABLED_KEY, "set", "true");
        AppState::handle_app_state_request(LOCK_METHOD_KEY, "set", "pin");
        AppState::handle_app_state_request(LOCK_ON_PAUSE_KEY, "set", "true");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state();
        assert!(mgr.lock_locked);

        mgr.unlock_now();
        assert_eq!(
            AppState::handle_app_state_request(LOCK_LOCKED_KEY, "get", ""),
            "false"
        );

        mgr.sync_lock_config_from_app_state();
        assert!(!mgr.lock_locked);

        let mut restarted = SessionManager::default();
        restarted.sync_lock_config_from_app_state();
        assert!(restarted.lock_locked);
    }

    #[test]
    fn snapshot_bytes_are_envelope_wrapped() {
        let _g = setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let bytes = get_session_snapshot_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x03, "must have 0x03 framing byte");
        let envelope = generated::Envelope::decode(&bytes[1..]).unwrap();
        match envelope.payload {
            Some(generated::envelope::Payload::SessionStateResponse(s)) => {
                assert_eq!(s.phase, "needs_genesis");
            }
            other => panic!("expected SessionStateResponse, got {:?}", other),
        }
    }
}
