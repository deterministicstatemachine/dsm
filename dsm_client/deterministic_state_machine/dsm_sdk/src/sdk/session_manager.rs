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

/// Set while C-DBRW bootstrap is in progress (between PHASE_STARTED and finalization).
/// Forces phase = "securing_device" so the progress screen stays up during the 34-second
/// SiliconFingerprint derivation, instead of falling back to "needs_genesis".
pub static BOOTSTRAP_SECURING: AtomicBool = AtomicBool::new(false);

/// Latches once this device's identity has reached publication quorum.
///
/// Publication is monotonic — a verified quorum does not become unverified when
/// a node later goes unreachable, because the nodes still hold the tuple. The
/// latch therefore only ever goes false -> true, and exists so the phase
/// computation does not hit SQLite on every snapshot.
pub static IDENTITY_PUBLISHED: AtomicBool = AtomicBool::new(false);

/// Set SDK readiness flag.
pub fn set_sdk_ready(ready: bool) {
    SDK_READY.store(ready, Ordering::SeqCst);
    log::info!("session_manager::set_sdk_ready: SDK_READY={}", ready);
}

/// Record a failed startup as the session's fatal error.
///
/// The page learns the phase from the session. Without this a failed startup
/// left the phase at `runtime_loading`, and the screen said the runtime was
/// starting while nothing was: a device whose store refused its schema sat on
/// that screen for good, and only the device log said why. This reads nothing
/// from the store, because the store refusing is one of the failures it records.
pub fn record_startup_failure(message: &str) {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.fatal_error = Some(message.to_string());
    mgr.fatal_is_startup_failure = true;
    log::error!("session_manager::record_startup_failure: {message}");
}

/// Startup succeeded: a failure an earlier attempt recorded is no longer
/// true, so it goes. A fatal error anyone else reported stays.
pub fn clear_startup_failure() {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    if mgr.fatal_is_startup_failure {
        mgr.fatal_error = None;
        mgr.fatal_is_startup_failure = false;
    }
}

/// Process-global session manager instance.
pub static SESSION_MANAGER: Lazy<Mutex<SessionManager>> =
    Lazy::new(|| Mutex::new(SessionManager::default()));

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
    /// Wrong tries since the last opening, as `app_lock` stores them.
    pub lock_misses: u32,
    pub fatal_error: Option<String>,
    /// Whether `fatal_error` is a failed startup, which a later successful
    /// startup takes back. An error anyone else reported is theirs to clear.
    pub fatal_is_startup_failure: bool,
    pub wallet_refresh_hint: u64,
    pub hardware: HardwareFacts,
    pub lock_state_initialized: bool,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            lock_enabled: false,
            lock_locked: false,
            lock_method: "none".to_string(),
            lock_on_pause: true,
            lock_misses: 0,
            fatal_error: None,
            fatal_is_startup_failure: false,
            wallet_refresh_hint: 0,
            hardware: HardwareFacts::default(),
            lock_state_initialized: false,
        }
    }
}

impl SessionManager {
    fn read_pref(key: &str) -> Option<String> {
        AppState::get_pref(key)
    }

    fn write_pref(key: &str, value: &str) -> Result<(), dsm::types::error::DsmError> {
        AppState::set_pref(key, value)
    }

    /// A stored lock flag, or `current` when none is stored. A stored value
    /// that is neither `true` nor `false` is an error, never read as `current`.
    fn pref_bool(key: &str, current: bool) -> Result<bool, dsm::types::error::DsmError> {
        match Self::read_pref(key).as_deref() {
            None => Ok(current),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(other) => Err(dsm::types::error::DsmError::InvalidState(format!(
                "lock setting {key} holds {other:?}, not true or false"
            ))),
        }
    }

    /// Take the lock in as `app_lock` holds it: on exactly while a PIN or
    /// pattern is enrolled, by the method it was enrolled for.
    fn load_lock(&mut self, lock_on_pause: bool) -> Result<(), dsm::types::error::DsmError> {
        let enrolled = crate::sdk::app_lock::enrolled_method()?;
        let enabled = enrolled.is_some();
        self.lock_method = match enrolled {
            Some(method) => method.name(),
            None => "none",
        }
        .to_string();
        self.lock_enabled = enabled;
        self.lock_on_pause = lock_on_pause;
        self.lock_misses = crate::sdk::app_lock::misses()?;
        if enabled {
            Ok(())
        } else {
            self.set_locked(enabled)
        }
    }

    /// Configure the lock as `session.configure_lock` asks: by "pin" or
    /// "combo", [`Self::enable_lock`]; by "none", [`Self::disable_lock`].
    pub fn configure_lock(
        &mut self,
        method: &str,
        lock_on_pause: bool,
        secret: &str,
    ) -> Result<(), dsm::types::error::DsmError> {
        match method {
            "none" => self.disable_lock(lock_on_pause),
            named => self.enable_lock(named, secret, lock_on_pause),
        }
    }

    fn require_open(&self) -> Result<(), dsm::types::error::DsmError> {
        if self.lock_locked {
            return Err(dsm::types::error::DsmError::invalid_operation(
                "the wallet is locked: open it before changing its lock",
            ));
        }
        Ok(())
    }

    /// Turn the lock on, only while the wallet is open, opened by `method`
    /// with `secret` (the PIN, or the pattern's buttons joined by ","). An
    /// empty `secret` keeps the one enrolled, which must be for `method`. The
    /// settings are stored before this returns, so a restart keeps them.
    pub fn enable_lock(
        &mut self,
        method: &str,
        secret: &str,
        lock_on_pause: bool,
    ) -> Result<(), dsm::types::error::DsmError> {
        self.require_open()?;
        let named = crate::sdk::app_lock::LockMethod::parse(method)?;
        if secret.is_empty() {
            let same = self.lock_enabled && self.lock_method == named.name();
            if !same {
                return Err(dsm::types::error::DsmError::invalid_operation(
                    "a new lock needs its PIN or pattern",
                ));
            }
        } else {
            crate::sdk::app_lock::enroll(named, secret)?;
        }
        self.load_lock(lock_on_pause)?;
        self.persist_lock_config_to_app_state()
    }

    /// Turn the lock off, only while the wallet is open, forgetting what was
    /// enrolled, and store the settings.
    pub fn disable_lock(&mut self, lock_on_pause: bool) -> Result<(), dsm::types::error::DsmError> {
        self.require_open()?;
        crate::sdk::app_lock::clear()?;
        self.load_lock(lock_on_pause)?;
        self.persist_lock_config_to_app_state()
    }

    /// Try to open the lock with its PIN or pattern. Rust checks it and counts
    /// the miss; the session opens only on a match.
    pub fn try_unlock(
        &mut self,
        secret: &str,
    ) -> Result<crate::sdk::app_lock::Tried, dsm::types::error::DsmError> {
        if !self.lock_enabled {
            self.unlock_now()?;
            return Ok(crate::sdk::app_lock::Tried::Opened);
        }
        let method = crate::sdk::app_lock::LockMethod::parse(&self.lock_method)?;
        let tried = crate::sdk::app_lock::try_secret(method, secret)?;
        self.lock_misses = crate::sdk::app_lock::misses()?;
        if tried == crate::sdk::app_lock::Tried::Opened {
            self.unlock_now()?;
        }
        Ok(tried)
    }

    /// Try to open the lock with the wallet's recovery phrase.
    pub fn try_unlock_with_phrase(
        &mut self,
        phrase: &str,
    ) -> Result<crate::sdk::app_lock::PhraseTried, dsm::types::error::DsmError> {
        let tried = crate::sdk::app_lock::try_phrase(phrase)?;
        self.lock_misses = crate::sdk::app_lock::misses()?;
        if tried == crate::sdk::app_lock::PhraseTried::Opened {
            self.unlock_now()?;
        }
        Ok(tried)
    }

    /// Lock or unlock. A lock takes effect in memory even if it cannot be
    /// persisted (the error is still returned); an unlock takes effect only
    /// once it is persisted.
    pub fn set_locked(&mut self, locked: bool) -> Result<(), dsm::types::error::DsmError> {
        if self.lock_enabled && locked {
            self.lock_locked = true;
            Self::write_pref(LOCK_LOCKED_KEY, "true")
        } else {
            Self::write_pref(LOCK_LOCKED_KEY, "false")?;
            self.lock_locked = false;
            Ok(())
        }
    }

    pub fn lock_now(&mut self) -> Result<(), dsm::types::error::DsmError> {
        self.set_locked(true)
    }

    /// Open the session. Reached only from a check that passed
    /// ([`Self::try_unlock`], [`Self::try_unlock_with_phrase`]) or from a lock
    /// that is not enabled; no route opens it unchecked.
    fn unlock_now(&mut self) -> Result<(), dsm::types::error::DsmError> {
        self.set_locked(false)
    }

    /// Bring the lock configuration and state in from the stored settings. A
    /// setting never stored keeps the manager's own.
    pub fn sync_lock_config_from_app_state(&mut self) -> Result<(), dsm::types::error::DsmError> {
        let lock_on_pause = Self::pref_bool(LOCK_ON_PAUSE_KEY, self.lock_on_pause)?;
        self.load_lock(lock_on_pause)?;
        if !self.lock_state_initialized {
            self.lock_state_initialized = true;
            // Fresh process start: an enabled lock must come back locked instead of
            // silently inheriting an unlocked in-memory session from a dead process.
            return if self.lock_enabled {
                self.lock_now()
            } else {
                self.unlock_now()
            };
        }
        let persisted_locked = Self::pref_bool(LOCK_LOCKED_KEY, self.lock_locked)?;
        self.lock_locked = self.lock_enabled && persisted_locked;
        Ok(())
    }

    pub fn persist_lock_config_to_app_state(&self) -> Result<(), dsm::types::error::DsmError> {
        Self::write_pref(
            LOCK_ON_PAUSE_KEY,
            if self.lock_on_pause { "true" } else { "false" },
        )?;
        Self::write_pref(
            LOCK_LOCKED_KEY,
            if self.lock_locked { "true" } else { "false" },
        )
    }

    /// Compute the current session phase by reading from authoritative Rust sources.
    /// Called on every snapshot — never caches `sdk_ready` or `has_identity`.
    fn compute_phase(&self) -> &'static str {
        let fatal = self.fatal_error.is_some();
        let securing = BOOTSTRAP_SECURING.load(Ordering::SeqCst);
        let sdk_ready = SDK_READY.load(Ordering::SeqCst);
        let has_id = AppState::get_has_identity();
        // Short-circuits: the publication lookup resolves the device id, which
        // requires storage to be initialised. With no identity there is nothing
        // to publish, so never ask.
        let published = has_id && Self::identity_published();
        let locked = self.lock_locked;

        let phase = if fatal {
            "error"
        } else if securing {
            // If C-DBRW bootstrap is actively in progress (Kotlin sent BOOTSTRAP_PHASE_STARTED),
            // show the securing screen even while SDK_READY is still false.  The 34-second
            // SiliconFingerprint derivation window falls here; without this check the phase
            // would stay "runtime_loading" the whole time and the progress screen would never show.
            "securing_device"
        } else if !sdk_ready {
            "runtime_loading"
        } else if !has_id {
            "needs_genesis"
        } else if !published {
            // Local genesis is durable but the identity is not yet resolvable by
            // peers. The wallet is NOT ready: online sends to this device cannot
            // be addressed and authenticated storage writes will 401.
            "publication_pending"
        } else if locked {
            "locked"
        } else {
            "wallet_ready"
        };

        log::info!(
            "COMPUTE_PHASE: fatal={} securing={} sdk_ready={} has_id={} published={} locked={} -> phase={}",
            fatal,
            securing,
            sdk_ready,
            has_id,
            published,
            locked,
            phase
        );
        phase
    }

    /// Whether this device's identity has reached publication quorum.
    ///
    /// Cached in an atomic because publication is monotonic — once a quorum has
    /// been read-back verified the identity stays published — so the SQLite
    /// lookup only runs while still unpublished, not on every snapshot.
    fn identity_published() -> bool {
        if IDENTITY_PUBLISHED.load(Ordering::SeqCst) {
            return true;
        }
        // Resolving the device id reads app state, which panics if the storage
        // base dir has not been set. Phase computation runs on every snapshot
        // and must never panic, so treat "storage not ready" as "not yet
        // published" rather than asking.
        if crate::storage_utils::get_storage_base_dir().is_none() {
            return false;
        }
        let Some(device_id) = AppState::get_device_id() else {
            return false;
        };
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
        // Readiness is a recorded fact; a row that cannot be read establishes
        // none, so the identity is not ready yet.
        let ready = match crate::sdk::identity_publication::is_identity_ready(&device_id_b32) {
            Ok(ready) => ready,
            Err(e) => {
                log::warn!("session: identity publication state unreadable: {e}");
                false
            }
        };
        if ready {
            IDENTITY_PUBLISHED.store(true, Ordering::SeqCst);
        }
        ready
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
    pub fn apply_hardware_facts(
        &mut self,
        facts: &generated::SessionHardwareFactsProto,
    ) -> Result<(), dsm::types::error::DsmError> {
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
                self.lock_now()?;
                log::info!("SessionManager: auto-locked on app background (lock_on_pause policy)");
            }
        }
        Ok(())
    }

    /// Whether the BLE pairing loop may run: the app is in the foreground,
    /// Bluetooth is on and permitted, and there is an identity to pair as.
    /// The loop itself ends once no contact is left unpaired.
    pub fn pairing_may_run(&self, has_identity: bool) -> bool {
        self.hardware.app_foreground
            && self.hardware.ble_enabled
            && self.hardware.ble_permissions
            && has_identity
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
                misses_left: crate::sdk::app_lock::MISSES_BEFORE_PHRASE
                    .saturating_sub(self.lock_misses),
                phrase_required: self.lock_enabled
                    && self.lock_misses >= crate::sdk::app_lock::MISSES_BEFORE_PHRASE,
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
    crate::handlers::response_helpers::frame_local_envelope(
        generated::envelope::Payload::SessionStateResponse(snapshot),
    )
}

/// Acquire the global session manager lock and return envelope-wrapped snapshot bytes.
/// Returns `[0x03][Envelope(SessionStateResponse)]` — Kotlin relays untouched to WebView.
/// Whether the app is on screen, as the last session facts from the host said.
/// The inbox poller polls faster while it is.
pub fn app_in_foreground() -> bool {
    let mgr = match SESSION_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    mgr.hardware.app_foreground
}

/// Refuse `what` while the session is locked (S-LOCK). The lock's settings
/// are brought in first, so a process that has not read them yet reads them
/// now, and an enabled lock starts locked. Before the store exists there is
/// no wallet, and so no lock: nothing is set up for one to keep closed.
pub fn refuse_while_locked(what: &str) -> Result<(), String> {
    if crate::storage_utils::get_storage_base_dir().is_none() {
        return Ok(());
    }
    let mut mgr = match SESSION_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    mgr.sync_lock_config_from_app_state()
        .map_err(|e| format!("{what}: the session lock settings: {e}"))?;
    if mgr.lock_locked {
        return Err(format!("{what}: the wallet is locked; open it first"));
    }
    Ok(())
}

pub fn get_session_snapshot_bytes() -> Result<Vec<u8>, String> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state()
        .map_err(|e| format!("session lock settings: {e}"))?;
    Ok(envelope_wrap_snapshot(mgr.compute_snapshot()))
}

/// Update hardware facts and return the new envelope-wrapped snapshot bytes.
/// Returns `[0x03][Envelope(SessionStateResponse)]` — Kotlin relays untouched to WebView.
pub fn update_hardware_and_snapshot(facts_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let facts = generated::SessionHardwareFactsProto::decode(facts_bytes)
        .map_err(|e| format!("decode SessionHardwareFactsProto failed: {e}"))?;
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state()
        .map_err(|e| format!("session lock settings: {e}"))?;
    mgr.apply_hardware_facts(&facts)
        .map_err(|e| format!("session lock: {e}"))?;
    let snapshot = envelope_wrap_snapshot(mgr.compute_snapshot());
    let pairing_may_run = mgr.pairing_may_run(AppState::get_has_identity());
    drop(mgr);
    // Pairing follows the session, as the lock does.
    crate::bluetooth::pairing_follows(pairing_may_run);
    Ok(snapshot)
}

/// Whether the BLE pairing loop may run, on the session's last facts.
pub fn pairing_may_run_now() -> bool {
    SESSION_MANAGER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .pairing_may_run(AppState::get_has_identity())
}

/// Set a fatal error on the session manager and return envelope-wrapped snapshot bytes.
/// Used by Kotlin to report pre-bootstrap failures (env config errors).
pub fn set_fatal_error_and_snapshot(message: &str) -> Result<Vec<u8>, String> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state()
        .map_err(|e| format!("session lock settings: {e}"))?;
    mgr.fatal_error = Some(message.to_string());
    mgr.fatal_is_startup_failure = false;
    log::error!("session_manager::set_fatal_error: {message}");
    Ok(envelope_wrap_snapshot(mgr.compute_snapshot()))
}

/// Clear fatal error and return envelope-wrapped snapshot bytes.
pub fn clear_fatal_error_and_snapshot() -> Result<Vec<u8>, String> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state()
        .map_err(|e| format!("session lock settings: {e}"))?;
    mgr.fatal_error = None;
    mgr.fatal_is_startup_failure = false;
    log::info!("session_manager::clear_fatal_error");
    Ok(envelope_wrap_snapshot(mgr.compute_snapshot()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh store and fresh session globals. Every test here is serial:
    /// they share `SDK_READY`, the identity flags and the state file.
    fn setup_test_env() {
        crate::economic_fixtures::use_test_storage_dir();
        AppState::reset_for_testing();
        AppState::ensure_storage_loaded();
        SDK_READY.store(false, Ordering::SeqCst);
        // The publication latch is process-global and monotonic. Reset it here
        // so one test marking an identity published cannot leak into the next.
        IDENTITY_PUBLISHED.store(false, Ordering::SeqCst);
    }

    /// The session snapshot inside a local answer's framing.
    fn decode_snapshot(bytes: &[u8]) -> generated::AppSessionStateProto {
        assert_eq!(bytes[0], 0x03, "must have 0x03 framing byte");
        let envelope = generated::Envelope::decode(&bytes[1..]).expect("envelope");
        match envelope.payload {
            Some(generated::envelope::Payload::SessionStateResponse(s)) => s,
            other => panic!("expected SessionStateResponse, got {:?}", other),
        }
    }

    /// Mark the identity as published for tests whose subject is a LATER phase
    /// (lock, fatal error) and which therefore need to get past the publication
    /// gate. Tests that are about publication itself must not use this.
    fn mark_identity_published_for_test() {
        IDENTITY_PUBLISHED.store(true, Ordering::SeqCst);
    }

    /// A failed startup is the session's fatal error until a startup
    /// succeeds; an error someone else reported outlives a later success.
    #[test]
    #[serial_test::serial]
    fn a_startup_failure_is_the_sessions_error_until_a_startup_succeeds() {
        setup_test_env();
        clear_fatal_error_and_snapshot().expect("clear");
        let snapshot = || {
            SESSION_MANAGER
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .compute_snapshot()
        };
        record_startup_failure("startup: init_dsm_sdk failed: the store refused");
        assert_eq!(snapshot().phase, "error");
        assert_eq!(
            snapshot().fatal_error,
            "startup: init_dsm_sdk failed: the store refused"
        );
        clear_startup_failure();
        assert_eq!(snapshot().phase, "runtime_loading");
        assert_eq!(snapshot().fatal_error, "");

        set_fatal_error_and_snapshot("configuration file not found").expect("set");
        clear_startup_failure();
        assert_eq!(snapshot().fatal_error, "configuration file not found");
        clear_fatal_error_and_snapshot().expect("clear");
    }

    #[test]
    #[serial_test::serial]
    fn default_phase_is_runtime_loading() {
        setup_test_env();
        // SDK_READY already reset to false by setup_test_env
        let mgr = SessionManager::default();
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "runtime_loading");
        assert_eq!(snap.identity_status, "runtime_not_ready");
    }

    #[test]
    #[serial_test::serial]
    fn phase_needs_genesis_when_ready_but_no_identity() {
        setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let mgr = SessionManager::default();
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "needs_genesis");
        assert_eq!(snap.identity_status, "missing");
    }

    #[test]
    #[serial_test::serial]
    fn phase_locked_when_lock_set() {
        setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);
        AppState::set_has_identity(true).expect("identity mark");
        mark_identity_published_for_test();

        let mgr = SessionManager {
            lock_locked: true,
            ..SessionManager::default()
        };
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "locked");
        assert_eq!(snap.identity_status, "ready");
    }

    #[test]
    #[serial_test::serial]
    fn phase_is_publication_pending_when_identity_is_not_published() {
        setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);
        // Genesis committed locally -- the device HAS an identity -- but no node
        // has been read-back verified, so it is not resolvable by peers.
        AppState::set_has_identity(true).expect("identity mark");

        let mgr = SessionManager::default();
        let snap = mgr.compute_snapshot();
        assert_eq!(
            snap.phase, "publication_pending",
            "a durable local genesis must not report the wallet as ready"
        );

        // And once publication reaches quorum, the wallet becomes ready.
        mark_identity_published_for_test();
        let snap = mgr.compute_snapshot();
        assert_eq!(snap.phase, "wallet_ready");
    }

    #[test]
    #[serial_test::serial]
    fn fatal_error_overrides_phase() {
        setup_test_env();
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
    #[serial_test::serial]
    fn auto_lock_on_background() {
        setup_test_env();
        let mut mgr = SessionManager {
            lock_enabled: true,
            lock_on_pause: true,
            ..SessionManager::default()
        };

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: false,
            ..Default::default()
        };
        mgr.apply_hardware_facts(&facts).expect("apply facts");
        assert!(mgr.lock_locked);
    }

    #[test]
    #[serial_test::serial]
    fn no_auto_lock_when_policy_disabled() {
        setup_test_env();
        let mut mgr = SessionManager {
            lock_enabled: true,
            lock_on_pause: false,
            ..SessionManager::default()
        };

        let facts = generated::SessionHardwareFactsProto {
            app_foreground: false,
            ..Default::default()
        };
        mgr.apply_hardware_facts(&facts).expect("apply facts");
        assert!(!mgr.lock_locked);
    }

    #[test]
    #[serial_test::serial]
    fn no_auto_lock_while_qr_scanner_active() {
        setup_test_env();
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
        mgr.apply_hardware_facts(&facts).expect("apply facts");
        assert!(!mgr.lock_locked);
    }

    #[test]
    #[serial_test::serial]
    fn hardware_facts_round_trip() {
        setup_test_env();
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
        let envelope_bytes = update_hardware_and_snapshot(&bytes).expect("snapshot");
        let snap = decode_snapshot(&envelope_bytes);
        let hw = snap.hardware_status.expect("hardware status");
        assert!(hw.app_foreground);
        let ble = hw.ble.expect("ble status");
        assert!(ble.enabled);
        assert!(ble.advertising);
        assert!(!ble.scanning);
    }

    /// Pairing runs only while the app is in the foreground with Bluetooth
    /// on and permitted and an identity to pair as: the contacts screen used
    /// to start it when it saw an unpaired contact and stop it when it
    /// unmounted.
    #[test]
    fn pairing_runs_only_in_the_foreground_with_bluetooth_on_permitted_and_an_identity() {
        let facts =
            |app_foreground, ble_enabled, ble_permissions| generated::SessionHardwareFactsProto {
                app_foreground,
                ble_enabled,
                ble_permissions,
                ..Default::default()
            };
        let mut mgr = SessionManager::default();
        mgr.apply_hardware_facts(&facts(true, true, true))
            .expect("facts");
        assert!(mgr.pairing_may_run(true));
        assert!(!mgr.pairing_may_run(false), "no identity to pair as");
        for (foreground, on, permitted) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            mgr.apply_hardware_facts(&facts(foreground, on, permitted))
                .expect("facts");
            assert!(
                !mgr.pairing_may_run(true),
                "foreground={foreground} on={on} permitted={permitted}"
            );
        }
    }

    /// A pattern Rust enrolled is the lock, by its method, as the stored
    /// settings say.
    #[test]
    #[serial_test::serial]
    fn sync_lock_config_reads_the_enrolled_lock() {
        setup_test_env();
        crate::sdk::app_lock::enroll(
            crate::sdk::app_lock::LockMethod::Combo,
            "up,up,down,down,left,right,b,a",
        )
        .expect("enrolled");
        AppState::set_pref(LOCK_ON_PAUSE_KEY, "false").expect("pref");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state()
            .expect("lock settings");

        assert!(mgr.lock_enabled);
        assert_eq!(mgr.lock_method, "combo");
        assert!(!mgr.lock_on_pause);
        assert!(mgr.lock_locked);
    }

    #[test]
    #[serial_test::serial]
    fn cold_start_with_enabled_lock_defaults_to_locked() {
        setup_test_env();
        crate::sdk::app_lock::enroll(crate::sdk::app_lock::LockMethod::Pin, "2468")
            .expect("enrolled");
        AppState::set_pref(LOCK_ON_PAUSE_KEY, "true").expect("pref");
        AppState::set_pref(LOCK_LOCKED_KEY, "false").expect("pref");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state()
            .expect("lock settings");

        assert!(mgr.lock_enabled);
        assert!(mgr.lock_locked);
        assert_eq!(AppState::get_pref(LOCK_LOCKED_KEY).as_deref(), Some("true"));
    }

    #[test]
    #[serial_test::serial]
    fn runtime_unlock_persists_until_next_process_start() {
        setup_test_env();
        crate::sdk::app_lock::enroll(crate::sdk::app_lock::LockMethod::Pin, "2468")
            .expect("enrolled");
        AppState::set_pref(LOCK_ON_PAUSE_KEY, "true").expect("pref");

        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state()
            .expect("lock settings");
        assert!(mgr.lock_locked);

        mgr.unlock_now().expect("unlock");
        assert_eq!(
            AppState::get_pref(LOCK_LOCKED_KEY).as_deref(),
            Some("false")
        );

        mgr.sync_lock_config_from_app_state()
            .expect("lock settings");
        assert!(!mgr.lock_locked);

        let mut restarted = SessionManager::default();
        restarted
            .sync_lock_config_from_app_state()
            .expect("lock settings");
        assert!(restarted.lock_locked);
    }

    #[test]
    #[serial_test::serial]
    fn snapshot_bytes_are_envelope_wrapped() {
        setup_test_env();
        SDK_READY.store(true, Ordering::SeqCst);

        let bytes = get_session_snapshot_bytes().expect("snapshot");
        assert!(!decode_snapshot(&bytes).phase.is_empty());
    }

    /// A stored lock setting that is neither `true` nor `false` is an error,
    /// never read as the manager's own setting: a corrupted "lock on pause"
    /// must not quietly become the manager's.
    #[test]
    #[serial_test::serial]
    fn a_malformed_lock_setting_is_an_error_not_a_default() {
        setup_test_env();
        AppState::set_pref(LOCK_ON_PAUSE_KEY, "yes").expect("pref");
        let mut mgr = SessionManager {
            lock_enabled: true,
            ..SessionManager::default()
        };
        let refused = mgr.sync_lock_config_from_app_state();
        assert!(refused.is_err(), "a malformed setting is reported");
        assert!(mgr.lock_enabled, "the manager's setting is untouched");
    }

    // ── The app lock: Rust enrolls and checks the PIN or pattern ──────────

    use crate::sdk::app_lock::{PhraseTried, Tried, MISSES_BEFORE_PHRASE};

    /// A fresh store with this wallet's seed loaded, as an unlocked wallet
    /// holds it, and an open session.
    fn wallet_with_seed(phrase: &str) -> SessionManager {
        setup_test_env();
        crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(phrase).expect("the seed");
        let mut mgr = SessionManager::default();
        mgr.sync_lock_config_from_app_state()
            .expect("lock settings");
        mgr
    }

    fn snapshot_of(mgr: &SessionManager) -> generated::AppSessionLockStatusProto {
        mgr.compute_snapshot().lock_status.expect("a lock status")
    }

    /// The lock opens for the PIN enrolled and for nothing else; each miss is
    /// stored before it is answered, and the store holds a hash, never the PIN.
    #[test]
    #[serial_test::serial]
    fn the_lock_opens_only_for_its_own_pin_and_counts_each_miss() {
        let mut mgr = wallet_with_seed(&crate::economic_fixtures::test_mnemonic(0x31));
        mgr.enable_lock("pin", "4321", mgr.lock_on_pause)
            .expect("enabled");
        let stored = AppState::get_pref("lock_credential").expect("a credential");
        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert!(!stored.contains("4321"), "the PIN itself is never stored");

        mgr.lock_now().expect("locked");
        assert_eq!(
            mgr.try_unlock("1111").expect("tried"),
            Tried::Wrong { left: 2 }
        );
        assert!(mgr.lock_locked, "a wrong PIN leaves the wallet locked");
        assert_eq!(AppState::get_pref("lock_misses").as_deref(), Some("1"));
        assert_eq!(snapshot_of(&mgr).misses_left, 2);

        // A pattern spelling the same text is not the PIN.
        assert_eq!(
            crate::sdk::app_lock::try_secret(crate::sdk::app_lock::LockMethod::Combo, "4321")
                .expect("tried"),
            Tried::Wrong { left: 1 }
        );

        assert_eq!(mgr.try_unlock("4321").expect("tried"), Tried::Opened);
        assert!(!mgr.lock_locked);
        assert_eq!(snapshot_of(&mgr).misses_left, MISSES_BEFORE_PHRASE);
    }

    /// After the third miss no PIN is checked, not even the right one, and a
    /// restart does not give the tries back; only this wallet's recovery
    /// phrase opens the lock, and it starts the count again.
    #[test]
    #[serial_test::serial]
    fn after_three_misses_only_the_recovery_phrase_opens_the_lock() {
        let phrase = crate::economic_fixtures::test_mnemonic(0x32);
        let mut mgr = wallet_with_seed(&phrase);
        mgr.enable_lock("pin", "2468", mgr.lock_on_pause)
            .expect("enabled");
        mgr.lock_now().expect("locked");
        assert_eq!(
            mgr.try_unlock("0000").expect("tried"),
            Tried::Wrong { left: 2 }
        );
        assert_eq!(
            mgr.try_unlock("0001").expect("tried"),
            Tried::Wrong { left: 1 }
        );
        assert_eq!(
            mgr.try_unlock("0002").expect("tried"),
            Tried::PhraseRequired
        );
        assert_eq!(
            mgr.try_unlock("2468").expect("tried"),
            Tried::PhraseRequired
        );
        assert!(mgr.lock_locked, "the right PIN no longer opens it");

        let mut restarted = SessionManager::default();
        restarted
            .sync_lock_config_from_app_state()
            .expect("lock settings");
        assert!(
            snapshot_of(&restarted).phrase_required,
            "a restart gives no try back"
        );
        assert_eq!(
            restarted.try_unlock("2468").expect("tried"),
            Tried::PhraseRequired
        );

        let another = crate::economic_fixtures::test_mnemonic(0x33);
        assert_eq!(
            restarted.try_unlock_with_phrase(&another).expect("tried"),
            PhraseTried::NotThisWallet
        );
        assert!(restarted.lock_locked);
        assert_eq!(
            restarted.try_unlock_with_phrase(&phrase).expect("tried"),
            PhraseTried::Opened
        );
        assert!(!restarted.lock_locked);
        let status = snapshot_of(&restarted);
        assert!(!status.phrase_required);
        assert_eq!(status.misses_left, MISSES_BEFORE_PHRASE);
        restarted.lock_now().expect("locked");
        assert_eq!(restarted.try_unlock("2468").expect("tried"), Tried::Opened);
    }

    /// A locked wallet cannot change or turn off its own lock: a caller that
    /// could would not need the PIN.
    #[test]
    #[serial_test::serial]
    fn a_locked_wallet_cannot_change_its_lock() {
        let mut mgr = wallet_with_seed(&crate::economic_fixtures::test_mnemonic(0x34));
        mgr.enable_lock("pin", "1357", mgr.lock_on_pause)
            .expect("enabled");
        mgr.lock_now().expect("locked");
        let off = mgr
            .disable_lock(mgr.lock_on_pause)
            .expect_err("turned off while locked");
        assert!(off.to_string().contains("the wallet is locked"), "{off}");
        let again = mgr
            .enable_lock("pin", "9999", mgr.lock_on_pause)
            .expect_err("re-enrolled while locked");
        assert!(
            again.to_string().contains("the wallet is locked"),
            "{again}"
        );
        assert!(mgr.lock_enabled && mgr.lock_locked);
        assert_eq!(mgr.try_unlock("1357").expect("tried"), Tried::Opened);
    }

    /// A PIN or pattern enrolled under a method Rust does not know is an
    /// error, never a method chosen in its place.
    #[test]
    #[serial_test::serial]
    fn an_enrolled_lock_under_a_method_rust_does_not_know_is_an_error() {
        let mut mgr = wallet_with_seed(&crate::economic_fixtures::test_mnemonic(0x35));
        mgr.enable_lock("pin", "1234", mgr.lock_on_pause)
            .expect("enabled");
        AppState::set_pref("lock_method", "face").expect("pref");
        let refused = SessionManager::default()
            .sync_lock_config_from_app_state()
            .expect_err("no method stands in");
        assert!(refused.to_string().contains("face"), "{refused}");
    }

    /// Rust decides what a lock is: a PIN of 4 to 8 digits, or 8 presses of
    /// the shell's buttons. Anything else is refused and enrolls nothing.
    #[test]
    #[serial_test::serial]
    fn a_lock_enrolls_only_a_pin_of_four_to_eight_digits_or_eight_shell_buttons() {
        let mut mgr = wallet_with_seed(&crate::economic_fixtures::test_mnemonic(0x36));
        for (method, secret, refusal) in [
            ("pin", "", "a new lock needs its PIN or pattern"),
            ("pin", "123", "4 to 8 digits"),
            ("pin", "123456789", "4 to 8 digits"),
            ("pin", "12a4", "4 to 8 digits"),
            ("pin", "１２３４", "4 to 8 digits"),
            (
                "combo",
                "up,up,down,down,left,right,left",
                "8 presses, not 7",
            ),
            (
                "combo",
                "up,up,down,down,left,right,left,right,a",
                "8 presses, not 9",
            ),
            (
                "combo",
                "up,up,down,down,left,right,left,jump",
                "\"jump\" is not one of the shell's buttons",
            ),
        ] {
            let refused = mgr
                .enable_lock(method, secret, mgr.lock_on_pause)
                .expect_err(secret);
            assert!(
                refused.to_string().contains(refusal),
                "{secret:?}: {refused}"
            );
            assert!(
                !crate::sdk::app_lock::enrolled(),
                "{secret:?} enrolled nothing"
            );
        }
        mgr.enable_lock("combo", "up,up,down,down,left,right,b,a", mgr.lock_on_pause)
            .expect("a pattern of the shell's buttons");
        mgr.lock_now().expect("locked");
        assert_eq!(
            mgr.try_unlock("up,up,down,down,left,right,a,b")
                .expect("tried"),
            Tried::Wrong { left: 2 }
        );
        assert_eq!(
            mgr.try_unlock("up,up,down,down,left,right,b,a")
                .expect("tried"),
            Tried::Opened
        );
    }
}
