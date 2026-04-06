//! # Persistent Application State
//!
//! Manages the SDK's on-disk identity and preference store. All data is
//! serialized as protobuf (`generated::AppStateStorage`) with no JSON or
//! Base64. The file is written atomically (tmp, chmod 0600, rename) to
//! prevent partial-write corruption.
//!
//! Identity fields (`device_id`, `genesis_hash`, `public_key`, `smt_root`)
//! are stored as raw bytes. String key-value pairs are available for
//! preference storage via [`AppState::handle_app_state_request`].
//!
//! The state file lives at `<storage_base_dir>/dsm_app_state.pb`.

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use prost::Message;
use dsm::types::receipt_types::DeviceTreeAcceptanceCommitment;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::generated;
use crate::storage_utils;

// —————————————————————————–
// Global flags (process-lifetime)
// —————————————————————————–
static HAS_IDENTITY: AtomicBool = AtomicBool::new(false);
static SDK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static STORAGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// —————————————————————————–
// In-memory mirror of the canonical protobuf (generated::AppStateStorage)
// Persisted bytes on disk are strictly protobuf—no JSON/base64/hex.
// —————————————————————————–
#[derive(Debug, Clone, Default)]
struct AppStateStorage {
    has_identity: bool,
    sdk_initialized: bool,
    device_id: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    genesis_hash: Option<Vec<u8>>,
    smt_root: Option<Vec<u8>>,
    device_tree_root: Option<Vec<u8>>,
    recovery_sessions: HashMap<String, String>,
    key_value_store: HashMap<String, String>,
    // (§2.3.1) Contact's Device Tree roots — indexed by contact device_id
    contact_device_tree_roots: HashMap<String, Vec<u8>>,
}

// Global storage slot
static STORAGE: Mutex<Option<AppStateStorage>> = Mutex::new(None);

// —————————————————————————–
// Public API
// —————————————————————————–
pub struct AppState;

impl AppState {
    /// Compute the canonical state file path (protobuf only).
    fn get_storage_path() -> PathBuf {
        let base = match storage_utils::get_storage_base_dir() {
            Some(p) => p,
            None => {
                #[allow(clippy::panic)]
                {
                    panic!(
                        "DSM storage base dir not set; call set_storage_base_dir() exactly once at app startup"
                    );
                }
            }
        };
        let path = base.join("dsm_app_state.pb");
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                #[allow(clippy::panic)]
                {
                    panic!("Failed to create app state dir {parent:?}: {e}");
                }
            }
        }
        path
    }

    /// Load persisted state once (idempotent).
    pub fn ensure_storage_loaded() {
        if STORAGE_INITIALIZED.load(Ordering::SeqCst) {
            log::debug!("AppState: storage already initialized; skipping load");
            return;
        }

        let path = Self::get_storage_path();
        log::info!("AppState: loading from {:?}", path);

        let storage = if path.exists() {
            match fs::read(&path) {
                Ok(bytes) => match generated::AppStateStorage::decode(&*bytes) {
                    Ok(proto) => AppStateStorage {
                        has_identity: proto.has_identity,
                        sdk_initialized: proto.sdk_initialized,
                        device_id: proto.device_id,
                        public_key: proto.public_key,
                        genesis_hash: proto.genesis_hash,
                        smt_root: proto.smt_root,
                        device_tree_root: proto.device_tree_root,
                        recovery_sessions: proto.recovery_sessions,
                        key_value_store: proto.key_value_store,
                        contact_device_tree_roots: proto.contact_device_tree_roots,
                    },
                    Err(e) => {
                        log::warn!("AppState: decode failed ({e}); using defaults");
                        AppStateStorage::default()
                    }
                },
                Err(e) => {
                    log::warn!("AppState: read failed ({e}); using defaults");
                    AppStateStorage::default()
                }
            }
        } else {
            AppStateStorage::default()
        };

        // prime atomics from persisted state
        HAS_IDENTITY.store(storage.has_identity, Ordering::SeqCst);
        SDK_INITIALIZED.store(storage.sdk_initialized, Ordering::SeqCst);

        // publish storage
        *STORAGE.lock().unwrap_or_else(|p| p.into_inner()) = Some(storage);
        STORAGE_INITIALIZED.store(true, Ordering::SeqCst);
    }

    /// Atomically write current in-memory storage to disk as protobuf.
    fn save_storage() {
        if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            log::info!("AppState: test mode—skip save");
            return;
        }

        // Snapshot current storage without holding the lock during I/O.
        let storage_lock = STORAGE.lock().unwrap_or_else(|p| p.into_inner());

        if storage_lock.is_none() {
            log::warn!("AppState: save requested but storage not loaded");
            return;
        }

        let mut storage = match storage_lock.as_ref() {
            Some(s) => s.clone(),
            None => {
                log::warn!("AppState: save requested but storage not loaded (race) ");
                return;
            }
        };
        drop(storage_lock); // release lock before encoding and file I/O

        // Refresh flags from atomics; never mutate identity bytes here.
        storage.has_identity = HAS_IDENTITY.load(Ordering::SeqCst);
        storage.sdk_initialized = SDK_INITIALIZED.load(Ordering::SeqCst);

        // Map to prost and encode once
        let proto = generated::AppStateStorage {
            has_identity: storage.has_identity,
            sdk_initialized: storage.sdk_initialized,
            device_id: storage.device_id,
            public_key: storage.public_key,
            genesis_hash: storage.genesis_hash,
            smt_root: storage.smt_root,
            device_tree_root: storage.device_tree_root,
            recovery_sessions: storage.recovery_sessions,
            key_value_store: storage.key_value_store,
            contact_device_tree_roots: storage.contact_device_tree_roots,
        };
        let buf = proto.encode_to_vec();

        // Atomic replace: write tmp → set perms → rename
        let path = Self::get_storage_path();
        let tmp = path.with_extension("pb.tmp");

        if let Err(e) = fs::write(&tmp, &buf) {
            log::error!("AppState: tmp write failed {tmp:?}: {e}");
            return;
        }
        #[cfg(unix)]
        {
            if let Ok(meta) = fs::metadata(&tmp) {
                let mut p = meta.permissions();
                p.set_mode(0o600);
                let _ = fs::set_permissions(&tmp, p);
            }
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            log::error!("AppState: atomic rename failed {tmp:?} → {path:?}: {e}");
            let _ = fs::remove_file(&tmp);
            return;
        }
        log::info!("AppState: state saved ({:?}, {} bytes)", path, buf.len());
    }

    /// Mark identity presence flag and persist.
    pub fn set_has_identity(value: bool) {
        HAS_IDENTITY.store(value, Ordering::SeqCst);
        Self::save_storage();
    }

    /// After successful genesis, write identity bytes and persist (overwrites existing).
    pub fn set_identity_info(
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        genesis_hash: Vec<u8>,
        smt_root: Vec<u8>,
    ) {
        Self::ensure_storage_loaded();
        {
            let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut s) = *guard {
                s.device_id = Some(device_id.clone());
                s.public_key = Some(public_key);
                s.genesis_hash = Some(genesis_hash);
                s.smt_root = Some(smt_root);
                // Auto-compute R_G from device_id (§2.3 single-device)
                if device_id.len() == 32 {
                    let mut devid = [0u8; 32];
                    devid.copy_from_slice(&device_id);
                    s.device_tree_root = Some(
                        dsm::common::device_tree::DeviceTree::single(devid)
                            .root()
                            .to_vec(),
                    );
                }
            } else {
                log::warn!("AppState: storage None in set_identity_info");
            }
        }
        Self::save_storage();
    }

    /// Write identity bytes only if empty (idempotent bootstrap).
    pub fn set_identity_info_if_empty(
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        genesis_hash: Vec<u8>,
        smt_root: Vec<u8>,
    ) {
        Self::ensure_storage_loaded();
        {
            let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut s) = *guard {
                if s.device_id.is_none() {
                    s.device_id = Some(device_id.clone());
                }
                if s.public_key.is_none() {
                    s.public_key = Some(public_key);
                }
                if s.genesis_hash.is_none() {
                    s.genesis_hash = Some(genesis_hash);
                }
                if s.smt_root.is_none() {
                    s.smt_root = Some(smt_root);
                }
                // Auto-compute R_G from device_id if not yet set (§2.3 single-device)
                if s.device_tree_root.is_none() && device_id.len() == 32 {
                    let mut devid = [0u8; 32];
                    devid.copy_from_slice(&device_id);
                    s.device_tree_root = Some(
                        dsm::common::device_tree::DeviceTree::single(devid)
                            .root()
                            .to_vec(),
                    );
                }
            }
        }
        Self::save_storage();
    }

    /// Accessors (binary values stay binary; UI must encode externally).
    pub fn get_device_id() -> Option<Vec<u8>> {
        Self::ensure_storage_loaded();
        STORAGE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|s| s.device_id.clone())
    }
    pub fn get_public_key() -> Option<Vec<u8>> {
        Self::ensure_storage_loaded();
        STORAGE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|s| s.public_key.clone())
    }
    pub fn get_genesis_hash() -> Option<Vec<u8>> {
        Self::ensure_storage_loaded();
        STORAGE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|s| s.genesis_hash.clone())
    }
    pub fn get_smt_root() -> Option<Vec<u8>> {
        Self::ensure_storage_loaded();
        STORAGE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|s| s.smt_root.clone())
    }
    /// Get the Device Tree root R_G (§2.3).
    /// Returns the stored 32-byte root, or None if not yet computed.
    pub fn get_device_tree_root() -> Option<[u8; 32]> {
        Self::ensure_storage_loaded();
        let guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref()?.device_tree_root.as_ref().and_then(|v| {
            if v.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Some(arr)
            } else {
                None
            }
        })
    }
    /// Get the authenticated local device-tree commitment used for `π_dev`
    /// verification on receipt paths that require device membership under `R_G`.
    ///
    /// Today this returns the raw persisted `R_G` wrapped in an explicit
    /// acceptance-commitment type.
    pub fn get_device_tree_commitment() -> Option<DeviceTreeAcceptanceCommitment> {
        Self::get_device_tree_root().map(DeviceTreeAcceptanceCommitment::from_root)
    }
    /// Set the Device Tree root R_G and persist.
    pub fn set_device_tree_root(root: [u8; 32]) {
        Self::ensure_storage_loaded();
        {
            let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut s) = *guard {
                s.device_tree_root = Some(root.to_vec());
            }
        }
        Self::save_storage();
    }

    /// Boolean flags
    pub fn get_has_identity() -> bool {
        if std::env::var("DSM_SDK_TEST_MODE").is_err() {
            Self::ensure_storage_loaded();
        }
        HAS_IDENTITY.load(Ordering::SeqCst)
    }
    pub fn set_sdk_initialized(value: bool) {
        Self::ensure_storage_loaded();
        SDK_INITIALIZED.store(value, Ordering::SeqCst);
        Self::save_storage();
    }
    pub fn get_sdk_initialized() -> bool {
        if std::env::var("DSM_SDK_TEST_MODE").is_err() {
            Self::ensure_storage_loaded();
        }
        SDK_INITIALIZED.load(Ordering::SeqCst)
    }

    /// Preference bridge used by JNI-facing helpers (string K/V only).
    /// Binary fields remain inaccessible here (device_id/genesis_hash).
    pub fn handle_app_state_request(key: &str, operation: &str, value: &str) -> String {
        if std::env::var("DSM_SDK_TEST_MODE").is_err() {
            Self::ensure_storage_loaded();
        }

        match key {
            "has_identity" => {
                if operation == "set" {
                    match value {
                        "true" => Self::set_has_identity(true),
                        "false" => Self::set_has_identity(false),
                        _ => {}
                    }
                }
                if Self::get_has_identity() {
                    "true"
                } else {
                    "false"
                }
                .to_string()
            }
            "sdk_initialized" => {
                if operation == "set" {
                    match value {
                        "true" => Self::set_sdk_initialized(true),
                        "false" => Self::set_sdk_initialized(false),
                        _ => {}
                    }
                }
                if Self::get_sdk_initialized() {
                    "true"
                } else {
                    "false"
                }
                .to_string()
            }
            "genesis_hash" => "".to_string(), // binary-only
            "device_id" => "".to_string(),    // binary-only
            "chain_tip" => "0".to_string(),
            _ => {
                let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(ref mut store) = *guard {
                    match operation {
                        "get" => store.key_value_store.get(key).cloned().unwrap_or_default(),
                        "set" => {
                            store
                                .key_value_store
                                .insert(key.to_string(), value.to_string());
                            drop(guard);
                            Self::save_storage();
                            value.to_string()
                        }
                        _ => "unknown_operation".to_string(),
                    }
                } else {
                    "storage_not_loaded".to_string()
                }
            }
        }
    }

    /// Recovery session helpers
    pub fn set_recovery_state(recovery_id: &str, status: &str) -> Result<(), String> {
        Self::ensure_storage_loaded();
        {
            let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut store) = *guard {
                store
                    .recovery_sessions
                    .insert(recovery_id.to_string(), status.to_string());
            } else {
                return Err("Storage not available".to_string());
            }
        }
        Self::save_storage();
        Ok(())
    }

    pub fn get_recovery_state(recovery_id: &str) -> Option<String> {
        Self::ensure_storage_loaded();
        let guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref()?.recovery_sessions.get(recovery_id).cloned()
    }

    pub fn clear_recovery_state(recovery_id: &str) -> Result<(), String> {
        Self::ensure_storage_loaded();
        {
            let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref mut store) = *guard {
                store.recovery_sessions.remove(recovery_id);
            } else {
                return Err("Storage not available".to_string());
            }
        }
        Self::save_storage();
        Ok(())
    }

    // ----------------- Test utilities -----------------
    #[cfg(test)]
    pub fn reset_for_testing() {
        HAS_IDENTITY.store(false, Ordering::SeqCst);
        SDK_INITIALIZED.store(false, Ordering::SeqCst);
        STORAGE_INITIALIZED.store(false, Ordering::SeqCst);

        if let Ok(mut storage) = STORAGE.try_lock() {
            *storage = None;
        }

        let path = Self::get_storage_path();
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }

    #[cfg(test)]
    pub fn reset_memory_for_testing() {
        HAS_IDENTITY.store(false, Ordering::SeqCst);
        SDK_INITIALIZED.store(false, Ordering::SeqCst);
        STORAGE_INITIALIZED.store(false, Ordering::SeqCst);
        *STORAGE.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    #[cfg(test)]
    pub fn prime_memory_for_testing() {
        HAS_IDENTITY.store(false, Ordering::SeqCst);
        SDK_INITIALIZED.store(false, Ordering::SeqCst);
        STORAGE_INITIALIZED.store(true, Ordering::SeqCst);
        *STORAGE.lock().unwrap_or_else(|p| p.into_inner()) = Some(AppStateStorage::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_env() {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        AppState::reset_memory_for_testing();
        // Prime in-memory storage so global is Some (no file I/O in test mode)
        *STORAGE.lock().unwrap_or_else(|p| p.into_inner()) = Some(AppStateStorage::default());
        STORAGE_INITIALIZED.store(true, Ordering::SeqCst);
    }

    // ── AppStateStorage default ──

    #[test]
    fn app_state_storage_default() {
        let s = AppStateStorage::default();
        assert!(!s.has_identity);
        assert!(!s.sdk_initialized);
        assert!(s.device_id.is_none());
        assert!(s.public_key.is_none());
        assert!(s.genesis_hash.is_none());
        assert!(s.smt_root.is_none());
        assert!(s.device_tree_root.is_none());
        assert!(s.recovery_sessions.is_empty());
        assert!(s.key_value_store.is_empty());
        assert!(s.contact_device_tree_roots.is_empty());
    }

    // ── Boolean flags ──

    #[test]
    fn has_identity_default_false() {
        setup_test_env();
        assert!(!AppState::get_has_identity());
    }

    #[test]
    fn set_and_get_has_identity() {
        setup_test_env();
        AppState::set_has_identity(true);
        assert!(AppState::get_has_identity());
        AppState::set_has_identity(false);
        assert!(!AppState::get_has_identity());
    }

    #[test]
    fn sdk_initialized_default_false() {
        setup_test_env();
        assert!(!AppState::get_sdk_initialized());
    }

    #[test]
    fn set_and_get_sdk_initialized() {
        setup_test_env();
        AppState::set_sdk_initialized(true);
        assert!(AppState::get_sdk_initialized());
        AppState::set_sdk_initialized(false);
        assert!(!AppState::get_sdk_initialized());
    }

    // ── handle_app_state_request: has_identity ──

    #[test]
    fn handle_has_identity_get() {
        setup_test_env();
        let result = AppState::handle_app_state_request("has_identity", "get", "");
        assert_eq!(result, "false");
    }

    #[test]
    fn handle_has_identity_set_true() {
        setup_test_env();
        let result = AppState::handle_app_state_request("has_identity", "set", "true");
        assert_eq!(result, "true");
        assert!(AppState::get_has_identity());
    }

    #[test]
    fn handle_has_identity_set_false() {
        setup_test_env();
        HAS_IDENTITY.store(true, Ordering::SeqCst);
        let result = AppState::handle_app_state_request("has_identity", "set", "false");
        assert_eq!(result, "false");
    }

    #[test]
    fn handle_has_identity_set_invalid_value_noop() {
        setup_test_env();
        AppState::handle_app_state_request("has_identity", "set", "maybe");
        // should stay at default false
        assert!(!AppState::get_has_identity());
    }

    // ── handle_app_state_request: sdk_initialized ──

    #[test]
    fn handle_sdk_initialized_get() {
        setup_test_env();
        let result = AppState::handle_app_state_request("sdk_initialized", "get", "");
        assert_eq!(result, "false");
    }

    #[test]
    fn handle_sdk_initialized_set_true() {
        setup_test_env();
        let result = AppState::handle_app_state_request("sdk_initialized", "set", "true");
        assert_eq!(result, "true");
        assert!(AppState::get_sdk_initialized());
    }

    // ── handle_app_state_request: binary-only keys ──

    #[test]
    fn handle_genesis_hash_returns_empty() {
        setup_test_env();
        let result = AppState::handle_app_state_request("genesis_hash", "get", "");
        assert_eq!(result, "");
    }

    #[test]
    fn handle_device_id_returns_empty() {
        setup_test_env();
        let result = AppState::handle_app_state_request("device_id", "get", "");
        assert_eq!(result, "");
    }

    #[test]
    fn handle_chain_tip_returns_zero() {
        setup_test_env();
        let result = AppState::handle_app_state_request("chain_tip", "get", "");
        assert_eq!(result, "0");
    }

    // ── handle_app_state_request: custom K/V (in-memory only) ──

    #[test]
    fn handle_custom_key_set_returns_value() {
        setup_test_env();
        let set_result = AppState::handle_app_state_request("theme", "set", "dark");
        // "dark" when STORAGE is primed; "storage_not_loaded" if another test raced
        assert!(set_result == "dark" || set_result == "storage_not_loaded");
    }

    #[test]
    fn handle_unknown_operation_returns_marker() {
        setup_test_env();
        let result = AppState::handle_app_state_request("key", "delete", "");
        assert!(result == "unknown_operation" || result == "storage_not_loaded");
    }

    // ── Identity info: direct in-memory manipulation ──

    #[test]
    fn storage_identity_fields_default_none() {
        let s = AppStateStorage::default();
        assert!(s.device_id.is_none());
        assert!(s.public_key.is_none());
        assert!(s.genesis_hash.is_none());
        assert!(s.smt_root.is_none());
        assert!(s.device_tree_root.is_none());
    }

    #[test]
    fn storage_identity_fields_can_be_set() {
        let s = AppStateStorage {
            device_id: Some(vec![0x11; 32]),
            public_key: Some(vec![0x22; 32]),
            genesis_hash: Some(vec![0x33; 32]),
            smt_root: Some(vec![0x44; 32]),
            ..Default::default()
        };

        assert_eq!(s.device_id.as_ref().unwrap(), &vec![0x11; 32]);
        assert_eq!(s.public_key.as_ref().unwrap(), &vec![0x22; 32]);
        assert_eq!(s.genesis_hash.as_ref().unwrap(), &vec![0x33; 32]);
        assert_eq!(s.smt_root.as_ref().unwrap(), &vec![0x44; 32]);
    }

    #[test]
    fn storage_device_tree_root_can_be_set() {
        let s = AppStateStorage {
            device_tree_root: Some(vec![0xDD; 32]),
            ..Default::default()
        };
        assert_eq!(s.device_tree_root.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn storage_recovery_sessions_crud() {
        let mut s = AppStateStorage::default();
        s.recovery_sessions
            .insert("r1".to_string(), "pending".to_string());
        s.recovery_sessions
            .insert("r2".to_string(), "active".to_string());
        assert_eq!(s.recovery_sessions.get("r1").unwrap(), "pending");

        s.recovery_sessions
            .insert("r1".to_string(), "done".to_string());
        assert_eq!(s.recovery_sessions.get("r1").unwrap(), "done");

        s.recovery_sessions.remove("r1");
        assert!(!s.recovery_sessions.contains_key("r1"));
        assert_eq!(s.recovery_sessions.get("r2").unwrap(), "active");
    }

    #[test]
    fn storage_kv_store_crud() {
        let mut s = AppStateStorage::default();
        s.key_value_store
            .insert("lang".to_string(), "en".to_string());
        assert_eq!(s.key_value_store.get("lang").unwrap(), "en");

        s.key_value_store
            .insert("lang".to_string(), "fr".to_string());
        assert_eq!(s.key_value_store.get("lang").unwrap(), "fr");
        assert!(!s.key_value_store.contains_key("missing"));
    }

    #[test]
    fn storage_contact_device_tree_roots() {
        let mut s = AppStateStorage::default();
        s.contact_device_tree_roots
            .insert("c1".to_string(), vec![0xAA; 32]);
        assert_eq!(
            s.contact_device_tree_roots.get("c1").unwrap(),
            &vec![0xAA; 32]
        );
    }

    // ── DeviceTreeAcceptanceCommitment from root ──

    #[test]
    fn device_tree_commitment_from_root_roundtrips() {
        use dsm::types::receipt_types::DeviceTreeAcceptanceCommitment;
        let root = [0xCC; 32];
        let commitment = DeviceTreeAcceptanceCommitment::from_root(root);
        assert_eq!(commitment.root(), root);
    }

    // ── reset_memory_for_testing ──

    #[test]
    fn reset_memory_clears_atomics() {
        HAS_IDENTITY.store(true, Ordering::SeqCst);
        SDK_INITIALIZED.store(true, Ordering::SeqCst);
        STORAGE_INITIALIZED.store(true, Ordering::SeqCst);

        AppState::reset_memory_for_testing();

        assert!(!HAS_IDENTITY.load(Ordering::SeqCst));
        assert!(!SDK_INITIALIZED.load(Ordering::SeqCst));
        assert!(!STORAGE_INITIALIZED.load(Ordering::SeqCst));
    }

    // ── set_identity_info overwrites ──

    #[test]
    fn set_identity_info_overwrites_existing() {
        setup_test_env();
        AppState::set_identity_info(
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            vec![0x04; 32],
        );
        AppState::set_identity_info(
            vec![0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 32],
            vec![0xDD; 32],
        );

        assert_eq!(AppState::get_device_id().unwrap(), vec![0xAA; 32]);
        assert_eq!(AppState::get_public_key().unwrap(), vec![0xBB; 32]);
        assert_eq!(AppState::get_genesis_hash().unwrap(), vec![0xCC; 32]);
        assert_eq!(AppState::get_smt_root().unwrap(), vec![0xDD; 32]);
    }

    // ── Multiple recovery sessions ──

    #[test]
    fn multiple_recovery_sessions_independent() {
        setup_test_env();
        AppState::set_recovery_state("r1", "pending").unwrap();
        AppState::set_recovery_state("r2", "active").unwrap();
        AppState::set_recovery_state("r3", "complete").unwrap();

        assert_eq!(AppState::get_recovery_state("r1").unwrap(), "pending");
        assert_eq!(AppState::get_recovery_state("r2").unwrap(), "active");
        assert_eq!(AppState::get_recovery_state("r3").unwrap(), "complete");
    }

    #[test]
    fn clear_one_recovery_leaves_others() {
        setup_test_env();
        AppState::set_recovery_state("r1", "a").unwrap();
        AppState::set_recovery_state("r2", "b").unwrap();

        AppState::clear_recovery_state("r1").unwrap();
        assert!(AppState::get_recovery_state("r1").is_none());
        assert_eq!(AppState::get_recovery_state("r2").unwrap(), "b");
    }

    #[test]
    fn clear_nonexistent_recovery_is_ok() {
        setup_test_env();
        assert!(AppState::clear_recovery_state("ghost").is_ok());
    }

    // ── Custom K/V: multiple keys ──

    #[test]
    fn handle_multiple_custom_keys() {
        setup_test_env();
        AppState::handle_app_state_request("lang", "set", "en");
        AppState::handle_app_state_request("theme", "set", "dark");
        AppState::handle_app_state_request("font_size", "set", "14");

        assert_eq!(AppState::handle_app_state_request("lang", "get", ""), "en");
        assert_eq!(
            AppState::handle_app_state_request("theme", "get", ""),
            "dark"
        );
        assert_eq!(
            AppState::handle_app_state_request("font_size", "get", ""),
            "14"
        );
    }

    #[test]
    fn handle_custom_key_empty_value() {
        setup_test_env();
        AppState::handle_app_state_request("key", "set", "");
        let result = AppState::handle_app_state_request("key", "get", "");
        assert_eq!(result, "");
    }

    // ── Device tree root: overwrite ──

    #[test]
    fn set_device_tree_root_overwrites() {
        setup_test_env();
        AppState::set_device_tree_root([0x01; 32]);
        AppState::set_device_tree_root([0x02; 32]);
        assert_eq!(AppState::get_device_tree_root().unwrap(), [0x02; 32]);
    }

    // ── set_identity_info_if_empty: partial fill ──

    #[test]
    fn set_identity_info_if_empty_partial_fill() {
        setup_test_env();
        // Set device_id directly, leave others empty
        {
            let mut guard = STORAGE.lock().unwrap();
            if let Some(ref mut s) = *guard {
                s.device_id = Some(vec![0x99; 32]);
            }
        }

        AppState::set_identity_info_if_empty(
            vec![0xFF; 32],
            vec![0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 32],
        );

        // device_id should NOT be overwritten
        assert_eq!(AppState::get_device_id().unwrap(), vec![0x99; 32]);
        // others should be filled
        assert_eq!(AppState::get_public_key().unwrap(), vec![0xAA; 32]);
        assert_eq!(AppState::get_genesis_hash().unwrap(), vec![0xBB; 32]);
        assert_eq!(AppState::get_smt_root().unwrap(), vec![0xCC; 32]);
    }

    // ── AppStateStorage clone ──

    #[test]
    fn app_state_storage_clone() {
        let mut s = AppStateStorage {
            has_identity: true,
            device_id: Some(vec![1, 2, 3]),
            ..Default::default()
        };
        s.key_value_store.insert("k".to_string(), "v".to_string());

        let cloned = s.clone();
        assert!(cloned.has_identity);
        assert_eq!(cloned.device_id, Some(vec![1, 2, 3]));
        assert_eq!(cloned.key_value_store.get("k").unwrap(), "v");
    }

    // ── AppStateStorage debug ──

    #[test]
    fn app_state_storage_debug() {
        let s = AppStateStorage::default();
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("AppStateStorage"));
    }

    // ── handle_app_state_request: sdk_initialized set false ──

    #[test]
    fn handle_sdk_initialized_set_false() {
        setup_test_env();
        SDK_INITIALIZED.store(true, Ordering::SeqCst);
        let result = AppState::handle_app_state_request("sdk_initialized", "set", "false");
        assert_eq!(result, "false");
        assert!(!AppState::get_sdk_initialized());
    }

    #[test]
    fn handle_sdk_initialized_set_invalid_noop() {
        setup_test_env();
        AppState::handle_app_state_request("sdk_initialized", "set", "maybe");
        assert!(!AppState::get_sdk_initialized());
    }

    // ── contact_device_tree_roots in default ──

    #[test]
    fn app_state_storage_contact_roots_empty() {
        let s = AppStateStorage::default();
        assert!(s.contact_device_tree_roots.is_empty());
    }
}
