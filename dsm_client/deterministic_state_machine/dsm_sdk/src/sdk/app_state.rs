// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Persistent Application State
//!
//! Manages the SDK's on-disk identity and preference store. All data is
//! serialized as protobuf (`generated::AppStateStorage`) with no JSON or
//! Base64. The file is written atomically (tmp, chmod 0600, rename) to
//! prevent partial-write corruption.
//!
//! Identity fields (`device_id`, `genesis_hash`, `public_key`, `smt_root`)
//! are stored as raw bytes. String key-value pairs are available for
//! preference storage via [`AppState::get_pref`] / [`AppState::set_pref`].
//!
//! The state file lives at `<storage_base_dir>/dsm_app_state.pb`.

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
use dsm::types::error::DsmError;

/// The single-device tree root `R_G` over `device_id` (§2.3).
fn single_device_tree_root(device_id: &[u8]) -> Result<Vec<u8>, DsmError> {
    let device_id: [u8; 32] = device_id
        .try_into()
        .map_err(|e| DsmError::InvalidState(format!("AppState: device_id: {e}")))?;
    Ok(dsm::common::device_tree::DeviceTree::single(device_id)
        .root()
        .to_vec())
}

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

        // A state file that exists but cannot be read or decoded is not an
        // absent one: reading it as defaults would report "no identity" for a
        // device that has one.
        let storage = if path.exists() {
            let bytes = fs::read(&path).unwrap_or_else(|e| {
                #[allow(clippy::panic)]
                {
                    panic!(
                        "AppState: {} exists but cannot be read ({e}); it is not treated as \
                         empty",
                        path.display()
                    )
                }
            });
            let proto = generated::AppStateStorage::decode(&*bytes).unwrap_or_else(|e| {
                #[allow(clippy::panic)]
                {
                    panic!(
                        "AppState: {} is not a valid state file ({e}); it is not treated as empty",
                        path.display()
                    )
                }
            });
            AppStateStorage {
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

    /// Whether AppState can be read without reaching the loader's missing-base-dir
    /// panic: once startup has set the storage base dir. Platform entry points
    /// that can run before startup finishes (an Android lifecycle callback, a
    /// background service Android restarts on its own) check this and answer
    /// "not available" instead.
    pub fn readable() -> bool {
        storage_utils::get_storage_base_dir().is_some()
    }

    /// Write `storage` to disk atomically: a temp file, mode 0600, renamed
    /// over the state file.
    fn write(storage: &AppStateStorage) -> Result<(), DsmError> {
        let proto = generated::AppStateStorage {
            has_identity: storage.has_identity,
            sdk_initialized: storage.sdk_initialized,
            device_id: storage.device_id.clone(),
            public_key: storage.public_key.clone(),
            genesis_hash: storage.genesis_hash.clone(),
            smt_root: storage.smt_root.clone(),
            device_tree_root: storage.device_tree_root.clone(),
            recovery_sessions: storage.recovery_sessions.clone(),
            key_value_store: storage.key_value_store.clone(),
            contact_device_tree_roots: storage.contact_device_tree_roots.clone(),
        };
        let buf = proto.encode_to_vec();
        let path = Self::get_storage_path();
        let tmp = path.with_extension("pb.tmp");

        fs::write(&tmp, &buf).map_err(|e| {
            DsmError::storage(format!("AppState: write {}", tmp.display()), Some(e))
        })?;
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&tmp)
                .map_err(|e| {
                    DsmError::storage(format!("AppState: stat {}", tmp.display()), Some(e))
                })?
                .permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&tmp, permissions).map_err(|e| {
                DsmError::storage(format!("AppState: chmod {}", tmp.display()), Some(e))
            })?;
        }
        if let Err(rename) = fs::rename(&tmp, &path) {
            return Err(match fs::remove_file(&tmp) {
                Ok(()) => DsmError::storage(
                    format!("AppState: rename {} to {}", tmp.display(), path.display()),
                    Some(rename),
                ),
                Err(cleanup) => DsmError::storage(
                    format!(
                        "AppState: rename {} to {} failed ({rename}) and the temp file was not \
                         removed ({cleanup})",
                        tmp.display(),
                        path.display()
                    ),
                    None::<std::io::Error>,
                ),
            });
        }
        log::info!("AppState: state saved ({:?}, {} bytes)", path, buf.len());
        Ok(())
    }

    /// Apply `change` to the stored state and persist it. Memory holds the
    /// change only once the disk does: a failed write leaves both as they were.
    fn update<T>(change: impl FnOnce(&mut AppStateStorage) -> T) -> Result<T, DsmError> {
        Self::ensure_storage_loaded();
        let mut guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = guard
            .clone()
            .ok_or_else(|| DsmError::InvalidState("AppState: storage is not loaded".into()))?;
        let outcome = change(&mut next);
        Self::write(&next)?;
        HAS_IDENTITY.store(next.has_identity, Ordering::SeqCst);
        SDK_INITIALIZED.store(next.sdk_initialized, Ordering::SeqCst);
        *guard = Some(next);
        Ok(outcome)
    }

    /// Mark identity presence flag and persist.
    pub fn set_has_identity(value: bool) -> Result<(), DsmError> {
        Self::update(|s| s.has_identity = value)
    }

    /// After successful genesis, write identity bytes and persist (overwrites
    /// existing). The device tree root `R_G` is the single-device tree over the
    /// device id (§2.3).
    pub fn set_identity_info(
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        genesis_hash: Vec<u8>,
        smt_root: Vec<u8>,
    ) -> Result<(), DsmError> {
        let tree_root = single_device_tree_root(&device_id)?;
        Self::update(|s| {
            s.device_id = Some(device_id);
            s.public_key = Some(public_key);
            s.genesis_hash = Some(genesis_hash);
            s.smt_root = Some(smt_root);
            s.device_tree_root = Some(tree_root);
        })
    }

    /// Write identity bytes only where none are held yet (idempotent
    /// bootstrap).
    pub fn set_identity_info_if_empty(
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        genesis_hash: Vec<u8>,
        smt_root: Vec<u8>,
    ) -> Result<(), DsmError> {
        let tree_root = single_device_tree_root(&device_id)?;
        Self::update(|s| {
            if s.device_id.is_none() {
                s.device_id = Some(device_id);
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
            if s.device_tree_root.is_none() {
                s.device_tree_root = Some(tree_root);
            }
        })
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
    pub fn set_device_tree_root(root: [u8; 32]) -> Result<(), DsmError> {
        Self::update(|s| s.device_tree_root = Some(root.to_vec()))
    }

    /// Boolean flags
    pub fn get_has_identity() -> bool {
        Self::ensure_storage_loaded();
        HAS_IDENTITY.load(Ordering::SeqCst)
    }
    pub fn set_sdk_initialized(value: bool) -> Result<(), DsmError> {
        Self::update(|s| s.sdk_initialized = value)
    }
    pub fn get_sdk_initialized() -> bool {
        Self::ensure_storage_loaded();
        SDK_INITIALIZED.load(Ordering::SeqCst)
    }

    /// A stored preference, or `None` when none is held under `key`.
    pub fn get_pref(key: &str) -> Option<String> {
        Self::ensure_storage_loaded();
        let guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref()?.key_value_store.get(key).cloned()
    }

    /// Store a preference and persist it.
    pub fn set_pref(key: &str, value: &str) -> Result<(), DsmError> {
        Self::update(|s| {
            s.key_value_store.insert(key.to_string(), value.to_string());
        })
    }

    /// Recovery session helpers
    pub fn set_recovery_state(recovery_id: &str, status: &str) -> Result<(), DsmError> {
        Self::update(|s| {
            s.recovery_sessions
                .insert(recovery_id.to_string(), status.to_string());
        })
    }

    pub fn get_recovery_state(recovery_id: &str) -> Option<String> {
        Self::ensure_storage_loaded();
        let guard = STORAGE.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref()?.recovery_sessions.get(recovery_id).cloned()
    }

    pub fn clear_recovery_state(recovery_id: &str) -> Result<(), DsmError> {
        Self::update(|s| {
            s.recovery_sessions.remove(recovery_id);
        })
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
            if let Err(e) = fs::remove_file(&path) {
                panic!(
                    "AppState::reset_for_testing: remove {}: {e}",
                    path.display()
                );
            }
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
    use serial_test::serial;

    /// A fresh store: the test storage dir, no state file, nothing in memory.
    fn fresh_store() {
        crate::economic_fixtures::use_test_storage_dir();
        AppState::reset_for_testing();
    }

    /// Drop what memory holds and read the state file again, as a restarted
    /// process does.
    fn reload() {
        AppState::reset_memory_for_testing();
        AppState::ensure_storage_loaded();
    }

    // ── identity reads before storage init ──

    /// Run only by `identity_reads_before_storage_init_answer_not_available`,
    /// in a process of its own where no storage base dir has been set, as when
    /// an Android lifecycle callback or a restarted background service asks
    /// for identity before startup.
    #[test]
    #[ignore = "run by identity_reads_before_storage_init_answer_not_available in its own process"]
    fn identity_reads_before_storage_init_child() {
        assert!(
            storage_utils::get_storage_base_dir().is_none(),
            "the child runs before any storage init"
        );
        assert!(
            !AppState::readable(),
            "AppState is not readable before storage init"
        );
        assert_eq!(
            AppState::readable().then(AppState::get_device_id).flatten(),
            None
        );
        assert_eq!(
            AppState::readable()
                .then(AppState::get_genesis_hash)
                .flatten(),
            None
        );
        assert_eq!(
            AppState::readable()
                .then(AppState::get_public_key)
                .flatten(),
            None
        );
        // The check is load-bearing: the same read without it panics here.
        assert!(
            std::panic::catch_unwind(AppState::get_device_id).is_err(),
            "an unguarded read before storage init panics"
        );
    }

    /// Identity reads that can arrive before startup has set the storage base dir
    /// answer "not available" instead of panicking. The check runs in a child process
    /// because the storage base dir is set once per process and other tests set it.
    #[test]
    fn identity_reads_before_storage_init_answer_not_available() {
        let path = module_path!();
        let test_module = path.split_once("::").map_or(path, |(crate_name, rest)| {
            assert_eq!(crate_name, "dsm_sdk");
            rest
        });
        let child = format!("{test_module}::identity_reads_before_storage_init_child");
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                child.as_str(),
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("spawn the child test");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // ── persistence ──

    /// Everything a setter stores is on disk: a reload reads it back.
    #[test]
    #[serial]
    fn what_is_set_survives_a_reload() {
        fresh_store();
        let device_id = vec![0x11; 32];
        AppState::set_identity_info(
            device_id.clone(),
            vec![0x22; 64],
            vec![0x33; 32],
            vec![0x44; 32],
        )
        .expect("identity");
        AppState::set_has_identity(true).expect("has identity");
        AppState::set_sdk_initialized(true).expect("sdk initialized");
        AppState::set_pref("theme", "dark").expect("pref");
        AppState::set_recovery_state("r1", "pending").expect("recovery state");

        reload();
        assert_eq!(AppState::get_device_id(), Some(device_id.clone()));
        assert_eq!(AppState::get_public_key(), Some(vec![0x22; 64]));
        assert_eq!(AppState::get_genesis_hash(), Some(vec![0x33; 32]));
        assert_eq!(AppState::get_smt_root(), Some(vec![0x44; 32]));
        let expected_root: [u8; 32] = dsm::common::device_tree::DeviceTree::single(
            device_id.as_slice().try_into().expect("32 bytes"),
        )
        .root();
        assert_eq!(AppState::get_device_tree_root(), Some(expected_root));
        assert!(AppState::get_has_identity());
        assert!(AppState::get_sdk_initialized());
        assert_eq!(AppState::get_pref("theme").as_deref(), Some("dark"));
        assert_eq!(
            AppState::get_recovery_state("r1").as_deref(),
            Some("pending")
        );

        AppState::clear_recovery_state("r1").expect("clear");
        reload();
        assert_eq!(AppState::get_recovery_state("r1"), None);
    }

    /// A pref never set reads as absent, not as an empty value.
    #[test]
    #[serial]
    fn an_unset_pref_is_absent() {
        fresh_store();
        assert_eq!(AppState::get_pref("never-set"), None);
        AppState::set_pref("set-empty", "").expect("pref");
        assert_eq!(AppState::get_pref("set-empty").as_deref(), Some(""));
    }

    /// A write that cannot land changes neither the disk nor memory, and says
    /// so: the temp file's path is a directory, so the write fails.
    #[test]
    #[serial]
    fn a_failed_write_changes_nothing_and_is_reported() {
        fresh_store();
        AppState::set_pref("theme", "dark").expect("first write");
        let tmp = AppState::get_storage_path().with_extension("pb.tmp");
        fs::create_dir_all(&tmp).expect("block the temp path");

        let refused = AppState::set_pref("theme", "light");
        fs::remove_dir_all(&tmp).expect("unblock the temp path");

        assert!(refused.is_err(), "the failed write is reported");
        assert_eq!(
            AppState::get_pref("theme").as_deref(),
            Some("dark"),
            "memory still holds what the disk holds"
        );
        reload();
        assert_eq!(AppState::get_pref("theme").as_deref(), Some("dark"));
    }

    /// A state file that is not a valid state is refused on load, never read
    /// as an empty store (which would report "no identity").
    #[test]
    #[serial]
    fn a_corrupt_state_file_is_not_read_as_empty() {
        fresh_store();
        AppState::set_has_identity(true).expect("has identity");
        fs::write(AppState::get_storage_path(), [0xFF, 0xFF, 0xFF]).expect("corrupt the file");
        AppState::reset_memory_for_testing();

        assert!(
            std::panic::catch_unwind(AppState::ensure_storage_loaded).is_err(),
            "a corrupt state file stops the load"
        );
        AppState::reset_for_testing();
    }

    /// An identity whose device id is not 32 bytes is refused: its device tree
    /// root cannot be derived.
    #[test]
    #[serial]
    fn an_identity_without_a_32_byte_device_id_is_refused() {
        fresh_store();
        assert!(AppState::set_identity_info(
            vec![0x11; 31],
            vec![0x22; 64],
            vec![0x33; 32],
            vec![0x44; 32],
        )
        .is_err());
        assert_eq!(AppState::get_device_id(), None);
    }

    /// Only the empty identity fields are filled by the bootstrap write.
    #[test]
    #[serial]
    fn set_identity_info_if_empty_keeps_what_is_held() {
        fresh_store();
        AppState::set_identity_info(
            vec![0x11; 32],
            vec![0x22; 64],
            vec![0x33; 32],
            vec![0x44; 32],
        )
        .expect("identity");
        AppState::set_identity_info_if_empty(
            vec![0x55; 32],
            vec![0x66; 64],
            vec![0x77; 32],
            vec![0x88; 32],
        )
        .expect("bootstrap write");
        reload();
        assert_eq!(AppState::get_device_id(), Some(vec![0x11; 32]));
        assert_eq!(AppState::get_public_key(), Some(vec![0x22; 64]));
    }
}
