//! # Storage Base Directory Management
//!
//! Manages the root filesystem path for all SDK-persisted data (AppState,
//! client database, bilateral storage). The base directory must be set
//! exactly once at application startup via [`set_storage_base_dir`] before
//! any other SDK operation. Subsequent calls return `Ok(false)` without
//! overwriting.

use std::path::PathBuf;
use std::sync::OnceLock;
use dsm::types::error::DsmError;

static STORAGE_BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_storage_base_dir(path: PathBuf) -> Result<bool, DsmError> {
    if !path.exists() {
        std::fs::create_dir_all(&path).map_err(|e| {
            DsmError::storage(
                format!("Failed to create storage base dir {path:?}: {e}"),
                Some(e),
            )
        })?;
    }
    match STORAGE_BASE_DIR.set(path) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn get_storage_base_dir() -> Option<PathBuf> {
    STORAGE_BASE_DIR.get().cloned()
}

pub fn ensure_storage_base_dir() -> Result<PathBuf, DsmError> {
    get_storage_base_dir().ok_or_else(|| {
        DsmError::storage(
            "Storage base directory not set. Call set_storage_base_dir() at app startup.",
            Option::<std::io::Error>::None,
        )
    })
}
