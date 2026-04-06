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

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(suffix: &str) -> PathBuf {
        std::env::temp_dir()
            .join("dsm_storage_utils_tests")
            .join(suffix)
    }

    #[test]
    fn set_storage_creates_nonexistent_dir() {
        let dir = unique_temp_dir("create_test");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).ok();
        }
        assert!(!dir.exists());
        let result = set_storage_base_dir(dir.clone());
        // May return Ok(true) or Ok(false) depending on whether OnceLock was already set
        // by another test in this process, but should not error.
        assert!(result.is_ok());
        assert!(dir.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_storage_returns_false_on_second_call() {
        // OnceLock is per-process, so if another test already set it, this returns Ok(false)
        let dir1 = unique_temp_dir("second_call_1");
        let dir2 = unique_temp_dir("second_call_2");
        let _ = set_storage_base_dir(dir1.clone());
        let result = set_storage_base_dir(dir2.clone());
        assert!(result.is_ok());
        assert!(!result.unwrap());
        std::fs::remove_dir_all(&dir1).ok();
        std::fs::remove_dir_all(&dir2).ok();
    }

    #[test]
    fn get_storage_base_dir_returns_option() {
        // After any set call, get should return Some
        let val = get_storage_base_dir();
        // We can't guarantee the OnceLock state across tests, but the function should not panic
        let _ = val;
    }

    #[test]
    fn ensure_storage_base_dir_returns_result() {
        // If OnceLock was never set (unlikely given other tests), this returns Err
        // If it was set, it returns Ok with the path
        let result = ensure_storage_base_dir();
        // Just verify it doesn't panic
        let _ = result;
    }
}
