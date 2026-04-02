//! # Decentralized Storage Adapter
//!
//! Implements the [`DecentralizedStorage`]
//! trait using the SDK's SQLite client database, bridging the core security
//! layer's storage requirements to the local persistence engine.

use dsm::core::security::DecentralizedStorage;
use dsm::types::error::DsmError;
use dsm::types::state_types::State;

use crate::storage::client_db;

/// SDK-backed storage adapter for bilateral control resistance checks.
#[derive(Debug, Clone, Default)]
pub struct BcrStorage;

impl BcrStorage {
    pub fn new() -> Self {
        Self
    }
}

impl DecentralizedStorage for BcrStorage {
    fn store_suspicious_activity_report(&self, report: &[u8]) -> Result<(), DsmError> {
        client_db::store_bcr_report(report).map_err(|e| {
            DsmError::storage(
                format!("bcr report persist failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    fn get_historical_states(&self, device_id: &[u8; 32]) -> Result<Vec<State>, DsmError> {
        client_db::get_bcr_states(device_id, false).map_err(|e| {
            DsmError::storage(
                format!("bcr historical state load failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    fn get_published_states(&self, device_id: &[u8; 32]) -> Result<Vec<State>, DsmError> {
        client_db::get_bcr_states(device_id, true).map_err(|e| {
            DsmError::storage(
                format!("bcr published state load failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcr_storage_new() {
        let s = BcrStorage::new();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("BcrStorage"));
    }

    #[test]
    fn bcr_storage_default() {
        let s = BcrStorage::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("BcrStorage"));
    }

    #[test]
    fn bcr_storage_clone() {
        let s = BcrStorage::new();
        let s2 = s.clone();
        let _ = format!("{s2:?}");
    }

    #[test]
    fn bcr_storage_implements_decentralized_storage() {
        fn assert_impl<T: DecentralizedStorage>(_: &T) {}
        assert_impl(&BcrStorage::new());
    }

    #[test]
    fn bcr_storage_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BcrStorage>();
    }

    #[test]
    fn bcr_storage_multiple_clones_independent() {
        let s1 = BcrStorage::new();
        let s2 = s1.clone();
        let s3 = s2.clone();
        let _ = format!("{s1:?} {s2:?} {s3:?}");
    }

    #[test]
    fn bcr_storage_default_eq_new() {
        let d = BcrStorage::default();
        let n = BcrStorage::new();
        assert_eq!(format!("{d:?}"), format!("{n:?}"));
    }
}
