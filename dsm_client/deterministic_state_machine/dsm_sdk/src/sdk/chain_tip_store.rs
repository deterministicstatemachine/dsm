//! # SQLite Chain Tip Store
//!
//! Implements the [`ChainTipStore`]
//! trait from `dsm::core` using the SDK's SQLite client database as the
//! backing store. This allows the bilateral transaction manager to persist
//! and retrieve per-contact chain tips across process restarts.

use dsm::core::chain_tip_store::ChainTipStore;
use dsm::types::error::DsmError;

use crate::storage::client_db;

/// SQLite-backed chain tip store for SDK usage.
#[derive(Default, Clone)]
pub struct SqliteChainTipStore;

impl SqliteChainTipStore {
    pub fn new() -> Self {
        Self
    }
}

impl ChainTipStore for SqliteChainTipStore {
    fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
        client_db::get_contact_chain_tip_raw(device_id)
    }

    fn set_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
        expected_parent_tip: [u8; 32],
        new_tip: [u8; 32],
    ) -> Result<bool, DsmError> {
        let request = client_db::bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: *device_id,
            expected_parent_tip,
            target_tip: new_tip,
            observed_gate: None,
            clear_gate_on_success: false,
        };
        match client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request) {
            Ok(outcome) => match outcome {
                client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. }
                | client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. }
                | client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. } => Ok(true),
                _ => Ok(false),
            },
            Err(e) => Err(DsmError::InvalidState(format!(
                "SqliteChainTipStore persist failed: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_instance() {
        let store = SqliteChainTipStore::new();
        let _ = format!("{:?}", &store as &dyn ChainTipStore);
    }

    #[test]
    fn default_creates_instance() {
        let store = SqliteChainTipStore;
        let store2 = store.clone();
        let _ = store2;
    }

    #[test]
    fn implements_chain_tip_store_trait() {
        fn assert_impl<T: ChainTipStore>(_: &T) {}
        assert_impl(&SqliteChainTipStore::new());
    }

    #[test]
    fn implements_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteChainTipStore>();
    }

    #[test]
    fn clone_produces_equivalent_instance() {
        let s1 = SqliteChainTipStore::new();
        let s2 = s1.clone();
        let fmt1 = format!("{:?}", &s1 as &dyn ChainTipStore);
        let fmt2 = format!("{:?}", &s2 as &dyn ChainTipStore);
        assert_eq!(fmt1, fmt2);
    }

    #[test]
    fn multiple_instances_independent() {
        let _a = SqliteChainTipStore::new();
        let _b = SqliteChainTipStore;
        let _c = SqliteChainTipStore::new();
    }

    #[test]
    fn can_be_boxed_as_trait_object() {
        let store: Box<dyn ChainTipStore> = Box::new(SqliteChainTipStore::new());
        let _ = format!("{store:?}");
    }

    #[test]
    fn can_be_arc_wrapped() {
        let store = std::sync::Arc::new(SqliteChainTipStore::new());
        let store2 = std::sync::Arc::clone(&store);
        let _ = store2;
    }
}
