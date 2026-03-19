//! # SQLite Chain Tip Store
//!
//! Implements the [`ChainTipStore`]
//! trait from `dsm::core` using the SDK's SQLite client database as the
//! backing store. This allows the bilateral transaction manager to persist
//! and retrieve per-contact chain tips across process restarts.

use dsm::core::chain_tip_store::ChainTipStore;

use crate::storage::client_db;
use log::warn;

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

    fn set_contact_chain_tip(&self, device_id: &[u8; 32], new_tip: [u8; 32]) {
        if let Err(e) = client_db::update_finalized_bilateral_chain_tip(device_id, &new_tip) {
            warn!("SqliteChainTipStore: failed to persist finalized chain tip: {e}");
        }
    }
}
