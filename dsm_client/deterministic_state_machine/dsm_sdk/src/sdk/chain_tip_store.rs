// SPDX-License-Identifier: MIT OR Apache-2.0

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
pub struct SqliteChainTipStore {
    /// In-memory anchor frontier (one per anchor device id), shared across clones. The contact chain
    /// tip is SQLite-backed; the anchor frontier is in-memory for now — enough for mock-anchor
    /// end-to-end testing within a process. SQLite persistence of the frontier is a follow-up.
    anchor_frontier:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], ([u8; 32], u64)>>>,
}

impl SqliteChainTipStore {
    pub fn new() -> Self {
        Self::default()
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

    fn get_anchor_frontier(&self, anchor_id: &[u8; 32]) -> Option<([u8; 32], u64)> {
        self.anchor_frontier.lock().unwrap().get(anchor_id).copied()
    }

    fn set_anchor_frontier(
        &self,
        anchor_id: &[u8; 32],
        expected_parent_root: [u8; 32],
        new_root: [u8; 32],
        new_state_number: u64,
    ) -> Result<bool, DsmError> {
        let mut map = self.anchor_frontier.lock().unwrap();
        if let Some((cur_root, cur_state)) = map.get(anchor_id).copied() {
            if cur_root != expected_parent_root || new_state_number <= cur_state {
                return Ok(false);
            }
        }
        map.insert(*anchor_id, (new_root, new_state_number));
        Ok(true)
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
        let store = SqliteChainTipStore::default();
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
        let _b = SqliteChainTipStore::default();
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

    #[test]
    fn anchor_frontier_cas_advances_rejects_replay_and_is_shared_across_clones() {
        let store = SqliteChainTipStore::new();
        let anchor = [7u8; 32];
        let (r0, r1, r2) = ([0u8; 32], [11u8; 32], [22u8; 32]);
        // Untracked frontier starts as None (caller treats it as genesis (0,0)).
        assert_eq!(store.get_anchor_frontier(&anchor), None);
        // First advance from genesis.
        assert!(store.set_anchor_frontier(&anchor, r0, r1, 1).unwrap());
        assert_eq!(store.get_anchor_frontier(&anchor), Some((r1, 1)));
        // Replay from the now-consumed genesis parent is rejected (fork detection).
        assert!(!store.set_anchor_frontier(&anchor, r0, r2, 2).unwrap());
        // Correct parent but non-monotonic state is rejected.
        assert!(!store.set_anchor_frontier(&anchor, r1, r2, 1).unwrap());
        // Correct parent + strictly monotonic state advances (multi-transfer works).
        assert!(store.set_anchor_frontier(&anchor, r1, r2, 2).unwrap());
        assert_eq!(store.get_anchor_frontier(&anchor), Some((r2, 2)));
        // A clone shares the same in-memory frontier (Arc), so the manager's single store tracks it.
        let store2 = store.clone();
        assert_eq!(store2.get_anchor_frontier(&anchor), Some((r2, 2)));
    }
}
