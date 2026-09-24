// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-relationship chain tip tracking for bilateral state synchronization.
//!
//! Provides the [`ChainTipStore`] trait, an abstraction over persistent storage
//! for bilateral chain tips. Each relationship maintains its own chain tip
//! (the hash of the most recent bilateral state) keyed by a device ID.
//! The SDK layer provides the concrete implementation backed by
//! platform-specific storage.

use crate::types::error::DsmError;

/// Chain-tip store abstraction (SDKs provide the backing store).
///
/// Core stays storage-agnostic; callers can provide a DB-backed implementation.
pub trait ChainTipStore: Send + Sync {
    /// Get the latest chain tip for a contact relationship (if available).
    fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]>;

    /// Persist the latest chain tip for a contact relationship if the parent still matches.
    ///
    /// Returns `Ok(true)` when the update was applied, `Ok(false)` when the
    /// expected parent no longer matches, and `Err(_)` for storage failures.
    fn set_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
        expected_parent_tip: [u8; 32],
        new_tip: [u8; 32],
    ) -> Result<bool, DsmError>;
}

impl std::fmt::Debug for dyn ChainTipStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainTipStore(..)")
    }
}

/// A chain-tip store over process memory with the trait's compare-and-set
/// semantics, for Core's own tests: Core has no durable store of its own, and
/// the SDK's store needs the SDK's database.
#[cfg(test)]
pub(crate) mod memory {
    use super::ChainTipStore;
    use crate::types::error::DsmError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The tip recorded per counterparty device id; an absent tip reads as
    /// the zero parent a relationship starts from.
    #[derive(Default)]
    pub(crate) struct InMemoryChainTipStore {
        tips: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    }

    impl InMemoryChainTipStore {
        pub(crate) fn new() -> Self {
            Self::default()
        }
    }

    impl ChainTipStore for InMemoryChainTipStore {
        fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
            self.tips
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(device_id)
                .copied()
        }

        fn set_contact_chain_tip(
            &self,
            device_id: &[u8; 32],
            expected_parent_tip: [u8; 32],
            new_tip: [u8; 32],
        ) -> Result<bool, DsmError> {
            let mut tips = self.tips.lock().unwrap_or_else(|p| p.into_inner());
            let current = tips.get(device_id).copied().unwrap_or([0u8; 32]);
            if current != expected_parent_tip {
                return Ok(false);
            }
            tips.insert(*device_id, new_tip);
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::InMemoryChainTipStore;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn debug_impl_for_dyn_chain_tip_store() {
        let store: Arc<dyn ChainTipStore> = Arc::new(InMemoryChainTipStore::new());
        let dbg = format!("{:?}", store);
        assert!(dbg.contains("ChainTipStore(..)"));
    }

    #[test]
    fn in_memory_store_set_then_get() {
        let store = InMemoryChainTipStore::new();
        let id = [42u8; 32];
        let tip = [99u8; 32];
        assert!(store.get_contact_chain_tip(&id).is_none());
        assert!(store.set_contact_chain_tip(&id, [0u8; 32], tip).unwrap());
        assert_eq!(store.get_contact_chain_tip(&id), Some(tip));
    }

    #[test]
    fn in_memory_store_cas_rejects_wrong_parent() {
        let store = InMemoryChainTipStore::new();
        let id = [1u8; 32];
        let tip1 = [10u8; 32];
        let tip2 = [20u8; 32];
        store.set_contact_chain_tip(&id, [0u8; 32], tip1).unwrap();

        let wrong_parent = [0xFFu8; 32];
        let applied = store
            .set_contact_chain_tip(&id, wrong_parent, tip2)
            .unwrap();
        assert!(!applied, "CAS should reject wrong parent");
        assert_eq!(store.get_contact_chain_tip(&id), Some(tip1));
    }

    #[test]
    fn in_memory_store_cas_accepts_correct_parent() {
        let store = InMemoryChainTipStore::new();
        let id = [5u8; 32];
        let tip1 = [10u8; 32];
        let tip2 = [20u8; 32];
        store.set_contact_chain_tip(&id, [0u8; 32], tip1).unwrap();
        let applied = store.set_contact_chain_tip(&id, tip1, tip2).unwrap();
        assert!(applied);
        assert_eq!(store.get_contact_chain_tip(&id), Some(tip2));
    }
}
