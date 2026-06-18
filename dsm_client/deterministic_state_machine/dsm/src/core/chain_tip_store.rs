// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-relationship chain tip tracking for bilateral state synchronization.
//!
//! Provides the [`ChainTipStore`] trait, an abstraction over persistent storage
//! for bilateral chain tips. Each relationship maintains its own chain tip
//! (the hash of the most recent bilateral state) keyed by a device ID.
//! The SDK layer provides the concrete implementation backed by
//! platform-specific storage.

use std::sync::Arc;

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

    /// Get an anchor DEVICE's single monotonic frontier `(stored_root, state_number)`, if tracked.
    ///
    /// The anchor frontier is ONE per device — keyed by the anchor identity `id_anchor`, NOT per
    /// relationship. Every offline-bearer transition the device makes (to ANY counterparty) advances
    /// this one frontier (`dsm_anchor_frontier_successor`); that single serialization is what makes
    /// a clone detectable (it must fork the one counter). Default: untracked (`None`).
    fn get_anchor_frontier(&self, _anchor_id: &[u8; 32]) -> Option<([u8; 32], u64)> {
        None
    }

    /// CAS-advance an anchor device's single frontier: apply only if the stored root still equals
    /// `expected_parent_root` AND `new_state_number` strictly exceeds the stored one (or none is
    /// stored). Returns `Ok(false)` on a stale parent or non-monotonic state — detection of a fork
    /// (a second advance from an already-consumed `parent_root`: a clone or concurrent signer).
    /// Default: a no-op accept for core-only contexts (the device firmware is the primary enforcer;
    /// this is the host-side mirror/detector).
    fn set_anchor_frontier(
        &self,
        _anchor_id: &[u8; 32],
        _expected_parent_root: [u8; 32],
        _new_root: [u8; 32],
        _new_state_number: u64,
    ) -> Result<bool, DsmError> {
        Ok(true)
    }
}

impl std::fmt::Debug for dyn ChainTipStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainTipStore(..)")
    }
}

/// No-op chain-tip store used by default in core-only contexts.
#[derive(Default)]
pub struct NoopChainTipStore;

impl ChainTipStore for NoopChainTipStore {
    fn get_contact_chain_tip(&self, _device_id: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }

    fn set_contact_chain_tip(
        &self,
        _device_id: &[u8; 32],
        _expected_parent_tip: [u8; 32],
        _new_tip: [u8; 32],
    ) -> Result<bool, DsmError> {
        Ok(true)
    }
}

/// Convenience helper for a default no-op store.
pub fn noop_chain_tip_store() -> Arc<dyn ChainTipStore> {
    Arc::new(NoopChainTipStore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn noop_get_always_returns_none() {
        let store = NoopChainTipStore;
        let id = [0xABu8; 32];
        assert!(store.get_contact_chain_tip(&id).is_none());
        assert!(store.get_contact_chain_tip(&[0u8; 32]).is_none());
    }

    #[test]
    fn noop_set_always_succeeds() {
        let store = NoopChainTipStore;
        let id = [1u8; 32];
        let parent = [2u8; 32];
        let tip = [3u8; 32];
        assert!(store.set_contact_chain_tip(&id, parent, tip).unwrap());
    }

    #[test]
    fn noop_helper_returns_arc() {
        let store = noop_chain_tip_store();
        assert!(store.get_contact_chain_tip(&[0u8; 32]).is_none());
        assert!(store
            .set_contact_chain_tip(&[0u8; 32], [0u8; 32], [1u8; 32])
            .unwrap());
    }

    #[test]
    fn debug_impl_for_dyn_chain_tip_store() {
        let store: Arc<dyn ChainTipStore> = noop_chain_tip_store();
        let dbg = format!("{:?}", store);
        assert!(dbg.contains("ChainTipStore(..)"));
    }

    /// `(root, state_number)` recorded per device id.
    type RootEntry = ([u8; 32], u64);

    struct InMemoryChainTipStore {
        tips: Mutex<HashMap<[u8; 32], [u8; 32]>>,
        roots: Mutex<HashMap<[u8; 32], RootEntry>>,
    }

    impl InMemoryChainTipStore {
        fn new() -> Self {
            Self {
                tips: Mutex::new(HashMap::new()),
                roots: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ChainTipStore for InMemoryChainTipStore {
        fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
            self.tips.lock().unwrap().get(device_id).copied()
        }

        fn set_contact_chain_tip(
            &self,
            device_id: &[u8; 32],
            expected_parent_tip: [u8; 32],
            new_tip: [u8; 32],
        ) -> Result<bool, DsmError> {
            let mut tips = self.tips.lock().unwrap();
            let current = tips.get(device_id).copied().unwrap_or([0u8; 32]);
            if current != expected_parent_tip {
                return Ok(false);
            }
            tips.insert(*device_id, new_tip);
            Ok(true)
        }

        fn get_anchor_frontier(&self, anchor_id: &[u8; 32]) -> Option<([u8; 32], u64)> {
            self.roots.lock().unwrap().get(anchor_id).copied()
        }

        fn set_anchor_frontier(
            &self,
            anchor_id: &[u8; 32],
            expected_parent_root: [u8; 32],
            new_root: [u8; 32],
            new_state_number: u64,
        ) -> Result<bool, DsmError> {
            let mut roots = self.roots.lock().unwrap();
            if let Some((cur_root, cur_state)) = roots.get(anchor_id).copied() {
                if cur_root != expected_parent_root || new_state_number <= cur_state {
                    return Ok(false);
                }
            }
            roots.insert(*anchor_id, (new_root, new_state_number));
            Ok(true)
        }
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

    #[test]
    fn anchor_frontier_cas_rejects_double_advance_and_non_monotonic_state() {
        let store = InMemoryChainTipStore::new();
        let anchor = [7u8; 32]; // ONE frontier per anchor device, keyed by id_anchor.
        let (r0, r1, r2) = ([0u8; 32], [11u8; 32], [22u8; 32]);
        // First advance from the empty frontier.
        assert!(store.set_anchor_frontier(&anchor, r0, r1, 1).unwrap());
        assert_eq!(store.get_anchor_frontier(&anchor), Some((r1, 1)));
        // Double-advance from the SAME (now-consumed) parent root is rejected — fork detection.
        assert!(!store.set_anchor_frontier(&anchor, r0, r2, 2).unwrap());
        // Correct parent but non-monotonic state is rejected.
        assert!(!store.set_anchor_frontier(&anchor, r1, r2, 1).unwrap());
        // Correct parent + strictly monotonic state advances.
        assert!(store.set_anchor_frontier(&anchor, r1, r2, 2).unwrap());
        assert_eq!(store.get_anchor_frontier(&anchor), Some((r2, 2)));
    }
}
