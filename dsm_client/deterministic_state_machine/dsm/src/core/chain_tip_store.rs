//! Per-relationship chain tip tracking for bilateral state synchronization.
//!
//! Provides the [`ChainTipStore`] trait, an abstraction over persistent storage
//! for bilateral chain tips. Each relationship maintains its own chain tip
//! (the hash of the most recent bilateral state) keyed by a device ID.
//! The SDK layer provides the concrete implementation backed by
//! platform-specific storage.

use std::sync::Arc;

/// Chain-tip store abstraction (SDKs provide the backing store).
///
/// Core stays storage-agnostic; callers can provide a DB-backed implementation.
pub trait ChainTipStore: Send + Sync {
    /// Get the latest chain tip for a contact relationship (if available).
    fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]>;

    /// Persist the latest chain tip for a contact relationship.
    fn set_contact_chain_tip(&self, device_id: &[u8; 32], new_tip: [u8; 32]);
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

    fn set_contact_chain_tip(&self, _device_id: &[u8; 32], _new_tip: [u8; 32]) {}
}

/// Convenience helper for a default no-op store.
pub fn noop_chain_tip_store() -> Arc<dyn ChainTipStore> {
    Arc::new(NoopChainTipStore)
}
