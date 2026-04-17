//! # Counterparty Genesis State Helpers
//!
//! Utility functions for working with counterparty Genesis states in
//! bilateral transactions, including fetching from storage nodes,
//! in-memory caching, and cryptographic verification of genesis material.

use dsm::{core::identity::genesis::GenesisState, types::error::DsmError};
use std::{
    collections::{HashMap, VecDeque},
    sync::RwLock,
};

// HashChainSDK import removed: create_bilateral_branch + get_branch_tip_id
// helpers (the only HashChainSDK consumers in this file) deleted below.

/// Storage format for cached Genesis states
#[derive(Clone, Debug)]
pub struct CachedGenesisState {
    /// The Genesis state
    pub state: GenesisState,
    /// Hash of the Genesis state
    pub state_hash: Vec<u8>,
    /// Whether the Genesis state was verified
    pub verified: bool,
    /// Source endpoint where this Genesis was fetched
    pub source: String,
    /// Device ID this Genesis state belongs to
    pub device_id: String,
}

/// Genesis state cache for efficient retrieval and verification
/// Uses insertion order for eviction (deterministic, clockless)
pub struct GenesisStateCache {
    /// Mapping from device ID to its Genesis state
    cache: RwLock<HashMap<String, CachedGenesisState>>,
    /// Insertion order for LRU eviction
    insertion_order: RwLock<VecDeque<String>>,
    /// Maximum number of Genesis states to cache
    max_size: usize,
}

impl Default for GenesisStateCache {
    fn default() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            insertion_order: RwLock::new(VecDeque::new()),
            max_size: 100,
        }
    }
}

impl GenesisStateCache {
    /// Create a new Genesis state cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            insertion_order: RwLock::new(VecDeque::new()),
            max_size,
        }
    }

    /// Cache a Genesis state
    pub fn cache_genesis_state(
        &self,
        device_id: &str,
        state: GenesisState,
        state_hash: Vec<u8>,
        verified: bool,
        source: &str,
    ) -> Result<(), DsmError> {
        let mut cache = self.cache.write().map_err(|_| {
            DsmError::internal(
                "Failed to acquire write lock for Genesis cache",
                None::<String>,
            )
        })?;
        let mut insertion_order = self.insertion_order.write().map_err(|_| {
            DsmError::internal(
                "Failed to acquire write lock for insertion order",
                None::<String>,
            )
        })?;

        // Remove existing entry if present to update insertion order
        if cache.contains_key(device_id) {
            insertion_order.retain(|k| k != device_id);
        }

        // Enforce cache size limit using insertion order
        if cache.len() >= self.max_size && !cache.contains_key(device_id) {
            // Remove the oldest entry (front of deque)
            if let Some(oldest_key) = insertion_order.front().cloned() {
                cache.remove(&oldest_key);
                insertion_order.pop_front();
            }
        }

        // Add to insertion order
        insertion_order.push_back(device_id.to_string());

        // Add or update the cached Genesis state
        cache.insert(
            device_id.to_string(),
            CachedGenesisState {
                state,
                state_hash,
                verified,
                source: source.to_string(),
                device_id: device_id.to_string(),
            },
        );

        Ok(())
    }

    /// Get a cached Genesis state
    pub async fn get_genesis_state(
        &self,
        device_id: &str,
    ) -> Result<Option<CachedGenesisState>, DsmError> {
        let cache = self.cache.read().map_err(|_| {
            DsmError::internal(
                "Failed to acquire read lock for Genesis cache",
                None::<String>,
            )
        })?;

        Ok(cache.get(device_id).cloned())
    }

    /// Check if a Genesis state is in the cache
    pub async fn is_genesis_state_cached(&self, device_id: &str) -> Result<bool, DsmError> {
        let cache = self.cache.read().map_err(|_| {
            DsmError::internal(
                "Failed to acquire read lock for Genesis cache",
                None::<String>,
            )
        })?;

        Ok(cache.contains_key(device_id))
    }

    /// Remove a cached Genesis state
    pub fn remove_genesis_state(&self, device_id: &str) -> Result<bool, DsmError> {
        let mut cache = self.cache.write().map_err(|_| {
            DsmError::internal(
                "Failed to acquire write lock for Genesis cache",
                None::<String>,
            )
        })?;
        let mut insertion_order = self.insertion_order.write().map_err(|_| {
            DsmError::internal(
                "Failed to acquire write lock for insertion order",
                None::<String>,
            )
        })?;

        insertion_order.retain(|k| k != device_id);
        Ok(cache.remove(device_id).is_some())
    }

    /// Mark a Genesis state as verified
    pub fn mark_genesis_state_verified(&self, device_id: &str) -> Result<bool, DsmError> {
        let mut cache = self.cache.write().map_err(|_| {
            DsmError::internal(
                "Failed to acquire write lock for Genesis cache",
                None::<String>,
            )
        })?;

        if let Some(entry) = cache.get_mut(device_id) {
            entry.verified = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all cached Genesis states
    pub async fn list_cached_genesis_states(&self) -> Result<Vec<String>, DsmError> {
        let cache = self.cache.read().map_err(|_| {
            DsmError::internal(
                "Failed to acquire read lock for Genesis cache",
                None::<String>,
            )
        })?;

        Ok(cache.keys().cloned().collect())
    }
}

/// Create a binding between two Genesis states
pub fn create_genesis_binding(
    local_genesis: &GenesisState,
    counterparty_genesis: &GenesisState,
    binding_type: &str,
) -> Result<Vec<u8>, DsmError> {
    // Combine the Genesis hashes and binding type to create a binding
    let mut binding = Vec::new();

    // Add binding type
    binding.extend_from_slice(binding_type.as_bytes());
    binding.push(0); // Null separator

    // Add local Genesis hash
    binding.extend_from_slice(&local_genesis.hash);

    // Add counterparty Genesis hash
    binding.extend_from_slice(&counterparty_genesis.hash);

    Ok(binding)
}

// create_bilateral_branch + get_branch_tip_id deleted alongside HashChainSDK:
// both were TODO-stubs that took a HashChainSDK but either ignored it
// (`_hashchain_sdk`) or called `hashchain_sdk.merkle_root()` whose underlying
// state-history tree is superseded by DeviceState's per-relationship SMT.
// Zero external callers for either function.

/// Fetch a Genesis state from a storage node (network operation)
pub async fn fetch_genesis_state(
    device_id: &str,
    _storage_endpoint: &str,
) -> Result<GenesisState, DsmError> {
    // In a real implementation, this would make an HTTP request to the storage node
    // For now (tests/utilities), synthesize a MPC-style Genesis using the strict path
    use dsm::core::identity::genesis::create_genesis_via_blind_mpc;
    use dsm::types::identifiers::NodeId;

    // Derive a deterministic 32-byte device id from the provided string
    let device_id_arr = crate::util::domain_helpers::device_id_hash(device_id);

    // Use a fixed small set of test nodes (deterministic; no network dependency)
    let nodes = vec![NodeId::new("n1"), NodeId::new("n2"), NodeId::new("n3")];

    // Threshold pinned to production minimum (3)
    create_genesis_via_blind_mpc(device_id_arr, nodes, 3, None).await
}

/// Verify a Genesis state against known storage nodes
pub async fn verify_genesis_state(
    _genesis_state: &GenesisState,
    _storage_endpoints: &[&str],
) -> Result<bool, DsmError> {
    // In a real implementation, this would verify the Genesis state with multiple storage nodes
    // For now, always return true
    Ok(true)
}

/// Generate a hash of a Genesis state
pub fn hash_genesis_state(genesis_state: &GenesisState) -> Vec<u8> {
    // In a real implementation, this would compute a cryptographic hash
    // For now, just return the existing hash
    genesis_state.hash.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_genesis(hash: [u8; 32]) -> GenesisState {
        use dsm::core::identity::genesis::{GenesisState as GS, KyberKey, SigningKey};
        GS {
            hash,
            initial_entropy: [0u8; 32],
            threshold: 2,
            participants: Default::default(),
            merkle_root: None,
            device_id: Some([0x01; 32]),
            signing_key: SigningKey {
                public_key: vec![0u8; 32],
                secret_key: vec![0u8; 64],
            },
            kyber_keypair: KyberKey {
                public_key: vec![0u8; 32],
                secret_key: vec![0u8; 64],
            },
            contributions: vec![],
        }
    }

    // ── GenesisStateCache construction ──

    #[test]
    fn default_cache_has_max_100() {
        let cache = GenesisStateCache::default();
        assert_eq!(cache.max_size, 100);
    }

    #[test]
    fn new_cache_respects_max_size() {
        let cache = GenesisStateCache::new(10);
        assert_eq!(cache.max_size, 10);
    }

    // ── cache_genesis_state / get / remove ──

    #[test]
    fn cache_and_retrieve() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0xAA; 32]);
        cache
            .cache_genesis_state("dev1", gs.clone(), vec![1, 2, 3], true, "http://node")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = rt.block_on(cache.get_genesis_state("dev1")).unwrap();
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached.device_id, "dev1");
        assert!(cached.verified);
        assert_eq!(cached.source, "http://node");
        assert_eq!(cached.state_hash, vec![1, 2, 3]);
        assert_eq!(cached.state.hash, [0xAA; 32]);
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = GenesisStateCache::new(10);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = rt.block_on(cache.get_genesis_state("nonexistent")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn is_cached_check() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        assert!(!rt.block_on(cache.is_genesis_state_cached("dev1")).unwrap());
        cache
            .cache_genesis_state("dev1", gs, vec![], false, "src")
            .unwrap();
        assert!(rt.block_on(cache.is_genesis_state_cached("dev1")).unwrap());
    }

    #[test]
    fn remove_existing_returns_true() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);
        cache
            .cache_genesis_state("dev1", gs, vec![], false, "src")
            .unwrap();

        assert!(cache.remove_genesis_state("dev1").unwrap());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt
            .block_on(cache.get_genesis_state("dev1"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let cache = GenesisStateCache::new(10);
        assert!(!cache.remove_genesis_state("ghost").unwrap());
    }

    // ── mark_genesis_state_verified ──

    #[test]
    fn mark_verified_flips_flag() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);
        cache
            .cache_genesis_state("dev1", gs, vec![], false, "src")
            .unwrap();

        assert!(cache.mark_genesis_state_verified("dev1").unwrap());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let cached = rt
            .block_on(cache.get_genesis_state("dev1"))
            .unwrap()
            .unwrap();
        assert!(cached.verified);
    }

    #[test]
    fn mark_verified_missing_returns_false() {
        let cache = GenesisStateCache::new(10);
        assert!(!cache.mark_genesis_state_verified("ghost").unwrap());
    }

    // ── list_cached_genesis_states ──

    #[test]
    fn list_cached_states() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);
        cache
            .cache_genesis_state("a", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("b", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("c", gs, vec![], false, "s")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut list = rt.block_on(cache.list_cached_genesis_states()).unwrap();
        list.sort();
        assert_eq!(list, vec!["a", "b", "c"]);
    }

    // ── Eviction (insertion-order) ──

    #[test]
    fn eviction_removes_oldest() {
        let cache = GenesisStateCache::new(3);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("d1", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("d2", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("d3", gs.clone(), vec![], false, "s")
            .unwrap();

        // Now at capacity; adding d4 should evict d1
        cache
            .cache_genesis_state("d4", gs, vec![], false, "s")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt
            .block_on(cache.get_genesis_state("d1"))
            .unwrap()
            .is_none());
        assert!(rt
            .block_on(cache.get_genesis_state("d2"))
            .unwrap()
            .is_some());
        assert!(rt
            .block_on(cache.get_genesis_state("d4"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn update_existing_resets_insertion_order() {
        let cache = GenesisStateCache::new(3);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("d1", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("d2", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("d3", gs.clone(), vec![], false, "s")
            .unwrap();

        // Re-insert d1 → moves to back; d2 is now oldest
        cache
            .cache_genesis_state("d1", gs.clone(), vec![9, 9], false, "updated")
            .unwrap();

        // Adding d4 should evict d2 (now oldest)
        cache
            .cache_genesis_state("d4", gs, vec![], false, "s")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt
            .block_on(cache.get_genesis_state("d2"))
            .unwrap()
            .is_none());
        assert!(rt
            .block_on(cache.get_genesis_state("d1"))
            .unwrap()
            .is_some());
        let updated = rt.block_on(cache.get_genesis_state("d1")).unwrap().unwrap();
        assert_eq!(updated.source, "updated");
        assert_eq!(updated.state_hash, vec![9, 9]);
    }

    // ── create_genesis_binding ──

    #[test]
    fn create_genesis_binding_contains_both_hashes() {
        let local = dummy_genesis([0x11; 32]);
        let remote = dummy_genesis([0x22; 32]);
        let binding = create_genesis_binding(&local, &remote, "bilateral").unwrap();

        assert!(binding.starts_with(b"bilateral\0"));
        assert!(binding.windows(32).any(|w| w == [0x11; 32]));
        assert!(binding.windows(32).any(|w| w == [0x22; 32]));
    }

    #[test]
    fn create_genesis_binding_deterministic() {
        let local = dummy_genesis([0xAA; 32]);
        let remote = dummy_genesis([0xBB; 32]);
        let b1 = create_genesis_binding(&local, &remote, "test").unwrap();
        let b2 = create_genesis_binding(&local, &remote, "test").unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn create_genesis_binding_type_affects_output() {
        let local = dummy_genesis([0x01; 32]);
        let remote = dummy_genesis([0x02; 32]);
        let b1 = create_genesis_binding(&local, &remote, "typeA").unwrap();
        let b2 = create_genesis_binding(&local, &remote, "typeB").unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn create_genesis_binding_length() {
        let local = dummy_genesis([0x01; 32]);
        let remote = dummy_genesis([0x02; 32]);
        let binding = create_genesis_binding(&local, &remote, "xyz").unwrap();
        // "xyz" (3) + null (1) + hash_a (32) + hash_b (32) = 68
        assert_eq!(binding.len(), 3 + 1 + 32 + 32);
    }

    // create_bilateral_branch tests removed alongside the helper.

    // ── hash_genesis_state ──

    #[test]
    fn hash_genesis_state_returns_existing_hash() {
        let gs = dummy_genesis([0xDE; 32]);
        let h = hash_genesis_state(&gs);
        assert_eq!(h, vec![0xDE; 32]);
    }

    #[test]
    fn hash_genesis_state_length_32() {
        let gs = dummy_genesis([0x01; 32]);
        assert_eq!(hash_genesis_state(&gs).len(), 32);
    }

    // get_branch_tip_id tests removed alongside the helper.

    // ── CachedGenesisState clone & debug ──

    #[test]
    fn cached_genesis_state_clone_and_debug() {
        let gs = dummy_genesis([0x01; 32]);
        let cached = CachedGenesisState {
            state: gs,
            state_hash: vec![1, 2],
            verified: true,
            source: "test".to_string(),
            device_id: "dev".to_string(),
        };
        let cloned = cached.clone();
        assert_eq!(cloned.device_id, "dev");
        assert!(cloned.verified);
        let dbg = format!("{:?}", cached);
        assert!(dbg.contains("CachedGenesisState"));
    }

    // ── Cache with max_size = 1 ──

    #[test]
    fn cache_max_size_one_evicts_immediately() {
        let cache = GenesisStateCache::new(1);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("first", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("second", gs, vec![], false, "s")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt
            .block_on(cache.get_genesis_state("first"))
            .unwrap()
            .is_none());
        assert!(rt
            .block_on(cache.get_genesis_state("second"))
            .unwrap()
            .is_some());
    }

    // ── Cache: re-insert same key doesn't grow size ──

    #[test]
    fn reinsert_same_key_no_size_growth() {
        let cache = GenesisStateCache::new(2);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("a", gs.clone(), vec![1], false, "s1")
            .unwrap();
        cache
            .cache_genesis_state("a", gs.clone(), vec![2], true, "s2")
            .unwrap();
        cache
            .cache_genesis_state("a", gs.clone(), vec![3], false, "s3")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let list = rt.block_on(cache.list_cached_genesis_states()).unwrap();
        assert_eq!(list.len(), 1);

        let entry = rt.block_on(cache.get_genesis_state("a")).unwrap().unwrap();
        assert_eq!(entry.state_hash, vec![3]);
        assert_eq!(entry.source, "s3");
    }

    // ── Cache: remove then re-add ──

    #[test]
    fn remove_then_readd() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("dev1", gs.clone(), vec![], false, "s")
            .unwrap();
        cache.remove_genesis_state("dev1").unwrap();

        cache
            .cache_genesis_state("dev1", gs, vec![9], true, "s2")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let entry = rt
            .block_on(cache.get_genesis_state("dev1"))
            .unwrap()
            .unwrap();
        assert_eq!(entry.state_hash, vec![9]);
        assert!(entry.verified);
    }

    // ── Cache: list is empty initially ──

    #[test]
    fn list_empty_cache() {
        let cache = GenesisStateCache::new(10);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let list = rt.block_on(cache.list_cached_genesis_states()).unwrap();
        assert!(list.is_empty());
    }

    // ── create_genesis_binding: empty binding type ──

    #[test]
    fn create_genesis_binding_empty_type() {
        let local = dummy_genesis([0x01; 32]);
        let remote = dummy_genesis([0x02; 32]);
        let binding = create_genesis_binding(&local, &remote, "").unwrap();
        // "" (0) + null (1) + hash_a (32) + hash_b (32) = 65
        assert_eq!(binding.len(), 1 + 32 + 32);
        assert_eq!(binding[0], 0); // null separator right at start
    }

    // ── create_genesis_binding: same genesis for both ──

    #[test]
    fn create_genesis_binding_same_genesis() {
        let gs = dummy_genesis([0x55; 32]);
        let binding = create_genesis_binding(&gs, &gs, "self").unwrap();
        // Both hash windows should be identical
        let hash_start = "self".len() + 1; // after "self\0"
        assert_eq!(
            &binding[hash_start..hash_start + 32],
            &binding[hash_start + 32..hash_start + 64]
        );
    }

    // create_bilateral_branch tests (different counterparties / different
    // bindings) removed alongside the helper.

    // ── hash_genesis_state: different hashes ──

    #[test]
    fn hash_genesis_state_different_inputs() {
        let gs1 = dummy_genesis([0x01; 32]);
        let gs2 = dummy_genesis([0x02; 32]);
        assert_ne!(hash_genesis_state(&gs1), hash_genesis_state(&gs2));
    }

    // ── mark_genesis_state_verified: idempotent ──

    #[test]
    fn mark_verified_idempotent() {
        let cache = GenesisStateCache::new(10);
        let gs = dummy_genesis([0x01; 32]);
        cache
            .cache_genesis_state("dev1", gs, vec![], false, "s")
            .unwrap();

        assert!(cache.mark_genesis_state_verified("dev1").unwrap());
        assert!(cache.mark_genesis_state_verified("dev1").unwrap());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(
            rt.block_on(cache.get_genesis_state("dev1"))
                .unwrap()
                .unwrap()
                .verified
        );
    }

    // ── Eviction order: multiple evictions ──

    #[test]
    fn eviction_multiple_rounds() {
        let cache = GenesisStateCache::new(2);
        let gs = dummy_genesis([0x01; 32]);

        cache
            .cache_genesis_state("a", gs.clone(), vec![], false, "s")
            .unwrap();
        cache
            .cache_genesis_state("b", gs.clone(), vec![], false, "s")
            .unwrap();
        // Full. Adding "c" evicts "a".
        cache
            .cache_genesis_state("c", gs.clone(), vec![], false, "s")
            .unwrap();
        // Full with b,c. Adding "d" evicts "b".
        cache
            .cache_genesis_state("d", gs, vec![], false, "s")
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(rt.block_on(cache.get_genesis_state("a")).unwrap().is_none());
        assert!(rt.block_on(cache.get_genesis_state("b")).unwrap().is_none());
        assert!(rt.block_on(cache.get_genesis_state("c")).unwrap().is_some());
        assert!(rt.block_on(cache.get_genesis_state("d")).unwrap().is_some());
    }
}
