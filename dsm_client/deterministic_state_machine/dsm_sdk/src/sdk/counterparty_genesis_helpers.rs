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

use super::hashchain_sdk::HashChainSDK;

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

/// Create a bilateral branch from a Genesis binding
pub fn create_bilateral_branch(
    _hashchain_sdk: &HashChainSDK,
    counterparty_id: &str,
    genesis_binding: &[u8],
) -> Result<String, DsmError> {
    // Create a unique branch ID based on the Genesis binding
    let branch_id = format!(
        "bilateral_{}_{}",
        crate::util::text_id::short_id(genesis_binding, std::cmp::min(8, genesis_binding.len())),
        counterparty_id
    );

    // In a real implementation, we would:
    // 1. Create a new branch in the hash chain
    // 2. Initialize it with the genesis binding
    // 3. Set up appropriate metadata

    // For now, just return the branch ID
    Ok(branch_id)
}

/// Get the hash of the tip of a branch
pub fn get_branch_tip_id(
    hashchain_sdk: &HashChainSDK,
    branch_id: &str,
) -> Result<String, DsmError> {
    // For the main chain (empty branch ID), get the merkle root
    if branch_id.is_empty() {
        let root = hashchain_sdk.merkle_root()?;
        let tip_id = crate::util::text_id::encode_base32_crockford(root.as_bytes());
        // Return the actual merkle root tip ID
        Ok(tip_id)
    } else {
        // In a real implementation, we would look up the branch's tip
        // For now, return a test value
        Ok(format!("tip_{branch_id}"))
    }
}

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
