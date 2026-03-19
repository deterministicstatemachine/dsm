//! src/core/token/policy/policy_cache.rs
//! Policy Cache Implementation

use std::collections::HashMap;
use parking_lot::RwLock;
use crate::types::policy_types::{TokenPolicy, PolicyAnchor};
use crate::types::error::DsmError;

#[derive(Debug, Clone)]
pub struct PolicyCacheConfig {
    pub max_entries: usize,
    /// Maximum age in deterministic ticks before an entry is eligible for LRU eviction.
    /// Uses `crate::util::deterministic_time::tick_index()` — not wall-clock time.
    pub ttl_ticks: u64,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            ttl_ticks: 10_000, // deterministic ticks
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyCacheEntry {
    pub policy: TokenPolicy,
    pub last_accessed: u64, // Ticks
}

#[derive(Debug)]
pub struct PolicyCache {
    entries: RwLock<HashMap<PolicyAnchor, PolicyCacheEntry>>,
    token_index: RwLock<HashMap<String, PolicyAnchor>>,
    config: PolicyCacheConfig,
}

impl PolicyCache {
    pub fn new(config: PolicyCacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            token_index: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub async fn get_policy(&self, anchor: &PolicyAnchor) -> Result<Option<TokenPolicy>, DsmError> {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.get_mut(anchor) {
            entry.last_accessed = crate::util::deterministic_time::tick_index();
            return Ok(Some(entry.policy.clone()));
        }
        Ok(None)
    }

    pub fn store_policy(&self, anchor: PolicyAnchor, policy: TokenPolicy) {
        let mut entries = self.entries.write();
        // LRU eviction: remove the least-recently-accessed entry when at capacity.
        if entries.len() >= self.config.max_entries && !entries.contains_key(&anchor) {
            if let Some(k) = entries
                .iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&k);
            }
        }

        entries.insert(
            anchor,
            PolicyCacheEntry {
                policy,
                last_accessed: crate::util::deterministic_time::tick_index(),
            },
        );
    }

    pub fn index_token_policy(&self, token_id: String, anchor: PolicyAnchor) {
        let mut index = self.token_index.write();
        index.insert(token_id, anchor);
    }
}
