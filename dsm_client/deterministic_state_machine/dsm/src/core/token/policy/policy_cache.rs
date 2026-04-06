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
    /// Uses `crate::utils::deterministic_time::tick_index()` — not wall-clock time.
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
            entry.last_accessed = crate::utils::deterministic_time::tick_index();
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
                last_accessed: crate::utils::deterministic_time::tick_index(),
            },
        );
    }

    pub fn index_token_policy(&self, token_id: String, anchor: PolicyAnchor) {
        let mut index = self.token_index.write();
        index.insert(token_id, anchor);
    }

    pub fn get_anchor_for_token(&self, token_id: &str) -> Option<PolicyAnchor> {
        self.token_index.read().get(token_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::policy_types::{PolicyCondition, PolicyFile, PolicyRole};

    fn make_policy(author: &str) -> TokenPolicy {
        let mut pf = PolicyFile::new("TestPolicy", "1.0", author);
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["Transfer".to_string()],
        });
        pf.add_role(PolicyRole {
            id: "owner".into(),
            name: "Owner".into(),
            permissions: vec!["Transfer".into()],
        });
        TokenPolicy::new(pf).unwrap()
    }

    #[tokio::test]
    async fn test_store_and_get_policy() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());
        let policy = make_policy("author-stored");
        let anchor = policy.anchor.clone();

        cache.store_policy(anchor.clone(), policy.clone());
        let retrieved = cache.get_policy(&anchor).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().anchor, anchor);
    }

    #[tokio::test]
    async fn test_get_missing_policy_returns_none() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());
        let fake_anchor = PolicyAnchor::from_bytes([0xBB; 32]);
        let result = cache.get_policy(&fake_anchor).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_lru_eviction_at_capacity() {
        let config = PolicyCacheConfig {
            max_entries: 2,
            ttl_ticks: 100_000,
        };
        let cache = PolicyCache::new(config);

        let p1 = make_policy("author-p1");
        let p2 = make_policy("author-p2");
        let p3 = make_policy("author-p3");

        let a1 = p1.anchor.clone();
        let a2 = p2.anchor.clone();
        let a3 = p3.anchor.clone();

        cache.store_policy(a1.clone(), p1);
        cache.store_policy(a2.clone(), p2);
        assert_eq!(cache.len(), 2);

        cache.store_policy(a3.clone(), p3);
        assert_eq!(cache.len(), 2);
        assert!(cache.entries.read().contains_key(&a3));
    }

    #[test]
    fn test_index_token_policy_and_lookup() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());
        let policy = make_policy("author-indexed");
        let anchor = policy.anchor.clone();

        cache.store_policy(anchor.clone(), policy);
        cache.index_token_policy("tok-123".to_string(), anchor.clone());

        let looked_up = cache.get_anchor_for_token("tok-123");
        assert_eq!(looked_up, Some(anchor));
    }

    #[test]
    fn test_index_token_policy_missing_returns_none() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());
        assert!(cache.get_anchor_for_token("nonexistent").is_none());
    }

    #[test]
    fn test_default_config_values() {
        let config = PolicyCacheConfig::default();
        assert_eq!(config.max_entries, 1000);
        assert_eq!(config.ttl_ticks, 10_000);
    }

    #[test]
    fn test_is_empty_and_len() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let policy = make_policy("author-len");
        let anchor = policy.anchor.clone();
        cache.store_policy(anchor, policy);

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_overwrite_same_anchor() {
        let config = PolicyCacheConfig {
            max_entries: 2,
            ttl_ticks: 100_000,
        };
        let cache = PolicyCache::new(config);

        let policy = make_policy("author-same");
        let anchor = policy.anchor.clone();

        cache.store_policy(anchor.clone(), policy.clone());
        cache.store_policy(anchor.clone(), policy);
        assert_eq!(cache.len(), 1);
    }
}
