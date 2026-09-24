// SPDX-License-Identifier: MIT OR Apache-2.0

//! src/core/token/policy/policy_cache.rs
//! Policy Cache Implementation

use std::collections::HashMap;
use parking_lot::RwLock;
use crate::types::policy_types::{TokenPolicy, PolicyAnchor};
use crate::types::error::DsmError;

#[derive(Debug, Clone)]
pub struct PolicyCacheConfig {
    /// The most policies held; beyond it the least recently used is evicted.
    /// A policy is content-addressed and immutable, so an entry never goes
    /// stale — eviction only bounds memory.
    pub max_entries: usize,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self { max_entries: 1000 }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyCacheEntry {
    pub policy: TokenPolicy,
    /// This cache's access sequence at the entry's last use.
    pub last_access: u64,
}

#[derive(Debug, Default)]
struct Entries {
    by_anchor: HashMap<PolicyAnchor, PolicyCacheEntry>,
    /// Incremented on every access; orders entries by recency.
    access_seq: u64,
}

impl Entries {
    fn next_access(&mut self) -> u64 {
        self.access_seq += 1;
        self.access_seq
    }
}

#[derive(Debug)]
pub struct PolicyCache {
    entries: RwLock<Entries>,
    token_index: RwLock<HashMap<String, PolicyAnchor>>,
    config: PolicyCacheConfig,
}

impl PolicyCache {
    pub fn new(config: PolicyCacheConfig) -> Self {
        Self {
            entries: RwLock::new(Entries::default()),
            token_index: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub async fn get_policy(&self, anchor: &PolicyAnchor) -> Result<Option<TokenPolicy>, DsmError> {
        let mut entries = self.entries.write();
        let access = entries.next_access();
        Ok(entries.by_anchor.get_mut(anchor).map(|entry| {
            entry.last_access = access;
            entry.policy.clone()
        }))
    }

    pub fn store_policy(&self, anchor: PolicyAnchor, policy: TokenPolicy) {
        let mut entries = self.entries.write();
        let access = entries.next_access();

        // LRU eviction: remove the least-recently-used entry when at capacity.
        if entries.by_anchor.len() >= self.config.max_entries
            && !entries.by_anchor.contains_key(&anchor)
        {
            if let Some(k) = entries
                .by_anchor
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone())
            {
                entries.by_anchor.remove(&k);
            }
        }

        entries.by_anchor.insert(
            anchor,
            PolicyCacheEntry {
                policy,
                last_access: access,
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
        self.entries.read().by_anchor.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().by_anchor.is_empty()
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
        let config = PolicyCacheConfig { max_entries: 2 };
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
        assert!(cache.entries.read().by_anchor.contains_key(&a3));
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
        let config = PolicyCacheConfig { max_entries: 2 };
        let cache = PolicyCache::new(config);

        let policy = make_policy("author-same");
        let anchor = policy.anchor.clone();

        cache.store_policy(anchor.clone(), policy.clone());
        cache.store_policy(anchor.clone(), policy);
        assert_eq!(cache.len(), 1);
    }
}
