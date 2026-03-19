//! Token Policy Storage
//!
//! Persistent storage and retrieval for token policies (CTPAs), with an
//! in-memory LRU cache that uses deterministic ticks (no wall clocks) for TTL.
//!
//! Notes:
//! - No wall clocks: all timing is based on `crate::util::deterministic_time`.
//! - No hex/base64 in filenames or logs: anchors are encoded as raw path bytes on Unix.
//! - On non-Unix platforms we fall back to a debug-ish string that avoids hex/base64.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::util::deterministic_time as dt;
use crate::types::{
    error::DsmError,
    policy_types::{PolicyAnchor, TokenPolicy},
};

/// Abstract persistence layer for policies (implemented in SDK)
#[async_trait]
pub trait PolicyPersistence: Send + Sync + std::fmt::Debug {
    /// Read policy bytes by anchor
    async fn read(&self, anchor: &PolicyAnchor) -> Result<Vec<u8>, DsmError>;
    /// Write policy bytes by anchor
    async fn write(&self, anchor: &PolicyAnchor, data: &[u8]) -> Result<(), DsmError>;
    /// Delete policy by anchor
    async fn delete(&self, anchor: &PolicyAnchor) -> Result<(), DsmError>;
    /// List all available policy anchors
    async fn list_anchors(&self) -> Result<Vec<PolicyAnchor>, DsmError>;
}

#[derive(Debug, Clone)]
struct CacheEntry {
    policy: TokenPolicy,
    /// Logical-tick when added
    added_tick: u64,
    /// Logical-tick when last accessed
    last_access_tick: u64,
}

/// Token Policy Store (persistence-backed with LRU cache)
#[derive(Debug, Clone)]
pub struct PolicyStore {
    cache: Arc<RwLock<HashMap<PolicyAnchor, CacheEntry>>>,
    access_order: Arc<RwLock<VecDeque<PolicyAnchor>>>,
    max_cache_size: usize,
    /// TTL expressed in logical ticks (not wall seconds)
    cache_ttl_ticks: u64,
    persistence: Arc<dyn PolicyPersistence>,
}

impl PolicyStore {
    /// Create a new policy store with specified persistence backend.
    /// Defaults: max 1024 entries, TTL = 86_400 ticks.
    pub fn new(persistence: Arc<dyn PolicyPersistence>) -> Self {
        Self::with_cache_settings(persistence, 1024, 86_400)
    }

    /// Create a new policy store with specified cache settings.
    /// `cache_ttl_ticks` uses deterministic ticks, not wall time.
    pub fn with_cache_settings(
        persistence: Arc<dyn PolicyPersistence>,
        max_cache_size: usize,
        cache_ttl_ticks: u64,
    ) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(RwLock::new(VecDeque::with_capacity(max_cache_size))),
            max_cache_size,
            cache_ttl_ticks,
            persistence,
        }
    }

    /// Retrieve a policy by its anchor (cache → persistence).
    #[allow(clippy::unused_async)]
    pub async fn get_policy(&self, anchor: &PolicyAnchor) -> Result<TokenPolicy, DsmError> {
        // Cache lookup/refresh
        {
            let mut cache = self.cache.write();
            let mut order = self.access_order.write();

            if let Some(entry) = cache.get_mut(anchor) {
                let now_tick = dt::peek().1;
                if now_tick.saturating_sub(entry.added_tick) > self.cache_ttl_ticks {
                    // expired: evict
                    cache.remove(anchor);
                    if let Some(pos) = order.iter().position(|a| a == anchor) {
                        order.remove(pos);
                    }
                } else {
                    // touch
                    entry.last_access_tick = dt::peek().1;
                    if let Some(pos) = order.iter().position(|a| a == anchor) {
                        order.remove(pos);
                    }
                    order.push_back(anchor.clone());
                    return Ok(entry.policy.clone());
                }
            }
        }

        // Persistence load
        let bytes = self.persistence.read(anchor).await?;
        let file = crate::types::policy_types::PolicyFile::from_bytes(&bytes)?;
        let policy = TokenPolicy::new(file)?;

        // Verify anchor matches
        if &policy.anchor != anchor {
            return Err(DsmError::Integrity {
                context: "Policy anchor mismatch".into(),
                source: None,
            });
        }

        // Update cache
        {
            let mut cache = self.cache.write();
            let mut order = self.access_order.write();

            let entry = CacheEntry {
                policy: policy.clone(),
                added_tick: dt::peek().1,
                last_access_tick: dt::peek().1,
            };

            if cache.len() >= self.max_cache_size {
                if let Some(oldest) = order.pop_front() {
                    cache.remove(&oldest);
                }
            }

            cache.insert(anchor.clone(), entry);
            order.push_back(anchor.clone());
        }

        Ok(policy)
    }

    /// Verify and retrieve a policy by its anchor.
    #[allow(clippy::unused_async)]
    pub async fn verify_and_get_policy(
        &self,
        anchor: &PolicyAnchor,
        policy_data: Option<&[u8]>,
    ) -> Result<TokenPolicy, DsmError> {
        if policy_data.is_some() {
            return Err(DsmError::invalid_operation(
                "Inline policy verification requires protobuf PolicyMessage; supply canonical prost bytes.",
            ));
        }
        self.get_policy(anchor).await
    }

    /// Store a policy file (persistence + cache).
    pub async fn store_policy(
        &self,
        file: &crate::types::policy_types::PolicyFile,
    ) -> Result<PolicyAnchor, DsmError> {
        let policy = TokenPolicy::new(file.clone())?;
        let anchor = policy.anchor.clone();
        // Use the file's bytes for storage
        let bytes = file.to_bytes()?;

        self.persistence.write(&anchor, &bytes).await?;

        self.add_to_cache(anchor.clone(), policy);
        Ok(anchor)
    }

    /// List stored policy anchors (best-effort).
    pub async fn list_policy_anchors(&self) -> Result<Vec<PolicyAnchor>, DsmError> {
        self.persistence.list_anchors().await
    }

    /// Delete a policy (cache + persistence).
    #[allow(clippy::unused_async)]
    pub async fn delete_policy(&self, anchor: &PolicyAnchor) -> Result<(), DsmError> {
        // Evict from cache
        {
            let mut cache = self.cache.write();
            let mut order = self.access_order.write();
            cache.remove(anchor);
            if let Some(pos) = order.iter().position(|a| a == anchor) {
                order.remove(pos);
            }
        }

        // Remove from persistence
        self.persistence.delete(anchor).await
    }

    /// Clear the in-memory cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        let mut order = self.access_order.write();
        cache.clear();
        order.clear();
    }

    /// Get a policy from cache if present and not expired (no disk touch).
    pub fn get_from_cache(&self, anchor: &PolicyAnchor) -> Option<TokenPolicy> {
        let mut cache = self.cache.write();
        let mut order = self.access_order.write();

        if let Some(entry) = cache.get_mut(anchor) {
            let now_tick = dt::peek().1;
            if now_tick.saturating_sub(entry.added_tick) > self.cache_ttl_ticks {
                cache.remove(anchor);
                if let Some(pos) = order.iter().position(|a| a == anchor) {
                    order.remove(pos);
                }
                return None;
            }

            entry.last_access_tick = dt::peek().1;
            if let Some(pos) = order.iter().position(|a| a == anchor) {
                order.remove(pos);
            }
            order.push_back(anchor.clone());
            return Some(entry.policy.clone());
        }

        None
    }

    /// Insert/refresh a policy in the cache (LRU semantics).
    #[allow(dead_code)]
    pub fn add_to_cache(&self, anchor: PolicyAnchor, policy: TokenPolicy) {
        let mut cache = self.cache.write();
        let mut order = self.access_order.write();

        if cache.len() >= self.max_cache_size && !cache.contains_key(&anchor) {
            if let Some(lru) = order.pop_front() {
                cache.remove(&lru);
            }
        }

        let now = dt::peek().1;
        let entry = CacheEntry {
            policy,
            added_tick: now,
            last_access_tick: now,
        };

        if let Some(pos) = order.iter().position(|a| a == &anchor) {
            order.remove(pos);
        }
        order.push_back(anchor.clone());
        cache.insert(anchor, entry);
    }

    /// Purge expired entries from the cache based on deterministic ticks.
    pub fn evict_expired(&self) {
        let mut cache = self.cache.write();
        let mut order = self.access_order.write();
        let now = dt::peek().1;

        let expired: Vec<PolicyAnchor> = cache
            .iter()
            .filter(|&(_a, e)| now.saturating_sub(e.added_tick) > self.cache_ttl_ticks)
            .map(|(a, _e)| a.clone())
            .collect();

        for a in expired {
            cache.remove(&a);
            if let Some(pos) = order.iter().position(|x| x == &a) {
                order.remove(pos);
            }
        }
    }
}
