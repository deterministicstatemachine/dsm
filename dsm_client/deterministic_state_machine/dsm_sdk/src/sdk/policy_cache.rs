//! Token Policy Cache SDK
//!
//! This module implements client-side caching for token policies,
//! allowing token holders to efficiently access and validate policies
//! without constantly querying storage nodes.

use std::{collections::HashMap, sync::Arc};
use crate::util::deterministic_time as dt;

use dsm::{
    types::{
        error::DsmError,
        policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
    },
};
use parking_lot::RwLock;

use super::core_sdk::CoreSDK;

/// Configuration for policy cache
#[derive(Debug, Clone)]
pub struct PolicyCacheConfig {
    /// Default time-to-live for cached policies in seconds
    pub default_ttl: u64,
    /// Maximum number of policies to cache
    pub max_cache_size: usize,
    /// Whether to automatically refresh policies near expiration
    pub auto_refresh: bool,
    /// Threshold for auto-refresh (percentage of TTL remaining)
    pub refresh_threshold: f32,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: 86400, // 1 day
            max_cache_size: 100,
            auto_refresh: true,
            refresh_threshold: 0.2, // 20% of TTL remaining
        }
    }
}

/// Cache entry for a token policy
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The policy
    policy: TokenPolicy,
    /// When the entry was cached
    cached_at: u64,
    /// When the entry expires
    expires_at: u64,
    /// Last time the policy was accessed
    last_accessed: u64,
    /// Number of times the policy has been accessed
    access_count: usize,
}

/// Client response for policy retrieval
#[derive(Debug, Clone)]
pub struct PolicyResponse {
    /// Policy ID
    pub policy_id: String,
    /// Whether the policy was found
    pub found: bool,
    /// Policy file if found
    pub policy: Option<PolicyFile>,
    /// Whether the policy came from cache
    pub from_cache: bool,
    /// Deterministic tick of the operation
    pub tick: u64,
}

/// Token Policy Cache for efficiently accessing and validating policies locally
pub struct TokenPolicyCache {
    /// Core SDK for communication with storage nodes
    core_sdk: Arc<CoreSDK>,
    /// Cache configuration
    config: PolicyCacheConfig,
    /// In-memory cache of policies
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// Cache statistics
    stats: RwLock<CacheStats>,
    /// HTTP client for storage node communication (real network when local-mpc is off)
    http_client: Option<reqwest::Client>,
    /// Storage node URLs for policy publishing/fetching
    storage_node_urls: Vec<String>,
    /// Mapping from CPTA anchor (Base32 policy_id) → storage-level anchor (32 bytes).
    ///
    /// The CPTA anchor uses domain tag `DSM/cpta` while the storage node uses `DSM/policy`,
    /// so they differ even for the same canonical bytes. This map is populated at publish
    /// time and used at fetch time to translate the CPTA-based policy_id into the storage
    /// node's content-addressed key.
    storage_anchor_map: RwLock<HashMap<String, Vec<u8>>>,
}

/// Statistics for cache performance monitoring
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: usize,
    /// Number of cache misses
    pub misses: usize,
    /// Number of cache refreshes
    pub refreshes: usize,
    /// Number of cache evictions
    pub evictions: usize,
}

impl TokenPolicyCache {
    /// Create a new token policy cache
    pub fn new(
        core_sdk: Arc<CoreSDK>,
        config: Option<PolicyCacheConfig>,
        http_client: Option<reqwest::Client>,
        storage_node_urls: Vec<String>,
    ) -> Self {
        Self {
            core_sdk,
            config: config.unwrap_or_default(),
            cache: RwLock::new(HashMap::new()),
            stats: RwLock::new(CacheStats::default()),
            http_client,
            storage_node_urls,
            storage_anchor_map: RwLock::new(HashMap::new()),
        }
    }

    /// Get the current deterministic tick (clockless)
    fn now() -> u64 {
        dt::tick()
    }

    /// Get a policy by its ID, first checking the cache and then fetching from storage nodes if needed
    pub async fn get_policy(&self, policy_id: &str) -> Result<PolicyResponse, DsmError> {
        let now = Self::now();

        // Check if policy exists in cache and is not expired
        {
            let mut cache = self.cache.write();
            if let Some(entry) = cache.get_mut(policy_id) {
                if now < entry.expires_at {
                    // Update access stats
                    entry.last_accessed = now;
                    entry.access_count += 1;

                    // Update hit stats
                    {
                        let mut stats = self.stats.write();
                        stats.hits += 1;
                    }

                    // Check if we should refresh in the background (close to expiration)
                    if self.config.auto_refresh {
                        let ttl_remaining = entry.expires_at.saturating_sub(now);
                        let total_ttl = entry.expires_at.saturating_sub(entry.cached_at);
                        let ttl_percentage = ttl_remaining as f32 / total_ttl as f32;

                        if ttl_percentage <= self.config.refresh_threshold {
                            // Clone what we need for background refresh
                            let policy_id = policy_id.to_string();
                            let self_clone = Arc::new(self.clone());

                            // Spawn background refresh
                            tokio::spawn(async move {
                                if let Ok(fresh_policy) =
                                    self_clone.fetch_policy_from_network(&policy_id).await
                                {
                                    let _ =
                                        self_clone.update_cached_policy(&policy_id, fresh_policy);

                                    // Update refresh stats
                                    {
                                        let mut stats = self_clone.stats.write();
                                        stats.refreshes += 1;
                                    }
                                }
                            });
                        }
                    }

                    // Return cached policy
                    return Ok(PolicyResponse {
                        policy_id: policy_id.to_string(),
                        found: true,
                        policy: Some(entry.policy.file.clone()),
                        from_cache: true,
                        tick: now,
                    });
                }
            }
        }

        // Update miss stats
        {
            let mut stats = self.stats.write();
            stats.misses += 1;
        }

        // Fetch from network
        match self.fetch_policy_from_network(policy_id).await {
            Ok(policy) => {
                // Cache the policy
                self.cache_policy_internal(policy_id, policy.clone())?;

                Ok(PolicyResponse {
                    policy_id: policy_id.to_string(),
                    found: true,
                    policy: Some(policy.file),
                    from_cache: false,
                    tick: now,
                })
            }
            Err(_) => {
                // Policy not found or error
                Ok(PolicyResponse {
                    policy_id: policy_id.to_string(),
                    found: false,
                    policy: None,
                    from_cache: false,
                    tick: now,
                })
            }
        }
    }

    /// Cache a policy locally
    pub async fn cache_policy(&self, policy: PolicyFile, force: bool) -> Result<String, DsmError> {
        let policy_anchor = PolicyAnchor::from_policy(&policy).map_err(|e| {
            DsmError::internal(
                format!("Failed to generate policy anchor: {e}"),
                None::<std::io::Error>,
            )
        })?;
        // Use a short display-only ID for UI, but cache key remains full bytes string.
        let policy_id = crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes());

        // Check if already cached and not forcing
        if !force && self.is_cached(&policy_id) {
            return Ok(policy_id);
        }

        let now = Self::now();
        let policy = TokenPolicy {
            anchor: policy_anchor,
            file: policy,
            verified: false,
            last_verified: now,
        };

        // Add to cache
        self.cache_policy_internal(&policy_id, policy)?;

        Ok(policy_id)
    }

    /// Publish a policy to the network
    pub async fn publish_policy_to_network(
        &self,
        policy: PolicyFile,
    ) -> Result<PolicyAnchor, DsmError> {
        let policy_anchor = PolicyAnchor::from_policy(&policy).map_err(|e| {
            DsmError::internal(
                format!("Failed to generate policy anchor: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Publish to storage nodes via HTTP (feature-gated)
        #[cfg(not(feature = "local-mpc"))]
        {
            // POST canonical_bytes (semantic-only policy content) to storage nodes.
            //
            // The storage node hashes the body with BLAKE3("DSM/policy\0" || body)
            // to derive its content-addressed key. The CPTA anchor uses a different
            // domain tag ("DSM/cpta"), so we store the mapping CPTA→storage_anchor
            // locally to enable fetch by CPTA anchor later.
            if let Some(client) = &self.http_client {
                let canonical_bytes = policy.canonical_bytes().unwrap_or_default();
                if canonical_bytes.is_empty() {
                    log::warn!(
                        "Policy canonical_bytes() produced empty bytes, skipping network publish"
                    );
                } else {
                    // Pre-compute the storage-level anchor on the client side for verification.
                    // This MUST match what the storage node returns.
                    let expected_storage_anchor =
                        dsm::crypto::blake3::domain_hash("DSM/policy", &canonical_bytes);

                    let mut published_count = 0u32;
                    for url in &self.storage_node_urls {
                        let policy_url = format!("{}/api/v2/policy", url.trim_end_matches('/'));

                        match client
                            .post(&policy_url)
                            .header("content-type", "application/octet-stream")
                            .body(canonical_bytes.clone())
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => {
                                // Verify the returned 32-byte anchor matches our expectation
                                if let Ok(anchor_body) = resp.bytes().await {
                                    if anchor_body.len() == 32 {
                                        if anchor_body.as_ref()
                                            == expected_storage_anchor.as_bytes()
                                        {
                                            log::info!(
                                                "Policy published to {} — anchor verified",
                                                url
                                            );
                                        } else {
                                            log::warn!(
                                                "Storage node {} returned mismatched anchor (expected {:?}, got {:?})",
                                                url,
                                                &expected_storage_anchor.as_bytes()[..4],
                                                &anchor_body[..4]
                                            );
                                        }
                                    }
                                }
                                published_count += 1;
                            }
                            Ok(resp) => {
                                log::warn!(
                                    "Storage node {} returned {} for policy publish",
                                    url,
                                    resp.status()
                                );
                            }
                            Err(e) => {
                                log::warn!("Failed to publish policy to {}: {}", url, e);
                            }
                        }
                    }

                    // Store the CPTA→storage anchor mapping for fetch-time lookup
                    let cpta_key =
                        crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes());
                    {
                        let mut map = self.storage_anchor_map.write();
                        map.insert(cpta_key, expected_storage_anchor.as_bytes().to_vec());
                    }

                    if published_count == 0 && !self.storage_node_urls.is_empty() {
                        log::warn!(
                            "Policy {} could not be published to any storage node (non-fatal)",
                            crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes())
                        );
                    } else {
                        log::info!(
                            "Policy {} published to {}/{} storage nodes",
                            crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes()),
                            published_count,
                            self.storage_node_urls.len()
                        );
                    }
                }
            }
        }

        #[cfg(feature = "local-mpc")]
        {
            log::info!(
                "Publishing policy {} to network (local-mpc: simulated)",
                crate::util::text_id::encode_base32_crockford(policy_anchor.as_bytes())
            );
        }

        // Always cache locally in both modes
        self.cache_policy(policy, false).await?;

        Ok(policy_anchor)
    }

    /// List all cached policies
    pub async fn list_cached_policies(&self) -> Result<Vec<PolicyFile>, DsmError> {
        let cache = self.cache.read();
        let policies: Vec<PolicyFile> = cache
            .values()
            .map(|entry| entry.policy.file.clone())
            .collect();

        Ok(policies)
    }

    /// Get a policy by ID (returns the PolicyFile directly)
    pub async fn get_policy_file(&self, policy_id: &str) -> Result<Option<PolicyFile>, DsmError> {
        let response = self.get_policy(policy_id).await?;
        Ok(response.policy)
    }

    /// Internal method to cache a policy with deduplication
    fn cache_policy_internal(&self, policy_id: &str, policy: TokenPolicy) -> Result<(), DsmError> {
        let now = Self::now();
        let mut cache = self.cache.write();

        // Check if we need to evict entries due to cache size limit
        if cache.len() >= self.config.max_cache_size && !cache.contains_key(policy_id) {
            self.evict_entry(&mut cache)?;
        }

        // Cache the policy
        cache.insert(
            policy_id.to_string(),
            CacheEntry {
                policy,
                cached_at: now,
                expires_at: now + self.config.default_ttl,
                last_accessed: now,
                access_count: 1,
            },
        );

        Ok(())
    }

    /// Internal method to update an already cached policy
    fn update_cached_policy(&self, policy_id: &str, policy: TokenPolicy) -> Result<(), DsmError> {
        let now = Self::now();
        let mut cache = self.cache.write();

        if let Some(entry) = cache.get_mut(policy_id) {
            // Update the entry
            entry.policy = policy;
            entry.cached_at = now;
            entry.expires_at = now + self.config.default_ttl;
            // Don't reset access count or last_accessed
        }

        Ok(())
    }

    /// Evict an entry from the cache based on least recently used
    fn evict_entry(&self, cache: &mut HashMap<String, CacheEntry>) -> Result<(), DsmError> {
        if let Some((key, _)) = cache.iter().min_by_key(|(_, entry)| entry.last_accessed) {
            let key = key.clone();
            cache.remove(&key);

            // Update eviction stats
            {
                let mut stats = self.stats.write();
                stats.evictions += 1;
            }
        }

        Ok(())
    }

    /// Fetch a policy from the network by its Base32-encoded CPTA anchor ID.
    ///
    /// In real MPC mode, queries storage nodes via `POST /api/v2/policy/get`.
    /// The storage node keys by `BLAKE3("DSM/policy\0" || body)` while the CPTA anchor
    /// uses `BLAKE3("DSM/cpta\0" || canonical_bytes)` — different domain tags.
    /// Queries must use the translated storage anchor from `storage_anchor_map`.
    ///
    /// In local-mpc mode, returns a simulated policy.
    async fn fetch_policy_from_network(&self, policy_id: &str) -> Result<TokenPolicy, DsmError> {
        // Suppress unused-variable warning in local-mpc mode where the network
        // fetch block is compiled out and policy_id is not referenced.
        let _ = policy_id;

        #[cfg(not(feature = "local-mpc"))]
        {
            if let Some(client) = &self.http_client {
                // Decode Base32 Crockford policy_id to 32-byte CPTA anchor
                let cpta_anchor_bytes = crate::util::text_id::decode_base32_crockford(policy_id)
                    .ok_or_else(|| {
                        DsmError::internal(
                            format!("Invalid Base32 policy ID: {policy_id}"),
                            None::<std::io::Error>,
                        )
                    })?;

                if cpta_anchor_bytes.len() != 32 {
                    return Err(DsmError::internal(
                        format!(
                            "Policy anchor must be 32 bytes, got {}",
                            cpta_anchor_bytes.len()
                        ),
                        None::<std::io::Error>,
                    ));
                }

                // Look up the storage-level anchor from the CPTA→storage mapping.
                // This mapping was populated during publish_policy_to_network().
                let storage_anchor = {
                    let map = self.storage_anchor_map.read();
                    map.get(policy_id).cloned()
                };

                let query_anchor = storage_anchor.ok_or_else(|| {
                    DsmError::not_found(
                        "policy storage mapping",
                        Some(format!(
                            "No storage anchor mapping recorded for policy {policy_id}"
                        )),
                    )
                })?;

                for url in &self.storage_node_urls {
                    let policy_url = format!("{}/api/v2/policy/get", url.trim_end_matches('/'));

                    match client
                        .post(&policy_url)
                        .header("content-type", "application/octet-stream")
                        .body(query_anchor.clone())
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(body) = resp.bytes().await {
                                // The storage node returns canonical_bytes (what was POSTed at publish).
                                // Deserialize via from_canonical_bytes (CanonicalPolicy proto).
                                match PolicyFile::from_canonical_bytes(&body) {
                                    Ok(policy_file) => {
                                        let token_policy = TokenPolicy::new(policy_file)?;
                                        return Ok(token_policy);
                                    }
                                    Err(_) => {
                                        // Fallback: try full StoredPolicy deserialization
                                        // (in case an older node stored to_bytes())
                                        match PolicyFile::from_bytes(&body) {
                                            Ok(policy_file) => {
                                                let token_policy = TokenPolicy::new(policy_file)?;
                                                return Ok(token_policy);
                                            }
                                            Err(e) => {
                                                log::warn!(
                                                    "Failed to deserialize policy from {}: {}",
                                                    url,
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                            log::debug!("Policy not found on node {}", url);
                        }
                        Ok(resp) => {
                            log::warn!("Node {} returned {} for policy fetch", url, resp.status());
                        }
                        Err(e) => {
                            log::warn!("Failed to fetch policy from {}: {}", url, e);
                        }
                    }
                }

                return Err(DsmError::NotFound {
                    entity: "policy".to_string(),
                    details: Some(policy_id.to_string()),
                    context: "Policy not found on any storage node".to_string(),
                    source: None,
                });
            }
        }

        // Fallback: local-mpc mode or no HTTP client
        let policy_file = PolicyFile::new("Simulated Policy", "1.0", "System");
        let token_policy = TokenPolicy::new(policy_file)?;
        Ok(token_policy)
    }

    /// Clear the entire cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }

    /// Remove a specific policy from the cache
    pub fn remove_from_cache(&self, policy_id: &str) -> bool {
        let mut cache = self.cache.write();
        cache.remove(policy_id).is_some()
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Get the number of policies in the cache
    pub async fn cache_size(&self) -> usize {
        self.cache.read().len()
    }

    /// Check if a policy exists in the cache
    pub fn is_cached(&self, policy_id: &str) -> bool {
        let cache = self.cache.read();
        cache.contains_key(policy_id)
    }

    /// Pin a policy to cache (extends TTL)
    pub fn pin_policy(&self, policy_id: &str, ttl: Option<u64>) -> Result<bool, DsmError> {
        let now = Self::now();
        let mut cache = self.cache.write();

        if let Some(entry) = cache.get_mut(policy_id) {
            // Update the expiration time
            entry.expires_at = now + ttl.unwrap_or(self.config.default_ttl);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Mark a policy as required for a specific operation
    /// This ensures the policy is prioritized for caching and validation
    pub fn mark_policy_as_required(
        &self,
        policy_id: &str,
        operation_type: &str,
    ) -> Result<(), DsmError> {
        let now = Self::now();

        log::info!("Marking policy {policy_id} as required for operation: {operation_type}");

        {
            let mut cache = self.cache.write();

            if let Some(entry) = cache.get_mut(policy_id) {
                // Mark as high priority and extend TTL
                entry.expires_at = now + (self.config.default_ttl * 2); // Double the TTL for required policies
                log::debug!("Extended TTL for required policy: {policy_id}");
            } else {
                // Policy not in cache - we should fetch it immediately
                log::warn!("Required policy {policy_id} not found in cache, should be fetched");
                return Err(DsmError::state(format!(
                    "Required policy {policy_id} not available in cache",
                )));
            }
        }

        Ok(())
    }

    /// Check if a policy is marked as required
    pub fn is_policy_required(&self, policy_id: &str) -> bool {
        let cache = self.cache.read();
        if let Some(entry) = cache.get(policy_id) {
            let now = Self::now();
            // Check if this policy has extended TTL (indicating it's required)
            entry.expires_at > now + self.config.default_ttl
        } else {
            false
        }
    }

    /// Get cache statistics for monitoring and debugging
    pub async fn get_stats_extended(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Clear expired entries from the cache
    pub fn cleanup_expired(&self) -> Result<usize, DsmError> {
        let now = Self::now();
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();

        let initial_count = cache.len();
        cache.retain(|_policy_id, entry| entry.expires_at > now);
        let removed_count = initial_count - cache.len();

        stats.evictions += removed_count;

        log::debug!("Cleaned up {removed_count} expired cache entries");
        Ok(removed_count)
    }
}

// Clone implementation for the cache
impl Clone for TokenPolicyCache {
    fn clone(&self) -> Self {
        // Create a new instance with the same configuration but fresh cache/stats.
        // Preserve the storage anchor mapping so fetches still work.
        let cloned = Self::new(
            self.core_sdk.clone(),
            Some(self.config.clone()),
            self.http_client.clone(),
            self.storage_node_urls.clone(),
        );
        {
            let src = self.storage_anchor_map.read();
            *cloned.storage_anchor_map.write() = src.clone();
        }
        cloned
    }
}

#[cfg(test)]
mod tests {
    // Tests for TokenPolicyCache would go here
}
