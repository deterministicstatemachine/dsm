//! Device-Local Memory Manager for DSM
//!
//! This module provides efficient memory management for individual devices
//! in the DSM network. Each device maintains its own memory pools and
//! optimizations, with no shared memory across the network.

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use crate::types::error::DsmError;
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Device-specific memory configuration
#[derive(Debug, Clone)]
pub struct DeviceMemoryConfig {
    /// Maximum memory usage for this device
    pub max_memory_bytes: usize,
    /// Maximum number of cached signatures
    pub max_signature_cache: usize,
    /// Maximum number of cached keys
    pub max_key_cache: usize,
    /// Chunk size for large operations
    pub chunk_size: usize,
    /// Whether to enable aggressive cleanup
    pub aggressive_cleanup: bool,
}

impl Default for DeviceMemoryConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 50 * 1024 * 1024, // 50MB per device
            max_signature_cache: 100,
            max_key_cache: 50,
            chunk_size: 1024,
            aggressive_cleanup: true,
        }
    }
}

/// Device-local memory statistics
#[derive(Debug, Clone)]
pub struct DeviceMemoryStats {
    /// Current memory usage in bytes
    pub current_usage: usize,
    /// Peak memory usage in bytes
    pub peak_usage: usize,
    /// Number of cached signatures
    pub cached_signatures: usize,
    /// Number of cached keys
    pub cached_keys: usize,
    /// Memory allocation count
    pub allocations: u64,
    /// Memory reuse count
    pub reuses: u64,
    /// Memory cleanup count
    pub cleanups: u64,
}

/// Device-local memory manager
pub struct DeviceMemoryManager {
    /// Configuration
    config: DeviceMemoryConfig,
    /// Signature cache (device-local)
    signature_cache: Arc<RwLock<HashMap<String, CachedSignature>>>,
    /// Key cache (device-local)
    key_cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    /// Buffer pools by size (device-local)
    buffer_pools: Arc<RwLock<HashMap<usize, Vec<BytesMut>>>>,
    /// Statistics
    stats: Arc<RwLock<DeviceMemoryStats>>,
    /// Memory usage tracker
    memory_usage: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct CachedSignature {
    /// Signature data
    data: Bytes,
    /// Last access tick
    last_access: u64,
    /// Access count
    access_count: u64,
    /// Size in bytes
    size: usize,
}

impl CachedSignature {
    /// Check if this signature is stale (not accessed recently)
    pub fn is_stale(&self, max_age_ticks: u64) -> bool {
        let now = crate::utils::time::now();
        now - self.last_access > max_age_ticks
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct CachedKey {
    /// Key data
    data: Vec<u8>,
    /// Last access tick
    last_access: u64,
    /// Access count
    access_count: u64,
    /// Size in bytes
    size: usize,
}

impl CachedKey {
    /// Create a new cached key
    pub fn new(data: Vec<u8>) -> Self {
        let size = data.len();
        let now = crate::utils::time::now();

        Self {
            data,
            last_access: now,
            access_count: 1,
            size,
        }
    }

    /// Access the key data and update statistics
    pub fn access(&mut self) -> &Vec<u8> {
        self.last_access = crate::utils::time::now();
        self.access_count += 1;
        &self.data
    }

    /// Get the size of this cached key
    pub fn size(&self) -> usize {
        self.size
    }

    /// Check if this key is stale (not accessed recently)
    pub fn is_stale(&self, max_age_ticks: u64) -> bool {
        let now = crate::utils::time::now();
        now - self.last_access > max_age_ticks
    }
}

impl DeviceMemoryManager {
    /// Create a new device memory manager
    pub fn new(config: DeviceMemoryConfig) -> Self {
        Self {
            config,
            signature_cache: Arc::new(RwLock::new(HashMap::new())),
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            buffer_pools: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DeviceMemoryStats {
                current_usage: 0,
                peak_usage: 0,
                cached_signatures: 0,
                cached_keys: 0,
                allocations: 0,
                reuses: 0,
                cleanups: 0,
            })),
            memory_usage: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Cache a signature for this device
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn cache_signature(&self, id: String, signature: Vec<u8>) -> Result<(), DsmError> {
        let size = signature.len();

        // Check memory limits
        if self.memory_usage.load(Ordering::Relaxed) + size > self.config.max_memory_bytes {
            self.cleanup_if_needed().await;

            if self.memory_usage.load(Ordering::Relaxed) + size > self.config.max_memory_bytes {
                return Err(DsmError::Runtime {
                    context: "Device memory limit exceeded".to_string(),
                    source: None,
                });
            }
        }

        let mut cache = self.signature_cache.write().await;

        // Evict if cache is full
        if cache.len() >= self.config.max_signature_cache {
            self.evict_oldest_signature(&mut cache).await;
        }

        let cached_sig = CachedSignature {
            data: Bytes::from(signature),
            last_access: self.current_tick(),
            access_count: 1,
            size,
        };

        cache.insert(id, cached_sig);
        self.memory_usage.fetch_add(size, Ordering::Relaxed);

        let mut stats = self.stats.write().await;
        stats.cached_signatures = cache.len();
        stats.current_usage = self.memory_usage.load(Ordering::Relaxed);
        stats.peak_usage = stats.peak_usage.max(stats.current_usage);
        stats.allocations += 1;

        Ok(())
    }

    /// Retrieve a cached signature for this device
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn get_signature(&self, id: &str) -> Option<Bytes> {
        let mut cache = self.signature_cache.write().await;

        if let Some(cached_sig) = cache.get_mut(id) {
            cached_sig.last_access = self.current_tick();
            cached_sig.access_count += 1;

            let mut stats = self.stats.write().await;
            stats.reuses += 1;

            Some(cached_sig.data.clone())
        } else {
            None
        }
    }

    /// Cache a key for this device
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn cache_key(&self, id: String, key: Vec<u8>) -> Result<(), DsmError> {
        let size = key.len();

        // Check memory limits
        if self.memory_usage.load(Ordering::Relaxed) + size > self.config.max_memory_bytes {
            self.cleanup_if_needed().await;

            if self.memory_usage.load(Ordering::Relaxed) + size > self.config.max_memory_bytes {
                return Err(DsmError::Runtime {
                    context: "Device memory limit exceeded".to_string(),
                    source: None,
                });
            }
        }

        let mut cache = self.key_cache.write().await;

        // Evict if cache is full
        if cache.len() >= self.config.max_key_cache {
            self.evict_oldest_key(&mut cache).await;
        }

        let cached_key = CachedKey::new(key);

        cache.insert(id, cached_key);
        self.memory_usage.fetch_add(size, Ordering::Relaxed);

        let mut stats = self.stats.write().await;
        stats.cached_keys = cache.len();
        stats.current_usage = self.memory_usage.load(Ordering::Relaxed);
        stats.peak_usage = stats.peak_usage.max(stats.current_usage);
        stats.allocations += 1;

        Ok(())
    }

    /// Get a buffer from the device's buffer pool
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn get_buffer(&self, size: usize) -> BytesMut {
        let mut pools = self.buffer_pools.write().await;

        if let Some(pool) = pools.get_mut(&size) {
            if let Some(buffer) = pool.pop() {
                // Reuse existing buffer
                let mut stats = self.stats.write().await;
                stats.reuses += 1;
                return buffer;
            }
        }

        // Allocate new buffer
        let mut stats = self.stats.write().await;
        stats.allocations += 1;

        BytesMut::with_capacity(size)
    }

    /// Retrieve a cached key for this device
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn get_key(&self, id: &str) -> Option<Bytes> {
        let mut cache = self.key_cache.write().await;

        if let Some(cached_key) = cache.get_mut(id) {
            // Use the access method to update statistics
            let data = cached_key.access().clone();

            let mut stats = self.stats.write().await;
            stats.reuses += 1;

            Some(Bytes::from(data))
        } else {
            None
        }
    }

    /// Return a buffer to the device's pool
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn return_buffer(&self, mut buffer: BytesMut, size: usize) {
        buffer.clear();

        let mut pools = self.buffer_pools.write().await;
        let pool = pools.entry(size).or_insert_with(Vec::new);

        // Limit pool size to prevent memory exhaustion
        if pool.len() < 10 {
            pool.push(buffer);
        }
    }

    /// Clean up old entries if needed
    #[allow(clippy::unused_async)]
    async fn cleanup_if_needed(&self) {
        if !self.config.aggressive_cleanup {
            return;
        }

        let current_usage = self.memory_usage.load(Ordering::Relaxed);
        if current_usage > self.config.max_memory_bytes * 80 / 100 {
            self.perform_cleanup().await;
        }
    }

    /// Perform memory cleanup
    #[allow(clippy::unused_async)]
    async fn perform_cleanup(&self) {
        debug!("Performing device memory cleanup");

        // Clean up old signatures
        {
            let mut cache = self.signature_cache.write().await;
            let mut to_remove = Vec::new();

            for (id, cached_sig) in cache.iter() {
                // Remove signatures older than 3600 ticks or with low access count
                if cached_sig.is_stale(3600) || cached_sig.access_count < 2 {
                    to_remove.push(id.clone());
                }
            }

            for id in to_remove {
                if let Some(cached_sig) = cache.remove(&id) {
                    self.memory_usage
                        .fetch_sub(cached_sig.size, Ordering::Relaxed);
                }
            }
        }

        // Clean up old keys
        {
            let mut cache = self.key_cache.write().await;
            let mut to_remove = Vec::new();

            for (id, cached_key) in cache.iter() {
                // Remove keys older than 1800 ticks or with low access count
                if cached_key.is_stale(1800) || cached_key.access_count < 3 {
                    to_remove.push(id.clone());
                }
            }

            for id in to_remove {
                if let Some(cached_key) = cache.remove(&id) {
                    self.memory_usage
                        .fetch_sub(cached_key.size(), Ordering::Relaxed);
                }
            }
        }

        let mut stats = self.stats.write().await;
        stats.cleanups += 1;
        stats.current_usage = self.memory_usage.load(Ordering::Relaxed);
    }

    /// Evict oldest signature
    #[allow(clippy::unused_async)]
    async fn evict_oldest_signature(&self, cache: &mut HashMap<String, CachedSignature>) {
        let mut oldest_id = None;
        let mut oldest_time = u64::MAX;

        for (id, cached_sig) in cache.iter() {
            if cached_sig.last_access < oldest_time {
                oldest_time = cached_sig.last_access;
                oldest_id = Some(id.clone());
            }
        }

        if let Some(id) = oldest_id {
            if let Some(cached_sig) = cache.remove(&id) {
                self.memory_usage
                    .fetch_sub(cached_sig.size, Ordering::Relaxed);
            }
        }
    }

    /// Evict oldest key
    #[allow(clippy::unused_async)]
    async fn evict_oldest_key(&self, cache: &mut HashMap<String, CachedKey>) {
        let mut oldest_id = None;
        let mut oldest_time = u64::MAX;

        for (id, cached_key) in cache.iter() {
            if cached_key.last_access < oldest_time {
                oldest_time = cached_key.last_access;
                oldest_id = Some(id.clone());
            }
        }

        if let Some(id) = oldest_id {
            if let Some(cached_key) = cache.remove(&id) {
                self.memory_usage
                    .fetch_sub(cached_key.size(), Ordering::Relaxed);
            }
        }
    }

    /// Get current tick
    fn current_tick(&self) -> u64 {
        crate::utils::time::now()
    }

    /// Get device memory statistics
    #[allow(clippy::unused_async)]
    #[allow(clippy::unused_async)]
    pub async fn get_stats(&self) -> DeviceMemoryStats {
        self.stats.read().await.clone()
    }

    /// Get current memory usage
    pub fn get_memory_usage(&self) -> usize {
        self.memory_usage.load(Ordering::Relaxed)
    }
}

/// Global device memory manager instance
static DEVICE_MEMORY_MANAGER: once_cell::sync::Lazy<Arc<DeviceMemoryManager>> =
    once_cell::sync::Lazy::new(|| {
        Arc::new(DeviceMemoryManager::new(DeviceMemoryConfig::default()))
    });

/// Get the global device memory manager
pub fn get_device_memory_manager() -> Arc<DeviceMemoryManager> {
    DEVICE_MEMORY_MANAGER.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_device_memory_manager() -> Result<(), DsmError> {
        let manager = DeviceMemoryManager::new(DeviceMemoryConfig {
            max_memory_bytes: 1024 * 1024, // 1MB
            max_signature_cache: 5,
            max_key_cache: 3,
            chunk_size: 1024,
            aggressive_cleanup: true,
        });

        // Test signature caching
        let signature = vec![1u8; 1024];
        manager
            .cache_signature("test_sig_1".to_string(), signature.clone())
            .await?;

        // Test signature retrieval
        let retrieved = manager.get_signature("test_sig_1").await;
        assert!(retrieved.is_some());

        // Test buffer pool
        let buffer = manager.get_buffer(512).await;
        assert_eq!(buffer.capacity(), 512);

        // Test statistics
        let stats = manager.get_stats().await;
        assert_eq!(stats.cached_signatures, 1);
        assert_eq!(stats.allocations, 2); // 1 signature + 1 buffer

        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_memory_limit_enforcement() {
        let manager = DeviceMemoryManager::new(DeviceMemoryConfig {
            max_memory_bytes: 1024, // 1KB limit
            max_signature_cache: 10,
            max_key_cache: 5,
            chunk_size: 1024,
            aggressive_cleanup: true,
        });

        // Try to cache a signature larger than the limit
        let large_signature = vec![1u8; 2048]; // 2KB
        let result = manager
            .cache_signature("large_sig".to_string(), large_signature)
            .await;
        assert!(result.is_err());
    }
}
