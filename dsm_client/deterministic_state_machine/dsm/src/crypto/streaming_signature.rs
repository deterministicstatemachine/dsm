//! Streaming Signature Implementation for Large Cryptographic Data
//!
//! This module provides efficient handling of large signatures (7KB-35KB SPHINCS+)
//! through streaming operations to prevent memory exhaustion on mobile devices.

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::types::error::DsmError;
use crate::utils::time; // tick-based deterministic time
use tracing::debug;

#[inline]
fn now_tick() -> u64 {
    time::now()
}

/// Configuration for streaming signature operations
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Maximum chunk size in bytes
    pub chunk_size: usize,
    /// Maximum number of chunks per signature
    pub max_chunks: usize,
    /// Memory limit for signature processing
    pub memory_limit: usize,
    /// Whether to enable compression
    pub enable_compression: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024,               // 1KB chunks
            max_chunks: 64,                 // 64KB max signature size
            memory_limit: 10 * 1024 * 1024, // 10MB limit
            enable_compression: true,
        }
    }
}

/// Streaming signature for large cryptographic data
#[derive(Debug, Clone)]
pub struct StreamingSignature {
    /// Signature chunks
    chunks: Vec<Bytes>,
    /// Total signature size
    total_size: usize,
    /// Signature metadata
    #[allow(dead_code)]
    metadata: SignatureMetadata,
    /// Chunk hashes for integrity verification
    chunk_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct SignatureMetadata {
    /// Signature algorithm identifier
    pub algorithm: String,
    /// Creation tick
    pub created_at: u64,
    /// Signature version
    pub version: u32,
    /// Whether signature is compressed
    pub compressed: bool,
}

impl StreamingSignature {
    /// Create a new streaming signature from large signature data
    pub fn from_signature(signature: &[u8], algorithm: &str) -> Result<Self, DsmError> {
        let config = StreamingConfig::default();

        if signature.len() > config.chunk_size * config.max_chunks {
            return Err(DsmError::InvalidParameter(format!(
                "Signature too large: {} bytes",
                signature.len()
            )));
        }

        // Split signature into chunks
        let chunks: Vec<Bytes> = signature
            .chunks(config.chunk_size)
            .map(Bytes::copy_from_slice)
            .collect();

        // Calculate chunk hashes for integrity
        let chunk_hashes: Vec<[u8; 32]> = chunks
            .iter()
            .map(|chunk| crate::crypto::blake3::domain_hash("DSM/stream-chunk", chunk).into())
            .collect();

        let metadata = SignatureMetadata {
            algorithm: algorithm.to_string(),
            created_at: now_tick(),
            version: 1,
            compressed: false,
        };

        Ok(Self {
            chunks,
            total_size: signature.len(),
            metadata,
            chunk_hashes,
        })
    }

    /// Get a specific chunk by index
    pub fn get_chunk(&self, index: usize) -> Option<&Bytes> {
        self.chunks.get(index)
    }

    /// Get the total number of chunks
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Get the total size of the signature
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Verify chunk integrity
    pub fn verify_chunk(&self, index: usize, chunk: &[u8]) -> bool {
        if index >= self.chunk_hashes.len() {
            return false;
        }

        let expected_hash = self.chunk_hashes[index];
        let actual_hash = crate::crypto::blake3::domain_hash("DSM/stream-chunk", chunk);

        expected_hash == *actual_hash.as_bytes()
    }

    /// Reconstruct the full signature (use with caution for large signatures)
    pub fn reconstruct(&self) -> Result<Vec<u8>, DsmError> {
        let mut result = Vec::with_capacity(self.total_size);

        for chunk in &self.chunks {
            result.extend_from_slice(chunk);
        }

        if result.len() != self.total_size {
            return Err(DsmError::Integrity {
                context: "Signature reconstruction size mismatch".to_string(),
                source: None,
            });
        }

        Ok(result)
    }

    /// Stream the signature chunks with callback
    #[allow(clippy::unused_async)]
    pub async fn stream_chunks<F>(&self, mut callback: F) -> Result<(), DsmError>
    where
        F: FnMut(usize, &Bytes) -> Result<(), DsmError>,
    {
        for (index, chunk) in self.chunks.iter().enumerate() {
            callback(index, chunk)?;
        }
        Ok(())
    }
}

/// Memory pool for signature chunks
pub struct SignatureChunkPool {
    /// Available chunks by size
    chunks: Arc<RwLock<HashMap<usize, Vec<BytesMut>>>>,
    /// Configuration
    #[allow(dead_code)]
    config: StreamingConfig,
    /// Statistics
    stats: Arc<RwLock<PoolStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub allocations: u64,
    pub reuses: u64,
    pub total_memory: usize,
}

impl SignatureChunkPool {
    /// Create a new chunk pool
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            chunks: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(PoolStats::default())),
        }
    }

    /// Acquire a chunk buffer of the specified size
    #[allow(clippy::unused_async)]
    pub async fn acquire(&self, size: usize) -> BytesMut {
        let mut chunks = self.chunks.write().await;

        if let Some(pool) = chunks.get_mut(&size) {
            if let Some(chunk) = pool.pop() {
                // Reuse existing chunk
                let mut stats = self.stats.write().await;
                stats.reuses += 1;
                return chunk;
            }
        }

        // Allocate new chunk
        let mut stats = self.stats.write().await;
        stats.allocations += 1;
        stats.total_memory += size;

        BytesMut::with_capacity(size)
    }

    /// Release a chunk buffer back to the pool
    #[allow(clippy::unused_async)]
    pub async fn release(&self, mut chunk: BytesMut, size: usize) {
        chunk.clear();

        let mut chunks = self.chunks.write().await;
        let pool = chunks.entry(size).or_insert_with(Vec::new);

        // Limit pool size to prevent memory exhaustion
        if pool.len() < 10 {
            pool.push(chunk);
        }
    }

    /// Get pool statistics
    #[allow(clippy::unused_async)]
    pub async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }
}

/// Streaming signature processor for large operations
pub struct StreamingSignatureProcessor {
    /// Chunk pool
    pool: SignatureChunkPool,
    /// Configuration
    config: StreamingConfig,
}

impl StreamingSignatureProcessor {
    /// Create a new streaming signature processor
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            pool: SignatureChunkPool::new(config.clone()),
            config,
        }
    }

    /// Process a large signature in streaming fashion
    #[allow(clippy::unused_async)]
    pub async fn process_signature<F>(
        &self,
        signature: &[u8],
        algorithm: &str,
        mut processor: F,
    ) -> Result<(), DsmError>
    where
        F: FnMut(&Bytes, usize) -> Result<(), DsmError>,
    {
        debug!(
            "Processing streaming signature: algo={}, size={} bytes",
            algorithm,
            signature.len()
        );

        if signature.len() > self.config.chunk_size * self.config.max_chunks {
            return Err(DsmError::InvalidParameter(format!(
                "Signature too large: {} bytes",
                signature.len()
            )));
        }

        // Process chunks without allocating full StreamingSignature
        for (index, chunk_slice) in signature.chunks(self.config.chunk_size).enumerate() {
            // Create a Bytes object for the chunk (allocates, but short-lived)
            let bytes = Bytes::copy_from_slice(chunk_slice);
            processor(&bytes, index)?;
        }

        Ok(())
    }

    /// Verify a streaming signature
    #[allow(clippy::unused_async)]
    pub async fn verify_signature(&self, signature: &StreamingSignature) -> Result<bool, DsmError> {
        // Verify chunk integrity
        for (index, chunk) in signature.chunks.iter().enumerate() {
            if !signature.verify_chunk(index, chunk) {
                return Ok(false);
            }
        }

        // Additional verification logic can be added here
        Ok(true)
    }

    /// Get pool statistics from the processor
    #[allow(clippy::unused_async)]
    pub async fn get_pool_stats(&self) -> PoolStats {
        self.pool.stats().await
    }

    /// Get the configuration used by this processor
    pub fn get_config(&self) -> &StreamingConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_streaming_signature_creation() -> Result<(), DsmError> {
        let test_signature = vec![0u8; 2048]; // 2KB test signature
        let streaming_sig = StreamingSignature::from_signature(&test_signature, "SPHINCS+")?;

        assert_eq!(streaming_sig.total_size(), 2048);
        assert_eq!(streaming_sig.chunk_count(), 2);
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_signature_reconstruction() -> Result<(), DsmError> {
        let test_signature = vec![1u8; 1024];
        let streaming_sig = StreamingSignature::from_signature(&test_signature, "SPHINCS+")?;

        let reconstructed = streaming_sig.reconstruct()?;
        assert_eq!(reconstructed, test_signature);
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::unused_async)]
    async fn test_chunk_pool() -> Result<(), DsmError> {
        let config = StreamingConfig::default();
        let pool = SignatureChunkPool::new(config);

        let chunk1 = pool.acquire(1024).await;
        let chunk2 = pool.acquire(1024).await;

        pool.release(chunk1, 1024).await;
        pool.release(chunk2, 1024).await;

        let stats = pool.stats().await;
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.reuses, 0);
        Ok(())
    }
}
