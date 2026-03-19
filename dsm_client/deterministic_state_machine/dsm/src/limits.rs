// SPDX-License-Identifier: MIT OR Apache-2.0
//! Configurable Limits for DSM Operations (clockless, deterministic)
//!
//! This module provides configurable limits for various DSM operations including
//! request sizes, batch sizes, concurrency limits, and resource constraints.
//! All limits are expressed in deterministic units (counts, sizes, ticks) with
//! no wall-clock dependencies.

use std::collections::HashMap;

/// Configuration for operation limits
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    /// Maximum size of a single request payload (bytes)
    pub max_request_size_bytes: usize,
    /// Maximum number of operations in a single batch
    pub max_batch_size: usize,
    /// Maximum concurrent operations per component
    pub max_concurrent_operations: usize,
    /// Maximum number of active connections
    pub max_connections: usize,
    /// Maximum memory usage per operation (bytes)
    pub max_memory_per_operation: usize,
    /// Maximum CPU time per operation (ticks)
    pub max_cpu_ticks_per_operation: u64,
    /// Maximum I/O time per operation (ticks)
    pub max_io_ticks_per_operation: u64,
    /// Maximum number of retries for failed operations
    pub max_retries: usize,
    /// Maximum queue depth for pending operations
    pub max_queue_depth: usize,
    /// Component-specific limits
    pub component_limits: HashMap<String, ComponentLimits>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_size_bytes: 1024 * 1024, // 1MB
            max_batch_size: 100,
            max_concurrent_operations: 10,
            max_connections: 100,
            max_memory_per_operation: 10 * 1024 * 1024, // 10MB
            max_cpu_ticks_per_operation: 1000,
            max_io_ticks_per_operation: 5000,
            max_retries: 3,
            max_queue_depth: 1000,
            component_limits: HashMap::new(),
        }
    }
}

/// Component-specific limits
#[derive(Debug, Clone)]
pub struct ComponentLimits {
    /// Maximum concurrent operations for this component
    pub max_concurrent: usize,
    /// Maximum queue depth for this component
    pub max_queue_depth: usize,
    /// Maximum ticks allowed for operations in this component
    pub max_ticks: u64,
    /// Maximum memory usage for this component
    pub max_memory_bytes: usize,
}

impl Default for ComponentLimits {
    fn default() -> Self {
        Self {
            max_concurrent: 5,
            max_queue_depth: 100,
            max_ticks: 1000,
            max_memory_bytes: 1024 * 1024, // 1MB
        }
    }
}

/// Limits enforcement engine
pub struct LimitsEnforcer {
    config: LimitsConfig,
    active_operations: std::sync::Arc<tokio::sync::RwLock<HashMap<String, usize>>>,
    queue_depths: std::sync::Arc<tokio::sync::RwLock<HashMap<String, usize>>>,
}

impl LimitsEnforcer {
    /// Create a new limits enforcer
    pub fn new(config: LimitsConfig) -> Self {
        Self {
            config,
            active_operations: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            queue_depths: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Check if a request size is within limits
    pub fn check_request_size(&self, size: usize) -> Result<(), LimitsError> {
        if size > self.config.max_request_size_bytes {
            return Err(LimitsError::RequestTooLarge {
                size,
                max_size: self.config.max_request_size_bytes,
            });
        }
        Ok(())
    }

    /// Check if batch size is within limits
    pub fn check_batch_size(&self, batch_size: usize) -> Result<(), LimitsError> {
        if batch_size > self.config.max_batch_size {
            return Err(LimitsError::BatchTooLarge {
                size: batch_size,
                max_size: self.config.max_batch_size,
            });
        }
        Ok(())
    }

    /// Check if an operation can be started for a component
    pub async fn check_operation_start(&self, component: &str) -> Result<(), LimitsError> {
        let active_ops = self.active_operations.read().await;
        let current_active = active_ops.get(component).copied().unwrap_or(0);

        let max_concurrent = self
            .get_component_limit(component, |c| c.max_concurrent)
            .unwrap_or(self.config.max_concurrent_operations);

        if current_active >= max_concurrent {
            return Err(LimitsError::TooManyConcurrentOperations {
                component: component.to_string(),
                current: current_active,
                max: max_concurrent,
            });
        }

        Ok(())
    }

    /// Record that an operation has started
    pub async fn record_operation_start(&self, component: &str) {
        let mut active_ops = self.active_operations.write().await;
        *active_ops.entry(component.to_string()).or_insert(0) += 1;
    }

    /// Record that an operation has completed
    pub async fn record_operation_complete(&self, component: &str) {
        let mut active_ops = self.active_operations.write().await;
        if let Some(count) = active_ops.get_mut(component) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    /// Check if an item can be queued
    pub async fn check_queue_depth(&self, component: &str) -> Result<(), LimitsError> {
        let queue_depths = self.queue_depths.read().await;
        let current_depth = queue_depths.get(component).copied().unwrap_or(0);

        let max_depth = self
            .get_component_limit(component, |c| c.max_queue_depth)
            .unwrap_or(self.config.max_queue_depth);

        if current_depth >= max_depth {
            return Err(LimitsError::QueueFull {
                component: component.to_string(),
                current: current_depth,
                max: max_depth,
            });
        }

        Ok(())
    }

    /// Record that an item has been queued
    pub async fn record_queue_add(&self, component: &str) {
        let mut queue_depths = self.queue_depths.write().await;
        *queue_depths.entry(component.to_string()).or_insert(0) += 1;
    }

    /// Record that an item has been dequeued
    pub async fn record_queue_remove(&self, component: &str) {
        let mut queue_depths = self.queue_depths.write().await;
        if let Some(depth) = queue_depths.get_mut(component) {
            if *depth > 0 {
                *depth -= 1;
            }
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> LimitsMetrics {
        let active_ops = self.active_operations.read().await.clone();
        let queue_depths = self.queue_depths.read().await.clone();

        LimitsMetrics {
            active_operations: active_ops,
            queue_depths,
            config: self.config.clone(),
        }
    }

    /// Get component-specific limit
    fn get_component_limit<F>(&self, component: &str, extractor: F) -> Option<usize>
    where
        F: Fn(&ComponentLimits) -> usize,
    {
        self.config.component_limits.get(component).map(extractor)
    }
}

/// Metrics for limits enforcement
#[derive(Debug, Clone)]
pub struct LimitsMetrics {
    pub active_operations: HashMap<String, usize>,
    pub queue_depths: HashMap<String, usize>,
    pub config: LimitsConfig,
}

/// Limits enforcement errors
#[derive(Debug, thiserror::Error)]
pub enum LimitsError {
    #[error("Request size {size} exceeds maximum {max_size} bytes")]
    RequestTooLarge { size: usize, max_size: usize },

    #[error("Batch size {size} exceeds maximum {max_size}")]
    BatchTooLarge { size: usize, max_size: usize },

    #[error("Too many concurrent operations for component {component}: {current}/{max}")]
    TooManyConcurrentOperations {
        component: String,
        current: usize,
        max: usize,
    },

    #[error("Queue full for component {component}: {current}/{max}")]
    QueueFull {
        component: String,
        current: usize,
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_size_limits() {
        let enforcer = LimitsEnforcer::new(LimitsConfig::default());

        // Should allow requests within limit
        assert!(enforcer.check_request_size(1024).is_ok());

        // Should reject requests over limit
        assert!(enforcer.check_request_size(2 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_batch_size_limits() {
        let enforcer = LimitsEnforcer::new(LimitsConfig::default());

        // Should allow batches within limit
        assert!(enforcer.check_batch_size(50).is_ok());

        // Should reject batches over limit
        assert!(enforcer.check_batch_size(200).is_err());
    }

    #[tokio::test]
    async fn test_concurrent_operation_limits() {
        let config = LimitsConfig {
            max_concurrent_operations: 2,
            ..LimitsConfig::default()
        };
        let enforcer = LimitsEnforcer::new(config);

        // Should allow starting operations up to limit
        assert!(enforcer.check_operation_start("test").await.is_ok());
        enforcer.record_operation_start("test").await;
        assert!(enforcer.check_operation_start("test").await.is_ok());
        enforcer.record_operation_start("test").await;

        // Should reject when at limit
        assert!(enforcer.check_operation_start("test").await.is_err());

        // Should allow after completing operations
        enforcer.record_operation_complete("test").await;
        assert!(enforcer.check_operation_start("test").await.is_ok());
    }

    #[tokio::test]
    async fn test_queue_depth_limits() {
        let config = LimitsConfig {
            max_queue_depth: 2,
            ..LimitsConfig::default()
        };
        let enforcer = LimitsEnforcer::new(config);

        // Should allow queuing up to limit
        assert!(enforcer.check_queue_depth("test").await.is_ok());
        enforcer.record_queue_add("test").await;
        assert!(enforcer.check_queue_depth("test").await.is_ok());
        enforcer.record_queue_add("test").await;

        // Should reject when queue is full
        assert!(enforcer.check_queue_depth("test").await.is_err());

        // Should allow after dequeuing
        enforcer.record_queue_remove("test").await;
        assert!(enforcer.check_queue_depth("test").await.is_ok());
    }
}
