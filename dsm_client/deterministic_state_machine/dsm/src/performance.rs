//! Performance optimization and resource management for DSM (STRICT: no wall/epoch time)
//!
//! This module provides CPU/I/O offloading, concurrency control, and cryptographic
//! progress-based accounting to keep the system responsive under load while remaining
//! fully deterministic (no `Instant`, no `Duration`, no sleeps).
//!
//! Design invariants:
//! - No wall clock, no epoch. All progress/tracking uses cryptographic progress anchors
//!   derived from SMT root transitions.
//! - No timeouts. Operations complete or return cooperatively. If you need cancellation
//!   or budgets, wire them via cryptographic progress budgets in your own call sites.
//! - No sleeps. Where previous code used `sleep` or `timeout`, this version eliminates
//!   those to preserve determinism.
//! - All logic is strictly cryptographic-progress-based and deterministic. No wall-clock,
//!   Duration, or time-based logic remains.
//!
//! Notes for integrators:
//! - `PerformanceConfig.requests_per_second` was time-based; that concept is removed.
//!   If you need gating, drive it via your own cryptographic progress pump and a token budget.
//! - Telemetry durations are reported as **commit heights**, not milliseconds.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Semaphore, RwLock};
use tokio::task;
#[cfg(feature = "web-stack")]
use tower::limit::ConcurrencyLimit;
#[cfg(feature = "web-stack")]
use tower::{Service, ServiceBuilder};

use tracing::{debug, warn};
use crate::types::unified_error::UnifiedDsmError;
use crate::telemetry;

// -------------------- Cryptographic Progress (process-local) --------------------

/// Get current commit height (cryptographic progress anchor)
#[inline]
pub fn mono_commit_height() -> u64 {
    crate::utils::deterministic_time::current_commit_height_blocking()
}

/// Get current progress hash for deterministic operations
#[inline]
pub fn mono_progress_hash(context: &[u8]) -> [u8; 32] {
    crate::utils::deterministic_time::derive_progress_hash(context)
}

// -------------------- Configuration --------------------

/// Performance configuration (clockless)
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Maximum concurrent CPU-bound operations
    pub max_cpu_tasks: usize,
    /// Maximum concurrent I/O operations
    pub max_io_tasks: usize,
    /// Enable performance monitoring (cryptographic-progress-based)
    pub enable_monitoring: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_cpu_tasks: 4,
            max_io_tasks: 16,
            enable_monitoring: true,
        }
    }
}

// -------------------- Manager --------------------

/// Performance manager for coordinating resource usage (clockless)
pub struct PerformanceManager {
    config: PerformanceConfig,
    cpu_semaphore: Arc<Semaphore>,
    io_semaphore: Arc<Semaphore>,
    active_operations: Arc<RwLock<HashMap<String, ()>>>,
}

#[inline]
fn operation_id(prefix: &str, operation_name: &str, start_tick: u64) -> String {
    // Deterministic, process-local ID.
    // NOTE: We intentionally avoid UUIDv4/randomness to preserve replay/debug determinism.
    format!("{prefix}_{operation_name}_{start_tick}")
}

// OperationMetrics removed: we only track operation presence for counts

/// CPU-bound operation result
pub type CpuResult<T> = Result<T, UnifiedDsmError>;

/// I/O-bound operation result
pub type IoResult<T> = Result<T, UnifiedDsmError>;

impl PerformanceManager {
    /// Create a new performance manager
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            cpu_semaphore: Arc::new(Semaphore::new(config.max_cpu_tasks)),
            io_semaphore: Arc::new(Semaphore::new(config.max_io_tasks)),
            active_operations: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Execute a CPU-bound operation with concurrency control (no timeouts)
    pub async fn execute_cpu_task<F, T>(&self, operation_name: &str, operation: F) -> CpuResult<T>
    where
        F: FnOnce() -> Result<T, UnifiedDsmError> + Send + 'static,
        T: Send + 'static,
    {
        // Acquire permit (owned, independent of borrow lifetimes)
        let _permit = self
            .cpu_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| UnifiedDsmError::Internal {
                context: "Failed to acquire CPU semaphore".to_string(),
                component: Some("performance_manager".to_string()),
                source: Some(Box::new(e)),
                recoverable: true,
            })?;

        let start_tick = mono_commit_height();
        let operation_id = operation_id("cpu", operation_name, start_tick);

        // Record operation start
        if self.config.enable_monitoring {
            let mut active_ops = self.active_operations.write().await;
            let _ = start_tick; // recorded for ticks_elapsed only
            active_ops.insert(operation_id.clone(), ());
        }

        // Spawn blocking task; no timeout wrapper (deterministic)
        let result = task::spawn_blocking(operation).await;

        let end_tick = mono_commit_height();
        let ticks_elapsed = end_tick.saturating_sub(start_tick);

        // Record metrics (ticks)
        if self.config.enable_monitoring {
            telemetry::telemetry_metrics::record_operation_ticks(
                operation_name,
                ticks_elapsed,
                result.is_ok(),
            );
            telemetry::telemetry_metrics::increment_counter(
                "cpu_operations_total",
                &[("operation", operation_name)],
            );

            // Cleanup
            let mut active_ops = self.active_operations.write().await;
            active_ops.remove(&operation_id);
        }

        match result {
            Ok(Ok(value)) => {
                debug!(
                    "CPU operation '{}' completed successfully (ticks_elapsed={})",
                    operation_name, ticks_elapsed
                );
                Ok(value)
            }
            Ok(Err(e)) => {
                warn!("CPU operation '{}' failed: {}", operation_name, e);
                Err(e)
            }
            Err(join_error) => {
                warn!(
                    "CPU operation '{}' panicked: {}",
                    operation_name, join_error
                );
                Err(UnifiedDsmError::Internal {
                    context: format!("CPU operation '{operation_name}' panicked"),
                    component: Some("performance_manager".to_string()),
                    source: Some(Box::new(join_error)),
                    recoverable: false,
                })
            }
        }
    }

    /// Execute an I/O-bound operation with concurrency control (no timeouts)
    pub async fn execute_io_task<F, Fut, T>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> IoResult<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, UnifiedDsmError>> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self
            .io_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| UnifiedDsmError::Internal {
                context: "Failed to acquire I/O semaphore".to_string(),
                component: Some("performance_manager".to_string()),
                source: Some(Box::new(e)),
                recoverable: true,
            })?;

        let start_tick = mono_commit_height();
        let operation_id = operation_id("io", operation_name, start_tick);

        // Record operation start
        if self.config.enable_monitoring {
            let mut active_ops = self.active_operations.write().await;
            let _ = start_tick; // recorded for ticks_elapsed only
            active_ops.insert(operation_id.clone(), ());
        }

        // Execute I/O future directly; no timeout wrapper (deterministic)
        let result = operation().await;

        let end_tick = mono_commit_height();
        let ticks_elapsed = end_tick.saturating_sub(start_tick);

        // Record metrics (ticks)
        if self.config.enable_monitoring {
            telemetry::telemetry_metrics::record_operation_ticks(
                operation_name,
                ticks_elapsed,
                result.is_ok(),
            );
            telemetry::telemetry_metrics::increment_counter(
                "io_operations_total",
                &[("operation", operation_name)],
            );

            let mut active_ops = self.active_operations.write().await;
            active_ops.remove(&operation_id);
        }

        match result {
            Ok(value) => {
                debug!(
                    "I/O operation '{}' completed successfully (ticks_elapsed={})",
                    operation_name, ticks_elapsed
                );
                Ok(value)
            }
            Err(e) => {
                warn!("I/O operation '{}' failed: {}", operation_name, e);
                Err(e)
            }
        }
    }

    /// Get current performance metrics (typed, clockless)
    pub async fn get_metrics(&self) -> MetricsSnapshot {
        let active_ops = self.active_operations.read().await;

        let cpu_available = self.cpu_semaphore.available_permits();
        let io_available = self.io_semaphore.available_permits();

        MetricsSnapshot {
            cpu_tasks: TaskMetrics {
                available_permits: cpu_available,
                max_permits: self.config.max_cpu_tasks,
                utilization_percent: ((self.config.max_cpu_tasks - cpu_available) as f64
                    / self.config.max_cpu_tasks as f64)
                    * 100.0,
            },
            io_tasks: TaskMetrics {
                available_permits: io_available,
                max_permits: self.config.max_io_tasks,
                utilization_percent: ((self.config.max_io_tasks - io_available) as f64
                    / self.config.max_io_tasks as f64)
                    * 100.0,
            },
            active_operations: active_ops.len(),
            config: self.config.clone(),
        }
    }
}

/// Typed metrics snapshot
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub cpu_tasks: TaskMetrics,
    pub io_tasks: TaskMetrics,
    pub active_operations: usize,
    pub config: PerformanceConfig,
}

/// Per-task metrics
#[derive(Debug, Clone)]
pub struct TaskMetrics {
    pub available_permits: usize,
    pub max_permits: usize,
    pub utilization_percent: f64,
}

impl PerformanceManager {
    /// Create a concurrency-limited service layer (clockless).
    ///
    /// Previous time-based `RateLimit` has been removed. If you need request gating,
    /// apply it at your router using your own tick-driven token bucket.
    #[cfg(feature = "web-stack")]
    pub fn create_rate_limited_service<S>(
        &self,
        service: S,
    ) -> ConcurrencyLimit<ConcurrencyLimit<S>>
    where
        S: Service<axum::http::Request<axum::body::Body>> + Clone,
        S::Future: Send + 'static,
    {
        ServiceBuilder::new()
            .concurrency_limit(self.config.max_io_tasks)
            .concurrency_limit(self.config.max_cpu_tasks)
            .service(service)
    }
}

/// CPU-intensive cryptographic operations (clockless)
pub mod crypto_ops {
    use super::*;
    use crate::crypto::{blake3, sphincs, kyber};

    /// Hash data using Blake3 (CPU-intensive)
    pub async fn hash_data(perf_manager: &PerformanceManager, data: &[u8]) -> CpuResult<Vec<u8>> {
        let data = data.to_vec();
        perf_manager
            .execute_cpu_task("hash_data", move || {
                Ok(blake3::domain_hash("DSM/hash-data", &data)
                    .as_bytes()
                    .to_vec())
            })
            .await
    }

    /// Generate SPHINCS+ keypair (very CPU-intensive)
    pub async fn generate_sphincs_keypair(
        perf_manager: &PerformanceManager,
    ) -> CpuResult<(Vec<u8>, Vec<u8>)> {
        perf_manager
            .execute_cpu_task("generate_sphincs_keypair", || {
                sphincs::generate_sphincs_keypair().map_err(|e| UnifiedDsmError::Crypto {
                    context: "Failed to generate SPHINCS+ keypair".to_string(),
                    component: Some("crypto_ops".to_string()),
                    source: Some(Box::new(e)),
                    recoverable: true,
                })
            })
            .await
    }

    /// Perform Kyber key encapsulation (CPU-intensive)
    pub async fn kyber_encapsulate(
        perf_manager: &PerformanceManager,
        public_key: &[u8],
    ) -> CpuResult<(Vec<u8>, Vec<u8>)> {
        let public_key = public_key.to_vec();
        perf_manager
            .execute_cpu_task("kyber_encapsulate", move || {
                kyber::kyber_encapsulate(&public_key).map_err(|e| UnifiedDsmError::Crypto {
                    context: "Failed to perform Kyber encapsulation".to_string(),
                    component: Some("crypto_ops".to_string()),
                    source: Some(Box::new(e)),
                    recoverable: true,
                })
            })
            .await
    }

    /// Generate Kyber keypair (CPU-intensive)
    pub async fn generate_kyber_keypair(
        perf_manager: &PerformanceManager,
    ) -> CpuResult<(Vec<u8>, Vec<u8>)> {
        perf_manager
            .execute_cpu_task("generate_kyber_keypair", || {
                let keypair =
                    kyber::generate_kyber_keypair().map_err(|e| UnifiedDsmError::Crypto {
                        context: "Failed to generate Kyber keypair".to_string(),
                        component: Some("crypto_ops".to_string()),
                        source: Some(Box::new(e)),
                        recoverable: true,
                    })?;
                Ok((keypair.public_key.clone(), keypair.secret_key.clone()))
            })
            .await
    }
}

/// I/O-intensive operations (clockless).
/// Gated behind `perf` feature to keep core I/O-free by default.
#[cfg(feature = "perf")]
pub mod io_ops {
    use super::*;
    use std::path::Path;

    /// Read file asynchronously with resource management
    pub async fn read_file(perf_manager: &PerformanceManager, path: &Path) -> IoResult<Vec<u8>> {
        let path_str = path.to_string_lossy().to_string();
        perf_manager
            .execute_io_task("read_file", move || async move {
                tokio::fs::read(&path_str)
                    .await
                    .map_err(|e| UnifiedDsmError::Storage {
                        context: format!("Failed to read file: {path_str}"),
                        component: Some("io_ops".to_string()),
                        source: Some(Box::new(e)),
                        recoverable: true,
                    })
            })
            .await
    }

    /// Write file asynchronously with resource management
    pub async fn write_file(
        perf_manager: &PerformanceManager,
        path: &Path,
        data: &[u8],
    ) -> IoResult<()> {
        let path_str = path.to_string_lossy().to_string();
        let data = data.to_vec();
        perf_manager
            .execute_io_task("write_file", move || async move {
                tokio::fs::write(&path_str, &data)
                    .await
                    .map_err(|e| UnifiedDsmError::Storage {
                        context: format!("Failed to write file: {path_str}"),
                        component: Some("io_ops".to_string()),
                        source: Some(Box::new(e)),
                        recoverable: true,
                    })
            })
            .await
    }
}

/// LRU cache for expensive operations (unchanged; clockless)
pub mod cache {
    use lru::LruCache;
    use std::hash::Hash;
    use std::num::NonZeroUsize;
    use std::sync::Mutex;

    /// Thread-safe LRU cache
    pub struct ThreadSafeLruCache<K, V> {
        cache: Mutex<LruCache<K, V>>,
    }

    impl<K, V> ThreadSafeLruCache<K, V>
    where
        K: Hash + Eq + Clone,
        V: Clone,
    {
        /// Create a new cache with the given capacity
        pub fn new(capacity: usize) -> Self {
            let capacity =
                NonZeroUsize::new(capacity.max(1)).expect("capacity is clamped to at least 1");
            Self {
                cache: Mutex::new(LruCache::new(capacity)),
            }
        }

        /// Get a value from the cache
        pub fn get(&self, key: &K) -> Option<V> {
            // If the mutex is poisoned, recover the inner cache to avoid panicking
            let mut cache = match self.cache.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.get(key).cloned()
        }

        /// Put a value in the cache
        pub fn put(&self, key: K, value: V) {
            let mut cache = match self.cache.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.put(key, value);
        }

        /// Get cache statistics
        pub fn stats(&self) -> (usize, usize) {
            let cache = match self.cache.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            (cache.len(), cache.cap().into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cpu_task_execution() {
        let perf_manager = PerformanceManager::new(PerformanceConfig::default());

        let result = perf_manager
            .execute_cpu_task("test_operation", || {
                // Do some deterministic CPU work; no sleeps.
                let mut acc = 0u64;
                for i in 0..10_000 {
                    acc = acc.wrapping_add(i);
                }
                Ok(acc as i32) // value isn't important
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_io_task_execution() {
        let perf_manager = PerformanceManager::new(PerformanceConfig::default());

        let result = perf_manager
            .execute_io_task("test_io", || async {
                // Yield cooperatively instead of sleeping
                tokio::task::yield_now().await;
                Ok("success".to_string())
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let perf_manager = PerformanceManager::new(PerformanceConfig::default());
        let metrics = perf_manager.get_metrics().await;
        assert!(metrics.cpu_tasks.max_permits > 0);
        assert!(metrics.io_tasks.max_permits > 0);
    }
}
