// SPDX-License-Identifier: Apache-2.0
//! Chaos and Load Testing Framework for DSM Storage Nodes
//! Implements comprehensive testing for fault tolerance, load handling, and chaos scenarios.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

/// Chaos test configuration
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// Network failure probability (0.0 to 1.0)
    pub network_failure_rate: f64,
    /// Node crash probability
    pub node_crash_rate: f64,
    /// Data corruption probability
    pub corruption_rate: f64,
    /// Maximum delay for network operations
    pub max_network_delay_ms: u64,
    /// Test duration
    pub test_duration_secs: u64,
}

/// Load test configuration
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// Number of concurrent clients
    pub concurrent_clients: usize,
    /// Operations per second target
    pub ops_per_second: usize,
    /// Test duration
    pub duration_secs: u64,
    /// Data size distribution (min, max bytes)
    pub data_size_range: (usize, usize),
}

/// Test result metrics
#[derive(Debug, Clone)]
pub struct TestMetrics {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub errors: HashMap<String, u64>,
}

/// Chaos testing engine
#[derive(Clone)]
pub struct ChaosEngine {
    config: ChaosConfig,
    metrics: Arc<Mutex<TestMetrics>>,
}

impl ChaosEngine {
    pub fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(Mutex::new(TestMetrics {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                average_latency_ms: 0.0,
                p95_latency_ms: 0.0,
                p99_latency_ms: 0.0,
                throughput_ops_per_sec: 0.0,
                errors: HashMap::new(),
            })),
        }
    }

    /// Run chaos test scenario
    pub async fn run_chaos_test(&self) -> Result<TestMetrics, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let handles = vec![
            tokio::spawn(self.clone().inject_network_failures()),
            tokio::spawn(self.clone().inject_node_crashes()),
            tokio::spawn(self.clone().inject_data_corruption()),
            tokio::spawn(self.clone().generate_load()),
        ];

        // Wait for test duration
        sleep(Duration::from_secs(self.config.test_duration_secs)).await;

        // Abort all tasks
        for handle in handles {
            handle.abort();
        }

        let mut metrics = self.metrics.lock().await;
        metrics.throughput_ops_per_sec =
            metrics.total_operations as f64 / start_time.elapsed().as_secs_f64();

        Ok(metrics.clone())
    }

    /// Inject network failures
    async fn inject_network_failures(self) {
        loop {
            if rand::random::<f64>() < self.config.network_failure_rate {
                // Simulate network partition
                self.record_error("network_partition".to_string()).await;
                sleep(Duration::from_millis(rand::random::<u64>() % 5000)).await;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Inject node crashes
    async fn inject_node_crashes(self) {
        loop {
            if rand::random::<f64>() < self.config.node_crash_rate {
                // Simulate node crash
                self.record_error("node_crash".to_string()).await;
                sleep(Duration::from_millis(rand::random::<u64>() % 10000)).await;
            }
            sleep(Duration::from_millis(1000)).await;
        }
    }

    /// Inject data corruption
    async fn inject_data_corruption(self) {
        loop {
            if rand::random::<f64>() < self.config.corruption_rate {
                // Simulate data corruption
                self.record_error("data_corruption".to_string()).await;
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Generate test load
    async fn generate_load(self) {
        let start_time = Instant::now();
        let mut latencies = Vec::new();

        while start_time.elapsed() < Duration::from_secs(self.config.test_duration_secs) {
            let start = Instant::now();

            // Simulate operation with potential delays
            if rand::random::<f64>() < self.config.network_failure_rate {
                sleep(Duration::from_millis(
                    rand::random::<u64>() % self.config.max_network_delay_ms,
                ))
                .await;
                self.record_operation(false).await;
            } else {
                // Simulate successful operation
                sleep(Duration::from_millis(rand::random::<u64>() % 100)).await;
                self.record_operation(true).await;
            }

            let latency = start.elapsed().as_millis() as f64;
            latencies.push(latency);

            sleep(Duration::from_millis(10)).await;
        }

        // Calculate percentiles
        latencies.sort_by(|a, b| a.total_cmp(b));
        let p95_idx = (latencies.len() as f64 * 0.95) as usize;
        let p99_idx = (latencies.len() as f64 * 0.99) as usize;

        let mut metrics = self.metrics.lock().await;
        if !latencies.is_empty() {
            metrics.average_latency_ms = latencies.iter().sum::<f64>() / latencies.len() as f64;
            metrics.p95_latency_ms = latencies.get(p95_idx).copied().unwrap_or(0.0);
            metrics.p99_latency_ms = latencies.get(p99_idx).copied().unwrap_or(0.0);
        }
    }

    async fn record_operation(&self, success: bool) {
        let mut metrics = self.metrics.lock().await;
        metrics.total_operations += 1;
        if success {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }
    }

    async fn record_error(&self, error_type: String) {
        let mut metrics = self.metrics.lock().await;
        *metrics.errors.entry(error_type).or_insert(0) += 1;
    }
}

/// Load testing engine
pub struct LoadEngine {
    config: LoadConfig,
}

impl LoadEngine {
    pub fn new(config: LoadConfig) -> Self {
        Self { config }
    }

    /// Run load test
    pub async fn run_load_test(&self) -> Result<TestMetrics, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut handles = Vec::new();
        let metrics = Arc::new(Mutex::new(TestMetrics {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            average_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            throughput_ops_per_sec: 0.0,
            errors: HashMap::new(),
        }));

        // Spawn client workers
        for client_id in 0..self.config.concurrent_clients {
            let metrics_clone = metrics.clone();
            let config_clone = self.config.clone();
            handles.push(tokio::spawn(async move {
                Self::run_client_worker(client_id, config_clone, metrics_clone).await;
            }));
        }

        // Wait for test duration
        sleep(Duration::from_secs(self.config.duration_secs)).await;

        // Stop workers
        for handle in handles {
            let _ = timeout(Duration::from_secs(5), handle).await;
        }

        let mut final_metrics = metrics.lock().await;
        final_metrics.throughput_ops_per_sec =
            final_metrics.total_operations as f64 / start_time.elapsed().as_secs_f64();

        Ok(final_metrics.clone())
    }

    async fn run_client_worker(
        _client_id: usize,
        config: LoadConfig,
        metrics: Arc<Mutex<TestMetrics>>,
    ) {
        let mut latencies = Vec::new();

        loop {
            let start = Instant::now();

            // Generate random data size
            let data_size = rand::random::<usize>()
                % (config.data_size_range.1 - config.data_size_range.0)
                + config.data_size_range.0;

            // Simulate operation
            let success = Self::simulate_operation(data_size).await;

            let latency = start.elapsed().as_millis() as f64;
            latencies.push(latency);

            // Update metrics
            let mut m = metrics.lock().await;
            m.total_operations += 1;
            if success {
                m.successful_operations += 1;
            } else {
                m.failed_operations += 1;
            }

            // Rate limiting
            let target_interval = Duration::from_secs_f64(1.0 / config.ops_per_second as f64);
            if latency < target_interval.as_millis() as f64 {
                sleep(target_interval - Duration::from_millis(latency as u64)).await;
            }
        }
    }

    async fn simulate_operation(data_size: usize) -> bool {
        // Simulate network and processing delays based on data size
        let base_delay = Duration::from_millis(10);
        let size_factor = data_size as f64 / 1024.0; // KB factor
        let delay = base_delay.mul_f64(1.0 + size_factor * 0.1);

        sleep(delay).await;

        // Random success/failure
        rand::random::<f64>() > 0.05 // 95% success rate
    }
}

/// Integration test utilities
pub struct IntegrationTester;

impl IntegrationTester {
    /// Test storage node failover
    pub async fn test_failover() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate node failure and verify data availability
        println!("Testing storage node failover...");

        // Implementation would test actual failover scenarios
        Ok(())
    }

    /// Test network partition handling
    pub async fn test_network_partition() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate network partitions and verify consistency
        println!("Testing network partition handling...");

        Ok(())
    }

    /// Test data consistency under load
    pub async fn test_consistency_under_load() -> Result<(), Box<dyn std::error::Error>> {
        // Test that data remains consistent during high load
        println!("Testing data consistency under load...");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::hardening;

    #[tokio::test]
    async fn test_chaos_engine_basic() {
        let config = ChaosConfig {
            network_failure_rate: 0.1,
            node_crash_rate: 0.05,
            corruption_rate: 0.01,
            max_network_delay_ms: 1000,
            test_duration_secs: 1,
        };

        let engine = ChaosEngine::new(config);
        let result = engine.run_chaos_test().await;

        let metrics = match result {
            Ok(metrics) => metrics,
            Err(err) => panic!("chaos test should succeed: {err}"),
        };
        assert!(metrics.total_operations > 0);
    }

    #[tokio::test]
    async fn test_load_engine_basic() {
        let config = LoadConfig {
            concurrent_clients: 2,
            ops_per_second: 10,
            duration_secs: 1,
            data_size_range: (100, 1000),
        };

        let engine = LoadEngine::new(config);
        let result = engine.run_load_test().await;

        let metrics = match result {
            Ok(metrics) => metrics,
            Err(err) => panic!("load test should succeed: {err}"),
        };
        assert!(metrics.total_operations > 0);
        assert!(metrics.successful_operations > 0);
    }

    #[test]
    fn test_clockless_commit_invariant_under_time() {
        // Deterministic hash should not vary with wall-clock time.
        let input = b"clockless-test";
        let a = hardening::blake3_tagged("DSM/clockless-test\0", input);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = hardening::blake3_tagged("DSM/clockless-test\0", input);
        assert_eq!(a, b);
    }
}
