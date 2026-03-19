//! DSM Storage Node Communication Health Monitor
//!
//! This module provides comprehensive health monitoring and recovery mechanisms
//! for storage node communication, ensuring robust client-storage node connectivity.

use reqwest::Client;
use crate::util::deterministic_time;
use prost::Message; // for protobuf decode in discovery
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{debug, error, info, warn};
use dsm::types::error::DsmError;

/// Storage node health status
#[derive(Debug, Clone)]
pub struct StorageNodeHealth {
    pub node_id: String,
    pub endpoint: String,
    pub is_healthy: bool,
    pub last_check: u64,
    pub response_time_ticks: u64,
    pub consecutive_failures: u32,
    pub error_count: u32,
    pub last_error: Option<String>,
    pub health_score: f64,
}

/// Health monitor configuration
#[derive(Debug, Clone)]
pub struct HealthMonitorConfig {
    pub check_interval_ticks: u64,
    pub request_timeout_ticks: u64,
    pub max_consecutive_failures: u32,
    pub health_score_threshold: f64,
    pub recovery_check_interval_ticks: u64,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval_ticks: 2500, // ~30 seconds worth of ticks
            request_timeout_ticks: 417, // ~5 seconds worth of ticks
            max_consecutive_failures: 3,
            health_score_threshold: 0.7,
            recovery_check_interval_ticks: 5000, // ~60 seconds worth of ticks
        }
    }
}

/// Storage node health monitor
pub struct StorageNodeHealthMonitor {
    config: HealthMonitorConfig,
    client: Client,
    node_health: Arc<RwLock<HashMap<String, StorageNodeHealth>>>,
    monitoring_active: Arc<std::sync::atomic::AtomicBool>,
}

impl StorageNodeHealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthMonitorConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            node_health: Arc::new(RwLock::new(HashMap::new())),
            monitoring_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start monitoring storage nodes
    pub async fn start_monitoring(&self, storage_endpoints: Vec<String>) -> Result<(), String> {
        info!(
            "Starting storage node health monitoring for {} nodes",
            storage_endpoints.len()
        );

        // Initialize health status for all nodes
        {
            let mut health_map = self.node_health.write().await;
            for endpoint in &storage_endpoints {
                let node_id = Self::generate_node_id(endpoint);
                health_map.insert(
                    node_id.clone(),
                    StorageNodeHealth {
                        node_id: node_id.clone(),
                        endpoint: endpoint.clone(),
                        is_healthy: false,
                        last_check: 0,
                        response_time_ticks: 0,
                        consecutive_failures: 0,
                        error_count: 0,
                        last_error: None,
                        health_score: 0.0,
                    },
                );
            }
        }

        // Start monitoring task
        self.monitoring_active
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let monitor = self.clone_for_task();
        tokio::spawn(async move {
            monitor.monitoring_loop().await;
        });

        Ok(())
    }

    /// Stop monitoring
    pub fn stop_monitoring(&self) {
        info!("Stopping storage node health monitoring");
        self.monitoring_active
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get current health status for all nodes
    pub async fn get_health_status(&self) -> HashMap<String, StorageNodeHealth> {
        self.node_health.read().await.clone()
    }

    /// Get healthy storage nodes
    pub async fn get_healthy_nodes(&self) -> Vec<StorageNodeHealth> {
        let health_map = self.node_health.read().await;
        health_map
            .values()
            .filter(|health| {
                health.is_healthy && health.health_score >= self.config.health_score_threshold
            })
            .cloned()
            .collect()
    }

    /// Get best storage node based on health score and response time
    pub async fn get_best_node(&self) -> Option<StorageNodeHealth> {
        let healthy_nodes = self.get_healthy_nodes().await;

        healthy_nodes.into_iter().max_by(|a, b| {
            // Primary: health score, Secondary: inverse of response time
            let score_a = a.health_score - (a.response_time_ticks as f64 / 10000.0);
            let score_b = b.health_score - (b.response_time_ticks as f64 / 10000.0);
            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Check health of a specific node
    pub async fn check_node_health(&self, endpoint: &str) -> Result<StorageNodeHealth, DsmError> {
        let node_id = Self::generate_node_id(endpoint);

        let health_url = format!("{endpoint}/health");

        // Clockless: we do not apply wall-clock or tokio timeouts here.
        // If the transport hangs, cancellation must be handled by the caller's task budget.
        let (is_healthy, error_msg) = match self.client.get(&health_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    (true, None)
                } else {
                    (
                        false,
                        Some({
                            let status = response.status();
                            format!("HTTP {status}")
                        }),
                    )
                }
            }
            Err(e) => (false, Some(format!("Request error: {e}"))),
        };

        // Deterministic bookkeeping only (ticks), not measured latency.
        let response_time_ticks = if is_healthy {
            4
        } else {
            self.config.request_timeout_ticks
        };
        // Clockless: use deterministic logical tick instead of wall-clock
        let tick = deterministic_time::tick();

        // Get current health status to update
        let mut current_health = {
            let health_map = self.node_health.read().await;
            health_map
                .get(&node_id)
                .cloned()
                .unwrap_or_else(|| StorageNodeHealth {
                    node_id: node_id.clone(),
                    endpoint: endpoint.to_string(),
                    is_healthy: false,
                    last_check: 0,
                    response_time_ticks: 0,
                    consecutive_failures: 0,
                    error_count: 0,
                    last_error: None,
                    health_score: 0.0,
                })
        };

        // Update health status
        current_health.last_check = tick;
        current_health.response_time_ticks = response_time_ticks;

        if is_healthy {
            current_health.consecutive_failures = 0;
            current_health.is_healthy = true;
            current_health.last_error = None;
            // Improve health score
            current_health.health_score = (current_health.health_score + 0.1).min(1.0);
        } else {
            current_health.consecutive_failures += 1;
            current_health.error_count += 1;
            current_health.last_error = error_msg;

            // Mark as unhealthy if too many consecutive failures
            if current_health.consecutive_failures >= self.config.max_consecutive_failures {
                current_health.is_healthy = false;
            }

            // Decrease health score
            current_health.health_score = (current_health.health_score - 0.2).max(0.0);
        }

        // Store updated health status
        {
            let mut health_map = self.node_health.write().await;
            health_map.insert(node_id, current_health.clone());
        }

        debug!(
            "Health check for {}: healthy={}, response_time={}ms, score={:.2}",
            endpoint, current_health.is_healthy, response_time_ticks, current_health.health_score
        );

        Ok(current_health)
    }

    /// Main monitoring loop
    async fn monitoring_loop(&self) {
        while self
            .monitoring_active
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let endpoints: Vec<String> = {
                let health_map = self.node_health.read().await;
                health_map.values().map(|h| h.endpoint.clone()).collect()
            };

            // Check health of all nodes concurrently
            let mut health_checks = Vec::new();
            for endpoint in endpoints {
                let monitor = self.clone_for_task();
                health_checks.push(tokio::spawn(async move {
                    monitor.check_node_health(&endpoint).await
                }));
            }

            // Wait for all health checks to complete
            for check in health_checks {
                if let Err(e) = check.await {
                    warn!("Health check task failed: {e}");
                }
            }

            // Log summary
            let healthy_count = self.get_healthy_nodes().await.len();
            let total_count = self.node_health.read().await.len();

            if healthy_count < total_count {
                warn!("Storage node health: {healthy_count}/{total_count} nodes healthy");
            } else {
                debug!("Storage node health: {healthy_count}/{total_count} nodes healthy");
            }

            // Deterministic: no wall-clock delays, continue immediately
        }

        info!("Storage node health monitoring stopped");
    }

    /// Generate a consistent node ID from endpoint
    fn generate_node_id(endpoint: &str) -> String {
        // Derive a deterministic decimal suffix from a BLAKE3 hash of the endpoint.
        // Avoid hex/base64 encodings internally per policy; this ID is display/log only.
        let h = dsm::crypto::blake3::domain_hash("DSM/node-endpoint", endpoint.as_bytes());
        let bytes = h.as_bytes();
        let mut four = [0u8; 4];
        four.copy_from_slice(&bytes[..4]);
        let n = u32::from_le_bytes(four);
        format!("node_{n}")
    }

    /// Clone for async task
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            node_health: self.node_health.clone(),
            monitoring_active: self.monitoring_active.clone(),
        }
    }
}

/// Storage node discovery and auto-configuration
pub struct StorageNodeDiscovery {
    client: Client,
    known_discovery_endpoints: Vec<String>,
}

impl StorageNodeDiscovery {
    /// Create new discovery service
    pub fn new(discovery_endpoints: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            known_discovery_endpoints: discovery_endpoints,
        }
    }

    /// Discover available storage nodes
    pub async fn discover_nodes(&self) -> Result<Vec<String>, String> {
        info!("Discovering storage nodes...");

        let mut discovered_nodes = Vec::new();

        // Try each discovery endpoint
        for endpoint in &self.known_discovery_endpoints {
            match self.discover_from_endpoint(endpoint).await {
                Ok(mut nodes) => {
                    discovered_nodes.append(&mut nodes);
                }
                Err(e) => {
                    warn!("Failed to discover nodes from {endpoint}: {e}");
                }
            }
        }

        // Remove duplicates
        discovered_nodes.sort();
        discovered_nodes.dedup();

        info!("Discovered {} storage nodes", discovered_nodes.len());
        Ok(discovered_nodes)
    }

    /// Discover nodes from a specific endpoint
    async fn discover_from_endpoint(&self, endpoint: &str) -> Result<Vec<String>, String> {
        let discovery_url = format!("{endpoint}/api/v2/nodes/discover");

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        // If the transport hangs, cancellation must be handled by the caller's task budget.
        let response = self
            .client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| format!("Discovery request failed: {e}"))?;

        if !response.status().is_success() {
            return Err({
                let status = response.status();
                format!("Discovery failed with status: {status}")
            });
        }

        // Protobuf-only: decode DiscoverLocalResponse from bytes
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read discovery response bytes: {e}"))?;

        let resp = crate::generated::DiscoverLocalResponse::decode(bytes.as_ref())
            .map_err(|e| format!("Failed to decode DiscoverLocalResponse: {e}"))?;

        Ok(resp.discovered_nodes)
    }
}

/// Connection pool manager for storage nodes
pub struct StorageNodeConnectionPool {
    healthy_monitor: Arc<StorageNodeHealthMonitor>,
    discovery: Arc<StorageNodeDiscovery>,
    pool_config: PoolConfig,
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_healthy_nodes: usize,
    pub max_connections_per_node: usize,
    pub connection_timeout_ms: u64,
    pub auto_discovery_enabled: bool,
    pub discovery_interval_ms: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_healthy_nodes: 2,
            max_connections_per_node: 10,
            connection_timeout_ms: 5000,
            auto_discovery_enabled: true,
            discovery_interval_ms: 300000, // 5 minutes
        }
    }
}

impl StorageNodeConnectionPool {
    /// Create new connection pool
    pub fn new(
        monitor: Arc<StorageNodeHealthMonitor>,
        discovery: Arc<StorageNodeDiscovery>,
        config: PoolConfig,
    ) -> Self {
        Self {
            healthy_monitor: monitor,
            discovery,
            pool_config: config,
        }
    }

    /// Get optimal storage node for a request
    pub async fn get_optimal_node(&self) -> Result<StorageNodeHealth, String> {
        // Try to get best healthy node
        if let Some(best_node) = self.healthy_monitor.get_best_node().await {
            return Ok(best_node);
        }

        // If no healthy nodes and auto-discovery is enabled, try discovery
        if self.pool_config.auto_discovery_enabled {
            warn!("No healthy storage nodes found, attempting discovery...");

            match self.discovery.discover_nodes().await {
                Ok(new_nodes) => {
                    if !new_nodes.is_empty() {
                        // Start monitoring new nodes
                        if let Err(e) = self.healthy_monitor.start_monitoring(new_nodes).await {
                            error!("Failed to start monitoring discovered nodes: {e}");
                        } else {
                            // Give a moment for health checks to complete (deterministic sleep)
                            // Deterministic: no wall-clock delays, continue immediately

                            // Try again
                            if let Some(best_node) = self.healthy_monitor.get_best_node().await {
                                return Ok(best_node);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Node discovery failed: {e}");
                }
            }
        }

        Err("No healthy storage nodes available".to_string())
    }

    /// Get multiple nodes for redundant operations
    pub async fn get_multiple_nodes(&self, count: usize) -> Vec<StorageNodeHealth> {
        let healthy_nodes = self.healthy_monitor.get_healthy_nodes().await;

        // Sort by health score descending
        let mut sorted_nodes = healthy_nodes;
        sorted_nodes.sort_by(|a, b| {
            b.health_score
                .partial_cmp(&a.health_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sorted_nodes.into_iter().take(count).collect()
    }

    /// Check if minimum healthy nodes requirement is met
    pub async fn has_minimum_healthy_nodes(&self) -> bool {
        let healthy_count = self.healthy_monitor.get_healthy_nodes().await.len();
        healthy_count >= self.pool_config.min_healthy_nodes
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_health_monitor_creation() {
        let config = HealthMonitorConfig::default();
        let monitor = StorageNodeHealthMonitor::new(config);

        let health_status = monitor.get_health_status().await;
        assert!(health_status.is_empty());
    }

    #[tokio::test]
    async fn test_node_id_generation() {
        let endpoint1 = "http://localhost:8080";
        let endpoint2 = "http://localhost:8081";

        let id1 = StorageNodeHealthMonitor::generate_node_id(endpoint1);
        let id2 = StorageNodeHealthMonitor::generate_node_id(endpoint2);

        assert_ne!(id1, id2);
        assert!(id1.starts_with("node_"));
        assert!(id2.starts_with("node_"));

        // IDs should be deterministic
        let id1_again = StorageNodeHealthMonitor::generate_node_id(endpoint1);
        assert_eq!(id1, id1_again);
    }

    #[tokio::test]
    async fn test_discovery_creation() {
        let discovery = StorageNodeDiscovery::new(vec!["http://localhost:8080".to_string()]);

        assert_eq!(discovery.known_discovery_endpoints.len(), 1);
    }
}
