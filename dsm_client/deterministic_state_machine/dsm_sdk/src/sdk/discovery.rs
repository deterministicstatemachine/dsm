//! # Storage Node Discovery (Development Only)
//!
//! Automatic discovery of DSM storage nodes via mDNS, network scanning,
//! and discovery-service endpoints. Feature-gated behind `dev-discovery`
//! since production deployments use explicit endpoint configuration
//! loaded from `dsm_env_config.toml`.
//!
//! Discovery is clockless: iteration budgets replace wall-clock timeouts
//! for mDNS scanning and cooperative yields replace `tokio::time::timeout`.

use crate::sdk::storage_node_sdk::StorageNodeError;
use reqwest::Client;
use prost::Message;
use log::{debug, error, info, warn};
use std::collections::HashSet;
use dsm::utils::deterministic_time::tick_index;

/// Configuration for node discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub discovery_url: String,
    pub discovery_timeout_ms: u64,
    pub discovery_interval_ms: u64,
    pub mdns_service_type: String,
    pub enable_mdns: bool,
}

/// Node discovery interface for finding storage nodes in the DSM network
#[derive(Debug)]
pub struct DiscoveryService {
    config: DiscoveryConfig,
    client: Client,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryConfig {
    pub fn new() -> Self {
        Self {
            discovery_url: "".to_string(), // NO HARDCODED ADDRESSES
            discovery_timeout_ms: 5000,
            discovery_interval_ms: 30000,
            mdns_service_type: "_dsm-storage._tcp.local.".to_string(),
            enable_mdns: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageNodeInfo {
    pub url: String,
    pub id: String,
    pub region: String,
    pub version: String,
    pub health_status: bool,
}

#[derive(Debug, Clone)]
pub struct NodeDiscoveryResponse {
    pub count: usize,
    pub nodes: Vec<String>,
}

/// Discover available storage nodes using multiple discovery methods
/// This is the main entry point for automatic node discovery (sync version)
pub fn discover_storage_nodes() -> Result<Vec<String>, StorageNodeError> {
    // Check if we're already in a Tokio runtime
    if tokio::runtime::Handle::try_current().is_ok() {
        // We're already in a runtime, this will cause a panic
        // Instead, suggest using the async version
        error!("discover_storage_nodes() called from within an async runtime");
        error!("Use discover_storage_nodes_async() instead when already in an async context");
        return Err(StorageNodeError::from_message(
            "Cannot create nested runtime. Use discover_storage_nodes_async() when already in async context".to_string()
        ));
    }

    // Not in a runtime, safe to create one
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime for discovery: {e}");
            return Err(StorageNodeError::from_message(format!(
                "Failed to create runtime: {e}"
            )));
        }
    };

    rt.block_on(discover_storage_nodes_async())
}

/// Discover available storage nodes using multiple discovery methods (async version)
/// This is the async entry point for automatic node discovery
pub async fn discover_storage_nodes_async() -> Result<Vec<String>, StorageNodeError> {
    // In tests, short-circuit to a deterministic empty set to keep tests hermetic and fast.
    // In test builds, return a deterministic empty set.
    // In tests previously we short-circuited to a deterministic empty set, but that caused
    // unreachable-code warnings under #![deny(warnings)] when building tests. We now run the
    // same logic in tests to keep compilation clean and behavior consistent.

    info!("Starting automatic discovery of DSM storage nodes");

    // Use network detector from network_detection module
    let network_detector = crate::sdk::network_detection::NetworkDetector::with_defaults();

    // Detect primary network interface
    let primary_interface_opt = match network_detector.detect_primary_network_interface().await {
        Ok(interface) => {
            info!(
                "Detected primary network interface: {} ({})",
                interface.name, interface.ip_address
            );
            Some(interface)
        }
        Err(e) => {
            warn!("Failed to detect network interface: {e}");
            None
        }
    };

    // Create a set to deduplicate node URLs
    let mut discovered_node_urls = HashSet::new();

    // 1. Discover via network detection (local network scanning)
    if let Some(primary_interface) = primary_interface_opt {
        info!("Attempting discovery via local network scanning");
        let network_nodes = network_detector
            .discover_local_storage_nodes(&primary_interface.ip_address)
            .await;

        for node in network_nodes {
            discovered_node_urls.insert(node.endpoint);
        }
    } else {
        info!("Skipping local network scanning due to missing network interface");
    }

    // 2. Try mDNS discovery
    info!("Attempting discovery via mDNS");
    match discover_via_mdns().await {
        Ok(ref mdns_nodes) => {
            for url in mdns_nodes {
                discovered_node_urls.insert(url.clone());
            }
            info!("Found {} nodes via mDNS", mdns_nodes.len());
        }
        Err(e) => {
            warn!("mDNS discovery failed: {e}");
        }
    }

    // 3. Try discovery service as another method
    info!("Attempting discovery via discovery service");
    let discovery_config = DiscoveryConfig::default();
    match DiscoveryService::new(discovery_config).await {
        Ok(discovery_service) => match discovery_service.discover_nodes().await {
            Ok(ref service_nodes) => {
                for node in service_nodes {
                    discovered_node_urls.insert(node.url.clone());
                }
                info!("Found {} nodes via discovery service", service_nodes.len());
            }
            Err(e) => {
                warn!("Discovery service failed: {e}");
            }
        },
        Err(e) => {
            warn!("Failed to create discovery service: {e}");
        }
    }

    // Production: best-effort; return empty list if none are found, callers may decide behavior
    if discovered_node_urls.is_empty() {
        warn!("No DSM storage nodes discovered via automatic discovery; returning empty list");
        return Ok(Vec::new());
    }

    // Convert the HashSet to a Vec
    let node_urls: Vec<String> = discovered_node_urls.into_iter().collect();

    info!("Discovered {} unique storage nodes", node_urls.len());
    Ok(node_urls)
}

/// Discover storage nodes using mDNS - REAL IMPLEMENTATION
async fn discover_via_mdns() -> Result<Vec<String>, StorageNodeError> {
    #[cfg(feature = "mdns")]
    {
        use mdns_sd::{ServiceDaemon, ServiceEvent};
        use std::net::IpAddr;

        info!("Starting mDNS discovery for _dsm-storage._tcp.local");

        let mdns = ServiceDaemon::new().map_err(|e| {
            StorageNodeError::from_message(format!("Failed to initialize mDNS daemon: {e}"))
        })?;

        let service_type = "_dsm-storage._tcp.local.";

        // Start browsing for DSM storage nodes
        let receiver = mdns.browse(service_type).map_err(|e| {
            StorageNodeError::from_message(format!("Failed to start mDNS browsing: {e}"))
        })?;

        let mut discovered_nodes = Vec::new();
        // Clockless: enforce an iteration budget (ticks), not wall-clock seconds.
        // Each loop iteration advances via local tick_index() and cooperative yields.
        let max_iterations: u64 = 250; // deterministic bound
        let start_tick = tick_index();
        let deadline_ticks = start_tick.saturating_add(max_iterations);

        info!(
            "Scanning for DSM storage nodes via mDNS (clockless budget={max_iterations} ticks)..."
        );

        while tick_index() < deadline_ticks {
            // Clockless: do not use tokio::time::timeout. Try to receive an event; if none is ready,
            // yield and continue.
            match receiver.try_recv() {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    let name = info.get_fullname();
                    let port = info.get_port();
                    let addresses: Vec<IpAddr> = info
                        .get_addresses()
                        .iter()
                        .map(|s| s.to_ip_addr())
                        .collect();

                    info!("✅ Resolved DSM node: {name} at port {port}");

                    for addr in addresses {
                        let protocol = if port == 443 { "https" } else { "http" };
                        let url = format!("{protocol}://{addr}:{port}");
                        info!("  → Available at: {url}");
                        discovered_nodes.push(url);
                    }
                }
                Ok(ServiceEvent::ServiceRemoved(name, _regtype)) => {
                    debug!("Service removed: {name}");
                }
                Ok(_) => {
                    // Other events we don't care about
                }
                Err(_) => {
                    // No event ready; cooperate with scheduler.
                    tokio::task::yield_now().await;
                    continue;
                }
            }
        }

        // Properly shutdown mDNS to prevent channel errors
        if let Err(e) = mdns.shutdown() {
            debug!("mDNS shutdown error (non-critical): {e}");
        }

        info!(
            "mDNS discovery completed. Found {} storage nodes",
            discovered_nodes.len()
        );
        Ok(discovered_nodes)
    }

    #[cfg(not(feature = "mdns"))]
    {
        error!("mDNS discovery not enabled - feature 'mdns' not compiled in");
        Err(StorageNodeError::from_message(
            "mDNS discovery not available. Compile with --features mdns".to_string(),
        ))
    }
}

impl DiscoveryService {
    /// Create a new discovery service with the specified configuration
    pub async fn new(config: DiscoveryConfig) -> Result<Self, StorageNodeError> {
        let client = Client::builder()
            // No wall clocks/timeouts; deterministic, best-effort only
            .build()
            .map_err(|e| {
                StorageNodeError::from_message(format!(
                    "Failed to create HTTP client for discovery: {e}"
                ))
            })?;

        Ok(Self { config, client })
    }

    /// Discover available storage nodes in the network
    pub async fn discover_nodes(&self) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        // No tokio::time::timeout; compute-bound budget only
        self.perform_discovery().await
    }

    async fn perform_discovery(&self) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        info!(
            "Starting node discovery from: {}",
            self.config.discovery_url
        );

        // Try to discover nodes from the configured discovery URL
        match self.discover_from_url(&self.config.discovery_url).await {
            Ok(nodes) => {
                info!("Successfully discovered {} nodes", nodes.len());
                Ok(nodes)
            }
            Err(e) => {
                warn!("Primary discovery failed: {e}, using bootstrap node path");
                self.get_bootstrap_nodes().await
            }
        }
    }

    async fn discover_from_url(&self, url: &str) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        fn join(base: &str, path: &str) -> String {
            let base = base.trim_end_matches('/');
            format!("{base}{path}")
        }

        // Try different discovery endpoints (PROTOBUF ONLY)
        let endpoints = vec![join(url, "/nodes/discover")];

        for endpoint in endpoints {
            debug!("Trying discovery endpoint: {endpoint}");

            match self.client.get(&endpoint).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        // Protobuf-only: decode DiscoverLocalResponse from bytes
                        if let Ok(bytes) = response.bytes().await {
                            match crate::generated::DiscoverLocalResponse::decode(bytes.as_ref()) {
                                Ok(resp) => {
                                    debug!(
                                        "Got discovery response with {} nodes",
                                        resp.discovered_nodes.len()
                                    );
                                    return self
                                        .convert_urls_to_node_info(resp.discovered_nodes)
                                        .await;
                                }
                                Err(e) => debug!(
                                    "Failed to decode DiscoverLocalResponse from {endpoint}: {e}",
                                ),
                            }
                        } else {
                            debug!("Failed to read discovery response bytes from {endpoint}");
                        }
                    } else {
                        debug!(
                            "Discovery endpoint {} returned status: {}",
                            endpoint,
                            response.status()
                        );
                    }
                }
                Err(e) => {
                    debug!("Failed to contact discovery endpoint {endpoint}: {e}");
                }
            }
        }

        Err(StorageNodeError::network(
            "All discovery endpoints failed".to_string(),
        ))
    }

    async fn convert_urls_to_node_info(
        &self,
        urls: Vec<String>,
    ) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        let mut nodes = Vec::new();

        for url in urls {
            // Try to get node info from each URL
            match self.get_node_info(&url).await {
                Ok(node_info) => nodes.push(node_info),
                Err(e) => {
                    warn!("Failed to get info for node {url}: {e}");
                    // Create a basic node info even if we can't get detailed info
                    nodes.push(StorageNodeInfo {
                        url: url.clone(),
                        id: Self::extract_node_id(&url),
                        region: "unknown".to_string(),
                        version: "unknown".to_string(),
                        health_status: false,
                    });
                }
            }
        }

        Ok(nodes)
    }

    async fn get_node_info(&self, url: &str) -> Result<StorageNodeInfo, StorageNodeError> {
        let status_url = format!("{url}/api/v2/health");

        let response =
            self.client.get(&status_url).send().await.map_err(|e| {
                StorageNodeError::network(format!("Failed to get node status: {e}"))
            })?;

        if response.status().is_success() {
            // Protobuf-only policy: do not parse JSON payloads here. Rely on endpoint success and
            // derive basic info deterministically; additional details can be added via protobuf if needed.
            let node_id = Self::extract_node_id(url);
            // Try to derive a version token from headers if present; otherwise mark unknown
            let version = response
                .headers()
                .get("x-dsm-version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            // Check health
            let health_status = self.check_node_health(url).await.unwrap_or(false);

            Ok(StorageNodeInfo {
                url: url.to_string(),
                id: node_id,
                region: "unknown".to_string(),
                version,
                health_status,
            })
        } else {
            Err(StorageNodeError::server_error(format!(
                "Node status endpoint returned: {}",
                response.status()
            )))
        }
    }

    async fn check_node_health(&self, url: &str) -> Result<bool, StorageNodeError> {
        let health_url = format!("{url}/api/v2/health");

        match self.client.get(&health_url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    fn extract_node_id(url: &str) -> String {
        // Extract a simple node ID from URL (e.g., port number or host)
        // Simple parsing without external url crate
        if url.starts_with("http://") || url.starts_with("https://") {
            let without_protocol = if let Some(stripped) = url.strip_prefix("https://") {
                stripped
            } else {
                &url[7..]
            };

            // Find the end of host:port (before any path)
            let host_port = without_protocol
                .split('/')
                .next()
                .unwrap_or(without_protocol);

            // Return the host:port regardless of whether it contains a port
            return host_port.to_string();
        }

        // Derive a numeric suffix from the URL in a deterministic way (no hex/base64)
        let hash = dsm::crypto::blake3::domain_hash("DSM/discovery-url", url.as_bytes());
        let mut four = [0u8; 4];
        four.copy_from_slice(&hash.as_bytes()[..4]);
        let n = u32::from_le_bytes(four);
        format!("node_{n}")
    }

    async fn get_bootstrap_nodes(&self) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        error!("Bootstrap nodes requested but no hardcoded addresses allowed");

        // NO HARDCODED BOOTSTRAP NODES - discovery must be truly automatic
        Err(StorageNodeError::from_message(
            "No bootstrap nodes available. Network discovery must find nodes automatically."
                .to_string(),
        ))
    }

    /// Discover nodes from multiple sources
    pub async fn discover_from_multiple_sources(
        &self,
        sources: Vec<String>,
    ) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        let mut all_nodes = Vec::new();

        for source in sources {
            match self.discover_from_url(&source).await {
                Ok(mut nodes) => {
                    info!("Discovered {} nodes from {}", nodes.len(), source);
                    all_nodes.append(&mut nodes);
                }
                Err(e) => {
                    warn!("Failed to discover from {source}: {e}");
                }
            }
        }

        // Remove duplicates based on URL
        all_nodes.sort_by(|a, b| a.url.cmp(&b.url));
        all_nodes.dedup_by(|a, b| a.url == b.url);

        if all_nodes.is_empty() {
            error!("No nodes discovered from any source");
            return Err(StorageNodeError::not_found(
                "No storage nodes discovered".to_string(),
            ));
        }

        Ok(all_nodes)
    }

    /// Discover and filter healthy nodes only
    pub async fn discover_healthy_nodes(&self) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        let all_nodes = self.discover_nodes().await?;

        let healthy_nodes: Vec<StorageNodeInfo> = all_nodes
            .into_iter()
            .filter(|node| node.health_status)
            .collect();

        if healthy_nodes.is_empty() {
            warn!("No healthy nodes found during discovery");
            return Err(StorageNodeError::not_found(
                "No healthy storage nodes found".to_string(),
            ));
        }

        info!("Found {} healthy nodes", healthy_nodes.len());
        Ok(healthy_nodes)
    }

    /// Get the best nodes based on criteria (health, region, etc.)
    pub async fn get_best_nodes(
        &self,
        max_count: usize,
        preferred_region: Option<&str>,
    ) -> Result<Vec<StorageNodeInfo>, StorageNodeError> {
        let mut nodes = self.discover_healthy_nodes().await?;

        // Sort by criteria (prefer specified region, then by health, then by last_seen)
        nodes.sort_by(|a, b| {
            // Prefer specified region
            if let Some(region) = preferred_region {
                let a_region_match = a.region == region;
                let b_region_match = b.region == region;

                if a_region_match && !b_region_match {
                    return std::cmp::Ordering::Less;
                } else if !a_region_match && b_region_match {
                    return std::cmp::Ordering::Greater;
                }
            }

            // Then by health status
            match (a.health_status, b.health_status) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Finally by device ID (lexicographic order)
                    a.id.cmp(&b.id)
                }
            }
        });

        // Take only the best nodes up to max_count
        nodes.truncate(max_count);

        Ok(nodes)
    }

    /// Continuous discovery with callback
    pub async fn start_continuous_discovery<F>(
        &self,
        mut callback: F,
    ) -> Result<(), StorageNodeError>
    where
        F: FnMut(Vec<StorageNodeInfo>) + Send + 'static,
    {
        info!("Starting continuous discovery with deterministic work budget (no clocks)");

        // Replace time-based interval with a deterministic yield loop (work units derived
        // from configured discovery_interval_ms but interpreted as iteration budget, not ms)
        let work_units: u64 = self.config.discovery_interval_ms.max(1);

        loop {
            // Deterministic cooperative yields to avoid busy-spin without clocks
            for _ in 0..work_units {
                tokio::task::yield_now().await;
            }

            match self.discover_nodes().await {
                Ok(nodes) => {
                    debug!("Continuous discovery found {} nodes", nodes.len());
                    callback(nodes);
                }
                Err(e) => {
                    error!("Continuous discovery failed: {e}");
                    // Call callback with empty list to indicate failure
                    callback(Vec::new());
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_service_creation() {
        let config = DiscoveryConfig::default();
        let service = DiscoveryService::new(config).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_node_id_extraction() {
        assert_eq!(
            DiscoveryService::extract_node_id("http://localhost:8080"),
            "localhost:8080"
        );
        assert_eq!(
            DiscoveryService::extract_node_id("https://storage.dsm.network"),
            "storage.dsm.network"
        );
    }

    #[test]
    fn test_discover_storage_nodes() {
        // This is a basic test that just ensures the function doesn't panic
        // In a real environment, we would test the network calls
        let result = discover_storage_nodes();

        // We can't assert success as it depends on the network environment
        // Just verify it returns a result
        match result {
            Ok(nodes) => {
                println!("Discovered {} nodes in test", nodes.len());
            }
            Err(e) => {
                println!("Discovery failed in test environment: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_discover_storage_nodes_async() {
        // Test the async version
        let result = discover_storage_nodes_async().await;

        match result {
            Ok(nodes) => {
                println!("Discovered {} nodes in async test", nodes.len());
            }
            Err(e) => {
                println!("Async discovery failed in test environment: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_bootstrap_nodes() {
        let config = DiscoveryConfig::default();
        let service = DiscoveryService::new(config).await.unwrap();

        let result = service.get_bootstrap_nodes().await;
        // By design, there are no hardcoded bootstrap nodes; ensure this returns an error
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().unwrap());
        assert!(err_msg.contains("No bootstrap nodes available"));
    }
}
