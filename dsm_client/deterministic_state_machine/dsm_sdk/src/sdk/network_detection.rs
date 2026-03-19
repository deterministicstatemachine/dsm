//! STRICT PROTOBUF-ONLY / CLOCKLESS / NO SERDE-JSON-BASE64-HEX
//! Deterministic step-bounded networking (no wall clocks, no tokio::time).
//! HTTP is used only as a transport wrapper; payloads must be protobuf bytes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
use std::process::Command;
use std::str::FromStr;
use log::{debug, info, error, warn};
use dsm::types::error::DsmError;
use prost::Message;

use crate::util::deterministic_time as dt;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use once_cell::sync::OnceCell;

// Global network connectivity gate
static NETWORK_GATE: OnceCell<Arc<NetworkConnectivityGate>> = OnceCell::new();

/// Get or create the global network connectivity gate
pub fn get_network_gate() -> &'static Arc<NetworkConnectivityGate> {
    NETWORK_GATE.get_or_init(|| Arc::new(NetworkConnectivityGate::new()))
}

// ------------------------- Protobuf shim for health -------------------------
mod pb {
    // Minimal health message expected from storage node over HTTP (octet-stream).
    // Adjust tags to your canonical schema if needed.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NodeHealth {
        /// "ok" on healthy nodes
        #[prost(string, tag = "1")]
        pub status: String,
        /// Optional semantic version
        #[prost(string, optional, tag = "2")]
        pub version: Option<String>,
        /// Whether MPC endpoints are enabled
        #[prost(bool, tag = "3")]
        pub supports_mpc: bool,
    }
}

// =====================
// SDK Config & Typings
// =====================

/// DSM SDK Configuration (pure Rust struct; no serde/json/base64/hex)
#[derive(Debug, Clone)]
pub struct DsmSdkConfig {
    pub storage_nodes: Vec<String>,
    pub default_threshold: usize,
    pub device_fingerprint: String, // ASCII decimal encoding only (no hex/base64)
    pub network_mode: String,
    pub mpc_timeout_ms: u64, // kept for compatibility; not used for wall clocks
    pub connection_timeout_ms: u64, // kept for compatibility; not used for wall clocks
    pub max_retries: u32,
    pub enable_offline_mode: bool,
    pub enable_bilateral_transactions: bool,
    pub enable_unilateral_transactions: bool,
    pub vault_support: bool,
}

/// Network connectivity gate with failure tracking and recovery
#[derive(Debug)]
pub struct NetworkConnectivityGate {
    network_available: AtomicBool,
    network_failure_count: AtomicU32,
    network_recovery_attempted: AtomicBool,
}

impl NetworkConnectivityGate {
    pub fn new() -> Self {
        Self {
            network_available: AtomicBool::new(true), // Assume available initially
            network_failure_count: AtomicU32::new(0),
            network_recovery_attempted: AtomicBool::new(false),
        }
    }

    /// Record a network connectivity failure
    pub fn record_network_failure(&self) {
        let count = self.network_failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        warn!("[NetworkGate] Network failure recorded (count: {})", count);

        if count >= 3 {
            self.network_available.store(false, Ordering::Relaxed);
            warn!("[NetworkGate] Network connectivity disabled due to repeated failures");
        }
    }

    /// Record successful network operation
    pub fn record_network_success(&self) {
        if self.network_failure_count.load(Ordering::Relaxed) > 0 {
            self.network_failure_count.store(0, Ordering::Relaxed);
            self.network_available.store(true, Ordering::Relaxed);
            info!("[NetworkGate] Network connectivity restored");
        }
    }

    /// Check if network operations should be disabled
    pub fn should_disable_network_features(&self) -> bool {
        !self.network_available.load(Ordering::Relaxed)
    }

    /// Check if network is available
    pub fn is_network_available(&self) -> bool {
        self.network_available.load(Ordering::Relaxed)
    }

    /// Get current failure count
    pub fn get_failure_count(&self) -> u32 {
        self.network_failure_count.load(Ordering::Relaxed)
    }

    /// Attempt network recovery
    pub fn attempt_network_recovery(&self) -> bool {
        if self
            .network_recovery_attempted
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            info!("[NetworkGate] Attempting network recovery");
            // Reset failure count to allow one retry
            self.network_failure_count.store(0, Ordering::Relaxed);
            self.network_available.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl Default for NetworkConnectivityGate {
    fn default() -> Self {
        Self::new()
    }
}

/// DSM node information for verification (protobuf-backed)
#[derive(Debug, Clone)]
struct DsmNodeInfo {
    pub version: Option<String>,
    pub supports_mpc: bool,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: IpAddr,
    pub is_active: bool,
    pub interface_type: NetworkInterfaceType,
}

/// Types of network interfaces
#[derive(Debug, Clone)]
pub enum NetworkInterfaceType {
    Ethernet,
    WiFi,
    Cellular,
    Bluetooth,
    Loopback,
    Unknown,
}

/// Network type classification
#[derive(Debug, Clone)]
pub enum NetworkType {
    WifiHome,  // 192.168.x.x
    Corporate, // 10.x.x.x
    Private,   // 172.16-31.x.x
    Localhost, // 127.x.x.x
    Public,    // Other addresses
    Unknown,
}

/// Storage node discovery result
#[derive(Debug, Clone)]
pub struct StorageNodeInfo {
    pub endpoint: String,
    pub ip_address: IpAddr,
    pub port: u16,
    pub is_reachable: bool,
    /// NOTE: value is deterministic tick counts (NOT milliseconds)
    pub latency_ms: Option<u64>,
    pub supports_mpc: bool,
    pub node_version: Option<String>,
    /// deterministic tick at last check
    pub last_check: u64,
}

/// Network discovery configuration (clockless)
#[derive(Debug, Clone)]
pub struct NetworkDiscoveryConfig {
    pub enable_local_discovery: bool,
    pub enable_dns_discovery: bool,
    pub enable_mdns_discovery: bool,

    /// Kept name for compatibility, but semantics are CLOCKLESS:
    /// used as a deterministic step budget (loop/yield count), NOT wall-clock ms.
    pub discovery_timeout_ms: u64,

    pub port_scan_range: (u16, u16),
    pub preferred_dns_servers: Vec<String>,
    pub local_network_ranges: Vec<String>,
    /// Include localhost (127.0.0.1) in scan targets when appropriate
    pub include_localhost: bool,
    /// Optional IPv4 last-octet scan bounds (inclusive)
    pub ip_scan_bounds: Option<(u8, u8)>,
}

impl Default for NetworkDiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_local_discovery: true,
            enable_dns_discovery: true,
            enable_mdns_discovery: true,
            discovery_timeout_ms: 8000, // interpreted as step budget, not time
            port_scan_range: (8080, 8084),
            preferred_dns_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "9.9.9.9".to_string(),
            ],
            local_network_ranges: vec![
                "192.168.0.0/16".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
            ],
            include_localhost: true,
            ip_scan_bounds: None,
        }
    }
}

/// Automatic network detection and configuration
pub struct NetworkDetector {
    config: NetworkDiscoveryConfig,
    /// Test-only overrides to avoid real network probes in CI
    #[cfg(test)]
    override_primary_interface: Option<NetworkInterface>,
    #[cfg(test)]
    override_nodes: Option<Vec<StorageNodeInfo>>,
}

/// Test-only builder for constructing a NetworkDetector with deterministic knobs
#[cfg(test)]
pub struct NetworkDetectorBuilder {
    config: NetworkDiscoveryConfig,
    primary: Option<NetworkInterface>,
    nodes: Option<Vec<StorageNodeInfo>>,
}

#[cfg(test)]
impl Default for NetworkDetectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl NetworkDetectorBuilder {
    pub fn new() -> Self {
        Self {
            config: NetworkDiscoveryConfig::default(),
            primary: None,
            nodes: None,
        }
    }

    pub fn with_discovery_timeout_ms(mut self, ms: u64) -> Self {
        self.config.discovery_timeout_ms = ms;
        self
    }

    pub fn with_ip_scan_bounds(mut self, lo: u8, hi: u8) -> Self {
        self.config.ip_scan_bounds = Some((lo, hi));
        self
    }

    pub fn enable_dns(mut self, enabled: bool) -> Self {
        self.config.enable_dns_discovery = enabled;
        self
    }

    pub fn enable_mdns(mut self, enabled: bool) -> Self {
        self.config.enable_mdns_discovery = enabled;
        self
    }

    pub fn include_localhost(mut self, include: bool) -> Self {
        self.config.include_localhost = include;
        self
    }

    pub fn with_port_scan_range(mut self, start: u16, end: u16) -> Self {
        self.config.port_scan_range = (start, end);
        self
    }

    pub fn override_primary_interface(mut self, iface: NetworkInterface) -> Self {
        self.primary = Some(iface);
        self
    }

    pub fn override_nodes(mut self, nodes: Vec<StorageNodeInfo>) -> Self {
        self.nodes = Some(nodes);
        self
    }

    pub fn build(self) -> NetworkDetector {
        let mut det = NetworkDetector::new(self.config);
        det.override_primary_interface = self.primary;
        det.override_nodes = self.nodes;
        det
    }
}

impl NetworkDetector {
    /// Create a new network detector
    pub fn new(config: NetworkDiscoveryConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            override_primary_interface: None,
            #[cfg(test)]
            override_nodes: None,
        }
    }

    /// Create detector with default configuration
    pub fn with_defaults() -> Self {
        #[allow(unused_mut)]
        let mut cfg = NetworkDiscoveryConfig::default();
        #[cfg(test)]
        {
            cfg.discovery_timeout_ms = 200; // step budget (not time)
            cfg.ip_scan_bounds = Some((1, 1)); // scan only x.x.x.1 in tests
            cfg.enable_dns_discovery = false;
            cfg.enable_mdns_discovery = false;
        }
        Self::new(cfg)
    }

    /// Create a detector with deterministic, test-only overrides that disable real probes.
    #[cfg(test)]
    pub fn with_test_overrides(
        primary_interface: NetworkInterface,
        nodes: Vec<StorageNodeInfo>,
    ) -> Self {
        let mut d = Self::with_defaults();
        d.override_primary_interface = Some(primary_interface);
        d.override_nodes = Some(nodes);
        d
    }

    /// Detect primary network interface and IP address
    pub async fn detect_primary_network_interface(&self) -> Result<NetworkInterface, String> {
        info!("Detecting primary network interface");

        // In tests, prefer deterministic override to avoid any real network access
        #[cfg(test)]
        if let Some(ref iface) = self.override_primary_interface {
            return Ok(iface.clone());
        }

        // On Android, skip route-based detection
        #[cfg(not(target_os = "android"))]
        {
            if let Ok(interface) = self.detect_via_route().await {
                info!("Primary interface via route: {interface:?}");
                return Ok(interface);
            }
            if let Ok(interface) = self.detect_via_platform_tools().await {
                info!("Primary interface via platform tools: {interface:?}");
                return Ok(interface);
            }
        }

        if let Ok(interface) = self.detect_via_interface_enumeration().await {
            info!("Primary interface via enumeration: {interface:?}");
            return Ok(interface);
        }

        #[cfg(target_os = "android")]
        {
            warn!("Using Android secondary interface path");
            if let Ok(interface) = self.android_safe_secondary().await {
                return Ok(interface);
            }
        }

        error!("Could not detect primary interface; no alternate paths allowed");
        Err("Could not detect primary network interface. No alternate paths allowed.".to_string())
    }

    /// Route-based (desktop)
    #[allow(dead_code)]
    async fn detect_via_route(&self) -> Result<NetworkInterface, String> {
        debug!("Route-based detection");
        #[cfg(target_os = "android")]
        {
            return Err("Route-based disabled on Android".to_string());
        }
        #[cfg(not(target_os = "android"))]
        {
            let output = Command::new("ip")
                .args(["route", "get", "8.8.8.8"])
                .output()
                .map_err(|e| format!("Failed to run ip route: {e}"))?;
            if !output.status.success() {
                return Err("ip route command failed".to_string());
            }
            let route_info = String::from_utf8_lossy(&output.stdout);
            debug!("Route info: {route_info}");
            for line in route_info.lines() {
                if let Some(src_pos) = line.find("src ") {
                    let src_part = &line[src_pos + 4..];
                    if let Some(ip_str) = src_part.split_whitespace().next() {
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            let interface_name = self
                                .get_interface_name_for_ip(&ip)
                                .await
                                .unwrap_or_else(|| "unknown".to_string());
                            return Ok(NetworkInterface {
                                name: interface_name,
                                ip_address: ip,
                                is_active: true,
                                interface_type: self.classify_interface_type(&ip),
                            });
                        }
                    }
                }
            }
            Err("Could not parse route information".to_string())
        }
    }

    /// Platform-specific tools
    #[allow(dead_code)]
    async fn detect_via_platform_tools(&self) -> Result<NetworkInterface, String> {
        debug!("Platform-specific detection");
        if cfg!(target_os = "macos") {
            return self.detect_macos_interface().await;
        }
        if cfg!(target_os = "linux") {
            return self.detect_linux_interface().await;
        }
        if cfg!(target_os = "windows") {
            return self.detect_windows_interface().await;
        }
        Err("Unsupported platform".to_string())
    }

    #[allow(dead_code)]
    async fn detect_macos_interface(&self) -> Result<NetworkInterface, String> {
        debug!("macOS interface detection");
        let services_output = Command::new("networksetup")
            .args(["-listnetworkserviceorder"])
            .output()
            .map_err(|e| format!("Failed to list network services: {e}"))?;
        let services_info = String::from_utf8_lossy(&services_output.stdout);
        for line in services_info.lines() {
            if line.contains("Wi-Fi") {
                if let Some(start) = line.find(") ") {
                    let service_name = &line[start + 2..];
                    let info_output = Command::new("networksetup")
                        .args(["-getinfo", service_name])
                        .output()
                        .map_err(|e| format!("Failed to get service info: {e}"))?;
                    let info = String::from_utf8_lossy(&info_output.stdout);
                    for info_line in info.lines() {
                        if let Some(ip_str) = info_line.strip_prefix("IP address: ") {
                            if let Ok(ip) = IpAddr::from_str(ip_str) {
                                return Ok(NetworkInterface {
                                    name: "en0".to_string(),
                                    ip_address: ip,
                                    is_active: true,
                                    interface_type: NetworkInterfaceType::WiFi,
                                });
                            }
                        }
                    }
                }
            }
        }
        Err("Could not detect macOS interface".to_string())
    }

    #[allow(dead_code)]
    async fn detect_linux_interface(&self) -> Result<NetworkInterface, String> {
        debug!("Linux interface detection");
        if let Ok(output) = Command::new("ip").args(["addr", "show"]).output() {
            let addr_info = String::from_utf8_lossy(&output.stdout);
            return self.parse_ip_addr_output(&addr_info);
        }
        if let Ok(output) = Command::new("ifconfig").output() {
            let ifconfig_info = String::from_utf8_lossy(&output.stdout);
            return self.parse_ifconfig_output(&ifconfig_info);
        }
        Err("Could not run ip or ifconfig".to_string())
    }

    #[allow(dead_code)]
    async fn detect_windows_interface(&self) -> Result<NetworkInterface, String> {
        debug!("Windows interface detection");
        let output = Command::new("ipconfig")
            .args(["/all"])
            .output()
            .map_err(|e| format!("Failed to run ipconfig: {e}"))?;
        let ipconfig_info = String::from_utf8_lossy(&output.stdout);
        self.parse_ipconfig_output(&ipconfig_info)
    }

    #[allow(dead_code)]
    fn parse_ip_addr_output(&self, output: &str) -> Result<NetworkInterface, String> {
        let mut current_interface = None;
        let mut current_ip = None;
        for line in output.lines() {
            let line = line.trim();
            if line.contains(": ") && !line.starts_with(' ') {
                if let Some(name_part) = line.split(": ").nth(1) {
                    if let Some(name) = name_part.split_whitespace().next() {
                        current_interface = Some(name.to_string());
                    }
                }
            }
            if line.starts_with("inet ") && !line.contains("127.0.0.1") {
                if let Some(addr_part) = line.split_whitespace().nth(1) {
                    if let Some(ip_str) = addr_part.split('/').next() {
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            current_ip = Some(ip);
                            break;
                        }
                    }
                }
            }
        }
        if let (Some(name), Some(ip)) = (current_interface, current_ip) {
            Ok(NetworkInterface {
                name,
                ip_address: ip,
                is_active: true,
                interface_type: self.classify_interface_type(&ip),
            })
        } else {
            Err("Could not parse ip addr output".to_string())
        }
    }

    #[allow(dead_code)]
    fn parse_ifconfig_output(&self, output: &str) -> Result<NetworkInterface, String> {
        let mut current_interface = None;
        for line in output.lines() {
            let line = line.trim();
            if !line.starts_with(' ') && line.contains(':') {
                if let Some(name) = line.split(':').next() {
                    current_interface = Some(name.to_string());
                }
            }
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                let ip_str = if line.contains("inet addr:") {
                    line.split("inet addr:")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                } else if line.contains("inet ") {
                    line.split("inet ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                } else {
                    None
                };
                if let Some(ip_str) = ip_str {
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        let interface_name = current_interface
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string());
                        return Ok(NetworkInterface {
                            name: interface_name,
                            ip_address: ip,
                            is_active: true,
                            interface_type: self.classify_interface_type(&ip),
                        });
                    }
                }
            }
        }
        Err("Could not parse ifconfig output".to_string())
    }

    #[allow(dead_code)]
    fn parse_ipconfig_output(&self, output: &str) -> Result<NetworkInterface, String> {
        let mut current_adapter = None;
        for line in output.lines() {
            let line = line.trim();
            if line.contains("adapter") && line.contains(':') {
                current_adapter = Some(line.to_string());
            }
            if line.contains("IPv4 Address") && line.contains(':') {
                if let Some(ip_part) = line.split(':').nth(1) {
                    let ip_str = ip_part.trim();
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        if !ip.is_loopback() {
                            let adapter_name = current_adapter
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());
                            return Ok(NetworkInterface {
                                name: adapter_name,
                                ip_address: ip,
                                is_active: true,
                                interface_type: self.classify_interface_type(&ip),
                            });
                        }
                    }
                }
            }
        }
        Err("Could not parse ipconfig output".to_string())
    }

    async fn detect_via_interface_enumeration(&self) -> Result<NetworkInterface, String> {
        debug!("Interface enumeration");
        #[cfg(target_os = "android")]
        {
            warn!("Enumeration disabled on Android; using secondary path");
            return self.android_safe_secondary().await;
        }
        #[cfg(not(target_os = "android"))]
        {
            match std::net::UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    if let Ok(()) = socket.connect("8.8.8.8:80") {
                        if let Ok(local_addr) = socket.local_addr() {
                            return Ok(NetworkInterface {
                                name: "detected".to_string(),
                                ip_address: local_addr.ip(),
                                is_active: true,
                                interface_type: self.classify_interface_type(&local_addr.ip()),
                            });
                        }
                    }
                }
                Err(e) => debug!("UDP bind failed: {e}"),
            }
            Err("Interface enumeration not available".to_string())
        }
    }

    #[cfg(target_os = "android")]
    async fn android_safe_secondary(&self) -> Result<NetworkInterface, String> {
        debug!("Android-safe secondary path");
        let secondary_ips = [
            "10.0.2.2",
            "10.0.2.15",
            "192.168.1.100",
            "192.168.0.100",
            "10.167.12.22",
        ];
        for ip_str in secondary_ips {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                info!("Using Android secondary-path IP: {ip}");
                return Ok(NetworkInterface {
                    name: "android_secondary".to_string(),
                    ip_address: ip,
                    is_active: true,
                    interface_type: self.classify_interface_type(&ip),
                });
            }
        }
        Err("Android secondary path failed".to_string())
    }

    async fn get_interface_name_for_ip(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let o = ipv4.octets();
                if o[0] == 192 && o[1] == 168 {
                    Some("wlan0".to_string())
                } else if o[0] == 10 {
                    Some("eth0".to_string())
                } else {
                    Some("unknown".to_string())
                }
            }
            IpAddr::V6(_) => Some("unknown".to_string()),
        }
    }

    fn classify_interface_type(&self, ip: &IpAddr) -> NetworkInterfaceType {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() {
                    NetworkInterfaceType::Loopback
                } else if ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168 {
                    NetworkInterfaceType::WiFi
                } else {
                    NetworkInterfaceType::Ethernet
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() {
                    NetworkInterfaceType::Loopback
                } else {
                    NetworkInterfaceType::Unknown
                }
            }
        }
    }

    pub fn classify_network_type(&self, ip: &IpAddr) -> NetworkType {
        match ip {
            IpAddr::V4(ipv4) => {
                let o = ipv4.octets();
                if o[0] == 192 && o[1] == 168 {
                    NetworkType::WifiHome
                } else if o[0] == 10 {
                    NetworkType::Corporate
                } else if o[0] == 172 && (16..=31).contains(&o[1]) {
                    NetworkType::Private
                } else if o[0] == 127 {
                    NetworkType::Localhost
                } else {
                    NetworkType::Public
                }
            }
            IpAddr::V6(_) => NetworkType::Unknown,
        }
    }

    /// Deterministic step-bounded await helper (no wall clocks).
    async fn with_budget<F, T>(&self, mut budget_steps: u64, fut: F) -> Option<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let handle = tokio::spawn(fut);
        loop {
            if handle.is_finished() {
                return handle.await.ok();
            }
            if budget_steps == 0 {
                handle.abort();
                return None;
            }
            budget_steps -= 1;
            // Yield to reactor once; deterministic in count, not in time.
            tokio::task::yield_now().await;
        }
    }

    /// Discover local DSM storage nodes with network-first strategy (no alternate paths)
    pub async fn discover_local_storage_nodes(&self, primary_ip: &IpAddr) -> Vec<StorageNodeInfo> {
        info!("Discovering DSM storage nodes from IP: {primary_ip} (clockless)");

        #[cfg(test)]
        if let Some(ref nodes) = self.override_nodes {
            return nodes.clone();
        }

        let mut discovered_nodes = Vec::new();

        if self.config.enable_local_discovery {
            info!("🔍 Scanning local network for DSM storage nodes...");
            if let Ok(local_nodes) = self.discover_nodes_in_local_network(primary_ip).await {
                discovered_nodes.extend(local_nodes);
                let count = discovered_nodes.len();
                info!("✅ Found {count} nodes via local network scan");
            } else {
                error!("❌ Local network discovery failed");
            }
        }

        if self.config.enable_dns_discovery {
            info!("🔍 Attempting DNS discovery...");
            if let Ok(dns_nodes) = self.discover_nodes_via_dns().await {
                let dns_count = dns_nodes.len();
                discovered_nodes.extend(dns_nodes);
                info!("✅ Found {dns_count} additional nodes via DNS");
            } else {
                warn!("⚠️ DNS discovery failed");
            }
        }

        if self.config.enable_mdns_discovery {
            info!("🔍 Attempting mDNS discovery...");
            if let Ok(mdns_nodes) = self.discover_nodes_via_mdns().await {
                let mdns_count = mdns_nodes.len();
                discovered_nodes.extend(mdns_nodes);
                info!("✅ Found {mdns_count} additional nodes via mDNS");
            } else {
                warn!("⚠️ mDNS discovery failed");
            }
        }

        if discovered_nodes.is_empty() {
            error!("❌ No DSM storage nodes discovered on network. No alternate paths allowed.");
        }

        self.deduplicate_and_sort_nodes(discovered_nodes)
    }

    async fn discover_nodes_in_local_network(
        &self,
        primary_ip: &IpAddr,
    ) -> Result<Vec<StorageNodeInfo>, String> {
        debug!("Scanning local network for DSM nodes");
        let mut nodes = Vec::new();
        let ip_range = self.generate_local_ip_range(primary_ip)?;
        let ip_targets = ip_range.len();
        debug!("Scanning {ip_targets} IP addresses for DSM storage nodes");

        for (ip_index, ip) in ip_range.iter().enumerate() {
            let idx = ip_index + 1;
            let total = ip_range.len();
            debug!("Scanning IP {idx}/{total}: {ip}");

            for port in self.config.port_scan_range.0..=self.config.port_scan_range.1 {
                debug!("  Checking {ip}:{port}");
                match self.check_dsm_node(ip, port).await {
                    Ok(Some(node)) => {
                        debug!("  ✅ Found DSM node at {}", node.endpoint);
                        nodes.push(node);
                    }
                    Ok(None) => {
                        debug!("  ❌ No DSM node at {ip}:{port}");
                    }
                    Err(e) => {
                        debug!("  ⚠️  Error checking {ip}:{port} - {e}");
                    }
                }
            }
        }
        let found = nodes.len();
        debug!("Network scan completed, found {found} nodes");
        Ok(nodes)
    }

    fn generate_local_ip_range(&self, primary_ip: &IpAddr) -> Result<Vec<IpAddr>, String> {
        let env_override = std::env::var("DSM_DISCOVERY_LOCALHOST")
            .ok()
            .map(|v| v == "0" || v.to_lowercase() == "false");
        let disable_localhost = match env_override {
            Some(flag) => flag,
            None => !self.config.include_localhost,
        };
        match primary_ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let mut ips = Vec::new();

                let env_bounds = std::env::var("DSM_IP_SCAN_RANGE")
                    .ok()
                    .and_then(|s| {
                        let parts: Vec<&str> = s.trim().split('-').collect();
                        if parts.len() == 2 {
                            if let (Ok(a), Ok(b)) =
                                (parts[0].parse::<u16>(), parts[1].parse::<u16>())
                            {
                                if (1..=254).contains(&a) && (1..=254).contains(&b) {
                                    let (lo, hi) = if a <= b {
                                        (a as u8, b as u8)
                                    } else {
                                        (b as u8, a as u8)
                                    };
                                    return Some((lo, hi));
                                }
                            }
                        }
                        None
                    })
                    .or_else(|| {
                        match (
                            std::env::var("DSM_IP_SCAN_MIN")
                                .ok()
                                .and_then(|v| v.parse::<u16>().ok()),
                            std::env::var("DSM_IP_SCAN_MAX")
                                .ok()
                                .and_then(|v| v.parse::<u16>().ok()),
                        ) {
                            (Some(a), Some(b))
                                if (1..=254).contains(&a) && (1..=254).contains(&b) =>
                            {
                                let (lo, hi) = if a <= b {
                                    (a as u8, b as u8)
                                } else {
                                    (b as u8, a as u8)
                                };
                                Some((lo, hi))
                            }
                            _ => None,
                        }
                    });

                let scan_bounds = env_bounds.or(self.config.ip_scan_bounds);

                if ipv4.is_loopback() {
                    if !disable_localhost {
                        info!("Loopback detected; scanning only 127.0.0.1 for DSM nodes");
                        return Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
                    } else {
                        info!("Loopback detected but localhost scanning disabled");
                        return Ok(vec![]);
                    }
                }

                if octets[0] == 10 && octets[1] == 0 && octets[2] == 2 {
                    info!("🤖 Android emulator network detected (10.0.2.x)");
                    info!("Using emulator host bridge 10.0.2.2");
                    ips.push(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)));
                    if !disable_localhost {
                        ips.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                    }
                    let ip_count = ips.len();
                    info!("Will scan {ip_count} IP addresses for emulator setup");
                    return Ok(ips);
                }

                info!(
                    "Generating IP range for network {}.{}.{}.x",
                    octets[0], octets[1], octets[2]
                );

                if !disable_localhost {
                    ips.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                }

                match scan_bounds {
                    Some((lo, hi)) => {
                        let (start, end) = if lo <= hi { (lo, hi) } else { (hi, lo) };
                        info!("Using configured IPv4 scan bounds: last octet {start}-{end}");
                        for last_octet in start..=end {
                            if last_octet == octets[3] {
                                continue;
                            }
                            let ip = IpAddr::V4(Ipv4Addr::new(
                                octets[0], octets[1], octets[2], last_octet,
                            ));
                            ips.push(ip);
                        }
                        let ip_count = ips.len();
                        info!("Will scan {ip_count} IP addresses in configured range");
                    }
                    None => {
                        for addr in 1..=254u16 {
                            let last_octet = addr as u8;
                            if last_octet == octets[3] {
                                continue;
                            }
                            let ip = IpAddr::V4(Ipv4Addr::new(
                                octets[0], octets[1], octets[2], last_octet,
                            ));
                            ips.push(ip);
                        }
                        let ip_count = ips.len();
                        info!("Will scan {ip_count} IP addresses in /24");
                    }
                }
                Ok(ips)
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() && disable_localhost {
                    info!("IPv6 loopback detected but localhost scanning disabled");
                    return Ok(vec![]);
                }
                // Minimal IPv6 support: probe the detected IPv6 address only (no /64 sweep).
                Ok(vec![IpAddr::V6(*ipv6)])
            }
        }
    }

    async fn check_dsm_node(
        &self,
        ip: &IpAddr,
        port: u16,
    ) -> Result<Option<StorageNodeInfo>, String> {
        let start_tick = dt::tick();

        {
            let addr = SocketAddr::new(*ip, port);
            let connect_steps = 32; // deterministic work budget

            // with_budget yields Option<Result<TcpStream, io::Error>>
            let polled = self
                .with_budget(connect_steps, TcpStream::connect(addr))
                .await;
            // If not polled within budget, treat as not reachable
            let Some(connect_res) = polled else {
                return Ok(None);
            };
            // If connect errored, also treat as not reachable (no wall clocks/timeouts)
            let _stream = match connect_res {
                Ok(s) => s,
                Err(_ioe) => return Ok(None),
            };
        }

        // Verify via HTTP octet-stream protobuf health still clockless via step budget
        let url = format!("http://{ip}:{port}");
        match self.verify_dsm_node(&url).await {
            Ok(node_info) => {
                debug!("✅ Verified DSM storage node at {url}");
                let end_tick = dt::tick();
                let latency_ticks = end_tick.saturating_sub(start_tick);
                Ok(Some(StorageNodeInfo {
                    endpoint: url,
                    ip_address: *ip,
                    port,
                    is_reachable: true,
                    latency_ms: Some(latency_ticks), // ticks, not ms
                    supports_mpc: node_info.supports_mpc,
                    node_version: node_info.version,
                    last_check: dt::tick(),
                }))
            }
            Err(e) => {
                debug!("❌ Not a DSM node at {url} - {e}");
                Ok(None)
            }
        }
    }

    async fn discover_nodes_via_dns(&self) -> Result<Vec<StorageNodeInfo>, String> {
        debug!("DNS discovery disabled - no hardcoded hostnames allowed");
        warn!("DNS discovery skipped - no known hostnames configured (by design)");
        Ok(vec![])
    }

    async fn discover_nodes_via_mdns(&self) -> Result<Vec<StorageNodeInfo>, DsmError> {
        debug!("Discovering DSM nodes via mDNS");
        Err(DsmError::NotImplemented(
            "Implement mDNS discovery".to_string(),
        ))
    }

    fn deduplicate_and_sort_nodes(&self, mut nodes: Vec<StorageNodeInfo>) -> Vec<StorageNodeInfo> {
        let mut seen_endpoints = std::collections::HashSet::new();
        nodes.retain(|node| seen_endpoints.insert(node.endpoint.clone()));

        nodes.sort_by(|a, b| match (a.is_reachable, b.is_reachable) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => a
                .latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.latency_ms.unwrap_or(u64::MAX)),
            (false, false) => std::cmp::Ordering::Equal,
        });

        nodes
    }

    pub async fn find_available_ports(&self, start_port: u16, count: usize) -> Vec<u16> {
        debug!("Finding {count} available ports starting from {start_port}");
        let mut available_ports = Vec::new();
        let mut port = start_port;

        while available_ports.len() < count && port < 65535 {
            if self.is_port_available(port).await {
                available_ports.push(port);
                debug!("Port {port} is available");
            }
            port += 1;
        }
        available_ports
    }

    async fn is_port_available(&self, port: u16) -> bool {
        (TcpStream::connect(format!("127.0.0.1:{port}")).await).is_err()
    }

    pub async fn generate_auto_config(&self) -> Result<DsmSdkConfig, String> {
        info!("Generating automatic network configuration");

        let primary_interface = self.detect_primary_network_interface().await?;
        let network_type = self.classify_network_type(&primary_interface.ip_address);

        let discovered_nodes = self
            .discover_local_storage_nodes(&primary_interface.ip_address)
            .await;

        if discovered_nodes.is_empty() {
            error!("No storage nodes discovered; no alternate paths allowed");
            return Err("No storage nodes discovered. Automatic discovery is required by protocol. No alternate paths allowed.".to_string());
        }

        let storage_nodes = discovered_nodes
            .iter()
            .map(|node| node.endpoint.clone())
            .collect();

        let device_fingerprint = self.generate_device_fingerprint(&primary_interface).await?;

        let network_mode = match network_type {
            NetworkType::Localhost => "development".to_string(),
            NetworkType::WifiHome | NetworkType::Private => "testnet".to_string(),
            NetworkType::Corporate => "staging".to_string(),
            NetworkType::Public => "mainnet".to_string(),
            NetworkType::Unknown => "development".to_string(),
        };

        let config = DsmSdkConfig {
            storage_nodes,
            default_threshold: 2,
            device_fingerprint,
            network_mode,
            mpc_timeout_ms: 30000, // kept for API compatibility (not used for time)
            connection_timeout_ms: 5000, // kept for API compatibility (not used for time)
            max_retries: 3,
            enable_offline_mode: true,
            enable_bilateral_transactions: true,
            enable_unilateral_transactions: true,
            vault_support: true,
        };

        Ok(config)
    }

    async fn generate_device_fingerprint(
        &self,
        interface: &NetworkInterface,
    ) -> Result<String, String> {
        // Deterministic, clockless fingerprint string (ASCII decimal only).
        // No hex/base64/serde; includes ip/name/env and a deterministic tick.
        let mut fingerprint_data = Vec::new();
        fingerprint_data.extend_from_slice(interface.ip_address.to_string().as_bytes());
        fingerprint_data.extend_from_slice(interface.name.as_bytes());
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            fingerprint_data.extend_from_slice(hostname.as_bytes());
        }
        let tick = dt::tick();
        fingerprint_data.extend_from_slice(&tick.to_le_bytes());

        let hash = dsm::crypto::hash::blake3(&fingerprint_data);
        let bytes = hash.as_bytes();

        // Render first 16 bytes as decimal dot-separated (no hex)
        let mut s = String::from("fp:");
        s.push_str(&tick.to_string());
        s.push(':');
        for (i, b) in bytes[..16].iter().enumerate() {
            if i > 0 {
                s.push('.');
            }
            s.push_str(&b.to_string());
        }
        Ok(s)
    }

    /// Verify DSM node via HTTP octet-stream protobuf (clockless: step-bounded awaits only)
    async fn verify_dsm_node(&self, base_url: &str) -> Result<DsmNodeInfo, String> {
        // Prefer canonical health endpoint; accept a small set of alternates.
        let endpoints = [
            format!("{base_url}/api/v2/health"),
            format!("{base_url}/health"),
            format!("{base_url}/api/health"),
        ];

        let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
        let budget = self.config.discovery_timeout_ms;

        for endpoint in endpoints {
            // Step-bounded send (no timeouts)
            let resp_opt = self
                .with_budget(
                    budget,
                    client
                        .get(&endpoint)
                        .header("accept", "application/octet-stream")
                        .send(),
                )
                .await;
            let Some(resp_res) = resp_opt else { continue };
            let Ok(resp) = resp_res else { continue };

            if !resp.status().is_success() {
                debug!("Endpoint {endpoint} returned HTTP {}", resp.status());
                continue;
            }

            // Step-bounded read of body
            let body_opt = self.with_budget(budget, async { resp.bytes().await }).await;
            let Some(body_res) = body_opt else { continue };
            let Ok(body) = body_res else { continue };

            // Try protobuf decode
            if let Ok(health) = pb::NodeHealth::decode(body.clone()) {
                let ok = health.status.eq_ignore_ascii_case("ok");
                if ok || health.supports_mpc {
                    debug!("🔍 DSM node verified via protobuf health at {endpoint}");
                    return Ok(DsmNodeInfo {
                        version: health.version,
                        supports_mpc: health.supports_mpc || ok,
                    });
                } else {
                    debug!("Health protobuf present but not OK at {endpoint}");
                    continue;
                }
            }

            // Allow minimal "ok" plaintext for transitional nodes (no JSON)
            if body.len() <= 8 {
                let lower = String::from_utf8_lossy(&body).trim().to_ascii_lowercase();
                if lower == "ok" {
                    debug!("🔍 DSM node verified via simple 'ok' at {endpoint}");
                    return Ok(DsmNodeInfo {
                        version: None,
                        supports_mpc: true,
                    });
                }
            }
        }

        Err("No DSM endpoints responded with valid protobuf/OK".to_string())
    }
}

/// Network detection results
#[derive(Debug, Clone)]
pub struct NetworkDetectionResult {
    pub primary_interface: NetworkInterface,
    pub network_type: NetworkType,
    pub discovered_storage_nodes: Vec<StorageNodeInfo>,
    pub available_ports: Vec<u16>,
    pub generated_config: DsmSdkConfig,
    pub detection_tick: u64,
}

/// Convenience function for automatic network detection and configuration
pub async fn auto_detect_and_configure() -> Result<NetworkDetectionResult, String> {
    info!("Starting automatic network detection and configuration");

    let detector = NetworkDetector::with_defaults();

    let primary_interface = detector.detect_primary_network_interface().await?;
    let network_type = detector.classify_network_type(&primary_interface.ip_address);

    let discovered_storage_nodes = detector
        .discover_local_storage_nodes(&primary_interface.ip_address)
        .await;

    if discovered_storage_nodes.is_empty() {
        error!("No storage nodes discovered; no alternate paths allowed");
        return Err("No storage nodes discovered. Automatic discovery is required by protocol. No alternate paths allowed.".to_string());
    }

    let discovered_count = discovered_storage_nodes.len();
    info!("Discovered {discovered_count} storage nodes");

    let available_ports = detector.find_available_ports(9000, 5).await;

    let generated_config = detector.generate_auto_config().await?;

    let result = NetworkDetectionResult {
        primary_interface,
        network_type,
        discovered_storage_nodes,
        available_ports,
        generated_config,
        detection_tick: dt::tick(),
    };

    Ok(result)
}

// ============================ TESTS =========================================

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_detector_creation() {
        let detector = NetworkDetector::with_defaults();
        // In tests we keep local discovery enabled but disable DNS/mDNS to avoid
        // environment-dependent hangs. Also enforce a short "budget" and tight scan bounds.
        assert!(detector.config.enable_local_discovery);
        assert!(!detector.config.enable_dns_discovery);
        assert!(!detector.config.enable_mdns_discovery);
        assert!(detector.config.discovery_timeout_ms <= 200);
        assert_eq!(detector.config.ip_scan_bounds, Some((1, 1)));
    }

    #[tokio::test]
    async fn test_network_type_classification() {
        let detector = NetworkDetector::with_defaults();

        let home_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(matches!(
            detector.classify_network_type(&home_ip),
            NetworkType::WifiHome
        ));

        let corporate_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        assert!(matches!(
            detector.classify_network_type(&corporate_ip),
            NetworkType::Corporate
        ));

        let localhost_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(matches!(
            detector.classify_network_type(&localhost_ip),
            NetworkType::Localhost
        ));
    }

    #[tokio::test]
    async fn test_port_availability() {
        let detector = NetworkDetector::with_defaults();
        let _ = detector.is_port_available(65432).await;
    }

    #[tokio::test]
    async fn test_auto_config_generation() {
        let primary = NetworkInterface {
            name: "lo0".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            is_active: true,
            interface_type: NetworkInterfaceType::Loopback,
        };
        let mock_node = StorageNodeInfo {
            endpoint: "http://127.0.0.1:8080".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
            is_reachable: true,
            latency_ms: Some(1),
            supports_mpc: true,
            node_version: Some("test-1.0".to_string()),
            last_check: dt::tick(),
        };

        let detector = NetworkDetector::with_test_overrides(primary.clone(), vec![mock_node]);

        let config = detector.generate_auto_config().await.expect("config");
        assert!(!config.device_fingerprint.is_empty());
        assert!(config.default_threshold >= 1);
        assert!(!config.storage_nodes.is_empty());
        assert_eq!(config.network_mode, "development");
    }

    #[tokio::test]
    async fn test_builder_allows_deterministic_knobs() {
        let primary = NetworkInterface {
            name: "lo0".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            is_active: true,
            interface_type: NetworkInterfaceType::Loopback,
        };
        let node = StorageNodeInfo {
            endpoint: "http://127.0.0.1:8083".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 8083,
            is_reachable: true,
            latency_ms: Some(2),
            supports_mpc: true,
            node_version: Some("test-2.0".to_string()),
            last_check: dt::tick(),
        };

        let detector = NetworkDetectorBuilder::new()
            .with_discovery_timeout_ms(50)
            .with_ip_scan_bounds(10, 12)
            .with_port_scan_range(9000, 9001)
            .include_localhost(false)
            .enable_dns(false)
            .enable_mdns(false)
            .override_primary_interface(primary.clone())
            .override_nodes(vec![node.clone()])
            .build();

        assert_eq!(detector.config.discovery_timeout_ms, 50);
        assert_eq!(detector.config.ip_scan_bounds, Some((10, 12)));
        assert_eq!(detector.config.port_scan_range, (9000, 9001));
        assert!(!detector.config.enable_dns_discovery);
        assert!(!detector.config.enable_mdns_discovery);

        let primary_detected = detector
            .detect_primary_network_interface()
            .await
            .expect("iface");
        assert_eq!(primary_detected.ip_address, primary.ip_address);

        let discovered = detector
            .discover_local_storage_nodes(&primary_detected.ip_address)
            .await;
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].endpoint, node.endpoint);
    }

    #[test]
    fn test_generate_local_ip_range_loopback_only_localhost() {
        let mut cfg_enabled = NetworkDiscoveryConfig::default();
        cfg_enabled.include_localhost = true;
        let detector_enabled = NetworkDetector::new(cfg_enabled);
        let ips_enabled = detector_enabled
            .generate_local_ip_range(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("should generate ip list");
        assert_eq!(ips_enabled, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        let mut cfg_disabled = NetworkDiscoveryConfig::default();
        cfg_disabled.include_localhost = false;
        let detector_disabled = NetworkDetector::new(cfg_disabled);
        let ips_disabled = detector_disabled
            .generate_local_ip_range(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("should generate ip list");
        assert!(ips_disabled.is_empty());
    }

    #[test]
    fn test_generate_local_ip_range_respects_bounds_and_ordering_config() {
        let cfg = NetworkDiscoveryConfig {
            include_localhost: false,
            ip_scan_bounds: Some((50, 60)),
            ..Default::default()
        };
        let detector = NetworkDetector::new(cfg);

        let primary = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ips = detector
            .generate_local_ip_range(&primary)
            .unwrap_or_default();

        assert_eq!(ips.len(), 11);
        assert_eq!(
            ips.first()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
        );
        assert_eq!(
            ips.last()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))
        );
        for w in ips.windows(2) {
            if let [IpAddr::V4(a), IpAddr::V4(b)] = &w {
                assert!(a.octets()[3] < b.octets()[3]);
            }
        }
    }

    #[test]
    fn test_generate_local_ip_range_default_full_scan_ordering() {
        let cfg = NetworkDiscoveryConfig {
            include_localhost: false,
            ..Default::default()
        };
        let detector = NetworkDetector::new(cfg);
        let primary = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let ips = detector
            .generate_local_ip_range(&primary)
            .unwrap_or_default();

        assert_eq!(ips.len(), 253);
        assert_eq!(
            ips.first()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            ips.last()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))
        );
        assert!(!ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
    }

    #[test]
    fn test_android_emulator_special_case_uses_10_0_2_2() {
        let cfg = NetworkDiscoveryConfig {
            include_localhost: false,
            ..Default::default()
        };
        let detector = NetworkDetector::new(cfg);
        let primary = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 16));
        let ips = detector
            .generate_local_ip_range(&primary)
            .unwrap_or_default();

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))]);
    }
}
