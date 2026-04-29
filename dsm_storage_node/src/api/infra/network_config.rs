//! # Network Auto-Detection
//!
//! Clockless, Serde-free network interface detection for the storage node.
//! Discovers the primary listening address and advertises it to peers
//! during gossip and replication setup.

// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use blake3;
use log::{debug, info};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct AutoNetworkConfig {
    pub node_id: String,
    pub listen_address: IpAddr,
    pub port: u16,
    pub public_endpoint: String,
    pub peers: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum NetworkType {
    Local,
    Wifi,
    Corporate,
    Public,
}

pub struct NetworkDetector;

impl NetworkDetector {
    /// Automatically detect the best network configuration for this storage node
    pub fn detect_network_config(node_index: usize) -> Result<AutoNetworkConfig> {
        Self::detect_network_config_with_tls(node_index, false)
    }

    /// Autodetect with optional TLS scheme for the public endpoint.
    pub fn detect_network_config_with_tls(
        node_index: usize,
        tls_enabled: bool,
    ) -> Result<AutoNetworkConfig> {
        let primary_ip = Self::detect_primary_ip()?;
        let network_type = Self::classify_network(&primary_ip);
        let base_port = Self::get_base_port();
        let preferred = base_port + node_index as u16;
        let port = Self::find_available_port(preferred)?;

        let node_id = format!(
            "node-{}-{}",
            node_index + 1,
            Self::generate_node_suffix(&primary_ip)
        );
        let scheme = if tls_enabled { "https" } else { "http" };
        let public_endpoint = format!("{scheme}://{primary_ip}:{port}");

        // Discover peers on same host/segment: deterministic list by index
        let peers = Self::discover_peer_nodes(&primary_ip, base_port, node_index, 5)?;

        info!(
            "net:auto {} -> {} ({})",
            node_id,
            public_endpoint,
            network_type_str(&network_type)
        );

        Ok(AutoNetworkConfig {
            node_id,
            listen_address: primary_ip,
            port,
            public_endpoint,
            peers,
        })
    }

    /// Best-effort primary IP detection (route → interfaces → connect).
    fn detect_primary_ip() -> Result<IpAddr> {
        if let Ok(ip) = Self::detect_via_route() {
            debug!("primary ip via route: {}", ip);
            return Ok(ip);
        }
        if let Ok(ip) = Self::detect_via_interfaces() {
            debug!("primary ip via interfaces: {}", ip);
            return Ok(ip);
        }
        if let Ok(ip) = Self::detect_via_connect() {
            debug!("primary ip via connect: {}", ip);
            return Ok(ip);
        }
        Err(anyhow::anyhow!("Could not detect primary IP address"))
    }

    /// macOS `route -n get 8.8.8.8` → interface → `ifconfig <iface>`
    /// Linux  `ip route get 8.8.8.8 | ...`
    fn detect_via_route() -> Result<IpAddr> {
        // macOS path
        if let Ok(output) = Command::new("route")
            .arg("-n")
            .arg("get")
            .arg("8.8.8.8")
            .output()
        {
            if output.status.success() {
                let route_info = String::from_utf8_lossy(&output.stdout);
                for line in route_info.lines() {
                    if line.trim().starts_with("interface:") {
                        if let Some(interface) = line.split(':').nth(1) {
                            let interface = interface.trim();
                            if let Ok(ip) = Self::get_interface_ip(interface) {
                                return Ok(ip);
                            }
                        }
                    }
                }
            }
        }

        // Linux path
        let output = Command::new("sh")
            .arg("-c")
            .arg("ip route get 8.8.8.8 2>/dev/null | grep -o 'src [0-9.]*' | cut -d' ' -f2 | head -1")
            .output()?;

        if output.status.success() {
            let ip_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip_str.is_empty() {
                return Ok(ip_str.parse()?);
            }
        }

        Err(anyhow::anyhow!("Route detection failed"))
    }

    /// Parse IP from `ifconfig <iface>` on BSD/macOS.
    fn get_interface_ip(interface: &str) -> Result<IpAddr> {
        if let Ok(output) = Command::new("ifconfig").arg(interface).output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout);
                for line in s.lines() {
                    if line.contains("inet ") && !line.contains("127.0.0.1") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(i) = parts.iter().position(|&x| x == "inet") {
                            if let Some(ip_str) = parts.get(i + 1) {
                                let ip: IpAddr = (*ip_str).parse()?;
                                if !ip.is_loopback() {
                                    return Ok(ip);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "Could not get IP for interface {interface}"
        ))
    }

    /// Interface-based detection using a UDP connect trick.
    fn detect_via_interfaces() -> Result<IpAddr> {
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        Ok(socket.local_addr()?.ip())
    }

    /// Fallback scan of common private ranges to find a bindable local IP.
    fn detect_via_connect() -> Result<IpAddr> {
        // WiFi ranges 192.168.x.1 gateways
        for i in 1..255 {
            let gw = Ipv4Addr::new(192, 168, i, 1);
            if Self::can_reach_gateway(gw.into()) {
                return Self::find_local_ip_in_subnet(192, 168, i);
            }
        }
        // Corporate 10.x.0.1 gateways
        for i in 0..255 {
            let gw = Ipv4Addr::new(10, i, 0, 1);
            if Self::can_reach_gateway(gw.into()) {
                return Self::find_local_ip_in_subnet(10, i, 0);
            }
        }
        Err(anyhow::anyhow!("No suitable network found"))
    }

    fn can_reach_gateway(gateway: IpAddr) -> bool {
        use std::net::TcpStream;
        use std::time::Duration;
        if let Ok(addr) = format!("{gateway}:80").parse::<SocketAddr>() {
            TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
        } else {
            false
        }
    }

    fn find_local_ip_in_subnet(a: u8, b: u8, c: u8) -> Result<IpAddr> {
        use std::net::UdpSocket;
        for i in 2..254 {
            let ip = Ipv4Addr::new(a, b, c, i);
            let addr = SocketAddr::new(ip.into(), 0);
            if let Ok(sock) = UdpSocket::bind(addr) {
                return Ok(sock.local_addr()?.ip());
            }
        }
        Err(anyhow::anyhow!(
            "Could not find local IP in subnet {a}.{b}.{c}.x"
        ))
    }

    fn classify_network(ip: &IpAddr) -> NetworkType {
        match ip {
            IpAddr::V4(v4) => match v4.octets() {
                [192, 168, _, _] => NetworkType::Wifi,
                [10, _, _, _] => NetworkType::Corporate,
                [172, b, _, _] if (16..=31).contains(&b) => NetworkType::Corporate,
                [127, _, _, _] => NetworkType::Local,
                _ => NetworkType::Public,
            },
            IpAddr::V6(_) => NetworkType::Public,
        }
    }

    fn get_base_port() -> u16 {
        if let Ok(port_str) = std::env::var("DSM_BASE_PORT") {
            if let Ok(port) = port_str.parse::<u16>() {
                return port;
            }
        }
        8080
    }

    fn find_available_port(preferred_port: u16) -> Result<u16> {
        for port in preferred_port..preferred_port + 100 {
            if Self::is_port_available(port) {
                return Ok(port);
            }
        }
        Err(anyhow::anyhow!(
            "No available ports in [{preferred_port}, +100)"
        ))
    }

    pub fn is_port_available(port: u16) -> bool {
        TcpListener::bind(("0.0.0.0", port)).is_ok()
    }

    /// Deterministic node suffix from IP (no wall clocks).
    fn generate_node_suffix(ip: &IpAddr) -> String {
        let h = blake3::hash(ip.to_string().as_bytes());
        let b = h.as_bytes();
        format!("{:02x}{:02x}{:02x}", b[0], b[1], b[2])
    }

    /// Deterministic peer list for local dev nodes (same host).
    fn discover_peer_nodes(
        local_ip: &IpAddr,
        base_port: u16,
        current_index: usize,
        total_nodes: usize,
    ) -> Result<Vec<String>> {
        let mut peers = Vec::with_capacity(total_nodes.saturating_sub(1));
        for i in 0..total_nodes {
            if i != current_index {
                let p = base_port + i as u16;
                peers.push(format!("http://{local_ip}:{p}"));
            }
        }
        info!("net:peers {} discovered", peers.len());
        debug!("net:peer endpoints = {:?}", peers);
        Ok(peers)
    }

    /// Optional validation helper (bind test).
    #[allow(dead_code)]
    pub fn validate_config(cfg: &AutoNetworkConfig) -> Result<()> {
        if !Self::is_port_available(cfg.port) {
            return Err(anyhow::anyhow!("Port {} is not available", cfg.port));
        }
        let addr = SocketAddr::new(cfg.listen_address, cfg.port);
        let _ = TcpListener::bind(addr)
            .map_err(|e| anyhow::anyhow!("Cannot bind to {}: {}", addr, e))?;
        info!("net:config validated");
        Ok(())
    }

    /// Build N-node config set on current host (best-effort).
    #[allow(dead_code)]
    pub fn create_dev_node_configs(num_nodes: usize) -> Result<Vec<AutoNetworkConfig>> {
        let mut cfgs = Vec::with_capacity(num_nodes);
        for i in 0..num_nodes {
            let c = Self::detect_network_config(i)?;
            let _ = Self::validate_config(&c);
            cfgs.push(c);
        }
        // Normalize peers across the set
        let mut all: Vec<String> = cfgs.iter().map(|c| c.public_endpoint.clone()).collect();
        all.sort();
        all.dedup();
        for c in &mut cfgs {
            c.peers = all
                .iter()
                .filter(|ep| *ep != &c.public_endpoint)
                .cloned()
                .collect();
        }
        Ok(cfgs)
    }
}

fn network_type_str(t: &NetworkType) -> &'static str {
    match t {
        NetworkType::Local => "Local",
        NetworkType::Wifi => "WiFi",
        NetworkType::Corporate => "Corporate",
        NetworkType::Public => "Public",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify() {
        let wifi: IpAddr = "192.168.1.10"
            .parse()
            .unwrap_or_else(|e| panic!("parse wifi ip failed: {e}"));
        let corp: IpAddr = "10.2.3.4"
            .parse()
            .unwrap_or_else(|e| panic!("parse corp ip failed: {e}"));
        let local: IpAddr = "127.0.0.1"
            .parse()
            .unwrap_or_else(|e| panic!("parse local ip failed: {e}"));
        assert!(matches!(
            NetworkDetector::classify_network(&wifi),
            NetworkType::Wifi
        ));
        assert!(matches!(
            NetworkDetector::classify_network(&corp),
            NetworkType::Corporate
        ));
        assert!(matches!(
            NetworkDetector::classify_network(&local),
            NetworkType::Local
        ));
    }

    #[test]
    fn port_zero_is_bindable() {
        assert!(NetworkDetector::is_port_available(0));
    }
}
