//! STRICT multi-node network registry for DSM SDK.
//! - No auto-discovery, no LAN scans, no silent defaults.
//! - Requires DSM_ENV_CONFIG_PATH (TOML) OR DSM_SDK_TEST_MODE=1 for hermetic tests.
//! - Deterministic round-robin across ALL configured nodes.
//! - On failure, callers may quarantine a node (time-based skip) without background tasks.
//!
//! This implementation uses serde for type-safe TOML parsing.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use serde::{Deserialize, Serialize};
use toml;

use crate::types::error::DsmError;
use crate::util::deterministic_time::tick;

/// Global config path set by JNI at initialization
/// This is the authoritative source for DSM_ENV_CONFIG_PATH
static ENV_CONFIG_PATH: OnceLock<String> = OnceLock::new();

/// Set the global config path (called once from JNI initDsmSdk)
pub fn set_env_config_path(path: String) {
    let _ = ENV_CONFIG_PATH.set(path);
}

/// Get the global config path if initialized (diagnostics only).
pub fn get_env_config_path() -> Option<&'static str> {
    ENV_CONFIG_PATH.get().map(|s| s.as_str())
}

/// Environment config with serde support.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvConfig {
    pub protocol: String, // e.g., "http"
    pub lan_ip: String,   // e.g., "127.0.0.1" (informational)
    #[serde(default)]
    pub ports: Vec<u16>, // optional, informational
    pub nodes: Vec<NodeConfig>, // REQUIRED
    // Optional MPC-only genesis endpoint (strictly for genesis flow)
    pub mpc_genesis_url: Option<String>,
    pub mpc_api_key: Option<String>,
    /// Set `allow_localhost = true` in the TOML to permit 127.0.0.1 endpoints
    /// on Android release builds when using `adb reverse` for local dev.
    #[serde(default)]
    pub allow_localhost: bool,
    /// Bitcoin network for dBTC key derivation and address format.
    /// Valid: "mainnet", "testnet", "signet". Defaults to "signet".
    #[serde(default)]
    pub bitcoin_network: Option<String>,

    // ── dBTC economic parameter overrides (all optional) ──
    // These override compile-time constants in bitcoin_tap_sdk.rs.
    // Operators can tune these per-deployment without recompilation
    // (e.g. raise sweep fee estimate during high-fee environments).
    // Omit to use compile-time defaults.
    /// Override for DBTC_DUST_FLOOR_SATS (default: 546)
    #[serde(default)]
    pub dbtc_dust_floor_sats: Option<u64>,
    /// Override for DBTC_ESTIMATED_SWEEP_FEE_SATS (default: 2000)
    #[serde(default)]
    pub dbtc_estimated_sweep_fee_sats: Option<u64>,
    /// Override for DBTC_MIN_CONFIRMATIONS (default: 100)
    #[serde(default)]
    pub dbtc_min_confirmations: Option<u64>,
    /// Override for DBTC_MAX_SUCCESSOR_DEPTH (default: 5)
    #[serde(default)]
    pub dbtc_max_successor_depth: Option<u32>,
    /// Override for DBTC_MIN_VAULT_BALANCE_SATS (default: 100000)
    #[serde(default)]
    pub dbtc_min_vault_balance_sats: Option<u64>,
    // dbtc_iterations_per_block_estimate and dbtc_timeout_safety_margin removed:
    // Dual-hashlock HTLC (main.tex Definition 7.1) eliminates DSM-Bitcoin clock coupling.
    // Refunds are state-budgeted on the DSM side and claimed on Bitcoin via the refund hashlock.
    /// Override for the withdrawal fee rate in sat/vbyte (default: 10).
    #[serde(default)]
    pub dbtc_fee_rate_sat_vb: Option<u64>,

    // ── mempool.space API (for signet/testnet — no local node needed) ──
    /// Base URL for mempool.space API. Defaults to "https://mempool.space".
    #[serde(default)]
    pub mempool_api_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    pub name: String,
    pub endpoint: String, // e.g., "http://10.0.0.5:8080"
}

pub struct NetworkConfigLoader;

impl NetworkConfigLoader {
    /// Load environment config strictly from TOML or TEST_MODE.
    pub fn load_env_config() -> Result<EnvConfig, DsmError> {
        // Try global static first (set by JNI), then fall back to env var
        let explicit_path = if let Some(p) = ENV_CONFIG_PATH.get() {
            log::info!("NetworkConfigLoader: using global ENV_CONFIG_PATH={}", p);
            Some(p.clone())
        } else if let Ok(env_path) = std::env::var("DSM_ENV_CONFIG_PATH") {
            log::info!(
                "NetworkConfigLoader: using DSM_ENV_CONFIG_PATH={}",
                env_path
            );
            Some(env_path)
        } else {
            None
        };

        if explicit_path.is_none() && std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            return Ok(Self::test_env_config());
        }

        let path = explicit_path.ok_or_else(|| {
            DsmError::storage(
                "STRICT: DSM_ENV_CONFIG_PATH not set and global config path not initialized; no network config available.",
                Option::<std::io::Error>::None,
            )
        })?;

        let p = PathBuf::from(&path);
        if !p.exists() {
            return Err(DsmError::storage(
                format!(
                    "STRICT: DSM_ENV_CONFIG_PATH does not exist: {}",
                    p.display()
                ),
                Option::<std::io::Error>::None,
            ));
        };

        log::info!(
            "NetworkConfigLoader: reading env config TOML from {}",
            p.display()
        );
        let toml_str = fs::read_to_string(&p).map_err(|e| {
            DsmError::storage(
                format!("STRICT: failed to read env config at {}", p.display()),
                Some(e),
            )
        })?;

        parse_env_config_toml(&toml_str)
    }

    fn test_env_config() -> EnvConfig {
        EnvConfig {
            protocol: "http".into(),
            lan_ip: "127.0.0.1".into(),
            ports: vec![8080, 8081, 8082],
            nodes: vec![
                NodeConfig {
                    name: "test-1".into(),
                    endpoint: "http://127.0.0.1:8080".into(),
                },
                NodeConfig {
                    name: "test-2".into(),
                    endpoint: "http://127.0.0.1:8081".into(),
                },
                NodeConfig {
                    name: "test-3".into(),
                    endpoint: "http://127.0.0.1:8082".into(),
                },
            ],
            mpc_genesis_url: None,
            mpc_api_key: None,
            allow_localhost: true,
            bitcoin_network: None,
            dbtc_dust_floor_sats: None,
            dbtc_estimated_sweep_fee_sats: None,
            dbtc_min_confirmations: None,
            dbtc_max_successor_depth: None,
            dbtc_min_vault_balance_sats: None,
            dbtc_fee_rate_sat_vb: None,
            mempool_api_url: None,
        }
    }
}

/// Parse TOML using serde for type safety and automatic deserialization.
fn parse_env_config_toml(toml_str: &str) -> Result<EnvConfig, DsmError> {
    let mut config: EnvConfig = toml::from_str(toml_str).map_err(|e| {
        DsmError::serialization_error(
            "STRICT: failed to parse TOML env config",
            "network_env_config",
            Option::<&str>::None,
            Some(e),
        )
    })?;

    // Validate that nodes are present and not empty
    if config.nodes.is_empty() {
        return Err(DsmError::storage(
            "STRICT: env config has zero nodes; at least one node is required.",
            Option::<std::io::Error>::None,
        ));
    }

    // Set defaults for optional fields
    if config.protocol.is_empty() {
        config.protocol = "http".to_string();
    }
    if config.lan_ip.is_empty() {
        config.lan_ip = "127.0.0.1".to_string();
    }

    // Validate and normalize nodes
    config.nodes = validate_and_normalize_nodes(config.nodes, config.allow_localhost)?;

    log::info!(
        "NetworkConfigLoader: parsed {} nodes from TOML",
        config.nodes.len()
    );

    Ok(config)
}

/// Validate node endpoints and apply platform-specific hardening.
/// - On Android, disallow localhost/127.0.0.1 unless explicitly allowed via DSM_ALLOW_LOCALHOST=1
///   because each device would talk to its own loopback and never see each other's messages.
fn validate_and_normalize_nodes(
    nodes: Vec<NodeConfig>,
    toml_allow_localhost: bool,
) -> Result<Vec<NodeConfig>, DsmError> {
    if nodes.is_empty() {
        return Err(DsmError::storage(
            "STRICT: env config has zero nodes; at least one node is required.",
            Option::<std::io::Error>::None,
        ));
    }

    // Fast path: if not android, accept as-is.
    #[cfg(not(target_os = "android"))]
    {
        let _ = toml_allow_localhost;
        Ok(nodes)
    }

    // Android hardening: ban localhost unless an explicit opt-in is set.
    #[cfg(target_os = "android")]
    {
        let allow_localhost_env = std::env::var("DSM_ALLOW_LOCALHOST").ok();
        // Allow localhost endpoints in debug/dev builds as a convenience for adb reverse / local testing.
        // Production builds still require explicit opt-in via DSM_ALLOW_LOCALHOST=1.
        let allow_localhost = allow_localhost_env.as_deref() == Some("1")
            || cfg!(debug_assertions)
            || toml_allow_localhost;
        log::info!(
            "NetworkConfigLoader: Android localhost policy — DSM_ALLOW_LOCALHOST={:?} => allow_localhost={} (debug_override={})",
            allow_localhost_env,
            allow_localhost,
            cfg!(debug_assertions)
        );
        if allow_localhost {
            log::info!(
                "NetworkConfigLoader: localhost endpoints permitted; accepting {} node(s)",
                nodes.len()
            );
            return Ok(nodes);
        }

        let mut bad: Vec<String> = Vec::new();
        for n in &nodes {
            // Very small and safe parser: we only need the host component.
            // Avoid pulling full URL parsers to keep deps minimal.
            let lower = n.endpoint.to_ascii_lowercase();
            // Extract host by stripping scheme if present and taking substring before next '/'
            let host_port = if let Some(idx) = lower.find("://") {
                &lower[idx + 3..]
            } else {
                lower.as_str()
            };
            let host = host_port.split('/').next().unwrap_or("");
            let host_only = host
                .split('@')
                .last()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");

            if host_only == "127.0.0.1" || host_only == "localhost" {
                bad.push(n.endpoint.clone());
            }
        }

        if !bad.is_empty() {
            log::warn!(
                "NetworkConfigLoader: rejecting localhost endpoints on Android: {}",
                bad.join(", ")
            );
            return Err(DsmError::storage(
                format!(
                    "STRICT: Localhost endpoints are not allowed on Android device builds. \
Update dsm_env_config.toml to use LAN/IP or domain reachable by all devices. \
Offending endpoints: {}. \
To override for dev with adb reverse, set DSM_ALLOW_LOCALHOST=1 before init.",
                    bad.join(", ")
                ),
                Option::<std::io::Error>::None,
            ));
        }

        log::info!(
            "NetworkConfigLoader: nodes validated under Android policy; {} node(s) accepted",
            nodes.len()
        );
        Ok(nodes)
    }
}

/// Global, multi-node registry (deterministic selection; no background threads).
struct NodeRegistry {
    nodes: std::sync::RwLock<Vec<NodeConfig>>,
    idx: AtomicUsize,
    quarantine_for: u64,                           // ticks
    quarantine_until: Mutex<HashMap<String, u64>>, // endpoint -> until_ticks
}

static REGISTRY: OnceLock<Arc<NodeRegistry>> = OnceLock::new();

impl NodeRegistry {
    fn new(nodes: Vec<NodeConfig>, seed: Option<String>) -> Self {
        let n_len = nodes.len();
        let start_idx = match (seed, n_len) {
            (Some(s), n) if n > 0 => {
                let hash = dsm::crypto::blake3::domain_hash("DSM/network-hash", s.as_bytes());
                let mut le8 = [0u8; 8];
                le8.copy_from_slice(&hash.as_bytes()[0..8]);
                (u64::from_le_bytes(le8) as usize) % n
            }
            _ => 0,
        };

        // Optional quarantine override via env (ticks)
        let quarantine_ticks = std::env::var("DSM_NODE_QUARANTINE_TICKS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30); // default: 30 logical ticks

        Self {
            nodes: std::sync::RwLock::new(nodes),
            idx: AtomicUsize::new(start_idx),
            quarantine_for: quarantine_ticks,
            quarantine_until: Mutex::new(HashMap::new()),
        }
    }

    fn next_endpoint(&self) -> Result<String, DsmError> {
        let nodes = self.nodes.read().unwrap_or_else(|p| p.into_inner());
        let n = nodes.len();
        if n == 0 {
            return Err(DsmError::storage(
                "STRICT: no nodes in registry.",
                None::<std::io::Error>,
            ));
        }

        let start = self.idx.fetch_add(1, Ordering::Relaxed) % n;
        let now_ticks = tick();

        for step in 0..n {
            let i = (start + step) % n;
            let endpoint = &nodes[i].endpoint;

            let mut q = self
                .quarantine_until
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(&until_ticks) = q.get(endpoint) {
                if until_ticks > now_ticks {
                    continue;
                } else {
                    // Penalty expired; clear it.
                    q.remove(endpoint);
                }
            }

            return Ok(endpoint.clone());
        }

        Err(DsmError::storage(
            "STRICT: all configured nodes are temporarily quarantined; backoff and retry.",
            None::<std::io::Error>,
        ))
    }

    fn list_endpoints(&self) -> Vec<String> {
        let nodes = self.nodes.read().unwrap_or_else(|p| p.into_inner());
        nodes.iter().map(|n| n.endpoint.clone()).collect()
    }

    fn add_endpoint(&self, endpoint: &str) -> Result<(), DsmError> {
        let mut nodes = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        if nodes.iter().any(|n| n.endpoint == endpoint) {
            return Ok(()); // already present, idempotent
        }
        let name = format!("node-{}", nodes.len() + 1);
        nodes.push(NodeConfig {
            name,
            endpoint: endpoint.to_string(),
        });
        log::info!(
            "NodeRegistry: added endpoint {}, total={}",
            endpoint,
            nodes.len()
        );
        Ok(())
    }

    fn remove_endpoint(&self, endpoint: &str) -> Result<(), DsmError> {
        let mut nodes = self.nodes.write().unwrap_or_else(|p| p.into_inner());
        let before = nodes.len();
        nodes.retain(|n| n.endpoint != endpoint);
        if nodes.len() == before {
            return Err(DsmError::storage(
                format!("Endpoint not found in registry: {endpoint}"),
                None::<std::io::Error>,
            ));
        }
        // Clear any quarantine for the removed endpoint
        let mut q = self
            .quarantine_until
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        q.remove(endpoint);
        log::info!(
            "NodeRegistry: removed endpoint {}, total={}",
            endpoint,
            nodes.len()
        );
        Ok(())
    }

    fn quarantine_endpoint(&self, endpoint: &str) {
        let now_ticks = tick();
        let until_ticks = now_ticks.saturating_add(self.quarantine_for);
        let mut q = self
            .quarantine_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        q.insert(endpoint.to_string(), until_ticks);
    }

    fn clear_quarantine(&self, endpoint: &str) {
        let mut q = self
            .quarantine_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        q.remove(endpoint);
    }
}

/// Install global registry from EnvConfig. Must be called exactly once at SDK init.
pub fn install_registry(cfg: EnvConfig) -> Result<(), DsmError> {
    let seed = std::env::var("DSM_NODE_SEED").ok();
    if cfg.nodes.is_empty() {
        return Err(DsmError::storage(
            "STRICT: cannot install registry with zero nodes.",
            None::<std::io::Error>,
        ));
    }
    let reg = Arc::new(NodeRegistry::new(cfg.nodes.clone(), seed));
    match REGISTRY.set(reg) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Treat repeated installation as idempotent: keep existing registry.
            log::info!("Node registry already installed; continuing (idempotent).");
            Ok(())
        }
    }
}

/// Get the next endpoint using deterministic round-robin across all nodes.
pub fn next_storage_endpoint() -> Result<String, DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })?
        .next_endpoint()
}

/// List all configured endpoints (for diagnostics/telemetry).
pub fn list_storage_endpoints() -> Result<Vec<String>, DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })
        .map(|r| r.list_endpoints())
}

/// Report a failed attempt; endpoint will be quarantined temporarily.
pub fn report_storage_failure(endpoint: &str) -> Result<(), DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })
        .map(|r| r.quarantine_endpoint(endpoint))
}

/// Report a successful attempt; clears quarantine if any.
pub fn report_storage_success(endpoint: &str) -> Result<(), DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })
        .map(|r| r.clear_quarantine(endpoint))
}

/// Add a storage endpoint to the live registry.
pub fn add_storage_endpoint(endpoint: &str) -> Result<(), DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })?
        .add_endpoint(endpoint)
}

/// Remove a storage endpoint from the live registry (Fisher-Yates placement recalculates automatically).
pub fn remove_storage_endpoint(endpoint: &str) -> Result<(), DsmError> {
    REGISTRY
        .get()
        .ok_or_else(|| {
            DsmError::storage(
                "STRICT: node registry not installed.",
                None::<std::io::Error>,
            )
        })?
        .remove_endpoint(endpoint)
}

/// Auto-assign the next storage node via keyed Fisher-Yates.
///
/// Protocol rule: the device does not choose which storage node to add.
/// The SDK selects deterministically from the known pool (all nodes in
/// dsm_env_config.toml) minus the currently active set, using a
/// BLAKE3-keyed unbiased sampling seeded by the device's own ID bytes.
///
/// Domain: `BLAKE3("DSM/place\0" || device_id_bytes)` → 32-byte seed.
/// PRF per draw: `BLAKE3("DSM/perm\0" || seed || ctr_le64)`.
/// Rejection-sampled to be unbiased for any pool size.
///
/// Returns the URL of the newly added node.
pub fn auto_assign_storage_node(device_id_bytes: &[u8]) -> Result<String, DsmError> {
    // Full pool from TOML (all known nodes).
    let all_nodes = NetworkConfigLoader::load_env_config()?.nodes;

    // Currently active endpoints in the live registry.
    let active = list_storage_endpoints()?;
    let active_set: std::collections::HashSet<&str> = active.iter().map(|s| s.as_str()).collect();

    // Candidates: pool nodes not already active.
    let candidates: Vec<String> = all_nodes
        .into_iter()
        .filter(|n| !active_set.contains(n.endpoint.as_str()))
        .map(|n| n.endpoint)
        .collect();

    if candidates.is_empty() {
        return Err(DsmError::storage(
            "auto-assign: no new storage nodes available (all configured nodes already active)",
            None::<std::io::Error>,
        ));
    }

    // Seed: BLAKE3("DSM/place\0" || device_id_bytes).
    let seed = {
        let mut input = Vec::with_capacity(10 + device_id_bytes.len());
        input.extend_from_slice(b"DSM/place\0");
        input.extend_from_slice(device_id_bytes);
        *dsm::crypto::blake3::domain_hash("DSM/network-hash", &input).as_bytes()
    };

    // Unbiased sample one index from [0, candidates.len()).
    let selected_idx = fisher_yates_sample_one(seed, candidates.len() as u64) as usize;
    let selected = candidates[selected_idx].clone();

    // Add to live registry.
    add_storage_endpoint(&selected)?;

    log::info!(
        "auto_assign_storage_node: selected {} (pool={}, active={})",
        selected,
        candidates.len(),
        active.len()
    );

    Ok(selected)
}

/// Return one unbiased index in [0, range) using BLAKE3 PRF rejection sampling.
///
/// PRF block: `BLAKE3("DSM/perm\0" || seed || ctr_le64)` → first 8 bytes as u64.
/// Rejection threshold eliminates modular bias.
fn fisher_yates_sample_one(seed: [u8; 32], range: u64) -> u64 {
    // Threshold = lowest multiple of `range` that fits in u64.
    // Reject values below `threshold` to get an unbiased sample.
    // threshold = (2^64 % range) — we compute it as (u64::MAX - range + 1) % range.
    let threshold = u64::MAX.wrapping_sub(range).wrapping_add(1) % range;
    let mut ctr: u64 = 0;
    loop {
        let v = fisher_yates_prf_u64(seed, ctr);
        ctr += 1;
        if v >= threshold {
            return v % range;
        }
    }
}

/// Single PRF draw: `BLAKE3("DSM/perm\0" || seed || ctr_le64)` → u64.
fn fisher_yates_prf_u64(seed: [u8; 32], ctr: u64) -> u64 {
    let domain: &[u8] = b"DSM/perm\0";
    let mut buf = Vec::with_capacity(domain.len() + 32 + 8);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&seed);
    buf.extend_from_slice(&ctr.to_le_bytes());
    let h = dsm::crypto::blake3::domain_hash("DSM/network-hash", &buf);
    let bytes = h.as_bytes();
    let mut le8 = [0u8; 8];
    le8.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(le8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> String {
        r#"
protocol = "http"
lan_ip = "10.0.0.1"
ports = [8080, 8081]

[[nodes]]
name = "node-a"
endpoint = "http://10.0.0.1:8080"

[[nodes]]
name = "node-b"
endpoint = "http://10.0.0.2:8081"
"#
        .to_string()
    }

    #[test]
    fn parse_env_config_toml_valid() {
        let cfg = parse_env_config_toml(&sample_toml()).unwrap();
        assert_eq!(cfg.protocol, "http");
        assert_eq!(cfg.lan_ip, "10.0.0.1");
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.nodes[0].name, "node-a");
        assert_eq!(cfg.nodes[1].endpoint, "http://10.0.0.2:8081");
    }

    #[test]
    fn parse_env_config_toml_defaults_protocol_and_ip() {
        let toml = r#"
protocol = ""
lan_ip = ""

[[nodes]]
name = "n1"
endpoint = "http://1.2.3.4:80"
"#;
        let cfg = parse_env_config_toml(toml).unwrap();
        assert_eq!(cfg.protocol, "http");
        assert_eq!(cfg.lan_ip, "127.0.0.1");
    }

    #[test]
    fn parse_env_config_toml_rejects_empty_nodes() {
        let toml = r#"
protocol = "http"
lan_ip = "127.0.0.1"
nodes = []
"#;
        assert!(parse_env_config_toml(toml).is_err());
    }

    #[test]
    fn parse_env_config_toml_rejects_invalid_toml() {
        assert!(parse_env_config_toml("not valid toml {{{").is_err());
    }

    #[test]
    fn parse_env_config_toml_optional_fields() {
        let toml = r#"
protocol = "https"
lan_ip = "10.0.0.5"
mpc_genesis_url = "https://mpc.example.com"
mpc_api_key = "secret"
allow_localhost = true
bitcoin_network = "signet"
dbtc_dust_floor_sats = 1000

[[nodes]]
name = "n1"
endpoint = "http://10.0.0.5:9090"
"#;
        let cfg = parse_env_config_toml(toml).unwrap();
        assert_eq!(cfg.mpc_genesis_url.as_deref(), Some("https://mpc.example.com"));
        assert_eq!(cfg.mpc_api_key.as_deref(), Some("secret"));
        assert!(cfg.allow_localhost);
        assert_eq!(cfg.bitcoin_network.as_deref(), Some("signet"));
        assert_eq!(cfg.dbtc_dust_floor_sats, Some(1000));
    }

    #[test]
    fn node_registry_round_robin() {
        let nodes = vec![
            NodeConfig { name: "a".into(), endpoint: "http://a".into() },
            NodeConfig { name: "b".into(), endpoint: "http://b".into() },
            NodeConfig { name: "c".into(), endpoint: "http://c".into() },
        ];
        let reg = NodeRegistry::new(nodes, None);
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(reg.next_endpoint().unwrap());
        }
        // Should cycle through all 3 endpoints twice
        assert_eq!(seen[0], seen[3]);
        assert_eq!(seen[1], seen[4]);
        assert_eq!(seen[2], seen[5]);
    }

    #[test]
    fn node_registry_add_and_remove() {
        let nodes = vec![
            NodeConfig { name: "a".into(), endpoint: "http://a".into() },
        ];
        let reg = NodeRegistry::new(nodes, None);

        assert_eq!(reg.list_endpoints(), vec!["http://a"]);

        reg.add_endpoint("http://b").unwrap();
        assert_eq!(reg.list_endpoints().len(), 2);

        // Adding duplicate is idempotent
        reg.add_endpoint("http://b").unwrap();
        assert_eq!(reg.list_endpoints().len(), 2);

        reg.remove_endpoint("http://a").unwrap();
        assert_eq!(reg.list_endpoints(), vec!["http://b"]);

        // Removing non-existent returns error
        assert!(reg.remove_endpoint("http://z").is_err());
    }

    #[test]
    fn node_registry_quarantine_skips_node() {
        let nodes = vec![
            NodeConfig { name: "a".into(), endpoint: "http://a".into() },
            NodeConfig { name: "b".into(), endpoint: "http://b".into() },
        ];
        let reg = NodeRegistry::new(nodes, None);

        // Quarantine the first node picked by round-robin
        let first = reg.next_endpoint().unwrap();
        reg.quarantine_endpoint(&first);

        // Subsequent calls should skip the quarantined node
        let next = reg.next_endpoint().unwrap();
        assert_ne!(next, first);
    }

    #[test]
    fn node_registry_clear_quarantine() {
        let nodes = vec![
            NodeConfig { name: "a".into(), endpoint: "http://a".into() },
        ];
        let reg = NodeRegistry::new(nodes, None);

        reg.quarantine_endpoint("http://a");
        assert!(reg.next_endpoint().is_err()); // all quarantined

        reg.clear_quarantine("http://a");
        assert_eq!(reg.next_endpoint().unwrap(), "http://a");
    }

    #[test]
    fn node_registry_empty_returns_error() {
        let reg = NodeRegistry::new(vec![], None);
        assert!(reg.next_endpoint().is_err());
    }

    #[test]
    fn fisher_yates_prf_deterministic() {
        let seed = [42u8; 32];
        let a = fisher_yates_prf_u64(seed, 0);
        let b = fisher_yates_prf_u64(seed, 0);
        assert_eq!(a, b);

        // Different counter yields different value (overwhelmingly likely)
        let c = fisher_yates_prf_u64(seed, 1);
        assert_ne!(a, c);
    }

    #[test]
    fn fisher_yates_sample_one_in_range() {
        let seed = [7u8; 32];
        for range in [1u64, 2, 3, 5, 10, 100, 1000] {
            let idx = fisher_yates_sample_one(seed, range);
            assert!(idx < range, "sample {idx} out of range {range}");
        }
    }

    #[test]
    fn fisher_yates_sample_one_deterministic() {
        let seed = [99u8; 32];
        let a = fisher_yates_sample_one(seed, 50);
        let b = fisher_yates_sample_one(seed, 50);
        assert_eq!(a, b);
    }

    #[test]
    fn validate_and_normalize_nodes_non_android_accepts_all() {
        let nodes = vec![
            NodeConfig { name: "local".into(), endpoint: "http://127.0.0.1:8080".into() },
            NodeConfig { name: "remote".into(), endpoint: "http://10.0.0.5:9090".into() },
        ];
        let result = validate_and_normalize_nodes(nodes.clone(), false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn validate_and_normalize_nodes_rejects_empty() {
        assert!(validate_and_normalize_nodes(vec![], false).is_err());
    }

    #[test]
    fn env_config_serialization_roundtrip() {
        let cfg = EnvConfig {
            protocol: "http".into(),
            lan_ip: "10.0.0.1".into(),
            ports: vec![8080],
            nodes: vec![NodeConfig {
                name: "n1".into(),
                endpoint: "http://10.0.0.1:8080".into(),
            }],
            mpc_genesis_url: None,
            mpc_api_key: None,
            allow_localhost: false,
            bitcoin_network: Some("signet".into()),
            dbtc_dust_floor_sats: None,
            dbtc_estimated_sweep_fee_sats: None,
            dbtc_min_confirmations: None,
            dbtc_max_successor_depth: None,
            dbtc_min_vault_balance_sats: None,
            dbtc_fee_rate_sat_vb: None,
            mempool_api_url: None,
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let reparsed = parse_env_config_toml(&toml_str).unwrap();
        assert_eq!(reparsed.protocol, "http");
        assert_eq!(reparsed.nodes.len(), 1);
        assert_eq!(reparsed.bitcoin_network.as_deref(), Some("signet"));
    }
}
