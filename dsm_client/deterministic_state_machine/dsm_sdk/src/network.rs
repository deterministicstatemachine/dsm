// SPDX-License-Identifier: MIT OR Apache-2.0

//! STRICT multi-node network registry for DSM SDK.
//! - No auto-discovery, no LAN scans, no silent defaults.
//! - Requires the env config TOML: the path set at init, else DSM_ENV_CONFIG_PATH.
//!
//! This implementation uses serde for type-safe TOML parsing.

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use serde::{Deserialize, Serialize};
use toml;

use crate::types::error::DsmError;

/// Global config path set by JNI at initialization
/// This is the authoritative source for DSM_ENV_CONFIG_PATH
static ENV_CONFIG_PATH: OnceLock<String> = OnceLock::new();

/// Set the global config path (called once from JNI initDsmSdk)
pub fn set_env_config_path(path: String) {
    if let Err(refused) = ENV_CONFIG_PATH.set(path) {
        log::warn!("env config path is already set; {refused} was not installed");
    }
}

/// Get the global config path if initialized (diagnostics only).
pub fn get_env_config_path() -> Option<&'static str> {
    ENV_CONFIG_PATH.get().map(|s| s.as_str())
}

/// The env config every reader loads: the path set at init, else
/// `DSM_ENV_CONFIG_PATH`. One resolution, so the node list and the CA
/// certificates always come from the same file.
pub(crate) fn resolved_env_config_path() -> Option<String> {
    ENV_CONFIG_PATH
        .get()
        .cloned()
        .or_else(|| std::env::var("DSM_ENV_CONFIG_PATH").ok())
}

/// Environment config with serde support.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvConfig {
    pub nodes: Vec<NodeConfig>, // REQUIRED
    /// Set `allow_localhost = true` in the TOML to permit 127.0.0.1 endpoints
    /// on Android when using `adb reverse` for local dev. The TOML is the only
    /// switch: no environment variable and no build profile changes it.
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
    /// The member's durable register incarnation, Base32-Crockford over 32
    /// bytes, as that node reports it.
    ///
    /// REQUIRED, deliberately. A storage-set id is a function of
    /// `(member_id, register_incarnation_id)` pairs, so a catalog that cannot
    /// state a member's incarnation cannot resolve any set it belongs to —
    /// and defaulting the field would resolve every set to whatever the
    /// default hashed to. A config written before this field existed fails to
    /// load, which is the reprovision.
    pub register_incarnation: String,
}

pub struct NetworkConfigLoader;

impl NetworkConfigLoader {
    /// Load the environment config from its TOML: the path set at init
    /// (`set_env_config_path`), else `DSM_ENV_CONFIG_PATH`. Nothing else: with
    /// neither there is no network config.
    pub fn load_env_config() -> Result<EnvConfig, DsmError> {
        let path = resolved_env_config_path().ok_or_else(|| {
            DsmError::storage(
                "STRICT: DSM_ENV_CONFIG_PATH not set and global config path not initialized; \
                 no network config available.",
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

    // Validate and normalize nodes
    config.nodes = validate_and_normalize_nodes(config.nodes, config.allow_localhost)?;

    log::info!(
        "NetworkConfigLoader: parsed {} nodes from TOML",
        config.nodes.len()
    );

    Ok(config)
}

/// Validate node endpoints and apply platform-specific hardening.
/// - On Android, disallow localhost/127.0.0.1 unless the TOML sets `allow_localhost = true`,
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

    // Android hardening: ban localhost unless the TOML opts in.
    #[cfg(target_os = "android")]
    {
        if toml_allow_localhost {
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
For dev with adb reverse, set allow_localhost = true in the config TOML.",
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

/// Global registry of the configured storage endpoints: what the env config
/// names, never edited at runtime. Protocol paths use the network's pinned set
/// (`sdk::storage_set`), never this list (storage spec §10: the set is
/// committed).
struct NodeRegistry {
    nodes: Vec<NodeConfig>,
}

static REGISTRY: OnceLock<Arc<NodeRegistry>> = OnceLock::new();

impl NodeRegistry {
    fn new(nodes: Vec<NodeConfig>) -> Self {
        Self { nodes }
    }

    fn list_endpoints(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.endpoint.clone()).collect()
    }
}

/// Install global registry from EnvConfig. Must be called exactly once at SDK init.
pub fn install_registry(cfg: EnvConfig) -> Result<(), DsmError> {
    if cfg.nodes.is_empty() {
        return Err(DsmError::storage(
            "STRICT: cannot install registry with zero nodes.",
            None::<std::io::Error>,
        ));
    }
    let reg = Arc::new(NodeRegistry::new(cfg.nodes.clone()));
    match REGISTRY.set(reg) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Treat repeated installation as idempotent: keep existing registry.
            log::info!("Node registry already installed; continuing (idempotent).");
            Ok(())
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> String {
        r#"
[[nodes]]
name = "node-a"
endpoint = "http://10.0.0.1:8080"
register_incarnation = "BHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE0"

[[nodes]]
name = "node-b"
endpoint = "http://10.0.0.2:8081"
register_incarnation = "BHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE0"
"#
        .to_string()
    }

    #[test]
    fn parse_env_config_toml_valid() {
        let cfg = parse_env_config_toml(&sample_toml()).unwrap();
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.nodes[0].name, "node-a");
        assert_eq!(cfg.nodes[1].endpoint, "http://10.0.0.2:8081");
    }

    #[test]
    fn parse_env_config_toml_rejects_empty_nodes() {
        let toml = r#"
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
allow_localhost = true
bitcoin_network = "signet"
dbtc_dust_floor_sats = 1000

[[nodes]]
name = "n1"
endpoint = "http://10.0.0.5:9090"
register_incarnation = "BHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE5RQ2WBHE0"
"#;
        let cfg = parse_env_config_toml(toml).unwrap();
        assert!(cfg.allow_localhost);
        assert_eq!(cfg.bitcoin_network.as_deref(), Some("signet"));
        assert_eq!(cfg.dbtc_dust_floor_sats, Some(1000));
    }

    #[test]
    fn node_registry_lists_the_configured_endpoints_in_order() {
        let node = |name: &str, endpoint: &str| NodeConfig {
            name: name.into(),
            register_incarnation: crate::util::text_id::encode_base32_crockford(&[0x5C_u8; 32]),
            endpoint: endpoint.into(),
        };
        let reg = NodeRegistry::new(vec![node("a", "http://a"), node("b", "http://b")]);
        assert_eq!(reg.list_endpoints(), vec!["http://a", "http://b"]);
    }

    #[test]
    fn validate_and_normalize_nodes_non_android_accepts_all() {
        let nodes = vec![
            NodeConfig {
                name: "local".into(),
                register_incarnation: crate::util::text_id::encode_base32_crockford(&[0x5C_u8; 32]),
                endpoint: "http://127.0.0.1:8080".into(),
            },
            NodeConfig {
                name: "remote".into(),
                register_incarnation: crate::util::text_id::encode_base32_crockford(&[0x5C_u8; 32]),
                endpoint: "http://10.0.0.5:9090".into(),
            },
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
            nodes: vec![NodeConfig {
                name: "n1".into(),
                register_incarnation: crate::util::text_id::encode_base32_crockford(&[0x5C_u8; 32]),
                endpoint: "http://10.0.0.1:8080".into(),
            }],
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
        assert_eq!(reparsed.nodes.len(), 1);
        assert_eq!(reparsed.bitcoin_network.as_deref(), Some("signet"));
    }
}
