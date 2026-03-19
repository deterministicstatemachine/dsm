//! # Runtime Configuration Module (no serde / no JSON / no base64 / no `hex` crate)
//!
//! Binary-first, protobuf-friendly runtime config for the DSM SDK. This module
//! manages device/runtime settings and persists them in a compact **binary**
//! TLV format (`*.bin`). We avoid JSON, TOML, serde, and base64 entirely.
//!
//! ## TLV on-disk format (little-endian)
//! Header: b"DSMCFG\0" (7 bytes) | u32 version (=1)
//! Repeated TLVs: u16 type | u32 len | `<len bytes>`
//!
//! Types:
//!  1 = device_id (string)
//!  2 = device_fingerprint (bytes)
//!  3 = storage_nodes (u32 count | repeated string)
//! 20 = NetworkConfig
//! 30 = SecurityConfig
//! 40 = StorageConfig
//! 41 = StorageConfig.database_path (string, optional)
//! 50 = DeviceConfig.device_type (string)
//! 60 = metadata (u32 count | repeated (string key | string val))
//! 90 = environment (u8 enum)
//! 91 = version string
//! 92 = created_at_tick (u64)
//! 93 = updated_at_tick (u64)
//!
//! Strings are length-prefixed (u32) UTF-8. Booleans are u8 (0/1).

use dsm::types::error::DsmError;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use dsm::crypto::blake3::dsm_domain_hasher;

static RUNTIME_CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

#[derive(Debug, Clone, PartialEq)]
pub enum EnvironmentType {
    Development,
    Testing,
    Staging,
    Production,
    Local,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub auto_discovery: bool,
    pub max_storage_nodes: usize,
    pub network_timeout_ms: u64,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub enable_tls: bool,
    pub custom_ca_certs: Option<Vec<String>>, // not persisted (binary keeps core fields only)
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enable_auth: bool,
    pub enable_encryption: bool,
    pub min_key_size: u32,
    pub quantum_resistant: bool,
    pub device_fingerprinting: bool,
    pub mpc_min_participants: u32,
    pub require_genesis_verification: bool,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub local_storage_dir: PathBuf,
    pub cache_size_bytes: u64,
    pub persistent_storage: bool,
    pub database_path: Option<PathBuf>,
    pub backup_enabled: bool,
    pub compression_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub device_type: String,
    pub hardware_capabilities: HashMap<String, String>, // not persisted (derived at runtime)
    pub platform_settings: HashMap<String, String>,     // not persisted (derived at runtime)
    pub entropy_sources: Vec<String>,                   // not persisted
    pub fingerprint_components: Vec<String>,            // not persisted
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub environment: EnvironmentType,
    pub device_id: String,
    pub device_fingerprint: Vec<u8>,
    pub storage_nodes: Vec<String>,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub device: DeviceConfig,
    pub metadata: HashMap<String, String>,
    pub version: String,
    pub created_at_tick: u64,
    pub updated_at_tick: u64,
}

// ------------------------ Defaults ------------------------

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            auto_discovery: true,
            max_storage_nodes: 10,
            network_timeout_ms: 30_000,
            retry_attempts: 3,
            retry_delay_ms: 1_000,
            enable_tls: true,
            custom_ca_certs: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_auth: true,
            enable_encryption: true,
            min_key_size: 256,
            quantum_resistant: true,
            device_fingerprinting: true,
            mpc_min_participants: 3,
            require_genesis_verification: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("./data"))
            .join("dsm");
        Self {
            local_storage_dir: dir,
            cache_size_bytes: 100 * 1024 * 1024,
            persistent_storage: true,
            database_path: None,
            backup_enabled: true,
            compression_enabled: true,
        }
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        let mut hw = HashMap::new();
        hw.insert("cpu_cores".to_string(), num_cpus::get().to_string());
        hw.insert("platform".to_string(), std::env::consts::OS.to_string());
        hw.insert("arch".to_string(), std::env::consts::ARCH.to_string());

        let mut ps = HashMap::new();
        ps.insert("os_version".to_string(), "unknown".to_string());

        Self {
            device_type: "generic".to_string(),
            hardware_capabilities: hw,
            platform_settings: ps,
            entropy_sources: vec![
                "system_time".into(),
                "random_generator".into(),
                "hardware_id".into(),
            ],
            fingerprint_components: vec!["mac_address".into(), "cpu_info".into(), "os_info".into()],
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            environment: EnvironmentType::Development,
            device_id: RuntimeConfig::generate_device_id(),
            device_fingerprint: RuntimeConfig::generate_device_fingerprint(),
            storage_nodes: Vec::new(), // triggers auto-discovery in dev/local
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            device: DeviceConfig::default(),
            metadata: HashMap::new(),
            version: "1.0.0".to_string(),
            created_at_tick: Self::current_tick(),
            updated_at_tick: Self::current_tick(),
        }
    }
}

// ------------------------ Public API ------------------------

impl RuntimeConfig {
    /// Load runtime configuration from cache, environment, binary file, or defaults.
    pub fn load() -> Result<RuntimeConfig, DsmError> {
        if let Some(c) = RUNTIME_CONFIG.get() {
            return Ok(c.clone());
        }

        if let Ok(cfg) = Self::load_from_environment() {
            let _ = RUNTIME_CONFIG.set(cfg.clone());
            return Ok(cfg);
        }

        if let Ok(cfg) = Self::load_from_file() {
            let _ = RUNTIME_CONFIG.set(cfg.clone());
            return Ok(cfg);
        }

        let cfg = Self::create_default_config()?;
        let _ = RUNTIME_CONFIG.set(cfg.clone());
        Ok(cfg)
    }

    fn create_default_config() -> Result<RuntimeConfig, DsmError> {
        let mut config = RuntimeConfig {
            environment: Self::detect_environment(),
            device_id: Self::generate_device_id(),
            device_fingerprint: Self::generate_device_fingerprint(),
            ..Default::default()
        };

        let env_defaults = std::env::var("DSM_DEFAULT_NODES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        config.storage_nodes = match config.environment {
            EnvironmentType::Production => vec![
                "https://storage1.dsm.network".into(),
                "https://storage2.dsm.network".into(),
                "https://storage3.dsm.network".into(),
            ],
            EnvironmentType::Staging => vec![
                "https://staging-storage1.dsm.network".into(),
                "https://staging-storage2.dsm.network".into(),
            ],
            EnvironmentType::Local | EnvironmentType::Development | EnvironmentType::Testing => {
                if env_defaults.is_empty() {
                    log::warn!(
                        "RuntimeConfig: no default storage nodes configured for non-prod env"
                    );
                }
                env_defaults
            }
        };

        match config.environment {
            EnvironmentType::Production => {
                config.security.enable_auth = true;
                config.security.enable_encryption = true;
                config.security.quantum_resistant = true;
            }
            EnvironmentType::Development | EnvironmentType::Testing => {
                config.security.enable_auth = false;
                config.security.enable_encryption = false;
                config.security.quantum_resistant = false;
            }
            _ => {}
        }

        Ok(config)
    }

    fn detect_environment() -> EnvironmentType {
        if let Ok(env) = std::env::var("DSM_ENVIRONMENT") {
            return match env.to_lowercase().as_str() {
                "production" => EnvironmentType::Production,
                "staging" => EnvironmentType::Staging,
                "testing" => EnvironmentType::Testing,
                "local" => EnvironmentType::Local,
                _ => EnvironmentType::Development,
            };
        }
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            return EnvironmentType::Testing;
        }
        if std::path::Path::new("/.dockerenv").exists() {
            return EnvironmentType::Staging;
        }
        if std::env::var("CARGO_MANIFEST_DIR").is_ok() || std::env::var("RUST_LOG").is_ok() {
            return EnvironmentType::Development;
        }
        EnvironmentType::Development
    }

    fn load_from_environment() -> Result<RuntimeConfig, DsmError> {
        let mut config = RuntimeConfig::default();

        if let Ok(device_id) = std::env::var("DSM_DEVICE_ID") {
            config.device_id = device_id;
        }
        if let Ok(env_type) = std::env::var("DSM_ENVIRONMENT") {
            config.environment = match env_type.to_lowercase().as_str() {
                "production" => EnvironmentType::Production,
                "staging" => EnvironmentType::Staging,
                "testing" => EnvironmentType::Testing,
                "local" => EnvironmentType::Local,
                _ => EnvironmentType::Development,
            };
        }

        if matches!(
            config.environment,
            EnvironmentType::Development | EnvironmentType::Local
        ) {
            config.network.auto_discovery = true;
        }

        if !config.network.auto_discovery {
            if let Ok(nodes) = std::env::var("DSM_STORAGE_NODES") {
                config.storage_nodes = nodes.split(',').map(|s| s.trim().to_string()).collect();
            }
        }

        if let Ok(timeout) = std::env::var("DSM_NETWORK_TIMEOUT") {
            if let Ok(ms) = timeout.parse::<u64>() {
                config.network.network_timeout_ms = ms;
            }
        }
        if let Ok(max_nodes) = std::env::var("DSM_MAX_STORAGE_NODES") {
            if let Ok(max) = max_nodes.parse::<usize>() {
                config.network.max_storage_nodes = max;
            }
        }
        if let Ok(auth) = std::env::var("DSM_ENABLE_AUTH") {
            config.security.enable_auth = auth.eq_ignore_ascii_case("true");
        }
        if let Ok(enc) = std::env::var("DSM_ENABLE_ENCRYPTION") {
            config.security.enable_encryption = enc.eq_ignore_ascii_case("true");
        }

        Ok(config)
    }

    fn load_from_file() -> Result<RuntimeConfig, DsmError> {
        // Try several binary paths
        let candidates: Vec<Option<PathBuf>> = vec![
            Some(PathBuf::from("dsm_runtime_config.bin")),
            Some(PathBuf::from("dsm_config.bin")),
            dirs::config_dir().map(|d| d.join("dsm/config.bin")),
        ];
        for p in candidates.into_iter().flatten() {
            if p.exists() {
                let bytes = std::fs::read(&p).map_err(|e| {
                    DsmError::config_simple(format!(
                        "Failed to read config file '{}': {e}",
                        p.display()
                    ))
                })?;
                return Self::decode_binary(&bytes).map_err(|e| {
                    DsmError::config_simple(format!(
                        "Failed to parse binary config '{}': {e}",
                        p.display()
                    ))
                });
            }
        }
        Err(DsmError::config_simple("No configuration file found"))
    }

    /// Save to binary config (TLV) at default path or a provided one.
    pub fn save(&self) -> Result<(), DsmError> {
        self.save_to_file(None)
    }

    pub fn save_to_file(&self, path: Option<PathBuf>) -> Result<(), DsmError> {
        let config_path = path.unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push("dsm_runtime_config.bin");
            p
        });
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DsmError::config_simple(format!("Failed to create config directory: {e}"))
            })?;
        }
        let bytes = self
            .encode_binary()
            .map_err(|e| DsmError::config_simple(format!("Failed to encode binary config: {e}")))?;
        std::fs::write(&config_path, bytes).map_err(|e| {
            DsmError::config_simple(format!(
                "Failed to write config to {}: {e}",
                config_path.display()
            ))
        })?;
        Ok(())
    }

    pub fn get_storage_nodes(&self) -> &Vec<String> {
        &self.storage_nodes
    }

    pub fn validate(&self) -> Result<(), DsmError> {
        if self.device_id.is_empty() {
            return Err(DsmError::config_simple("Device ID cannot be empty"));
        }
        if self.device_fingerprint.is_empty() {
            return Err(DsmError::config_simple(
                "Device fingerprint cannot be empty",
            ));
        }
        if self.storage_nodes.is_empty() && !self.network.auto_discovery {
            return Err(DsmError::config_simple(
                "At least one storage node must be configured when auto-discovery is disabled",
            ));
        }
        if self.network.max_storage_nodes == 0 {
            return Err(DsmError::config_simple(
                "Max storage nodes must be greater than 0",
            ));
        }
        if self.security.min_key_size < 128 {
            return Err(DsmError::config_simple(
                "Minimum key size must be at least 128 bits",
            ));
        }
        Ok(())
    }

    pub fn update_storage_nodes(&mut self, nodes: Vec<String>) {
        self.storage_nodes = nodes;
        self.updated_at_tick = Self::current_tick();
    }

    pub fn environment_config(&self) -> (bool, bool, bool) {
        match self.environment {
            EnvironmentType::Production => (true, true, true),
            EnvironmentType::Staging => (true, true, true),
            EnvironmentType::Local => (false, false, false),
            EnvironmentType::Development => (false, false, false),
            EnvironmentType::Testing => (false, false, false),
        }
    }

    pub fn network_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.network.network_timeout_ms)
    }

    /// Get the configured Bitcoin network for dBTC key derivation.
    ///
    /// Priority: `DSM_BITCOIN_NETWORK` env var > `bitcoin_network` in TOML > Signet.
    /// Valid values: "mainnet", "testnet", "signet"
    pub fn get_bitcoin_network() -> dsm::bitcoin::types::BitcoinNetwork {
        // 1. Check env var
        if let Ok(net) = std::env::var("DSM_BITCOIN_NETWORK") {
            match dsm::bitcoin::types::BitcoinNetwork::try_from(net.as_str()) {
                Ok(n) => return n,
                Err(_) => {
                    log::warn!("Unknown DSM_BITCOIN_NETWORK '{net}', defaulting to signet");
                }
            }
        }
        // 2. Check TOML config
        if let Ok(env_cfg) = crate::network::NetworkConfigLoader::load_env_config() {
            if let Some(ref net_str) = env_cfg.bitcoin_network {
                match dsm::bitcoin::types::BitcoinNetwork::try_from(net_str.as_str()) {
                    Ok(n) => return n,
                    Err(_) => {
                        log::warn!(
                            "Unknown bitcoin_network '{net_str}' in config, defaulting to signet"
                        );
                    }
                }
            }
        }
        log::warn!("No bitcoin_network configured via env or TOML, defaulting to signet");
        log::error!(
            "SECURITY: bitcoin_network not configured in a production build. \
             Set DSM_BITCOIN_NETWORK env var or bitcoin_network in config TOML. \
             Defaulting to signet is the safe fallback."
        );
        dsm::bitcoin::types::BitcoinNetwork::Signet
    }

    pub fn should_auto_discover(&self) -> bool {
        self.network.auto_discovery
    }

    pub fn retry_config(&self) -> (u32, u64) {
        (self.network.retry_attempts, self.network.retry_delay_ms)
    }

    pub fn storage_directory(&self) -> &PathBuf {
        &self.storage.local_storage_dir
    }

    pub fn use_persistent_storage(&self) -> bool {
        self.storage.persistent_storage
    }

    pub fn cache_size(&self) -> u64 {
        self.storage.cache_size_bytes
    }

    // ------------------------ Helpers ------------------------

    fn current_tick() -> u64 {
        crate::util::deterministic_time::tick()
    }

    fn generate_device_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        if let Ok(id) = std::env::var("DSM_DEVICE_ID") {
            return id;
        }
        let mut hasher = dsm_domain_hasher("DSM/device-id-gen");
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        // Monotonic per-process counter ensures unique IDs across successive calls
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        hasher.update(&seq.to_le_bytes());
        // Deterministic tick counter for cross-session uniqueness
        let tick_counter = crate::util::deterministic_time::tick();
        hasher.update(&tick_counter.to_le_bytes());
        let digest = hasher.finalize();
        // Use first 8 bytes of hash as a numeric suffix
        let num = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        format!("dsm_device_{num}")
    }

    fn generate_device_fingerprint() -> Vec<u8> {
        let mut hasher = dsm_domain_hasher("DSM/device-fingerprint");
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }
        hasher.update(&num_cpus::get().to_le_bytes());
        if let Ok(user) = std::env::var("USER") {
            hasher.update(user.as_bytes());
        } else if let Ok(user) = std::env::var("USERNAME") {
            hasher.update(user.as_bytes());
        }
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn device_entropy() -> Result<Vec<u8>, DsmError> {
        let mut hasher = dsm_domain_hasher("DSM/device-entropy");
        hasher.update(&Self::generate_device_fingerprint());
        hasher.update(&Self::current_tick().to_le_bytes());
        let random_bytes = (0..32).map(|_| fastrand::u8(..)).collect::<Vec<u8>>();
        hasher.update(&random_bytes);
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hasher.update(&num_cpus::get().to_le_bytes());
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    // ------------------------ Binary codec ------------------------

    fn encode_binary(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(1024);

        // header
        buf.extend_from_slice(b"DSMCFG\0");
        write_u32(&mut buf, 1); // version

        // environment
        write_tlv_u8(&mut buf, 90, env_to_u8(&self.environment));
        // version string
        write_tlv_string(&mut buf, 91, &self.version);
        // ticks (deterministic logical time)
        write_tlv_u64(&mut buf, 92, self.created_at_tick);
        write_tlv_u64(&mut buf, 93, self.updated_at_tick);

        // device id + fingerprint
        write_tlv_string(&mut buf, 1, &self.device_id);
        write_tlv_bytes(&mut buf, 2, &self.device_fingerprint);

        // storage nodes
        write_tlv_string_list(&mut buf, 3, &self.storage_nodes);

        // network
        {
            let mut inner = Vec::new();
            write_u8(&mut inner, bool_to_u8(self.network.auto_discovery));
            write_u32(&mut inner, self.network.max_storage_nodes as u32);
            write_u64(&mut inner, self.network.network_timeout_ms);
            write_u32(&mut inner, self.network.retry_attempts);
            write_u64(&mut inner, self.network.retry_delay_ms);
            write_u8(&mut inner, bool_to_u8(self.network.enable_tls));
            write_tlv_block(&mut buf, 20, &inner);
        }

        // security
        {
            let mut inner = Vec::new();
            write_u8(&mut inner, bool_to_u8(self.security.enable_auth));
            write_u8(&mut inner, bool_to_u8(self.security.enable_encryption));
            write_u32(&mut inner, self.security.min_key_size);
            write_u8(&mut inner, bool_to_u8(self.security.quantum_resistant));
            write_u8(&mut inner, bool_to_u8(self.security.device_fingerprinting));
            write_u32(&mut inner, self.security.mpc_min_participants);
            write_u8(
                &mut inner,
                bool_to_u8(self.security.require_genesis_verification),
            );
            write_tlv_block(&mut buf, 30, &inner);
        }

        // storage
        {
            let mut inner = Vec::new();
            let dir_s = path_to_string(&self.storage.local_storage_dir);
            write_string(&mut inner, &dir_s);
            write_u64(&mut inner, self.storage.cache_size_bytes);
            write_u8(&mut inner, bool_to_u8(self.storage.persistent_storage));
            write_u8(&mut inner, bool_to_u8(self.storage.backup_enabled));
            write_u8(&mut inner, bool_to_u8(self.storage.compression_enabled));
            write_tlv_block(&mut buf, 40, &inner);

            if let Some(p) = &self.storage.database_path {
                let db_s = path_to_string(p);
                write_tlv_string(&mut buf, 41, &db_s);
            }
        }

        // device (persist only device_type)
        write_tlv_string(&mut buf, 50, &self.device.device_type);

        // metadata
        {
            let mut inner = Vec::new();
            write_u32(&mut inner, self.metadata.len() as u32);
            for (k, v) in &self.metadata {
                write_string(&mut inner, k);
                write_string(&mut inner, v);
            }
            write_tlv_block(&mut buf, 60, &inner);
        }

        Ok(buf)
    }

    fn decode_binary(bytes: &[u8]) -> Result<RuntimeConfig, std::io::Error> {
        let mut cur = Cursor::new(bytes);

        // header
        {
            let mut magic = [0u8; 7];
            cur.read_exact(&mut magic)?;
            if &magic != b"DSMCFG\0" {
                return Err(ioerr("bad magic"));
            }
            let ver = read_u32(&mut cur)?;
            if ver != 1 {
                return Err(ioerr("unsupported version"));
            }
        }

        let mut cfg = RuntimeConfig::default();
        cfg.metadata.clear();
        cfg.storage_nodes.clear();

        while (cur.position() as usize) < bytes.len() {
            let t = match read_u16(&mut cur) {
                Ok(v) => v,
                Err(_) => break,
            };
            let len = read_u32(&mut cur)? as usize;
            if (cur.position() as usize) + len > bytes.len() {
                return Err(ioerr("truncated TLV"));
            }
            let start = cur.position() as usize;
            let end = start + len;
            let seg = &bytes[start..end];

            match t {
                90 => cfg.environment = u8_to_env(seg.first().copied().unwrap_or(0)),
                91 => cfg.version = read_string(&mut Cursor::new(seg))?,
                92 => cfg.created_at_tick = read_u64(&mut Cursor::new(seg))?,
                93 => cfg.updated_at_tick = read_u64(&mut Cursor::new(seg))?,
                1 => cfg.device_id = read_string(&mut Cursor::new(seg))?,
                2 => cfg.device_fingerprint = seg.to_vec(),
                3 => cfg.storage_nodes = read_string_list(seg)?,
                20 => {
                    let mut c = Cursor::new(seg);
                    cfg.network.auto_discovery = read_bool(&mut c)?;
                    cfg.network.max_storage_nodes = read_u32(&mut c)? as usize;
                    cfg.network.network_timeout_ms = read_u64(&mut c)?;
                    cfg.network.retry_attempts = read_u32(&mut c)?;
                    cfg.network.retry_delay_ms = read_u64(&mut c)?;
                    cfg.network.enable_tls = read_bool(&mut c)?;
                }
                30 => {
                    let mut c = Cursor::new(seg);
                    cfg.security.enable_auth = read_bool(&mut c)?;
                    cfg.security.enable_encryption = read_bool(&mut c)?;
                    cfg.security.min_key_size = read_u32(&mut c)?;
                    cfg.security.quantum_resistant = read_bool(&mut c)?;
                    cfg.security.device_fingerprinting = read_bool(&mut c)?;
                    cfg.security.mpc_min_participants = read_u32(&mut c)?;
                    cfg.security.require_genesis_verification = read_bool(&mut c)?;
                }
                40 => {
                    let mut c = Cursor::new(seg);
                    cfg.storage.local_storage_dir = PathBuf::from(read_string(&mut c)?);
                    cfg.storage.cache_size_bytes = read_u64(&mut c)?;
                    cfg.storage.persistent_storage = read_bool(&mut c)?;
                    cfg.storage.backup_enabled = read_bool(&mut c)?;
                    cfg.storage.compression_enabled = read_bool(&mut c)?;
                }
                41 => {
                    let s = read_string(&mut Cursor::new(seg))?;
                    cfg.storage.database_path = Some(PathBuf::from(s));
                }
                50 => {
                    cfg.device.device_type = read_string(&mut Cursor::new(seg))?;
                }
                60 => {
                    let mut c = Cursor::new(seg);
                    let n = read_u32(&mut c)? as usize;
                    let mut map = HashMap::with_capacity(n);
                    for _ in 0..n {
                        let k = read_string(&mut c)?;
                        let v = read_string(&mut c)?;
                        map.insert(k, v);
                    }
                    cfg.metadata = map;
                }
                _ => {
                    // skip unknown
                }
            }
            cur.set_position(end as u64);
        }

        Ok(cfg)
    }
}

// ------------------------ Small binary helpers ------------------------

fn ioerr(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn write_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}
fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_string(out: &mut Vec<u8>, s: &str) {
    write_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn write_tlv_block(buf: &mut Vec<u8>, t: u16, payload: &[u8]) {
    write_u16(buf, t);
    write_u32(buf, payload.len() as u32);
    buf.extend_from_slice(payload);
}
fn write_tlv_u8(buf: &mut Vec<u8>, t: u16, v: u8) {
    write_u16(buf, t);
    write_u32(buf, 1);
    buf.push(v);
}
fn write_tlv_u64(buf: &mut Vec<u8>, t: u16, v: u64) {
    let mut tmp = Vec::with_capacity(8);
    write_u64(&mut tmp, v);
    write_tlv_block(buf, t, &tmp);
}
fn write_tlv_string(buf: &mut Vec<u8>, t: u16, s: &str) {
    let mut tmp = Vec::with_capacity(s.len() + 4);
    write_string(&mut tmp, s);
    write_tlv_block(buf, t, &tmp);
}
fn write_tlv_bytes(buf: &mut Vec<u8>, t: u16, bytes: &[u8]) {
    write_u16(buf, t);
    write_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}
fn write_tlv_string_list(buf: &mut Vec<u8>, t: u16, list: &Vec<String>) {
    let mut tmp = Vec::new();
    write_u32(&mut tmp, list.len() as u32);
    for s in list {
        write_string(&mut tmp, s.as_str());
    }
    write_tlv_block(buf, t, &tmp);
}

fn read_u16(cur: &mut Cursor<&[u8]>) -> Result<u16, std::io::Error> {
    let mut b = [0u8; 2];
    cur.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32(cur: &mut Cursor<&[u8]>) -> Result<u32, std::io::Error> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(cur: &mut Cursor<&[u8]>) -> Result<u64, std::io::Error> {
    let mut b = [0u8; 8];
    cur.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn read_bool(cur: &mut Cursor<&[u8]>) -> Result<bool, std::io::Error> {
    let mut b = [0u8; 1];
    cur.read_exact(&mut b)?;
    Ok(b[0] != 0)
}
fn read_string(cur: &mut Cursor<&[u8]>) -> Result<String, std::io::Error> {
    let len = read_u32(cur)? as usize;
    let mut v = vec![0u8; len];
    cur.read_exact(&mut v)?;
    String::from_utf8(v).map_err(|_| ioerr("invalid utf8 string"))
}
fn read_string_list(seg: &[u8]) -> Result<Vec<String>, std::io::Error> {
    let mut c = Cursor::new(seg);
    let n = read_u32(&mut c)? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_string(&mut c)?);
    }
    Ok(out)
}

fn bool_to_u8(b: bool) -> u8 {
    if b {
        1
    } else {
        0
    }
}

fn env_to_u8(e: &EnvironmentType) -> u8 {
    match e {
        EnvironmentType::Development => 0,
        EnvironmentType::Testing => 1,
        EnvironmentType::Staging => 2,
        EnvironmentType::Production => 3,
        EnvironmentType::Local => 4,
    }
}
fn u8_to_env(v: u8) -> EnvironmentType {
    match v {
        3 => EnvironmentType::Production,
        2 => EnvironmentType::Staging,
        1 => EnvironmentType::Testing,
        4 => EnvironmentType::Local,
        _ => EnvironmentType::Development,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_creation() {
        let config = RuntimeConfig::default();
        assert!(!config.device_id.is_empty());
        assert!(!config.device_fingerprint.is_empty());
        assert!(
            !config.storage_nodes.is_empty() || config.network.auto_discovery,
            "default config should either include storage nodes or have auto-discovery enabled"
        );
    }

    #[test]
    fn test_device_id_generation() {
        let id1 = RuntimeConfig::generate_device_id();
        let id2 = RuntimeConfig::generate_device_id();
        assert!(id1.starts_with("dsm_device_"));
        assert!(id2.starts_with("dsm_device_"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_device_entropy_generation() -> Result<(), DsmError> {
        let entropy = RuntimeConfig::device_entropy()?;
        assert_eq!(entropy.len(), 32);
        assert!(entropy.iter().any(|&b| b != 0));
        Ok(())
    }

    #[test]
    fn test_roundtrip_binary_config() {
        let mut cfg = RuntimeConfig {
            environment: EnvironmentType::Staging,
            storage_nodes: vec!["http://a:1".into(), "http://b:2".into()],
            ..Default::default()
        };
        cfg.metadata.insert("k".into(), "v".into());
        cfg.device.device_type = "phone".into();
        cfg.security.min_key_size = 192;
        cfg.network.enable_tls = false;
        cfg.storage.database_path = Some(PathBuf::from("/tmp/dsm.db"));

        let bytes = cfg.encode_binary().unwrap();
        let dec = RuntimeConfig::decode_binary(&bytes).unwrap();

        assert_eq!(dec.environment, EnvironmentType::Staging);
        assert_eq!(dec.storage_nodes, cfg.storage_nodes);
        assert_eq!(dec.metadata.get("k"), Some(&"v".to_string()));
        assert_eq!(dec.device.device_type, "phone");
        assert_eq!(dec.security.min_key_size, 192);
        assert!(!dec.network.enable_tls);
        assert_eq!(
            dec.storage.database_path,
            Some(PathBuf::from("/tmp/dsm.db"))
        );
    }
}
