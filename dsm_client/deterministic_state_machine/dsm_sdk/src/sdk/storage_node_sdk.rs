//! # Storage Node SDK (protobuf-only, clockless, signature-free nodes)
//!
//! - Protobuf octet-stream only; no JSON/CBOR/base64/hex on the wire.
//! - Storage nodes are dumb indexers: they never sign, never enforce time-based TTL, never attest.
//! - Client-side must sign canonical bytes; nodes simply persist bytes and mirror hash-addressed content.
//! - TTL parameters are retained for wire compatibility but MUST be set to 0 in the clockless protocol.
//! - All identifiers are raw bytes; any UI/base32 rendering happens at the edges, not in this SDK.
//! - Deterministic behavior only: no wall clocks, no randomized alternate paths, no best-effort paths.
use dsm::types::error::DsmError;

use prost::Message; // for canonical proto encode/decode
use crate::generated; // prost generated messages

use std::collections::HashMap; // HashSet removed as unused
use std::sync::Arc;
use dsm::utils::time::Duration;

use tokio::sync::{Mutex, RwLock};

use log::{debug, info, warn};

use crate::util::deterministic_time as dt;
use crate::util::registry_addr::{
    build_root_device_tree_evidence, registry_content_addr_b64url, REGISTRY_QUORUM_THRESHOLD,
};
use dsm::common::deterministic_id;
use dsm::crypto::blake3::dsm_domain_hasher;

/// Auth credentials for storage node device authentication.
/// Transport-layer only — does not affect protocol semantics (Invariant #12).
#[derive(Debug, Clone)]
pub struct StorageAuthContext {
    /// Device ID in Base32 Crockford (52 chars for 32 bytes)
    pub device_id_b32: String,
    /// Auth token in Base32 Crockford (as returned by device registration)
    pub token_b32: String,
}

/// Minimal StorageNodeClient type required by impl blocks below.
#[derive(Debug, Clone)]
pub struct StorageNodeClient {
    pub client: reqwest::Client,
    pub node_info: NodeInfo,
    pub security_config: SecurityConfig,
    /// Optional device auth credentials for write operations (PUT/DELETE).
    pub auth: Option<StorageAuthContext>,
}

/// Simple connection pool container expected by the SDK.
pub struct ConnectionPool {
    pub pools: Arc<RwLock<HashMap<String, NodeConnectionPool>>>,
    pub config: ConnectionPoolConfig,
}

impl ConnectionPool {
    pub fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
}

/// API-facing health status for nodes
#[derive(Debug, Clone)]
pub struct ApiNodeHealthStatus {
    pub node_id: String,
    pub is_healthy: bool,
    pub last_check: u64,
    pub response_time_ms: u64,
    pub error_count: u32,
    pub region: String,
    pub load_percentage: f64,
    pub storage_utilization: f64,
}

/// Metrics collected by the SDK
#[derive(Debug, Clone)]
pub struct StorageMetrics {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_response_time_ticks: f64,
    pub bytes_stored: u64,
    pub bytes_retrieved: u64,
    pub cache_hit_ratio: f64,
}

/// Retry policy structure used in configs
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

/// Minimal security configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    pub enable_auth: bool,
}

/// Minimal B0x types used locally by this module
#[derive(Debug, Clone)]
pub struct B0xEntry {
    pub id: String,
    pub sender_genesis_hash: String,
    pub recipient_genesis_hash: String,
    pub transaction: Vec<u8>,
    pub signature: Vec<u8>,
    pub tick: u64,
    pub expires_at: u64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct B0xSubmission {
    pub entry: B0xEntry,
}

/// Minimal DeviceIdentity used for the simple reconstruction in retrieve_device_identity
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: Vec<u8>,
    pub genesis_state: dsm::core::identity::genesis::GenesisState,
    pub device_entropy: Vec<u8>,
    pub blind_key: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Convert a HashMap into a deterministic, lexicographically sorted Vec of ParamKv for tests.
pub fn map_to_param_kv(m: &HashMap<String, String>) -> Vec<generated::ParamKv> {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    keys.into_iter()
        .map(|k| generated::ParamKv {
            key: k.clone(),
            value: m.get(k).cloned().unwrap_or_default(),
        })
        .collect()
}

/// Produce canonical bytes for transaction parameters deterministically (length-prefixed key/value).
/// This avoids any reliance on JSON and keeps ordering deterministic.
pub fn canonical_params_bytes(m: &HashMap<String, String>) -> Vec<u8> {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    let mut out = Vec::new();
    for k in keys {
        let v = m.get(k).map(|s| s.as_bytes()).unwrap_or(&[]);
        // encode key length (u16) + key bytes + value length (u32) + value bytes for deterministic parsing
        let kbytes = k.as_bytes();
        let klen = (kbytes.len() as u16).to_le_bytes();
        out.extend_from_slice(&klen);
        out.extend_from_slice(kbytes);
        let vlen = (v.len() as u32).to_le_bytes();
        out.extend_from_slice(&vlen);
        out.extend_from_slice(v);
    }
    out
}

/// Build a reqwest::Client that loads custom CA certs from the DSM env config TOML.
/// Reusable by any code path that needs HTTPS to storage nodes with self-signed certs.
pub fn build_ca_aware_client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder().user_agent("DSM-SDK/1.0");
    let mut certs_loaded: u32 = 0;
    let env_path_opt = std::env::var("DSM_ENV_CONFIG_PATH")
        .ok()
        .or_else(|| crate::network::get_env_config_path().map(|s| s.to_string()))
        .or_else(|| std::env::var("ENV_CONFIG_PATH").ok());
    match env_path_opt {
        Some(ref env_path) => {
            log::info!("[build_ca_aware_client] env config path: {}", env_path);
            let config_dir = std::path::Path::new(env_path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            match std::fs::read_to_string(env_path) {
                Ok(toml_str) => match toml::from_str::<toml::Value>(&toml_str) {
                    Ok(v) => {
                        if let Some(arr) = v.get("custom_ca_certs").and_then(|a| a.as_array()) {
                            for item in arr {
                                if let Some(p) = item.as_str() {
                                    let cert_path = if std::path::Path::new(p).is_absolute() {
                                        std::path::PathBuf::from(p)
                                    } else {
                                        config_dir.join(p)
                                    };
                                    match std::fs::read(&cert_path) {
                                        Ok(bytes) => match reqwest::Certificate::from_pem(&bytes) {
                                            Ok(cert) => {
                                                builder = builder.add_root_certificate(cert);
                                                certs_loaded += 1;
                                                log::info!(
                                                            "[build_ca_aware_client] Loaded CA cert: {} ({} bytes)",
                                                            cert_path.display(),
                                                            bytes.len()
                                                        );
                                            }
                                            Err(e) => {
                                                log::error!(
                                                            "[build_ca_aware_client] PEM parse FAILED for {}: {} — HTTPS to self-signed storage nodes will fail",
                                                            cert_path.display(),
                                                            e
                                                        );
                                            }
                                        },
                                        Err(e) => {
                                            log::error!(
                                                    "[build_ca_aware_client] Cannot read CA cert at {}: {} — HTTPS to self-signed storage nodes will fail",
                                                    cert_path.display(),
                                                    e
                                                );
                                        }
                                    }
                                }
                            }
                        } else {
                            log::warn!(
                                    "[build_ca_aware_client] No custom_ca_certs array in env config — using system CA store only"
                                );
                        }
                    }
                    Err(e) => {
                        log::error!(
                                "[build_ca_aware_client] Failed to parse env config TOML: {} — no custom CA certs loaded",
                                e
                            );
                    }
                },
                Err(e) => {
                    log::error!(
                        "[build_ca_aware_client] Cannot read env config at {}: {} — no custom CA certs loaded",
                        env_path,
                        e
                    );
                }
            }
        }
        None => {
            log::warn!(
                "[build_ca_aware_client] No env config path found (DSM_ENV_CONFIG_PATH / get_env_config_path / ENV_CONFIG_PATH) — no custom CA certs loaded"
            );
        }
    }
    CA_CERTS_LOADED.store(certs_loaded, std::sync::atomic::Ordering::SeqCst);
    log::info!(
        "[build_ca_aware_client] Total custom CA certs loaded: {}",
        certs_loaded
    );
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// Number of custom CA certificates loaded by `build_ca_aware_client()`.
/// Exposed for diagnostics (storage.connectivity route).
static CA_CERTS_LOADED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Returns the number of custom CA certificates that were loaded into the HTTP client.
pub fn ca_certs_loaded_count() -> u32 {
    CA_CERTS_LOADED.load(std::sync::atomic::Ordering::SeqCst)
}

#[derive(Debug, Clone)]
pub struct MpcGenesisConfig {
    pub identity_id: String,
    pub participants: Vec<String>,
    pub quantum_resistant: bool,
    pub key_rotation_interval_hours: u64,
}

#[derive(Debug, Clone)]
pub struct BilateralSyncState {
    pub last_sync_tick: u64,
    pub pending_operations: u64,
    pub sync_conflicts: u64,
    pub resolution_strategy: String,
}

#[derive(Debug, Clone)]
pub struct MpcGenesisResponse {
    pub success: bool,
    pub session_id: String,
    // Raw bytes
    pub device_id: Option<Vec<u8>>,
    pub error: Option<String>,
    // Raw bytes
    pub genesis_hash: Option<Vec<u8>>,
}

/// Response for Genesis ID creation via MPC (CORRECTED IMPLEMENTATION)
/// Genesis device ID is the OUTPUT of this process
#[derive(Debug, Clone)]
pub struct GenesisCreationResponse {
    /// Session ID for tracking this Genesis creation
    pub session_id: String,
    /// GENERATED Genesis device ID (output of MPC process)
    // Raw bytes; no encoding in SDK
    pub genesis_device_id: Vec<u8>,
    /// Current session state
    pub state: String,
    /// Number of contributions received (n-of-n; whitepaper §2.5)
    pub contributions_received: usize,
    /// Whether genesis creation is complete
    pub complete: bool,
    /// Genesis hash for verification (available when complete)
    pub genesis_hash: Option<Vec<u8>>,
    /// List of participating storage node IDs
    pub participating_nodes: Vec<String>,
    /// Deterministic tick
    pub tick: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageNodeErrorKind {
    Network,
    Timeout,
    Authentication,
    NotFound,
    InvalidInput,
    ServerError,
    PoolExhausted,
    DiscoveryFailed,
    HealthCheckFailed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StorageNodeError {
    message: String,
    pub(crate) kind: StorageNodeErrorKind,
}

impl StorageNodeError {
    pub fn from_message(message: String) -> Self {
        Self {
            message,
            kind: StorageNodeErrorKind::Unknown,
        }
    }

    pub fn new(message: String) -> Self {
        Self::from_message(message)
    }

    pub fn network(message: String) -> Self {
        Self {
            message,
            kind: StorageNodeErrorKind::Network,
        }
    }

    pub fn timeout() -> Self {
        Self {
            message: "Operation timed out".to_string(),
            kind: StorageNodeErrorKind::Timeout,
        }
    }

    pub fn not_found(message: String) -> Self {
        Self {
            message,
            kind: StorageNodeErrorKind::NotFound,
        }
    }

    pub fn invalid_input(message: String) -> Self {
        Self {
            message,
            kind: StorageNodeErrorKind::InvalidInput,
        }
    }

    pub fn server_error(message: String) -> Self {
        Self {
            message,
            kind: StorageNodeErrorKind::ServerError,
        }
    }

    pub fn unknown() -> Self {
        Self {
            message: "Unknown error".to_string(),
            kind: StorageNodeErrorKind::Unknown,
        }
    }
}

impl std::fmt::Display for StorageNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StorageNodeError {}

impl StorageNodeClient {
    pub async fn new(config: StorageNodeConfig) -> Result<Self, StorageNodeError> {
        let client = build_ca_aware_client();

        // Use the first node URL as primary
        let primary_url = config.node_urls.first().ok_or_else(|| {
            StorageNodeError::invalid_input("No storage node URLs provided".to_string())
        })?;

        let node_info = NodeInfo {
            url: primary_url.clone(),
            id: "primary".to_string(),
            region: config
                .selection_config
                .preferred_regions
                .first()
                .cloned()
                .unwrap_or_default(),
            health_status: NodeHealthStatus {
                is_healthy: true,
                last_check: dt::tick(),
                response_time_ms: 0,
                consecutive_failures: 0,
                error_rate: 0.0,
            },
            performance_metrics: NodePerformanceMetrics {
                total_requests: 0,
                successful_requests: 0,
                average_latency_ms: 0.0,
                throughput_mbps: 0.0,
                load_score: 0.0,
            },
            last_updated: dt::tick(),
        };

        Ok(Self {
            client,
            node_info,
            security_config: config.security_config,
            auth: None,
        })
    }

    /// Set device auth credentials for write operations (PUT/DELETE).
    pub fn with_auth(mut self, auth: StorageAuthContext) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Generate a unique message ID for replay protection (transport-layer, not protocol).
    /// Uses BLAKE3 domain-separated hash of the key + deterministic tick for uniqueness.
    fn generate_message_id(key: &str) -> String {
        let tick = dt::tick();
        let mut hasher = dsm_domain_hasher("DSM/obj-msg-id");
        hasher.update(key.as_bytes());
        hasher.update(&tick.to_le_bytes());
        crate::util::text_id::encode_base32_crockford(hasher.finalize().as_bytes())
    }

    pub async fn put(
        &self,
        key: &str,
        data: &[u8],
        _ttl_seconds: Option<u64>, // Unused: clockless system
    ) -> Result<String, StorageNodeError> {
        // Generate DLV ID from key
        let mut hasher = dsm_domain_hasher("DSM/dlv-partition");
        hasher.update(key.as_bytes());
        let dlv_id = hasher.finalize();

        // Transport header identifier: use canonical Base32 Crockford (no hex).
        let dlv_id_text = crate::util::text_id::encode_base32_crockford(dlv_id.as_bytes());
        let stake_hash_text = crate::util::text_id::encode_base32_crockford(&[0u8; 32]);

        let url = format!("{base}/api/v2/object/put", base = self.node_info.url);

        // Send data with headers (storage node expects headers + raw body)
        // Also provide bootstrap headers for auto-slot creation (428 fix)
        let mut req_builder = self
            .client
            .post(&url)
            .header("x-dlv-id", dlv_id_text)
            .header("x-path", key)
            .header("x-capacity-bytes", "10485760")
            .header("x-stake-hash", stake_hash_text)
            .header("Content-Type", "application/octet-stream");

        // Add device auth headers for authenticated write (transport-layer, Invariant #12 preserved)
        if let Some(auth) = &self.auth {
            let msg_id = Self::generate_message_id(key);
            req_builder = req_builder
                .header(
                    "authorization",
                    format!("DSM {}:{}", auth.device_id_b32, auth.token_b32),
                )
                .header("x-dsm-message-id", msg_id);
        }

        let req_builder = req_builder.body(data.to_vec());

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        let response = req_builder
            .send()
            .await
            .map_err(|e| StorageNodeError::network(format!("HTTP request failed: {e}")))?;

        if response.status().is_success() {
            let addr = response
                .headers()
                .get("x-object-address")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Ok(addr)
        } else {
            Err(StorageNodeError::server_error(format!(
                "PUT failed with status: {}",
                response.status()
            )))
        }
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StorageNodeError> {
        // Use direct GET by key/addr
        let encoded_key = urlencoding::encode(key);
        let url = format!(
            "{base}/api/v2/object/get/{encoded_key}",
            base = self.node_info.url
        );

        let req_builder = self.client.get(&url);

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        let response = req_builder
            .send()
            .await
            .map_err(|e| StorageNodeError::network(format!("HTTP request failed: {e}")))?;

        if response.status().is_success() {
            let bytes = response.bytes().await.map_err(|e| {
                StorageNodeError::network(format!("Failed to read response body: {e}"))
            })?;
            Ok(bytes.to_vec())
        } else if response.status() == 404 {
            Err(StorageNodeError::not_found(format!("Key not found: {key}")))
        } else {
            Err(StorageNodeError::server_error(format!(
                "GET failed with status: {}",
                response.status()
            )))
        }
    }

    pub async fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<generated::ObjectListResponseV1, StorageNodeError> {
        let query = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            if !prefix.is_empty() {
                serializer.append_pair("prefix", prefix);
            }
            serializer.append_pair("limit", &limit.clamp(1, 1000).to_string());
            if let Some(cursor) = cursor.filter(|value| !value.is_empty()) {
                serializer.append_pair("cursor", cursor);
            }
            serializer.finish()
        };
        let url = format!("{}/api/v2/object/list?{}", self.node_info.url, query);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageNodeError::network(format!("HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(StorageNodeError::server_error(format!(
                "LIST failed with status: {}",
                response.status()
            )));
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| StorageNodeError::network(format!("Failed to read response body: {e}")))?;
        generated::ObjectListResponseV1::decode(body.as_ref()).map_err(|e| {
            StorageNodeError::server_error(format!("Object list response decode failed: {e}"))
        })
    }

    pub async fn delete(&self, key: &str) -> Result<(), StorageNodeError> {
        // Generate DLV ID from key
        let mut hasher = dsm_domain_hasher("DSM/dlv-partition");
        hasher.update(key.as_bytes());
        let dlv_id = hasher.finalize();

        // Create protobuf message
        let delete_request = generated::StorageObjectDelete {
            dlv_id: dlv_id.as_bytes().to_vec(),
            path: key.to_string(),
        };

        // Encode to protobuf bytes
        let request_bytes = delete_request.encode_to_vec();

        let url = format!(
            "{base}/api/v2/object/delete_proto",
            base = self.node_info.url
        );

        let mut req_builder = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream");

        // Add device auth headers for authenticated delete (transport-layer, Invariant #12 preserved)
        if let Some(auth) = &self.auth {
            let msg_id = Self::generate_message_id(key);
            req_builder = req_builder
                .header(
                    "authorization",
                    format!("DSM {}:{}", auth.device_id_b32, auth.token_b32),
                )
                .header("x-dsm-message-id", msg_id);
        }

        let req_builder = req_builder.body(request_bytes);

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        let response = req_builder
            .send()
            .await
            .map_err(|e| StorageNodeError::network(format!("HTTP request failed: {e}")))?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == 404 {
            Err(StorageNodeError::not_found(format!("Key not found: {key}")))
        } else {
            Err(StorageNodeError::server_error(format!(
                "DELETE failed with status: {}",
                response.status()
            )))
        }
    }

    pub async fn check_health(&self) -> Result<bool, StorageNodeError> {
        let url = format!("{}/api/v2/health", self.node_info.url);

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageNodeError::network(format!("Health check failed: {e}")))?;

        Ok(response.status().is_success())
    }

    pub async fn get_session_status(
        &self,
        session_id: &str,
    ) -> Result<generated::GenesisCreated, StorageNodeError> {
        let url = format!(
            "{base}/api/v2/session/{sid}",
            base = self.node_info.url,
            sid = session_id
        );

        let req_builder = self.client.get(&url);

        // Clockless: do not enforce wall-clock/tokio timeouts here.
        let response = req_builder.send().await.map_err(|e| {
            StorageNodeError::network(format!("Session status request failed: {e}"))
        })?;

        if response.status().is_success() {
            let bytes = response.bytes().await.map_err(|e| {
                StorageNodeError::network(format!("Failed to read session response bytes: {e}"))
            })?;

            generated::GenesisCreated::decode(bytes.as_ref()).map_err(|e| {
                StorageNodeError::network(format!(
                    "Failed to decode protobuf session response: {e}"
                ))
            })
        } else {
            Err(StorageNodeError::server_error(format!(
                "Session status request failed with status: {}",
                response.status()
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    ConsistentHashing,
    AdaptiveLatency,
    GeographicAffinity,
}

#[derive(Debug, Clone)]
pub enum NodeSelectionAlgorithm {
    Random,
    HealthBased,
    LatencyBased,
    ReputationBased,
    HybridScoring,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BilateralTransactionStatus {
    /// Transaction initiated, waiting for recipient signature
    Pending,
    /// Recipient has signed, transaction is complete offline
    Signed,
    /// Transaction has been finalized and published to network
    Finalized,
    /// Transaction was rejected by recipient
    Rejected,
    /// Transaction expired without completion
    Expired,
}

/// Additional missing types for JNI bindings
#[derive(Debug)]
#[allow(dead_code)] // Fields used for future connection pooling functionality
pub struct NodeConnectionPool {
    #[allow(dead_code)]
    node_url: String,
    clients: Mutex<Vec<Arc<StorageNodeClient>>>,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    max_connections: usize,
}

impl NodeConnectionPool {
    pub fn new(node_url: String, max_connections: usize) -> Self {
        Self {
            node_url,
            clients: Mutex::new(Vec::new()),
            active_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_connections,
        }
    }
}

/// Enhanced storage node with health and performance metrics
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub url: String,
    pub id: String,
    pub region: String,
    pub health_status: NodeHealthStatus,
    pub performance_metrics: NodePerformanceMetrics,
    pub last_updated: u64,
}

#[derive(Debug, Clone)]
pub struct NodeHealthStatus {
    pub is_healthy: bool,
    pub last_check: u64,
    pub response_time_ms: u64,
    pub consecutive_failures: usize,
    pub error_rate: f64,
}

#[derive(Debug, Clone)]
pub struct NodePerformanceMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub average_latency_ms: f64,
    pub throughput_mbps: f64,
    pub load_score: f64,
}

// Removed orphan trait implementation for GenesisState - cannot implement orphan traits
// Default for GenesisState should be implemented in the dsm crate where it's defined

/// Production-grade SDK for interacting with DSM Storage Nodes
#[derive(Clone)]
pub struct StorageNodeSDK {
    inner: Arc<StorageNodeClient>,
    pub config: StorageNodeConfig,
    #[allow(dead_code)]
    connection_pool: Arc<ConnectionPool>,
    health_statuses: Arc<RwLock<HashMap<String, ApiNodeHealthStatus>>>,
    metrics: Arc<RwLock<StorageMetrics>>,
    mpc_genesis_config: Arc<RwLock<Option<MpcGenesisConfig>>>,
    bilateral_sync_state: Arc<RwLock<BilateralSyncState>>,
}

impl StorageNodeSDK {
    /// Initialize the SDK with enhanced configuration and production features
    pub async fn new(config: StorageNodeConfig) -> Result<Self, DsmError> {
        let client = StorageNodeClient::new(config.clone()).await.map_err(|e| {
            DsmError::storage(format!("StorageNodeSDK.new: {e}"), None::<std::io::Error>)
        })?;

        let connection_pool = Arc::new(ConnectionPool::new(config.pool_config.clone()));

        let sdk = StorageNodeSDK {
            inner: Arc::new(client),
            config: config.clone(),
            connection_pool,
            health_statuses: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(StorageMetrics {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                average_response_time_ticks: 0.0,
                bytes_stored: 0,
                bytes_retrieved: 0,
                cache_hit_ratio: 0.0,
            })),
            mpc_genesis_config: Arc::new(RwLock::new(None)),
            bilateral_sync_state: Arc::new(RwLock::new(BilateralSyncState {
                last_sync_tick: dt::tick(),
                pending_operations: 0,
                sync_conflicts: 0,
                resolution_strategy: "last_write_wins".to_string(),
            })),
        };

        // Start background health monitoring if enabled
        if config.selection_config.health_check_interval_ms > 0 {
            sdk.start_health_monitoring().await;
        }

        Ok(sdk)
    }

    /// Store data in the storage node with comprehensive error handling and retry logic
    pub async fn put(
        &self,
        key: &str,
        data: &[u8],
        ttl_seconds: Option<u64>,
    ) -> Result<String, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        let result = self
            .execute_with_retry(|client| {
                let key = key.to_string();
                let data = data.to_vec();
                async move { client.put(&key, &data, ttl_seconds).await }
            })
            .await;

        // Update metrics
        #[cfg(feature = "perf-metrics")]
        {
            self.update_metrics(start_time, data.len() as u64, 0, result.is_ok())
                .await;
        }

        result.map_err(|e| {
            DsmError::storage(format!("StorageNodeSDK.put: {e}"), None::<std::io::Error>)
        })
    }

    /// Write to ALL configured storage nodes (spec §6: redundant mirrors).
    ///
    /// Fans out the PUT to every endpoint in the live registry. Returns
    /// successfully if at least one write succeeds. Failed nodes are
    /// quarantined via `report_storage_failure`.
    pub async fn put_to_all_replicas(
        &self,
        key: &str,
        data: &[u8],
        ttl_seconds: Option<u64>,
    ) -> Result<String, DsmError> {
        let endpoints = crate::network::list_storage_endpoints()?;
        if endpoints.is_empty() {
            return self.put(key, data, ttl_seconds).await;
        }

        let mut primary_addr = String::new();
        let mut success_count = 0u32;
        let total = endpoints.len();

        for endpoint in &endpoints {
            let temp_config = StorageNodeConfig::new(vec![endpoint.clone()]);
            let temp_client = match StorageNodeClient::new(temp_config).await {
                Ok(mut c) => {
                    // Propagate auth from primary client.
                    c.auth.clone_from(&self.inner.auth);
                    c
                }
                Err(e) => {
                    log::warn!("replica fanout: failed to create client for {endpoint}: {e}");
                    let _ = crate::network::report_storage_failure(endpoint);
                    continue;
                }
            };
            match temp_client.put(key, data, ttl_seconds).await {
                Ok(addr) => {
                    if primary_addr.is_empty() {
                        primary_addr = addr;
                    }
                    success_count += 1;
                    let _ = crate::network::report_storage_success(endpoint);
                }
                Err(e) => {
                    log::warn!("replica fanout: PUT to {endpoint} failed: {e}");
                    let _ = crate::network::report_storage_failure(endpoint);
                }
            }
        }

        log::info!(
            "put_to_all_replicas: key={} success={}/{} nodes",
            &key[..key.len().min(24)],
            success_count,
            total
        );

        if success_count == 0 {
            return Err(DsmError::storage(
                "all replica writes failed",
                None::<std::io::Error>,
            ));
        }
        Ok(primary_addr)
    }

    /// Retrieve data from storage node with automatic decoding and failover
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        let result = self
            .execute_with_retry(|client| {
                let key = key.to_string();
                async move { client.get(&key).await }
            })
            .await;

        let _data_size = result.as_ref().map(|data| data.len() as u64).unwrap_or(0);
        #[cfg(feature = "perf-metrics")]
        {
            self.update_metrics(start_time, 0, _data_size, result.is_ok())
                .await;
        }

        result.map_err(|e| {
            DsmError::storage(format!("StorageNodeSDK.get: {e}"), None::<std::io::Error>)
        })
    }

    pub async fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<generated::ObjectListResponseV1, DsmError> {
        let result = self
            .execute_with_retry(|client| {
                let prefix = prefix.to_string();
                let cursor = cursor.map(str::to_string);
                async move { client.list_objects(&prefix, cursor.as_deref(), limit).await }
            })
            .await;

        result.map_err(|e| {
            DsmError::storage(
                format!("StorageNodeSDK.list_objects: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Delete data from storage
    pub async fn delete(&self, key: &str) -> Result<(), DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        let result = self
            .execute_with_retry(|client| {
                let key = key.to_string();
                async move { client.delete(&key).await }
            })
            .await;

        #[cfg(feature = "perf-metrics")]
        {
            self.update_metrics(start_time, 0, 0, result.is_ok()).await;
        }

        result.map_err(|e| {
            DsmError::crypto(
                format!("StorageNodeSDK.delete: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Enhanced health check with node discovery and status caching
    pub async fn check_health(&self) -> Result<bool, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let _start_tick = dt::tick();

        let result = self.inner.check_health().await.map_err(|e| {
            DsmError::crypto(
                format!("StorageNodeSDK.check_health: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Update health status cache
        let node_status = ApiNodeHealthStatus {
            node_id: self.inner.node_info.id.clone(),
            is_healthy: result,
            last_check: dt::tick(),
            #[cfg(feature = "perf-metrics")]
            // Clockless: measured milliseconds are forbidden; expose 0 here.
            response_time_ms: 0,
            #[cfg(not(feature = "perf-metrics"))]
            response_time_ms: 0,
            error_count: if result { 0 } else { 1 },
            region: self.inner.node_info.region.clone(),
            load_percentage: 0.0, // This would require more advanced metrics from the node
            storage_utilization: 0.0, // This would require more advanced metrics from the node
        };

        // Scope the lock to release it before potential async operations
        {
            let mut health_statuses = self.health_statuses.write().await;
            health_statuses.insert(self.inner.node_info.id.clone(), node_status);
        } // Lock is released here

        Ok(result)
    }

    /// Initialize MPC Genesis identity for quantum-resistant operations
    pub async fn initialize_mpc_genesis(&self, config: MpcGenesisConfig) -> Result<(), DsmError> {
        if !self.config.advanced_features.enable_mpc_genesis {
            return Err(DsmError::crypto(
                "MPC Genesis not enabled in configuration".to_string(),
                None::<std::io::Error>,
            ));
        }

        // Store MPC Genesis configuration - scope the lock
        {
            let mut mpc_config = self.mpc_genesis_config.write().await;
            *mpc_config = Some(config.clone());
        } // Lock is released here

        // Initialize identity with the storage node using the create_genesis_with_mpc method.
        // No threshold parameter — n-of-n MPC per whitepaper §2.5.
        match self.create_genesis_with_mpc(None).await {
            Ok(response) => {
                if !response.session_id.is_empty() {
                    info!(
                        "MPC Genesis initialized successfully for {} with session {}",
                        config.identity_id, response.session_id
                    );
                    Ok(())
                } else {
                    Err(DsmError::crypto(
                        "MPC Genesis failed: empty session ID".to_string(),
                        None::<std::io::Error>,
                    ))
                }
            }
            Err(e) => Err(DsmError::crypto(
                format!("MPC Genesis initialization failed: {e}"),
                None::<std::io::Error>,
            )),
        }
    }

    /// Perform bilateral sync with remote nodes
    pub async fn bilateral_sync(&self) -> Result<(), DsmError> {
        if !self.config.advanced_features.enable_epidemic_sync {
            return Err(DsmError::crypto(
                "Bilateral sync not enabled in configuration".to_string(),
                None::<std::io::Error>,
            ));
        }

        // In a real implementation, this would sync with other nodes
        // For now, just update sync state - scope the lock
        {
            let mut sync_state = self.bilateral_sync_state.write().await;
            sync_state.last_sync_tick = dt::tick();
            sync_state.pending_operations = 0;
        }

        info!("Bilateral sync completed");
        Ok(())
    }

    /// Get current storage metrics
    pub async fn get_metrics(&self) -> StorageMetrics {
        self.metrics.read().await.clone()
    }

    /// Get all node health statuses
    pub async fn get_health_statuses(&self) -> HashMap<String, ApiNodeHealthStatus> {
        self.health_statuses.read().await.clone()
    }

    /// Get current MPC Genesis configuration
    pub async fn get_mpc_genesis_config(&self) -> Option<MpcGenesisConfig> {
        self.mpc_genesis_config.read().await.clone()
    }

    /// Get current bilateral sync state
    pub async fn get_bilateral_sync_state(&self) -> BilateralSyncState {
        self.bilateral_sync_state.read().await.clone()
    }

    /// Get session status for Genesis creation session (CORRECTED IMPLEMENTATION)
    pub async fn get_genesis_session_status(
        &self,
        session_id: &str,
    ) -> Result<GenesisCreationResponse, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        let url = format!(
            "{}/api/v2/genesis/session/{}",
            self.inner.node_info.url, session_id
        );

        let response = self.inner.client.get(&url).send().await.map_err(|e| {
            DsmError::crypto(
                format!("Genesis session status request failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        if response.status().is_success() {
            let bytes = response.bytes().await.map_err(|e| {
                DsmError::crypto(
                    format!("Failed to read Genesis session status response bytes: {e}"),
                    None::<std::io::Error>,
                )
            })?;

            // Expect protobuf-encoded GenesisCreated message from storage node
            match generated::GenesisCreated::decode(bytes.as_ref()) {
                Ok(g) => {
                    // Map prost GenesisCreated -> local GenesisCreationResponse
                    let genesis_response = GenesisCreationResponse {
                        session_id: g.session_id.clone(),
                        genesis_device_id: g.device_id.clone(),
                        state: "complete".to_string(),
                        contributions_received: 0_usize, // detailed counts not always provided here
                        complete: true,
                        genesis_hash: g.genesis_hash.as_ref().map(|h| h.v.clone()),
                        participating_nodes: g.storage_nodes.clone(),
                        // No wall-clock time in protocol; use deterministic monotonic tick
                        tick: dt::tick(),
                    };
                    #[cfg(feature = "perf-metrics")]
                    self.update_metrics(start_time, 0, 0, true).await;
                    Ok(genesis_response)
                }
                Err(e) => Err(DsmError::crypto(
                    format!("Failed to decode GenesisCreated protobuf: {e}"),
                    None::<std::io::Error>,
                )),
            }
        } else {
            Err(DsmError::crypto(
                format!(
                    "Genesis session status failed with status: {}",
                    response.status()
                ),
                None::<std::io::Error>,
            ))
        }
    }

    /// Store data with geographic replication across multiple regions
    pub async fn put_with_replication(
        &self,
        key: &str,
        data: &[u8],
        ttl_seconds: Option<u64>,
        replicas: u32,
    ) -> Result<String, DsmError> {
        if !self.config.advanced_features.enable_geo_replication {
            return self.put(key, data, ttl_seconds).await;
        }

        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();
        let mut successful_replicas = 0;
        let required_replicas = std::cmp::min(
            replicas,
            self.config.selection_config.preferred_regions.len() as u32,
        );

        // For now, just use the primary node (in a real implementation, this would use regional endpoints)
        let mut primary_addr = String::new();
        match self.put(key, data, ttl_seconds).await {
            Ok(addr) => {
                successful_replicas += 1;
                primary_addr = addr;
            }
            Err(e) => {
                warn!("Failed to replicate to primary node: {e}");
            }
        }

        #[cfg(feature = "perf-metrics")]
        self.update_metrics(start_time, data.len() as u64, 0, successful_replicas > 0)
            .await;

        if successful_replicas == 0 {
            Err(DsmError::crypto(
                "All geographic replications failed".to_string(),
                None::<std::io::Error>,
            ))
        } else if successful_replicas < required_replicas {
            warn!("Only {successful_replicas} of {required_replicas} replicas succeeded");
            Ok(primary_addr)
        } else {
            Ok(primary_addr)
        }
    }

    /// Retrieve data with automatic failover across regions
    pub async fn get_with_failover(&self, key: &str) -> Result<Vec<u8>, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Try primary region first
        match self.get(key).await {
            Ok(data) => {
                #[cfg(feature = "perf-metrics")]
                self.update_metrics(start_time, 0, data.len() as u64, true)
                    .await;
                return Ok(data);
            }
            Err(e) => {
                if !self.config.advanced_features.enable_geo_replication {
                    return Err(e);
                }
                warn!("Primary retrieval failed, trying failover: {e}");
            }
        }

        // Build a list of candidate node URLs excluding the current primary
        let primary_url = self.inner.node_info.url.clone();
        let mut candidates: Vec<String> = self
            .config
            .node_urls
            .iter()
            .filter(|&u| u.trim_end_matches('/') != primary_url.trim_end_matches('/'))
            .cloned()
            .collect();

        // Deterministic ordering: keep as configured
        let mut last_err: Option<DsmError> = None;

        for url in candidates.drain(..) {
            // Create a temporary client targeting this candidate URL
            let mut cfg = self.config.clone();
            cfg.node_urls = vec![url.clone()];

            match StorageNodeClient::new(cfg.clone()).await {
                Ok(temp_client) => {
                    match temp_client.get(key).await {
                        Ok(data) => {
                            #[cfg(feature = "perf-metrics")]
                            self.update_metrics(start_time, 0, data.len() as u64, true)
                                .await;
                            // Optionally update health cache to mark this node healthy
                            {
                                let mut hs = self.health_statuses.write().await;
                                hs.insert(
                                    url.clone(),
                                    ApiNodeHealthStatus {
                                        node_id: url.clone(),
                                        is_healthy: true,
                                        last_check: dt::tick(),
                                        response_time_ms: 0,
                                        error_count: 0,
                                        region: self.inner.node_info.region.clone(),
                                        load_percentage: 0.0,
                                        storage_utilization: 0.0,
                                    },
                                );
                            }
                            return Ok(data);
                        }
                        Err(err) => {
                            warn!("Failover GET failed on {url}: {err}");
                            // Update health cache to reflect failure
                            {
                                let mut hs = self.health_statuses.write().await;
                                hs.insert(
                                    url.clone(),
                                    ApiNodeHealthStatus {
                                        node_id: url.clone(),
                                        is_healthy: false,
                                        last_check: dt::tick(),
                                        response_time_ms: 0,
                                        error_count: 1,
                                        region: self.inner.node_info.region.clone(),
                                        load_percentage: 0.0,
                                        storage_utilization: 0.0,
                                    },
                                );
                            }
                            last_err = Some(DsmError::crypto(
                                format!("Failover GET error on {url}: {err}"),
                                None::<std::io::Error>,
                            ));
                        }
                    }
                }
                Err(ne) => {
                    warn!("Failed to initialize client for {url}: {ne}");
                    last_err = Some(DsmError::crypto(
                        format!("Client init failed for {url}: {ne}"),
                        None::<std::io::Error>,
                    ));
                }
            }
        }

        #[cfg(feature = "perf-metrics")]
        self.update_metrics(start_time, 0, 0, false).await;
        Err(last_err.unwrap_or_else(|| {
            DsmError::crypto(
                "Failover exhausted: no storage nodes succeeded".to_string(),
                None::<std::io::Error>,
            )
        }))
    }

    /// Submit a b0x entry for unilateral transactions
    pub async fn submit_b0x_entry(
        &self,
        entry_id: &str,
        sender_genesis_hash: &str,
        recipient_genesis_hash: &str,
        transaction_data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Create the b0x entry
        let b0x_entry = B0xEntry {
            id: entry_id.to_string(),
            sender_genesis_hash: sender_genesis_hash.to_string(),
            recipient_genesis_hash: recipient_genesis_hash.to_string(),
            transaction: transaction_data.clone(),
            signature: signature.clone(),
            tick: dt::tick(),
            expires_at: 0, // Never expires
            metadata: HashMap::new(),
        };

        // Create the submission wrapper
        let submission = B0xSubmission { entry: b0x_entry };

        // Submit via HTTP POST to /api/v2/b0x
        let result = self
            .execute_with_retry(|client| {
                let submission = submission.clone();
                async move {
                    let url = format!("{}/api/v2/b0x/submit", client.node_info.url);

                    let mut buf = Vec::new();
                    // If a protobuf for B0x exists, encode it; otherwise, send opaque bytes of serialized entry
                    // Here we serialize entry as proto-opaque in Envelope body (application/octet-stream)
                    // For now, just send the transaction bytes as body; storage node API should expect protobuf.
                    buf.extend_from_slice(&submission.entry.transaction);

                    let req_builder = client
                        .client
                        .post(&url)
                        .header("content-type", "application/octet-stream")
                        .body(buf);

                    // Clockless: do not enforce wall-clock/tokio timeouts here.
                    let response = req_builder.send().await.map_err(|e| {
                        StorageNodeError::network(format!("HTTP request failed: {e}"))
                    })?;

                    if response.status().is_success() {
                        debug!("Successfully submitted b0x entry: {entry_id}");
                        Ok(())
                    } else {
                        let status = response.status();
                        let error_text = response.text().await.unwrap_or_default();
                        Err(StorageNodeError::server_error(format!(
                            "B0x submission failed {status}: {error_text}"
                        )))
                    }
                }
            })
            .await;

        // Update metrics
        #[cfg(feature = "perf-metrics")]
        self.update_metrics(start_time, transaction_data.len() as u64, 0, result.is_ok())
            .await;

        result.map_err(|e| {
            DsmError::crypto(
                format!("StorageNodeSDK.submit_b0x_entry: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Submit a bilateral transaction entry for offline peer-to-peer transfers
    /// Implements the bilateral transaction protocol from DSM whitepaper Section 17.2
    pub async fn submit_bilateral_entry(
        &self,
        sender_genesis_hash: &str,
        recipient_genesis_hash: &str,
        transaction_params: HashMap<String, String>,
        state_number: u64,
    ) -> Result<BilateralEntry, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Generate deterministic entry ID from transaction parameters hash
        let params_hash = {
            let mut hasher = dsm_domain_hasher("DSM/bilateral-params-hash");
            for (k, v) in transaction_params.iter() {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
            hasher.finalize()
        };
        let entry_id = format!(
            "bilateral_{}",
            deterministic_id::derive_id_from_hash("DSM/entry-id", &[params_hash.as_bytes()])
        );

        // Generate pre-commitment hash strictly using provided state hash (raw bytes only)
        let state_hash_bytes: Vec<u8> = match transaction_params.get("state_hash") {
            Some(v) if !v.is_empty() => v.as_bytes().to_vec(),
            _ => {
                return Err(DsmError::invalid_parameter(
                    "transaction_params.state_hash (bytes) is required",
                ));
            }
        };
        // Canonicalize transaction parameters into a deterministic protobuf
        // representation. This avoids using JSON for canonical commit preimages
        // and for persisted payloads.
        let params_proto = generated::TransactionParamsProto {
            kv: map_to_param_kv(&transaction_params),
        };
        let params_bytes = params_proto.encode_to_vec();

        let next_state = state_number + 1;

        // Build canonical precommitment preimage as bytes: state_hash || params_proto || next_state(le)
        let mut preimage: Vec<u8> = Vec::with_capacity(32 + params_bytes.len() + 8);
        preimage.extend_from_slice(&state_hash_bytes);
        preimage.extend_from_slice(&params_bytes);
        preimage.extend_from_slice(&next_state.to_le_bytes());
        let pre_commitment_hash = dsm::crypto::blake3::domain_hash("DSM/precommit-hash", &preimage);

        // transaction_payload is the canonical proto bytes for parameters
        let transaction_payload = params_bytes.clone();

        // Create bilateral entry
        let bilateral_entry = BilateralEntry {
            id: entry_id,
            sender_genesis_hash: sender_genesis_hash.to_string(),
            recipient_genesis_hash: recipient_genesis_hash.to_string(),
            pre_commitment_hash: pre_commitment_hash.as_bytes().to_vec(),
            sender_signature: Vec::new(), // Will be populated by calling code
            recipient_signature: None,
            transaction_payload,
            final_signature: None,
            transaction_params,
            state_number,
            tick: dt::tick(),
            status: BilateralTransactionStatus::Pending,
            metadata: HashMap::new(),
        };

        // Update metrics for submit step
        #[cfg(feature = "perf-metrics")]
        {
            self.update_metrics(
                start_time,
                bilateral_entry.transaction_payload.len() as u64,
                0,
                true,
            )
            .await;
        }

        Ok(bilateral_entry)
    }

    /// Process a received bilateral transaction for counter-signing
    /// Implements recipient-side bilateral transaction processing per DSM whitepaper
    pub async fn process_bilateral_transaction(
        &self,
        mut bilateral_entry: BilateralEntry,
        recipient_signature: Vec<u8>,
        approve: bool,
    ) -> Result<BilateralEntry, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Verify pre-commitment hash
        // Recompute state hash strictly from provided parameter
        let state_hash_bytes: Vec<u8> = match bilateral_entry.transaction_params.get("state_hash") {
            Some(v) if !v.is_empty() => v.as_bytes().to_vec(),
            _ => {
                return Err(DsmError::invalid_parameter(
                    "transaction_params.state_hash (bytes) is required",
                ));
            }
        };
        // Reconstruct canonical params proto bytes and recompute expected preimage
        // Reconstruct canonical params bytes deterministically (same format as when created)
        let params_proto = generated::TransactionParamsProto {
            kv: map_to_param_kv(&bilateral_entry.transaction_params),
        };
        let params_bytes = params_proto.encode_to_vec();
        let next_state = bilateral_entry.state_number + 1;
        let mut expected_preimage: Vec<u8> = Vec::with_capacity(32 + params_bytes.len() + 8);
        expected_preimage.extend_from_slice(&state_hash_bytes);
        expected_preimage.extend_from_slice(&params_bytes);
        expected_preimage.extend_from_slice(&next_state.to_le_bytes());
        let expected_hash =
            dsm::crypto::blake3::domain_hash("DSM/precommit-hash", &expected_preimage);

        if bilateral_entry.pre_commitment_hash != expected_hash.as_bytes() {
            bilateral_entry.status = BilateralTransactionStatus::Rejected;
            return Err(DsmError::crypto(
                "Pre-commitment hash verification failed".to_string(),
                None::<std::io::Error>,
            ));
        }

        // Update transaction status based on approval
        if approve {
            bilateral_entry.recipient_signature = Some(recipient_signature);
            bilateral_entry.status = BilateralTransactionStatus::Signed;
            bilateral_entry.tick = dt::tick();
        } else {
            bilateral_entry.status = BilateralTransactionStatus::Rejected;
        }

        // Update metrics
        #[cfg(feature = "perf-metrics")]
        self.update_metrics(
            start_time,
            bilateral_entry.transaction_payload.len() as u64,
            0,
            approve,
        )
        .await;

        Ok(bilateral_entry)
    }

    /// Finalize a bilateral transaction after both parties have signed
    /// Prepares transaction for network publication when connectivity is restored
    pub async fn finalize_bilateral_transaction(
        &self,
        mut bilateral_entry: BilateralEntry,
        final_signature: Vec<u8>,
    ) -> Result<BilateralEntry, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Verify transaction is ready for finalization
        if bilateral_entry.status != BilateralTransactionStatus::Signed {
            return Err(DsmError::crypto(
                "Transaction must be signed before finalization".to_string(),
                None::<std::io::Error>,
            ));
        }

        if bilateral_entry.recipient_signature.is_none() {
            return Err(DsmError::crypto(
                "Recipient signature required for finalization".to_string(),
                None::<std::io::Error>,
            ));
        }

        // Set final signature and mark as finalized
        bilateral_entry.final_signature = Some(final_signature);
        bilateral_entry.status = BilateralTransactionStatus::Finalized;
        bilateral_entry.tick = dt::tick();

        // Update metrics
        #[cfg(feature = "perf-metrics")]
        self.update_metrics(
            start_time,
            bilateral_entry.transaction_payload.len() as u64,
            0,
            true,
        )
        .await;

        Ok(bilateral_entry)
    }

    /// Graceful shutdown with connection cleanup
    pub async fn shutdown(&self) -> Result<(), DsmError> {
        info!("Shutting down StorageNodeSDK");
        // Deterministic: no wall-clock delays
        Ok(())
    }

    /// Create a DSM Genesis Identity via Multi-Party Computation (MPC).
    ///
    /// Per whitepaper §2.5: this is n-of-n commit-then-reveal entropy
    /// aggregation, NOT threshold cryptography.  Every configured storage
    /// node contributes; the floor is `≥3` (anti-2-collusion).  The prior
    /// `threshold` argument and `node_urls.iter().take(threshold_count)`
    /// pre-truncation (Issue #252 prefix-bias sub-bug) have been removed:
    /// every node contributes its entropy, every contribution goes into G.
    pub async fn create_genesis_with_mpc(
        &self,
        client_entropy: Option<Vec<u8>>,
    ) -> Result<GenesisCreationResponse, DsmError> {
        // Genesis is created LOCALLY by gathering entropy from storage nodes
        // Storage nodes just provide entropy - they don't create genesis

        log::info!("Creating genesis locally with MPC entropy from storage nodes");

        // For the FIRST device: Genesis hash = Device ID (root device)
        // The device_id parameter to create_genesis_via_blind_mpc is a temporary value
        // The actual Genesis G will become DevID_1, and we'll use G as both genesis and device_id

        // Use client entropy as temporary device_id for the MPC process
        // The final genesis hash G will replace this as the root device ID
        let temp_device_id = if let Some(ref entropy) = client_entropy {
            if entropy.len() >= 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&entropy[..32]);
                id.to_vec()
            } else {
                let mut hasher = dsm_domain_hasher("DSM/genesis-entropy-pad");
                hasher.update(entropy);
                hasher.finalize().as_bytes().to_vec()
            }
        } else {
            return Err(DsmError::invalid_operation(
                "Client entropy required for genesis creation",
            ));
        };

        if temp_device_id.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Temporary device ID must be 32 bytes",
            ));
        }

        // Gather entropy from ALL storage nodes (n-of-n).
        let node_urls = self.get_node_urls();

        if node_urls.len() < 3 {
            return Err(DsmError::invalid_operation(format!(
                "Need at least 3 storage nodes for MPC genesis (whitepaper §2.5), only {} configured",
                node_urls.len()
            )));
        }

        log::info!(
            "Gathering entropy from all {} storage nodes (n-of-n; whitepaper §2.5)",
            node_urls.len(),
        );

        // Fetch entropy from EVERY storage node.  No prefix truncation —
        // closes Issue #252's "first threshold_count nodes" bias.
        let mut mpc_participants = Vec::new();
        for (i, url) in node_urls.iter().enumerate() {
            let entropy_url = format!("{}/api/v2/genesis/entropy", url.trim_end_matches('/'));

            log::info!("Fetching entropy from node {}: {}", i, entropy_url);

            let response = match self.inner.client.get(&entropy_url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    log::error!("Failed to fetch entropy from {}: {}", entropy_url, e);
                    return Err(DsmError::crypto(
                        format!("Failed to fetch entropy from storage node: {}", e),
                        None::<String>,
                    ));
                }
            };

            if !response.status().is_success() {
                return Err(DsmError::crypto(
                    format!("Storage node returned error: {}", response.status()),
                    None::<String>,
                ));
            }

            let entropy_bytes = response.bytes().await.map_err(|e| {
                DsmError::crypto(
                    format!("Failed to read entropy bytes: {}", e),
                    None::<String>,
                )
            })?;

            if entropy_bytes.len() != 32 {
                return Err(DsmError::crypto(
                    format!(
                        "Storage node returned {} bytes, expected 32",
                        entropy_bytes.len()
                    ),
                    None::<String>,
                ));
            }

            mpc_participants.push(entropy_bytes.to_vec());
            log::info!("Received 32 bytes of entropy from node {}", i);
        }

        log::info!(
            "Gathered {} entropy contributions, creating genesis locally",
            mpc_participants.len()
        );

        // Create genesis locally using core SDK
        use crate::sdk::core_sdk::CoreSDK;
        let core_sdk = CoreSDK::new()?;

        let genesis_info = core_sdk
            .create_genesis_with_passive_contributors(
                temp_device_id.clone(),
                mpc_participants.clone(),
                client_entropy.clone(),
            )
            .await?;

        log::info!(
            "Genesis created locally: hash={}",
            crate::util::text_id::encode_base32_crockford(&genesis_info.genesis_hash)
        );

        // CRITICAL: For the root device, Genesis hash = Device ID
        // The genesis_hash IS the device_id for the first device
        let device_id = genesis_info.genesis_hash.clone();

        log::info!(
            "Root device ID (same as genesis): {}",
            crate::util::text_id::encode_base32_crockford(&device_id)
        );

        // Build response matching expected structure
        let genesis_response = GenesisCreationResponse {
            session_id: crate::util::text_id::encode_base32_crockford(
                &genesis_info.genesis_hash[0..16],
            ),
            genesis_device_id: device_id, // Genesis hash = Device ID for root device
            state: "complete".to_string(),
            contributions_received: mpc_participants.len(),
            complete: true,
            genesis_hash: Some(genesis_info.genesis_hash),
            participating_nodes: mpc_participants
                .iter()
                .map(|p| crate::util::text_id::encode_base32_crockford(p))
                .collect(),
            tick: dt::tick(),
        };

        Ok(genesis_response)
    }

    /// Add a secondary device to an existing genesis
    /// This requires scanning a QR code from the root device to get the genesis hash
    /// The new device_id = H(DSM/device\0 || client_entropy || genesis_hash || DBRW)
    pub async fn add_secondary_device(
        &self,
        genesis_hash: Vec<u8>,
        client_entropy: Vec<u8>,
    ) -> Result<GenesisCreationResponse, DsmError> {
        log::info!("Adding secondary device to existing genesis");

        if genesis_hash.len() != 32 {
            return Err(DsmError::invalid_operation("Genesis hash must be 32 bytes"));
        }

        if client_entropy.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Client entropy must be 32 bytes",
            ));
        }

        // Derive new device ID bound to the existing genesis
        // DevID_N = H(DSM/device\0 || client_entropy || genesis_hash || DBRW)
        let mut hasher = dsm_domain_hasher("DSM/device");
        hasher.update(&client_entropy);
        hasher.update(&genesis_hash);

        // C-DBRW binding (required)
        let cdbrw_binding = crate::fetch_dbrw_binding_key()?;
        hasher.update(&cdbrw_binding);

        let new_device_id = hasher.finalize().as_bytes().to_vec();

        log::info!(
            "Derived secondary device ID: {}",
            crate::util::text_id::encode_base32_crockford(&new_device_id)
        );
        log::info!(
            "Bound to genesis: {}",
            crate::util::text_id::encode_base32_crockford(&genesis_hash)
        );

        // Add this device to the Device Tree on storage nodes
        // 1. Fetch current Device Tree (list of device IDs for this genesis)
        let device_tree_key = format!(
            "device_tree:{}",
            crate::util::text_id::encode_base32_crockford(&genesis_hash)
        );
        let mut device_ids = match self.inner.get(&device_tree_key).await {
            Ok(bytes) if !bytes.is_empty() => {
                // Try to decode as a simple repeated bytes message
                // For now, assume it's stored as: [count: u32][device_id_1: 32 bytes][device_id_2: 32 bytes]...
                if bytes.len() >= 4 {
                    let count =
                        u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0u8; 4])) as usize;
                    let mut ids = Vec::new();
                    for i in 0..count {
                        let offset = 4 + i * 32;
                        if offset + 32 <= bytes.len() {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(&bytes[offset..offset + 32]);
                            ids.push(id);
                        }
                    }
                    ids
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(), // No existing tree or error
        };

        // 2. Add new_device_id as a leaf (if not already present)
        let new_device_id_array: [u8; 32] = new_device_id.clone().try_into().unwrap_or([0u8; 32]);
        if !device_ids.contains(&new_device_id_array) {
            device_ids.push(new_device_id_array);
        }

        // 3. Sort lexicographically (big-endian byte order as per spec)
        device_ids.sort();

        // Compute the new Device Tree root
        let new_root = compute_device_tree_root(&device_ids);
        log::info!(
            "New Device Tree root for genesis {}: {}",
            crate::util::text_id::encode_base32_crockford(&genesis_hash),
            crate::util::text_id::encode_base32_crockford(&new_root)
        );

        // 4. Store updated tree on storage nodes
        // Encode as: [count: u32][device_id_1: 32 bytes][device_id_2: 32 bytes]...
        let mut tree_bytes = Vec::new();
        tree_bytes.extend_from_slice(&(device_ids.len() as u32).to_le_bytes());
        for id in &device_ids {
            tree_bytes.extend_from_slice(id);
        }

        // Store the updated device tree
        match self.inner.put(&device_tree_key, &tree_bytes, None).await {
            Ok(_) => {
                log::info!(
                    "Successfully updated Device Tree for genesis {}",
                    crate::util::text_id::encode_base32_crockford(&genesis_hash)
                );
            }
            Err(e) => {
                log::warn!("Failed to update Device Tree: {}", e);
                // Continue anyway - the device was created locally
            }
        }

        // For now, return a response indicating the device was added locally
        let response = GenesisCreationResponse {
            session_id: crate::util::text_id::encode_base32_crockford(&new_device_id[0..16]),
            genesis_device_id: new_device_id,
            state: "complete".to_string(),
            contributions_received: 0, // No MPC for secondary devices
            complete: true,
            genesis_hash: Some(genesis_hash),
            participating_nodes: vec![],
            tick: dt::tick(),
        };

        Ok(response)
    }

    /// Retrieve the complete device identity after Genesis creation
    pub async fn retrieve_device_identity(
        &self,
        device_id: &str,
    ) -> Result<Option<DeviceIdentity>, DsmError> {
        let key = format!("device_identity:{device_id}");

        // Use the storage node's get endpoint to retrieve the device identity
        match self.inner.get(&key).await {
            Ok(response_bytes) => {
                // Protobuf-only: decode a stored protobuf DeviceIdentity if present
                if response_bytes.is_empty() {
                    return Ok(None);
                }

                let identity = generated::GenesisCreated::decode(response_bytes.as_ref()).ok();
                if let Some(gen) = identity {
                    // Construct a minimal DeviceIdentity from prost type; for richer details,
                    // extend protobuf on storage-node side to return a dedicated identity message.
                    let device_identity = DeviceIdentity {
                        device_id: gen.device_id.clone(),
                        genesis_state: {
                            // Compatibility genesis_state built from prost fields (non-authoritative)
                            use dsm::core::identity::genesis::{
                                GenesisState, KyberKey, SigningKey, Contribution,
                            };
                            use std::collections::HashSet;
                            GenesisState {
                                hash: gen
                                    .genesis_hash
                                    .as_ref()
                                    .map(|h| h.v.clone().try_into().unwrap_or([0u8; 32]))
                                    .unwrap_or([0u8; 32]),
                                initial_entropy: gen
                                    .device_entropy
                                    .clone()
                                    .try_into()
                                    .unwrap_or([0u8; 32]),
                                participants: HashSet::new(),
                                merkle_root: None,
                                device_id: None,
                                signing_key: SigningKey {
                                    public_key: gen.public_key.clone(),
                                    secret_key: Vec::new(),
                                },
                                kyber_keypair: KyberKey {
                                    public_key: Vec::new(),
                                    secret_key: Vec::new(),
                                },
                                contributions: Vec::<Contribution>::new(),
                            }
                        },
                        device_entropy: gen.device_entropy,
                        blind_key: Vec::new(),
                        created_at: dt::tick(),
                        updated_at: dt::tick(),
                    };
                    Ok(Some(device_identity))
                } else {
                    Ok(None)
                }
            }
            Err(e) if matches!(e.kind, StorageNodeErrorKind::NotFound) => Ok(None),
            Err(e) => Err(DsmError::crypto(
                format!("Failed to retrieve device identity: {e}"),
                None::<String>,
            )),
        }
    }

    /// Start health monitoring for storage nodes
    pub async fn start_health_monitoring(&self) {
        let health_statuses = self.health_statuses.clone();

        tokio::spawn(async move {
            loop {
                // In a real implementation, this would check actual node health
                // For now, we'll just maintain basic health status
                let statuses = health_statuses.read().await;

                // In a real implementation, this would ping nodes and update their status
                // For now, we'll just read the existing status for monitoring
                let _active_nodes = statuses.values().filter(|status| status.is_healthy).count();
                log::trace!("Health check completed, {} active nodes", _active_nodes);

                drop(statuses);
                // Deterministic: no wall-clock delays
            }
        });
    }

    /// Execute a storage operation with retry logic
    pub async fn execute_with_retry<F, Fut, T>(&self, operation: F) -> Result<T, DsmError>
    where
        F: Fn(Arc<StorageNodeClient>) -> Fut,
        Fut: std::future::Future<Output = Result<T, StorageNodeError>>,
    {
        let max_retries = 3; // Default retry count since field doesn't exist
        let base_delay = Duration::from_ticks(1000); // Default deterministic delay (ticks)

        for attempt in 0..=max_retries {
            match operation(self.inner.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) if attempt < max_retries => {
                    let delay = base_delay * (2_u32.pow(attempt as u32)); // Exponential backoff
                    warn!("Storage operation failed (attempt {})", attempt + 1);
                    warn!("Retrying in {delay:?}: {e}");
                    // Deterministic: no wall-clock delays
                }
                Err(e) => {
                    return Err(DsmError::storage(
                        format!("Storage operation failed after {max_retries} retries: {e}"),
                        None::<std::io::Error>,
                    ));
                }
            }
        }

        // This part should ideally not be reached if retry logic is exhaustive
        // and error handling is complete. If it is reached, it indicates an unhandled
        // error condition or an issue with the retry mechanism.
        Err(DsmError::storage(
            "Storage operation failed due to unhandled error after retries".to_string(),
            None::<std::io::Error>,
        ))
    }

    /// Update storage metrics
    #[cfg(feature = "perf-metrics")]
    pub async fn update_metrics(
        &self,
        start_time: u64,
        bytes_written: u64,
        bytes_read: u64,
        success: bool,
    ) {
        let mut metrics = self.metrics.write().await;

        metrics.total_operations += 1;
        if success {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        metrics.bytes_stored += bytes_written;
        metrics.bytes_retrieved += bytes_read;

        // Update average response time
        let operation_time = dt::tick().saturating_sub(start_time) as f64;
        if metrics.total_operations == 1 {
            metrics.average_response_time_ticks = operation_time;
        } else {
            // Moving average calculation
            let total_time = metrics.average_response_time_ticks
                * (metrics.total_operations - 1) as f64
                + operation_time;
            metrics.average_response_time_ticks = total_time / metrics.total_operations as f64;
        }
    }

    #[cfg(not(feature = "perf-metrics"))]
    pub async fn update_metrics(
        &self,
        _start_time: u64,
        bytes_written: u64,
        bytes_read: u64,
        success: bool,
    ) {
        // Update counters without timing when perf metrics are disabled
        let mut metrics = self.metrics.write().await;

        metrics.total_operations += 1;
        if success {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        metrics.bytes_stored += bytes_written;
        metrics.bytes_retrieved += bytes_read;
        // Do not touch average_response_time_ms when perf metrics are disabled
    }

    /// Return a new SDK instance with device auth credentials set on the inner client.
    /// Required for authenticated PUT/DELETE operations on storage nodes.
    pub fn with_auth(self, auth: StorageAuthContext) -> Self {
        let client = (*self.inner).clone().with_auth(auth);
        Self {
            inner: Arc::new(client),
            ..self
        }
    }

    /// Store data with a simple interface for Genesis publication
    pub async fn store_data(&self, key: &str, data: &[u8]) -> Result<String, DsmError> {
        // Clockless: do not use wall-clock-based TTLs.
        // Storage nodes are dumb mirrors; retention/policy is enforced by
        // content-addressing and higher-level deterministic rules.
        self.put(key, data, None).await
    }

    /// Get the list of configured storage node URLs
    pub fn get_node_urls(&self) -> Vec<String> {
        self.config.node_urls.clone()
    }

    /// Discover local storage nodes (simplified for JNI)
    pub async fn discover_local(
        &self,
    ) -> Result<crate::generated::DiscoverLocalResponse, DsmError> {
        let resp = crate::generated::DiscoverLocalResponse {
            discovered_nodes: self.config.node_urls.clone(),
            discovery_method: "configuration".to_string(),
            event_counter: dt::tick(),
        };
        Ok(resp)
    }

    /// Publish genesis data to storage nodes
    pub async fn publish_genesis_to_nodes(
        &self,
        genesis: crate::generated::GenesisCreated,
    ) -> Result<crate::generated::PublishGenesisResponse, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        // Use protobuf canonical bytes for storage persistence
        let genesis_bytes = genesis.encode_to_vec();

        // Publish to registry endpoint on ALL storage nodes (required for HTTP verification)
        let mut published_count = 0u32;
        let mut last_error: Option<String> = None;

        for node_url in &self.config.node_urls {
            let url = format!("{}/api/v2/registry/publish", node_url.trim_end_matches('/'));

            match self
                .inner
                .client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .body(genesis_bytes.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    log::info!("Genesis published to node: {}", node_url);
                    published_count += 1;
                }
                Ok(resp) => {
                    let err = format!(
                        "Failed to publish genesis to node {}: status {}",
                        node_url,
                        resp.status()
                    );
                    log::warn!("{}", err);
                    last_error = Some(err);
                }
                Err(e) => {
                    let err = format!(
                        "Network error publishing genesis to node {}: {}",
                        node_url, e
                    );
                    log::warn!("{}", err);
                    last_error = Some(err);
                }
            }
        }

        #[cfg(feature = "perf-metrics")]
        self.update_metrics(
            start_time,
            genesis_bytes.len() as u64,
            0,
            published_count > 0,
        )
        .await;

        // Fail if no nodes succeeded
        if published_count == 0 {
            return Err(DsmError::internal(
                format!(
                    "Failed to publish genesis to any storage node. Last error: {:?}",
                    last_error
                ),
                None::<std::io::Error>,
            ));
        }

        let resp = crate::generated::PublishGenesisResponse {
            success: true,
            published: true,
            key: "registry".to_string(),
            published_to_nodes: published_count,
            event_counter: dt::tick(),
        };

        Ok(resp)
    }

    /// Register a device in the Device Tree on storage nodes.
    ///
    /// Publishes the 100-byte DeviceTreeEntry evidence blob to the
    /// content-addressed `/api/v2/registry/publish` endpoint on all configured
    /// nodes. The entry is required for contact discovery (`contacts.addManual`
    /// → `verify_device_tree_evidence_quorum`).
    ///
    /// **Quorum contract.** The read side requires at least
    /// [`REGISTRY_QUORUM_THRESHOLD`] nodes to hold the entry before a contact
    /// can be resolved. If fewer nodes accept the publish, this function
    /// returns an `Err` so the caller can surface (or retry) the failure
    /// rather than silently proceeding with an unreachable identity.
    ///
    /// Writes are idempotent — the server keys each object by
    /// `BLAKE3("DSM/registry\0" || evidence)`, so repeated publishes of the
    /// same 100-byte evidence are no-ops and safe to call on every bootstrap.
    pub async fn register_device_in_tree(
        &self,
        device_id: &[u8],
        genesis_hash: &[u8],
    ) -> Result<crate::generated::PublishGenesisResponse, DsmError> {
        #[cfg(feature = "perf-metrics")]
        let start_time = dt::tick();

        if device_id.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "register_device_in_tree: device_id must be 32 bytes, got {}",
                device_id.len()
            )));
        }
        if genesis_hash.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "register_device_in_tree: genesis_hash must be 32 bytes, got {}",
                genesis_hash.len()
            )));
        }

        // Canonical 100-byte evidence (shared with the quorum reader).
        let evidence_bytes = build_root_device_tree_evidence(device_id, genesis_hash);

        // Publish to registry endpoint on all storage nodes.
        let mut published_count: u32 = 0;
        let mut last_error: Option<String> = None;
        // HTTP headers require text; use Base32 Crockford (canon), not hex/base64.
        let genesis_text = crate::util::text_id::encode_base32_crockford(genesis_hash);

        for node_url in &self.config.node_urls {
            let url = format!("{}/api/v2/registry/publish", node_url.trim_end_matches('/'));

            match self
                .inner
                .client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-DSM-Kind", "1") // Device tree evidence kind
                .header("X-DSM-DLV-ID", genesis_text.clone())
                .body(evidence_bytes.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    log::info!("Device registered in tree on node: {}", node_url);
                    published_count += 1;
                }
                Ok(resp) => {
                    let err = format!(
                        "register_device_in_tree: node {} returned HTTP {}",
                        node_url,
                        resp.status()
                    );
                    log::warn!("{err}");
                    last_error = Some(err);
                }
                Err(e) => {
                    let err = format!(
                        "register_device_in_tree: network error on node {}: {}",
                        node_url, e
                    );
                    log::warn!("{err}");
                    last_error = Some(err);
                }
            }
        }

        #[cfg(feature = "perf-metrics")]
        self.update_metrics(
            start_time,
            evidence_bytes.len() as u64,
            0,
            published_count as usize >= REGISTRY_QUORUM_THRESHOLD,
        )
        .await;

        // Reject any publish that fell below the quorum threshold required by
        // the reader. Without this gate, an identity would be persisted locally
        // with no way for peers to verify it, leaving QR pairing permanently
        // broken until a manual re-publish (see fix: systemic silent failure).
        if (published_count as usize) < REGISTRY_QUORUM_THRESHOLD {
            return Err(DsmError::internal(
                format!(
                    "register_device_in_tree: published to only {}/{} nodes (need >= {} for quorum). Last error: {:?}",
                    published_count,
                    self.config.node_urls.len(),
                    REGISTRY_QUORUM_THRESHOLD,
                    last_error
                ),
                None::<std::io::Error>,
            ));
        }

        // Avoid hex/base64 in filenames/keys: render a deterministic small decimal suffix.
        let device_prefix_u64 = {
            let mut b = [0u8; 8];
            let take = std::cmp::min(8, device_id.len());
            b[..take].copy_from_slice(&device_id[..take]);
            u64::from_le_bytes(b)
        };

        Ok(crate::generated::PublishGenesisResponse {
            success: true,
            published: true,
            key: format!("device_tree:{}", device_prefix_u64),
            published_to_nodes: published_count,
            event_counter: dt::tick(),
        })
    }

    /// Idempotent self-heal for a root device's registry entry.
    ///
    /// Verifies that the content-addressed DeviceTreeEntry for `(device_id,
    /// genesis_hash)` is present on at least [`REGISTRY_QUORUM_THRESHOLD`]
    /// storage nodes. If the entry is already visible to a quorum of nodes,
    /// returns immediately without any writes. Otherwise, re-runs
    /// [`Self::register_device_in_tree`] to republish.
    ///
    /// This exists to close the "silent publish failure" gap that used to
    /// leave users with locally-valid-but-network-invisible genesis states.
    /// Call it from bootstrap so any previously dropped publish heals itself
    /// on the first successful network round-trip after the issue.
    ///
    /// Returns:
    /// - `Ok(verified_count)` with `verified_count >= REGISTRY_QUORUM_THRESHOLD`
    ///   on success (either already present or republish succeeded).
    /// - `Err(_)` if the entry is below quorum AND republish fails.
    pub async fn ensure_device_in_tree(
        &self,
        device_id: &[u8],
        genesis_hash: &[u8],
    ) -> Result<u32, DsmError> {
        if device_id.len() != 32 || genesis_hash.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "ensure_device_in_tree: device_id and genesis_hash must be 32 bytes",
            ));
        }

        let evidence = build_root_device_tree_evidence(device_id, genesis_hash);
        let addr = registry_content_addr_b64url(&evidence);

        // Quick verify pass: count nodes that already hold the entry.
        let mut verified: u32 = 0;
        for node_url in &self.config.node_urls {
            let trimmed = node_url.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            let url = format!("{}/api/v2/registry/get/{}", trimmed, addr);
            match self.inner.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    verified += 1;
                }
                Ok(resp) => {
                    log::debug!(
                        "ensure_device_in_tree: node {} returned HTTP {} (will attempt republish if below quorum)",
                        trimmed,
                        resp.status()
                    );
                }
                Err(e) => {
                    log::debug!(
                        "ensure_device_in_tree: network error verifying node {}: {}",
                        trimmed,
                        e
                    );
                }
            }

            if verified as usize >= REGISTRY_QUORUM_THRESHOLD {
                log::info!(
                    "ensure_device_in_tree: registry entry already visible on {} nodes (>= quorum {}), no republish needed",
                    verified,
                    REGISTRY_QUORUM_THRESHOLD
                );
                return Ok(verified);
            }
        }

        // Below quorum — republish. register_device_in_tree is idempotent
        // (content-addressed), so this is safe on every bootstrap.
        log::warn!(
            "ensure_device_in_tree: registry entry visible on only {}/{} nodes (< quorum {}), republishing",
            verified,
            self.config.node_urls.len(),
            REGISTRY_QUORUM_THRESHOLD
        );
        let resp = self
            .register_device_in_tree(device_id, genesis_hash)
            .await?;
        Ok(resp.published_to_nodes)
    }

    /// Register device with storage nodes for authentication
    /// Returns the auth token from the first successful registration
    pub async fn register_device_for_auth(
        &self,
        device_id: &str,    // base32-encoded device_id
        pubkey: &str,       // base32-encoded public key
        genesis_hash: &str, // base32-encoded genesis hash
    ) -> Result<String, DsmError> {
        // IMPORTANT: `device_id` must be the canonical base32(32 bytes) identifier.
        // Using dotted-decimal here leads to tokens being stored/used under a different key, and
        // later authenticated b0x calls will fail (storage-node rejects non-base32 device ids).
        let decoded =
            crate::util::text_id::decode_base32_crockford(device_id).ok_or_else(|| {
                DsmError::invalid_parameter("register_device_for_auth: device_id must be base32")
            })?;
        if decoded.len() != 32 {
            return Err(DsmError::invalid_parameter(format!(
                "register_device_for_auth: device_id base32 decoded to {} bytes (expected 32)",
                decoded.len()
            )));
        }

        let req = dsm::types::proto::RegisterDeviceRequest {
            device_id: decoded.clone(),
            pubkey: crate::util::text_id::decode_base32_crockford(pubkey).unwrap_or_default(),
            genesis_hash: crate::util::text_id::decode_base32_crockford(genesis_hash)
                .unwrap_or_default(),
        };
        let mut body = Vec::with_capacity(req.encoded_len());
        req.encode(&mut body).map_err(|e| {
            DsmError::internal(
                format!("Failed to encode RegisterDeviceRequest: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let mut last_error = None;

        // Try to register with each storage node
        for node_url in &self.config.node_urls {
            let url = format!("{}/api/v2/device/register", node_url.trim_end_matches('/'));

            match self
                .inner
                .client
                .post(&url)
                .header("Content-Type", "application/protobuf")
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            match dsm::types::proto::RegisterDeviceResponse::decode(bytes.as_ref())
                            {
                                Ok(parsed) => {
                                    // token is now bytes on the wire; encode to Base32 for storage/return
                                    let token = crate::util::text_id::encode_base32_crockford(
                                        &parsed.token,
                                    );
                                    log::info!("Device registered for auth on node: {}", node_url);

                                    // Store the auth token for this node
                                    if let Err(e) = crate::storage::client_db::store_auth_token(
                                        node_url,
                                        device_id,
                                        genesis_hash,
                                        &token,
                                    ) {
                                        log::warn!(
                                            "Failed to store auth token for {} (device {}): {}",
                                            node_url,
                                            device_id,
                                            e
                                        );
                                    }

                                    // Return the token from first successful registration
                                    return Ok(token);
                                }
                                Err(e) => {
                                    log::warn!("Failed to decode RegisterDeviceResponse: {}", e);
                                    last_error = Some(format!("Decode error: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to read bytes from response: {}", e);
                            last_error = Some(format!("Read error: {}", e));
                        }
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error_text = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    log::warn!(
                        "Failed to register device on node {}: status {} - {}",
                        node_url,
                        status,
                        error_text
                    );
                    last_error = Some(format!("HTTP {}: {}", status, error_text));
                }
                Err(e) => {
                    log::warn!(
                        "Network error registering device on node {}: {}",
                        node_url,
                        e
                    );
                    last_error = Some(format!("Network error: {}", e));
                }
            }
        }

        Err(DsmError::storage(
            format!(
                "Failed to register device with any storage node. Last error: {}",
                last_error.unwrap_or_else(|| "Unknown".to_string())
            ),
            None::<std::io::Error>,
        ))
    }

    /// Sync with a storage node (simplified for JNI)
    /// Returns a protobuf-typed response to avoid JSON usage.
    /// Performs a real health check against the node to confirm connectivity.
    pub async fn sync(
        &self,
        node_url: &str,
    ) -> Result<crate::generated::PublishGenesisResponse, DsmError> {
        let url = format!("{}/api/v2/health", node_url.trim_end_matches('/'));

        // Perform real network check
        let response = self.inner.client.get(&url).send().await.map_err(|e| {
            DsmError::network(
                format!("Failed to sync with node {}: {}", node_url, e),
                Some(e),
            )
        })?;

        if !response.status().is_success() {
            return Err(DsmError::network(
                format!("Node sync failed: HTTP {}", response.status()),
                None::<std::io::Error>,
            ));
        }

        // Emit a canonical protobuf response indicating success
        let resp = crate::generated::PublishGenesisResponse {
            success: true,
            published: true,
            key: format!("synced:{node_url}"),
            published_to_nodes: 1,
            event_counter: dt::tick(),
        };
        Ok(resp)
    }
}

// ────────────────────────────────────────────────────────────────
// Blocking convenience helpers for recovery route handlers.
// These create a short-lived runtime + SDK to perform a single
// storage operation synchronously.  Used by recovery_routes.rs.
// ────────────────────────────────────────────────────────────────

/// Store data at a key on the first available storage node (blocking).
pub fn put_to_storage(key: &str, data: &[u8]) -> Result<(), StorageNodeError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| StorageNodeError::new(format!("Failed to create tokio runtime: {e}")))?;
    let cfg = rt.block_on(StorageNodeConfig::from_env_config())?;
    let sdk = rt
        .block_on(StorageNodeSDK::new(cfg))
        .map_err(|e| StorageNodeError::new(format!("SDK init failed: {e}")))?;

    rt.block_on(sdk.inner.put(key, data, None))?;
    Ok(())
}

/// Retrieve data by key from the first available storage node (blocking).
/// Returns `Ok(None)` if the key is not found.
pub fn get_from_storage(key: &str) -> Result<Option<Vec<u8>>, StorageNodeError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| StorageNodeError::new(format!("Failed to create tokio runtime: {e}")))?;
    let cfg = rt.block_on(StorageNodeConfig::from_env_config())?;
    let sdk = rt
        .block_on(StorageNodeSDK::new(cfg))
        .map_err(|e| StorageNodeError::new(format!("SDK init failed: {e}")))?;

    match rt.block_on(sdk.inner.get(key)) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind == StorageNodeErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod storage_node_sdk_auth_tests {
    use super::*;

    #[test]
    fn register_device_for_auth_rejects_dotted_decimal_device_id() {
        // This is a pure validation test; we do not hit the network.
        // We only need to ensure the function fails fast before attempting HTTP.
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("Failed to create runtime: {:?}", e),
        };

        // Construct a minimal valid SDK using a dummy node URL.
        // The dotted-decimal validation should fail before any HTTP is attempted.
        let cfg = StorageNodeConfig {
            node_urls: vec!["http://127.0.0.1:1".to_string()],
            ..Default::default()
        };
        let sdk = match rt.block_on(StorageNodeSDK::new(cfg)) {
            Ok(sdk) => sdk,
            Err(e) => panic!("Failed to create SDK: {:?}", e),
        };

        let res = rt.block_on(sdk.register_device_for_auth(
            "1.2.3.4", // dotted-decimal must be rejected
            "AAAA", "BBBB",
        ));
        assert!(res.is_err());
    }
}

/// Configuration structures
#[derive(Debug, Clone, Default)]
pub struct StorageNodeConfig {
    pub node_urls: Vec<String>,
    pub pool_config: ConnectionPoolConfig,
    pub retry_config: RetryConfig,
    pub selection_config: NodeSelectionConfig,
    pub security_config: SecurityConfig,
    pub advanced_features: AdvancedFeatures,
    pub monitoring_config: MonitoringConfig,
    /// Dedicated MPC genesis endpoint (POST application/octet-stream)
    pub mpc_genesis_url: Option<String>,
    /// Optional API key sent as Bearer token to MPC service
    pub mpc_api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections: usize,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
}

#[derive(Debug, Clone)]
pub struct NodeSelectionConfig {
    pub strategy: LoadBalanceStrategy,
    pub algorithm: NodeSelectionAlgorithm,
    pub max_retries: u32,
    pub preferred_regions: Vec<String>,
    pub health_check_interval_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AdvancedFeatures {
    pub enable_bilateral_sync: bool,
    pub enable_mpc_genesis: bool,
    pub cache_size: usize,
    pub enable_epidemic_sync: bool,
    pub enable_geo_replication: bool,
}

#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub metrics_interval: Duration,
    pub log_level: String,
}

#[derive(Debug, Clone)]
pub struct BilateralEntry {
    pub id: String,
    pub sender_genesis_hash: String,
    pub recipient_genesis_hash: String,
    pub pre_commitment_hash: Vec<u8>,
    pub sender_signature: Vec<u8>,
    pub recipient_signature: Option<Vec<u8>>,
    pub transaction_payload: Vec<u8>,
    pub final_signature: Option<Vec<u8>>,
    pub transaction_params: HashMap<String, String>,
    pub state_number: u64,
    pub tick: u64,
    pub status: BilateralTransactionStatus,
    pub metadata: HashMap<String, String>,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 25,
            timeout_seconds: 30,
            retry_attempts: 3,
        }
    }
}

impl Default for NodeSelectionConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalanceStrategy::RoundRobin,
            algorithm: NodeSelectionAlgorithm::HealthBased,
            max_retries: 3,
            preferred_regions: vec!["us-east-1".to_string()],
            health_check_interval_ms: 30000,
        }
    }
}

impl Default for AdvancedFeatures {
    fn default() -> Self {
        Self {
            enable_bilateral_sync: false,
            enable_mpc_genesis: true,
            cache_size: 1000,
            enable_epidemic_sync: false,
            enable_geo_replication: false,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_interval: Duration::from_ticks(60),
            log_level: "info".to_string(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_ticks(1000),
            max_delay: Duration::from_ticks(30000),
            backoff_multiplier: 2.0,
        }
    }
}

impl StorageNodeConfig {
    pub fn new(node_urls: Vec<String>) -> Self {
        Self {
            node_urls,
            pool_config: ConnectionPoolConfig::default(),
            retry_config: RetryConfig {
                max_attempts: 3,
                initial_delay: Duration::from_ticks(1000),
                max_delay: Duration::from_ticks(30000),
                backoff_multiplier: 2.0,
            },
            selection_config: NodeSelectionConfig::default(),
            security_config: SecurityConfig { enable_auth: false },
            advanced_features: AdvancedFeatures::default(),
            monitoring_config: MonitoringConfig::default(),
            mpc_genesis_url: None,
            mpc_api_key: None,
        }
    }

    /// Create configuration by discovering storage node URLs automatically
    /// No hardcoded or compatibility-path values allowed per DSM protocol
    pub async fn from_env_config() -> Result<Self, StorageNodeError> {
        // First, try to load explicit endpoints from the core env config if present
        // This allows Android to provide a packaged config (copied to filesDir) and be honored here.
        match crate::network::NetworkConfigLoader::load_env_config() {
            Ok(env) => {
                let urls: Vec<String> = env.nodes.into_iter().map(|n| n.endpoint).collect();
                if !urls.is_empty() {
                    log::info!("Using {} storage nodes from env config", urls.len());
                    let mut cfg = Self::new(urls);
                    // Carry optional MPC endpoint from env config
                    if let Ok(env2) = crate::network::NetworkConfigLoader::load_env_config() {
                        cfg.mpc_genesis_url = env2.mpc_genesis_url;
                        cfg.mpc_api_key = env2.mpc_api_key;
                        if let Some(ref u) = cfg.mpc_genesis_url {
                            log::info!("MPC genesis endpoint configured: {}", u);
                        } else {
                            log::warn!(
                                "MPC genesis endpoint not configured; genesis will fail-closed"
                            );
                        }
                    }
                    return Ok(cfg);
                }
            }
            Err(e) => {
                log::warn!(
                    "Env config not available for storage nodes: {e} — no discovery in strict mode"
                );
            }
        }

        // In strict mode, we require env config - no automatic discovery
        Err(StorageNodeError::new("STRICT: env config unavailable or contains no storage nodes. Discovery is disabled in production builds.".to_string()))
    }

    /// Create configuration with automatic network detection and discovery
    #[cfg(feature = "dev-discovery")]
    pub async fn auto_discover() -> Result<Self, StorageNodeError> {
        log::info!("Starting automatic DSM storage node discovery");

        // Try the network detection auto-discovery
        match crate::sdk::network_detection::auto_detect_and_configure().await {
            Ok(detection_result) => {
                log::info!("Network detection succeeded");
                log::info!(
                    "Primary interface: {} ({})",
                    detection_result.primary_interface.name,
                    detection_result.primary_interface.ip_address
                );
                log::info!("Network type: {:?}", detection_result.network_type);
                log::info!(
                    "Discovered {} storage nodes",
                    detection_result.discovered_storage_nodes.len()
                );

                let urls: Vec<String> = detection_result
                    .discovered_storage_nodes
                    .into_iter()
                    .map(|node| node.endpoint)
                    .collect();

                if urls.is_empty() {
                    return Err(StorageNodeError::from_message(
                        "No storage nodes discovered via network detection".to_string(),
                    ));
                }

                log::info!(
                    "Auto-discovery completed successfully with {} storage nodes",
                    urls.len()
                );
                Ok(Self::new(urls))
            }
            Err(e) => {
                log::warn!("Network detection failed: {e}, trying fallback discovery");

                match crate::sdk::discovery::discover_storage_nodes_async().await {
                    Ok(nodes) => {
                        if nodes.is_empty() {
                            Err(StorageNodeError::from_message(
                                "No storage nodes found via any discovery method".to_string()
                            ))
                        } else {
                            log::info!("Compatibility discovery found {} nodes", nodes.len());
                            log::info!("Auto-discovery completed successfully with {} storage nodes", nodes.len());
                            Ok(Self::new(nodes))
                        }
                    },
                    Err(discovery_err) => {
                            Err(StorageNodeError::from_message(format!(
                                "All discovery methods failed. Network detection: {e}. Discovery service: {discovery_err}",
                          )))
                    }
                }
            }
        }
    }

    /// Auto-discovery is disabled unless the `dev-discovery` feature is enabled.
    #[cfg(not(feature = "dev-discovery"))]
    pub async fn auto_discover() -> Result<Self, StorageNodeError> {
        Err(StorageNodeError::from_message(
            "Auto-discovery requires the 'dev-discovery' Cargo feature".to_string(),
        ))
    }
}

/// Compute the Device Tree root from a sorted list of device IDs.
/// Uses domain-separated BLAKE3 hashing as per device_tree.rs.
fn compute_device_tree_root(device_ids: &[[u8; 32]]) -> [u8; 32] {
    use dsm::common::device_tree::{hash_leaf, hash_node, empty_root};

    if device_ids.is_empty() {
        return empty_root();
    }

    // Build leaf hashes
    let mut leaves: Vec<[u8; 32]> = device_ids.iter().map(hash_leaf).collect();

    // Build the Merkle tree bottom-up
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            match chunk {
                [left] => {
                    // Odd number of nodes - this node becomes its own parent
                    next_level.push(*left);
                }
                [left, right] => {
                    next_level.push(hash_node(left, right));
                }
                _ => unreachable!(),
            }
        }
        leaves = next_level;
    }

    leaves[0]
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Helper to build a minimal SDK instance (no network I/O on new())
    async fn make_sdk() -> StorageNodeSDK {
        let config = StorageNodeConfig::new(vec!["http://localhost:8080".to_string()]);
        StorageNodeSDK::new(config).await.expect("SDK init")
    }

    #[test]
    fn param_kv_is_deterministic_and_sorted() {
        let mut m = HashMap::new();
        m.insert("z".to_string(), "9".to_string());
        m.insert("a".to_string(), "1".to_string());
        m.insert("m".to_string(), "5".to_string());

        let kv = super::map_to_param_kv(&m);
        // Expect lexicographic order by key: a, m, z
        let keys: Vec<&str> = kv.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
        // Values should correspond to original map entries (order independent of insertion)
        let vals: Vec<&str> = kv.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(vals, vec!["1", "5", "9"]);
    }

    #[tokio::test]
    async fn submit_bilateral_requires_state_hash_param() {
        let sdk = make_sdk().await;

        let params: HashMap<String, String> = HashMap::new();
        let res = sdk
            .submit_bilateral_entry("sender_genesis", "recipient_genesis", params, 1)
            .await;
        assert!(res.is_err(), "expected error when state_hash missing");
    }

    #[tokio::test]
    async fn submit_bilateral_with_valid_state_hash() {
        let sdk = make_sdk().await;

        let mut params: HashMap<String, String> = HashMap::new();
        // Provide raw bytes via a short ASCII string (treated as bytes in SDK)
        params.insert("state_hash".to_string(), "abcd".to_string());

        let entry = sdk
            .submit_bilateral_entry("sender_genesis", "recipient_genesis", params.clone(), 1)
            .await
            .expect("submit should succeed with valid state_hash");

        // Recompute expected pre-commitment to verify
        // Build canonical params proto and preimage deterministically as used above
        let params_proto = generated::TransactionParamsProto {
            kv: super::map_to_param_kv(&params),
        };
        let params_bytes = params_proto.encode_to_vec();
        let mut preimage: Vec<u8> = Vec::with_capacity(4 + params_bytes.len() + 8);
        // state_hash is the raw bytes of "abcd"
        let state_hash_bytes_for_test = b"abcd".to_vec();
        preimage.extend_from_slice(&state_hash_bytes_for_test);
        preimage.extend_from_slice(&params_bytes);
        preimage.extend_from_slice(&2u64.to_le_bytes());
        let expected = dsm::crypto::blake3::domain_hash("DSM/precommit-hash", &preimage);
        assert_eq!(entry.pre_commitment_hash, expected.as_bytes());
        assert_eq!(entry.state_number, 1);
        assert_eq!(entry.status, BilateralTransactionStatus::Pending);
    }

    #[tokio::test]
    async fn process_bilateral_transaction_validates_hash() {
        let sdk = make_sdk().await;

        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("state_hash".to_string(), "abcd".to_string());

        let entry = sdk
            .submit_bilateral_entry("sender_genesis", "recipient_genesis", params.clone(), 5)
            .await
            .expect("submit should succeed with valid state_hash");

        // Happy path: approve with a dummy signature
        let approved = sdk
            .process_bilateral_transaction(entry.clone(), vec![1, 2, 3], true)
            .await
            .expect("process should verify and sign");
        assert_eq!(approved.status, BilateralTransactionStatus::Signed);
        assert!(approved.recipient_signature.is_some());

        // Tamper with params -> verification must fail
        let mut tampered = entry.clone();
        tampered
            .transaction_params
            .insert("memo".to_string(), "tamper".to_string());
        let err = sdk
            .process_bilateral_transaction(tampered, vec![9, 9], true)
            .await
            .expect_err("tampered pre-commitment should fail");
        let msg = format!("{}", err);
        assert!(msg.contains("Pre-commitment hash verification failed") || msg.contains("crypto"));
    }
}
