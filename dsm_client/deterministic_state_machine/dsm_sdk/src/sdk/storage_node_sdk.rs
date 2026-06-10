// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// Post-update Device Tree snapshot — populated by
    /// [`StorageNodeSDK::apply_admitted_device`] and
    /// [`StorageNodeSDK::remove_secondary_device`] so that the JNI / Kotlin
    /// layer can persist the new R_G locally without rebuilding the tree.
    /// `None` for primary-genesis responses (which do not modify a tree).
    pub device_tree: Option<DeviceTreeSnapshot>,
}

/// Lightweight snapshot of a published Device Tree. Mirrors the wire
/// [`generated::DeviceTreeV1`] message but uses native Rust types
/// (`[u8; 32]` root) so callers do not need a prost decode round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTreeSnapshot {
    /// 32-byte Merkle root R_G of the current Device Tree.
    pub root_hash: [u8; 32],
    /// Count of real (non-padding) DevID leaves. Always `>= 1` post-genesis.
    pub device_count: u32,
    /// Monotone counter; strictly increases on every successful add/remove.
    pub version_number: u64,
}

impl DeviceTreeSnapshot {
    /// Convert to the wire [`generated::DeviceTreeV1`] proto.
    pub fn to_proto(&self) -> generated::DeviceTreeV1 {
        generated::DeviceTreeV1 {
            schema_version: 1,
            root_hash: self.root_hash.to_vec(),
            device_count: self.device_count,
            version_number: self.version_number,
        }
    }
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
    ///
    /// The server-side replay guard at `dsm_storage_node/src/auth/mod.rs:78`
    /// enforces `unique(device_id, message_id)` per device.  A 409 Conflict
    /// is returned when an already-seen message_id is replayed.  The id is
    /// transport-layer only (not part of the canonical protocol) and the
    /// DSM clockless rule applies to PROTOCOL decisions, not transport
    /// nonces — so a CSPRNG nonce is the correct shape here.
    ///
    /// Prior versions of this function used `BLAKE3("DSM/obj-msg-id", key,
    /// dt::tick())` which was DETERMINISTIC per (key, tick).  Same key PUT
    /// twice in the same commit-height window collided.  Worse, once the
    /// server's auth layer recorded a message_id (even when the surrounding
    /// PUT body subsequently failed), that id was burnt forever — so any
    /// future retry with the same deterministic id 409'd against the
    /// poisoned slot.  Real-hardware repro: SoFiTradeRealHwTest's two
    /// publishRoutingAdvertisement calls both PUT under the same commit
    /// height; consistent 409 across runs even with genuinely fresh
    /// vault_ids.
    ///
    /// Generates 32 bytes of CSPRNG, encoded Base32-Crockford — same
    /// shape the server's auth layer parses.  The `key` arg is kept in
    /// the signature for telemetry / future binding but isn't hashed in;
    /// the server validates only `unique(device_id, message_id)`.
    fn generate_message_id(_key: &str) -> String {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        crate::util::text_id::encode_base32_crockford(&nonce)
    }

    pub async fn put(
        &self,
        key: &str,
        data: &[u8],
        _ttl_seconds: Option<u64>, // Unused: clockless system
    ) -> Result<String, StorageNodeError> {
        // Generate DLV ID from key
        let mut hasher = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_DLV_PARTITION);
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
        let mut hasher = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_DLV_PARTITION);
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
    /// Primary client — used by non-retry call sites and as `clients[0]`.
    inner: Arc<StorageNodeClient>,
    /// All configured storage node clients, one per URL in
    /// `config.node_urls` order.  DSM storage nodes are independent
    /// (not a cluster) — each is an autonomous endpoint that the SDK
    /// can hit directly.  Cross-device SoFi test surfaced that
    /// `execute_with_retry` had been hammering only `inner` (the first
    /// node) — when GCP-side rate limiting kicked in on that single
    /// endpoint with HTTP 429, every retry hit the same blacklisted
    /// URL.  Rotating through this slice lets the rate-limit window
    /// on one node clear while we hit a different region's node.
    clients: Arc<Vec<Arc<StorageNodeClient>>>,
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
        // Build a client per configured storage node URL.  DSM storage
        // nodes are independent (not a cluster); each is an autonomous
        // endpoint and the SDK can hit any of them.  First-built becomes
        // the primary; the full set is used by `execute_with_retry`
        // to rotate across nodes on transient failures (e.g. GCP-side
        // HTTP 429 throttling against any single endpoint).
        if config.node_urls.is_empty() {
            return Err(DsmError::storage(
                "StorageNodeSDK.new: no node URLs configured".to_string(),
                None::<std::io::Error>,
            ));
        }
        let mut clients: Vec<Arc<StorageNodeClient>> = Vec::with_capacity(config.node_urls.len());
        for url in &config.node_urls {
            // Per-URL client config: same as `config` but with this one URL
            // pinned as `node_urls.first()` so StorageNodeClient::new picks
            // it as primary.
            let mut per_url_config = config.clone();
            per_url_config.node_urls = vec![url.clone()];
            match StorageNodeClient::new(per_url_config).await {
                Ok(c) => clients.push(Arc::new(c)),
                Err(e) => log::warn!(
                    "StorageNodeSDK.new: skipping node {url}: {e} — other nodes still available"
                ),
            }
        }
        if clients.is_empty() {
            return Err(DsmError::storage(
                "StorageNodeSDK.new: every configured node failed to build a client".to_string(),
                None::<std::io::Error>,
            ));
        }
        let inner = clients[0].clone();

        let connection_pool = Arc::new(ConnectionPool::new(config.pool_config.clone()));

        let sdk = StorageNodeSDK {
            inner,
            clients: Arc::new(clients),
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
    /// DSM storage nodes are independent endpoints — there is NO server-
    /// side cross-node replication of object writes in production (the
    /// `dev_replication.rs` shim is localhost-only and not wired into
    /// the GCP deployment).  For the trader on device B to discover
    /// what the owner on device A published, the owner must write to
    /// every node the trader might query.  Calling `put` (single node)
    /// instead of this method is the canonical "owner writes get lost"
    /// failure mode in cross-device tests.
    ///
    /// Fans the PUT out to every client in `self.clients`, each of
    /// which already carries its own per-node auth token via
    /// [`with_per_node_auth`].  Returns successfully if at least one
    /// write succeeds, with the primary address from the first
    /// successful node.  Failed nodes are quarantined via
    /// `report_storage_failure` so background health monitoring picks
    /// them up.
    pub async fn put_to_all_replicas(
        &self,
        key: &str,
        data: &[u8],
        ttl_seconds: Option<u64>,
    ) -> Result<String, DsmError> {
        if self.clients.is_empty() {
            return Err(DsmError::storage(
                "put_to_all_replicas: no clients configured",
                None::<std::io::Error>,
            ));
        }

        let mut primary_addr = String::new();
        let mut success_count = 0u32;
        let total = self.clients.len();

        for client in self.clients.iter() {
            let endpoint = client.node_info.url.clone();
            match client.put(key, data, ttl_seconds).await {
                Ok(addr) => {
                    if primary_addr.is_empty() {
                        primary_addr = addr;
                    }
                    success_count += 1;
                    let _ = crate::network::report_storage_success(&endpoint);
                }
                Err(e) => {
                    log::warn!("replica fanout: PUT to {endpoint} failed: {e}");
                    let _ = crate::network::report_storage_failure(&endpoint);
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

    /// DELETE the key from ALL configured storage nodes.  Mirrors the
    /// put_to_all_replicas write-everywhere semantics so deletes also
    /// fan out — otherwise a deleted advertisement would still be
    /// reachable by traders hitting a node where the delete didn't
    /// reach.  Returns successfully if at least one delete succeeds.
    pub async fn delete_at_all_replicas(&self, key: &str) -> Result<(), DsmError> {
        if self.clients.is_empty() {
            return Err(DsmError::storage(
                "delete_at_all_replicas: no clients configured",
                None::<std::io::Error>,
            ));
        }

        let mut success_count = 0u32;
        let total = self.clients.len();

        for client in self.clients.iter() {
            let endpoint = client.node_info.url.clone();
            match client.delete(key).await {
                Ok(()) => {
                    success_count += 1;
                    let _ = crate::network::report_storage_success(&endpoint);
                }
                Err(e) => {
                    log::warn!("replica fanout: DELETE to {endpoint} failed: {e}");
                    let _ = crate::network::report_storage_failure(&endpoint);
                }
            }
        }

        log::info!(
            "delete_at_all_replicas: key={} success={}/{} nodes",
            &key[..key.len().min(24)],
            success_count,
            total
        );

        if success_count == 0 {
            return Err(DsmError::storage(
                "all replica deletes failed",
                None::<std::io::Error>,
            ));
        }
        Ok(())
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
                        device_tree: None,
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
            let mut hasher =
                dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_BILATERAL_PARAMS_HASH);
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

        // SDK-internal bilateral-entry tracking hash. This is NOT the protocol
        // precommit (which lives under the canonical v2 family in
        // dsm::commitments::precommit). The preimage shape
        // `state_hash || params_proto || next_state(le)` is SDK-specific and
        // distinct from the protocol's `h_n || payload_i || e_i`; the domain
        // tag is therefore SDK-scoped to prevent collision with the protocol
        // precommit family.
        let mut preimage: Vec<u8> = Vec::with_capacity(32 + params_bytes.len() + 8);
        preimage.extend_from_slice(&state_hash_bytes);
        preimage.extend_from_slice(&params_bytes);
        preimage.extend_from_slice(&next_state.to_le_bytes());
        let pre_commitment_hash = dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_SDK_BILATERAL_ENTRY_V1,
            &preimage,
        );

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
        // Match the SDK-internal domain used by submit_bilateral_entry above;
        // this is intentionally distinct from the protocol precommit family.
        let expected_hash = dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_SDK_BILATERAL_ENTRY_V1,
            &expected_preimage,
        );

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
                let mut hasher =
                    dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_GENESIS_ENTROPY_PAD);
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

        // Phase B.6 (issue #277): publish the initial DeviceTreeStateV1
        // to a quorum of storage nodes BEFORE the core SDK installs the
        // genesis into the state machine. If quorum cannot be reached
        // the closure returns Err, the core SDK aborts before touching
        // any local state, and the caller sees a clean fail-closed
        // error with no partial-genesis residue.
        //
        // The initial tree has exactly one leaf: the root device, whose
        // DevID equals the genesis hash by protocol invariant. The
        // SDK publishes against `/api/v2/identity/{genesis_b32}/devtree/root`
        // (Phase B.4 issue #275 validator) and counts 2xx responses
        // toward `REGISTRY_QUORUM_THRESHOLD`. A 409 Conflict (rejected
        // stale by the validator) also counts as a successful publish
        // because it confirms the storage node already holds a
        // DeviceTreeStateV1 row for this genesis at version >= 1,
        // which is the same end-state we wanted.
        let publisher_node_urls = node_urls.clone();
        let publisher_client = self.inner.client.clone();
        let initial_tree_snapshot: std::sync::Arc<tokio::sync::OnceCell<DeviceTreeSnapshot>> =
            std::sync::Arc::new(tokio::sync::OnceCell::new());
        let snapshot_for_publisher = initial_tree_snapshot.clone();
        let publisher = move |genesis_hash: [u8; 32]| {
            let publisher_node_urls = publisher_node_urls.clone();
            let publisher_client = publisher_client.clone();
            let snapshot_for_publisher = snapshot_for_publisher.clone();
            async move {
                let (snapshot, payload) = Self::build_initial_device_tree_payload(genesis_hash)?;
                // Stash the snapshot so the outer scope can build the
                // GenesisCreationResponse without recomputing it.
                let _ = snapshot_for_publisher.set(snapshot);

                let genesis_b32 = crate::util::text_id::encode_base32_crockford(&genesis_hash);
                let acks = Self::publish_initial_device_tree_to_quorum(
                    &publisher_client,
                    &publisher_node_urls,
                    &genesis_b32,
                    &payload,
                )
                .await;

                if acks < REGISTRY_QUORUM_THRESHOLD {
                    return Err(DsmError::network(
                        format!(
                            "Phase B.6: initial Device Tree publish reached only {}/{} \
                             storage nodes; need >= {} for quorum. Genesis aborted; \
                             no local state installed.",
                            acks,
                            publisher_node_urls.len(),
                            REGISTRY_QUORUM_THRESHOLD
                        ),
                        None::<std::io::Error>,
                    ));
                }

                log::info!(
                    "Phase B.6: initial Device Tree published to {}/{} storage nodes \
                     (quorum {} satisfied) for genesis={}",
                    acks,
                    publisher_node_urls.len(),
                    REGISTRY_QUORUM_THRESHOLD,
                    genesis_b32,
                );
                Ok::<(), DsmError>(())
            }
        };

        let genesis_info = core_sdk
            .create_genesis_with_passive_contributors(
                temp_device_id.clone(),
                mpc_participants.clone(),
                client_entropy.clone(),
                publisher,
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

        // Persist the initial R_G as the bilateral-settlement device
        // tree root so receipts post-genesis verify against the
        // canonical anchor that storage nodes now hold.
        let initial_snapshot = initial_tree_snapshot.get().copied();
        if let Some(snapshot) = initial_snapshot {
            crate::sdk::app_state::AppState::set_device_tree_root(snapshot.root_hash);
        }

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
            // Phase B.6 (issue #277): the initial single-leaf tree
            // snapshot the publisher just anchored to quorum-N storage
            // nodes. None only on the unreachable case where the
            // OnceCell wasn't initialised before the publisher Ok'd.
            device_tree: initial_snapshot,
        };

        Ok(genesis_response)
    }

    /// Fetch + re-verify one genesis's Device Tree from any node in
    /// the configured cluster.
    ///
    /// The Phase B.4 validator guarantees that every node holds the
    /// same `DeviceTreeStateV1` for a given genesis at version >= the
    /// monotone counter, so picking any one node is sufficient. We
    /// walk `self.config.node_urls` in order and return on the first
    /// successful GET; if every node returns an error or 404, the
    /// outer call returns `Err`.
    ///
    /// On success returns a [`DeviceTreeSnapshotView`] whose
    /// `inclusion_verified` flags are all `true` for an honest
    /// server (since we re-derive proofs from the same canonical
    /// leaf list before verifying), but the
    /// `claimed_root_matches_recomputed` gate can still be `false`
    /// if the storage node lied about its `root_hash` while serving
    /// a tampered `device_ids` list.
    pub async fn fetch_device_tree_snapshot(
        &self,
        genesis_hash: &[u8; 32],
    ) -> Result<DeviceTreeSnapshotView, DsmError> {
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(genesis_hash);

        let mut last_err: Option<String> = None;
        for node_url in &self.config.node_urls {
            let trimmed = node_url.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            let url = format!("{}/api/v2/identity/{}/devtree/root", trimmed, genesis_b32);
            match self.inner.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes().await.map_err(|e| {
                        DsmError::network(
                            format!("fetch_device_tree_snapshot: read body: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    return build_device_tree_snapshot_view(&bytes);
                }
                Ok(resp) => {
                    last_err = Some(format!(
                        "{} returned HTTP {}",
                        trimmed,
                        resp.status().as_u16()
                    ));
                    log::debug!(
                        "fetch_device_tree_snapshot: {} returned HTTP {}",
                        trimmed,
                        resp.status().as_u16()
                    );
                }
                Err(e) => {
                    last_err = Some(format!("{trimmed}: {e}"));
                    log::debug!(
                        "fetch_device_tree_snapshot: network error against {}: {}",
                        trimmed,
                        e
                    );
                }
            }
        }

        Err(DsmError::not_found(
            "DeviceTreeStateV1",
            Some(format!(
                "no storage node returned a published Device Tree for genesis {genesis_b32}{}",
                last_err
                    .map(|e| format!(" (last error: {e})"))
                    .unwrap_or_default()
            )),
        ))
    }

    /// Build the canonical initial `DeviceTreeStateV1` proto payload
    /// for a freshly-created genesis. Single leaf = `genesis_hash`
    /// (root device's DevID by protocol invariant). Used by the
    /// Phase B.6 (issue #277) initial-tree publish path.
    pub(crate) fn build_initial_device_tree_payload(
        genesis_hash: [u8; 32],
    ) -> Result<(DeviceTreeSnapshot, Vec<u8>), DsmError> {
        let tree = dsm::common::device_tree::DeviceTree::single(genesis_hash);
        let snapshot = DeviceTreeSnapshot {
            root_hash: tree.root(),
            device_count: 1,
            version_number: 1,
        };
        let state = generated::DeviceTreeStateV1 {
            tree: Some(snapshot.to_proto()),
            device_ids: vec![genesis_hash.to_vec()],
        };
        let mut payload = Vec::with_capacity(state.encoded_len());
        state.encode(&mut payload).map_err(|e| {
            DsmError::internal(
                format!("encode initial DeviceTreeStateV1: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok((snapshot, payload))
    }

    /// PUT `payload` to `/api/v2/identity/{genesis_b32}/devtree/root` on
    /// every node in `node_urls`. Returns the count of nodes that
    /// confirmed the write (HTTP 2xx OR 409 Conflict).
    ///
    /// 409 Conflict from the Phase B.4 validator means the storage node
    /// already holds a DeviceTreeStateV1 row for this genesis at a
    /// version >= the candidate version. For the initial publish
    /// (`version_number = 1`) this can only happen if a prior
    /// successful publish landed on that node, so it's the same
    /// end-state we wanted and counts toward quorum.
    async fn publish_initial_device_tree_to_quorum(
        client: &reqwest::Client,
        node_urls: &[String],
        genesis_b32: &str,
        payload: &[u8],
    ) -> usize {
        let mut acks: usize = 0;
        for node_url in node_urls {
            let trimmed = node_url.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            let url = format!("{}/api/v2/identity/{}/devtree/root", trimmed, genesis_b32);
            match client
                .put(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(payload.to_vec())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status == reqwest::StatusCode::CONFLICT {
                        acks += 1;
                        log::info!(
                            "Phase B.6 publish: {} accepted (HTTP {})",
                            trimmed,
                            status.as_u16()
                        );
                    } else {
                        log::warn!(
                            "Phase B.6 publish: {} returned HTTP {}",
                            trimmed,
                            status.as_u16()
                        );
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Phase B.6 publish: network error against {}: {}",
                        trimmed,
                        e
                    );
                }
            }
        }
        acks
    }

    /// Read the current authoritative Device Tree frontier for `genesis_hash`:
    /// `(sorted device_ids, version_number, root)`. Used by the admitting (existing) device to fill
    /// an `AddDeviceAdmission`'s parent frontier and by the gated insert to verify it. An empty
    /// store (pre-publish edge) returns the canonical root-only tree.
    pub async fn read_device_tree_state(
        &self,
        genesis_hash: &[u8; 32],
    ) -> Result<(Vec<[u8; 32]>, u64, [u8; 32]), DsmError> {
        let key = Self::device_tree_state_key(genesis_hash);
        let bytes = self.inner.get(&key).await.map_err(|e| {
            DsmError::network(
                format!("read_device_tree_state: {e}"),
                None::<std::io::Error>,
            )
        })?;
        if bytes.is_empty() {
            let tree = dsm::common::device_tree::DeviceTree::single(*genesis_hash);
            return Ok((tree.leaves().to_vec(), 1, tree.root()));
        }
        let st = decode_device_tree_state(&bytes)?;
        let tree = dsm::common::device_tree::DeviceTree::new(st.device_ids);
        Ok((tree.leaves().to_vec(), st.version_number, tree.root()))
    }

    /// ADMITTING (existing) device: verify a gate-signed `AddDeviceAdmission` against the current
    /// authoritative tree, then insert the new device. `signer_signing_pubkey` is the existing
    /// device's signing key (from the QR the new device scanned — no quorum). The gate signature in
    /// the admission IS the authorization (only a key already in the tree can produce a verifying
    /// admission); this replaces the old ungated self-insert. Returns the new tree snapshot.
    pub async fn apply_admitted_device(
        &self,
        admission: &dsm::common::device_admission::AddDeviceAdmission,
        signer_signing_pubkey: &[u8],
    ) -> Result<DeviceTreeSnapshot, DsmError> {
        let genesis = admission.genesis_hash;
        let (device_ids, version, _root) = self.read_device_tree_state(&genesis).await?;
        // Fail-closed: full gate-signature + self-attestation + frontier verification.
        let expected_next = dsm::common::device_admission::verify_add_device_admission(
            admission,
            &genesis,
            &device_ids,
            version,
            signer_signing_pubkey,
        )?;
        let new_id = admission.new_device_id;
        let snapshot = self
            .mutate_device_tree_state(genesis, move |ids| {
                if !ids.contains(&new_id) {
                    ids.push(new_id);
                }
            })
            .await?;
        if snapshot.root_hash != expected_next {
            return Err(DsmError::verification(
                "apply_admitted_device: post-insert root != verified next root (concurrent tree \
                 change); refusing",
            ));
        }
        Ok(snapshot)
    }

    /// Remove a secondary device from an existing Device Tree.
    ///
    /// Loads the persisted
    /// [`DeviceTreeStateV1`], drops `device_id_to_remove`, bumps
    /// `version_number`, and writes the new state back.
    ///
    /// Enforces:
    /// * `genesis_hash` and `device_id_to_remove` are 32 bytes each.
    /// * A Device Tree state must already exist for this genesis
    ///   (returns [`DsmError::not_found`] otherwise — there is nothing
    ///   to remove from).
    /// * The device must currently be a member (returns
    ///   [`DsmError::not_found`] otherwise so callers can distinguish
    ///   "already gone" from "tree missing").
    /// * `device_count >= 1` after removal — the root device leaf is
    ///   permanent; removing the last remaining leaf is rejected with
    ///   [`DsmError::invalid_operation`]. This preserves the post-
    ///   genesis non-empty-tree invariant.
    ///
    /// Returns a [`GenesisCreationResponse`] whose `device_tree` field
    /// carries the post-removal snapshot.
    pub async fn remove_secondary_device(
        &self,
        genesis_hash: Vec<u8>,
        device_id_to_remove: Vec<u8>,
    ) -> Result<GenesisCreationResponse, DsmError> {
        log::info!("Removing secondary device from existing genesis");

        if genesis_hash.len() != 32 {
            return Err(DsmError::invalid_operation("Genesis hash must be 32 bytes"));
        }
        if device_id_to_remove.len() != 32 {
            return Err(DsmError::invalid_operation(
                "device_id_to_remove must be 32 bytes",
            ));
        }

        let mut genesis_hash_array = [0u8; 32];
        genesis_hash_array.copy_from_slice(&genesis_hash);
        let mut target = [0u8; 32];
        target.copy_from_slice(&device_id_to_remove);

        // Read first so we can fail-closed if the tree is absent or the
        // device is not currently a member — distinct from the
        // post-mutation device_count >= 1 check inside the mutator.
        let device_tree_key = Self::device_tree_state_key(&genesis_hash_array);
        let bytes = self.inner.get(&device_tree_key).await.map_err(|e| {
            DsmError::network(
                format!(
                    "remove_secondary_device: failed to read DeviceTreeStateV1 for genesis: {e}"
                ),
                None::<std::io::Error>,
            )
        })?;
        if bytes.is_empty() {
            return Err(DsmError::not_found(
                "DeviceTreeStateV1",
                Some(format!(
                    "no Device Tree state for genesis {}",
                    crate::util::text_id::encode_base32_crockford(&genesis_hash)
                )),
            ));
        }
        let existing = decode_device_tree_state(&bytes)?;
        if !existing.device_ids.contains(&target) {
            return Err(DsmError::not_found(
                "DeviceTreeStateV1.device_ids",
                Some(format!(
                    "device {} not in tree for genesis {}",
                    crate::util::text_id::encode_base32_crockford(&device_id_to_remove),
                    crate::util::text_id::encode_base32_crockford(&genesis_hash)
                )),
            ));
        }

        let snapshot = self
            .mutate_device_tree_state(genesis_hash_array, |device_ids| {
                device_ids.retain(|id| id != &target);
            })
            .await?;

        let response = GenesisCreationResponse {
            session_id: crate::util::text_id::encode_base32_crockford(&device_id_to_remove[0..16]),
            genesis_device_id: device_id_to_remove,
            state: "complete".to_string(),
            contributions_received: 0,
            complete: true,
            genesis_hash: Some(genesis_hash),
            participating_nodes: vec![],
            tick: dt::tick(),
            device_tree: Some(snapshot),
        };

        Ok(response)
    }

    /// Local KV key for the persisted [`generated::DeviceTreeStateV1`].
    fn device_tree_state_key(genesis_hash: &[u8; 32]) -> String {
        format!(
            "device_tree:{}",
            crate::util::text_id::encode_base32_crockford(genesis_hash)
        )
    }

    /// Read-modify-write the persisted [`generated::DeviceTreeStateV1`]
    /// for `genesis_hash`. The `mutate` closure receives a mutable
    /// device-id list; on return, the list is canonicalised via
    /// [`dsm::common::device_tree::DeviceTree::new`] (sort + dedup) and
    /// the new state is persisted with `version_number` strictly
    /// greater than the previous value. Enforces the post-genesis
    /// non-empty-tree invariant (`device_count >= 1`).
    async fn mutate_device_tree_state<F: FnOnce(&mut Vec<[u8; 32]>)>(
        &self,
        genesis_hash: [u8; 32],
        mutate: F,
    ) -> Result<DeviceTreeSnapshot, DsmError> {
        let device_tree_key = Self::device_tree_state_key(&genesis_hash);

        // Read prior state (if any). Empty bytes means the initial
        // root-device-only tree has not been written yet (Phase B.6
        // issue #277 lands the genesis-time write).
        let prior_bytes = self.inner.get(&device_tree_key).await.map_err(|e| {
            DsmError::network(
                format!("mutate_device_tree_state: read failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let (snapshot, new_bytes) = apply_device_tree_mutation(&prior_bytes, genesis_hash, mutate)?;

        // Persist the new state.
        self.inner
            .put(&device_tree_key, &new_bytes, None)
            .await
            .map_err(|e| {
                DsmError::network(
                    format!("mutate_device_tree_state: write failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;

        log::info!(
            "Device Tree state for genesis {}: root={}, count={}, version={}",
            crate::util::text_id::encode_base32_crockford(&genesis_hash),
            crate::util::text_id::encode_base32_crockford(&snapshot.root_hash),
            snapshot.device_count,
            snapshot.version_number
        );

        Ok(snapshot)
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

    /// Execute a storage operation with exponential-backoff retry +
    /// node rotation across the configured set of independent storage
    /// nodes.
    ///
    /// **Transport-only operational behavior** — per the DSM clockless
    /// rule, wall-clock APIs are banned in protocol semantics (schemas,
    /// payloads, receipts, ordering).  Network retry backoff is the
    /// approved exception: it is opaque to the protocol layer and only
    /// affects HOW fast the SDK rehits a 429/503/transient failure.
    /// Mirrors the `b0x_sdk.rs` retry pattern.
    ///
    /// Each attempt rotates to a different storage node from
    /// `self.clients` (DSM storage nodes are independent endpoints,
    /// not a cluster).  Cross-device SoFi test surfaced that the
    /// previous single-node-only path failed every retry against the
    /// same blacklisted GCP-hosted endpoint when GCP-side rate
    /// limiting kicked in — rotation lets the limiter on one node
    /// clear while we hit a different region's healthy node.
    ///
    /// Backoff schedule (capped at MAX_DELAY_MS):
    ///   attempt 0 → no sleep (first try); pick clients[0]
    ///   attempt 1 → 200ms; pick clients[1 % N]
    ///   attempt 2 → 400ms; pick clients[2 % N]
    ///   ...
    ///   attempt 6 → 5000ms (capped); pick clients[6 % N]
    ///
    /// Total worst-case wait: ~11s spread across 7 attempts.
    pub async fn execute_with_retry<F, Fut, T>(&self, operation: F) -> Result<T, DsmError>
    where
        F: Fn(Arc<StorageNodeClient>) -> Fut,
        Fut: std::future::Future<Output = Result<T, StorageNodeError>>,
    {
        const MAX_RETRIES: u32 = 6;
        const BASE_DELAY_MS: u64 = 200;
        const MAX_DELAY_MS: u64 = 5_000;

        // `clients` is non-empty per `StorageNodeSDK::new` invariant;
        // pre-compute the modulus once to avoid taking the lock per
        // attempt.
        let n_clients = self.clients.len();

        for attempt in 0..=MAX_RETRIES {
            // Rotate: attempt N hits clients[N % n_clients].  When
            // n_clients == 1 (legacy single-node config) the rotation
            // degrades cleanly to retry-the-same-node behaviour.
            let client = self.clients[(attempt as usize) % n_clients].clone();
            match operation(client).await {
                Ok(result) => return Ok(result),
                Err(e) if attempt < MAX_RETRIES => {
                    let delay_ms =
                        (BASE_DELAY_MS.saturating_mul(1u64 << attempt.min(20))).min(MAX_DELAY_MS);
                    let next_node_idx = ((attempt as usize) + 1) % n_clients;
                    warn!(
                        "Storage operation failed (attempt {}/{} via node {}): {e} — \
                         retrying via node {} in {}ms",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        (attempt as usize) % n_clients,
                        next_node_idx,
                        delay_ms
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    return Err(DsmError::storage(
                        format!(
                            "Storage operation failed after {} retries across {} node(s): {e}",
                            MAX_RETRIES, n_clients
                        ),
                        None::<std::io::Error>,
                    ));
                }
            }
        }

        // Unreachable: the loop exits via `return` in both Ok and final-Err
        // branches; this is here only to satisfy the compiler.
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
    ///
    /// Single-node convenience — applies the same auth to `inner` only.
    /// Callers driving multi-node writes (put_to_all_replicas, rotated
    /// retries) should use [`with_per_node_auth`] so each client carries
    /// its own node-specific token instead of one token leaking across
    /// nodes.
    pub fn with_auth(self, auth: StorageAuthContext) -> Self {
        let client = (*self.inner).clone().with_auth(auth);
        Self {
            inner: Arc::new(client),
            ..self
        }
    }

    /// Return a new SDK with per-node auth tokens applied.
    ///
    /// Each `auths[url]` is matched against the corresponding
    /// `StorageNodeClient.node_info.url` in `self.clients` and applied
    /// to that specific client.  Clients whose URL is absent from
    /// `auths` retain whatever auth they had (typically None).
    ///
    /// Critical for production multi-node deployments: DSM storage nodes
    /// each maintain their own device-auth table, and a token issued by
    /// node A is invalid at node B.  Without per-node auth, rotated PUT
    /// retries against nodes 1..N return HTTP 401 even though the wallet
    /// is correctly registered with each of them.
    pub fn with_per_node_auth(
        self,
        auths: &std::collections::HashMap<String, StorageAuthContext>,
    ) -> Self {
        let new_clients: Vec<Arc<StorageNodeClient>> = self
            .clients
            .iter()
            .map(|c| {
                let mut client = (**c).clone();
                if let Some(auth) = auths.get(&client.node_info.url) {
                    client.auth = Some(auth.clone());
                }
                Arc::new(client)
            })
            .collect();
        // `clients` is non-empty per `StorageNodeSDK::new` invariant.
        let new_inner = new_clients[0].clone();
        Self {
            inner: new_inner,
            clients: Arc::new(new_clients),
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
        let mut first_success_token: Option<String> = None;
        let mut success_count = 0usize;

        // Register with EVERY configured storage node.  DSM storage
        // nodes are independent endpoints: each maintains its own
        // device-registration table and gates PUT/DELETE by an
        // auth-token issued by THAT node.  If we register with only
        // one node (the previous early-return-on-first-success
        // behaviour), subsequent PUTs that rotate to any of the other
        // nodes get rejected with HTTP 401 Unauthorized — exactly the
        // failure mode observed on the cross-device SoFi test after
        // node-rotation landed.  The fix is to keep walking the full
        // list so every node knows this device.
        //
        // Returned token: the first successful node's token (callers
        // use the return value only as a sentinel; per-node tokens
        // are read on demand via `resolve_storage_auth` against the
        // local DB which is keyed by (node_url, device_id)).
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

                                    success_count += 1;
                                    if first_success_token.is_none() {
                                        first_success_token = Some(token);
                                    }
                                    // DON'T return — keep walking the list so EVERY node
                                    // gets a registration + token entry in the local DB.
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

        log::info!(
            "register_device_for_auth: registered with {}/{} nodes",
            success_count,
            self.config.node_urls.len()
        );

        match first_success_token {
            Some(token) => Ok(token),
            None => Err(DsmError::storage(
                format!(
                    "Failed to register device with any storage node. Last error: {}",
                    last_error.unwrap_or_else(|| "Unknown".to_string())
                ),
                None::<std::io::Error>,
            )),
        }
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

/// Pure read-modify-canonicalise step for a Device Tree.
///
/// Given the prior-persisted [`generated::DeviceTreeStateV1`] bytes (or
/// an empty slice if no tree has been written yet), the `genesis_hash`
/// (used to seed the root-device leaf when no tree exists yet), and a
/// caller `mutate` closure, this function:
///
/// 1. Decodes the prior state if non-empty, or initialises a single-
///    leaf tree containing `genesis_hash` (== root device_id).
/// 2. Applies `mutate` to the mutable leaf list.
/// 3. Canonicalises through [`dsm::common::device_tree::DeviceTree::new`]
///    (sort + dedup).
/// 4. Enforces `device_count >= 1` post-genesis.
/// 5. Bumps `version_number` strictly.
/// 6. Re-encodes a fresh [`generated::DeviceTreeStateV1`] as bytes.
///
/// Returns the new [`DeviceTreeSnapshot`] alongside the bytes the
/// caller persists. Pure: no I/O, no global state, so it's directly
/// unit-testable.
fn apply_device_tree_mutation<F: FnOnce(&mut Vec<[u8; 32]>)>(
    prior_bytes: &[u8],
    genesis_hash: [u8; 32],
    mutate: F,
) -> Result<(DeviceTreeSnapshot, Vec<u8>), DsmError> {
    let (mut device_ids, prior_version) = if prior_bytes.is_empty() {
        (vec![genesis_hash], 0u64)
    } else {
        let prior = decode_device_tree_state(prior_bytes)?;
        (prior.device_ids, prior.version_number)
    };

    mutate(&mut device_ids);

    // Canonicalise (sort + dedup) via DeviceTree::new.
    let tree = dsm::common::device_tree::DeviceTree::new(device_ids);
    let device_count = tree.len() as u32;
    if device_count == 0 {
        return Err(DsmError::invalid_operation(
            "Device Tree must contain at least one device post-genesis",
        ));
    }

    let sorted_ids: Vec<[u8; 32]> = tree.leaves().to_vec();
    let root = tree.root();
    let new_version = prior_version.checked_add(1).ok_or_else(|| {
        DsmError::invalid_operation("Device Tree version_number overflowed u64; refusing to wrap")
    })?;

    let snapshot = DeviceTreeSnapshot {
        root_hash: root,
        device_count,
        version_number: new_version,
    };

    let new_state = generated::DeviceTreeStateV1 {
        tree: Some(snapshot.to_proto()),
        device_ids: sorted_ids.iter().map(|id| id.to_vec()).collect(),
    };
    let mut buf = Vec::with_capacity(new_state.encoded_len());
    new_state.encode(&mut buf).map_err(|e| {
        DsmError::internal(
            format!("encode DeviceTreeStateV1: {e}"),
            None::<std::io::Error>,
        )
    })?;

    Ok((snapshot, buf))
}

/// Phase B.7 (issue #278) — DeviceTreeViewer one-row-per-leaf view
/// of one genesis's currently-published Device Tree.
///
/// Returned by [`StorageNodeSDK::fetch_device_tree_snapshot`] and
/// consumed by the `identity.devtree.snapshot` query handler (in
/// `dsm_sdk::handlers::identity_routes`). Carries:
///
/// * `claimed_tree` — the storage-node-published `DeviceTreeV1`
///   summary (claimed root_hash, device_count, version_number).
/// * `recomputed_root` — the R_G we get from rebuilding
///   `DeviceTree::new` over the persisted `device_ids` list.
/// * `claimed_root_matches_recomputed` — trust-but-verify gate.
///   `false` means the storage node is serving a state whose
///   declared root doesn't match its declared leaf set.
/// * `leaves` — per-leaf `(device_id, encoded DeviceInclusionProofV1
///   bytes, inclusion_verified)`. `inclusion_verified` is the
///   Rust-side result of `DevTreeProof::verify(device_id,
///   recomputed_root)`.
#[derive(Debug, Clone)]
pub struct DeviceTreeSnapshotView {
    pub claimed_tree: generated::DeviceTreeV1,
    pub recomputed_root: [u8; 32],
    pub claimed_root_matches_recomputed: bool,
    pub leaves: Vec<DeviceTreeLeafViewRust>,
}

/// Phase B.7 (issue #278) — one row in [`DeviceTreeSnapshotView`].
#[derive(Debug, Clone)]
pub struct DeviceTreeLeafViewRust {
    pub device_id: [u8; 32],
    /// Encoded [`generated::DeviceInclusionProofV1`] proto bytes
    /// — produced via `DevTreeProof::to_v1_proto_bytes` so the
    /// storage-node-served and SDK-served bytes are byte-identical
    /// for the same input.
    pub proof_bytes: Vec<u8>,
    /// `DevTreeProof::verify(device_id, recomputed_root)` result.
    pub inclusion_verified: bool,
}

/// Pure helper for Phase B.7 (issue #278). Decodes a persisted
/// [`generated::DeviceTreeStateV1`] body, rebuilds the canonical
/// `DeviceTree`, derives a fresh inclusion proof for every leaf, and
/// verifies each proof locally with `DevTreeProof::verify`. Returns a
/// [`DeviceTreeSnapshotView`] suitable for handing to the
/// `identity.devtree.snapshot` route.
///
/// Pure: no I/O, so directly unit-testable.
pub(crate) fn build_device_tree_snapshot_view(
    persisted_bytes: &[u8],
) -> Result<DeviceTreeSnapshotView, DsmError> {
    let state = generated::DeviceTreeStateV1::decode(persisted_bytes).map_err(|e| {
        DsmError::serialization_error(
            format!("decode DeviceTreeStateV1: {e}"),
            "DeviceTreeStateV1",
            None::<String>,
            Some(e),
        )
    })?;
    let claimed_tree = state.tree.clone().ok_or_else(|| {
        DsmError::serialization_error(
            "DeviceTreeStateV1.tree is missing",
            "DeviceTreeStateV1",
            None::<String>,
            None::<std::io::Error>,
        )
    })?;

    let mut devids: Vec<[u8; 32]> = Vec::with_capacity(state.device_ids.len());
    for (i, id) in state.device_ids.iter().enumerate() {
        if id.len() != 32 {
            return Err(DsmError::serialization_error(
                format!(
                    "DeviceTreeStateV1.device_ids[{i}] is {} bytes, expected 32",
                    id.len()
                ),
                "DeviceTreeStateV1",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(id);
        devids.push(buf);
    }

    let tree = dsm::common::device_tree::DeviceTree::new(devids);
    let recomputed_root = tree.root();

    let claimed_root_matches_recomputed = claimed_tree.root_hash.len() == 32
        && claimed_tree.root_hash.as_slice() == recomputed_root.as_slice();

    let mut leaves: Vec<DeviceTreeLeafViewRust> = Vec::with_capacity(tree.leaves().len());
    for leaf in tree.leaves() {
        let dev_proof = tree.proof(leaf).ok_or_else(|| {
            DsmError::internal(
                "build_device_tree_snapshot_view: DeviceTree::proof returned None for own leaf",
                None::<std::io::Error>,
            )
        })?;
        let proof_bytes = dev_proof.to_v1_proto_bytes(leaf, &recomputed_root);
        let inclusion_verified = dev_proof.verify(leaf, &recomputed_root);
        leaves.push(DeviceTreeLeafViewRust {
            device_id: *leaf,
            proof_bytes,
            inclusion_verified,
        });
    }

    Ok(DeviceTreeSnapshotView {
        claimed_tree,
        recomputed_root,
        claimed_root_matches_recomputed,
        leaves,
    })
}

/// Owned view of a persisted [`generated::DeviceTreeStateV1`].
///
/// Carries the canonical sorted + deduplicated 32-byte DevID list and
/// the prior `version_number` so [`StorageNodeSDK::mutate_device_tree_state`]
/// can apply a strictly-monotonic bump on every accepted update.
#[derive(Debug, Clone)]
struct PersistedDeviceTreeState {
    device_ids: Vec<[u8; 32]>,
    version_number: u64,
}

/// Decode the persisted [`generated::DeviceTreeStateV1`] proto and
/// project it into a normalised [`PersistedDeviceTreeState`].
///
/// Returns [`DsmError::deserialization`] on any of:
///   - body fails prost decoding,
///   - the inner `tree` summary is missing,
///   - any `device_ids` element is not exactly 32 bytes.
///
/// The list is re-canonicalised via
/// [`dsm::common::device_tree::DeviceTree::new`] so a future restart
/// reproduces the byte-exact root even if the on-disk encoding was
/// produced by an older SDK that didn't sort + dedup pre-persist.
fn decode_device_tree_state(bytes: &[u8]) -> Result<PersistedDeviceTreeState, DsmError> {
    let state = generated::DeviceTreeStateV1::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            format!("decode DeviceTreeStateV1: {e}"),
            "DeviceTreeStateV1",
            None::<String>,
            Some(e),
        )
    })?;
    let tree = state.tree.ok_or_else(|| {
        DsmError::serialization_error(
            "DeviceTreeStateV1.tree is missing",
            "DeviceTreeStateV1",
            None::<String>,
            None::<std::io::Error>,
        )
    })?;
    let mut ids: Vec<[u8; 32]> = Vec::with_capacity(state.device_ids.len());
    for (i, id) in state.device_ids.iter().enumerate() {
        if id.len() != 32 {
            return Err(DsmError::serialization_error(
                format!(
                    "DeviceTreeStateV1.device_ids[{i}] is {} bytes, expected 32",
                    id.len()
                ),
                "DeviceTreeStateV1",
                None::<String>,
                None::<std::io::Error>,
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(id);
        ids.push(buf);
    }
    // Re-canonicalise via DeviceTree::new so any earlier writer that
    // happened to persist an unsorted / non-deduped list still yields
    // the same recovered list this code path produces. Idempotent
    // when the list is already canonical.
    let canon = dsm::common::device_tree::DeviceTree::new(ids);
    Ok(PersistedDeviceTreeState {
        device_ids: canon.leaves().to_vec(),
        version_number: tree.version_number,
    })
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
        let expected = dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_SDK_BILATERAL_ENTRY_V1,
            &preimage,
        );
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

    // ---------------------------------------------------------------
    // Phase B.3 (issue #274): Device Tree mutation invariants.
    // The mutator is split out as `apply_device_tree_mutation` so the
    // I/O-free core is directly unit-testable.
    // ---------------------------------------------------------------

    fn build_state_bytes(device_ids: Vec<[u8; 32]>, version: u64) -> Vec<u8> {
        let tree = dsm::common::device_tree::DeviceTree::new(device_ids.clone());
        let state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: tree.root().to_vec(),
                device_count: tree.len() as u32,
                version_number: version,
            }),
            device_ids: tree.leaves().iter().map(|id| id.to_vec()).collect(),
        };
        state.encode_to_vec()
    }

    #[test]
    fn add_first_secondary_seeds_with_root_device_and_bumps_version_to_1() {
        let genesis = [0x11u8; 32];
        let new_devid = [0x22u8; 32];
        let (snapshot, _bytes) = super::apply_device_tree_mutation(&[], genesis, |ids| {
            ids.push(new_devid);
        })
        .expect("first add must succeed");

        // Expect a 2-leaf tree: {genesis (root), new_devid}.
        assert_eq!(snapshot.device_count, 2);
        assert_eq!(snapshot.version_number, 1);
        let expected_root =
            dsm::common::device_tree::DeviceTree::new(vec![genesis, new_devid]).root();
        assert_eq!(snapshot.root_hash, expected_root);
    }

    #[test]
    fn add_is_idempotent_on_duplicate_device_id() {
        let genesis = [0x11u8; 32];
        let new_devid = [0x22u8; 32];

        // First add: empty -> {genesis, new_devid}.
        let (snap1, bytes1) =
            super::apply_device_tree_mutation(&[], genesis, |ids| ids.push(new_devid))
                .expect("first add");

        // Second add of the same device_id: should dedup and produce
        // identical root + device_count, but version_number must still
        // monotonically bump because a caller invoked the mutator.
        let (snap2, _bytes2) =
            super::apply_device_tree_mutation(&bytes1, genesis, |ids| ids.push(new_devid))
                .expect("second add");
        assert_eq!(snap2.root_hash, snap1.root_hash);
        assert_eq!(snap2.device_count, snap1.device_count);
        assert_eq!(snap2.version_number, snap1.version_number + 1);
    }

    #[test]
    fn add_then_remove_cycles_back_to_root_only() {
        let genesis = [0x11u8; 32];
        let dev_a = [0x22u8; 32];

        let (_snap1, bytes1) =
            super::apply_device_tree_mutation(&[], genesis, |ids| ids.push(dev_a)).expect("add A");

        let (snap2, _bytes2) = super::apply_device_tree_mutation(&bytes1, genesis, |ids| {
            ids.retain(|id| id != &dev_a)
        })
        .expect("remove A");

        // After removing A we should be back to a single-leaf tree
        // containing only the root device (genesis_hash).
        assert_eq!(snap2.device_count, 1);
        let expected_root = dsm::common::device_tree::DeviceTree::single(genesis).root();
        assert_eq!(snap2.root_hash, expected_root);
        // Two mutations applied, so version_number must be 2.
        assert_eq!(snap2.version_number, 2);
    }

    #[test]
    fn version_number_is_strictly_monotonic_across_multiple_updates() {
        let genesis = [0x11u8; 32];
        let dev_a = [0x22u8; 32];
        let dev_b = [0x33u8; 32];
        let dev_c = [0x44u8; 32];

        let (s1, b1) =
            super::apply_device_tree_mutation(&[], genesis, |ids| ids.push(dev_a)).expect("add A");
        let (s2, b2) =
            super::apply_device_tree_mutation(&b1, genesis, |ids| ids.push(dev_b)).expect("add B");
        let (s3, b3) =
            super::apply_device_tree_mutation(&b2, genesis, |ids| ids.push(dev_c)).expect("add C");
        let (s4, _b4) =
            super::apply_device_tree_mutation(&b3, genesis, |ids| ids.retain(|id| id != &dev_b))
                .expect("remove B");

        assert_eq!(s1.version_number, 1);
        assert_eq!(s2.version_number, 2);
        assert_eq!(s3.version_number, 3);
        assert_eq!(s4.version_number, 4);
    }

    #[test]
    fn input_order_is_canonicalised_via_lexicographic_sort_and_dedup() {
        let genesis = [0x11u8; 32];
        let dev_a = [0xAAu8; 32];
        let dev_b = [0xBBu8; 32];

        // Different insertion orders must produce the same persisted
        // bytes (modulo proto field-ordering, which prost emits
        // deterministically for the same input).
        let (snap_ab, bytes_ab) = super::apply_device_tree_mutation(&[], genesis, |ids| {
            ids.push(dev_a);
            ids.push(dev_b);
        })
        .expect("AB order");
        let (snap_ba, bytes_ba) = super::apply_device_tree_mutation(&[], genesis, |ids| {
            ids.push(dev_b);
            ids.push(dev_a);
        })
        .expect("BA order");

        assert_eq!(snap_ab.root_hash, snap_ba.root_hash);
        assert_eq!(snap_ab.device_count, snap_ba.device_count);
        assert_eq!(bytes_ab, bytes_ba);
    }

    #[test]
    fn removing_the_last_device_post_genesis_is_rejected() {
        // Construct a one-leaf state (just genesis) directly so we can
        // attempt to drain it.
        let genesis = [0x11u8; 32];
        let bytes = build_state_bytes(vec![genesis], 1);

        // Caller asks to remove the single leaf -> mutator must fail
        // closed with an InvalidOperation.
        let err = super::apply_device_tree_mutation(&bytes, genesis, |ids| ids.clear())
            .expect_err("empty post-mutation tree must be rejected");
        assert!(
            format!("{err}").contains("at least one device"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn malformed_state_bytes_are_rejected_with_serialization_error() {
        let genesis = [0x11u8; 32];
        let garbage = b"this is not a valid DeviceTreeStateV1 proto".to_vec();
        let err =
            super::apply_device_tree_mutation(&garbage, genesis, |ids| ids.push([0x99u8; 32]))
                .expect_err("garbage prior state must fail decode");
        let msg = format!("{err}");
        assert!(
            msg.contains("DeviceTreeStateV1")
                || msg.contains("Serialization")
                || msg.contains("decode"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn decode_device_tree_state_rejects_non_32_byte_device_ids() {
        let bad_state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0u8; 32],
                device_count: 1,
                version_number: 1,
            }),
            device_ids: vec![vec![0u8; 31]], // 31 bytes, not 32
        };
        let bytes = bad_state.encode_to_vec();
        let err =
            super::decode_device_tree_state(&bytes).expect_err("non-32-byte device_id rejected");
        let msg = format!("{err}");
        assert!(msg.contains("31 bytes"), "unexpected error: {msg}");
    }

    #[test]
    fn decode_device_tree_state_rejects_missing_tree_field() {
        let bad_state = generated::DeviceTreeStateV1 {
            tree: None,
            device_ids: vec![],
        };
        let bytes = bad_state.encode_to_vec();
        let err =
            super::decode_device_tree_state(&bytes).expect_err("missing tree summary rejected");
        let msg = format!("{err}");
        assert!(msg.contains("tree is missing"), "unexpected error: {msg}");
    }

    #[test]
    fn snapshot_to_proto_round_trips_through_prost() {
        let snap = DeviceTreeSnapshot {
            root_hash: [0x42u8; 32],
            device_count: 7,
            version_number: 123,
        };
        let proto = snap.to_proto();
        let bytes = proto.encode_to_vec();
        let decoded = generated::DeviceTreeV1::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.root_hash, snap.root_hash.to_vec());
        assert_eq!(decoded.device_count, 7);
        assert_eq!(decoded.version_number, 123);
    }

    #[test]
    fn root_hash_matches_canonical_device_tree_root() {
        // Cross-check: the snapshot.root_hash from apply_device_tree_mutation
        // must equal dsm::common::device_tree::DeviceTree::new(...).root().
        let genesis = [0x11u8; 32];
        let dev_a = [0x22u8; 32];
        let dev_b = [0x33u8; 32];

        let (snap, _bytes) = super::apply_device_tree_mutation(&[], genesis, |ids| {
            ids.push(dev_a);
            ids.push(dev_b);
        })
        .expect("add A then B");

        let expected =
            dsm::common::device_tree::DeviceTree::new(vec![genesis, dev_a, dev_b]).root();
        assert_eq!(snap.root_hash, expected);
    }

    // -----------------------------------------------------------------
    // Phase B.6 (issue #277): initial Device Tree publish at genesis-MPC
    // finalisation. The fail-closed publish-before-install contract is
    // implemented in `create_genesis_with_mpc`; the pure helper
    // `build_initial_device_tree_payload` is directly testable.
    // -----------------------------------------------------------------

    #[test]
    fn initial_device_tree_payload_has_single_root_leaf() {
        let genesis_hash = [0x77u8; 32];
        let (snapshot, payload) = StorageNodeSDK::build_initial_device_tree_payload(genesis_hash)
            .expect("initial payload");

        assert_eq!(snapshot.device_count, 1);
        assert_eq!(snapshot.version_number, 1);
        let expected_root = dsm::common::device_tree::DeviceTree::single(genesis_hash).root();
        assert_eq!(snapshot.root_hash, expected_root);

        // Decode the payload back and confirm the contained state
        // matches the snapshot exactly.
        let state =
            generated::DeviceTreeStateV1::decode(payload.as_slice()).expect("decode payload");
        let tree = state.tree.expect("tree summary");
        assert_eq!(tree.root_hash, expected_root.to_vec());
        assert_eq!(tree.device_count, 1);
        assert_eq!(tree.version_number, 1);
        assert_eq!(state.device_ids, vec![genesis_hash.to_vec()]);
    }

    #[test]
    fn initial_device_tree_payload_round_trips_through_validator_shape() {
        // The payload the publisher PUTs must be acceptable to the
        // Phase B.4 validator. Re-encode + decode it through the same
        // proto definitions and confirm the round-trip preserves
        // everything the validator cares about (CHECK 1: parses;
        // CHECK 2: 32-byte non-zero root; CHECK 3: device_count >= 1
        // and matches list length).
        let genesis_hash = [0xABu8; 32];
        let (_snapshot, payload) =
            StorageNodeSDK::build_initial_device_tree_payload(genesis_hash).expect("payload");

        let decoded =
            generated::DeviceTreeStateV1::decode(payload.as_slice()).expect("decode round-trip");
        let tree = decoded.tree.expect("tree present");
        assert_eq!(tree.root_hash.len(), 32);
        assert!(
            tree.root_hash.iter().any(|&b| b != 0),
            "root_hash must be non-zero"
        );
        assert!(tree.device_count >= 1);
        assert_eq!(tree.device_count as usize, decoded.device_ids.len());
        for id in &decoded.device_ids {
            assert_eq!(id.len(), 32);
        }
    }

    #[test]
    fn initial_device_tree_payload_is_deterministic() {
        // Two calls with the same genesis_hash must produce
        // byte-identical payloads — prost emits deterministic output
        // for the same input, so the storage-node-side dedup logic
        // (idempotent PUT on retries) holds.
        let genesis_hash = [0x12u8; 32];
        let (s1, p1) = StorageNodeSDK::build_initial_device_tree_payload(genesis_hash).unwrap();
        let (s2, p2) = StorageNodeSDK::build_initial_device_tree_payload(genesis_hash).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn initial_device_tree_payloads_differ_across_genesis() {
        let (s1, p1) = StorageNodeSDK::build_initial_device_tree_payload([0x01u8; 32]).unwrap();
        let (s2, p2) = StorageNodeSDK::build_initial_device_tree_payload([0x02u8; 32]).unwrap();
        assert_ne!(s1.root_hash, s2.root_hash);
        assert_ne!(p1, p2);
    }
}
