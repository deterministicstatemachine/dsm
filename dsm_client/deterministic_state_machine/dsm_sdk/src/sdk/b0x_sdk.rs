//! # B0x SDK — Unilateral Envelope Transport
//!
//! Deterministic, protobuf-only client for the b0x spool protocol.
//! Handles device registration (including 409 Already Registered recovery),
//! Envelope v3 submission, retrieval, and acknowledgement against the
//! storage-node `/api/v2/b0x/*` endpoints.
//!
//! Authorization uses `DSM <device_id>:<token>` headers with Base32
//! Crockford device identifiers. No wall clocks, no JSON, no hex in
//! protocol logic.

use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::util::{deterministic_time as dt, text_id};
// blake3 usage: all calls go through dsm::crypto::blake3::dsm_domain_hasher() for domain separation

use log::{info, warn, debug};
use prost::Message;
use rand_core06::{OsRng, RngCore};
use reqwest;
use std::collections::HashMap;
use std::sync::Arc;
use dsm::utils::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

// ...existing code...

fn looks_like_dotted_decimal_bytes(s: &str) -> bool {
    // Very small heuristic: 32 dot-separated u8-ish segments.
    // This is only for diagnostics; do NOT make protocol decisions based on this.
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 32 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn base32_decodes_to_32_bytes(s: &str) -> bool {
    match crate::util::text_id::decode_base32_crockford(s) {
        Some(b) => b.len() == 32,
        None => false,
    }
}

fn is_canonical_auth_device_id(device_id_b32: &str) -> bool {
    // Protocol invariant: Authorization device_id must be base32 decoding to exactly 32 bytes.
    // Reject dotted-decimal ("N.N.N..." 32 segments) and anything malformed.
    base32_decodes_to_32_bytes(device_id_b32) && !looks_like_dotted_decimal_bytes(device_id_b32)
}

/// Validate the canonical rotated b0x routing key.
///
/// The routing key is a single Base32 Crockford encoding of a 32-byte
/// domain-separated BLAKE3 digest.
fn validate_b0x_address(address: &str) -> Result<(), DsmError> {
    if !base32_decodes_to_32_bytes(address) {
        return Err(DsmError::internal(
            "Invalid b0x address format: must be canonical base32 encoding of 32 bytes",
            None::<std::io::Error>,
        ));
    }

    Ok(())
}

fn decode_base32_32(label: &str, value: &str) -> Result<[u8; 32], DsmError> {
    let bytes = text_id::decode_base32_crockford(value).ok_or_else(|| {
        DsmError::internal(
            format!("{label} must be valid base32 encoding of 32 bytes"),
            None::<std::io::Error>,
        )
    })?;
    if bytes.len() != 32 {
        return Err(DsmError::internal(
            format!(
                "{label} must decode to exactly 32 bytes (got {})",
                bytes.len()
            ),
            None::<std::io::Error>,
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckStatusSummary {
    Acked,
    NotAcked,
    Unavailable,
}

fn summarize_ack_status(
    acked_count: usize,
    quorum: usize,
    seen_unacked: bool,
    saw_authoritative_status: bool,
) -> AckStatusSummary {
    if acked_count >= quorum {
        return AckStatusSummary::Acked;
    }
    if seen_unacked {
        return AckStatusSummary::NotAcked;
    }
    if acked_count > 0 {
        return AckStatusSummary::Unavailable;
    }
    if saw_authoritative_status {
        return AckStatusSummary::NotAcked;
    }
    AckStatusSummary::Unavailable
}

/// Retry configuration for b0x operations
#[derive(Debug, Clone)]
pub struct B0xRetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for B0xRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1000, // 1 second
            max_delay_ms: 30000, // 30 seconds
            backoff_multiplier: 2.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct B0xEntry {
    pub transaction_id: String,
    pub inbox_key: String,
    // Textual fields are base32-encoded (Crockford: 0-9,A-H,J-K,M-N,P-T,V-Z with substitutions)
    pub sender_device_id: String,
    pub sender_genesis_hash: String,
    pub sender_chain_tip: String,
    /// Next chain tip (base32) anchoring this online transition.
    /// If unknown at decode time, fall back to sender_chain_tip.
    pub next_chain_tip: String,
    pub recipient_device_id: String,
    pub transaction: Operation,
    pub signature: Vec<u8>,
    /// Sender's SPHINCS+ public key (optional, embedded in envelope evidence)
    pub sender_signing_public_key: Vec<u8>,
    pub tick: u64,
    pub ttl_seconds: u64,
    // Envelope v3 signing context (AF-2 remediation)
    pub seq: u64,
    /// Canonical ReceiptCommit bytes (§4.2) — SMT proofs for this transition.
    pub receipt_commit: Vec<u8>,
    /// §4.2.1 Canonical unsigned Operation bytes (signing preimage).
    /// Receiver uses these directly for SPHINCS+ verification and tip computation.
    pub canonical_operation_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct B0xSubmissionParams {
    // Textual params must be base32-encoded when provided
    pub recipient_device_id: String,    // base32 of 32-byte DevID
    pub recipient_genesis_hash: String, // base32 of 32-byte genesis
    pub transaction: Operation,
    pub signature: Vec<u8>,
    pub sender_genesis_hash: String, // base32 of 32-byte genesis
    pub sender_chain_tip: String,    // base32 of 32-byte tip
    /// Sender's SPHINCS+ public key (optional, embedded for verification hints)
    pub sender_signing_public_key: Vec<u8>,
    /// TTL is ignored in the clockless protocol; keep for wire compatibility, always 0.
    pub ttl_seconds: u64,
    /// Sequence number for canonical signing (AF-2 remediation)
    pub seq: u64,
    /// Next chain tip bytes (32) anchoring this online transition (optional).
    pub next_chain_tip: Option<Vec<u8>>,
    /// Canonical ReceiptCommit bytes (§4.2) — SMT proofs for this transition.
    pub receipt_commit: Vec<u8>,
    /// Tip-scoped b0x routing address (§16.4).
    /// Computed via `B0xSDK::compute_b0x_address(recipient_genesis, recipient_device, chain_tip)`.
    pub routing_address: String,
    /// §4.2.1 Canonical unsigned Operation bytes (signing preimage).
    /// The exact bytes the sender signed with SPHINCS+.  The receiver MUST
    /// use these directly for verification — no field-by-field reconstruction.
    pub canonical_operation_bytes: Vec<u8>,
}

impl B0xSubmissionParams {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // recipient_device_id
        let r_dev = self.recipient_device_id.as_bytes();
        bytes.extend_from_slice(&(r_dev.len() as u32).to_le_bytes());
        bytes.extend_from_slice(r_dev);

        // recipient_genesis_hash
        let r_gen = self.recipient_genesis_hash.as_bytes();
        bytes.extend_from_slice(&(r_gen.len() as u32).to_le_bytes());
        bytes.extend_from_slice(r_gen);

        // transaction
        let tx_bytes = crate::storage::client_db::serialize_operation(&self.transaction);
        bytes.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&tx_bytes);

        // signature
        bytes.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.signature);

        // sender_signing_public_key (optional)
        bytes.extend_from_slice(&(self.sender_signing_public_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.sender_signing_public_key);

        // sender_genesis_hash
        let s_gen = self.sender_genesis_hash.as_bytes();
        bytes.extend_from_slice(&(s_gen.len() as u32).to_le_bytes());
        bytes.extend_from_slice(s_gen);

        // sender_chain_tip
        let s_tip = self.sender_chain_tip.as_bytes();
        bytes.extend_from_slice(&(s_tip.len() as u32).to_le_bytes());
        bytes.extend_from_slice(s_tip);

        // ttl_seconds
        bytes.extend_from_slice(&self.ttl_seconds.to_le_bytes());

        // seq (AF-2 canonical signing)
        bytes.extend_from_slice(&self.seq.to_le_bytes());

        // next_chain_tip (optional; length-prefixed)
        if let Some(ref next_tip) = self.next_chain_tip {
            bytes.extend_from_slice(&(next_tip.len() as u32).to_le_bytes());
            bytes.extend_from_slice(next_tip);
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }

        // receipt_commit (§4.2 ReceiptCommit canonical protobuf) — length-prefixed
        bytes.extend_from_slice(&(self.receipt_commit.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.receipt_commit);

        // routing_address (§16.4 tip-scoped b0x address) — length-prefixed
        let addr_bytes = self.routing_address.as_bytes();
        bytes.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(addr_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let mut cursor = 0;

        let read_string = |cursor: &mut usize| -> Result<String, DsmError> {
            if *cursor + 4 > bytes.len() {
                return Err(DsmError::internal(
                    "buffer underflow",
                    None::<std::io::Error>,
                ));
            }
            let len = u32::from_le_bytes(
                bytes[*cursor..*cursor + 4]
                    .try_into()
                    .map_err(|_| DsmError::internal("buffer underflow", None::<std::io::Error>))?,
            ) as usize;
            *cursor += 4;
            if *cursor + len > bytes.len() {
                return Err(DsmError::internal(
                    "buffer underflow",
                    None::<std::io::Error>,
                ));
            }
            let s = String::from_utf8(bytes[*cursor..*cursor + len].to_vec()).map_err(|e| {
                DsmError::internal(format!("utf8 error: {}", e), None::<std::io::Error>)
            })?;
            *cursor += len;
            Ok(s)
        };

        let read_bytes = |cursor: &mut usize| -> Result<Vec<u8>, DsmError> {
            if *cursor + 4 > bytes.len() {
                return Err(DsmError::internal(
                    "buffer underflow",
                    None::<std::io::Error>,
                ));
            }
            let len = u32::from_le_bytes(
                bytes[*cursor..*cursor + 4]
                    .try_into()
                    .map_err(|_| DsmError::internal("buffer underflow", None::<std::io::Error>))?,
            ) as usize;
            *cursor += 4;
            if *cursor + len > bytes.len() {
                return Err(DsmError::internal(
                    "buffer underflow",
                    None::<std::io::Error>,
                ));
            }
            let v = bytes[*cursor..*cursor + len].to_vec();
            *cursor += len;
            Ok(v)
        };

        let recipient_device_id = read_string(&mut cursor)?;
        let recipient_genesis_hash = read_string(&mut cursor)?;

        let tx_bytes = read_bytes(&mut cursor)?;
        let transaction =
            crate::storage::client_db::deserialize_operation(&tx_bytes).map_err(|e| {
                DsmError::internal(
                    format!("deserialize op failed: {}", e),
                    None::<std::io::Error>,
                )
            })?;

        let signature = read_bytes(&mut cursor)?;

        let sender_signing_public_key = read_bytes(&mut cursor)?;
        let sender_genesis_hash = read_string(&mut cursor)?;
        let sender_chain_tip = read_string(&mut cursor)?;

        if cursor + 8 > bytes.len() {
            return Err(DsmError::internal(
                "buffer underflow",
                None::<std::io::Error>,
            ));
        }
        let ttl_seconds = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| DsmError::internal("buffer underflow", None::<std::io::Error>))?,
        );
        cursor += 8;

        if cursor + 8 > bytes.len() {
            return Err(DsmError::internal(
                "buffer underflow",
                None::<std::io::Error>,
            ));
        }
        let seq = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| DsmError::internal("buffer underflow", None::<std::io::Error>))?,
        );

        cursor += 8;

        let next_chain_tip = if cursor + 4 <= bytes.len() {
            let len = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| DsmError::internal("buffer underflow", None::<std::io::Error>))?,
            ) as usize;
            cursor += 4;
            if len > 0 {
                if cursor + len > bytes.len() {
                    return Err(DsmError::internal(
                        "buffer underflow",
                        None::<std::io::Error>,
                    ));
                }
                let v = bytes[cursor..cursor + len].to_vec();
                cursor += len;
                Some(v)
            } else {
                None
            }
        } else {
            None
        };

        // receipt_commit (§4.2)
        let receipt_commit = read_bytes(&mut cursor)?;

        // routing_address (§16.4) — mandatory
        let routing_address = read_string(&mut cursor)?;
        if routing_address.is_empty() {
            return Err(DsmError::internal(
                "routing_address cannot be empty",
                None::<std::io::Error>,
            ));
        }

        Ok(Self {
            recipient_device_id,
            recipient_genesis_hash,
            transaction,
            signature,
            sender_signing_public_key,
            sender_genesis_hash,
            sender_chain_tip,
            ttl_seconds,
            seq,
            next_chain_tip,
            receipt_commit,
            routing_address,
            canonical_operation_bytes: Vec::new(),
        })
    }
}

fn anchor_tick_from_tip(tip: &[u8]) -> u64 {
    if tip.len() != 32 {
        return 0;
    }
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/anchor-tick");
    hasher.update(tip);
    let h = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

pub struct B0xSDK {
    // Device ID in base32 textual form for HTTP auth; decode to bytes for protobuf fields
    pub(crate) device_id: String,
    core_sdk: Arc<CoreSDK>,
    pub(crate) storage_node_endpoints: Vec<String>,
    http_client: reqwest::Client,
    pub(crate) request_timeout: Duration,
    pub(crate) max_retries: usize,
    pub(crate) retry_delay: Duration,
    circuit_breaker: CircuitBreaker,
    salt_genesis: [u8; 32],
    salt_device: [u8; 32],
    /// Per-endpoint tokens (tokens are node-specific). Persisted in client_db as well.
    tokens_by_endpoint: tokio::sync::RwLock<HashMap<String, String>>, // (endpoint|genesis|device) -> token
    /// Write quorum K for multi-node ops (submit/ack). Default 3.
    quorum_k: usize,
}

static MSG_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A persisted token can only be trusted if it was stored for the *same* canonical
/// device_id string that we will place into `Authorization: DSM <device_id>:<token>`.
///
/// If we see any evidence that the current `AppState` contains a non-canonical dotted-decimal
/// textual id ("N.N.N..."), we must *not* adopt cached tokens, because they will
/// guarantee 401 loops on v2 retrieve/ack.
fn app_state_device_id_is_canonical_base32() -> bool {
    match crate::sdk::app_state::AppState::get_device_id() {
        Some(b) if b.len() == 32 => {
            let b32 = crate::util::text_id::encode_base32_crockford(&b);
            base32_decodes_to_32_bytes(&b32)
        }
        _ => false,
    }
}

#[derive(Clone)]
struct CircuitBreaker {
    failed_nodes: Arc<tokio::sync::RwLock<HashMap<String, u64>>>, // ticks
    failure_threshold: Duration,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failed_nodes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            // Clockless: ticks-only threshold. The numeric magnitude is policy (not wall-clock).
            failure_threshold: Duration::from_ticks(300),
        }
    }
    async fn is_node_healthy(&self, endpoint: &str) -> bool {
        let failed = self.failed_nodes.read().await;
        if let Some(&t) = failed.get(endpoint) {
            let now = dt::peek() as i64;
            // Healthy again once the failure threshold window has elapsed.
            // NOTE: previous logic was inverted and would keep nodes unhealthy forever.
            (now - t as i64) as u64 >= self.failure_threshold.as_secs()
        } else {
            true
        }
    }
    async fn mark_node_failed(&self, endpoint: &str) {
        self.failed_nodes
            .write()
            .await
            .insert(endpoint.to_string(), dt::peek());
        warn!("CircuitBreaker: marked failed {}", endpoint);
    }
    async fn mark_node_healthy(&self, endpoint: &str) {
        if self.failed_nodes.write().await.remove(endpoint).is_some() {
            info!("CircuitBreaker: {} back to healthy", endpoint);
        }
    }
}

impl B0xSDK {
    fn hash_b0x_component(domain_tag: &str, input: &[u8]) -> [u8; 32] {
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(domain_tag);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }

    /// Derive a per-device blinding salt from domain tag and device identity.
    ///
    /// §16.4: salt = BLAKE3("DSM/b0x-salt-{G|D}\0" || genesis_hash || device_id)
    /// where genesis_hash is obtained from AppState (master secret Smaster).
    /// Falls back to device_id-only derivation if genesis is not yet available
    /// (e.g. during initial registration before genesis is stored).
    fn derive_salt(domain_tag: &[u8], device_id_bytes: &[u8]) -> [u8; 32] {
        // §16.4: saltG/saltD MUST be derived from Smaster (secret), not public inputs.
        // Spec: saltG := HKDF-BLAKE3("DSM/b0x-salt-G\0", Smaster)
        //       saltD := HKDF-BLAKE3("DSM/b0x-salt-D\0", Smaster)
        // KDBRW (cdbrw_binding) is the hardware-bound secret that approximates Smaster here:
        // it is never serialized or externalized per §12 Privacy Rule.
        // Without KDBRW (e.g. unit tests), falls back to genesis+device_id (public, weaker privacy).
        let tag_str = std::str::from_utf8(domain_tag).unwrap_or("DSM/b0x-salt");
        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(tag_str);
        // Primary IKM: KDBRW — the secret hardware-bound entropy source
        #[cfg(all(target_os = "android", feature = "jni"))]
        if let Some(k) = crate::jni::cdbrw::get_cdbrw_binding_key() {
            hasher.update(&k);
        }
        // Augment with public material for domain separation
        if crate::storage_utils::get_storage_base_dir().is_some() {
            if let Some(genesis) = crate::sdk::app_state::AppState::get_genesis_hash() {
                hasher.update(&genesis);
            }
        }
        hasher.update(device_id_bytes);
        *hasher.finalize().as_bytes()
    }

    /// Compose the current auth binding components: (genesis_b32, device_id, cache_key)
    async fn auth_binding_key(&self, endpoint: &str) -> Result<(String, String, String), DsmError> {
        let genesis_bytes = self.core_sdk.local_genesis_hash().await?;
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&genesis_bytes);
        let cache_key = format!("{}|{}|{}", endpoint, genesis_b32, self.device_id);
        Ok((genesis_b32, self.device_id.clone(), cache_key))
    }

    pub fn new(
        device_id_b32: String,
        core_sdk: Arc<CoreSDK>,
        storage_endpoints: Vec<String>,
    ) -> Result<Self, DsmError> {
        // Safety: the storage-node protocol uses base32(32 bytes) for device_id.
        // Refuse any non-canonical encoding here to avoid silent inbox mismatches.
        let decoded =
            crate::util::text_id::decode_base32_crockford(&device_id_b32).ok_or_else(|| {
                DsmError::internal(
                    "B0xSDK::new: device_id must be base32",
                    None::<std::io::Error>,
                )
            })?;
        if decoded.len() != 32 {
            return Err(DsmError::internal(
                format!(
                    "B0xSDK::new: device_id base32 decoded to {} bytes (expected 32)",
                    decoded.len()
                ),
                None::<std::io::Error>,
            ));
        }
        if !is_canonical_auth_device_id(&device_id_b32) {
            return Err(DsmError::internal(
                "B0xSDK::new: device_id is not canonical base32(32) for Authorization",
                None::<std::io::Error>,
            ));
        }

        // Clockless: do not set wall-clock request timeouts here.
        // Cancellation/limits are owned by the caller task lifetime.
        let http_client = crate::sdk::storage_node_sdk::build_ca_aware_client();

        let sdk = Self {
            device_id: device_id_b32,
            core_sdk,
            storage_node_endpoints: storage_endpoints,
            http_client,
            // Clockless: deterministic tick budget marker only; not used to enforce wall-clock.
            request_timeout: Duration::from_ticks(0),
            max_retries: 3,
            // Clockless: do not sleep between retries. Keep as metadata only.
            retry_delay: Duration::from_ticks(0),
            circuit_breaker: CircuitBreaker::new(),
            salt_genesis: Self::derive_salt(b"DSM/b0x-salt-G", &decoded),
            salt_device: Self::derive_salt(b"DSM/b0x-salt-D", &decoded),
            tokens_by_endpoint: tokio::sync::RwLock::new(HashMap::new()), // (endpoint|genesis|device) -> token
            quorum_k: 3,
        };

        // Token loading is now lazy - happens on first use via ensure_token()
        // This avoids blocking in the constructor and works in both sync and async contexts
        Ok(sdk)
    }

    /// Compute the deterministic b0x routing key for (genesis, device, tip).
    ///
    /// Each input is first domain-separated on its own axis, then folded into
    /// a single 32-byte routing digest:
    /// `Base32Crockford(BLAKE3-256("DSM/b0x\0" || h_g || h_d || h_t))`
    /// where `h_g = BLAKE3("DSM/b0x-G\0" || genesis)`,
    /// `h_d = BLAKE3("DSM/b0x-D\0" || device)`,
    /// and `h_t = BLAKE3("DSM/b0x-T\0" || tip)`.
    /// Each input MUST be exactly 32 bytes.
    pub fn compute_b0x_address(
        genesis: &[u8],
        device: &[u8],
        tip: &[u8],
    ) -> Result<String, DsmError> {
        if genesis.len() != 32 || device.len() != 32 || tip.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "genesis/device/tip must be 32 bytes",
            ));
        }
        let h_g = Self::hash_b0x_component("DSM/b0x-G", genesis);
        let h_d = Self::hash_b0x_component("DSM/b0x-D", device);
        let h_t = Self::hash_b0x_component("DSM/b0x-T", tip);

        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/b0x");
        hasher.update(&h_g);
        hasher.update(&h_d);
        hasher.update(&h_t);
        let h = hasher.finalize();
        let addr = crate::util::text_id::encode_base32_crockford(h.as_bytes());
        validate_b0x_address(&addr)?;
        Ok(addr)
    }

    /// Compute the canonical rotated b0x routing key from an explicit bilateral
    /// relationship tip. Missing or malformed tips are rejected instead of being
    /// normalized to a legacy zero-tip route.
    pub fn compute_b0x_address_for_optional_tip(
        genesis: &[u8],
        device: &[u8],
        chain_tip: Option<&[u8]>,
    ) -> Result<String, DsmError> {
        match chain_tip {
            Some(tip) if tip.len() == 32 => Self::compute_b0x_address(genesis, device, tip),
            Some(tip) => Err(DsmError::invalid_parameter(format!(
                "relationship tip must be exactly 32 bytes, got {}",
                tip.len()
            ))),
            None => Err(DsmError::invalid_parameter(
                "relationship tip is required for rotated b0x routing",
            )),
        }
    }

    #[inline]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    // ------------------------------------------------------------------------
    // b0x ID derivation (deterministic salts; no clocks)
    // ------------------------------------------------------------------------
    pub async fn b0x_id(&mut self, chain_tip_b32: &str) -> Result<String, DsmError> {
        // Use nonce=0 for stable routing key per relationship-step.
        // The receiver derives the address from the shared chain tip and expects nonce=0.
        let nonce = 0;

        // Prefer persisted canonical genesis from AppState; use core path for tests
        let local_genesis_bytes: [u8; 32] =
            match crate::sdk::app_state::AppState::get_genesis_hash() {
                Some(g) if g.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&g);
                    arr
                }
                _ => {
                    let g = self.core_sdk.local_genesis_hash().await?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&g);
                    arr
                }
            };

        // Decode inputs
        let device_id_bytes = crate::util::text_id::decode_base32_crockford(&self.device_id)
            .ok_or_else(|| {
                DsmError::internal("device_id base32 decode failed", None::<std::io::Error>)
            })?;
        let chain_tip_bytes = crate::util::text_id::decode_base32_crockford(chain_tip_b32)
            .ok_or_else(|| {
                DsmError::internal("chain_tip base32 decode failed", None::<std::io::Error>)
            })?;
        let mut dev_arr = [0u8; 32];
        dev_arr.copy_from_slice(&device_id_bytes[..32]);
        let mut tip_arr = [0u8; 32];
        tip_arr.copy_from_slice(&chain_tip_bytes[..32]);

        Self::b0x_id_for_device_with_salts(
            &local_genesis_bytes,
            &tip_arr,
            &dev_arr,
            &self.salt_genesis,
            &self.salt_device,
            nonce,
        )
        .await
    }

    pub async fn b0x_id_for_device(
        &mut self,
        recipient_genesis: &[u8; 32],
        chain_tip: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<String, DsmError> {
        // Use nonce=0 for stable routing key
        let nonce = 0;
        Self::b0x_id_for_device_with_salts(
            recipient_genesis,
            chain_tip,
            device_id,
            &self.salt_genesis,
            &self.salt_device,
            nonce,
        )
        .await
    }

    pub async fn b0x_id_for_device_with_salts(
        recipient_genesis: &[u8; 32],
        chain_tip: &[u8; 32],
        device_id: &[u8; 32],
        salt_genesis: &[u8; 32],
        salt_device: &[u8; 32],
        nonce: u64,
    ) -> Result<String, DsmError> {
        // §16.4: Domain-separated blinded address components
        // h_G = BLAKE3("DSM/addr-G\0" || genesis || salt_genesis)
        let h_g = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/addr-G");
            h.update(recipient_genesis);
            h.update(salt_genesis);
            h.finalize()
        };

        // h_D = BLAKE3("DSM/addr-D\0" || device_id || salt_device)
        let h_d = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/addr-D");
            h.update(device_id);
            h.update(salt_device);
            h.finalize()
        };

        // h_T = BLAKE3("DSM/addr-T\0" || chain_tip || nonce)
        let h_t = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/addr-T");
            h.update(chain_tip);
            h.update(&nonce.to_be_bytes());
            h.finalize()
        };

        let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/b0x");
        h.update(h_g.as_bytes());
        h.update(h_d.as_bytes());
        h.update(h_t.as_bytes());
        let id = crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes());
        Ok(id)
    }

    // ------------------------------------------------------------------------
    // Device registration / token management
    // ------------------------------------------------------------------------

    /// Attempt to load persisted tokens into memory map for all configured endpoints.
    async fn hydrate_tokens_from_disk(&self) {
        let mut map = self.tokens_by_endpoint.write().await;

        // Root-cause guard: if the local identity binding has changed (device_id/genesis),
        // purge persisted tokens so we never attempt to use stale tokens that will 401.
        // This is intentionally best-effort; failure here should not prevent startup.
        let genesis_b32 = match self.core_sdk.local_genesis_hash().await {
            Ok(gen_bytes) => crate::util::text_id::encode_base32_crockford(&gen_bytes),
            Err(e) => {
                warn!("🔐 hydrate_tokens_from_disk: unable to load genesis hash: {e}");
                return;
            }
        };
        if let Err(e) = crate::storage::client_db::ensure_auth_tokens_bound_to_identity(
            self.device_id.trim(),
            genesis_b32.trim(),
        ) {
            warn!("🔐 ensure_auth_tokens_bound_to_identity failed: {e}");
        }

        // If the running build is somehow feeding a dotted-decimal device id into the
        // auth layer, adopting any persisted tokens will *only* create an infinite 401 loop.
        // In that case, force a clean re-registration instead.
        if !app_state_device_id_is_canonical_base32() {
            warn!(
                "🔐 Refusing to hydrate persisted auth tokens: AppState device_id is not canonical base32(32). Will re-register instead."
            );
            map.clear();
            return;
        }

        for ep in &self.storage_node_endpoints {
            let cache_key = format!("{}|{}|{}", ep, genesis_b32, self.device_id);

            if let Ok(Some(tok)) =
                crate::storage::client_db::get_auth_token(ep, &self.device_id, &genesis_b32)
            {
                map.insert(cache_key.clone(), tok);
                continue;
            }
        }
    }

    pub async fn purge_persisted_token_for_endpoint(&self, endpoint: &str) {
        if let Ok((genesis_b32, device_id_b32, cache_key)) = self.auth_binding_key(endpoint).await {
            // Drop in-memory token
            self.tokens_by_endpoint.write().await.remove(&cache_key);
            // Drop persisted token for this (endpoint, device_id, genesis)
            let _ = crate::storage::client_db::delete_auth_token(
                endpoint,
                &device_id_b32,
                &genesis_b32,
            );
        }
    }

    /// Ensure a token exists for the specific endpoint. Attempts persisted load, then single-endpoint register.
    pub async fn ensure_token_for_endpoint(&self, endpoint: &str) -> Result<String, DsmError> {
        // If device_id is non-canonical, nothing we do with tokens can succeed.
        if !is_canonical_auth_device_id(self.device_id.trim()) {
            return Err(DsmError::unauthorized(
                "ensure_token: device_id is not canonical base32(32) for Authorization",
                None::<std::io::Error>,
            ));
        }
        let (genesis_b32, device_id_b32, cache_key) = self.auth_binding_key(endpoint).await?;

        if let Some(tok) = self
            .tokens_by_endpoint
            .read()
            .await
            .get(&cache_key)
            .cloned()
        {
            return Ok(tok);
        }
        // Try persisted
        if let Ok(Some(tok)) =
            crate::storage::client_db::get_auth_token(endpoint, &device_id_b32, &genesis_b32)
        {
            // IMPORTANT: do not immediately trust persisted tokens if they are actively failing.
            // We'll use it once; if it yields 401, the caller must purge + re-register.
            self.tokens_by_endpoint
                .write()
                .await
                .insert(cache_key.clone(), tok.clone());
            return Ok(tok);
        }
        // If there is a token persisted for this endpoint/device but under a different genesis, hard-fail with a deterministic error.
        if let Ok(Some(other_gen)) = crate::storage::client_db::get_mismatched_genesis(
            endpoint,
            &device_id_b32,
            &genesis_b32,
        ) {
            let msg = format!(
                "GENESIS_INBOX_MISMATCH: stored token bound to genesis {} differs from local {}",
                other_gen, genesis_b32
            );
            return Err(DsmError::InboxTokenInvalid(msg));
        }
        // Register on this endpoint
        let tok = self.register_device_on(endpoint).await?;
        self.tokens_by_endpoint
            .write()
            .await
            .insert(cache_key, tok.clone());
        // Persist under (endpoint, device_id, genesis)
        let _ = crate::storage::client_db::store_auth_token(
            endpoint,
            &device_id_b32,
            &genesis_b32,
            &tok,
        );
        Ok(tok)
    }

    /// Register device; on 409, transparently request a token re-issue.
    pub async fn register_device(&self) -> Result<(), DsmError> {
        info!("🔐 Register device flow start");

        let device_id_b32 = self.device_id.clone();
        let device_identity = self.core_sdk.get_device_identity();

        if device_identity.public_key.is_empty() {
            return Err(DsmError::internal(
                format!(
                    "Invalid public key length (must be non-empty): {}",
                    device_identity.public_key.len()
                ),
                None::<std::io::Error>,
            ));
        }

        let genesis_hash = self.core_sdk.local_genesis_hash().await?;
        if genesis_hash.len() != 32 {
            return Err(DsmError::internal(
                format!("Invalid genesis hash len: {}", genesis_hash.len()),
                None::<std::io::Error>,
            ));
        }

        let genesis_b32 = text_id::encode_base32_crockford(&genesis_hash);
        let req = dsm::types::proto::RegisterDeviceRequest {
            device_id: text_id::decode_base32_crockford(&device_id_b32).unwrap_or_default(),
            pubkey: device_identity.public_key.clone(),
            genesis_hash: genesis_hash.clone(),
        };
        let mut body = Vec::with_capacity(req.encoded_len());
        req.encode(&mut body).map_err(|e| {
            DsmError::internal(
                format!("RegisterDeviceRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Hydrate any persisted tokens into memory map first
        self.hydrate_tokens_from_disk().await;

        let mut last_err: Option<DsmError> = None;

        for endpoint in &self.storage_node_endpoints {
            // Primary: /device/register
            let url_register = format!("{}/api/v2/device/register", endpoint);

            match self
                .http_client
                .post(&url_register)
                .header("Content-Type", "application/protobuf")
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes().await.map_err(|e| {
                        DsmError::internal(
                            format!("RegisterDeviceResponse read failed: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    let parsed = dsm::types::proto::RegisterDeviceResponse::decode(bytes.as_ref())
                        .map_err(|e| {
                            DsmError::internal(
                                format!("RegisterDeviceResponse decode failed: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;
                    // store in per-endpoint map; token is bytes on wire, encode to Base32
                    let token_b32 = text_id::encode_base32_crockford(&parsed.token);
                    let cache_key = format!("{}|{}|{}", endpoint, genesis_b32, device_id_b32);
                    self.tokens_by_endpoint
                        .write()
                        .await
                        .insert(cache_key, token_b32.clone());
                    if let Err(e) = crate::storage::client_db::store_auth_token(
                        endpoint,
                        &device_id_b32,
                        &genesis_b32,
                        &token_b32,
                    ) {
                        warn!("Persist token failed: {e}");
                    }
                    info!("✅ Registered at {}", endpoint);
                    return Ok(());
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
                    // Device already registered, ask server to issue/return the existing token.
                    let url_token = format!("{}/api/v2/device/token", endpoint);
                    match self
                        .http_client
                        .post(&url_token)
                        .header("Content-Type", "application/protobuf")
                        .body(body.clone())
                        .send()
                        .await
                    {
                        Ok(resp2) if resp2.status().is_success() => {
                            let bytes = resp2.bytes().await.map_err(|e| {
                                DsmError::internal(
                                    format!("Token response read failed: {e}"),
                                    None::<std::io::Error>,
                                )
                            })?;
                            let parsed =
                                dsm::types::proto::RegisterDeviceResponse::decode(bytes.as_ref())
                                    .map_err(|e| {
                                    DsmError::internal(
                                        format!("Token response decode failed: {e}"),
                                        None::<std::io::Error>,
                                    )
                                })?;
                            let token_b32 = text_id::encode_base32_crockford(&parsed.token);
                            let cache_key =
                                format!("{}|{}|{}", endpoint, genesis_b32, device_id_b32);
                            self.tokens_by_endpoint
                                .write()
                                .await
                                .insert(cache_key, token_b32.clone());
                            if let Err(e) = crate::storage::client_db::store_auth_token(
                                endpoint,
                                &device_id_b32,
                                &genesis_b32,
                                &token_b32,
                            ) {
                                warn!("Persist token failed: {e}");
                            }
                            info!("🔑 Token re-issued at {}", endpoint);
                            return Ok(());
                        }
                        Ok(resp2) => {
                            let status = resp2.status();
                            let body_txt = resp2.text().await.unwrap_or_default();
                            warn!(
                                "Token re-issue failed at {}: status={} body={}",
                                endpoint, status, body_txt
                            );
                            last_err = Some(DsmError::internal(
                                format!(
                                    "Registration failed: 409 and token re-issue failed (status={} body={})",
                                    status, body_txt
                                ),
                                None::<std::io::Error>,
                            ));
                        }
                        Err(e) => {
                            warn!("Token re-issue transport failed at {}: {}", endpoint, e);
                            last_err = Some(DsmError::internal(
                                format!(
                                    "Registration failed: 409 and token re-issue transport failed: {}",
                                    e
                                ),
                                None::<std::io::Error>,
                            ));
                        }
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body_txt = resp.text().await.unwrap_or_default();
                    last_err = Some(DsmError::internal(
                        format!("Registration failed {}: {}", status, body_txt),
                        None::<std::io::Error>,
                    ));
                }
                Err(e) => {
                    last_err = Some(DsmError::internal(
                        format!("HTTP error: {e}"),
                        None::<std::io::Error>,
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            DsmError::internal("No storage endpoints available", None::<std::io::Error>)
        }))
    }

    /// Register on a specific endpoint; returns token string.
    async fn register_device_on(&self, endpoint: &str) -> Result<String, DsmError> {
        let device_id_b32 = self.device_id.clone();
        let device_identity = self.core_sdk.get_device_identity();
        let genesis_hash = self.core_sdk.local_genesis_hash().await?;
        let genesis_b32 = text_id::encode_base32_crockford(&genesis_hash);
        let device_id_raw = text_id::decode_base32_crockford(&device_id_b32).unwrap_or_default();

        info!(
            "register_device_on {}: device_id_raw.len={} pubkey.len={} genesis_hash.len={}",
            endpoint,
            device_id_raw.len(),
            device_identity.public_key.len(),
            genesis_hash.len(),
        );

        let req = dsm::types::proto::RegisterDeviceRequest {
            device_id: device_id_raw,
            pubkey: device_identity.public_key.clone(),
            genesis_hash: genesis_hash.clone(),
        };
        let mut body = Vec::with_capacity(req.encoded_len());
        req.encode(&mut body).map_err(|e| {
            DsmError::internal(
                format!("RegisterDeviceRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let url_register = format!("{}/api/v2/device/register", endpoint);
        let resp_ok = match self
            .http_client
            .post(&url_register)
            .header("Content-Type", "application/protobuf")
            .body(body.clone())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("register_device_on {} HTTP send failed: {e}", endpoint);
                warn!("{}", msg);
                return Err(DsmError::internal(msg, None::<std::io::Error>));
            }
        };

        let status = resp_ok.status();
        info!("register_device_on {}: HTTP status={}", endpoint, status);

        if status.is_success() {
            let bytes = resp_ok.bytes().await.map_err(|e| {
                DsmError::internal(
                    format!("RegisterDeviceResponse read failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            let parsed = dsm::types::proto::RegisterDeviceResponse::decode(bytes.as_ref())
                .map_err(|e| {
                    DsmError::internal(
                        format!("RegisterDeviceResponse decode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let token_b32 = text_id::encode_base32_crockford(&parsed.token);
            if let Err(e) = crate::storage::client_db::store_auth_token(
                endpoint,
                &device_id_b32,
                &genesis_b32,
                &token_b32,
            ) {
                warn!("Persist token failed: {e}");
            }
            return Ok(token_b32);
        }

        if status == reqwest::StatusCode::CONFLICT {
            let url_token = format!("{}/api/v2/device/token", endpoint);
            let resp2 = self
                .http_client
                .post(&url_token)
                .header("Content-Type", "application/protobuf")
                .body(body)
                .send()
                .await
                .map_err(|e| {
                    DsmError::internal(format!("token HTTP error: {e}"), None::<std::io::Error>)
                })?;
            if !resp2.status().is_success() {
                return Err(DsmError::internal(
                    format!("token re-issue failed: status={}", resp2.status()),
                    None::<std::io::Error>,
                ));
            }
            let bytes = resp2.bytes().await.map_err(|e| {
                DsmError::internal(
                    format!("Token response read failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            let parsed = dsm::types::proto::RegisterDeviceResponse::decode(bytes.as_ref())
                .map_err(|e| {
                    DsmError::internal(
                        format!("Token response decode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let token_b32 = text_id::encode_base32_crockford(&parsed.token);
            if let Err(e) = crate::storage::client_db::store_auth_token(
                endpoint,
                &device_id_b32,
                &genesis_b32,
                &token_b32,
            ) {
                warn!("Persist token failed: {e}");
            }
            return Ok(token_b32);
        }

        // Unexpected status — read body for diagnostics
        let resp_body = resp_ok
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".into());
        let msg = format!(
            "register_device_on {} failed: status={} body={}",
            endpoint, status, resp_body
        );
        warn!("{}", msg);
        Err(DsmError::internal(msg, None::<std::io::Error>))
    }

    // ------------------------------------------------------------------------
    // Submission (Envelope v3 over HTTP)
    // ------------------------------------------------------------------------

    pub async fn submit_to_b0x(&mut self, params: B0xSubmissionParams) -> Result<String, DsmError> {
        if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            let test_retry = B0xRetryConfig {
                max_retries: 0,
                base_delay_ms: 0,
                max_delay_ms: 0,
                backoff_multiplier: 1.0,
            };
            self.submit_to_b0x_with_retry(params, &test_retry).await
        } else {
            self.submit_to_b0x_with_retry(params, &B0xRetryConfig::default())
                .await
        }
    }

    /// Submit to b0x with configurable retry logic and enhanced validation
    pub async fn submit_to_b0x_with_retry(
        &mut self,
        params: B0xSubmissionParams,
        retry_config: &B0xRetryConfig,
    ) -> Result<String, DsmError> {
        info!("🎯 submit_to_b0x_with_retry");

        // Enhanced input validation
        self.validate_submission_params(&params)?;

        // 2) Build Envelope v3 with proper request payload
        let mut rand_bytes = [0u8; 16];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut rand_bytes);
        let mut msgid_buf = Vec::with_capacity(11 + 16 + 8 + self.device_id.len());
        msgid_buf.extend_from_slice(b"DSM/b0x-msgid\0");
        msgid_buf.extend_from_slice(&rand_bytes);
        msgid_buf.extend_from_slice(&dt::tick().to_le_bytes());
        msgid_buf.extend_from_slice(&std::process::id().to_le_bytes());
        let ctr = MSG_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        msgid_buf.extend_from_slice(&ctr.to_le_bytes());
        msgid_buf.extend_from_slice(self.device_id.as_bytes());
        let full = dsm::crypto::blake3::domain_hash("DSM/b0x-msgid", &msgid_buf);
        let mut message_id_bytes = [0u8; 16];
        message_id_bytes.copy_from_slice(&full.as_bytes()[..16]);
        let message_id_b32 = text_id::encode_base32_crockford(&message_id_bytes);
        if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            log::debug!("[B0X] submit msg_id={}", message_id_b32);
        }

        let actor_device_bytes = crate::util::text_id::decode_base32_crockford(&self.device_id)
            .ok_or_else(|| {
                DsmError::internal("device_id base32 decode failed", None::<std::io::Error>)
            })?;
        let sender_tip_bytes = if params.sender_chain_tip.is_empty() {
            Vec::new()
        } else {
            crate::util::text_id::decode_base32_crockford(&params.sender_chain_tip).ok_or_else(
                || {
                    DsmError::internal(
                        "sender_chain_tip base32 decode failed",
                        None::<std::io::Error>,
                    )
                },
            )?
        };

        enum SubmitOp {
            Transfer {
                to_device_id_bytes: Vec<u8>,
                amount: u64,
                token_id: String,
                memo: String,
                nonce_bytes: Vec<u8>,
            },
            Message {
                to_device_id_bytes: Vec<u8>,
                payload: Vec<u8>,
                memo: String,
                nonce_bytes: Vec<u8>,
            },
        }

        let submit_op = match &params.transaction {
            Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                message,
                nonce,
                ..
            } => {
                info!(
                    "🔍 submit_to_b0x: to_device_id raw bytes (first 8): {:?}",
                    &to_device_id[..8.min(to_device_id.len())]
                );
                SubmitOp::Transfer {
                    to_device_id_bytes: to_device_id.clone(),
                    amount: amount.value(),
                    token_id: String::from_utf8_lossy(token_id).into_owned(),
                    memo: message.clone(),
                    nonce_bytes: nonce.clone(),
                }
            }
            Operation::Generic {
                operation_type,
                data,
                message,
                ..
            } if operation_type.as_slice() == b"online.message" => {
                let to_device_id_bytes =
                    crate::util::text_id::decode_base32_crockford(&params.recipient_device_id)
                        .ok_or_else(|| {
                            DsmError::internal(
                                "submit_to_b0x: recipient_device_id base32 decode failed",
                                None::<std::io::Error>,
                            )
                        })?;
                let mut from_arr = [0u8; 32];
                if actor_device_bytes.len() == 32 {
                    from_arr.copy_from_slice(&actor_device_bytes);
                }
                let mut to_arr = [0u8; 32];
                if to_device_id_bytes.len() == 32 {
                    to_arr.copy_from_slice(&to_device_id_bytes);
                }
                let mut tip_arr = [0u8; 32];
                if sender_tip_bytes.len() == 32 {
                    tip_arr.copy_from_slice(&sender_tip_bytes);
                }
                let nonce_arr = dsm::envelope::compute_online_message_nonce_v3(
                    &from_arr, &to_arr, &tip_arr, params.seq, data, message,
                );
                SubmitOp::Message {
                    to_device_id_bytes,
                    payload: data.clone(),
                    memo: message.clone(),
                    nonce_bytes: nonce_arr.to_vec(),
                }
            }
            _ => {
                return Err(DsmError::internal(
                    "submit_to_b0x: expected Operation::Transfer or online.message",
                    None::<std::io::Error>,
                ));
            }
        };

        let (invoke_method, arg_pack, to_device_id_bytes, log_context) = match submit_op {
            SubmitOp::Transfer {
                to_device_id_bytes,
                amount,
                token_id,
                memo,
                nonce_bytes,
            } => {
                let transfer_req = dsm::types::proto::OnlineTransferRequest {
                    token_id: token_id.clone(),
                    to_device_id: to_device_id_bytes.clone(),
                    amount,
                    memo: memo.clone(),
                    signature: params.signature.clone(),
                    nonce: nonce_bytes.clone(),
                    from_device_id: actor_device_bytes.clone(),
                    chain_tip: sender_tip_bytes.clone(),
                    seq: params.seq,
                    receipt_commit: params.receipt_commit.clone(),
                    canonical_operation_bytes: params.canonical_operation_bytes.clone(),
                };
                info!(
                    "submit_to_b0x: transfer req context from_device_id(first4)={:?} seq={}",
                    &transfer_req.from_device_id[..4.min(transfer_req.from_device_id.len())],
                    transfer_req.seq
                );

                let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
                transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
                    DsmError::internal(
                        format!("OnlineTransferRequest encode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                let arg_pack = dsm::types::proto::ArgPack {
                    schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
                    codec: dsm::types::proto::Codec::Proto as i32,
                    body: transfer_req_bytes.clone(),
                };
                let decoded_req = dsm::types::proto::OnlineTransferRequest::decode(&*arg_pack.body)
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "decode transfer req",
                            "OnlineTransferRequest",
                            None::<String>,
                            Some(e),
                        )
                    })?;
                debug!(
                    "submit_to_b0x: decoded OnlineTransferRequest signature len={}",
                    decoded_req.signature.len()
                );
                assert_eq!(decoded_req.signature, params.signature);

                (
                    "wallet.send".to_string(),
                    arg_pack,
                    to_device_id_bytes,
                    format!("amount={}, token={}", amount, token_id),
                )
            }
            SubmitOp::Message {
                to_device_id_bytes,
                payload,
                memo,
                nonce_bytes,
            } => {
                let msg_req = dsm::types::proto::OnlineMessageRequest {
                    to_device_id: to_device_id_bytes.clone(),
                    payload: payload.clone(),
                    memo: memo.clone(),
                    signature: params.signature.clone(),
                    nonce: nonce_bytes.clone(),
                    from_device_id: actor_device_bytes.clone(),
                    chain_tip: sender_tip_bytes.clone(),
                    seq: params.seq,
                };
                let mut msg_req_bytes = Vec::with_capacity(msg_req.encoded_len());
                msg_req.encode(&mut msg_req_bytes).map_err(|e| {
                    DsmError::internal(
                        format!("OnlineMessageRequest encode failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                let arg_pack = dsm::types::proto::ArgPack {
                    schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
                    codec: dsm::types::proto::Codec::Proto as i32,
                    body: msg_req_bytes.clone(),
                };
                let decoded_req = dsm::types::proto::OnlineMessageRequest::decode(&*arg_pack.body)
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "decode message req",
                            "OnlineMessageRequest",
                            None::<String>,
                            Some(e),
                        )
                    })?;
                debug!(
                    "submit_to_b0x: decoded OnlineMessageRequest signature len={}",
                    decoded_req.signature.len()
                );
                assert_eq!(decoded_req.signature, params.signature);

                (
                    "message.send".to_string(),
                    arg_pack,
                    to_device_id_bytes,
                    format!("payload_len={}", payload.len()),
                )
            }
        };

        // Build Invoke with method="wallet.send"
        // IMPORTANT: SPHINCS+ signatures are large (~50KB). The canonical sender
        // signature already lives in OnlineTransferRequest.signature / OnlineMessageRequest.signature.
        // Do NOT duplicate that signature into EvidenceOracle.signature for b0x transport,
        // or envelopes can exceed storage-node body limits (HTTP 413).
        // Keep only oracle_key in evidence so receivers can still verify without extra lookups.
        // Use the wallet's SPHINCS+ public key from the state machine (updated by
        // initialize_device_keys) — NOT the genesis public key from AppState.
        let sender_signing_public_key = self
            .core_sdk
            .get_current_state()
            .map(|s| s.device_info.public_key.clone())
            .unwrap_or_else(|_| {
                crate::sdk::app_state::AppState::get_public_key().unwrap_or_default()
            });

        let evidence = if !sender_signing_public_key.is_empty() {
            Some(dsm::types::proto::Evidence {
                kind: Some(dsm::types::proto::evidence::Kind::Oracle(
                    dsm::types::proto::EvidenceOracle {
                        payload: vec![],
                        signature: vec![],
                        // Carry sender signing public key so receivers can verify without contact lookups.
                        oracle_key: sender_signing_public_key.clone(),
                    },
                )),
            })
        } else {
            None
        };

        let post_state_hash = match params.next_chain_tip.as_ref() {
            Some(t) if t.len() == 32 => Some(dsm::types::proto::Hash32 { v: t.clone() }),
            _ => None,
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: invoke_method,
            args: Some(arg_pack),
            pre_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            post_state_hash,
            cosigners: vec![],
            evidence,
            nonce: None,
        };

        // Build UniversalOp with the Invoke
        let local_genesis_bytes = self.core_sdk.local_genesis_hash().await?;
        // AF-4 fix: routing MUST be keyed by the *sender's* current relationship parent tip (hn)
        // (whitepaper: b0x key rotates with hn; sender posts to the key derived from the live parent)
        // Do NOT use a cached/stale recipient tip for routing.
        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 {
                v: message_id_bytes.to_vec(),
            }),
            actor: actor_device_bytes.clone(),
            genesis_hash: local_genesis_bytes.clone(),
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let universal_tx = dsm::types::proto::UniversalTx {
            ops: vec![op],
            atomic: false,
        };

        let envelope = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: actor_device_bytes,
                genesis_hash: local_genesis_bytes.to_vec(),
                // chain_tip in headers must be the live relationship parent tip used for addressing
                chain_tip: sender_tip_bytes,
                seq: 0,
            }),
            message_id: message_id_bytes.to_vec(),
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                universal_tx,
            )),
        };

        info!("📦 submit_to_b0x: envelope built with {}", log_context);

        let mut buf = Vec::with_capacity(envelope.encoded_len());
        prost::Message::encode(&envelope, &mut buf).map_err(|e| {
            DsmError::internal(
                format!("Envelope encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        info!("submit_to_b0x: envelope bytes={}", buf.len());

        // Signature is embedded in the request body only (canonical path).
        // Avoid duplicating into EvidenceOracle.signature to keep payload bounded.
        if !params.signature.is_empty() {
            info!(
                "submit_to_b0x: embedded sender signature in request (len={})",
                params.signature.len()
            );
        }

        // 3) Replicate to multiple endpoints; require quorum_k successes.
        let auth_device_id = self.device_id.clone(); // base32 textual id for auth header

        // Derive recipient routing key from the *validated* params (base32(32) string).
        // This avoids accidental mismatches if the Operation payload was constructed incorrectly.
        let recipient_device_id_b32 = params.recipient_device_id.trim().to_string();
        let recipient_device_id_from_op = text_id::encode_base32_crockford(&to_device_id_bytes);
        if recipient_device_id_b32 != recipient_device_id_from_op {
            warn!(
                "submit_to_b0x: recipient_device_id mismatch: params={} op={} (using params)",
                &recipient_device_id_b32[..16.min(recipient_device_id_b32.len())],
                &recipient_device_id_from_op[..16.min(recipient_device_id_from_op.len())]
            );
        }

        // §16.4 Tip-scoped b0x address rotation:
        // The inbox key is always the explicit rotated address.
        let routing_key = params.routing_address.clone();
        info!(
            "🔄 submit_to_b0x: using rotated b0x address = {}... (tip-scoped §16.4)",
            &routing_key[..16.min(routing_key.len())]
        );
        if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            println!(
                "submit route debug: routing={} recipient_device_id={} recipient_genesis_hash={} sender_chain_tip={}",
                routing_key,
                params.recipient_device_id,
                params.recipient_genesis_hash,
                params.sender_chain_tip,
            );
        }

        // DEBUG: Log the routing key prefix to diagnose mismatch issues
        info!(
            "🔍 submit_to_b0x: recipient routing key = {} (op_bytes_len={})",
            &routing_key[..16.min(routing_key.len())],
            to_device_id_bytes.len()
        );

        // 🔎 Instrument outgoing auth device id format (NO token leakage)
        // If this ever logs dotted=true or base32_32=false, we will get retrieve/submit mismatches.
        let auth_device_id_diag = auth_device_id.trim();
        info!(
            "🔐 submit_to_b0x auth_device_id diag: len={} prefix={}... base32_32={} dotted={}",
            auth_device_id_diag.len(),
            &auth_device_id_diag[..8.min(auth_device_id_diag.len())],
            base32_decodes_to_32_bytes(auth_device_id_diag),
            looks_like_dotted_decimal_bytes(auth_device_id_diag)
        );

        // Get healthy endpoints for submission
        let endpoints: Vec<String> = self
            .storage_node_endpoints
            .iter()
            .filter(|ep| futures::executor::block_on(self.circuit_breaker.is_node_healthy(ep)))
            .cloned()
            .collect();

        if endpoints.is_empty() {
            return Err(DsmError::internal(
                "No healthy endpoints available for submission",
                None::<std::io::Error>,
            ));
        }

        let total = endpoints.len();
        let quorum = self.quorum_k.min(total);
        let mut successes = 0usize;
        let mut submit_errors: Vec<String> = Vec::new();

        // Submit to endpoints with enhanced retry logic
        for epc in endpoints {
            match self
                .submit_with_retry(
                    &epc,
                    &buf,
                    &auth_device_id,
                    &routing_key,
                    &message_id_b32,
                    retry_config,
                )
                .await
            {
                Ok(()) => {
                    successes += 1;
                    if successes >= quorum {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to submit to endpoint {}: {}", epc, e);
                    submit_errors.push(format!("{}: {}", epc, e));
                    // Continue to next endpoint
                }
            }
        }

        if successes >= quorum {
            info!(
                "✅ submit quorum satisfied: {}/{} (K={})",
                successes, total, quorum
            );
            return Ok(message_id_b32);
        }

        Err(DsmError::internal(
            format!(
                "submit quorum not met: {}/{} (K={}); msg_id={}; errors={:?}",
                successes, total, quorum, message_id_b32, submit_errors
            ),
            None::<std::io::Error>,
        ))
    }

    /// Submit envelope to a single endpoint with retry logic
    async fn submit_with_retry(
        &mut self,
        endpoint: &str,
        envelope_buf: &[u8],
        auth_device_id: &str,
        routing_key: &str,
        message_id_b32: &str,
        retry_config: &B0xRetryConfig,
    ) -> Result<(), DsmError> {
        let mut attempt = 0;
        let mut delay = std::time::Duration::from_millis(retry_config.base_delay_ms);

        loop {
            // Ensure token for this endpoint
            let token = match self.ensure_token_for_endpoint(endpoint).await {
                Ok(t) => t,
                Err(e) => {
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                    return Err(DsmError::internal(
                        format!("Failed to get token for endpoint {}: {}", endpoint, e),
                        None::<std::io::Error>,
                    ));
                }
            };

            let url = format!("{}/api/v2/b0x/submit", endpoint);
            if attempt == 0 {
                info!(
                    "🚀 submit -> {} (recipient={}...)",
                    url,
                    &routing_key[..8.min(routing_key.len())]
                );
            } else {
                info!("🔄 retry submit -> {} (attempt {})", url, attempt + 1);
            }

            let mut req = self
                .http_client
                .post(&url)
                .header("Content-Type", "application/protobuf")
                .header("Authorization", format!("DSM {}:{}", auth_device_id, token))
                .header("x-dsm-message-id", message_id_b32)
                .header("x-dsm-recipient", routing_key)
                .body(envelope_buf.to_vec());

            if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                req = req.timeout(std::time::Duration::from_secs(2));
            }

            let resp = req.send().await;

            match resp {
                Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "submit success debug: endpoint={} route={} msg_id={}",
                            endpoint, routing_key, message_id_b32
                        );
                    }
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    return Ok(());
                }
                Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                    // Idempotent replay: treat as success since the message_id was already accepted.
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "submit conflict debug: endpoint={} route={} msg_id={}",
                            endpoint, routing_key, message_id_b32
                        );
                    }
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    return Ok(());
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    if attempt == 0 {
                        warn!("⚠️ 401 Unauthorized at {}; refreshing token...", endpoint);
                        self.purge_persisted_token_for_endpoint(endpoint).await;
                        // Try to re-register immediately
                        if let Ok(tok) = self.register_device_on(endpoint).await {
                            if let Ok((genesis_b32, device_id_b32, cache_key)) =
                                self.auth_binding_key(endpoint).await
                            {
                                self.tokens_by_endpoint
                                    .write()
                                    .await
                                    .insert(cache_key, tok.clone());
                                let _ = crate::storage::client_db::store_auth_token(
                                    endpoint,
                                    &device_id_b32,
                                    &genesis_b32,
                                    &tok,
                                );
                                // Continue to next attempt (retry)
                                attempt += 1;
                                if attempt < retry_config.max_retries {
                                    tokio::time::sleep(delay).await;
                                    delay = std::cmp::min(
                                        delay.mul_f64(retry_config.backoff_multiplier),
                                        std::time::Duration::from_millis(retry_config.max_delay_ms),
                                    );
                                    continue;
                                }
                            }
                        }
                        warn!("❌ Token refresh failed at {}", endpoint);
                        self.circuit_breaker.mark_node_failed(endpoint).await;
                        return Err(DsmError::internal(
                            format!("Token refresh failed at {}", endpoint),
                            None::<std::io::Error>,
                        ));
                    } else {
                        warn!("❌ 401 Unauthorized persists at {} after refresh", endpoint);
                        self.circuit_breaker.mark_node_failed(endpoint).await;
                        return Err(DsmError::internal(
                            format!("401 Unauthorized persists at {} after refresh", endpoint),
                            None::<std::io::Error>,
                        ));
                    }
                }
                Ok(r) => {
                    let status = r.status();
                    let body_txt = r.text().await.unwrap_or_default();
                    warn!("Submit failed {} via {}: {}", status, endpoint, body_txt);
                    self.circuit_breaker.mark_node_failed(endpoint).await;

                    // Check if this is a retryable error
                    if Self::is_retryable_error(status) && attempt < retry_config.max_retries {
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(
                            delay.mul_f64(retry_config.backoff_multiplier),
                            std::time::Duration::from_millis(retry_config.max_delay_ms),
                        );
                        continue;
                    } else {
                        return Err(DsmError::internal(
                            format!("Submit failed {} via {}: {}", status, endpoint, body_txt),
                            None::<std::io::Error>,
                        ));
                    }
                }
                Err(e) => {
                    warn!("HTTP error via {}: {}", endpoint, e);
                    self.circuit_breaker.mark_node_failed(endpoint).await;

                    // Network errors are retryable
                    if attempt < retry_config.max_retries {
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(
                            delay.mul_f64(retry_config.backoff_multiplier),
                            std::time::Duration::from_millis(retry_config.max_delay_ms),
                        );
                        continue;
                    } else {
                        return Err(DsmError::internal(
                            format!(
                                "HTTP error via {} after {} attempts: {}",
                                endpoint,
                                attempt + 1,
                                e
                            ),
                            None::<std::io::Error>,
                        ));
                    }
                }
            }
        }
    }

    /// Validate submission parameters comprehensively
    fn validate_submission_params(&self, params: &B0xSubmissionParams) -> Result<(), DsmError> {
        // Validate recipient device ID
        if params.recipient_device_id.is_empty() {
            return Err(DsmError::internal(
                "recipient_device_id cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !is_canonical_auth_device_id(&params.recipient_device_id) {
            return Err(DsmError::internal(
                "recipient_device_id must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate recipient genesis hash
        if params.recipient_genesis_hash.is_empty() {
            return Err(DsmError::internal(
                "recipient_genesis_hash cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.recipient_genesis_hash) {
            return Err(DsmError::internal(
                "recipient_genesis_hash must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate sender genesis hash
        if params.sender_genesis_hash.is_empty() {
            return Err(DsmError::internal(
                "sender_genesis_hash cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.sender_genesis_hash) {
            return Err(DsmError::internal(
                "sender_genesis_hash must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        // Validate sender chain tip
        if params.sender_chain_tip.is_empty() {
            return Err(DsmError::internal(
                "sender_chain_tip cannot be empty",
                None::<std::io::Error>,
            ));
        }
        if !base32_decodes_to_32_bytes(&params.sender_chain_tip) {
            return Err(DsmError::internal(
                "sender_chain_tip must be valid base32 encoding of 32 bytes",
                None::<std::io::Error>,
            ));
        }

        if params.routing_address.is_empty() {
            return Err(DsmError::internal(
                "routing_address cannot be empty",
                None::<std::io::Error>,
            ));
        }
        validate_b0x_address(&params.routing_address)?;

        // Validate operation
        match &params.transaction {
            dsm::types::operations::Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                ..
            } => {
                if to_device_id.len() != 32 {
                    return Err(DsmError::internal(
                        "transfer to_device_id must be exactly 32 bytes",
                        None::<std::io::Error>,
                    ));
                }
                if amount.value() == 0 {
                    return Err(DsmError::internal(
                        "transfer amount cannot be zero",
                        None::<std::io::Error>,
                    ));
                }
                if token_id.is_empty() {
                    return Err(DsmError::internal(
                        "token_id cannot be empty",
                        None::<std::io::Error>,
                    ));
                }
            }
            dsm::types::operations::Operation::Generic {
                operation_type,
                data,
                ..
            } if operation_type.as_slice() == b"online.message" => {
                if data.is_empty() {
                    return Err(DsmError::internal(
                        "online.message payload cannot be empty",
                        None::<std::io::Error>,
                    ));
                }
                if data.len() > 4096 {
                    return Err(DsmError::internal(
                        "online.message payload exceeds 4096 bytes",
                        None::<std::io::Error>,
                    ));
                }
            }
            _ => {
                return Err(DsmError::internal(
                    "only Transfer or online.message operations are supported for b0x submission",
                    None::<std::io::Error>,
                ));
            }
        }

        // Validate signature if present
        if !params.signature.is_empty() && params.signature.len() < 64 {
            return Err(DsmError::internal(
                "signature must be at least 64 bytes if present",
                None::<std::io::Error>,
            ));
        }

        // Validate sender public key if present
        if !params.sender_signing_public_key.is_empty()
            && params.sender_signing_public_key.len() != 64
        {
            return Err(DsmError::internal(
                "sender_signing_public_key must be exactly 64 bytes (SPHINCS+ SPX256s public key)",
                None::<std::io::Error>,
            ));
        }

        Ok(())
    }

    /// Determine if an HTTP status code represents a retryable error
    fn is_retryable_error(status: reqwest::StatusCode) -> bool {
        matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_MANY_REQUESTS
                | reqwest::StatusCode::INTERNAL_SERVER_ERROR
                | reqwest::StatusCode::BAD_GATEWAY
                | reqwest::StatusCode::SERVICE_UNAVAILABLE
                | reqwest::StatusCode::GATEWAY_TIMEOUT
        )
    }

    // ------------------------------------------------------------------------
    // v2 Retrieval & Acknowledgement (Envelope v3 over HTTP)
    // These are implemented conservatively to avoid schema drift:
    // - retrieve: POST /api/v2/b0x/retrieve with a small protobuf request
    // - ack:      POST /api/v2/b0x/ack with a small protobuf request
    // If your proto defines specific messages, wire them here; otherwise
    // this remains a safe, binary-first contract.
    // ------------------------------------------------------------------------

    pub async fn retrieve_from_b0x_v2(
        &mut self,
        b0x_address: &str,
        _limit: usize,
    ) -> Result<Vec<B0xEntry>, DsmError> {
        // Multi-node retrieve: query all healthy endpoints; merge unique entries by id.
        // Generate a unique message ID for this retrieve request (required by auth middleware)
        let mut msg_id_bytes = [0u8; 16];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut msg_id_bytes);
        let msg_id_b32 = text_id::encode_base32_crockford(&msg_id_bytes);

        if b0x_address.is_empty() {
            return Err(DsmError::internal(
                "retrieve_from_b0x_v2 requires a rotated b0x address",
                None::<std::io::Error>,
            ));
        }
        validate_b0x_address(b0x_address)?;

        let endpoints: Vec<String> = self
            .storage_node_endpoints
            .iter()
            .filter(|ep| futures::executor::block_on(self.circuit_breaker.is_node_healthy(ep)))
            .cloned()
            .collect();
        if endpoints.is_empty() {
            return Ok(vec![]);
        }
        let mut map: HashMap<String, dsm::types::proto::Envelope> = HashMap::new();
        let mut unauthorized_count = 0usize;
        let mut polled_count = 0usize;
        for epc in endpoints {
            let token = match self.ensure_token_for_endpoint(&epc).await {
                Ok(t) => t,
                Err(_) => {
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve token debug: endpoint={} route={} token_error=1",
                            epc, b0x_address
                        );
                    }
                    self.circuit_breaker.mark_node_failed(&epc).await;
                    continue;
                }
            };
            let url = format!("{}/api/v2/b0x/retrieve", &epc);
            // NOTE: Do not log the full Authorization header (it contains a bearer-like token).
            let did = self.device_id.trim();
            info!(
                "📬 retrieve_from_b0x_v2: GET {} (device_prefix={}..., msg_id={}...) auth_device_id diag: len={} base32_32={} dotted={}",
                url,
                &did[..8.min(did.len())],
                &msg_id_b32[..8.min(msg_id_b32.len())],
                did.len(),
                base32_decodes_to_32_bytes(did),
                looks_like_dotted_decimal_bytes(did)
            );

            let mut req = self
                .http_client
                .get(&url)
                .header("Accept", "application/protobuf")
                .header("Authorization", format!("DSM {}:{}", self.device_id, token))
                .header("x-dsm-message-id", &msg_id_b32);

            // Scope retrieval to the explicit rotated inbox key.
            req = req.header("x-dsm-b0x-address", b0x_address);

            if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                req = req.header("x-dsm-include-acked", "1");
            }

            let resp = req.send().await;
            polled_count += 1;
            match resp {
                Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve empty debug: endpoint={} route={}",
                            epc, b0x_address
                        );
                    }
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                }
                Ok(r) if r.status().is_success() => {
                    let bytes = r.bytes().await.map_err(|e| {
                        DsmError::internal(
                            format!("retrieve read failed: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    let batch = match dsm::types::proto::BatchEnvelope::decode(bytes.as_ref()) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("BatchEnvelope decode failed from {}: {}", epc, e);
                            self.circuit_breaker.mark_node_failed(&epc).await;
                            continue;
                        }
                    };
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve raw debug: endpoint={} route={} raw_envelopes={}",
                            epc,
                            b0x_address,
                            batch.envelopes.len(),
                        );
                    }
                    for env in batch.envelopes {
                        let key = text_id::encode_base32_crockford(&env.message_id);
                        map.entry(key).or_insert(env);
                    }
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    // Token is invalid for this endpoint/device-id. Purge it and continue with other endpoints.
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve unauthorized debug: endpoint={} route={}",
                            epc, b0x_address
                        );
                    }
                    self.purge_persisted_token_for_endpoint(&epc).await;
                    self.circuit_breaker.mark_node_failed(&epc).await;
                    unauthorized_count += 1;
                    warn!("[DSM_SDK] Inbox token invalid for endpoint {}. Purged token and continuing with other endpoints.", epc);
                }
                Ok(r) => {
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve other-status debug: endpoint={} route={} status={}",
                            epc,
                            b0x_address,
                            r.status()
                        );
                    }
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
                Err(e) => {
                    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
                        println!(
                            "retrieve transport debug: endpoint={} route={} error={}",
                            epc, b0x_address, e
                        );
                    }
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
            }
        }

        let mut entries = Vec::new();
        for (_, env) in map.into_iter() {
            if let Some(mut e) = self.envelope_to_b0x_entry(env) {
                e.inbox_key = b0x_address.to_string();
                entries.push(e);
            }
        }
        info!("📬 retrieve_from_b0x_v2: merged {} entries", entries.len());
        // Only surface InboxTokenInvalid if ALL polled endpoints responded 401.
        // If at least one endpoint is healthy (NO_CONTENT/success/other), do not escalate to UI error.
        if polled_count > 0 && unauthorized_count == polled_count && entries.is_empty() {
            return Err(DsmError::InboxTokenInvalid(
                "Inbox token invalid for this device across all endpoints. Genesis-bound inbox cannot be re-registered. Please re-bind device or contact support.".to_string()
            ));
        }
        Ok(entries)
    }

    pub async fn is_message_acknowledged(
        &mut self,
        message_id_b32: &str,
    ) -> Result<bool, DsmError> {
        let msg_id_bytes = text_id::decode_base32_crockford(message_id_b32).ok_or_else(|| {
            DsmError::internal("message_id must be valid base32", None::<std::io::Error>)
        })?;
        if msg_id_bytes.len() != 16 {
            return Err(DsmError::internal(
                format!(
                    "message_id must decode to 16 bytes (got {})",
                    msg_id_bytes.len()
                ),
                None::<std::io::Error>,
            ));
        }

        let mut request_msg_id = [0u8; 16];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut request_msg_id);
        let request_msg_id_b32 = text_id::encode_base32_crockford(&request_msg_id);

        let endpoints: Vec<String> = self
            .storage_node_endpoints
            .iter()
            .filter(|ep| futures::executor::block_on(self.circuit_breaker.is_node_healthy(ep)))
            .cloned()
            .collect();
        if endpoints.is_empty() {
            return Err(DsmError::internal(
                "No healthy endpoints",
                None::<std::io::Error>,
            ));
        }

        let quorum = self.quorum_k.min(endpoints.len()).max(1);
        let mut acked_count = 0usize;
        let mut seen_unacked = false;
        let mut saw_authoritative_status = false;

        for epc in endpoints {
            let token = match self.ensure_token_for_endpoint(&epc).await {
                Ok(t) => t,
                Err(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                    continue;
                }
            };

            let url = format!("{}/api/v2/b0x/status/{}", epc, message_id_b32);
            let resp = self
                .http_client
                .get(&url)
                .header("Authorization", format!("DSM {}:{}", self.device_id, token))
                .header("x-dsm-message-id", &request_msg_id_b32)
                .send()
                .await;

            match resp {
                Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                    acked_count += 1;
                    saw_authoritative_status = true;
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                    if acked_count >= quorum {
                        return Ok(true);
                    }
                }
                Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                    seen_unacked = true;
                    saw_authoritative_status = true;
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    self.purge_persisted_token_for_endpoint(&epc).await;
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                }
                Ok(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
                Err(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
            }
        }

        match summarize_ack_status(acked_count, quorum, seen_unacked, saw_authoritative_status) {
            AckStatusSummary::Acked => Ok(true),
            AckStatusSummary::NotAcked => Ok(false),
            AckStatusSummary::Unavailable => Err(DsmError::internal(
                format!("message status unavailable or below quorum: acked {acked_count}/{quorum}"),
                None::<std::io::Error>,
            )),
        }
    }

    pub async fn acknowledge_b0x_v2(
        &mut self,
        b0x_address: &str,
        tx_ids: Vec<String>,
    ) -> Result<(), DsmError> {
        if tx_ids.is_empty() {
            return Ok(());
        }
        if b0x_address.is_empty() {
            return Err(DsmError::internal(
                "acknowledge_b0x_v2 requires a rotated b0x address",
                None::<std::io::Error>,
            ));
        }
        validate_b0x_address(b0x_address)?;
        // Multi-node ack: broadcast; require quorum_k successes.
        // Generate a unique message ID for this ack request (required by auth middleware)
        let mut msg_id_bytes = [0u8; 16];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut msg_id_bytes);
        let msg_id_b32 = text_id::encode_base32_crockford(&msg_id_bytes);

        // ACK scoping:
        // - `x-dsm-b0x-address` MUST match the rotated inbox key used at submit.
        // - Authorization remains the recipient device identity for auth only.

        // Build BatchEnvelope with envelopes containing only message_id
        let mut batch = dsm::types::proto::BatchEnvelope::default();
        for tx_id in tx_ids {
            if let Some(mid_bytes) = text_id::decode_base32_crockford(&tx_id) {
                let env = dsm::types::proto::Envelope {
                    message_id: mid_bytes,
                    ..Default::default()
                };
                batch.envelopes.push(env);
            } else {
                warn!("Skipping invalid tx_id in ack: {}", tx_id);
            }
        }

        let mut body = Vec::with_capacity(batch.encoded_len());
        batch.encode(&mut body).map_err(|e| {
            DsmError::internal(
                format!("ack batch encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let endpoints: Vec<String> = self
            .storage_node_endpoints
            .iter()
            .filter(|ep| futures::executor::block_on(self.circuit_breaker.is_node_healthy(ep)))
            .cloned()
            .collect();
        if endpoints.is_empty() {
            return Err(DsmError::internal(
                "No healthy endpoints",
                None::<std::io::Error>,
            ));
        }
        let total = endpoints.len();
        let quorum = self.quorum_k.min(total);
        let mut successes = 0usize;
        for epc in endpoints {
            let token = match self.ensure_token_for_endpoint(&epc).await {
                Ok(t) => t,
                Err(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                    continue;
                }
            };
            let url = format!("{}/api/v2/b0x/ack", &epc);

            let mut req = self
                .http_client
                .post(&url)
                .header("Content-Type", "application/protobuf")
                .header("Authorization", format!("DSM {}:{}", self.device_id, token))
                .header("x-dsm-message-id", &msg_id_b32);
            // Explicitly scope ACK to the rotated inbox key that was retrieved.
            req = req.header("x-dsm-b0x-address", b0x_address);

            let resp = req.body(body.clone()).send().await;
            match resp {
                Ok(r)
                    if r.status().is_success() || r.status() == reqwest::StatusCode::NO_CONTENT =>
                {
                    self.circuit_breaker.mark_node_healthy(&epc).await;
                    successes += 1;
                    if successes >= quorum {
                        break;
                    }
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    self.purge_persisted_token_for_endpoint(&epc).await;
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
                Ok(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
                Err(_) => {
                    self.circuit_breaker.mark_node_failed(&epc).await;
                }
            }
        }
        if successes >= quorum {
            info!(
                "✅ ack quorum satisfied: {}/{} (K={})",
                successes, total, quorum
            );
            return Ok(());
        }
        Err(DsmError::internal(
            format!("ack quorum not met: {}/{} (K={})", successes, total, quorum),
            None::<std::io::Error>,
        ))
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    fn envelope_to_b0x_entry(&self, env: dsm::types::proto::Envelope) -> Option<B0xEntry> {
        let tid = text_id::encode_base32_crockford(&env.message_id);
        let (sender_dev, genesis_b32, chain_tip_text) = match &env.headers {
            Some(h) => {
                let dev = crate::util::text_id::encode_base32_crockford(&h.device_id);
                let gen_b32 = text_id::encode_base32_crockford(&h.genesis_hash);
                let tip_txt = crate::util::text_id::encode_base32_crockford(&h.chain_tip);
                (dev, gen_b32, tip_txt)
            }
            None => (String::new(), String::new(), String::new()),
        };

        if let Some(dsm::types::proto::envelope::Payload::UniversalTx(tx)) = &env.payload {
            for op in &tx.ops {
                if let Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)) = &op.kind {
                    if invoke.method == "wallet.send" {
                        if let Some(ref arg_pack) = invoke.args {
                            if let Ok(transfer_req) =
                                dsm::types::proto::OnlineTransferRequest::decode(&*arg_pack.body)
                            {
                                if transfer_req.nonce.len() != 32 {
                                    log::warn!(
                                        "📥 envelope_to_b0x_entry: nonce len={} (expected 32)",
                                        transfer_req.nonce.len()
                                    );
                                }

                                let balance_tick = if transfer_req.nonce.len() >= 8 {
                                    let mut tick_bytes = [0u8; 8];
                                    tick_bytes.copy_from_slice(&transfer_req.nonce[..8]);
                                    u64::from_le_bytes(tick_bytes)
                                } else {
                                    0
                                };
                                let balance_anchor =
                                    dsm::crypto::blake3::domain_hash("DSM/balance-anchor", &[]);
                                let recipient_id =
                                    text_id::encode_base32_crockford(&transfer_req.to_device_id);
                                // Prefer an explicit signature embedded in the OnlineTransferRequest
                                // Fall back to any Evidence::oracle.signature attached to the Invoke if present
                                let sig = if !transfer_req.signature.is_empty() {
                                    transfer_req.signature.clone()
                                } else if let Some(evd) = &invoke.evidence {
                                    match &evd.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.signature.clone()
                                        }
                                        _ => vec![],
                                    }
                                } else {
                                    vec![]
                                };

                                // The sender signs the Operation with recipient = receiver's
                                // PUBLIC KEY (not device_id).  The receiver must reconstruct
                                // the same Operation for signature verification.  Use local
                                // public key since we ARE the recipient.
                                let recipient_owner =
                                    crate::sdk::app_state::AppState::get_public_key()
                                        .unwrap_or_else(|| transfer_req.to_device_id.clone());

                                let transfer_op = Operation::Transfer {
                                    to_device_id: transfer_req.to_device_id.clone(),
                                    amount: dsm::types::token_types::Balance::from_state(
                                        transfer_req.amount,
                                        *balance_anchor.as_bytes(),
                                        balance_tick,
                                    ),
                                    token_id: if transfer_req.token_id.is_empty() {
                                        b"ERA".to_vec()
                                    } else {
                                        transfer_req.token_id.clone().into_bytes()
                                    },
                                    mode: dsm::types::operations::TransactionMode::Unilateral,
                                    nonce: transfer_req.nonce.clone(),
                                    verification:
                                        dsm::types::operations::VerificationType::Standard,
                                    pre_commit: None,
                                    recipient: recipient_owner,
                                    to: recipient_id.clone().into_bytes(),
                                    message: transfer_req.memo.clone(),
                                    signature: sig.clone(),
                                };

                                // Capture sender signing public key from Evidence.oracle.oracle_key if present
                                let sender_pk = match &invoke.evidence {
                                    Some(ev) => match &ev.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.oracle_key.clone()
                                        }
                                        _ => Vec::new(),
                                    },
                                    None => Vec::new(),
                                };

                                info!("📥 envelope_to_b0x_entry: extracted Transfer (amount={}, to={}, sig_len={}, seq={})", transfer_req.amount, recipient_id, sig.len(), transfer_req.seq);
                                let next_tip_bytes = invoke
                                    .post_state_hash
                                    .as_ref()
                                    .map(|h| h.v.clone())
                                    .filter(|v| v.len() == 32)
                                    .unwrap_or_default();
                                let next_tip_text = if next_tip_bytes.len() == 32 {
                                    text_id::encode_base32_crockford(&next_tip_bytes)
                                } else {
                                    chain_tip_text.clone()
                                };
                                let tick_anchor_bytes = if next_tip_bytes.len() == 32 {
                                    next_tip_bytes.clone()
                                } else {
                                    crate::util::text_id::decode_base32_crockford(&chain_tip_text)
                                        .filter(|b| b.len() == 32)
                                        .unwrap_or_else(|| vec![0u8; 32])
                                };
                                return Some(B0xEntry {
                                    transaction_id: tid,
                                    inbox_key: String::new(),
                                    sender_device_id: sender_dev,
                                    sender_genesis_hash: genesis_b32,
                                    sender_chain_tip: chain_tip_text,
                                    next_chain_tip: next_tip_text,
                                    recipient_device_id: recipient_id,
                                    transaction: transfer_op,
                                    signature: sig,
                                    sender_signing_public_key: sender_pk,
                                    tick: anchor_tick_from_tip(&tick_anchor_bytes),
                                    ttl_seconds: 0,
                                    seq: transfer_req.seq,
                                    receipt_commit: transfer_req.receipt_commit.clone(),
                                    canonical_operation_bytes: transfer_req
                                        .canonical_operation_bytes
                                        .clone(),
                                });
                            }
                        }
                    } else if invoke.method == "message.send" {
                        if let Some(ref arg_pack) = invoke.args {
                            if let Ok(msg_req) =
                                dsm::types::proto::OnlineMessageRequest::decode(&*arg_pack.body)
                            {
                                let recipient_id =
                                    text_id::encode_base32_crockford(&msg_req.to_device_id);
                                let msg_op = Operation::Generic {
                                    operation_type: b"online.message".to_vec(),
                                    data: msg_req.payload.clone(),
                                    message: msg_req.memo.clone(),
                                    signature: vec![],
                                };

                                let sig = if !msg_req.signature.is_empty() {
                                    msg_req.signature.clone()
                                } else if let Some(evd) = &invoke.evidence {
                                    match &evd.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.signature.clone()
                                        }
                                        _ => vec![],
                                    }
                                } else {
                                    vec![]
                                };

                                let sender_pk = match &invoke.evidence {
                                    Some(ev) => match &ev.kind {
                                        Some(dsm::types::proto::evidence::Kind::Oracle(oracle)) => {
                                            oracle.oracle_key.clone()
                                        }
                                        _ => Vec::new(),
                                    },
                                    None => Vec::new(),
                                };

                                info!(
                                    "📥 envelope_to_b0x_entry: extracted OnlineMessage (payload_len={}, to={}, sig_len={}, seq={})",
                                    msg_req.payload.len(),
                                    recipient_id,
                                    sig.len(),
                                    msg_req.seq
                                );
                                let next_tip_bytes = invoke
                                    .post_state_hash
                                    .as_ref()
                                    .map(|h| h.v.clone())
                                    .filter(|v| v.len() == 32)
                                    .unwrap_or_default();
                                let next_tip_text = if next_tip_bytes.len() == 32 {
                                    text_id::encode_base32_crockford(&next_tip_bytes)
                                } else {
                                    chain_tip_text.clone()
                                };
                                let tick_anchor_bytes = if next_tip_bytes.len() == 32 {
                                    next_tip_bytes.clone()
                                } else {
                                    crate::util::text_id::decode_base32_crockford(&chain_tip_text)
                                        .filter(|b| b.len() == 32)
                                        .unwrap_or_else(|| vec![0u8; 32])
                                };
                                return Some(B0xEntry {
                                    transaction_id: tid,
                                    inbox_key: String::new(),
                                    sender_device_id: sender_dev,
                                    sender_genesis_hash: genesis_b32,
                                    sender_chain_tip: chain_tip_text,
                                    next_chain_tip: next_tip_text,
                                    recipient_device_id: recipient_id,
                                    transaction: msg_op,
                                    signature: sig,
                                    sender_signing_public_key: sender_pk,
                                    tick: anchor_tick_from_tip(&tick_anchor_bytes),
                                    ttl_seconds: 0,
                                    seq: msg_req.seq,
                                    receipt_commit: Vec::new(),
                                    canonical_operation_bytes: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl B0xSDK {
    /// Push any pending bilateral messages that were persisted for reliability.
    ///
    /// Deterministic rules:
    /// - Only sessions that are not terminal (committed/rejected/failed) are considered.
    /// - A message is constructed from the persisted operation bytes and signatures.
    /// - Signatures: prefer counterparty_signature, otherwise local_signature; if neither
    ///   exists, the record is skipped (fail-closed, no alternate-path signing).
    /// - Recipient genesis hash must be found in the contact store; otherwise skip.
    /// - Sender signing public key is sourced from CoreSDK device identity.
    pub async fn push_pending_bilateral_messages(
        device_id_b32: String,
        core_sdk: Arc<CoreSDK>,
        storage_endpoints: Vec<String>,
    ) -> Result<usize, DsmError> {
        // Ensure DB is ready; ignore init failure and continue with empty result
        let _ = crate::storage::client_db::init_database();

        let sessions = match crate::storage::client_db::get_all_bilateral_sessions() {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "[B0xSDK] push_pending_bilateral_messages: failed to list sessions: {}",
                    e
                );
                return Ok(0);
            }
        };

        if sessions.is_empty() {
            return Ok(0);
        }

        let sender_genesis_hash = core_sdk
            .local_genesis_hash()
            .await
            .map(|v| text_id::encode_base32_crockford(&v))?;
        let sender_chain_tip = core_sdk
            .local_chain_tip()
            .await
            .map(|v| text_id::encode_base32_crockford(&v))?;
        let sender_signing_public_key = core_sdk.get_device_identity().public_key;

        let mut sdk = B0xSDK::new(device_id_b32, core_sdk.clone(), storage_endpoints)?;
        let mut pushed = 0usize;

        for record in sessions {
            // Skip terminal states
            if record.phase == "committed" || record.phase == "rejected" || record.phase == "failed"
            {
                continue;
            }

            if record.counterparty_device_id.len() != 32 {
                warn!(
                    "[B0xSDK] push_pending_bilateral_messages: skipping record with invalid counterparty id len {}",
                    record.counterparty_device_id.len()
                );
                continue;
            }

            // Deserialize operation strictly
            let operation = match crate::storage::client_db::deserialize_operation(
                &record.operation_bytes,
            ) {
                Ok(op) => op,
                Err(e) => {
                    warn!(
                        "[B0xSDK] push_pending_bilateral_messages: failed to deserialize operation: {}",
                        e
                    );
                    continue;
                }
            };

            // Choose signature deterministically
            let signature = if let Some(sig) = record.counterparty_signature.clone() {
                sig
            } else if let Some(sig) = record.local_signature.clone() {
                sig
            } else {
                warn!(
                    "[B0xSDK] push_pending_bilateral_messages: no signature present, commitment prefix={:02x}{:02x}{:02x}{:02x}",
                    record.commitment_hash.first().copied().unwrap_or(0),
                    record.commitment_hash.get(1).copied().unwrap_or(0),
                    record.commitment_hash.get(2).copied().unwrap_or(0),
                    record.commitment_hash.get(3).copied().unwrap_or(0)
                );
                continue;
            };

            // Resolve recipient genesis hash, preferring the persisted session binding.
            let recipient_genesis_hash = if let Some(g) = record.counterparty_genesis_hash.as_ref()
            {
                if g.len() == 32 {
                    text_id::encode_base32_crockford(g)
                } else {
                    warn!(
                        "[B0xSDK] push_pending_bilateral_messages: stored counterparty genesis has invalid length {}",
                        g.len()
                    );
                    continue;
                }
            } else {
                match crate::storage::client_db::get_contact_by_device_id(
                    &record.counterparty_device_id,
                ) {
                    Ok(Some(c)) => text_id::encode_base32_crockford(&c.genesis_hash),
                    Ok(None) => {
                        warn!(
                            "[B0xSDK] push_pending_bilateral_messages: contact not found for counterparty"
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "[B0xSDK] push_pending_bilateral_messages: contact lookup failed: {}",
                            e
                        );
                        continue;
                    }
                }
            };

            let recipient_device_id =
                text_id::encode_base32_crockford(&record.counterparty_device_id);
            let sender_chain_tip_arr = match decode_base32_32("sender_chain_tip", &sender_chain_tip)
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "[B0xSDK] push_pending_bilateral_messages: sender chain tip invalid: {}",
                        e
                    );
                    continue;
                }
            };
            let recipient_genesis_arr =
                match decode_base32_32("recipient_genesis_hash", &recipient_genesis_hash) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                        "[B0xSDK] push_pending_bilateral_messages: recipient genesis invalid: {}",
                        e
                    );
                        continue;
                    }
                };
            let routing_address = match B0xSDK::compute_b0x_address(
                &recipient_genesis_arr,
                &record.counterparty_device_id,
                &sender_chain_tip_arr,
            ) {
                Ok(addr) => addr,
                Err(e) => {
                    warn!(
                        "[B0xSDK] push_pending_bilateral_messages: routing address computation failed: {}",
                        e
                    );
                    continue;
                }
            };

            let params = B0xSubmissionParams {
                recipient_device_id,
                recipient_genesis_hash,
                transaction: operation,
                signature,
                sender_signing_public_key: sender_signing_public_key.clone(),
                sender_genesis_hash: sender_genesis_hash.clone(),
                sender_chain_tip: sender_chain_tip.clone(),
                ttl_seconds: 0,
                // AF-2 remediation: seq participates in canonical signing bytes.
                // We currently do not persist a per-session seq in the SQLite schema
                // (BilateralSessionRecord). Use a deterministic non-zero default so
                // we do not emit new submissions with seq=0.
                // NOTE: This is a stopgap until session rows capture the canonical seq.
                seq: std::cmp::max(1, record.created_at_step),
                next_chain_tip: None,
                receipt_commit: Vec::new(),
                routing_address,
                canonical_operation_bytes: Vec::new(),
            };

            match sdk.submit_to_b0x(params).await {
                Ok(msg_id) => {
                    pushed += 1;
                    info!("[B0xSDK] ✅ pushed pending bilateral (msg_id={})", msg_id);
                }
                Err(e) => {
                    warn!(
                        "[B0xSDK] push_pending_bilateral_messages: submit failed: {}",
                        e
                    );
                }
            }
        }

        Ok(pushed)
    }
}

// -------------------------------
// Tests
// -------------------------------
#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::useless_conversion)]
mod tests {
    use super::*;

    fn dev_id32_b32() -> String {
        // Deterministic 32-byte device id for tests.
        // Must satisfy B0xSDK::new base32(32 bytes) invariant.
        crate::util::text_id::encode_base32_crockford(&[0x11u8; 32])
    }
    use std::sync::Arc;

    #[test]
    fn test_b0x_id_generation() {
        // Use domain-separated salt derivation per §16.4
        let device_id = [0x33u8; 32];
        let salt_g = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &device_id);
        let salt_d = B0xSDK::derive_salt(b"DSM/b0x-salt-D", &device_id);
        let recipient_genesis = [0x11u8; 32];
        let chain_tip = [0x22u8; 32];
        let id = futures::executor::block_on(B0xSDK::b0x_id_for_device_with_salts(
            &recipient_genesis,
            &chain_tip,
            &device_id,
            &salt_g,
            &salt_d,
            0,
        ))
        .unwrap();
        assert!(base32_decodes_to_32_bytes(&id));
    }

    #[test]
    fn test_salts_are_domain_separated() {
        let dev = [0xAAu8; 32];
        let salt_g = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev);
        let salt_d = B0xSDK::derive_salt(b"DSM/b0x-salt-D", &dev);
        // Different domain tags must produce different salts
        assert_ne!(salt_g, salt_d, "genesis and device salts must differ");
    }

    #[test]
    fn test_salts_vary_per_device() {
        let dev_a = [0x01u8; 32];
        let dev_b = [0x02u8; 32];
        let salt_a = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev_a);
        let salt_b = B0xSDK::derive_salt(b"DSM/b0x-salt-G", &dev_b);
        // Different devices must produce different salts (correlation resistance)
        assert_ne!(salt_a, salt_b, "salts must vary per device");
    }

    #[test]
    fn test_address_components_domain_separated() {
        // Verify that address components use different domain tags
        let data = [0x11u8; 32];
        let salt = [0x33u8; 32];

        // h_G uses "DSM/addr-G"
        let h_g = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/addr-G");
            h.update(&data);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        // h_D uses "DSM/addr-D" with SAME input data
        let h_d = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/addr-D");
            h.update(&data);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        // Even with identical data, different domain tags must produce different results
        assert_ne!(
            h_g, h_d,
            "domain tags must differentiate address components"
        );
    }

    #[test]
    fn test_compute_b0x_address_rotation() {
        let genesis = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let device = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let tip1 = dsm::crypto::rng::generate_secure_random(32).expect("rand");
        let tip2 = dsm::crypto::rng::generate_secure_random(32).expect("rand");

        let a1 = B0xSDK::compute_b0x_address(&genesis, &device, &tip1).expect("ok");
        let a2 = B0xSDK::compute_b0x_address(&genesis, &device, &tip2).expect("ok");
        assert_ne!(a1, a2, "addresses must rotate when tip changes");
        assert_eq!(a1.len(), 52, "expected 52 base32 chars for 32-byte digest");
        assert!(base32_decodes_to_32_bytes(&a1));
        assert!(base32_decodes_to_32_bytes(&a2));
    }

    #[test]
    fn test_compute_b0x_address_matches_domain_hashed_formula() {
        let genesis = [0x11u8; 32];
        let device = [0x22u8; 32];
        let tip = [0x33u8; 32];

        let actual = B0xSDK::compute_b0x_address(&genesis, &device, &tip).expect("ok");

        let h_g = B0xSDK::hash_b0x_component("DSM/b0x-G", &genesis);
        let h_d = B0xSDK::hash_b0x_component("DSM/b0x-D", &device);
        let h_t = B0xSDK::hash_b0x_component("DSM/b0x-T", &tip);

        let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/b0x");
        hasher.update(&h_g);
        hasher.update(&h_d);
        hasher.update(&h_t);
        let expected = crate::util::text_id::encode_base32_crockford(hasher.finalize().as_bytes());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_compute_b0x_address_allowed_chars() {
        let genesis = [0u8; 32];
        let device = [1u8; 32];
        let tip = [2u8; 32];
        let a = B0xSDK::compute_b0x_address(&genesis, &device, &tip).expect("ok");
        assert_eq!(a.len(), 52);
        for ch in a.chars() {
            assert!(
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
                "invalid char {}",
                ch
            );
        }
    }

    #[test]
    fn test_compute_b0x_address_for_optional_tip_rejects_missing_tip() {
        let genesis = [7u8; 32];
        let device = [8u8; 32];
        let err = B0xSDK::compute_b0x_address_for_optional_tip(&genesis, &device, None)
            .expect_err("missing tip must fail");
        assert!(
            err.to_string().contains("relationship tip is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_compute_b0x_address_for_optional_tip_rejects_invalid_tip() {
        let genesis = [9u8; 32];
        let device = [10u8; 32];
        let invalid_tip = [11u8; 16];
        let err =
            B0xSDK::compute_b0x_address_for_optional_tip(&genesis, &device, Some(&invalid_tip))
                .expect_err("invalid tip must fail");
        assert!(
            err.to_string()
                .contains("relationship tip must be exactly 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_b0x_address_rejects_legacy_bracketed_format() {
        let legacy = "b0x[TEST][TEST][TEST]";
        assert!(validate_b0x_address(legacy).is_err());
    }

    #[test]
    fn test_summarize_ack_status_requires_quorum_for_success() {
        assert_eq!(
            summarize_ack_status(1, 3, false, true),
            AckStatusSummary::Unavailable
        );
        assert_eq!(
            summarize_ack_status(3, 3, false, true),
            AckStatusSummary::Acked
        );
    }

    #[test]
    fn test_summarize_ack_status_conflict_blocks_sender_progress() {
        assert_eq!(
            summarize_ack_status(0, 3, true, true),
            AckStatusSummary::NotAcked
        );
    }

    #[test]
    fn test_summarize_ack_status_without_authoritative_responses_is_unavailable() {
        assert_eq!(
            summarize_ack_status(0, 3, false, false),
            AckStatusSummary::Unavailable
        );
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new();
        let ep = "http://node";
        assert!(cb.is_node_healthy(ep).await);
        cb.mark_node_failed(ep).await;
        assert!(!cb.is_node_healthy(ep).await);
        cb.mark_node_healthy(ep).await;
        assert!(cb.is_node_healthy(ep).await);
    }

    #[test]
    fn test_sdk_new_scans_tokens() {
        // Construct without endpoints just to call new()
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let device_id = dev_id32_b32();
        let sdk = B0xSDK::new(device_id.clone(), core, vec![]).unwrap();
        assert_eq!(sdk.device_id(), &device_id);
    }

    #[test]
    fn test_sdk_new_rejects_dotted_decimal_device_id() {
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let res = B0xSDK::new(
            "1.2.3.4".to_string(),
            core,
            vec!["http://127.0.0.1:8080".to_string()],
        );
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_envelope_to_b0x_entry_preserves_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let sdk = B0xSDK::new(dev_id32_b32(), core, vec![]).unwrap();

        // Build an OnlineTransferRequest with an embedded signature
        let transfer_req = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: vec![0x11; 32],
            amount: 42,
            memo: "test".to_string(),
            signature: vec![1, 2, 3, 4, 5],
            nonce: vec![0xAA; 32],
            from_device_id: vec![0x22; 32],
            chain_tip: vec![0x33; 32],
            seq: 1,
            receipt_commit: vec![],
            canonical_operation_bytes: vec![],
        };
        let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
        transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineTransferRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Build ArgPack directly (not serialized - passed as struct)
        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            codec: dsm::types::proto::Codec::Proto as i32,
            body: transfer_req_bytes.clone(),
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "wallet.send".to_string(),
            args: Some(arg_pack),
            pre_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            post_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            genesis_hash: vec![3; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                chain_tip: vec![7; 32],
                genesis_hash: vec![0; 32],
                seq: 5,
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");
        assert_eq!(entry.signature, vec![1, 2, 3, 4, 5]);
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_to_b0x_entry_prefers_transfer_sig_but_falls_back_to_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let sdk = B0xSDK::new(dev_id32_b32(), core, vec![]).unwrap();

        // Build an OnlineTransferRequest WITHOUT an embedded signature
        let transfer_req = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: vec![0x11; 32],
            amount: 42,
            memo: "test".to_string(),
            signature: vec![],
            nonce: vec![0xBB; 32],
            from_device_id: vec![0x44; 32],
            chain_tip: vec![0x55; 32],
            seq: 2,
            receipt_commit: vec![],
            canonical_operation_bytes: vec![],
        };
        let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
        transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineTransferRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            codec: dsm::types::proto::Codec::Proto as i32,
            body: transfer_req_bytes.clone(),
        };

        let evidence = Some(dsm::types::proto::Evidence {
            kind: Some(dsm::types::proto::evidence::Kind::Oracle(
                dsm::types::proto::EvidenceOracle {
                    payload: vec![],
                    signature: vec![9, 8, 7],
                    oracle_key: vec![],
                },
            )),
        });

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "wallet.send".to_string(),
            args: Some(arg_pack),
            pre_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            post_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            cosigners: vec![],
            evidence,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            genesis_hash: vec![3; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                chain_tip: vec![7; 32],
                genesis_hash: vec![0; 32],
                seq: 5,
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");
        assert_eq!(entry.signature, vec![9, 8, 7]);
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_to_b0x_entry_online_message_payload_and_signature(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let sdk = B0xSDK::new(dev_id32_b32(), core, vec![]).unwrap();

        let payload = vec![1, 2, 3, 4, 5, 6];
        let memo = "hello".to_string();
        let msg_req = dsm::types::proto::OnlineMessageRequest {
            to_device_id: vec![0x11; 32],
            payload: payload.clone(),
            memo: memo.clone(),
            signature: vec![9, 9, 9],
            nonce: vec![0xAA; 32],
            from_device_id: vec![0x22; 32],
            chain_tip: vec![0x33; 32],
            seq: 7,
        };
        let mut msg_req_bytes = Vec::with_capacity(msg_req.encoded_len());
        msg_req.encode(&mut msg_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineMessageRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            codec: dsm::types::proto::Codec::Proto as i32,
            body: msg_req_bytes,
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "message.send".to_string(),
            args: Some(arg_pack),
            pre_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            post_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            genesis_hash: vec![3; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                chain_tip: vec![7; 32],
                genesis_hash: vec![0; 32],
                seq: 5,
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");

        assert_eq!(
            entry.recipient_device_id,
            crate::util::text_id::encode_base32_crockford(&[0x11u8; 32])
        );
        assert_eq!(entry.signature, vec![9, 9, 9]);

        match entry.transaction {
            Operation::Generic {
                operation_type,
                data,
                message,
                ..
            } => {
                assert_eq!(operation_type.as_slice(), b"online.message");
                assert_eq!(data, payload);
                assert_eq!(message, memo);
            }
            other => panic!("expected Generic op, got {other:?}"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_to_b0x_entry_uses_post_state_hash_as_next_tip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let core = Arc::new(CoreSDK::new().expect("CoreSDK"));
        let sdk = B0xSDK::new(dev_id32_b32(), core, vec![]).unwrap();

        let post_tip = vec![0x42; 32];
        let transfer_req = dsm::types::proto::OnlineTransferRequest {
            token_id: "ERA".to_string(),
            to_device_id: vec![0x11; 32],
            amount: 7,
            memo: "tip".to_string(),
            signature: vec![1, 2, 3],
            nonce: vec![0xAA; 32],
            from_device_id: vec![0x22; 32],
            chain_tip: vec![0x33; 32],
            seq: 9,
            receipt_commit: vec![],
            canonical_operation_bytes: vec![],
        };
        let mut transfer_req_bytes = Vec::with_capacity(transfer_req.encoded_len());
        transfer_req.encode(&mut transfer_req_bytes).map_err(|e| {
            DsmError::internal(
                format!("OnlineTransferRequest encode failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let arg_pack = dsm::types::proto::ArgPack {
            schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            codec: dsm::types::proto::Codec::Proto as i32,
            body: transfer_req_bytes,
        };

        let invoke = dsm::types::proto::Invoke {
            program: None,
            method: "wallet.send".to_string(),
            args: Some(arg_pack),
            pre_state_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
            post_state_hash: Some(dsm::types::proto::Hash32 {
                v: post_tip.clone(),
            }),
            cosigners: vec![],
            evidence: None,
            nonce: None,
        };

        let op = dsm::types::proto::UniversalOp {
            op_id: Some(dsm::types::proto::Hash32 { v: vec![9; 32] }),
            actor: vec![2; 32],
            genesis_hash: vec![3; 32],
            kind: Some(dsm::types::proto::universal_op::Kind::Invoke(invoke)),
        };

        let env = dsm::types::proto::Envelope {
            version: 3,
            headers: Some(dsm::types::proto::Headers {
                device_id: vec![0xAB; 32],
                chain_tip: vec![7; 32],
                genesis_hash: vec![0; 32],
                seq: 5,
            }),
            message_id: vec![8; 16],
            payload: Some(dsm::types::proto::envelope::Payload::UniversalTx(
                dsm::types::proto::UniversalTx {
                    ops: vec![op],
                    atomic: true,
                },
            )),
        };

        let entry = sdk
            .envelope_to_b0x_entry(env)
            .expect("should extract B0xEntry");

        let post_b32 = crate::util::text_id::encode_base32_crockford(&post_tip);
        assert_eq!(entry.next_chain_tip, post_b32);

        Ok(())
    }
}
