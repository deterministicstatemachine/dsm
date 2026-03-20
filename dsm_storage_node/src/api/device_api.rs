//! Device registration and management API

#[cfg(test)]
use crate::replication::{ReplicationConfig, ReplicationManager};
use axum::body::Bytes;
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
};
use dsm::types::proto as pb;
use prost::Message;
use std::sync::Arc;

#[cfg(test)]
use crate::AppState;
use dsm_sdk::util::text_id;
use log::info;

// Left for potential future JSON-based tools, but not used in protobuf-only path
#[allow(dead_code)]
#[derive(Debug)]
pub struct RegisterDeviceRequest {
    pub device_id: String,
    pub pubkey: String,       // base32-encoded public key
    pub genesis_hash: String, // base32-encoded genesis hash
}

#[derive(Debug)]
pub enum RegisterError {
    InvalidDeviceId,
    InvalidPubkey,
    InvalidGenesisHash,
    DeviceAlreadyExists,
    DatabaseError(String),
}

impl IntoResponse for RegisterError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            RegisterError::InvalidDeviceId => (StatusCode::BAD_REQUEST, "Invalid device_id format"),
            RegisterError::InvalidPubkey => (StatusCode::BAD_REQUEST, "Invalid pubkey format"),
            RegisterError::InvalidGenesisHash => {
                (StatusCode::BAD_REQUEST, "Invalid genesis_hash format")
            }
            RegisterError::DeviceAlreadyExists => {
                (StatusCode::CONFLICT, "Device already registered")
            }
            RegisterError::DatabaseError(e) => {
                log::error!("Database error during device registration: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
        };
        (status, message).into_response()
    }
}

/// Register a new device with the storage node.
/// Generates an auth token, hashes it, and stores in the devices table.
pub async fn register_device(
    Extension(state): Extension<Arc<crate::AppState>>,
    body: Bytes,
) -> Result<Vec<u8>, RegisterError> {
    // Decode protobuf request
    let req = pb::RegisterDeviceRequest::decode(body.as_ref())
        .map_err(|_e| RegisterError::InvalidDeviceId)?;
    // Validate device_id: must be exactly 32 raw bytes
    if req.device_id.len() != 32 {
        return Err(RegisterError::InvalidDeviceId);
    }

    // Validate pubkey: must be non-empty raw bytes
    if req.pubkey.is_empty() {
        return Err(RegisterError::InvalidPubkey);
    }

    // Validate genesis_hash: must be exactly 32 raw bytes
    if req.genesis_hash.len() != 32 {
        return Err(RegisterError::InvalidGenesisHash);
    }

    // Convert to Base32 for DB storage (DB uses string device_id)
    let device_id_b32 = text_id::encode_base32_crockford(&req.device_id);

    // Generate a secure random auth token (raw 32 bytes)
    use rand::Rng;
    let token_bytes: [u8; 32] = rand::thread_rng().gen();

    // Hash the token using blake3
    let token_hash = blake3::hash(&token_bytes);
    let token_hash_bytes = token_hash.as_bytes().to_vec();

    // Insert into database
    let rows_affected = crate::db::register_device(
        &state.db_pool,
        &device_id_b32,
        &req.genesis_hash,
        &req.pubkey,
        &token_hash_bytes,
    )
    .await
    .map_err(|e| RegisterError::DatabaseError(e.to_string()))?;

    // Check if the insert actually happened (rows_affected = 0 means device already exists)
    if rows_affected == 0 {
        return Err(RegisterError::DeviceAlreadyExists);
    }

    info!(
        "Registered new device: {} with genesis_hash: {}",
        device_id_b32,
        text_id::encode_base32_crockford(&req.genesis_hash)
    );

    // Encode protobuf response with raw token bytes
    let resp = pb::RegisterDeviceResponse {
        token: token_bytes.to_vec(),
    };
    let mut out = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut out)
        .map_err(|e| RegisterError::DatabaseError(e.to_string()))?;
    Ok(out)
}

pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/device/register",
            axum::routing::post(register_device),
        )
        .route("/api/v2/device/token", axum::routing::post(reissue_token))
        .route(
            "/api/v2/device/{device_id}",
            axum::routing::get(get_device_identity),
        )
        .layer(Extension(state))
}

/// Retrieve the registered genesis hash and pubkey for a device.
/// Storage nodes remain dumb indexers: this is a raw identity lookup only.
pub async fn get_device_identity(
    Path(device_id): Path<String>,
    Extension(state): Extension<Arc<crate::AppState>>,
) -> Result<Vec<u8>, StatusCode> {
    let device_id_bytes =
        text_id::decode_base32_crockford(device_id.trim()).ok_or(StatusCode::BAD_REQUEST)?;
    if device_id_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let stored = crate::db::get_device(&state.db_pool, device_id.trim())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some((genesis_hash, pubkey)) = stored else {
        return Err(StatusCode::NOT_FOUND);
    };
    if genesis_hash.len() != 32 || pubkey.is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let resp = pb::RegisterDeviceRequest {
        device_id: device_id_bytes,
        pubkey,
        genesis_hash,
    };
    let mut out = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut out)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(out)
}

/// Re-issue a token for an existing device. This accepts a RegisterDeviceRequest
/// and, if the device exists and the provided pubkey/genesis_hash match, generates
/// and persists a fresh token, returning it in RegisterDeviceResponse.
pub async fn reissue_token(
    Extension(state): Extension<Arc<crate::AppState>>,
    body: Bytes,
) -> Result<Vec<u8>, RegisterError> {
    // Decode protobuf request
    let req = pb::RegisterDeviceRequest::decode(body.as_ref())
        .map_err(|_e| RegisterError::InvalidDeviceId)?;

    // Basic validations: fields are now raw bytes
    if req.device_id.len() != 32 {
        return Err(RegisterError::InvalidDeviceId);
    }
    if req.pubkey.is_empty() {
        return Err(RegisterError::InvalidPubkey);
    }
    if req.genesis_hash.len() != 32 {
        return Err(RegisterError::InvalidGenesisHash);
    }

    // Convert to Base32 for DB lookup
    let device_id_b32 = text_id::encode_base32_crockford(&req.device_id);

    // Lookup existing device
    let (stored_genesis, stored_pubkey) = crate::db::get_device(&state.db_pool, &device_id_b32)
        .await
        .map_err(|e| RegisterError::DatabaseError(e.to_string()))?
        .ok_or(RegisterError::DeviceAlreadyExists)?;

    if stored_genesis != req.genesis_hash || stored_pubkey != req.pubkey {
        // Provided identity doesn't match stored device
        return Err(RegisterError::InvalidDeviceId);
    }

    // Generate and store a new token (raw bytes)
    use rand::Rng;
    let token_bytes: [u8; 32] = rand::thread_rng().gen();
    let token_hash = blake3::hash(&token_bytes);
    let token_hash_bytes = token_hash.as_bytes().to_vec();

    crate::db::update_device_token_hash(&state.db_pool, &device_id_b32, &token_hash_bytes)
        .await
        .map_err(|e| RegisterError::DatabaseError(e.to_string()))?;

    let resp = pb::RegisterDeviceResponse {
        token: token_bytes.to_vec(),
    };
    let mut out = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut out)
        .map_err(|e| RegisterError::DatabaseError(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DBPool;
    use axum::body::Bytes;
    use dsm::types::proto as pb;
    use prost::Message;
    use std::sync::Arc;

    struct TestDb {
        pool: Arc<DBPool>,
    }

    impl TestDb {
        async fn new() -> Self {
            // Use test database or skip tests if not configured
            let database_url = std::env::var("DSM_DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage_node1".to_string());

            let pool = crate::db::create_pool(&database_url, false)
                .unwrap_or_else(|e| panic!("Failed to connect to test database: {e}"));

            Self {
                pool: Arc::new(pool),
            }
        }
    }

    #[test]
    fn test_register_device_success() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
                eprintln!("Skipping DB test (set DSM_RUN_DB_TESTS=1 to enable)");
                return;
            }

            let test_db = TestDb::new().await;
            let replication_config = ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            };
            let replication_manager = Arc::new(
                ReplicationManager::new(
                    replication_config,
                    "test-node".to_string(),
                    "http://localhost:8080".to_string(),
                    std::path::Path::new("certs/node.crt"),
                )
                .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
            );
            let state = AppState::new(
                "test-node".to_string(),
                None,
                test_db.pool.clone(),
                replication_manager,
            );

            let req = pb::RegisterDeviceRequest {
                device_id: [1u8; 32].to_vec(),
                pubkey: [2u8; 32].to_vec(),
                genesis_hash: [3u8; 32].to_vec(),
            };
            let mut buf = Vec::new();
            req.encode(&mut buf)
                .unwrap_or_else(|e| panic!("encode request failed: {e}"));

            let result = register_device(Extension(Arc::new(state)), Bytes::from(buf)).await;
            assert!(result.is_ok());

            let bytes = result.unwrap_or_else(|e| panic!("register_device failed: {:?}", e));
            let resp = pb::RegisterDeviceResponse::decode(bytes.as_slice())
                .unwrap_or_else(|e| panic!("decode response failed: {e}"));
            assert!(!resp.token.is_empty());
        });
    }

    #[test]
    fn test_register_device_duplicate() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
                eprintln!("Skipping DB test (set DSM_RUN_DB_TESTS=1 to enable)");
                return;
            }

            let test_db = TestDb::new().await;
            let replication_config = ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            };
            let replication_manager = Arc::new(
                ReplicationManager::new(
                    replication_config,
                    "test-node".to_string(),
                    "http://localhost:8080".to_string(),
                    std::path::Path::new("certs/node.crt"),
                )
                .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
            );
            let state = AppState::new(
                "test-node".to_string(),
                None,
                test_db.pool.clone(),
                replication_manager,
            );

            let req = pb::RegisterDeviceRequest {
                device_id: [1u8; 32].to_vec(),
                pubkey: [2u8; 32].to_vec(),
                genesis_hash: [3u8; 32].to_vec(),
            };
            let mut buf = Vec::new();
            req.encode(&mut buf)
                .unwrap_or_else(|e| panic!("encode request failed: {e}"));
            // First registration should succeed
            let result1 =
                register_device(Extension(Arc::new(state.clone())), Bytes::from(buf.clone())).await;
            assert!(result1.is_ok());
            // Second registration should fail
            let result2 = register_device(Extension(Arc::new(state)), Bytes::from(buf)).await;
            assert!(result2.is_err());
        });
    }

    #[test]
    fn test_register_device_invalid_formats() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
                eprintln!("Skipping DB test (set DSM_RUN_DB_TESTS=1 to enable)");
                return;
            }

            let test_db = TestDb::new().await;
            let replication_config = ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            };
            let replication_manager = Arc::new(
                ReplicationManager::new(
                    replication_config,
                    "test-node".to_string(),
                    "http://localhost:8080".to_string(),
                    std::path::Path::new("certs/node.crt"),
                )
                .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
            );
            let state = AppState::new(
                "test-node".to_string(),
                None,
                test_db.pool.clone(),
                replication_manager,
            );

            // Invalid device_id length (not 32 bytes)
            let req = pb::RegisterDeviceRequest {
                device_id: vec![1u8; 5],
                pubkey: vec![2u8; 5],
                genesis_hash: vec![3u8; 5],
            };
            let mut buf = Vec::new();
            req.encode(&mut buf)
                .unwrap_or_else(|e| panic!("encode request failed: {e}"));
            let result =
                register_device(Extension(Arc::new(state.clone())), Bytes::from(buf)).await;
            assert!(matches!(result, Err(RegisterError::InvalidDeviceId)));

            // Invalid pubkey (empty)
            let req = pb::RegisterDeviceRequest {
                device_id: [1u8; 32].to_vec(),
                pubkey: vec![],
                genesis_hash: [3u8; 32].to_vec(),
            };
            let mut buf = Vec::new();
            req.encode(&mut buf)
                .unwrap_or_else(|e| panic!("encode request failed: {e}"));
            let result =
                register_device(Extension(Arc::new(state.clone())), Bytes::from(buf)).await;
            assert!(matches!(result, Err(RegisterError::InvalidPubkey)));

            // Invalid genesis_hash length (not 32 bytes)
            let req = pb::RegisterDeviceRequest {
                device_id: [1u8; 32].to_vec(),
                pubkey: [2u8; 32].to_vec(),
                genesis_hash: vec![3u8; 5],
            };
            let mut buf = Vec::new();
            req.encode(&mut buf)
                .unwrap_or_else(|e| panic!("encode request failed: {e}"));
            let result =
                register_device(Extension(Arc::new(state.clone())), Bytes::from(buf)).await;
            assert!(matches!(result, Err(RegisterError::InvalidPubkey)));
        });
    }
}
