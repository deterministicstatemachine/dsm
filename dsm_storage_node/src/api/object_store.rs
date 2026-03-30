//! DSM Object Store (deterministic, clockless)
//! - Raw bytes only ("application/octet-stream").
//! - Deterministic addresses: H("DSM/object\0" || dlv_id || path || H("DSM/obj-bytes\0" || content)).
//! - Capacity enforced per DLV slot (no clocks, BIGSERIAL ordering only).
//! - No JSON, no wall-clock markers.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use log::{info, warn};
use prost::Message;
use std::sync::Arc;

use super::hardening::blake3_tagged;
use super::validators::validate_vaultpost_smart_policy_if_present;
use crate::auth::DeviceContext;
use crate::db::{self};

// ---------------------- header keys ----------------------
const HDR_DLV_ID: &str = "x-dlv-id"; // Crockford base32 32B DLV partition id
const HDR_PATH: &str = "x-path"; // UTF-8 path (client-defined)
const HDR_CAPACITY: &str = "x-capacity-bytes"; // optional i64 for new slot
const HDR_STAKE_HASH: &str = "x-stake-hash"; // optional Crockford base32 bytes for new slot
const HDR_OBJ_ADDR: &str = "x-object-address"; // response header: Crockford base32 addr

// ---------------------- helpers --------------------------
// Crockford base32 is the only permitted string encoding at protocol boundaries (CLAUDE.md).
// Alphabet: 0-9 A-H J K M N P-T V-Z (32 symbols, uppercase, no padding).
fn encode_b32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    const ALPHA: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buf: u16 = 0;
    let mut bits: u8 = 0;
    for &b in bytes {
        buf = (buf << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHA[((buf >> (bits - 5)) & 0x1f) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn decode_b32(s: &str) -> Option<Vec<u8>> {
    fn v(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'H' => Some(c - b'A' + 10),
            b'J'..=b'K' => Some(c - b'J' + 18),
            b'M'..=b'N' => Some(c - b'M' + 20),
            b'P'..=b'T' => Some(c - b'P' + 22),
            b'V'..=b'Z' => Some(c - b'V' + 27),
            b'O' | b'o' => Some(0),
            b'I' | b'i' | b'L' | b'l' => Some(1),
            b'a'..=b'z' => v(c - 32),
            _ => None,
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for ch in s.bytes() {
        if ch == b'-' || ch == b' ' {
            continue;
        }
        buf = (buf << 5) | v(ch)? as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// addr := H("DSM/object\0" || dlv_id || path || H("DSM/obj-bytes\0" || content))
/// Returns the address as Crockford base32 — the only permitted string encoding at
/// protocol boundaries (CLAUDE.md hex ban).
fn compute_object_address(dlv_id: &[u8], path: &str, content: &[u8]) -> String {
    let content_hash = blake3_tagged("DSM/obj-bytes", content);
    let mut buf = Vec::with_capacity(dlv_id.len() + path.len() + content_hash.len());
    buf.extend_from_slice(dlv_id);
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(&content_hash);
    let addr = blake3_tagged("DSM/object", &buf);
    encode_b32(&addr)
}

/// Public read-only router — vault discovery by any device (no auth required).
/// Storage nodes are index-only (Invariant #12); reads don't require ownership proof.
pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/object/get/{key}", get(get_object_handler))
        .route("/api/v2/object/by-addr/{addr}", get(get_object_handler))
        // Expose ByteCommit endpoints alongside object store (transport-only, deterministic addresses)
        .merge(super::bytecommit::create_router(state.clone()))
    // Registry router is merged in main.rs, not here (avoid duplicate routes)
}

/// Authenticated write router — PUT/DELETE require device_auth middleware.
/// Mounted separately in main.rs behind the device_auth layer to prevent
/// unauthenticated callers from modifying or deleting vault advertisements.
pub fn create_write_router() -> Router<()> {
    Router::new()
        .route("/api/v2/object/put", post(put_object))
        .route("/api/v2/object/delete_proto", post(delete_object_proto))
}

/// PUT raw bytes into a DLV partition under deterministic address.
///
/// Required headers:
/// - x-dlv-id: Crockford base32 32B DLV partition id
/// - x-path:   UTF-8 logical path
///
/// Optional bootstrap headers (first time only):
/// - x-capacity-bytes: i64
/// - x-stake-hash:     Crockford base32 bytes
pub async fn put_object(
    Extension(state): Extension<Arc<crate::AppState>>,
    ctx: Option<Extension<DeviceContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let caller_device = ctx
        .as_ref()
        .map(|c| c.0.device_id.as_str())
        .unwrap_or("<unauthenticated>");
    info!(
        "put_object: handler entered, body_len={}, device={}, headers: dlv_id={}, path={}",
        body.len(),
        caller_device,
        headers
            .get("x-dlv-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>"),
        headers
            .get("x-path")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>"),
    );
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Pre-validate: if this looks like a VaultPostProto carrying a LimboVaultProto
    // with a CryptoCondition that embeds SmartPolicy bytes, ensure those bytes decode.
    // This check is deterministic and side-effect free; on failure, reject with 400.
    if validate_vaultpost_smart_policy_if_present(body.as_ref()).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Required headers
    let dlv_id_b = headers
        .get(HDR_DLV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(decode_b32)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let path = headers
        .get(HDR_PATH)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();

    // Optional slot bootstrap
    let capacity_opt = headers
        .get(HDR_CAPACITY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());
    let stake_hash_opt = headers
        .get(HDR_STAKE_HASH)
        .and_then(|v| v.to_str().ok())
        .and_then(decode_b32);

    // Ensure slot exists (create iff capacity+stake provided)
    let pool = &*state.db_pool;
    let mut exists: bool = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
        warn!("put_object: slot_exists DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !exists {
        match (capacity_opt, stake_hash_opt.as_ref()) {
            (Some(cap), Some(stake)) => {
                db::create_slot(pool, &dlv_id_b, cap, stake)
                    .await
                    .map_err(|e| {
                        warn!("put_object: create_slot DB error: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                exists = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
                    warn!("put_object: slot_exists (post-create) DB error: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }
            _ => return Err(StatusCode::PRECONDITION_REQUIRED),
        }
    }
    if !exists {
        warn!("put_object: slot still does not exist after create attempt");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Compute deterministic address
    let addr = compute_object_address(&dlv_id_b, &path, &body);

    // Store with atomic capacity check (prevents race conditions)
    let new_size: i64 = body.len() as i64;
    db::upsert_object_with_capacity_check(pool, &addr, body.as_ref(), &dlv_id_b, new_size)
        .await
        .map_err(|e| {
            if e.to_string().contains("capacity_exceeded") {
                warn!("DLV capacity exceeded: {}", e);
                metrics::counter!("dsm_storage_objects_put_capacity_exceeded_total").increment(1);
                StatusCode::INSUFFICIENT_STORAGE
            } else {
                warn!("put_object: upsert_object_with_capacity_check DB error: {e}");
                metrics::counter!("dsm_storage_objects_put_error_total").increment(1);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    // Also store a path-indexed copy so that prefix-based list queries
    // (e.g. `?prefix=dbtc/manifold/...`) can discover objects by their
    // logical path.  The capacity-checked row above is the authoritative
    // copy; this is a lightweight lookup index keyed by the original path.
    if let Err(e) = db::upsert_object(pool, &path, body.as_ref(), &dlv_id_b, new_size).await {
        warn!("put_object: path-index upsert for path={path} failed (non-fatal): {e}");
    }

    let mut out = HeaderMap::new();
    let _ = out.insert(
        HDR_OBJ_ADDR,
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    info!("object.put: addr={addr} path={path} bytes={new_size}");
    metrics::counter!("dsm_storage_objects_put_total").increment(1);
    metrics::counter!("dsm_storage_bytes_written_total").increment(new_size as u64);

    // Replicate to peer nodes in background (spec §6: redundant mirrors).
    {
        let rm = state.replication_manager.clone();
        let state_clone = state.clone();
        let obj_key = addr.clone();
        let obj_data = body.to_vec();
        tokio::spawn(async move {
            if let Err(e) = rm
                .replicate_object(state_clone, &obj_key, &obj_data, 0)
                .await
            {
                warn!("background replication failed for {obj_key}: {e}");
            }
        });
    }

    Ok((StatusCode::OK, out))
}

/// DELETE object by protobuf request.
/// Required headers: Content-Type: application/x-protobuf / application/octet-stream
pub async fn delete_object_proto(
    Extension(state): Extension<Arc<crate::AppState>>,
    ctx: Option<Extension<DeviceContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let caller_device = ctx
        .as_ref()
        .map(|c| c.0.device_id.as_str())
        .unwrap_or("<unauthenticated>");
    info!("delete_object_proto: device={}", caller_device,);
    match headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some("application/x-protobuf")
        | Some("application/octet-stream")
        | Some("application/protobuf") => {}
        _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    }

    let req = dsm::types::proto::StorageObjectDelete::decode(body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // validate simple params
    if req.dlv_id.len() != 32 || req.path.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pool = &*state.db_pool;
    // We treat 'path' as the key/address here.
    let n = db::delete_slot_object(pool, &req.dlv_id, &req.path)
        .await
        .map_err(|e| {
            log::error!("DB error during delete: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if n == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::OK)
}

/// GET raw bytes by deterministic address (path param is Crockford base32 key).
pub async fn get_object_handler(
    Extension(state): Extension<Arc<crate::AppState>>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match db::get_object_by_key(&state.db_pool, &addr)
        .await
        .map_err(|e| {
            warn!("get_object: DB error for addr={addr}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })? {
        Some(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            metrics::counter!("dsm_storage_objects_get_total").increment(1);
            metrics::counter!("dsm_storage_bytes_read_total").increment(bytes.len() as u64);
            Ok((StatusCode::OK, headers, bytes))
        }
        None => {
            metrics::counter!("dsm_storage_objects_get_not_found_total").increment(1);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
