//! DSM ByteCommit endpoints (deterministic, clockless, raw bytes)
//! - Publish ByteCommit or mirror under deterministic address.
//! - Capacity enforced per DLV slot.
//! - Raw bytes only ("application/octet-stream").
//! - No JSON, no wall-clock markers, no signatures verified here (nodes are dumb).

#[cfg(feature = "dev-replication")]
use crate::dev_replication;
#[cfg(feature = "dev-replication")]
use crate::timing::ExponentialBackoffTiming;
use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use log::{info, warn};
use std::sync::Arc;

use super::hardening::{blake3_tagged, mirror_set_w, window_index, B_GLOBAL};
use crate::db;
use crate::AppState;
use dsm_sdk::util::text_id;

use prost::Message;

/// Minimal ByteCommitV3 message used by storage nodes.
///
/// NOTE: This lives in the storage node crate because the node is signature-free and
/// acts as a dumb mirror. Devices/verifiers re-check hashes and chain links.
#[derive(Clone, PartialEq, Message)]
pub struct ByteCommitV3 {
    /// 32 bytes node id (content-addressed identifier)
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    /// cycle index t
    #[prost(uint64, tag = "2")]
    pub cycle_index: u64,
    /// 32 bytes SMT root for node storage
    #[prost(bytes = "vec", tag = "3")]
    pub smt_root: Vec<u8>,
    /// bytes used in this partition
    #[prost(uint64, tag = "4")]
    pub bytes_used: u64,
    /// 32 bytes parent digest (H(B_{t-1})) or all-zero for t=0
    #[prost(bytes = "vec", tag = "5")]
    pub parent_digest: Vec<u8>,
}

// ---------------------- header keys ----------------------
const HDR_DLV_ID: &str = "x-dlv-id"; // base32 32B DLV partition id
const HDR_CAPACITY: &str = "x-capacity-bytes"; // optional i64 for new slot
const HDR_STAKE_HASH: &str = "x-stake-hash"; // optional base32 bytes for new slot
const HDR_CYCLE_INDEX: &str = "x-cycle-index"; // u64 ASCII
const HDR_OBJ_ADDR: &str = "x-object-address"; // response header

// ---------------------- helpers --------------------------

/// dt := H("DSM/bytecommit\0" || ProtoDet(Bt))  (opaque to server)
#[inline]
fn bytecommit_digest_bytes(bytes: &[u8]) -> [u8; 32] {
    blake3_tagged("DSM/bytecommit", bytes)
}

/// addrB_t := H("DSM/obj-bytecommit\0" || node_id || t || dt)
#[inline]
fn bytecommit_addr(node_id: &[u8; 32], cycle_index: u64, dt: &[u8; 32]) -> String {
    let mut body = Vec::with_capacity(32 + 8 + dt.len());
    body.extend_from_slice(node_id);
    body.extend_from_slice(&cycle_index.to_be_bytes());
    body.extend_from_slice(dt);
    let digest = blake3_tagged("DSM/obj-bytecommit", &body);
    text_id::encode_base32_crockford(&digest)
}

pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/bytecommit/publish", post(publish_bytecommit))
        .route("/api/v2/bytecommit/by-addr/{addr}", get(get_by_addr))
        .layer(Extension(state))
}

/// Publish a ByteCommit or its mirror under deterministic address.
/// Required: x-dlv-id, x-node-id, x-cycle-index. Optional: x-peer-id for mirror.
/// Optional slot bootstrap: x-capacity-bytes + x-stake-hash.
pub async fn publish_bytecommit(
    Extension(state): Extension<Arc<crate::AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let dlv_id_b = headers
        .get(HDR_DLV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let cycle_index: u64 = headers
        .get(HDR_CYCLE_INDEX)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Slot bootstrap (optional)
    let capacity_opt = headers
        .get(HDR_CAPACITY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());
    let stake_hash_opt = headers
        .get(HDR_STAKE_HASH)
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford);

    // Ensure slot exists (create iff capacity+stake provided)
    let pool = &*state.db_pool;
    let mut exists = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
        warn!("bytecommit: slot_exists DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !exists {
        match (capacity_opt, stake_hash_opt.as_ref()) {
            (Some(cap), Some(stake)) => {
                db::create_slot(pool, &dlv_id_b, cap, stake)
                    .await
                    .map_err(|e| {
                        warn!("bytecommit: create_slot DB error: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                exists = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
                    warn!("bytecommit: slot_exists (post-create) DB error: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }
            _ => return Err(StatusCode::PRECONDITION_REQUIRED),
        }
    }
    if !exists {
        warn!("bytecommit: slot still does not exist after creation attempt");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Decode minimal ByteCommitV3 to bind addressing to the canonical node_id bytes.
    let commit = ByteCommitV3::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if commit.node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if commit.cycle_index != cycle_index {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut node_id_arr = [0u8; 32];
    node_id_arr.copy_from_slice(&commit.node_id);

    // Deterministic address (spec): addrB_t := H("DSM/obj-bytecommit\0" || node_id || t || dt)
    let dt = bytecommit_digest_bytes(&body);
    let addr = bytecommit_addr(&node_id_arr, cycle_index, &dt);

    // Mirror-set computation from live registry
    let win_seed = blake3_tagged("DSM/win-seed", &dt);
    let _t = window_index(B_GLOBAL);
    let active_positions: Vec<Vec<u8>> = db::get_active_registry_node_ids(pool)
        .await
        .unwrap_or_default();
    let expected_mirrors = mirror_set_w(
        node_id_arr.as_slice(),
        win_seed,
        &active_positions,
        node_id_arr.as_slice(),
    );
    info!(
        "bytecommit.publish: mirror-set computed ({} mirrors from {} active positions)",
        expected_mirrors.len(),
        active_positions.len()
    );

    // Store with atomic capacity check
    let new_size: i64 = body.len() as i64;
    db::upsert_object_with_capacity_check(pool, &addr, body.as_ref(), &dlv_id_b, new_size)
        .await
        .map_err(|e| {
            if e.to_string().contains("capacity_exceeded") {
                warn!("DLV capacity exceeded: {}", e);
                StatusCode::INSUFFICIENT_STORAGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    #[cfg(feature = "dev-replication")]
    {
        // Clockless durable replication:
        // - enqueue jobs into the local DB outbox (idempotent)
        // - optionally pump a bounded number of due jobs
        //
        // Scheduling is driven by an explicit `now_iter` supplied by the caller.
        // This avoids wall-clock dependencies.
        let now_iter = headers
            .get("x-dsm-now-iter")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        dev_replication::fanout_request_durable(
            state.clone(),
            reqwest::Method::POST,
            "/api/v2/bytecommit/publish",
            &headers
                .iter()
                .fold(reqwest::header::HeaderMap::new(), |mut acc, (k, v)| {
                    // best-effort conversion: keep raw bytes
                    if let Ok(name) = reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes())
                    {
                        if let Ok(hv) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                            acc.insert(name, hv);
                        }
                    }
                    acc
                }),
            body.to_vec(),
            now_iter,
        )
        .await;

        // Pump up to a small bounded number of jobs as part of the write path.
        // This keeps eventual delivery moving without any timers.
        let timing = ExponentialBackoffTiming::default();
        let _ = dev_replication::pump_replication_outbox(state.clone(), &timing, now_iter, 8).await;
    }

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        HDR_OBJ_ADDR,
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    info!("bytecommit.publish: addr={addr}");
    Ok((StatusCode::OK, out_headers))
}

/// Production ByteCommit emitter for clockless storage regulation.
///
/// Builds and stores a verifiable ByteCommitV3 object as ordinary content under the
/// deterministic address:
///   addrB_t := H("DSM/obj-bytecommit\0" || node_id || t || H(Bt))
///
/// The node does not sign. Verifiers check:
/// - deterministic protobuf encoding,
/// - parent digest link,
/// - SMT root correctness,
/// - mirror quorum externally.
pub async fn emit_cycle_commitment(
    state: &AppState,
    cycle_index: u64,
) -> Result<[u8; 32], anyhow::Error> {
    let pool = &*state.db_pool;

    // Convert configured node_id string to a canonical 32-byte identifier.
    // For production, this should be a content-addressed 32B digest (per spec §7).
    let node_id_32 = blake3_tagged("DSM/node-id", state.node_id.as_bytes());

    // 1) Compute node storage stats (SMT root + bytes_used) over current served objects.
    let (smt_root, bytes_used) = db::get_current_cycle_stats(pool).await?;

    // 2) Parent digest for chain continuity.
    // Spec chain link uses dt = H("DSM/bytecommit\0" || Bt).
    let parent_digest = db::get_last_bytecommit_hash(pool, state.node_id.as_str())
        .await?
        .unwrap_or([0u8; 32]);

    // 3) Construct message.
    let commit = ByteCommitV3 {
        node_id: node_id_32.to_vec(),
        cycle_index,
        smt_root: smt_root.to_vec(),
        bytes_used,
        parent_digest: parent_digest.to_vec(),
    };

    // 4) Deterministic protobuf bytes + dt.
    let mut commit_bytes = Vec::with_capacity(commit.encoded_len());
    commit.encode(&mut commit_bytes)?;
    let dt = bytecommit_digest_bytes(&commit_bytes);

    // 5) Deterministic address and store as dumb content.
    // Use a fixed internal DLV partition id for bytecommit namespace.
    // NOTE: This is a binary DLV id; verifiers treat ByteCommits as ordinary mirrored bytes.
    // Storage nodes must still enforce capacity via the shared DLV slot mechanism.
    let dlv_id: &[u8] = b"bytecommit";
    if !db::slot_exists(pool, dlv_id).await? {
        return Err(anyhow::anyhow!(
            "bytecommit slot missing: create a DLV slot for id={:?} before emitting",
            dlv_id
        ));
    }
    let addr = bytecommit_addr(&node_id_32, cycle_index, &dt);
    db::upsert_object_with_capacity_check(
        pool,
        &addr,
        &commit_bytes,
        dlv_id,
        commit_bytes.len() as i64,
    )
    .await?;
    // Record chain pointer after the object is durably stored.
    db::record_bytecommit_hash(pool, state.node_id.as_str(), cycle_index, &dt).await?;

    Ok(dt)
}

/// Deterministic address computation exposed for testing.
#[cfg(test)]
pub(crate) fn _test_bytecommit_addr(node_id: &[u8; 32], cycle_index: u64, dt: &[u8; 32]) -> String {
    bytecommit_addr(node_id, cycle_index, dt)
}

/// Fetch raw bytes by deterministic address (hex string)
pub async fn get_by_addr(
    Extension(state): Extension<Arc<crate::AppState>>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = db::get_object_by_key(&state.db_pool, &addr)
        .await
        .map_err(|e| {
            warn!("bytecommit: get_by_addr DB error for addr {addr}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn bytecommit_digest_is_deterministic() {
        let data = b"hello bytecommit";
        let d1 = bytecommit_digest_bytes(data);
        let d2 = bytecommit_digest_bytes(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn bytecommit_digest_differs_for_different_input() {
        let d1 = bytecommit_digest_bytes(b"aaa");
        let d2 = bytecommit_digest_bytes(b"bbb");
        assert_ne!(d1, d2);
    }

    #[test]
    fn bytecommit_addr_is_deterministic() {
        let node_id = [1u8; 32];
        let dt = [2u8; 32];
        let a1 = bytecommit_addr(&node_id, 5, &dt);
        let a2 = bytecommit_addr(&node_id, 5, &dt);
        assert_eq!(a1, a2);
        assert!(!a1.is_empty());
    }

    #[test]
    fn bytecommit_addr_varies_with_cycle() {
        let node_id = [1u8; 32];
        let dt = [2u8; 32];
        let a1 = bytecommit_addr(&node_id, 0, &dt);
        let a2 = bytecommit_addr(&node_id, 1, &dt);
        assert_ne!(a1, a2);
    }

    #[test]
    fn bytecommit_addr_varies_with_node_id() {
        let dt = [2u8; 32];
        let a1 = bytecommit_addr(&[0u8; 32], 0, &dt);
        let a2 = bytecommit_addr(&[1u8; 32], 0, &dt);
        assert_ne!(a1, a2);
    }

    #[test]
    fn bytecommit_v3_roundtrip() {
        let commit = ByteCommitV3 {
            node_id: vec![0xAA; 32],
            cycle_index: 42,
            smt_root: vec![0xBB; 32],
            bytes_used: 1024,
            parent_digest: vec![0; 32],
        };
        let mut buf = Vec::new();
        assert!(commit.encode(&mut buf).is_ok());
        let decoded = match ByteCommitV3::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("bytecommit should decode: {err}"),
        };
        assert_eq!(decoded, commit);
    }

    #[test]
    fn bytecommit_v3_empty_node_id_detected() {
        let commit = ByteCommitV3 {
            node_id: vec![],
            cycle_index: 0,
            smt_root: vec![],
            bytes_used: 0,
            parent_digest: vec![],
        };
        assert_ne!(commit.node_id.len(), 32);
    }

    #[test]
    fn bytecommit_digest_bytes_not_raw_blake3() {
        let data = b"test";
        let tagged = bytecommit_digest_bytes(data);
        let raw = blake3::hash(data);
        assert_ne!(tagged, *raw.as_bytes());
    }
}
