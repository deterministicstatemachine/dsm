// SPDX-License-Identifier: Apache-2.0
//! Append-only Per-Device SMT head chain (spec §0.5 gap 13, R4 layer 1).
//!
//! `PUT /api/v2/tips/{device}/head-chain` appends a `PostedPdsmtHead` to the device's
//! monotonic, append-only head chain. A new head is accepted only if it links the
//! current tip: the first head must be the genesis head (`head_number == 0`,
//! `parent_head_hash` all-zero); a later head must have `head_number == tip + 1` and
//! `parent_head_hash == tip head_hash`. No overwrite, no fork → 409 Conflict. An
//! identical replay at an existing position is idempotent. Full history is retained so
//! recovery can read the head at/before the tombstone snapshot via
//! `GET /api/v2/tips/{device}/head-chain` (latest) or `.../head-chain/{head_number}`.
//!
//! Storage enforces the CHAIN SHAPE only. It decodes the head (via `dsm`) to derive
//! `head_hash` (so a client cannot lie about chain links) and binds it to the `{device}`
//! path, but does NOT verify the head signature (it lacks `K_A_pub`) and does not attest
//! recovery validity — clients verify head signatures + inclusion. NOTE: the endpoint is
//! public/rate-limited (like devtree/anchor); a griefer can at worst DoS chain liveness,
//! not forge a head a client accepts nor shrink the gate-set (the counterparty-union
//! backstop covers any relationship griefed out of A_old's chain).

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, put},
    Router,
};
use std::sync::Arc;

use crate::AppState;

/// SPX256f signature (~49.9 KiB) + six 32-byte fields + a u64 fit well under 256 KiB.
const MAX_HEAD_BYTES: usize = 256 * 1024;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/tips/{device}/head-chain",
            put(put_head).get(get_head_latest),
        )
        .route(
            "/api/v2/tips/{device}/head-chain/{head_number}",
            get(get_head_at),
        )
        .layer(Extension(state))
}

fn decode_device(device: &str) -> Result<(Vec<u8>, String), StatusCode> {
    let device_b =
        dsm_sdk::util::text_id::decode_base32_crockford(device).ok_or(StatusCode::BAD_REQUEST)?;
    if device_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let device_key = dsm_sdk::util::text_id::encode_base32_crockford(&device_b);
    Ok((device_b, device_key))
}

async fn put_head(
    Extension(state): Extension<Arc<AppState>>,
    Path(device): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_HEAD_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let (device_b, device_key) = decode_device(&device)?;

    // Decode + structural validation (fail-closed 32-byte fields) via the canonical
    // codec, and derive head_hash so the client cannot misreport chain links.
    let head = dsm::recovery::PostedPdsmtHead::from_bytes(body.as_ref()).map_err(|e| {
        log::warn!("PUT /tips/{device}/head-chain: malformed head: {e}");
        StatusCode::BAD_REQUEST
    })?;
    if head.device_id[..] != device_b[..] {
        log::warn!("PUT /tips/{device}/head-chain: head device_id != path device");
        return Err(StatusCode::BAD_REQUEST);
    }
    if head.signature.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let head_hash = head.head_hash();
    let now_tick = state.current_tick.load(std::sync::atomic::Ordering::SeqCst);
    let outcome = crate::db::insert_pdsmt_head_if_chained(
        &state.db_pool,
        &device_key,
        head.head_number,
        &head_hash,
        &head.parent_head_hash,
        body.as_ref(),
        now_tick.max(0) as u64,
    )
    .await
    .map_err(|e| {
        log::error!("PUT /tips/{device}/head-chain: DB write failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match outcome {
        crate::db::PdsmtHeadChainOutcome::Appended { head_number } => {
            log::info!("PUT /tips/{device}/head-chain: appended head_number={head_number}");
            Ok(StatusCode::CREATED)
        }
        crate::db::PdsmtHeadChainOutcome::AlreadyExistsIdentical => Ok(StatusCode::OK),
        crate::db::PdsmtHeadChainOutcome::Conflict => {
            log::warn!(
                "PUT /tips/{device}/head-chain: rejected — head does not link the current tip (fork/gap/stale)"
            );
            Err(StatusCode::CONFLICT)
        }
    }
}

fn octet_stream(payload: Vec<u8>) -> impl IntoResponse {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    (StatusCode::OK, headers, payload)
}

async fn get_head_latest(
    Extension(state): Extension<Arc<AppState>>,
    Path(device): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let (_device_b, device_key) = decode_device(&device)?;
    let payload = crate::db::get_pdsmt_head_latest(&state.db_pool, &device_key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(octet_stream(payload))
}

async fn get_head_at(
    Extension(state): Extension<Arc<AppState>>,
    Path((device, head_number)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let (_device_b, device_key) = decode_device(&device)?;
    let head_number: u64 = head_number.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let payload = crate::db::get_pdsmt_head_at(&state.db_pool, &device_key, head_number)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(octet_stream(payload))
}
