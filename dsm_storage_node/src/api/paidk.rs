//! PaidK Spend-Gate endpoints (clockless, signature-free at node level).
//!
//! Spec §16: PaidK(G, DevID, R) := |{r in R | VerifyPayment(r) AND amt(r) >= FLAT_RATE}| >= K
//! - K=3 distinct operators, FLAT_RATE deployment-defined.
//! - Once satisfied, permanently enabled (no renewals).
//! - Node stores receipts and counts distinct operators. Verification is client-side.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use log::info;
use prost::Message;
use std::sync::Arc;

use super::hardening::blake3_tagged;
use crate::db;
use crate::AppState;
use dsm_sdk::util::text_id;

/// Default PaidK parameters (overridable via config).
const DEFAULT_K: u32 = 3;
const DEFAULT_FLAT_RATE: i64 = 1000;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/paidk/receipt", post(submit_receipt))
        .route("/api/v2/paidk/status/{device_id}", get(get_status))
        .layer(Extension(state))
}

/// Accept a StoragePaymentReceiptV3 protobuf.
/// Computes deterministic address H("DSM/pay/storage\0" || body).
/// Stores the receipt. If distinct paid operators >= K, marks paidk_satisfied.
pub async fn submit_receipt(
    Extension(state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode to validate structure
    let receipt = dsm::types::proto::StoragePaymentReceiptV3::decode(body.as_ref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if receipt.device_id.len() != 32 || receipt.operator_node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if receipt.amount == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Deterministic content address
    let addr_digest = blake3_tagged("DSM/pay/storage", &body);
    let addr = text_id::encode_base32_crockford(&addr_digest);

    let device_id_b32 = text_id::encode_base32_crockford(&receipt.device_id);
    let pool = &*state.db_pool;

    // Store receipt (idempotent)
    db::store_payment_receipt(
        pool,
        &device_id_b32,
        &receipt.operator_node_id,
        receipt.amount as i64,
        &addr,
        &body,
    )
    .await
    .map_err(|e| {
        log::warn!("paidk: store_payment_receipt DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Check if PaidK is now satisfied
    let distinct = db::count_distinct_paid_operators(pool, &device_id_b32, DEFAULT_FLAT_RATE)
        .await
        .map_err(|e| {
            log::warn!("paidk: count_distinct_paid_operators DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if distinct >= DEFAULT_K as i64 {
        let _ = db::mark_paidk_satisfied(pool, &device_id_b32).await;
        info!(
            "paidk: device {} satisfied (distinct_operators={})",
            device_id_b32, distinct
        );
    }

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        "x-object-address",
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    Ok((StatusCode::OK, out_headers))
}

/// Get PaidK status for a device. Returns PaidKStatusV3 protobuf.
pub async fn get_status(
    Extension(state): Extension<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let pool = &*state.db_pool;

    let satisfied = db::is_paidk_satisfied(pool, &device_id)
        .await
        .map_err(|e| {
            log::warn!("paidk: is_paidk_satisfied DB error for {device_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let distinct = db::count_distinct_paid_operators(pool, &device_id, DEFAULT_FLAT_RATE)
        .await
        .map_err(|e| {
            log::warn!("paidk: count_distinct_paid_operators DB error for {device_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let status = dsm::types::proto::PaidKStatusV3 {
        satisfied,
        distinct_operators: distinct as u32,
        required_k: DEFAULT_K,
    };

    let mut buf = Vec::with_capacity(status.encoded_len());
    status
        .encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, buf))
}
