//! DrainProof & Stake Unlock endpoints (clockless, advisory).
//!
//! Spec §15: StakeDLV unlocks iff d=2 consecutive ByteCommits have bytes_used=0.
//! Node stores DrainProof as evidence and performs advisory local verification.
//! Actual stake unlock is client-side via mirrored ByteCommit verification.

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
use dsm::types::proto as pb;
use dsm_sdk::util::text_id;

/// Required consecutive empty cycles for DrainProof (spec default).
const DRAIN_PROOF_D: i64 = 2;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/drain/proof", post(submit_drain_proof))
        .route("/api/v2/drain/proof/{node_id_b32}", get(get_drain_proof))
        .route("/api/v2/drain/verify/{node_id_b32}", get(verify_drain))
        .layer(Extension(state))
}

/// Submit a DrainProofV3. Domain: "DSM/drain\0".
/// Stores the proof and optionally does an advisory local check.
pub async fn submit_drain_proof(
    Extension(state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let proof = pb::DrainProofV3::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if proof.node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if proof.cycle_indices.len() < DRAIN_PROOF_D as usize {
        return Err(StatusCode::BAD_REQUEST);
    }

    let addr_digest = blake3_tagged("DSM/drain", &body);
    let addr = text_id::encode_base32_crockford(&addr_digest);

    let start_cycle = *proof.cycle_indices.first().unwrap_or(&0) as i64;
    let end_cycle = *proof.cycle_indices.last().unwrap_or(&0) as i64;

    // Advisory local check: does bytecommit_chain have these cycles?
    let node_id_text = text_id::encode_base32_crockford(&proof.node_id);
    let pool = &*state.db_pool;
    let verified_local =
        db::verify_bytecommit_chain_empty(pool, &node_id_text, start_cycle, DRAIN_PROOF_D)
            .await
            .unwrap_or(false);

    // Store (idempotent)
    db::store_drain_proof(
        pool,
        &addr,
        &proof.node_id,
        start_cycle,
        end_cycle,
        verified_local,
        &body,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Also store as evidence object
    db::upsert_object(pool, &addr, &body, b"drain", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        "drain.proof: addr={addr} node={node_id_text} cycles={start_cycle}-{end_cycle} verified_local={verified_local}"
    );

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        "x-object-address",
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    let _ = out_headers.insert(
        "x-verified-local",
        HeaderValue::from_str(&verified_local.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("false")),
    );
    Ok((StatusCode::OK, out_headers))
}

/// Get stored DrainProof for a node (raw protobuf bytes).
pub async fn get_drain_proof(
    Extension(state): Extension<Arc<AppState>>,
    Path(node_id_b32): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let node_id = text_id::decode_base32_crockford(&node_id_b32).ok_or(StatusCode::BAD_REQUEST)?;
    if node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pool = &*state.db_pool;
    let proof_bytes = db::get_drain_proof_for_node(pool, &node_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, proof_bytes))
}

/// Advisory verification: check if a node has d consecutive empty ByteCommit cycles.
/// Returns DrainVerifyV3 protobuf.
pub async fn verify_drain(
    Extension(state): Extension<Arc<AppState>>,
    Path(node_id_b32): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let node_id = text_id::decode_base32_crockford(&node_id_b32).ok_or(StatusCode::BAD_REQUEST)?;
    if node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pool = &*state.db_pool;

    // Find the latest bytecommit cycle for this node
    let last_hash = db::get_last_bytecommit_hash(pool, &node_id_b32)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let verified = if last_hash.is_some() {
        // Check from cycle 0 as a basic advisory (full verification is client-side)
        db::verify_bytecommit_chain_empty(pool, &node_id_b32, 0, DRAIN_PROOF_D)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    let result = pb::DrainVerifyV3 {
        verified,
        node_id: node_id.clone(),
        start_cycle: 0,
        end_cycle: DRAIN_PROOF_D as u64,
        consecutive_empty: if verified { DRAIN_PROOF_D as u32 } else { 0 },
    };

    let mut buf = Vec::with_capacity(result.encoded_len());
    result
        .encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn drain_proof_d_constant() {
        assert_eq!(DRAIN_PROOF_D, 2);
    }

    #[test]
    fn drain_proof_v3_roundtrip() {
        let proof = pb::DrainProofV3 {
            node_id: vec![0xAA; 32],
            cycle_indices: vec![10, 11],
            bytecommit_digests: vec![vec![0u8; 32], vec![1u8; 32]],
        };
        let mut buf = Vec::new();
        assert!(proof.encode(&mut buf).is_ok());
        let decoded = match pb::DrainProofV3::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("drain proof should decode: {err}"),
        };
        assert_eq!(decoded.node_id, vec![0xAA; 32]);
        assert_eq!(decoded.cycle_indices, vec![10, 11]);
        assert_eq!(decoded.bytecommit_digests.len(), 2);
    }

    #[test]
    fn drain_proof_insufficient_cycles_rejected() {
        let proof = pb::DrainProofV3 {
            node_id: vec![0xBB; 32],
            cycle_indices: vec![5],
            bytecommit_digests: vec![vec![0u8; 32]],
        };
        assert!(
            proof.cycle_indices.len() < DRAIN_PROOF_D as usize,
            "only 1 cycle should be fewer than d=2"
        );
    }

    #[test]
    fn drain_proof_addr_is_deterministic() {
        let body = b"some drain proof bytes";
        let d1 = blake3_tagged("DSM/drain", body);
        let d2 = blake3_tagged("DSM/drain", body);
        assert_eq!(d1, d2);
        let addr1 = text_id::encode_base32_crockford(&d1);
        let addr2 = text_id::encode_base32_crockford(&d2);
        assert_eq!(addr1, addr2);
        assert!(!addr1.is_empty());
    }

    #[test]
    fn drain_verify_v3_roundtrip() {
        let result = pb::DrainVerifyV3 {
            verified: true,
            node_id: vec![0xCC; 32],
            start_cycle: 0,
            end_cycle: 2,
            consecutive_empty: 2,
        };
        let mut buf = Vec::new();
        assert!(result.encode(&mut buf).is_ok());
        let decoded = match pb::DrainVerifyV3::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("drain verify result should decode: {err}"),
        };
        assert!(decoded.verified);
        assert_eq!(decoded.consecutive_empty, 2);
        assert_eq!(decoded.node_id, vec![0xCC; 32]);
    }
}
