//! Registry Scaling & Applicant Ranking (clockless, deterministic).
//!
//! Spec §8-10: Up/Down capacity signals → position delta ΔP → add/prune nodes.
//! - UpSignalV3: utilization >= U_UP for w consecutive cycles
//! - DownSignalV3: utilization <= U_DOWN for w consecutive cycles
//! - ΔP = |valid_up| - |valid_down|
//! - If ΔP > 0: rank applicants deterministically, add top |ΔP|
//! - If ΔP < 0: prune |ΔP| lowest-utilization nodes (tiebreak by node_id)
//! - Grace: new nodes protected for Gnew cycles (ignore Down signals)
//!
//! Storage nodes are dumb: they store signals and applicants as evidence.
//! Registry updates are pure functions of public inputs.

use axum::{
    body::Bytes,
    extract::Extension,
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

/// Grace period in cycles for new nodes (Down signals ignored).
const GRACE_CYCLES: i64 = 8;
/// Discovery window size for signal collection.
const DISCOVERY_WINDOW: i64 = 4;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/signals/up", post(submit_up_signal))
        .route("/api/v2/signals/down", post(submit_down_signal))
        .route("/api/v2/applicants/submit", post(submit_applicant))
        .route("/api/v2/registry/current", get(get_current_registry))
        .layer(Extension(state))
}

/// Admin router for registry update trigger.
pub fn admin_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/registry/update", post(trigger_registry_update))
        .route("/registry/seed", post(seed_registry_node))
        .layer(Extension(state))
}

/// Submit an UpSignalV3. Domain: "DSM/signal/up\0".
pub async fn submit_up_signal(
    Extension(state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let signal = pb::UpSignalV3::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if signal.node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let addr_digest = blake3_tagged("DSM/signal/up", &body);
    let addr = text_id::encode_base32_crockford(&addr_digest);

    // Derive window bounds from anchors length
    let window_end = signal.anchors.len() as i64;
    let window_start = (window_end - signal.anchors.len() as i64).max(0);

    let pool = &*state.db_pool;
    db::store_capacity_signal(
        pool,
        &db::CapacitySignalParams {
            signal_addr: &addr,
            node_id: &signal.node_id,
            signal_type: 1, // Up
            capacity: signal.capacity as i64,
            cycle_window_start: window_start,
            cycle_window_end: window_end,
            signal_bytes: &body,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Also store raw bytes as evidence object
    db::upsert_object(pool, &addr, &body, b"signals", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        "x-object-address",
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    info!(
        "signals.up: addr={addr} node={}",
        text_id::encode_base32_crockford(&signal.node_id)
    );
    Ok((StatusCode::OK, out_headers))
}

/// Submit a DownSignalV3. Domain: "DSM/signal/down\0".
pub async fn submit_down_signal(
    Extension(state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let signal = pb::DownSignalV3::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if signal.node_id.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let addr_digest = blake3_tagged("DSM/signal/down", &body);
    let addr = text_id::encode_base32_crockford(&addr_digest);

    let window_end = signal.anchors.len() as i64;
    let window_start = (window_end - signal.anchors.len() as i64).max(0);

    let pool = &*state.db_pool;
    db::store_capacity_signal(
        pool,
        &db::CapacitySignalParams {
            signal_addr: &addr,
            node_id: &signal.node_id,
            signal_type: 2, // Down
            capacity: signal.capacity as i64,
            cycle_window_start: window_start,
            cycle_window_end: window_end,
            signal_bytes: &body,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    db::upsert_object(pool, &addr, &body, b"signals", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        "x-object-address",
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    info!(
        "signals.down: addr={addr} node={}",
        text_id::encode_base32_crockford(&signal.node_id)
    );
    Ok((StatusCode::OK, out_headers))
}

/// Submit an ApplicantV3. Domain: "DSM/apply\0".
pub async fn submit_applicant(
    Extension(state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let applicant = pb::ApplicantV3::decode(body.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if applicant.seed_app.is_empty() || applicant.stake_dlv.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let addr_digest = blake3_tagged("DSM/apply", &body);
    let addr = text_id::encode_base32_crockford(&addr_digest);

    let pool = &*state.db_pool;
    db::store_applicant(
        pool,
        &addr,
        &applicant.seed_app,
        &applicant.stake_dlv,
        applicant.capacity as i64,
        &body,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    db::upsert_object(pool, &addr, &body, b"applicants", body.len() as i64)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out_headers = HeaderMap::new();
    let _ = out_headers.insert(
        "x-object-address",
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    info!("applicants.submit: addr={addr}");
    Ok((StatusCode::OK, out_headers))
}

/// Get current RegistryV3 (sorted active node_ids).
pub async fn get_current_registry(
    Extension(state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let pool = &*state.db_pool;
    let node_ids = db::get_active_registry_node_ids(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let registry = pb::RegistryV3 { node_ids };
    let mut buf = Vec::with_capacity(registry.encoded_len());
    registry
        .encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, buf))
}

/// Seed a node into the registry (admin endpoint for initial registry setup).
/// Body: raw 32-byte node_id. Header: x-first-cycle (u64).
pub async fn seed_registry_node(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let first_cycle: i64 = headers
        .get("x-first-cycle")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let pool = &*state.db_pool;
    db::upsert_registry_node(pool, &body, first_cycle)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        "registry.seed: node={}",
        text_id::encode_base32_crockford(&body)
    );
    Ok(StatusCode::OK)
}

/// Trigger a deterministic registry update (admin endpoint).
/// Header: x-current-cycle (u64), x-genesis-hash (base32 32B).
///
/// Pure function: computes ΔP from signals, ranks applicants, updates registry.
pub async fn trigger_registry_update(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let current_cycle: i64 = headers
        .get("x-current-cycle")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let genesis_hash = headers
        .get("x-genesis-hash")
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford)
        .unwrap_or_else(|| vec![0u8; 32]);

    let pool = &*state.db_pool;

    // Compute discovery window bounds
    let window_end = current_cycle;
    let window_start = (current_cycle - DISCOVERY_WINDOW).max(0);

    // Count valid signals
    let up_count = db::count_up_signals(pool, window_start, window_end)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let down_count = db::count_down_signals_excluding_grace(
        pool,
        window_start,
        window_end,
        current_cycle,
        GRACE_CYCLES,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let delta_p = up_count - down_count;
    info!("registry.update: cycle={current_cycle} up={up_count} down={down_count} ΔP={delta_p}");

    if delta_p > 0 {
        // Add top |ΔP| applicants ranked deterministically
        let active_nodes = db::get_active_registry_node_ids(pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Current registry address for salt computation
        let registry = pb::RegistryV3 {
            node_ids: active_nodes.clone(),
        };
        let mut reg_bytes = Vec::with_capacity(registry.encoded_len());
        let _ = registry.encode(&mut reg_bytes);
        let addr_reg = blake3_tagged("DSM/registry", &reg_bytes);

        // Deterministic salt: H("DSM/positions/salt\0" || G || addr_reg || ...)
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(&genesis_hash);
        salt_input.extend_from_slice(&addr_reg);
        let salt = blake3_tagged("DSM/positions/salt", &salt_input);

        // Rank applicants
        let applicants = db::list_pending_applicants(pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut ranked: Vec<([u8; 32], String, Vec<u8>)> = applicants
            .iter()
            .map(|(addr, seed_app, _stake, _cap)| {
                let mut rank_input = Vec::new();
                rank_input.extend_from_slice(&salt);
                rank_input.extend_from_slice(seed_app);
                let rank = blake3_tagged("DSM/order", &rank_input);
                (rank, addr.clone(), seed_app.clone())
            })
            .collect();
        ranked.sort_by_key(|a| a.0);

        // Add top |ΔP| winners
        let to_add = delta_p.min(ranked.len() as i64) as usize;
        for (_, applicant_addr, seed_app) in ranked.iter().take(to_add) {
            // Use seed_app hash as node_id for the new registry entry
            let node_id = blake3_tagged("DSM/node-id", seed_app);
            db::upsert_registry_node(pool, &node_id, current_cycle)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let _ = db::remove_applicant(pool, applicant_addr).await;
            info!(
                "registry.update: added node {}",
                text_id::encode_base32_crockford(&node_id)
            );
        }
    } else if delta_p < 0 {
        // Prune |ΔP| lowest-utilization nodes (tiebreak by node_id)
        let mut nodes = db::get_active_registry_nodes(pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Sort by utilization ascending, then node_id ascending for tiebreak
        nodes.sort_by(|a, b| {
            a.2.partial_cmp(&b.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        let to_prune = (-delta_p).min(nodes.len() as i64) as usize;
        for (node_id, _, _) in nodes.iter().take(to_prune) {
            db::deactivate_registry_node(pool, node_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            info!(
                "registry.update: pruned node {}",
                text_id::encode_base32_crockford(node_id)
            );
        }
    }

    // Store updated registry as evidence
    let updated_nodes = db::get_active_registry_node_ids(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_registry = pb::RegistryV3 {
        node_ids: updated_nodes,
    };
    let mut reg_bytes = Vec::with_capacity(new_registry.encoded_len());
    new_registry
        .encode(&mut reg_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let reg_addr = blake3_tagged("DSM/registry", &reg_bytes);
    let reg_addr_str = text_id::encode_base32_crockford(&reg_addr);
    db::upsert_object(
        pool,
        &reg_addr_str,
        &reg_bytes,
        b"registry",
        reg_bytes.len() as i64,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return update result
    let result = pb::RegistryUpdateV3 {
        previous_registry_addr: vec![],
        new_registry_addr: reg_addr.to_vec(),
        position_delta: delta_p,
        added_nodes: vec![],
        removed_nodes: vec![],
    };
    let mut buf = Vec::with_capacity(result.encoded_len());
    result
        .encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, out_headers, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm_sdk::util::text_id;

    #[test]
    fn constants_match_spec() {
        assert_eq!(GRACE_CYCLES, 8, "new-node grace period must be 8 cycles");
        assert_eq!(DISCOVERY_WINDOW, 4, "signal discovery window must be 4 cycles");
    }

    #[test]
    fn up_signal_address_is_deterministic() {
        let body = b"test-signal-body";
        let a1 = blake3_tagged("DSM/signal/up", body);
        let a2 = blake3_tagged("DSM/signal/up", body);
        assert_eq!(a1, a2, "same input must produce same address");

        let different = blake3_tagged("DSM/signal/up", b"different-body");
        assert_ne!(a1, different, "different bodies must produce different addresses");
    }

    #[test]
    fn up_and_down_signal_domains_differ() {
        let body = b"same-body";
        let up = blake3_tagged("DSM/signal/up", body);
        let down = blake3_tagged("DSM/signal/down", body);
        assert_ne!(up, down, "domain separation must produce distinct digests");
    }

    #[test]
    fn applicant_ranking_is_deterministic_and_sortable() {
        let salt = blake3_tagged("DSM/positions/salt", b"genesis+registry");

        let seeds: Vec<Vec<u8>> = (0u8..5)
            .map(|i| {
                let mut s = vec![0u8; 32];
                s[0] = i;
                s
            })
            .collect();

        let mut ranked: Vec<([u8; 32], usize)> = seeds
            .iter()
            .enumerate()
            .map(|(idx, seed)| {
                let mut input = Vec::new();
                input.extend_from_slice(&salt);
                input.extend_from_slice(seed);
                let rank = blake3_tagged("DSM/order", &input);
                (rank, idx)
            })
            .collect();
        ranked.sort_by_key(|a| a.0);

        // Re-run: same salt → same ordering
        let mut ranked2: Vec<([u8; 32], usize)> = seeds
            .iter()
            .enumerate()
            .map(|(idx, seed)| {
                let mut input = Vec::new();
                input.extend_from_slice(&salt);
                input.extend_from_slice(seed);
                let rank = blake3_tagged("DSM/order", &input);
                (rank, idx)
            })
            .collect();
        ranked2.sort_by_key(|a| a.0);

        let order1: Vec<usize> = ranked.iter().map(|r| r.1).collect();
        let order2: Vec<usize> = ranked2.iter().map(|r| r.1).collect();
        assert_eq!(order1, order2, "ranking must be deterministic across runs");
    }

    #[test]
    fn pruning_sort_by_utilization_then_node_id() {
        // (node_id, first_cycle, utilization)
        let mut nodes: Vec<(Vec<u8>, i64, f64)> = vec![
            (vec![0x03; 32], 1, 0.5),
            (vec![0x01; 32], 2, 0.2),
            (vec![0x02; 32], 3, 0.2), // same utilization as 0x01, higher node_id
            (vec![0x04; 32], 0, 0.9),
        ];

        nodes.sort_by(|a, b| {
            a.2.partial_cmp(&b.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        // Lowest utilization first; tiebreak by node_id ascending
        assert_eq!(nodes[0].0, vec![0x01; 32]);
        assert_eq!(nodes[1].0, vec![0x02; 32]);
        assert_eq!(nodes[2].0, vec![0x03; 32]);
        assert_eq!(nodes[3].0, vec![0x04; 32]);
    }

    #[test]
    fn window_bounds_clamped_to_zero() {
        let anchors_len = 3i64;
        let window_end = anchors_len;
        let window_start = (window_end - anchors_len).max(0);
        assert_eq!(window_start, 0);
        assert_eq!(window_end, 3);

        let current_cycle: i64 = 2;
        let start = (current_cycle - DISCOVERY_WINDOW).max(0);
        assert_eq!(start, 0, "window_start must not go negative");

        let current_cycle: i64 = 10;
        let start = (current_cycle - DISCOVERY_WINDOW).max(0);
        assert_eq!(start, 6);
    }

    #[test]
    fn delta_p_add_count_clamped_to_applicant_pool() {
        let delta_p: i64 = 10;
        let applicant_count = 3usize;
        let to_add = delta_p.min(applicant_count as i64) as usize;
        assert_eq!(to_add, 3, "cannot add more nodes than available applicants");
    }

    #[test]
    fn registry_address_uses_correct_domain() {
        let body = b"registry-bytes";
        let addr = blake3_tagged("DSM/registry", body);
        let addr_str = text_id::encode_base32_crockford(&addr);
        assert!(!addr_str.is_empty());

        let other = blake3_tagged("DSM/apply", body);
        assert_ne!(addr, other, "different domain tags must produce different digests");
    }
}
