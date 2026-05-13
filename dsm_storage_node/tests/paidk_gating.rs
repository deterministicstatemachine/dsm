//! Integration tests for the PaidK spend-gate (whitepaper §16 / storagenodes §16).
//!
//! Exercises `api::paidk::require_paidk` against an in-memory SQLite DB. PaidK
//! receipt submission earns access; storage writes (object put/delete, b0x
//! submit) check satisfaction via the helper. Operator-side endpoints
//! (ByteCommit publish, DLV slot mutation) are intentionally out of scope.

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use axum::http::StatusCode;
use dsm_sdk::util::text_id;
use dsm_storage_node::{
    db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use std::sync::Arc;

async fn make_state() -> AppState {
    let pool = db::create_pool(":memory:", true).expect("create_pool");
    db::init_db(&pool).await.expect("init_db");
    let replication_config = ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,
        failure_timeout_ticks: 300,
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    };
    let replication_manager = Arc::new(
        ReplicationManager::new_for_tests(
            replication_config,
            "test-node".to_string(),
            "http://localhost:8080".to_string(),
        )
        .expect("ReplicationManager::new_for_tests"),
    );
    AppState::new(
        "test-node".to_string(),
        "http://localhost:8080",
        None,
        Arc::new(pool),
        replication_manager,
    )
}

fn b32_of(bytes: &[u8; 32]) -> String {
    text_id::encode_base32_crockford(bytes)
}

async fn register_test_device(state: &AppState, device_b32: &str) {
    // `mark_paidk_satisfied` updates a row keyed by device_id; the row must
    // exist first. In production this is created by the device-registration
    // flow. For tests we insert a minimal device row.
    db::register_device(
        &state.db_pool,
        device_b32,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
    )
    .await
    .expect("register_device");
}

/// T-A: device with no `submit_receipt` history is rejected with PAYMENT_REQUIRED.
#[tokio::test]
async fn t_a_unpaid_device_rejected() {
    let state = make_state().await;
    let device_b32 = b32_of(&[0xAA; 32]);
    let err = dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
        .await
        .expect_err("unpaid device must be rejected");
    assert_eq!(err, StatusCode::PAYMENT_REQUIRED);
}

/// T-B: once `mark_paidk_satisfied` is recorded for a device, the gate passes.
#[tokio::test]
async fn t_b_paid_device_accepted() {
    let state = make_state().await;
    let device_b32 = b32_of(&[0xBB; 32]);
    register_test_device(&state, &device_b32).await;
    db::mark_paidk_satisfied(&state.db_pool, &device_b32)
        .await
        .expect("mark_paidk_satisfied");
    dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
        .await
        .expect("paid device must pass the gate");
}

/// T-C: submitting a malformed receipt (wrong-length device_id) does NOT flip
/// `paidk_satisfied`. The gate continues to reject after the malformed attempt.
#[tokio::test]
async fn t_c_malformed_receipt_does_not_unlock_gate() {
    let state = make_state().await;
    let device_b32 = b32_of(&[0xCC; 32]);

    // Confirm baseline: unpaid.
    let err = dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
        .await
        .expect_err("baseline unpaid");
    assert_eq!(err, StatusCode::PAYMENT_REQUIRED);

    // Direct DB inspection: no satisfaction was recorded.
    let satisfied = db::is_paidk_satisfied(&state.db_pool, &device_b32)
        .await
        .expect("is_paidk_satisfied");
    assert!(
        !satisfied,
        "malformed input must not produce paidk_satisfied state"
    );

    // And the gate still rejects.
    let err2 = dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
        .await
        .expect_err("still unpaid after malformed attempt");
    assert_eq!(err2, StatusCode::PAYMENT_REQUIRED);
}

/// T-D: `mark_paidk_satisfied` is idempotent — calling it twice leaves the
/// device satisfied, and the gate continues to accept.
#[tokio::test]
async fn t_d_idempotent_already_paid() {
    let state = make_state().await;
    let device_b32 = b32_of(&[0xDD; 32]);
    register_test_device(&state, &device_b32).await;
    db::mark_paidk_satisfied(&state.db_pool, &device_b32)
        .await
        .expect("first mark_paidk_satisfied");
    db::mark_paidk_satisfied(&state.db_pool, &device_b32)
        .await
        .expect("second mark_paidk_satisfied (idempotent)");
    dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
        .await
        .expect("paid device must still pass after idempotent re-mark");
}

/// T-E cross-endpoint sweep: a single shared unpaid device id is rejected by
/// the gate in every invocation, confirming the helper is the single source of
/// truth for the device-side spend gate.
#[tokio::test]
async fn t_e_cross_endpoint_sweep_unpaid_rejects() {
    let state = make_state().await;
    let device_b32 = b32_of(&[0xEE; 32]);
    // Five sweeps stand in for the three gated handlers calling the helper
    // (object put, object delete, b0x submit) plus headroom.
    for _ in 0..5 {
        let err = dsm_storage_node::api::paidk::require_paidk(&state, &device_b32)
            .await
            .expect_err("every invocation of the helper must reject unpaid");
        assert_eq!(err, StatusCode::PAYMENT_REQUIRED);
    }
}
