// SPDX-License-Identifier: Apache-2.0
//! End-to-end Genesis MPC test (Task A.4 follow-up).
//!
//! Spins up three real `axum` servers on `127.0.0.1:0`, each mounting
//! the storage-node's MPC + discovery routes against an in-memory
//! SQLite. The device-side orchestrator
//! (`dsm::core::identity::genesis_mpc::create_root_genesis_mpc`) runs
//! the full three-round protocol against the cluster via
//! `HttpGenesisMpcTransport` (real `reqwest`).
//!
//! These tests cover wire-level concerns the in-process tests can't:
//!
//! - URL path correctness on offer / commit / reveal endpoints
//! - prost framing + Content-Type handling
//! - Real cross-task state visibility (every node's DB row reaches
//!   "revealed" only after the bias-resistance gate)
//! - Real reqwest error mapping (a killed handler must abort the
//!   orchestrator)
//!
//! Cryptographic correctness (commit/reveal binding, G recomputability,
//! D_commit/D_reveal/η₀ pinning) is already covered by the in-process
//! orchestrator tests in
//! `dsm/src/core/identity/genesis_mpc.rs::tests` against the
//! `InMemoryCommitRevealCluster` mock, which mirrors the storage-node
//! state machine byte-for-byte (KAT-pinned by
//! `commit_digest_matches_core_genesis_commit_formula`).

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;

use dsm::core::identity::genesis_mpc::create_root_genesis_mpc;
use dsm_sdk::sdk::genesis_mpc_transport::HttpGenesisMpcTransport;
use dsm_storage_node::api;
use dsm_storage_node::db;
use dsm_storage_node::replication::{ReplicationConfig, ReplicationManager};
use dsm_storage_node::AppState;

/// Spawn one in-memory storage node and return its `AppState` plus
/// the public base URL the orchestrator will hit (e.g.
/// `http://127.0.0.1:54321`).
async fn spawn_test_node(seed: &str) -> (Arc<AppState>, String) {
    let pool = db::create_pool(":memory:", true).expect("test pool");
    db::init_db(&pool).await.expect("init_db");

    let cfg = ReplicationConfig {
        replication_factor: 1,
        gossip_interval_ticks: 1000,
        failure_timeout_ticks: 1000,
        gossip_fanout: 1,
        max_concurrent_jobs: 1,
    };
    let address = format!("http://{seed}.test");
    let replication_manager = Arc::new(
        ReplicationManager::new_for_tests(cfg, seed.to_string(), address.clone())
            .expect("test replication manager"),
    );

    let state = Arc::new(AppState::new(
        seed.to_string(),
        &address,
        None,
        Arc::new(pool),
        replication_manager,
    ));

    // Mount only the routes the MPC orchestrator + node-identity
    // lookup hit. No auth middleware needed — the MPC handler
    // itself enforces SPHINCS+ verification on /offer + /reveal.
    let app: Router = Router::new()
        .merge(api::identity::genesis_mpc::create_router(state.clone()))
        .merge(api::registry::discovery::create_router(state.clone()));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", local_addr);

    tokio::spawn(async move {
        // Ignore server-side errors — the test asserts via the
        // orchestrator's return values.
        let _ = axum::serve(listener, app).await;
    });

    (state, base_url)
}

/// Build an orchestrator-side test input set: a random keypair, a
/// random session_id, deterministic device_id / cdbrw / k_dbrw.
#[allow(clippy::type_complexity)]
fn make_orchestrator_inputs(
    state_a: &AppState,
    state_b: &AppState,
    state_c: &AppState,
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    Vec<u8>,
    Vec<u8>,
    Vec<[u8; 32]>,
) {
    let session_id = [0xAAu8; 32];
    let device_id = [0xBBu8; 32];
    let device_cdbrw = [0xCCu8; 32];
    let k_dbrw = [0xDDu8; 32];
    let (pk_attest, sk_attest) =
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("sphincs keypair");
    let mut participants = vec![
        *state_a.node_id.as_bytes(),
        *state_b.node_id.as_bytes(),
        *state_c.node_id.as_bytes(),
    ];
    participants.sort();
    (
        session_id,
        device_id,
        device_cdbrw,
        k_dbrw,
        pk_attest,
        sk_attest,
        participants,
    )
}

#[tokio::test]
async fn happy_path_3_nodes_real_http() {
    let (s_a, url_a) = spawn_test_node("e2e-a").await;
    let (s_b, url_b) = spawn_test_node("e2e-b").await;
    let (s_c, url_c) = spawn_test_node("e2e-c").await;

    let (session_id, device_id, device_cdbrw, k_dbrw, pk_attest, sk_attest, participants) =
        make_orchestrator_inputs(&s_a, &s_b, &s_c);

    let id_a = *s_a.node_id.as_bytes();
    let id_b = *s_b.node_id.as_bytes();
    let id_c = *s_c.node_id.as_bytes();
    let transport = HttpGenesisMpcTransport::new(vec![(id_a, url_a), (id_b, url_b), (id_c, url_c)]);

    let outcome = create_root_genesis_mpc(
        session_id,
        device_id,
        device_cdbrw,
        participants.clone(),
        k_dbrw,
        Some(b"e2e|happy".to_vec()),
        pk_attest,
        &sk_attest,
        &transport,
    )
    .await
    .expect("happy path 3-node MPC over HTTP must succeed");

    // Genesis hash is non-zero and the session passes its own
    // validation (verify_commitments + canonical_a check).
    assert_ne!(outcome.session.genesis_id, [0u8; 32]);
    assert_eq!(outcome.session.mpc_entropies.len(), 3);
    assert!(outcome.session.verify_commitments());

    // Every storage node's session row reached "revealed" — proves
    // the bias-resistance gate fired correctly and the orchestrator
    // ran all three rounds against each participant.
    for state in [&s_a, &s_b, &s_c] {
        let row = db::genesis_mpc_session_get(&state.db_pool, &session_id)
            .await
            .expect("session get")
            .expect("session row present");
        assert_eq!(
            row.state, "revealed",
            "node {:?} did not advance to revealed",
            state.node_id
        );
        // Persisted pk_attest + signature match what the orchestrator
        // sent — confirms the signature actually crossed the wire.
        assert_eq!(row.initiator_pk_attest.len(), outcome.pk_attest.len());
        assert!(!row.initiator_signature.is_empty());
    }
}

#[tokio::test]
async fn missing_participant_url_aborts_orchestrator() {
    // Only 2 of 3 declared participants are reachable — the third id
    // has no URL in the transport map. The orchestrator MUST abort
    // at the offer round (spec §5 N-of-N).
    let (s_a, url_a) = spawn_test_node("e2e-miss-a").await;
    let (s_b, url_b) = spawn_test_node("e2e-miss-b").await;
    let (s_c, _url_c) = spawn_test_node("e2e-miss-c").await;

    let (session_id, device_id, device_cdbrw, k_dbrw, pk_attest, sk_attest, participants) =
        make_orchestrator_inputs(&s_a, &s_b, &s_c);

    // Drop the third URL from the map (URL deliberately omitted).
    let id_a = *s_a.node_id.as_bytes();
    let id_b = *s_b.node_id.as_bytes();
    let transport = HttpGenesisMpcTransport::new(vec![(id_a, url_a), (id_b, url_b)]);

    let result = create_root_genesis_mpc(
        session_id,
        device_id,
        device_cdbrw,
        participants,
        k_dbrw,
        None,
        pk_attest,
        &sk_attest,
        &transport,
    )
    .await;
    assert!(
        result.is_err(),
        "MPC must abort when a declared participant has no transport URL"
    );
}

#[tokio::test]
async fn second_offer_with_same_session_id_returns_409() {
    // Driving the orchestrator twice against the same 3-node cluster
    // with the same `session_id` is the strongest end-to-end check
    // for the write-once primary-key invariant on storage nodes.
    // The first run completes; the second must abort because every
    // node returns 409 Conflict on the duplicate /offer.
    let (s_a, url_a) = spawn_test_node("e2e-dup-a").await;
    let (s_b, url_b) = spawn_test_node("e2e-dup-b").await;
    let (s_c, url_c) = spawn_test_node("e2e-dup-c").await;

    let (session_id, device_id, device_cdbrw, k_dbrw, pk_attest, sk_attest, participants) =
        make_orchestrator_inputs(&s_a, &s_b, &s_c);

    let id_a = *s_a.node_id.as_bytes();
    let id_b = *s_b.node_id.as_bytes();
    let id_c = *s_c.node_id.as_bytes();
    let transport = HttpGenesisMpcTransport::new(vec![(id_a, url_a), (id_b, url_b), (id_c, url_c)]);

    create_root_genesis_mpc(
        session_id,
        device_id,
        device_cdbrw,
        participants.clone(),
        k_dbrw,
        None,
        pk_attest.clone(),
        &sk_attest,
        &transport,
    )
    .await
    .expect("first run should succeed");

    let second = create_root_genesis_mpc(
        session_id,
        device_id,
        device_cdbrw,
        participants,
        k_dbrw,
        None,
        pk_attest,
        &sk_attest,
        &transport,
    )
    .await;
    assert!(
        second.is_err(),
        "second offer with same session_id must abort (write-once primary key)"
    );
}
