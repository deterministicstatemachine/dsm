// SPDX-License-Identifier: MIT OR Apache-2.0

//! Library crate for dsm_storage_node: shared types and routers for tests
#![deny(warnings)]

use axum::Extension;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub mod api;
pub mod auth;
pub mod db;
#[cfg(feature = "dev-replication")]
pub mod dev_replication;
pub mod replication;
pub mod timing;

use replication::StorageNodeId;

#[derive(Clone)]
pub struct AppState {
    pub node_id: StorageNodeId,
    pub hsts_max_age: Option<u64>,
    pub db_pool: Arc<db::DBPool>,
    pub replication_manager: Arc<replication::ReplicationManager>,
    pub current_tick: Arc<AtomicI64>,
    /// The canonical storage set this node is a member of (`[storage_set]
    /// members = [...]` in config, canonical id derived exactly as clients derive
    /// it). `None` = not configured: the settlement-slot register refuses every
    /// claim (fail closed) rather than accepting claims for an unknown set.
    pub storage_set: Option<Arc<NodeStorageSet>>,
    /// The DSM network this node serves (`node.network_id` in config). Gates
    /// the ERA faucet-ticket register: the canonical faucet identity is
    /// NETWORK-SCOPED (`era_faucet_id(network_id)`), so a node that does not
    /// know its network cannot tell the canonical faucet from an invented
    /// one and refuses every ticket claim (fail closed) rather than
    /// defaulting. `None` = faucet register inactive.
    pub network_id: Option<Arc<Vec<u8>>>,
}

/// This node's view of the canonical storage set it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStorageSet {
    /// `dsm_sdk::sdk::storage_set::compute_storage_set_id` over `member_ids`.
    pub id: [u8; 32],
    /// The configured protocol identities of every member (this node's own
    /// `node.id` string must be among them).
    pub member_ids: Vec<String>,
}

impl NodeStorageSet {
    /// Build from configured member ids; refuses an empty set, duplicate ids,
    /// or a set that does not contain `own_node_id` — a node that would
    /// acknowledge claims for a set it is not a member of is misconfigured.
    pub fn new(member_ids: Vec<String>, own_node_id: &str) -> anyhow::Result<Self> {
        if !member_ids.iter().any(|m| m == own_node_id) {
            anyhow::bail!(
                "storage_set.members does not contain this node's own id {own_node_id:?}"
            );
        }
        let refs: Vec<&str> = member_ids.iter().map(|s| s.as_str()).collect();
        let id = dsm_sdk::sdk::storage_set::compute_storage_set_id(&refs)
            .map_err(|e| anyhow::anyhow!("storage_set.members: {e}"))?;
        Ok(Self { id, member_ids })
    }
}

impl AppState {
    /// Build an AppState. The supplied `node_id_input` is canonicalised exactly
    /// like `canonical_node_info` does for gossip: if it is a valid 32-byte
    /// base32-crockford string, it is decoded as-is; otherwise a 32-byte node
    /// id is derived from `address_or_seed`. The result is the single
    /// canonical operator identity used across replication, ByteCommit
    /// emission, HTTP headers, and DB chain anchoring.
    pub fn new(
        node_id_input: String,
        address_or_seed: &str,
        hsts_max_age: Option<u64>,
        db_pool: Arc<db::DBPool>,
        replication_manager: Arc<replication::ReplicationManager>,
    ) -> Self {
        let node_id =
            StorageNodeId::from_base32_or_derive(&node_id_input, address_or_seed.as_bytes());
        Self {
            node_id,
            hsts_max_age,
            db_pool,
            replication_manager,
            current_tick: Arc::new(AtomicI64::new(0)),
            storage_set: None,
            network_id: None,
        }
    }

    /// Attach this node's canonical storage set (see [`NodeStorageSet`]).
    pub fn with_network_id(mut self, network_id: Vec<u8>) -> Self {
        self.network_id = Some(Arc::new(network_id));
        self
    }

    pub fn with_storage_set(mut self, set: NodeStorageSet) -> Self {
        self.storage_set = Some(Arc::new(set));
        self
    }
}

/// The device-authenticated WRITE half of the two economic write-once
/// registers (faucet tickets, economic roots), behind `auth::device_auth` so
/// attribution runs against the authenticated key AND device.
///
/// ONE assembly, used by the binary's router and by the register conformance
/// suite, so what the suite drives is what the binary serves.
pub fn economic_register_write_router(state: Arc<AppState>) -> axum::Router<()> {
    let auth_state = Arc::new(auth::AuthState {
        db_pool: state.db_pool.clone(),
    });
    api::economic::faucet_ticket::create_write_router()
        .merge(api::economic::root_register::create_write_router())
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            auth::device_auth,
        ))
        .layer(Extension(state))
}

/// The public READ half of the same two registers. The binary rate-limits it;
/// the conformance suite mounts it bare.
pub fn economic_register_read_router(state: Arc<AppState>) -> axum::Router<()> {
    api::economic::faucet_ticket::create_read_router(state.clone())
        .merge(api::economic::root_register::create_read_router(state))
}

/// Echo this node's configured protocol identity on EVERY response.
///
/// A client fanning a keyed write out over a canonical storage set counts an
/// acceptance only when the answering node IS the member its catalog says
/// lives at that endpoint — "distinct members" is executable, not
/// administrative. This is identity, not authentication (crash-fault node
/// model): it prevents two catalog entries on one physical node from yielding
/// two acceptances; it does not prove the node is honest. The value is the
/// RAW configured id, byte-for-byte what the client's catalog names.
pub fn node_identity_echo_layer(
    node_id: &str,
) -> tower_http::set_header::SetResponseHeaderLayer<axum::http::HeaderValue> {
    tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::HeaderName::from_static("x-dsm-node-id"),
        axum::http::HeaderValue::from_str(node_id)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("invalid-node-id")),
    )
}

/// Minimal app builder for tests that don't require DB access.
/// It wires only the routes needed by tests (registry gate), with a lazy pool.
///
/// When compiled with the `local-dev` feature (SQLite), defaults to an
/// in-memory database so no PostgreSQL installation is required.
/// When compiled with the `postgres` feature, honours the `DSM_DATABASE_URL`
/// environment variable (no default database URL is provided — tests that need
/// a real PG instance must set that variable).
pub async fn build_app_for_tests() -> anyhow::Result<axum::Router> {
    let database_url = std::env::var("DSM_DATABASE_URL").unwrap_or_else(|_| {
        // `local-dev` (SQLite) build: open an in-memory database.
        // `postgres` build: callers must supply DSM_DATABASE_URL.
        #[cfg(feature = "local-dev")]
        {
            ":memory:".to_string()
        }
        #[cfg(not(feature = "local-dev"))]
        {
            "postgresql://localhost:5432/dsm_storage".to_string()
        }
    });
    let pool = db::create_pool(&database_url, true)?;

    // Initialize DB schema for tests
    db::init_db(&pool).await?;

    let replication_config = replication::ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,
        failure_timeout_ticks: 500,
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    };
    let replication_manager = Arc::new(
        replication::ReplicationManager::new_for_tests(
            replication_config,
            "test-node".to_string(),
            "http://localhost:8080".to_string(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create replication manager: {}", e))?,
    );

    let state = AppState::new(
        "test-node".to_string(),
        "http://localhost:8080",
        None,
        Arc::new(pool),
        replication_manager,
    );
    let state_arc = Arc::new(state);

    // Only mount registry routes for the current tests
    Ok(axum::Router::new()
        .merge(api::registry::core::create_router(state_arc.clone()))
        .layer(Extension(state_arc)))
}
