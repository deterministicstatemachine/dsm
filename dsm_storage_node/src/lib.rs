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
        }
    }

    /// Attach this node's canonical storage set (see [`NodeStorageSet`]).
    pub fn with_storage_set(mut self, set: NodeStorageSet) -> Self {
        self.storage_set = Some(Arc::new(set));
        self
    }
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
