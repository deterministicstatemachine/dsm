//! Library crate for dsm_storage_node: shared types and routers for tests
#![deny(warnings)]

use axum::Extension;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub mod api;
pub mod auth;
#[cfg(feature = "chaos-testing")]
pub mod chaos_testing;
pub mod db;
#[cfg(feature = "dev-replication")]
pub mod dev_replication;
pub mod operational;
pub mod partitioning;
pub mod replication;
pub mod timing;

#[derive(Clone)]
pub struct AppState {
    pub node_id: Arc<String>,
    pub hsts_max_age: Option<u64>,
    pub db_pool: Arc<db::DBPool>,
    pub replication_manager: Arc<replication::ReplicationManager>,
    pub current_tick: Arc<AtomicI64>,
}

impl AppState {
    pub fn new(
        node_id: String,
        hsts_max_age: Option<u64>,
        db_pool: Arc<db::DBPool>,
        replication_manager: Arc<replication::ReplicationManager>,
    ) -> Self {
        Self {
            node_id: Arc::new(node_id),
            hsts_max_age,
            db_pool,
            replication_manager,
            current_tick: Arc::new(AtomicI64::new(0)),
        }
    }
}

/// Minimal app builder for tests that don't require DB access.
/// It wires only the routes needed by tests (registry gate), with a lazy pool.
pub async fn build_app_for_tests() -> anyhow::Result<axum::Router> {
    // Create a lazy pool; it won't connect until used.
    let database_url = std::env::var("DSM_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://dsm:dsm@localhost:5432/dsm_storage".to_string());
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
        None,
        Arc::new(pool),
        replication_manager,
    );
    let state_arc = Arc::new(state);

    // Only mount registry routes for the current tests
    Ok(axum::Router::new()
        .merge(api::registry::create_router(state_arc.clone()))
        .layer(Extension(state_arc)))
}
