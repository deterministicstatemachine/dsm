#![allow(clippy::disallowed_methods)]
#![allow(clippy::explicit_auto_deref)]

use std::sync::Arc;

use dsm_storage_node::{
    db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use prost::Message;
use rustls::crypto::{self, CryptoProvider};
use std::sync::Once;

fn ensure_rustls_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let provider = crypto::ring::default_provider();
        let _ = CryptoProvider::install_default(provider);
    });
}

fn unique_node_id() -> String {
    // Clockless uniqueness for test isolation (avoid cross-test interference in shared DB).
    // This is only for tests; production node ids are stable.
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("test-node-{}-{}", std::process::id(), n)
}

#[tokio::test]
async fn bytecommit_chain_records_parent_link() -> anyhow::Result<()> {
    if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
        eprintln!("Skipping DB test (set DSM_RUN_DB_TESTS=1 to enable)");
        return Ok(());
    }
    ensure_rustls_provider_installed();
    // Note: build_app_for_tests uses DSM_DATABASE_URL or defaults.
    let database_url = std::env::var("DSM_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());
    let pool = db::create_pool(&database_url, true)?;
    db::init_db(&pool).await?;

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
            unique_node_id(),
            "http://localhost:8080".to_string(),
        )
        .expect("Failed to create replication manager"),
    );
    let state = AppState::new(unique_node_id(), None, Arc::new(pool), replication_manager);

    // Ensure DLV slot exists for bytecommit namespace.
    // Deterministic, small capacity.
    let dlv_id: &[u8] = b"bytecommit";
    if !db::slot_exists(&*state.db_pool, dlv_id).await? {
        db::create_slot(&*state.db_pool, dlv_id, 10_000_000, b"stake").await?;
    }

    // Emit first commitment (returns dt := H("DSM/bytecommit\0" || Bt)).
    let dt0 = dsm_storage_node::api::objects::bytecommit::emit_cycle_commitment(&state, 0).await?;

    // Emit second commitment.
    let dt1 = dsm_storage_node::api::objects::bytecommit::emit_cycle_commitment(&state, 1).await?;

    // Fetch commit bytes at cycle 1 and decode with prost.
    let addr1 = {
        use dsm_sdk::util::text_id;
        use dsm_storage_node::api::infra::hardening::blake3_tagged;

        // addr := H("DSM/obj-bytecommit\0" || node_id_32 || t || dt)
        let node_id_32 = blake3_tagged("DSM/node-id", state.node_id.as_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&node_id_32);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&dt1);
        let digest = blake3_tagged("DSM/obj-bytecommit", &body);
        text_id::encode_base32_crockford(&digest)
    };

    let bytes = db::get_object_by_key(&*state.db_pool, &addr1)
        .await?
        .ok_or_else(|| anyhow::anyhow!("bytecommit object not found"))?;

    let msg = dsm_storage_node::api::objects::bytecommit::ByteCommitV3::decode(bytes.as_slice())?;

    assert_eq!(msg.cycle_index, 1);
    assert_eq!(msg.parent_digest.as_slice(), dt0.as_slice());

    Ok(())
}
