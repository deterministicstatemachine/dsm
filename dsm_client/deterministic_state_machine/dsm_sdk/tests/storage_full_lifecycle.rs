#![allow(clippy::disallowed_methods)]

use dsm_sdk::sdk::external_commitment_sdk::ExternalCommitmentSdk;
use dsm_sdk::sdk::storage_node_sdk::{
    StorageNodeSDK, StorageNodeConfig, ConnectionPoolConfig, RetryConfig, NodeSelectionConfig,
    SecurityConfig, AdvancedFeatures, MonitoringConfig, LoadBalanceStrategy,
    NodeSelectionAlgorithm,
};
use dsm_sdk::dsm::utils::time::Duration;
use dsm::commitments::external_source_id;
use std::sync::Arc;
use std::collections::HashMap;

#[tokio::test]
async fn test_storage_100pc_implemented() {
    // Check if storage node is running, otherwise skip
    let client = reqwest::Client::new();
    let health = client.get("http://localhost:8080/health").send().await;
    match health {
        Err(_) => {
            println!("Storage node not running at localhost:8080, skipping test");
            return;
        }
        Ok(resp) => {
            // Some local dev node sets require auth on /health (401). In that case this live
            // integration test cannot deterministically run, so skip.
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                println!(
                    "Storage node at localhost:8080 requires auth (401 on /health); skipping test"
                );
                return;
            }
            if !resp.status().is_success() {
                println!(
                    "Storage node health check returned {} (expected 2xx); skipping test",
                    resp.status()
                );
                return;
            }
        }
    }

    let config = StorageNodeConfig {
        node_urls: vec!["http://localhost:8080".to_string()],
        pool_config: ConnectionPoolConfig {
            max_connections: 10,
            timeout_seconds: 5,
            retry_attempts: 1,
        },
        retry_config: RetryConfig {
            max_attempts: 1,
            initial_delay: Duration::from_ticks(1),
            max_delay: Duration::from_ticks(2),
            backoff_multiplier: 1.5,
        },
        selection_config: NodeSelectionConfig {
            strategy: LoadBalanceStrategy::RoundRobin,
            algorithm: NodeSelectionAlgorithm::Random,
            max_retries: 1,
            preferred_regions: vec![],
            health_check_interval_ms: 0,
        },
        security_config: SecurityConfig::default(),
        advanced_features: AdvancedFeatures {
            enable_bilateral_sync: false,
            enable_mpc_genesis: false,
            cache_size: 100,
            enable_epidemic_sync: false,
            enable_geo_replication: false,
        },
        monitoring_config: MonitoringConfig {
            enable_metrics: false,
            metrics_interval: Duration::from_ticks(60),
            log_level: "info".to_string(),
        },
        mpc_genesis_url: None,
        mpc_api_key: None,
    };

    let storage_sdk = StorageNodeSDK::new(config).await.expect("SDK init failed");
    let ext_sdk = ExternalCommitmentSdk::new_with_storage(HashMap::new(), Arc::new(storage_sdk));

    // Register
    let context = "test_context";
    let data = b"some external data"; // Treat as 'original_hash' bytes for this test

    // register_commitment(data, provider/context)
    let proof_id = ext_sdk
        .register_commitment(data, context)
        .await
        .expect("Register failed");
    println!("Proof address: {}", proof_id);

    // Fetch
    let commitment = ext_sdk
        .fetch_commitment(&proof_id)
        .await
        .expect("Fetch failed");

    // Verify properties
    let fetched_source_id = ext_sdk.get_source_id(&commitment);
    let fetched_payload = ext_sdk.get_payload(&commitment);

    assert_eq!(fetched_source_id, external_source_id(context).to_vec());
    assert_eq!(fetched_payload, data.to_vec());

    // Test Delete
    ext_sdk
        .delete_commitment(&proof_id)
        .await
        .expect("Delete failed");

    // Verify Gone
    let res = ext_sdk.fetch_commitment(&proof_id).await;
    assert!(res.is_err(), "Should be gone");
}
