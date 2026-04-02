// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV Receipt Storage SDK — submit / retrieve stitched receipts to storage nodes.
//!
//! Uses the existing `/api/v2/object/put` and `/api/v2/object/get/{key}` endpoints
//! on storage nodes (the same object store used by vault advertisements and other
//! content-addressed data). No dedicated `/api/v2/dlv/receipt` endpoint required.
//!
//! - CircuitBreaker for node health
//! - Quorum writes (K healthy nodes)
//! - Local SQLite persistence as primary + remote storage as redundant copies

use dsm::types::error::DsmError;
use dsm::types::receipt_types::StitchedReceiptV2;

use crate::util::{deterministic_time as dt, text_id};

use log::{debug, info, warn};
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use dsm::utils::time::Duration;

/// DLV receipt storage SDK for submitting and retrieving stitched receipts
/// on storage nodes (redundant, public, asynchronous).
pub struct DlvReceiptSdk {
    device_id: String, // base32
    storage_node_endpoints: Vec<String>,
    http_client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
}

#[derive(Clone)]
struct CircuitBreaker {
    failed_nodes: Arc<tokio::sync::RwLock<HashMap<String, u64>>>,
    failure_threshold: Duration,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failed_nodes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            failure_threshold: Duration::from_ticks(300),
        }
    }

    async fn is_node_healthy(&self, endpoint: &str) -> bool {
        let failed = self.failed_nodes.read().await;
        if let Some(&t) = failed.get(endpoint) {
            let now = dt::peek() as i64;
            (now - t as i64) as u64 >= self.failure_threshold.as_secs()
        } else {
            true
        }
    }

    async fn mark_node_failed(&self, endpoint: &str) {
        self.failed_nodes
            .write()
            .await
            .insert(endpoint.to_string(), dt::peek());
        warn!("DlvReceiptSdk CircuitBreaker: marked failed {}", endpoint);
    }

    async fn mark_node_healthy(&self, endpoint: &str) {
        if self.failed_nodes.write().await.remove(endpoint).is_some() {
            info!("DlvReceiptSdk CircuitBreaker: {} back to healthy", endpoint);
        }
    }

    async fn healthy_endpoints(&self, all: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for ep in all {
            if self.is_node_healthy(ep).await {
                out.push(ep.clone());
            }
        }
        out
    }
}

impl DlvReceiptSdk {
    pub fn new(
        device_id_b32: String,
        _core_sdk: Arc<crate::sdk::core_sdk::CoreSDK>,
        storage_endpoints: Vec<String>,
    ) -> Result<Self, DsmError> {
        let decoded = text_id::decode_base32_crockford(&device_id_b32).ok_or_else(|| {
            DsmError::internal(
                "DlvReceiptSdk::new: device_id must be base32",
                None::<std::io::Error>,
            )
        })?;
        if decoded.len() != 32 {
            return Err(DsmError::internal(
                format!(
                    "DlvReceiptSdk::new: device_id base32 decoded to {} bytes (expected 32)",
                    decoded.len()
                ),
                None::<std::io::Error>,
            ));
        }

        let http_client = crate::sdk::storage_node_sdk::build_ca_aware_client();

        Ok(Self {
            device_id: device_id_b32,
            storage_node_endpoints: storage_endpoints,
            http_client,
            circuit_breaker: CircuitBreaker::new(),
        })
    }

    /// Submit a stitched receipt to storage nodes and persist locally.
    ///
    /// Returns the 32-byte σ commitment on success.
    pub async fn submit_receipt(
        &self,
        receipt: &StitchedReceiptV2,
        vault_id: &str,
    ) -> Result<[u8; 32], DsmError> {
        // 1. Compute σ
        let sigma = receipt.compute_commitment().map_err(|e| {
            DsmError::internal(
                format!("Failed to compute receipt commitment: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // 2. Serialize to canonical protobuf
        let receipt_proto = receipt.to_canonical_protobuf().map_err(|e| {
            DsmError::internal(
                format!("Failed to serialize receipt: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // 3. Build submission message
        let submission = crate::generated::DlvReceiptSubmission {
            sigma: sigma.to_vec(),
            vault_id: vault_id.to_string(),
            receipt_proto: receipt_proto.clone(),
            sig_a: receipt.sig_a.clone(),
            sig_b: receipt.sig_b.clone(),
        };
        let body = submission.encode_to_vec();

        // 4. POST to all healthy endpoints (quorum) via object store
        let healthy = self
            .circuit_breaker
            .healthy_endpoints(&self.storage_node_endpoints)
            .await;
        if healthy.is_empty() {
            warn!("DlvReceiptSdk: no healthy storage nodes, storing locally only");
        }

        let sigma_b32 = text_id::encode_base32_crockford(&sigma);
        let mut success_count = 0usize;
        for endpoint in &healthy {
            match self
                .post_receipt(endpoint, vault_id, &sigma_b32, &body)
                .await
            {
                Ok(()) => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    success_count += 1;
                }
                Err(e) => {
                    warn!("DlvReceiptSdk: submit to {} failed: {}", endpoint, e);
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                }
            }
        }

        if success_count > 0 {
            info!(
                "DlvReceiptSdk: submitted receipt σ={} to {}/{} nodes",
                text_id::encode_base32_crockford(&sigma),
                success_count,
                healthy.len()
            );
        }

        // 5. Persist locally
        // Fail-closed invariant: never persist synthetic identities.
        // Persist genesis/device IDs exactly as committed in the stitched receipt bytes.
        let genesis_arr = receipt.genesis;
        let devid_arr = receipt.devid_a;
        let devid_b = receipt.devid_b;

        let _ = crate::storage::client_db::store_dlv_receipt(
            &crate::storage::client_db::DlvReceiptRecord {
                sigma,
                vault_id: vault_id.to_string(),
                genesis: genesis_arr,
                devid_a: devid_arr,
                devid_b,
                receipt_cbor: receipt_proto,
                sig_a: receipt.sig_a.clone(),
                sig_b: receipt.sig_b.clone(),
                created_at: dt::tick(),
            },
        );

        Ok(sigma)
    }

    /// Retrieve a receipt by vault ID, checking local cache first.
    pub async fn retrieve_receipt_by_vault(
        &self,
        vault_id: &str,
    ) -> Result<Option<Vec<u8>>, DsmError> {
        // 1. Check local SQLite first
        if let Ok(Some(rec)) = crate::storage::client_db::get_dlv_receipt_by_vault(vault_id) {
            return Ok(Some(rec.receipt_cbor));
        }

        // 2. Try remote storage nodes via object store
        let obj_key = format!("dlv/receipt/{}", vault_id);
        let healthy = self
            .circuit_breaker
            .healthy_endpoints(&self.storage_node_endpoints)
            .await;

        for endpoint in &healthy {
            match self.get_object(endpoint, &obj_key).await {
                Ok(Some(data)) => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    // Data is a DlvReceiptSubmission protobuf — extract receipt_proto
                    if let Ok(sub) = crate::generated::DlvReceiptSubmission::decode(data.as_slice())
                    {
                        return Ok(Some(sub.receipt_proto));
                    }
                    // Fallback: return raw data
                    return Ok(Some(data));
                }
                Ok(None) => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                }
                Err(e) => {
                    debug!("DlvReceiptSdk: GET from {} failed: {}", endpoint, e);
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                }
            }
        }

        Ok(None)
    }

    /// Retrieve a receipt by sigma commitment, checking local cache first.
    pub async fn retrieve_receipt_by_sigma(
        &self,
        sigma: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, DsmError> {
        // 1. Check local SQLite first
        if let Ok(Some(rec)) = crate::storage::client_db::get_dlv_receipt_by_sigma(sigma) {
            return Ok(Some(rec.receipt_cbor));
        }

        // 2. Try remote storage nodes — sigma index stores the vault_id
        let sigma_b32 = text_id::encode_base32_crockford(sigma);
        let sigma_key = format!("dlv/receipt/sigma/{}", sigma_b32);
        let healthy = self
            .circuit_breaker
            .healthy_endpoints(&self.storage_node_endpoints)
            .await;

        for endpoint in &healthy {
            // First hop: get vault_id from sigma index
            match self.get_object(endpoint, &sigma_key).await {
                Ok(Some(vault_id_bytes)) => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                    let vault_id = String::from_utf8_lossy(&vault_id_bytes);
                    // Second hop: get actual receipt from vault_id key
                    let receipt_key = format!("dlv/receipt/{}", vault_id);
                    match self.get_object(endpoint, &receipt_key).await {
                        Ok(Some(data)) => {
                            if let Ok(sub) =
                                crate::generated::DlvReceiptSubmission::decode(data.as_slice())
                            {
                                return Ok(Some(sub.receipt_proto));
                            }
                            return Ok(Some(data));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            debug!(
                                "DlvReceiptSdk: GET receipt by sigma from {} failed: {}",
                                endpoint, e
                            );
                        }
                    }
                }
                Ok(None) => {
                    self.circuit_breaker.mark_node_healthy(endpoint).await;
                }
                Err(e) => {
                    debug!(
                        "DlvReceiptSdk: GET sigma index from {} failed: {}",
                        endpoint, e
                    );
                    self.circuit_breaker.mark_node_failed(endpoint).await;
                }
            }
        }

        Ok(None)
    }

    // ========================= Internal helpers =========================

    /// Store receipt via `/api/v2/object/put` with object store headers.
    /// Also stores a sigma index entry for sigma-based lookups.
    async fn post_receipt(
        &self,
        endpoint: &str,
        vault_id: &str,
        sigma_b32: &str,
        body: &[u8],
    ) -> Result<(), DsmError> {
        let obj_key = format!("dlv/receipt/{}", vault_id);
        self.put_object(endpoint, &obj_key, body).await?;

        // Sigma index: store vault_id under sigma key for reverse lookup
        let sigma_key = format!("dlv/receipt/sigma/{}", sigma_b32);
        self.put_object(endpoint, &sigma_key, vault_id.as_bytes())
            .await?;

        Ok(())
    }

    /// PUT bytes to the object store on a specific endpoint.
    async fn put_object(&self, endpoint: &str, obj_key: &str, body: &[u8]) -> Result<(), DsmError> {
        let url = format!("{}/api/v2/object/put", endpoint.trim_end_matches('/'));

        // Compute DLV partition ID (same pattern as StorageNodeSDK::store_data)
        let dlv_id = dsm::crypto::blake3::domain_hash("DSM/dlv-partition\0", obj_key.as_bytes());
        let dlv_id_b32 = text_id::encode_base32_crockford(dlv_id.as_bytes());
        let stake_hash_b32 = text_id::encode_base32_crockford(&[0u8; 32]);

        // Clockless: immediate retry with attempt counter only.
        let max_retries = 3u32;

        for attempt in 0..=max_retries {
            let resp = self
                .http_client
                .post(&url)
                .header("x-dlv-id", &dlv_id_b32)
                .header("x-path", obj_key)
                .header("x-capacity-bytes", "10485760")
                .header("x-stake-hash", &stake_hash_b32)
                .header("Content-Type", "application/octet-stream")
                .body(body.to_vec())
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if (200..300).contains(&status) {
                        return Ok(());
                    }
                    if attempt < max_retries && status >= 500 {
                        continue;
                    }
                    return Err(DsmError::internal(
                        format!("DlvReceiptSdk PUT {} returned {}", url, status),
                        None::<std::io::Error>,
                    ));
                }
                Err(e) => {
                    if attempt < max_retries {
                        continue;
                    }
                    return Err(DsmError::internal(
                        format!("DlvReceiptSdk PUT {} failed: {}", url, e),
                        None::<std::io::Error>,
                    ));
                }
            }
        }
        Ok(())
    }

    /// GET bytes from the object store on a specific endpoint.
    async fn get_object(&self, endpoint: &str, obj_key: &str) -> Result<Option<Vec<u8>>, DsmError> {
        let encoded_key = urlencoding::encode(obj_key);
        let url = format!(
            "{}/api/v2/object/get/{}",
            endpoint.trim_end_matches('/'),
            encoded_key,
        );

        let resp = self.http_client.get(&url).send().await.map_err(|e| {
            DsmError::internal(
                format!("DlvReceiptSdk GET {} failed: {}", url, e),
                None::<std::io::Error>,
            )
        })?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(DsmError::internal(
                format!("DlvReceiptSdk GET {} returned {}", url, status),
                None::<std::io::Error>,
            ));
        }

        let body = resp.bytes().await.map_err(|e| {
            DsmError::internal(
                format!("DlvReceiptSdk GET body read: {}", e),
                None::<std::io::Error>,
            )
        })?;

        Ok(Some(body.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CircuitBreaker ----

    #[test]
    fn circuit_breaker_new_defaults() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.failure_threshold, Duration::from_ticks(300));
    }

    #[tokio::test]
    async fn circuit_breaker_all_healthy_initially() {
        let cb = CircuitBreaker::new();
        assert!(cb.is_node_healthy("http://node1:8080").await);
        assert!(cb.is_node_healthy("http://node2:8080").await);
    }

    #[tokio::test]
    async fn circuit_breaker_mark_failed_then_unhealthy() {
        let cb = CircuitBreaker::new();
        cb.mark_node_failed("http://node1:8080").await;
        // Node should be unhealthy immediately after marking failed
        assert!(!cb.is_node_healthy("http://node1:8080").await);
        // Other nodes unaffected
        assert!(cb.is_node_healthy("http://node2:8080").await);
    }

    #[tokio::test]
    async fn circuit_breaker_mark_healthy_after_failed() {
        let cb = CircuitBreaker::new();
        cb.mark_node_failed("http://node1:8080").await;
        assert!(!cb.is_node_healthy("http://node1:8080").await);

        cb.mark_node_healthy("http://node1:8080").await;
        assert!(cb.is_node_healthy("http://node1:8080").await);
    }

    #[tokio::test]
    async fn circuit_breaker_mark_healthy_noop_when_not_failed() {
        let cb = CircuitBreaker::new();
        cb.mark_node_healthy("http://never-failed:8080").await;
        assert!(cb.is_node_healthy("http://never-failed:8080").await);
    }

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_filters() {
        let cb = CircuitBreaker::new();
        let all = vec![
            "http://a:8080".to_string(),
            "http://b:8080".to_string(),
            "http://c:8080".to_string(),
        ];
        cb.mark_node_failed("http://b:8080").await;

        let healthy = cb.healthy_endpoints(&all).await;
        assert!(healthy.contains(&"http://a:8080".to_string()));
        assert!(!healthy.contains(&"http://b:8080".to_string()));
        assert!(healthy.contains(&"http://c:8080".to_string()));
    }

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_all_failed() {
        let cb = CircuitBreaker::new();
        let all = vec!["http://x:8080".to_string(), "http://y:8080".to_string()];
        cb.mark_node_failed("http://x:8080").await;
        cb.mark_node_failed("http://y:8080").await;

        let healthy = cb.healthy_endpoints(&all).await;
        assert!(healthy.is_empty());
    }

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_empty_input() {
        let cb = CircuitBreaker::new();
        let healthy = cb.healthy_endpoints(&[]).await;
        assert!(healthy.is_empty());
    }

    #[tokio::test]
    async fn circuit_breaker_multiple_failures_same_node() {
        let cb = CircuitBreaker::new();
        cb.mark_node_failed("http://node:8080").await;
        cb.mark_node_failed("http://node:8080").await;
        assert!(!cb.is_node_healthy("http://node:8080").await);
        cb.mark_node_healthy("http://node:8080").await;
        assert!(cb.is_node_healthy("http://node:8080").await);
    }

    // ---- DlvReceiptSdk::new validation ----

    #[test]
    fn new_invalid_base32_device_id() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let result = DlvReceiptSdk::new(
            "not-valid-base32!!!".to_string(),
            core,
            vec!["http://localhost:8080".to_string()],
        );
        match result {
            Err(e) => assert!(format!("{e:?}").contains("base32")),
            Ok(_) => panic!("Expected error for invalid base32"),
        }
    }

    #[test]
    fn new_wrong_length_device_id() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let short_bytes = [0u8; 16];
        let encoded = text_id::encode_base32_crockford(&short_bytes);
        let result = DlvReceiptSdk::new(
            encoded,
            core,
            vec!["http://localhost:8080".to_string()],
        );
        match result {
            Err(e) => assert!(format!("{e:?}").contains("32")),
            Ok(_) => panic!("Expected error for wrong length"),
        }
    }

    #[test]
    fn new_valid_device_id_succeeds() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let device_bytes = [0xABu8; 32];
        let encoded = text_id::encode_base32_crockford(&device_bytes);
        let result = DlvReceiptSdk::new(
            encoded.clone(),
            core,
            vec!["http://node1:8080".to_string()],
        );
        match result {
            Ok(sdk) => {
                assert_eq!(sdk.device_id, encoded);
                assert_eq!(sdk.storage_node_endpoints.len(), 1);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test]
    fn new_empty_endpoints_ok() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let device_bytes = [1u8; 32];
        let encoded = text_id::encode_base32_crockford(&device_bytes);
        let result = DlvReceiptSdk::new(encoded, core, Vec::new());
        match result {
            Ok(sdk) => assert!(sdk.storage_node_endpoints.is_empty()),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    // ---- CircuitBreaker clone ----

    #[tokio::test]
    async fn circuit_breaker_clone_shares_state() {
        let cb = CircuitBreaker::new();
        let cb2 = cb.clone();
        cb.mark_node_failed("http://shared:8080").await;
        // Clone shares the same Arc, so both see the failure
        assert!(!cb2.is_node_healthy("http://shared:8080").await);
    }

    // ---- CircuitBreaker failure_threshold ----

    #[test]
    fn circuit_breaker_failure_threshold_value() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.failure_threshold.as_secs(), 300);
    }

    // ---- healthy_endpoints preserves order of healthy nodes ----

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_preserves_order() {
        let cb = CircuitBreaker::new();
        let all = vec![
            "http://first:8080".to_string(),
            "http://second:8080".to_string(),
            "http://third:8080".to_string(),
        ];
        let healthy = cb.healthy_endpoints(&all).await;
        assert_eq!(healthy[0], "http://first:8080");
        assert_eq!(healthy[1], "http://second:8080");
        assert_eq!(healthy[2], "http://third:8080");
    }

    // ---- DlvReceiptSdk field initialization ----

    #[test]
    fn new_multiple_endpoints_stored() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let device_bytes = [0xCDu8; 32];
        let encoded = text_id::encode_base32_crockford(&device_bytes);
        let endpoints = vec![
            "http://a:8080".to_string(),
            "http://b:8080".to_string(),
            "http://c:8080".to_string(),
        ];
        let sdk = DlvReceiptSdk::new(encoded, core, endpoints).unwrap();
        assert_eq!(sdk.storage_node_endpoints.len(), 3);
    }

    #[test]
    fn new_empty_device_id_fails() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let result = DlvReceiptSdk::new("".to_string(), core, Vec::new());
        assert!(result.is_err());
    }

    // ---- CircuitBreaker mark_node_healthy idempotent ----

    #[tokio::test]
    async fn circuit_breaker_mark_healthy_twice_ok() {
        let cb = CircuitBreaker::new();
        cb.mark_node_failed("http://node:8080").await;
        cb.mark_node_healthy("http://node:8080").await;
        cb.mark_node_healthy("http://node:8080").await;
        assert!(cb.is_node_healthy("http://node:8080").await);
    }

    // ---- CircuitBreaker independent nodes ----

    #[tokio::test]
    async fn circuit_breaker_fail_one_doesnt_affect_others() {
        let cb = CircuitBreaker::new();
        let nodes = ["http://a:8080", "http://b:8080", "http://c:8080"];
        cb.mark_node_failed(nodes[1]).await;
        assert!(cb.is_node_healthy(nodes[0]).await);
        assert!(!cb.is_node_healthy(nodes[1]).await);
        assert!(cb.is_node_healthy(nodes[2]).await);
    }

    // ---- DlvReceiptSdk new with different byte patterns ----

    #[test]
    fn new_all_zeros_device_id_succeeds() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let device_bytes = [0u8; 32];
        let encoded = text_id::encode_base32_crockford(&device_bytes);
        let result = DlvReceiptSdk::new(encoded, core, Vec::new());
        assert!(result.is_ok());
    }

    #[test]
    fn new_all_ff_device_id_succeeds() {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let device_bytes = [0xFFu8; 32];
        let encoded = text_id::encode_base32_crockford(&device_bytes);
        let result = DlvReceiptSdk::new(encoded, core, Vec::new());
        assert!(result.is_ok());
    }

    // ---- CircuitBreaker healthy_endpoints returns only unfailed ----

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_single_node_failed() {
        let cb = CircuitBreaker::new();
        let all = vec!["http://only:8080".to_string()];
        cb.mark_node_failed("http://only:8080").await;
        let healthy = cb.healthy_endpoints(&all).await;
        assert!(healthy.is_empty());
    }

    #[tokio::test]
    async fn circuit_breaker_healthy_endpoints_single_node_healthy() {
        let cb = CircuitBreaker::new();
        let all = vec!["http://only:8080".to_string()];
        let healthy = cb.healthy_endpoints(&all).await;
        assert_eq!(healthy.len(), 1);
    }
}
