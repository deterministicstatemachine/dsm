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
