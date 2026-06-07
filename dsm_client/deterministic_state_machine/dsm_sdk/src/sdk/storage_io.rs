// SPDX-License-Identifier: MIT OR Apache-2.0

//! Neutral storage object I/O over the DSM storage-node fleet.
//!
//! DSM storage nodes are independent endpoints (no server-side replication for the
//! production deployment) and each maintains its own per-device auth table, rejecting
//! tokens issued by a different node with HTTP 401. So a write must fan out to EVERY
//! configured node, each request authenticated with that node's OWN token resolved from
//! the local DB. This module is the single home for that fan-out + per-node-auth +
//! lazy auth back-fill logic.
//!
//! It was lifted out of `bitcoin_tap_sdk` so non-dBTC subsystems (recovery-authority
//! anchors, recovery evidence) can post/fetch objects without coupling to the dBTC SDK
//! or duplicating the auth handling. `bitcoin_tap_sdk::storage_*` now delegate their
//! production paths here while keeping their own in-memory test/demos store.
//!
//! Storage is availability-only: callers verify everything client-side. These helpers
//! return raw bytes; authentication of the CONTENT (signatures, genesis/device-tree
//! proofs) is the caller's responsibility.

use crate::sdk::storage_node_sdk::{
    build_ca_aware_client, StorageAuthContext, StorageNodeConfig, StorageNodeSDK,
};
use dsm::types::error::DsmError;
use dsm::types::proto as generated;

/// Resolve device auth credentials for a storage node write.
///
/// Looks up device_id + genesis from AppState, then fetches the per-node auth token
/// from SQLite. Returns `None` (with a log) if credentials are unavailable — callers
/// still attempt the request unauthenticated so regtest/dev flows work.
pub(crate) fn resolve_storage_auth(node_url: &str) -> Option<StorageAuthContext> {
    let device_id = crate::sdk::app_state::AppState::get_device_id()?;
    let genesis = crate::sdk::app_state::AppState::get_genesis_hash()?;
    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
    let genesis_b32 = crate::util::text_id::encode_base32_crockford(&genesis);
    let token =
        match crate::storage::client_db::get_auth_token(node_url, &device_id_b32, &genesis_b32) {
            Ok(Some(t)) => t,
            Ok(None) => {
                log::debug!(
                    "[storage_auth] no auth token for node={} device={} (device not registered?)",
                    &node_url[..node_url.len().min(40)],
                    &device_id_b32[..device_id_b32.len().min(12)]
                );
                return None;
            }
            Err(e) => {
                log::warn!("[storage_auth] auth token lookup failed: {e}");
                return None;
            }
        };
    Some(StorageAuthContext {
        device_id_b32,
        token_b32: token,
    })
}

/// Fan-out PUT to every configured storage node, each authenticated with its OWN
/// per-node token. Lazily back-fills missing auth tokens via a registration pass
/// (idempotent) so every node knows this device. Returns the object address.
pub(crate) async fn put_bytes(key: &str, payload: &[u8]) -> Result<String, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let sdk = StorageNodeSDK::new(config.clone()).await.map_err(|e| {
        DsmError::storage(
            format!("construct storage node sdk: {e}"),
            None::<std::io::Error>,
        )
    })?;
    // Resolve auth for each configured node so the per-client auth is the right token
    // for that specific endpoint.
    let mut auths = std::collections::HashMap::new();
    for url in &config.node_urls {
        if let Some(auth) = resolve_storage_auth(url) {
            auths.insert(url.clone(), auth);
        }
    }
    // Lazy back-fill: if any configured node has no token in the local DB, run a
    // registration pass so every node knows this device. Idempotent — re-registering a
    // known (device, node) pair returns the existing token.
    if auths.len() < config.node_urls.len() {
        let missing = config.node_urls.len() - auths.len();
        log::info!(
            "storage_io::put_bytes: {missing}/{} nodes lack a local auth token — running register_device_for_auth to back-fill",
            config.node_urls.len()
        );
        let device_id = crate::sdk::app_state::AppState::get_device_id().unwrap_or_default();
        let public_key = crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
        let genesis_hash = crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();
        if !device_id.is_empty() && !public_key.is_empty() && !genesis_hash.is_empty() {
            let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
            let public_key_b32 = crate::util::text_id::encode_base32_crockford(&public_key);
            let genesis_hash_b32 = crate::util::text_id::encode_base32_crockford(&genesis_hash);
            if let Err(e) = sdk
                .register_device_for_auth(&device_id_b32, &public_key_b32, &genesis_hash_b32)
                .await
            {
                log::warn!(
                    "storage_io::put_bytes: back-fill register_device_for_auth failed: {e} \
                     (continuing — some nodes may still PUT-401)"
                );
            }
            // Re-read the local DB to pick up the freshly-stored tokens.
            auths.clear();
            for url in &config.node_urls {
                if let Some(auth) = resolve_storage_auth(url) {
                    auths.insert(url.clone(), auth);
                }
            }
            log::info!(
                "storage_io::put_bytes: post-back-fill auths populated for {}/{} nodes",
                auths.len(),
                config.node_urls.len()
            );
        } else {
            log::warn!(
                "storage_io::put_bytes: skipping back-fill — AppState identity not loaded \
                 (device_id_empty={} pk_empty={} genesis_empty={})",
                device_id.is_empty(),
                public_key.is_empty(),
                genesis_hash.is_empty()
            );
        }
    }
    let sdk = sdk.with_per_node_auth(&auths);
    sdk.put_to_all_replicas(key, payload, None).await
}

/// Fetch an object's bytes by key, with failover across the configured nodes.
pub(crate) async fn get_bytes(key: &str) -> Result<Vec<u8>, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let sdk = StorageNodeSDK::new(config).await.map_err(|e| {
        DsmError::storage(
            format!("construct storage node sdk: {e}"),
            None::<std::io::Error>,
        )
    })?;
    sdk.get(key).await
}

/// List posted objects under `prefix` (paginated).
pub(crate) async fn list_objects(
    prefix: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<generated::ObjectListResponseV1, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let sdk = StorageNodeSDK::new(config).await.map_err(|e| {
        DsmError::storage(
            format!("construct storage node sdk: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let response = sdk.list_objects(prefix, cursor, limit).await?;
    Ok(generated::ObjectListResponseV1 {
        items: response
            .items
            .into_iter()
            .map(|item| generated::ObjectListItemV1 {
                key: item.key,
                dlv_id_b32: item.dlv_id_b32,
                size_bytes: item.size_bytes,
            })
            .collect(),
        next_cursor: response.next_cursor,
    })
}

/// Outcome of a fan-out PUT to a custom (non-object-store) endpoint path across
/// every configured node. DSM storage nodes are independent mirrors, so a write
/// must reach each one; `conflict` counts HTTP 409 (single-assignment rejection)
/// separately from `failed` (network / other non-2xx) so the caller can tell
/// "a different value is already bound" apart from "the node was unreachable".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PathPutFanout {
    pub ok: usize,
    pub conflict: usize,
    pub failed: usize,
    pub total: usize,
}

/// PUT `payload` to `{node}/{path}` on every configured node (no per-node auth —
/// these endpoints are public/rate-limited, like the device-tree root). `path`
/// is the endpoint path WITHOUT a leading slash, e.g.
/// `api/v2/recovery/authority-anchor/{genesis_b32}`.
pub(crate) async fn put_to_all_nodes_path(
    path: &str,
    payload: &[u8],
) -> Result<PathPutFanout, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let client = build_ca_aware_client();
    let path = path.trim_start_matches('/');
    let mut r = PathPutFanout::default();
    for node_url in &config.node_urls {
        let trimmed = node_url.trim_end_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        r.total += 1;
        let url = format!("{trimmed}/{path}");
        match client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(payload.to_vec())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    r.ok += 1;
                } else if status == reqwest::StatusCode::CONFLICT {
                    r.conflict += 1;
                    log::warn!("put_to_all_nodes_path: {trimmed} returned 409 Conflict for {path}");
                } else {
                    r.failed += 1;
                    log::warn!(
                        "put_to_all_nodes_path: {trimmed} returned HTTP {} for {path}",
                        status.as_u16()
                    );
                }
            }
            Err(e) => {
                r.failed += 1;
                log::warn!("put_to_all_nodes_path: network error against {trimmed}: {e}");
            }
        }
    }
    Ok(r)
}

/// GET `{node}/{path}` from the configured nodes, returning the first 2xx body
/// (failover). `path` is the endpoint path WITHOUT a leading slash.
pub(crate) async fn get_from_any_node_path(path: &str) -> Result<Vec<u8>, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let client = build_ca_aware_client();
    let path = path.trim_start_matches('/');
    let mut last_err = String::from("no nodes configured");
    for node_url in &config.node_urls {
        let trimmed = node_url.trim_end_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        let url = format!("{trimmed}/{path}");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => return Ok(b.to_vec()),
                Err(e) => last_err = format!("read body from {trimmed}: {e}"),
            },
            Ok(resp) => last_err = format!("{trimmed} returned HTTP {}", resp.status().as_u16()),
            Err(e) => last_err = format!("network error against {trimmed}: {e}"),
        }
    }
    Err(DsmError::storage(
        format!("get_from_any_node_path({path}) failed on all nodes: {last_err}"),
        None::<std::io::Error>,
    ))
}
