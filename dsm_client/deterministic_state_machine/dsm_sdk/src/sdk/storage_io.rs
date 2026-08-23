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

/// Keyed PUT of `payload` under `key` to every member of the canonical set
/// `set`, each authenticated with its OWN per-node token (lazily back-filled
/// like [`put_bytes`]). Returns the per-member fan-out; never short-circuits and
/// never decides quorum — `set.quorum()` is the caller's threshold and
/// `set.len()` its denominator.
///
/// This is the delivery primitive under frozen publication artifacts: the
/// caller passes the exact frozen bytes and the set they were frozen FOR
/// (resolved through the catalog), never "the configured fleet".
pub(crate) async fn put_bytes_to_all_members(
    set: &crate::sdk::storage_set::StorageSet,
    key: &str,
    payload: &[u8],
) -> Result<crate::sdk::storage_node_sdk::KeyedPutFanout, DsmError> {
    // Exactly one of these blocks survives cfg expansion, and it is the
    // function's tail expression (the shape `BitcoinTapSdk::storage_put_bytes`
    // uses for the same test seam).
    #[cfg(test)]
    {
        Ok(fake_fleet::put(set, key, payload))
    }
    #[cfg(not(test))]
    {
        put_bytes_to_all_members_live(set, key, payload).await
    }
}

/// Immutable-channel sibling of [`put_bytes_to_all_members`]: deliver one
/// Area-4 `(namespace, payload)` tuple to every member of `set` through the
/// write-once immutable endpoint. `expected_addr_b32` is the client's own
/// address derivation; a node that computes a different address refuses.
pub(crate) async fn put_immutable_to_all_members(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &str,
    payload: &[u8],
    expected_addr_b32: &str,
) -> Result<crate::sdk::storage_node_sdk::KeyedPutFanout, DsmError> {
    #[cfg(test)]
    {
        // The fake fleet stores under a key carrying the address, so tests can
        // assert exactly which immutable object reached which member.
        Ok(fake_fleet::put(
            set,
            &format!("immutable::{namespace}::{expected_addr_b32}"),
            payload,
        ))
    }
    #[cfg(not(test))]
    {
        let sdk = member_sdk_with_auth(set).await?;
        Ok(sdk
            .put_immutable_to_all_members(set, namespace, payload, expected_addr_b32)
            .await)
    }
}

/// Submit one frozen settlement-slot claim envelope to every member of `set`,
/// each authenticated with its OWN per-node token (lazily back-filled like
/// [`put_bytes`]). Never decides quorum; never retries — the caller replays the
/// same bytes if it must.
pub(crate) async fn submit_settlement_slot_claim(
    set: &crate::sdk::storage_set::StorageSet,
    envelope: &[u8],
) -> Result<crate::sdk::storage_node_sdk::ClaimFanout, DsmError> {
    // Exactly one of these blocks survives cfg expansion, and it is the
    // function's tail expression.
    #[cfg(test)]
    {
        Ok(fake_fleet::claim(set, envelope))
    }
    #[cfg(not(test))]
    {
        submit_settlement_slot_claim_live(set, envelope).await
    }
}

/// TEST-ONLY in-process member fleet: one object store per MEMBER ID (not per
/// URL), an injectable per-member failure, and an injectable echoed node id —
/// so a test can drive the real per-member replay/quorum logic through
/// partition splits, echo mismatches and foreign sets without HTTP.
#[cfg(test)]
pub(crate) mod fake_fleet {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use crate::sdk::storage_node_sdk::{KeyedPutFanout, MemberPutOutcome};
    use crate::sdk::storage_set::StorageSet;

    #[derive(Default)]
    struct FleetState {
        /// member_id -> (key -> bytes)
        stores: HashMap<String, HashMap<String, Vec<u8>>>,
        /// member_id -> ((vault_id, parent_sequence) -> (envelope, digest)):
        /// the write-once settlement-slot register, per member.
        registers: HashMap<String, HashMap<([u8; 32], u64), (Vec<u8>, [u8; 32])>>,
        /// members whose next PUTs fail (persistent until cleared)
        failing: HashSet<String>,
        /// member_id -> the node id it echoes (default: its own member id)
        echo_override: HashMap<String, Option<String>>,
        /// members that phrase a re-ack as `Refused { held_digest: <ours> }`
        /// instead of `HeldIdentical` — a shape the current node never emits,
        /// which is exactly why the claim path must not take it on trust.
        refuse_phrasing: HashSet<String>,
        /// every (member_id, key, digest-of-bytes) PUT that was attempted, in order
        put_log: Vec<(String, String, [u8; 32])>,
    }

    static STATE: once_cell::sync::Lazy<Mutex<FleetState>> =
        once_cell::sync::Lazy::new(|| Mutex::new(FleetState::default()));

    fn state() -> std::sync::MutexGuard<'static, FleetState> {
        STATE.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn reset() {
        *state() = FleetState::default();
    }

    pub(crate) fn fail_member(member_id: &str) {
        state().failing.insert(member_id.to_string());
    }

    pub(crate) fn heal_member(member_id: &str) {
        state().failing.remove(member_id);
    }

    /// Make `member_id` answer a re-ack as `Refused` carrying our own digest.
    pub(crate) fn set_refuse_phrasing(member_id: &str) {
        state().refuse_phrasing.insert(member_id.to_string());
    }

    /// Make `member_id` echo `echoes` (e.g. another member's id, or `None`).
    pub(crate) fn set_echo(member_id: &str, echoes: Option<&str>) {
        state()
            .echo_override
            .insert(member_id.to_string(), echoes.map(|s| s.to_string()));
    }

    /// The bytes ANY member holds under `key` (a reader fetches from any node).
    pub(crate) fn any_member_holding(key: &str) -> Option<Vec<u8>> {
        state().stores.values().find_map(|m| m.get(key).cloned())
    }

    pub(crate) fn stored(member_id: &str, key: &str) -> Option<Vec<u8>> {
        state()
            .stores
            .get(member_id)
            .and_then(|m| m.get(key))
            .cloned()
    }

    /// Every attempted PUT as (member_id, key, blake3(bytes)).
    pub(crate) fn put_log() -> Vec<(String, String, [u8; 32])> {
        state().put_log.clone()
    }

    /// The digest a member holds for a slot, if any (minority losing rows are
    /// legal and permanent — this is how a test proves they stay).
    pub(crate) fn slot_held_digest(
        member_id: &str,
        vault_id: &[u8; 32],
        parent_sequence: u64,
    ) -> Option<[u8; 32]> {
        state()
            .registers
            .get(member_id)
            .and_then(|r| r.get(&(*vault_id, parent_sequence)))
            .map(|(_, d)| *d)
    }

    /// Write-once conditional acceptance per member, exactly as the storage
    /// node does it: first bytes win, identical re-ack, different refused with
    /// the held digest. Attribution/set checks are the node's; the fake fleet
    /// models the register only.
    pub(crate) fn claim(
        set: &StorageSet,
        envelope: &[u8],
    ) -> crate::sdk::storage_node_sdk::ClaimFanout {
        use crate::sdk::storage_node_sdk::{ClaimFanout, MemberClaimOutcome, MemberClaimResult};
        let verified =
            dsm::dlv::settlement_slot_claim::decode_and_verify_settlement_slot_claim(envelope);
        let mut st = state();
        let mut outcomes = Vec::with_capacity(set.len());
        for m in set.members() {
            let key = format!(
                "slot:{}/{}",
                verified
                    .as_ref()
                    .map(|v| crate::util::text_id::encode_base32_crockford(&v.body.vault_id))
                    .unwrap_or_else(|_| "?".into()),
                verified
                    .as_ref()
                    .map(|v| v.body.parent_sequence)
                    .unwrap_or(0)
            );
            st.put_log
                .push((m.member_id.clone(), key, *blake3::hash(envelope).as_bytes()));
            if st.failing.contains(&m.member_id) {
                outcomes.push(MemberClaimOutcome {
                    member_id: m.member_id.clone(),
                    endpoint: m.endpoint.clone(),
                    result: MemberClaimResult::Unavailable("injected failure".into()),
                    echoed_node_id: None,
                });
                continue;
            }
            let echoed = match st.echo_override.get(&m.member_id) {
                Some(o) => o.clone(),
                None => Some(m.member_id.clone()),
            };
            let Ok(v) = verified.as_ref() else {
                outcomes.push(MemberClaimOutcome {
                    member_id: m.member_id.clone(),
                    endpoint: m.endpoint.clone(),
                    result: MemberClaimResult::Unavailable("malformed".into()),
                    echoed_node_id: echoed,
                });
                continue;
            };
            let slot = (v.body.vault_id, v.body.parent_sequence);
            let st_refuse_phrasing = st.refuse_phrasing.contains(&m.member_id);
            let reg = st.registers.entry(m.member_id.clone()).or_default();
            // Read the held digest OUT before deciding, so the write-once insert
            // does not overlap the read borrow.
            let held: Option<[u8; 32]> = reg.get(&slot).map(|(_, d)| *d);
            let result = match held {
                None => {
                    reg.insert(slot, (envelope.to_vec(), v.envelope_digest));
                    MemberClaimResult::Accepted
                }
                Some(d) if d == v.envelope_digest => {
                    if st_refuse_phrasing {
                        MemberClaimResult::Refused {
                            held_digest: Some(d.to_vec()),
                        }
                    } else {
                        MemberClaimResult::HeldIdentical
                    }
                }
                Some(d) => MemberClaimResult::Refused {
                    held_digest: Some(d.to_vec()),
                },
            };
            outcomes.push(MemberClaimOutcome {
                member_id: m.member_id.clone(),
                endpoint: m.endpoint.clone(),
                result,
                echoed_node_id: echoed,
            });
        }
        ClaimFanout {
            outcomes,
            total: set.len() as u32,
        }
    }

    pub(crate) fn put(set: &StorageSet, key: &str, payload: &[u8]) -> KeyedPutFanout {
        let mut st = state();
        let mut outcomes = Vec::with_capacity(set.len());
        let mut accepted = 0u32;
        for m in set.members() {
            st.put_log.push((
                m.member_id.clone(),
                key.to_string(),
                *blake3::hash(payload).as_bytes(),
            ));
            if st.failing.contains(&m.member_id) {
                outcomes.push(MemberPutOutcome {
                    member_id: m.member_id.clone(),
                    endpoint: m.endpoint.clone(),
                    accepted: false,
                    echoed_node_id: None,
                    error: Some("injected failure".into()),
                });
                continue;
            }
            st.stores
                .entry(m.member_id.clone())
                .or_default()
                .insert(key.to_string(), payload.to_vec());
            let echoed = match st.echo_override.get(&m.member_id) {
                Some(o) => o.clone(),
                None => Some(m.member_id.clone()),
            };
            let counted = echoed.as_deref() == Some(m.member_id.as_str());
            if counted {
                accepted += 1;
            }
            outcomes.push(MemberPutOutcome {
                member_id: m.member_id.clone(),
                endpoint: m.endpoint.clone(),
                accepted: counted,
                echoed_node_id: echoed,
                error: if counted {
                    None
                } else {
                    Some("echoed node id does not match member".into())
                },
            });
        }
        KeyedPutFanout {
            outcomes,
            accepted,
            total: set.len() as u32,
        }
    }
}

#[cfg(not(test))]
async fn submit_settlement_slot_claim_live(
    set: &crate::sdk::storage_set::StorageSet,
    envelope: &[u8],
) -> Result<crate::sdk::storage_node_sdk::ClaimFanout, DsmError> {
    let sdk = member_sdk_with_auth(set).await?;
    Ok(sdk.submit_settlement_slot_claim(set, envelope).await)
}

/// A `StorageNodeSDK` whose clients are exactly `set`'s member endpoints, each
/// carrying its own per-node auth token (lazily back-filled by an idempotent
/// registration pass).
#[cfg(not(test))]
async fn member_sdk_with_auth(
    set: &crate::sdk::storage_set::StorageSet,
) -> Result<StorageNodeSDK, DsmError> {
    let config = StorageNodeConfig::from_env_config().await.map_err(|e| {
        DsmError::storage(
            format!("load storage node config: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let mut member_config = config.clone();
    member_config.node_urls = set.members().iter().map(|m| m.endpoint.clone()).collect();
    let sdk = StorageNodeSDK::new(member_config.clone())
        .await
        .map_err(|e| {
            DsmError::storage(
                format!("construct storage node sdk: {e}"),
                None::<std::io::Error>,
            )
        })?;
    let mut auths = std::collections::HashMap::new();
    for url in &member_config.node_urls {
        if let Some(auth) = resolve_storage_auth(url) {
            auths.insert(url.clone(), auth);
        }
    }
    if auths.len() < member_config.node_urls.len() {
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
                    "storage_io: back-fill register_device_for_auth failed: {e} (continuing — \
                     some members may refuse auth)"
                );
            }
            auths.clear();
            for url in &member_config.node_urls {
                if let Some(auth) = resolve_storage_auth(url) {
                    auths.insert(url.clone(), auth);
                }
            }
        }
    }
    Ok(sdk.with_per_node_auth(&auths))
}

#[cfg(not(test))]
async fn put_bytes_to_all_members_live(
    set: &crate::sdk::storage_set::StorageSet,
    key: &str,
    payload: &[u8],
) -> Result<crate::sdk::storage_node_sdk::KeyedPutFanout, DsmError> {
    let sdk = member_sdk_with_auth(set).await?;
    Ok(sdk.put_bytes_to_all_members(set, key, payload).await)
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
