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
    {
        let sdk = member_sdk_with_auth(set).await?;
        Ok(sdk
            .put_immutable_to_all_members(set, namespace, payload, expected_addr_b32)
            .await)
    }
}

/// Fetch one Area-4 immutable `(namespace, payload)` object by its inner
/// digest, from whichever mirror holds it. The CLIENT-side re-hash against
/// the requested identity is performed HERE, in both cfg branches — it is
/// the Req 15.3 boundary, so no caller inherits it silently and no test seam
/// can weaken it.
pub(crate) async fn fetch_immutable_payload(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    inner: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    {
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
        let Some(payload) = sdk.fetch_immutable_verified(namespace, inner).await? else {
            return Ok(None);
        };
        // fetch_immutable_verified already re-hashed against the requested
        // address; re-state the inner-digest equality here so this function's
        // contract does not depend on a callee keeping it.
        if dsm::storage_object::immutable_inner(namespace, &payload) != *inner {
            return Err(DsmError::verification(
                "immutable fetch: bytes do not hash to the requested identity",
            ));
        }
        Ok(Some(payload))
    }
}

/// Outcome of a leader-first cell write (Part II §8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CellWrite {
    /// The leader holds the bytes.
    pub leader_reached: bool,
    /// Other members that hold the bytes.
    pub copies: u32,
}

/// The member that leads a cell, as an index into `set.members()`: the
/// first position of the Fisher-Yates shuffle of the committed set under
/// `seed` (Part II §7). Computed here and by Core; never by a node.
pub(crate) fn leader_index(
    set: &crate::sdk::storage_set::StorageSet,
    seed: &[u8; 32],
) -> Result<usize, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    let leader = dsm::economic::register::position_leader(seed, &members)
        .map_err(|e| DsmError::storage(format!("leader shuffle: {e:?}"), None::<std::io::Error>))?;
    set.members()
        .iter()
        .position(|m| m.member_id.as_bytes() == leader.as_slice())
        .ok_or_else(|| {
            DsmError::storage(
                "the shuffled leader is not a member of the set".to_string(),
                None::<std::io::Error>,
            )
        })
}

/// Part II §7.2, the vault seed: the member that leads every successor cell of
/// `vault_id` at `parent_root`, as an index into `set.members()`. `set` is the
/// committed set the vault state names (`storage_set_id`, resolved through the
/// catalog) — never the members this device can reach. Computed here and by
/// Core (`dsm::sofi::leader::successor_cell_leader`); never by a node.
pub fn successor_cell_leader_index(
    set: &crate::sdk::storage_set::StorageSet,
    vault_id: &[u8; 32],
    parent_root: &[u8; 32],
) -> Result<usize, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    let leader = dsm::sofi::leader::successor_cell_leader(vault_id, parent_root, &members)
        .map_err(|e| DsmError::storage(format!("leader shuffle: {e:?}"), None::<std::io::Error>))?;
    set.members()
        .iter()
        .position(|m| m.member_id.as_bytes() == leader.as_slice())
        .ok_or_else(|| {
            DsmError::storage(
                "the shuffled leader is not a member of the set".to_string(),
                None::<std::io::Error>,
            )
        })
}

/// Part II §8: write `value` at `key` under `namespace`, the leader of `seed`
/// first and the other members after. Nothing is checked or compared on the
/// way; the winner at the key is whatever object reached the leader first,
/// and Core reads that.
pub(crate) async fn write_cell_leader_first(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &[u8],
    key: &[u8; 32],
    seed: &[u8; 32],
    value: &[u8],
) -> Result<CellWrite, DsmError> {
    let leader = leader_index(set, seed)?;
    {
        let sdk = member_sdk_with_auth(set).await?;
        let key_b32 = crate::util::text_id::encode_base32_crockford(key);
        let fanout = sdk
            .put_cell_leader_first(set, leader, namespace, &key_b32, value)
            .await;
        for (member, error) in &fanout.errors {
            log::warn!("cell write: member {member} did not take the bytes: {error}");
        }
        Ok(CellWrite {
            leader_reached: fanout.leader_reached,
            copies: fanout.copies,
        })
    }
}

/// Part II §17.4: write several keys as ONE local transaction per member,
/// the leader of `seed` first and the other members after. Every member
/// takes all the entries or none of them; nothing is checked or compared.
pub(crate) async fn write_cells_leader_first(
    set: &crate::sdk::storage_set::StorageSet,
    seed: &[u8; 32],
    entries: &[(Vec<u8>, [u8; 32], Vec<u8>)],
) -> Result<CellWrite, DsmError> {
    let leader = leader_index(set, seed)?;
    {
        let sdk = member_sdk_with_auth(set).await?;
        let fanout = sdk.put_cells_leader_first(set, leader, entries).await;
        for (member, error) in &fanout.errors {
            log::warn!("cells write: member {member} did not take the batch: {error}");
        }
        Ok(CellWrite {
            leader_reached: fanout.leader_reached,
            copies: fanout.copies,
        })
    }
}

/// Part II §8 step 5: carry `value` at `key` under `namespace` to one member
/// of `set`, by index. Any party may carry the bytes to a member not reached
/// at write time; a member keeps what it is given, and answers with the
/// entry's arrival record, which is that seat's route link (storage spec §9).
pub(crate) async fn put_cell_to_member(
    set: &crate::sdk::storage_set::StorageSet,
    member: usize,
    namespace: &[u8],
    key: &[u8; 32],
    value: &[u8],
) -> Result<dsm::storage_cell::ArrivalRecord, DsmError> {
    {
        let sdk = member_sdk_with_auth(set).await?;
        let key_b32 = crate::util::text_id::encode_base32_crockford(key);
        sdk.put_cell_to_member(set, member, namespace, &key_b32, value)
            .await
            .map_err(|e| DsmError::storage(e, None::<std::io::Error>))
    }
}

/// Part II §13, the raw reads: everything each member holds at the key, in
/// set order, `None` where a member could not answer. Core derives
/// `LeaderHeld` and `Final` from these; nothing is counted here.
pub(crate) async fn read_cell_raw(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &[u8],
    key: &[u8; 32],
) -> Result<Vec<Option<Vec<Vec<u8>>>>, DsmError> {
    {
        let sdk = member_sdk_with_auth(set).await?;
        let key_b32 = crate::util::text_id::encode_base32_crockford(key);
        Ok(sdk.get_cell_all(set, namespace, &key_b32).await)
    }
}

/// Part II §10 `Stored(o)`: the exact bytes of the object at
/// `immutable_addr(namespace, inner)` once three members of `set` return
/// bytes that re-hash to that address; `Unavailable` otherwise. The fact is
/// derived by Core (`dsm::sofi::storage::stored`) from the raw member
/// answers; nothing here trusts a member.
pub async fn read_stored_object(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    inner: &[u8; 32],
) -> Result<dsm::sofi::storage::StoredFact, DsmError> {
    let addr = dsm::storage_object::immutable_addr_from_inner(namespace, inner);
    let reads = read_object_raw(set, &addr).await?;
    Ok(dsm::sofi::storage::stored(&addr, &reads))
}

/// Part II §12, append to index: put `addr` under `locator` at every member
/// of `set`. Returns how many members took it.
pub async fn append_to_index(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    addr: &[u8; 32],
) -> Result<u32, DsmError> {
    {
        let sdk = member_sdk_with_auth(set).await?;
        let locator_b32 = crate::util::text_id::encode_base32_crockford(locator);
        Ok(sdk
            .append_index_all(set, namespace, &locator_b32, addr)
            .await)
    }
}

/// Part II §11: the candidates under `locator` — each member's appends in
/// append order, members in set order, duplicates dropped — or `Unavailable`
/// when no member answered. Reading stops at `budget` addresses per member;
/// Core's scan applies the budget again over the merged order.
pub async fn read_index_candidates(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
) -> Result<dsm::sofi::storage::IndexCandidates, DsmError> {
    let reads = read_index_raw(set, namespace, locator, budget).await?;
    Ok(dsm::sofi::storage::merge_index_reads(&reads))
}

/// Part II §11, the whole read: the one object under `locator` whose bytes
/// are `Stored` and whose identity, recomputed by Core from the bytes with
/// `recognize`, is `locator`. Every other candidate is nothing; a scan that
/// would examine more than `budget` candidates is `Unavailable`, never
/// `Invalid`. Objects are fetched under `object_namespace`.
pub async fn resolve_locator<T>(
    set: &crate::sdk::storage_set::StorageSet,
    index_namespace: &[u8],
    object_namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<dsm::sofi::storage::Resolved<T>, DsmError> {
    use dsm::sofi::storage::{IndexCandidates, Resolved, StoredFact};
    let candidates = match read_index_candidates(set, index_namespace, locator, budget).await? {
        IndexCandidates::Unavailable => return Ok(Resolved::Unavailable),
        IndexCandidates::Candidates(c) => c,
    };
    // Fetch only what the scan may examine: the budget bounds the work a
    // flood of appends can cost, and nothing beyond it is read.
    let mut fetched: Vec<Option<Vec<u8>>> = Vec::with_capacity(candidates.len().min(budget + 1));
    for addr in candidates.iter().take(budget + 1) {
        let reads = read_object_raw(set, addr).await?;
        fetched.push(match dsm::sofi::storage::stored(addr, &reads) {
            StoredFact::Stored(bytes) => Some(bytes),
            StoredFact::Unavailable => None,
        });
    }
    // The object namespace binds the class: a candidate stored under another
    // namespace has another address and is never fetched here at all.
    let _ = object_namespace;
    Ok(dsm::sofi::storage::keep_verifying(
        locator, &fetched, budget, recognize,
    ))
}

/// Part II §11, discovery under an index of references: EVERY candidate
/// under `locator` whose `Stored` bytes recognize to `locator`, in append
/// order (`dsm::sofi::storage::keep_all_verifying`). It establishes what is
/// published under the locator and decides nothing about which applies.
pub async fn resolve_locator_all<T>(
    set: &crate::sdk::storage_set::StorageSet,
    index_namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<dsm::sofi::storage::Resolved<Vec<T>>, DsmError> {
    use dsm::sofi::storage::{IndexCandidates, Resolved, StoredFact};
    let candidates = match read_index_candidates(set, index_namespace, locator, budget).await? {
        IndexCandidates::Unavailable => return Ok(Resolved::Unavailable),
        IndexCandidates::Candidates(c) => c,
    };
    let mut fetched: Vec<Option<Vec<u8>>> = Vec::with_capacity(candidates.len().min(budget + 1));
    for addr in candidates.iter().take(budget + 1) {
        let reads = read_object_raw(set, addr).await?;
        fetched.push(match dsm::sofi::storage::stored(addr, &reads) {
            StoredFact::Stored(bytes) => Some(bytes),
            StoredFact::Unavailable => None,
        });
    }
    Ok(dsm::sofi::storage::keep_all_verifying(
        locator, &fetched, budget, recognize,
    ))
}

/// Part II §10 by address: the exact bytes at `addr` once three members
/// return bytes that re-hash to it, `None` otherwise. For an acquisition
/// that holds the address (a vault state commits its policies by address)
/// and not the inner identity.
pub(crate) async fn read_stored_bytes(
    set: &crate::sdk::storage_set::StorageSet,
    addr: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    let reads = read_object_raw(set, addr).await?;
    Ok(match dsm::sofi::storage::stored(addr, &reads) {
        dsm::sofi::storage::StoredFact::Stored(bytes) => Some(bytes),
        dsm::sofi::storage::StoredFact::Unavailable => None,
    })
}

/// The raw object reads at `addr`, one per member of `set` in set order.
async fn read_object_raw(
    set: &crate::sdk::storage_set::StorageSet,
    addr: &[u8; 32],
) -> Result<Vec<dsm::sofi::storage::ObjectRead>, DsmError> {
    {
        let sdk = member_sdk_with_auth(set).await?;
        let addr_b32 = crate::util::text_id::encode_base32_crockford(addr);
        Ok(sdk.get_immutable_all(set, &addr_b32).await)
    }
}

/// The raw index reads under `locator`, one per member of `set` in set order.
async fn read_index_raw(
    set: &crate::sdk::storage_set::StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
) -> Result<Vec<Option<Vec<[u8; 32]>>>, DsmError> {
    {
        let sdk = member_sdk_with_auth(set).await?;
        let locator_b32 = crate::util::text_id::encode_base32_crockford(locator);
        Ok(sdk
            .read_index_all(set, namespace, &locator_b32, budget)
            .await)
    }
}

/// TEST-ONLY in-process keyed cells (Part II §12): everything each member
/// was given at a `(namespace, key)`, in arrival order, with an injectable
/// per-member outage. Nothing is refused, replaced or compared — a member
/// holds bytes and decides nothing — so the leader-first facts a test
/// observes are exactly what Core derives from a live fleet's raw reads.
// Widened from `cfg(test)` to include `test-utils`: the LEGITIMATE funding
// path must be reachable from integration tests in `tests/*.rs`, which are
// external consumers a `cfg(test)` gate is invisible to. That invisibility is
// exactly why those tests fabricated balances instead of claiming them.
// `test-utils` is non-default and reaches the build only through
// dev-dependencies, so this still ships in nothing.

/// TEST-ONLY in-process member fleet: one object store per MEMBER ID (not per
/// URL), an injectable per-member failure, and an injectable echoed node id —
/// so a test can drive the real per-member replay/quorum logic through
/// partition splits, echo mismatches and foreign sets without HTTP.

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

/// Fetch an object's bytes by key, with `Ok(None)` for NOT-FOUND kept typed
/// rather than erased into an error string. See `StorageNodeSDK::get_opt`.
pub(crate) async fn get_bytes_opt(key: &str) -> Result<Option<Vec<u8>>, DsmError> {
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
    sdk.get_opt(key).await
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

/// Every key under `prefix` as ONE storage member lists it
/// ([`StorageNodeSDK::list_all_keys_pinned`]): pages from one member only, a
/// failed walk discarded whole, the walk stopped once past `max_keys`.
pub(crate) async fn list_all_keys_pinned(
    prefix: &str,
    page_limit: u32,
    max_keys: usize,
) -> Result<crate::sdk::storage_node_sdk::PinnedKeyListing, DsmError> {
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
    sdk.list_all_keys_pinned(prefix, page_limit, max_keys).await
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

/// R1 correspondence tests at the network layer: the SDK adapter over the
/// fake fleet establishes exactly the facts `dsm::sofi::storage` derives.
/// R3 correspondence: the leader of a cell is a function of the seed and the
/// committed set alone. Availability never enters (Part II §7).