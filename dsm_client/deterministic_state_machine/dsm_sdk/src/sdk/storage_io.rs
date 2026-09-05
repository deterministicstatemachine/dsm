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
    // The fake/real I/O selectors include `test-utils`, not just `test`.
    // Integration tests in `tests/*.rs` compile the library WITHOUT `cfg(test)`,
    // so under a `cfg(test)`-only selector they took the REAL HTTP branch and
    // talked to a port nothing listens on. That is why the legitimate funding
    // path was unreachable from them, and why they fabricated balances instead.
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_fleet::put(set, key, payload))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
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
    #[cfg(any(test, feature = "test-utils"))]
    {
        // The fake fleet stores under a key carrying the address, so tests can
        // assert exactly which immutable object reached which member.
        Ok(fake_fleet::put(
            set,
            &format!("immutable::{namespace}::{expected_addr_b32}"),
            payload,
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
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
    #[cfg(any(test, feature = "test-utils"))]
    {
        // The frozen-artifact sweep delivers immutable tuples to the fake
        // fleet under `immutable::{namespace}::{addr_b32}` — read them back
        // from whichever member holds the key, exactly as a live fetch takes
        // the first mirror that answers.
        let addr = dsm::storage_object::immutable_addr_from_inner(namespace, inner);
        let key = format!(
            "immutable::{}::{}",
            String::from_utf8_lossy(namespace.source_bytes()),
            crate::util::text_id::encode_base32_crockford(&addr)
        );
        let Some(payload) = fake_fleet::any_member_holding(&key) else {
            return Ok(None);
        };
        if dsm::storage_object::immutable_inner(namespace, &payload) != *inner {
            return Err(DsmError::verification(
                "immutable fetch: bytes do not hash to the requested identity",
            ));
        }
        Ok(Some(payload))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
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

/// Submit one frozen settlement-slot claim envelope to every member of `set`,
/// each authenticated with its OWN per-node token (lazily back-filled like
/// [`put_bytes`]). Never decides quorum; never retries — the caller replays the
/// same bytes if it must.
/// Economic-register seams. Same cfg discipline as the settlement claim:
/// tests drive the fake fleet; production fans out over the set's members
/// with per-member auth.
///
/// `network_id` is the network the members of `set` serve. A live member
/// knows its own network and gates the canonical faucet identity on it; the
/// in-process double must be told, so that it refuses a claim for another
/// network's faucet exactly as a live member would.
pub(crate) async fn submit_faucet_ticket_claim(
    set: &crate::sdk::storage_set::StorageSet,
    network_id: &[u8],
    envelope: &[u8],
) -> Result<crate::sdk::storage_node_sdk::ClaimFanout, DsmError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_registers::claim(
            set,
            fake_registers::RegisterKind::FaucetTicket,
            envelope,
            fake_registers::process_caller().as_ref(),
            Some(network_id),
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let _ = network_id;
        let sdk = member_sdk_with_auth(set).await?;
        Ok(sdk
            .submit_one_shot_claim(
                set,
                "/api/v2/faucet-ticket/claim",
                "x-dsm-faucet-ticket",
                envelope,
            )
            .await)
    }
}

pub(crate) async fn submit_economic_root_claim(
    set: &crate::sdk::storage_set::StorageSet,
    envelope: &[u8],
) -> Result<crate::sdk::storage_node_sdk::ClaimFanout, DsmError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_registers::claim(
            set,
            fake_registers::RegisterKind::EconomicRoot,
            envelope,
            fake_registers::process_caller().as_ref(),
            None,
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let sdk = member_sdk_with_auth(set).await?;
        Ok(sdk
            .submit_one_shot_claim(
                set,
                "/api/v2/economic-root/claim",
                "x-dsm-economic-root",
                envelope,
            )
            .await)
    }
}

pub(crate) async fn read_faucet_ticket_cell(
    set: &crate::sdk::storage_set::StorageSet,
    faucet_id: &[u8; 32],
    ticket_index: u64,
) -> Result<Vec<dsm::economic::cell_observation::MemberCellRead>, DsmError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_registers::read(
            set,
            fake_registers::RegisterKind::FaucetTicket,
            &fake_registers::ticket_key(faucet_id, ticket_index),
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let sdk = member_sdk_with_auth(set).await?;
        let path = crate::sdk::economic_registers::faucet_ticket_path(faucet_id, ticket_index);
        Ok(sdk.read_register_cell(set, &path).await)
    }
}

pub(crate) async fn read_economic_root_cell_rows(
    set: &crate::sdk::storage_set::StorageSet,
    k_root: &[u8; 32],
) -> Result<Vec<dsm::economic::cell_observation::MemberCellRead>, DsmError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_registers::read(
            set,
            fake_registers::RegisterKind::EconomicRoot,
            &fake_registers::root_key(k_root),
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let sdk = member_sdk_with_auth(set).await?;
        let path = crate::sdk::economic_registers::economic_root_path(k_root);
        Ok(sdk.read_register_cell(set, &path).await)
    }
}

/// TEST-ONLY in-process economic registers: one write-once cell map per
/// member per register kind, with the same injectable echo/failure seams the
/// settlement fake fleet has. Envelope digests use the REAL protocol digests,
/// so the counting logic under test sees production shapes.
///
/// The in-process double for the storage node's write-once ECONOMIC
/// registers (faucet tickets, economic roots).
///
/// Protocol-faithful by construction, not by resemblance: every check a
/// live member performs before touching its cell is the SAME shared
/// function the node's handler calls (`decode_and_verify_*`,
/// `verify_claim_attribution`, `verify_faucet_claim_attribution`,
/// `MAX_CLAIM_BYTES`), applied in the node's order, and every refusal is
/// expressed as the node's `(status, outcome)` pair and handed to the ONE
/// client-side classifier the live path uses. The double therefore never
/// constructs a client result of its own; it reproduces what a member
/// would have answered. Its equivalence with the real endpoint is proven
/// by `dsm_storage_node/tests/economic_register_conformance.rs`, which
/// drives identical vectors through both.
///
/// What it does NOT model, stated rather than hidden: the transport-layer
/// refusals a real member's `device_auth` can emit for a caller it does
/// know (revoked, bad token, replayed message id, oversize body), and the
/// per-member independence of a real fleet under concurrent claims — the
/// double serialises a whole fan-out, so every member agrees on one
/// winner, where real members decide independently and can split.
// Widened from `cfg(test)` to include `test-utils`: the LEGITIMATE funding
// path must be reachable from integration tests in `tests/*.rs`, which are
// external consumers a `cfg(test)` gate is invisible to. That invisibility is
// exactly why those tests fabricated balances instead of claiming them.
// `test-utils` is non-default and reaches the build only through
// dev-dependencies, so this still ships in nothing.
#[cfg(any(test, feature = "test-utils"))]
pub mod fake_registers {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use dsm::economic::register::AuthenticatedCaller;

    use crate::sdk::storage_node_sdk::{
        classify_one_shot_response, ClaimFanout, MemberClaimOutcome, MemberClaimResult,
    };
    use crate::sdk::storage_set::StorageSet;

    /// Which write-once register a claim targets. A type rather than a name:
    /// a member routes on the endpoint it was asked, never on a string that
    /// could fall through to a default.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum RegisterKind {
        FaucetTicket,
        EconomicRoot,
    }

    #[derive(Default)]
    struct State {
        /// (member_id, register) -> (cell key -> (bytes, digest))
        cells: HashMap<(String, RegisterKind), HashMap<Vec<u8>, (Vec<u8>, [u8; 32])>>,
        failing: HashSet<String>,
        echo_override: HashMap<String, Option<String>>,
        /// What a member echoes as its REGISTER INCARNATION, when it is not
        /// the one the set committed. `None` models a member that answers
        /// without saying which register it is serving.
        incarnation_override: HashMap<String, Option<[u8; 32]>>,
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
        let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
        f(guard.get_or_insert_with(State::default))
    }

    pub fn reset() {
        let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(State::default());
    }

    /// Take a member down (or bring it back). A down member answers nothing:
    /// its claim outcome is an unattributed `Unavailable`, and its read row is
    /// an unattributed empty — exactly the shape the live client produces for
    /// a transport failure, and never the attributed empty of a member that is
    /// up and holds nothing.
    pub fn fail_member(member_id: &str, failing: bool) {
        with_state(|s| {
            if failing {
                s.failing.insert(member_id.to_string());
            } else {
                s.failing.remove(member_id);
            }
        })
    }

    pub fn set_echo(member_id: &str, echo: Option<String>) {
        with_state(|s| {
            s.echo_override.insert(member_id.to_string(), echo);
        })
    }

    /// Model a member that is no longer serving the register the set
    /// committed — a lost-and-rebuilt database, or a restore from a snapshot.
    ///
    /// The member keeps its id and answers perfectly honestly; what changed is
    /// which durable register history is answering. `None` models a member
    /// that will not say which register it is serving at all.
    pub fn set_register_incarnation(member_id: &str, incarnation: Option<[u8; 32]>) {
        with_state(|s| {
            s.incarnation_override
                .insert(member_id.to_string(), incarnation);
        })
    }

    pub fn ticket_key(faucet_id: &[u8; 32], ticket_index: u64) -> Vec<u8> {
        let mut k = faucet_id.to_vec();
        k.extend_from_slice(&ticket_index.to_be_bytes());
        k
    }

    pub fn root_key(k_root: &[u8; 32]) -> Vec<u8> {
        k_root.to_vec()
    }

    /// The identity a live member would have authenticated for THIS process:
    /// the device id and signing key the process registered with its storage
    /// nodes — the same `AppState` fields `resolve_storage_auth` reads. `None`
    /// when no identity is installed, which a member answers as an
    /// unauthenticated request.
    pub fn process_caller() -> Option<AuthenticatedCaller> {
        let device_id = crate::sdk::app_state::AppState::get_device_id()?;
        let public_key = crate::sdk::app_state::AppState::get_public_key()?;
        let device_id: [u8; 32] = device_id.as_slice().try_into().ok()?;
        Some(AuthenticatedCaller {
            public_key,
            device_id,
        })
    }

    fn digest_for(kind: RegisterKind, envelope: &[u8]) -> [u8; 32] {
        match kind {
            RegisterKind::FaucetTicket => {
                dsm::economic::faucet::faucet_claim_evidence_addr(envelope)
            }
            RegisterKind::EconomicRoot => {
                dsm::economic::claim_envelope::economic_root_claim_envelope_digest(envelope)
            }
        }
    }

    /// Everything a member decides BEFORE it touches its cell, in the node's
    /// order, as the node's answer: `Ok(cell key)` or the `(status, outcome)`
    /// pair the node's handler (or its `device_auth` layer) would return.
    fn precheck(
        kind: RegisterKind,
        envelope: &[u8],
        caller: Option<&AuthenticatedCaller>,
        configured_set_id: &[u8; 32],
        network_id: Option<&[u8]>,
    ) -> Result<Vec<u8>, (u16, &'static str)> {
        // device_auth: no authenticated device -> 401, no outcome header.
        let Some(caller) = caller else {
            return Err((401, ""));
        };
        if envelope.is_empty() || envelope.len() > dsm::economic::register::MAX_CLAIM_BYTES {
            return Err((400, "malformed"));
        }
        match kind {
            RegisterKind::FaucetTicket => {
                use dsm::economic::faucet::{
                    decode_and_verify_faucet_ticket_claim, verify_faucet_claim_attribution,
                    FaucetAttributionError, FaucetClaimError,
                };
                let verified = match decode_and_verify_faucet_ticket_claim(envelope) {
                    Ok(v) => v,
                    Err(FaucetClaimError::SignatureInvalid) => {
                        return Err((403, "signature-invalid"))
                    }
                    Err(_) => return Err((400, "malformed")),
                };
                match verify_faucet_claim_attribution(
                    &verified,
                    caller,
                    Some(configured_set_id),
                    network_id,
                ) {
                    Ok(()) => {}
                    Err(FaucetAttributionError::ClaimantIsNotCaller) => {
                        return Err((403, "claimant-not-caller"))
                    }
                    Err(FaucetAttributionError::DeviceIsNotCaller) => {
                        return Err((403, "device-not-caller"))
                    }
                    Err(FaucetAttributionError::StorageSetUnconfigured) => {
                        return Err((503, "no-storage-set"))
                    }
                    Err(FaucetAttributionError::WrongStorageSet { .. }) => {
                        return Err((422, "foreign-set"))
                    }
                    Err(FaucetAttributionError::NetworkUnconfigured) => {
                        return Err((503, "no-network"))
                    }
                    Err(FaucetAttributionError::NoncanonicalFaucet) => {
                        return Err((422, "noncanonical-faucet"))
                    }
                    Err(FaucetAttributionError::TicketOutOfRange) => {
                        return Err((422, "ticket-out-of-range"))
                    }
                }
                Ok(ticket_key(
                    &verified.body.faucet_id,
                    verified.body.ticket_index,
                ))
            }
            RegisterKind::EconomicRoot => {
                use dsm::economic::claim_envelope::{
                    decode_and_verify_economic_root_claim, verify_claim_attribution,
                    ClaimEnvelopeError,
                };
                use dsm::economic::register::AttributionError;
                let verified = match decode_and_verify_economic_root_claim(envelope) {
                    Ok(v) => v,
                    Err(ClaimEnvelopeError::SignatureInvalid) => {
                        return Err((403, "signature-invalid"))
                    }
                    Err(_) => return Err((400, "malformed")),
                };
                match verify_claim_attribution(&verified, caller, configured_set_id) {
                    Ok(()) => {}
                    Err(AttributionError::ClaimantIsNotCaller) => {
                        return Err((403, "claimant-not-caller"))
                    }
                    Err(AttributionError::DeviceIsNotCaller) => {
                        return Err((403, "device-not-caller"))
                    }
                    Err(AttributionError::WrongStorageSet { .. }) => {
                        return Err((422, "foreign-set"))
                    }
                }
                Ok(dsm::economic::register::economic_root_register_key(
                    &verified.body.trader_genesis,
                    &verified.body.trader_devid,
                    verified.body.economic_position,
                )
                .to_vec())
            }
        }
    }

    /// Submit `envelope` to every member of `set` as `caller`, on members
    /// configured for `set` and (faucet register only) for `network_id`.
    /// First-write-wins per member, exactly like the node; every refusal is
    /// the node's own `(status, outcome)` through the shared classifier.
    pub fn claim(
        set: &StorageSet,
        kind: RegisterKind,
        envelope: &[u8],
        caller: Option<&AuthenticatedCaller>,
        network_id: Option<&[u8]>,
    ) -> ClaimFanout {
        let configured_set_id = set.id();
        let decision = precheck(kind, envelope, caller, &configured_set_id, network_id);
        let digest = digest_for(kind, envelope);
        let mut outcomes = Vec::new();
        with_state(|s| {
            for member in set.members() {
                let echoed = s
                    .echo_override
                    .get(&member.member_id)
                    .cloned()
                    .unwrap_or_else(|| Some(member.member_id.clone()));
                if s.failing.contains(&member.member_id) {
                    outcomes.push(MemberClaimOutcome {
                        member_id: member.member_id.clone(),
                        endpoint: member.endpoint.clone(),
                        result: MemberClaimResult::Unavailable("injected".into()),
                        echoed_node_id: None,
                    });
                    continue;
                }
                let result = match &decision {
                    Err((status, outcome)) => classify_one_shot_response(*status, outcome, None),
                    Ok(key) => {
                        let cells = s.cells.entry((member.member_id.clone(), kind)).or_default();
                        match cells.get(key) {
                            None => {
                                cells.insert(key.clone(), (envelope.to_vec(), digest));
                                classify_one_shot_response(200, "accepted", None)
                            }
                            Some((_, held)) if *held == digest => {
                                classify_one_shot_response(200, "held-identical", None)
                            }
                            Some((_, held)) => classify_one_shot_response(
                                409,
                                "refused",
                                Some(&crate::util::text_id::encode_base32_crockford(held)),
                            ),
                        }
                    }
                };
                outcomes.push(MemberClaimOutcome {
                    member_id: member.member_id.clone(),
                    endpoint: member.endpoint.clone(),
                    result,
                    echoed_node_id: echoed,
                });
            }
        });
        ClaimFanout {
            outcomes,
            total: set.len() as u32,
        }
    }

    /// Member-attributed read of one cell: `(member_id, echoed node id,
    /// winner bytes)` per member. A down member yields `(id, None, None)` —
    /// the live client's row for a transport failure — so silence can never
    /// count as an attributed empty.
    pub fn read(
        set: &StorageSet,
        kind: RegisterKind,
        key: &[u8],
    ) -> Vec<dsm::economic::cell_observation::MemberCellRead> {
        use dsm::economic::cell_observation::MemberCellRead;
        with_state(|s| {
            set.members()
                .iter()
                .map(|member| {
                    // A FAILING MEMBER DOES NOT ANSWER. It does not answer
                    // "empty": modelling an outage as an absence would let a
                    // fixture manufacture the one observation a forward walk
                    // treats as terminal.
                    if s.failing.contains(&member.member_id) {
                        return MemberCellRead::Unavailable;
                    }
                    let echoed = s
                        .echo_override
                        .get(&member.member_id)
                        .cloned()
                        .unwrap_or_else(|| Some(member.member_id.clone()));
                    // BOTH halves of the echo, exactly as the live client
                    // folds them (`storage_node_sdk::answer_counts_for`): a
                    // member that rebuilt its register still answers with its
                    // own id, so identity alone cannot tell it apart from the
                    // member the vault committed.
                    let echoed_incarnation = s
                        .incarnation_override
                        .get(&member.member_id)
                        .copied()
                        .unwrap_or(Some(member.register_incarnation_id));
                    if echoed.as_deref() != Some(member.member_id.as_str())
                        || echoed_incarnation != Some(member.register_incarnation_id)
                    {
                        return MemberCellRead::Unavailable;
                    }
                    match s
                        .cells
                        .get(&(member.member_id.clone(), kind))
                        .and_then(|cells| cells.get(key))
                    {
                        Some((b, _)) => MemberCellRead::Value(b.clone()),
                        None => MemberCellRead::Absent,
                    }
                })
                .collect()
        })
    }
}

/// Member-attributed read of one settlement-slot cell — rows of
/// `(member_id, echoed_node_id, winner_bytes)` for the quorum counter.
pub(crate) async fn read_settlement_slot_cell(
    set: &crate::sdk::storage_set::StorageSet,
    vault_id: &[u8; 32],
    parent_sequence: u64,
) -> Result<Vec<dsm::economic::cell_observation::MemberCellRead>, DsmError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_fleet::read_slot(set, vault_id, parent_sequence))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let sdk = member_sdk_with_auth(set).await?;
        let path = crate::sdk::economic_registers::settlement_slot_path(vault_id, parent_sequence);
        Ok(sdk.read_register_cell(set, &path).await)
    }
}

pub(crate) async fn submit_settlement_slot_claim(
    set: &crate::sdk::storage_set::StorageSet,
    envelope: &[u8],
) -> Result<crate::sdk::storage_node_sdk::ClaimFanout, DsmError> {
    // Exactly one of these blocks survives cfg expansion, and it is the
    // function's tail expression.
    #[cfg(any(test, feature = "test-utils"))]
    {
        Ok(fake_fleet::claim(set, envelope))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        submit_settlement_slot_claim_live(set, envelope).await
    }
}

/// TEST-ONLY in-process member fleet: one object store per MEMBER ID (not per
/// URL), an injectable per-member failure, and an injectable echoed node id —
/// so a test can drive the real per-member replay/quorum logic through
/// partition splits, echo mismatches and foreign sets without HTTP.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) mod fake_fleet {
    // As for `fake_registers`: a test-only double compiled under production
    // lints only by `--all-features`.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
        /// members that SERVE READS but refuse register writes — a node that
        /// is reachable and answering while unable to accept new state (a
        /// read-only mount, a full disk). Distinct from `failing`, because a
        /// composer can still count such a member's cell answer while a claim
        /// cannot reach quorum through it.
        claim_refusing: HashSet<String>,
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

    /// Member-attributed read of one slot cell, mirroring the register-read
    /// row shape: `(member_id, echoed_node_id, winner_bytes)`.
    pub(crate) fn read_slot(
        set: &StorageSet,
        vault_id: &[u8; 32],
        parent_sequence: u64,
    ) -> Vec<dsm::economic::cell_observation::MemberCellRead> {
        let s = state();
        use dsm::economic::cell_observation::MemberCellRead;
        set.members()
            .iter()
            .map(|member| {
                // A FAILING MEMBER DOES NOT ANSWER — and it does not answer
                // "empty". An attributed absence is a POSITIVE claim that the
                // cell holds nothing; modelling an outage as one would let a
                // fixture manufacture frontiers out of silence, the exact
                // defect this observation exists to remove.
                if s.failing.contains(&member.member_id) {
                    return MemberCellRead::Unavailable;
                }
                let echoed = s
                    .echo_override
                    .get(&member.member_id)
                    .cloned()
                    .unwrap_or_else(|| Some(member.member_id.clone()));
                if echoed.as_deref() != Some(member.member_id.as_str()) {
                    return MemberCellRead::Unavailable;
                }
                match s
                    .registers
                    .get(&member.member_id)
                    .and_then(|cells| cells.get(&(*vault_id, parent_sequence)))
                {
                    Some((b, _)) => MemberCellRead::Value(b.clone()),
                    None => MemberCellRead::Absent,
                }
            })
            .collect()
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

    /// `member_id` answers reads but refuses register writes.
    pub(crate) fn refuse_claims(member_id: &str) {
        state().claim_refusing.insert(member_id.to_string());
    }

    pub(crate) fn accept_claims(member_id: &str) {
        state().claim_refusing.remove(member_id);
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
            if st.failing.contains(&m.member_id) || st.claim_refusing.contains(&m.member_id) {
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
