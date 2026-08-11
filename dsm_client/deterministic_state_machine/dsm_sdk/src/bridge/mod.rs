// SPDX-License-Identifier: MIT OR Apache-2.0

//! # SDK Bridge API — APP INTEGRATION BOUNDARY
//!
//! If you are building a custom wallet, terminal app, CLI tool, or mobile
//! client on top of DSM, the [`AppRouter`] trait in this module is your
//! primary integration surface.
//!
//! ## How to Hook In
//!
//! 1. After SDK bootstrap, call [`app_router()`] to get the installed router.
//! 2. Use [`AppRouter::query()`] for read-only operations:
//!    - `"balance.list"`, `"wallet.history"`, `"contacts.list"`, `"sys.tick"`,
//!      `"state.info"`, `"bitcoin.balance"`, `"bilateral.pending_list"`, etc.
//! 3. Use [`AppRouter::invoke()`] for state-mutating operations:
//!    - `"wallet.send"`, `"token.create"`, `"faucet.claim"`, `"prefs.set"`,
//!      `"message.send"`, `"dbrw.export_report"`, etc.
//! 4. All parameters (`AppQuery::params`, `AppInvoke::args`) and return values
//!    (`AppResult::data`) are prost-encoded protobuf bytes. See `dsm_app.proto`.
//!
//! ## Protocol Rules
//!
//! - NO JSON — all payloads are protobuf (`prost`). `serde_json` is banned.
//! - NO HEX — use raw bytes internally, Base32 Crockford at string boundaries.
//! - NO WALL CLOCK — state transitions use BLAKE3 iteration counters, never
//!   `Instant::now()` or `SystemTime::now()`.
//! - Envelope v3 only — all wire responses carry the `0x03` framing prefix.
//!
//! ## Router Lifecycle
//!
//! - Pre-genesis: [`MinimalBootstrapRouter`] (limited queries, returns errors
//!   for anything requiring identity).
//! - Post-genesis: [`AppRouterImpl`] replaces it via [`install_app_router()`].
//!   This is a hot-swap — callers see the new router immediately.
//!
//! ## Adding a New Route
//!
//! Implement the handler in `handlers/app_router_impl.rs`, add a match arm in
//! `query()` or `invoke()`, and define the protobuf types in `dsm_app.proto`.
//! No Android boundary changes are needed — `dispatchIngress`
//! dispatches generically by path string.
//!
//! See `docs/INTEGRATION_GUIDE.md` for the full developer onboarding guide.
//!
//! ---
//!
//! Defines the minimal traits (`AppRouter`, `BilateralHandler`,
//! `UnilateralHandler`), dispatch types (`AppQuery`, `AppInvoke`,
//! `BiPrepare`, `UniOp`, etc.), and `OnceLock`-based installer functions
//! used by the SDK handler implementations. This keeps the transport/UI
//! bridge entirely out of the pure `dsm` core crate.

use once_cell::sync::OnceCell;
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;
use prost::Message;

// ---------- App Router ----------

#[derive(Debug, Clone)]
pub struct AppQuery {
    pub path: String,
    pub params: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AppInvoke {
    pub method: String,
    pub args: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AppResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub error_message: Option<String>,
}

#[async_trait::async_trait]
pub trait AppRouter: Send + Sync {
    async fn query(&self, q: AppQuery) -> AppResult;
    async fn invoke(&self, i: AppInvoke) -> AppResult;
    /// Reload in-memory balance cache from SQLite after external balance
    /// changes (e.g. BLE bilateral receiver credit landing in the
    /// `balance_projections` table). The canonical DeviceState head is
    /// installed by `execute_on_relationship` at the AdvanceOutcome
    /// chokepoint; settlement-layer state never needs to be pushed back
    /// into CoreSDK.
    fn sync_balance_cache(&self) {}

    /// Read-only snapshot of the canonical [`DeviceState`] head (§2.2 `r_A`).
    ///
    /// Used by settlement delegates to materialise display-layer projections
    /// from the device head's authoritative balance scalar — never to mutate
    /// it. Returns `None` when the router does not yet hold an identity
    /// (pre-genesis bootstrap router).
    fn device_head(&self) -> Option<dsm::types::device_state::DeviceState> {
        None
    }

    /// §9.5: resolve a token's canonical `policy_commit` from the local
    /// source-of-truth installed policy (builtins -> canonical constants;
    /// custom -> the device's own registration history). Returns `Err` when the
    /// policy is not locally installed — callers MUST fail closed and never
    /// absorb a peer-supplied commit. Default impl fails closed.
    fn resolve_policy_commit_strict(
        &self,
        _token_id: &[u8],
    ) -> Result<[u8; 32], dsm::types::error::DsmError> {
        Err(dsm::types::error::DsmError::invalid_operation(
            "resolve_policy_commit_strict: unsupported by this router",
        ))
    }

    /// Pure-prepare view of the canonical AdvanceOutcome — used by the BLE
    /// sender to build a stitched receipt with the real post-advance SMT
    /// roots/proofs before the canonical commit lands (canonical commit
    /// happens later inside `execute_on_relationship_for_bilateral`).
    /// Returns identical outcome for identical inputs, so the simulated
    /// receipt is byte-exact with the eventual real advance.
    #[allow(clippy::too_many_arguments)]
    fn simulate_advance_for_confirm(
        &self,
        _rel_key: [u8; 32],
        _counterparty_devid: [u8; 32],
        _operation: dsm::types::operations::Operation,
        _deltas: &[dsm::types::device_state::BalanceDelta],
        _initial_chain_tip: Option<[u8; 32]>,
        _anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        _offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, dsm::types::error::DsmError> {
        Err(dsm::types::error::DsmError::invalid_operation(
            "simulate_advance_for_confirm not implemented on this router",
        ))
    }

    /// v2 producer phase 1 (Software-Authority / Hardware-Identity): stage the next offline-bearer
    /// transition from the appliance's active state — the transition `Δ`, the successor frontier,
    /// and the successor anchor-state leaf — WITHOUT any appliance mutation. The caller simulates
    /// the DSM advance over the returned leaf to get `R_i`/`R_{i+1}` + `Π_i`/`Π_{i+1}`, then calls
    /// [`release_offline_bearer`](Self::release_offline_bearer). Delegates to
    /// [`CoreSDK::stage_offline_bearer_transition`].
    #[allow(clippy::too_many_arguments)]
    fn stage_offline_bearer_transition(
        &self,
        _relationship_id: [u8; 32],
        _recipient_device_id: [u8; 32],
        _object_id: [u8; 32],
        _payload_hash: [u8; 32],
        _authority_policy_hash: [u8; 32],
        _action_type: u32,
        _action_fields: Vec<u8>,
        _receiver_challenge: [u8; 32],
    ) -> Result<crate::sdk::core_sdk::StagedBearerTransition, dsm::types::error::DsmError> {
        Err(dsm::types::error::DsmError::invalid_operation(
            "stage_offline_bearer_transition not implemented on this router",
        ))
    }

    /// v2 producer phase 2: PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT → FINALIZE with the real
    /// device SMT roots from the caller's advance simulation, attaching `Π_i`/`Π_{i+1}` to the
    /// release package. Delegates to [`CoreSDK::release_offline_bearer`].
    fn release_offline_bearer(
        &self,
        _staged: &crate::sdk::core_sdk::StagedBearerTransition,
        _receiver_challenge: [u8; 32],
        _sender_device_root_before: [u8; 32],
        _sender_device_root_after: [u8; 32],
        _anchor_smt_proof_before: Vec<u8>,
        _anchor_smt_proof_after: Vec<u8>,
    ) -> Result<crate::sdk::core_sdk::OfflineBearerArtifacts, dsm::types::error::DsmError> {
        Err(dsm::types::error::DsmError::invalid_operation(
            "release_offline_bearer not implemented on this router",
        ))
    }

    /// Cleanup: release an ABANDONED prepared bearer (e.g. the confirm build failed between
    /// PREPARE and COMMIT) so the appliance returns to `Ready` and future offline-bearer sends do
    /// not fail closed. Best-effort no-op default; overridden to delegate to
    /// [`CoreSDK::cancel_offline_bearer_release`].
    fn cancel_offline_bearer_release(&self) -> Result<(), dsm::types::error::DsmError> {
        Ok(())
    }

    /// Execute a prepared bilateral advance through the canonical
    /// [`CoreSDK::execute_on_relationship`] chokepoint.
    ///
    /// This is the bilateral entry point into the §2.2 single Per-Device SMT
    /// advance (`prepare_advance_relationship → commit_advance`). It returns
    /// only the [`AdvanceOutcome`] — settlement and BLE paths do not need the
    /// compat `State` view. Callers feed in the tripwire-verified operation
    /// and balance deltas produced by
    /// `BilateralTransactionManager::finalize_offline_transfer_with_entropy`
    /// (which no longer mutates any SMT itself), along with the parent chain
    /// tip for CAS-style linkage.
    ///
    /// Returns `Err` if the router is not yet attached to an identity, or if
    /// the underlying advance fails (§4.3 acceptance, §6.1 tripwire, §8
    /// balance binding).
    #[allow(clippy::too_many_arguments)]
    fn execute_on_relationship_for_bilateral(
        &self,
        _rel_key: [u8; 32],
        _counterparty_devid: [u8; 32],
        _operation: dsm::types::operations::Operation,
        _deltas: &[dsm::types::device_state::BalanceDelta],
        _initial_chain_tip: Option<[u8; 32]>,
        _anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        _offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, dsm::types::error::DsmError> {
        Err(dsm::types::error::DsmError::invalid_operation(
            "execute_on_relationship_for_bilateral not implemented on this router",
        ))
    }
}

/// App router storage. Uses RwLock to allow replacement (MinimalBootstrapRouter → AppRouterImpl).
static APP_ROUTER: Lazy<RwLock<Option<Arc<dyn AppRouter>>>> = Lazy::new(|| RwLock::new(None));

/// The device_id the *full* [`AppRouterImpl`] currently in [`APP_ROUTER`] was built for; `None`
/// while the MinimalBootstrapRouter (or nothing) occupies the slot. `app_router().is_some()`
/// cannot distinguish the two (both occupy the single slot), so the post-genesis / post-unlock
/// hot-swap paths key idempotency off this marker instead — otherwise `ensureAppRouterInstalled`
/// would either rebuild the router on every call or (its original bug) short-circuit on the
/// *minimal* router and never upgrade.
///
/// Identity-keyed (not a bool) because `AppRouterImpl::new` SNAPSHOTS the identity at construction
/// (ContactManager, CoreSDK device info, wallet storage namespace): a bare "installed" bit would
/// keep reporting ready if AppState's identity ever changed under it, silently serving routes as
/// the OLD identity. Prod never resets `APP_ROUTER` (the only resets are `#[cfg(test)]`), so this
/// marker only clears in those test resets.
static FULL_APP_ROUTER_IDENTITY: Lazy<RwLock<Option<Vec<u8>>>> = Lazy::new(|| RwLock::new(None));

/// Whether the full app router (not the MinimalBootstrapRouter) is installed AND was built for the
/// CURRENT AppState identity. A mismatch (identity changed since the swap) reports `false` so
/// install paths rebuild rather than serve routes under a stale identity.
#[must_use]
pub fn full_app_router_installed() -> bool {
    let installed_for = match FULL_APP_ROUTER_IDENTITY.read() {
        Ok(g) => g.clone(),
        Err(_) => return false,
    };
    match (
        installed_for,
        crate::sdk::app_state::AppState::get_device_id(),
    ) {
        (Some(installed), Some(current)) => installed == current,
        _ => false,
    }
}

/// Record the device_id the full app router was built for. Called by the install helper after a
/// successful swap.
pub(crate) fn mark_full_app_router_installed(device_id: Vec<u8>) {
    if let Ok(mut g) = FULL_APP_ROUTER_IDENTITY.write() {
        *g = Some(device_id);
    }
}

/// Install (or replace) the SDK app router.
///
/// This is called:
/// 1. During early init with MinimalBootstrapRouter (pre-genesis)
/// 2. Post-genesis with the full AppRouterImpl
///
/// The second call replaces the first, enabling faucet/balance/etc. queries.
pub fn install_app_router(router: Arc<dyn AppRouter>) -> Result<(), dsm::types::error::DsmError> {
    let mut guard = APP_ROUTER
        .write()
        .map_err(|_| dsm::types::error::DsmError::LockError)?;
    let was_none = guard.is_none();
    *guard = Some(router);
    drop(guard);

    if was_none {
        log::info!("[SDK] AppRouter installed (first time)");
    } else {
        log::info!("[SDK] AppRouter replaced (upgrade from bootstrap to full router)");
    }
    Ok(())
}

pub fn app_router() -> Option<Arc<dyn AppRouter>> {
    APP_ROUTER.read().ok()?.clone()
}

/// The local device's CURRENT ML-KEM-768 (Kyber) encapsulation key. Installed by
/// `AppRouterImpl::new` right after `WalletSDK` initializes device keys — the keypair is
/// deliberately RANDOMIZED per wallet init (no persisted device secret), so this snapshot is
/// valid for the life of the wallet instance and is re-installed on every router (re)build.
/// The bilateral BLE prepare exchange attaches it so counterparties can refresh their contact
/// record (per-step EK receipts encapsulate to it). `None` -> prepare messages carry an empty
/// key and the counterparty's receipt build fail-closes exactly as before.
static LOCAL_KYBER_PUBKEY: Lazy<RwLock<Option<Vec<u8>>>> = Lazy::new(|| RwLock::new(None));

/// Install (or replace) the local wallet's Kyber public key snapshot.
pub fn install_local_kyber_pubkey(pk: Vec<u8>) {
    if let Ok(mut g) = LOCAL_KYBER_PUBKEY.write() {
        *g = Some(pk);
        log::info!("[SDK] Local Kyber public key installed (bilateral prepare exchange)");
    }
}

/// The local wallet's Kyber public key, if a wallet is initialized this session.
#[must_use]
pub fn local_kyber_pubkey() -> Option<Vec<u8>> {
    LOCAL_KYBER_PUBKEY.read().ok()?.clone()
}

/// Receiver-side pinned fused-anchor enrollment store. Installed by the device layer; supplies the
/// `FusedAnchorPin` the receiver admitted for a counterparty. `None` until installed -> no pin ->
/// offline-bearer acceptance fail-closed.
static ANCHOR_ENROLLMENT_STORE: Lazy<
    RwLock<Option<Arc<dyn dsm::crypto::anchor_enrollment::AnchorEnrollmentStore>>>,
> = Lazy::new(|| RwLock::new(None));

/// Install (or replace) the receiver-side fused-anchor enrollment store.
pub fn install_anchor_enrollment_store(
    store: Arc<dyn dsm::crypto::anchor_enrollment::AnchorEnrollmentStore>,
) {
    if let Ok(mut g) = ANCHOR_ENROLLMENT_STORE.write() {
        *g = Some(store);
        log::info!("[SDK] AnchorEnrollmentStore installed");
    }
}

/// Test-only: clear the installed enrollment store so a `#[serial]` test leaves the global bridge
/// as it found it (other tests assert the fail-closed `None` path).
#[cfg(test)]
pub(crate) fn uninstall_anchor_enrollment_store() {
    if let Ok(mut g) = ANCHOR_ENROLLMENT_STORE.write() {
        *g = None;
    }
}

#[must_use]
pub fn anchor_enrollment_store(
) -> Option<Arc<dyn dsm::crypto::anchor_enrollment::AnchorEnrollmentStore>> {
    ANCHOR_ENROLLMENT_STORE.read().ok()?.clone()
}

/// SENDER-side fused-anchor appliance factory. Produces the fresh `AnchorAppliance` the offline-bearer
/// release is built on. The device layer installs a factory that returns a `UsbAnchorAppliance`
/// driving the physical RP2350/TROPIC01; `build_offline_bearer_release` calls it ONCE and caches the
/// result (the appliance is stateful — its counter advances and its witness key erases on COMMIT).
///
/// `None` until installed. On device, an absent factory means offline-bearer is unavailable and the
/// send FAILS CLOSED (no mock fallback) — "offline = chips". The in-process mock is used only by the
/// SDK's own `#[cfg(test)]` release-path tests. The factory returns `Result` so a failed chip connect
/// (e.g. STATUS unreadable) propagates as a fail-closed error rather than a silent mock.
type AnchorApplianceFactory = Arc<
    dyn Fn() -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, dsm::types::error::DsmError>
        + Send
        + Sync,
>;
static ANCHOR_APPLIANCE_FACTORY: Lazy<RwLock<Option<AnchorApplianceFactory>>> =
    Lazy::new(|| RwLock::new(None));

/// Install (or replace) the sender-side anchor-appliance factory (the physical-chip producer).
pub fn install_anchor_appliance_factory(factory: AnchorApplianceFactory) {
    if let Ok(mut g) = ANCHOR_APPLIANCE_FACTORY.write() {
        *g = Some(factory);
        log::info!(
            "[SDK] AnchorApplianceFactory installed (offline-bearer release = physical chip)"
        );
    }
}

#[must_use]
pub fn anchor_appliance_factory() -> Option<AnchorApplianceFactory> {
    ANCHOR_APPLIANCE_FACTORY.read().ok()?.clone()
}

/// Test-only: uninstall the factory so the next test does not inherit it.
///
/// The factory is process-global. A test that installs one and does not remove it
/// changes the anchor-attach outcome for every test that runs after it, which surfaces
/// as unrelated failures far from the cause.
#[cfg(test)]
pub(crate) fn clear_anchor_appliance_factory_for_tests() {
    if let Ok(mut g) = ANCHOR_APPLIANCE_FACTORY.write() {
        *g = None;
    }
}

#[cfg(test)]
pub(crate) unsafe fn reset_bridge_handlers_for_tests() {
    if let Ok(mut guard) = APP_ROUTER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = FULL_APP_ROUTER_IDENTITY.write() {
        *guard = None;
    }
    if let Ok(mut guard) = UNILATERAL_HANDLER.write() {
        *guard = None;
    }
    std::ptr::write(
        std::ptr::addr_of!(BILATERAL_HANDLER) as *mut OnceCell<Arc<dyn BilateralHandler>>,
        OnceCell::new(),
    );
}

// ---------- Unilateral Ops ----------

#[derive(Debug, Clone)]
pub struct UniOp {
    pub operation_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UniResult {
    pub success: bool,
    pub result_data: Vec<u8>,
    pub error_message: Option<String>,
}

#[async_trait::async_trait]
pub trait UnilateralHandler: Send + Sync {
    async fn handle(&self, op: UniOp) -> UniResult;
}

/// Unilateral handler storage. Uses RwLock to allow replacement (pre-genesis → post-genesis).
static UNILATERAL_HANDLER: Lazy<RwLock<Option<Arc<dyn UnilateralHandler>>>> =
    Lazy::new(|| RwLock::new(None));

pub fn install_unilateral_handler(handler: Arc<dyn UnilateralHandler>) {
    match UNILATERAL_HANDLER.write() {
        Ok(mut guard) => {
            *guard = Some(handler);
        }
        Err(_) => {
            log::error!("install_unilateral_handler: unilateral handler lock poisoned");
        }
    }
}

pub fn unilateral_handler() -> Option<Arc<dyn UnilateralHandler>> {
    UNILATERAL_HANDLER.read().ok()?.clone()
}

// ---------------- Contact Management Helpers ----------------

pub fn sdk_remove_contact(contact_id: &str) -> bool {
    match crate::storage::client_db::remove_contact(contact_id) {
        Ok(r) => r,
        Err(e) => {
            log::error!("remove_contact failed: {e}");
            false
        }
    }
}

/// Helper: convert a u64 balance to the U128 le-bytes format used by TokenBalanceEntry.
fn u64_to_u128_le(val: u64) -> crate::generated::U128 {
    let mut le = vec![0u8; 16];
    le[..8].copy_from_slice(&val.to_le_bytes());
    crate::generated::U128 { le }
}

/// Fetch all token balances as a BalancesListResponse (strict, protobuf-encoded).
///
/// Routes through the app router `balance.list` handler which aggregates from authoritative sources:
/// 1. All DSM tokens from canonical balance projection rows materialized from DSM state
/// 2. Ensures dBTC always appears (even with 0) so the token picker works
///
/// Falls back to direct SQLite reads if the app router is not yet available.
/// Returns the CANONICAL `BalanceGetResponse` rows, not a surrogate.
///
/// This used to narrow each row into `TokenBalanceEntry { token_id, amount }`
/// and the JNI layer re-inflated it with `..Default::default()`, so `symbol`,
/// `decimals`, `locked` and `token_name` were silently dropped and came back
/// empty/zero. On device that meant a 2-decimal token with 100_000 base units
/// rendered as "100000" — the wallet had no decimals to format with, because a
/// two-field surrogate had thrown them away mid-flight.
///
/// One authoritative message end to end. A second representation only invites
/// the two to drift again.
pub fn get_all_balances_strict() -> Result<Vec<crate::generated::BalanceGetResponse>, String> {
    let device_id = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "No device_id available".to_string())?;
    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
    log::info!(
        "[getAllBalancesStrict] device_id_b32={} (first16)",
        &device_id_b32[..device_id_b32.len().min(16)]
    );

    // Try the app router first — it aggregates from the live authoritative paths.
    if let Some(router) = app_router() {
        let query = AppQuery {
            path: "balance.list".to_string(),
            params: vec![],
        };
        let result = futures::executor::block_on(router.query(query));
        if result.success && !result.data.is_empty() {
            // Response is 0x03-framed Envelope containing BalancesListResponse payload.
            let data = if result.data.first() == Some(&0x03) {
                &result.data[1..]
            } else {
                &result.data
            };
            if let Ok(envelope) = crate::envelope::from_canonical_bytes(data) {
                if let Some(crate::generated::envelope::Payload::BalancesListResponse(resp)) =
                    envelope.payload
                {
                    log::info!(
                        "[getAllBalancesStrict] via app_router: {} items",
                        resp.balances.len()
                    );
                    for b in &resp.balances {
                        log::info!("[getAllBalancesStrict]   {}={}", b.token_id, b.available);
                    }
                    // The router already built the canonical rows, metadata
                    // and all. Pass them straight through.
                    return Ok(resp.balances);
                }
            }
            log::warn!("[getAllBalancesStrict] app_router returned data but failed to decode");
        } else {
            log::warn!(
                "[getAllBalancesStrict] app_router query failed: {:?}",
                result.error_message
            );
        }
    }

    // Fallback: direct SQLite reads (pre-genesis or if app router unavailable)
    log::info!("[getAllBalancesStrict] falling back to direct SQLite reads");
    let mut entries: Vec<(String, u64)> = Vec::new();

    // 1. Tokens from canonical projection rows only.
    match crate::storage::client_db::list_balance_projections(&device_id_b32) {
        Ok(projected) => {
            for record in projected {
                let tok_id = record.token_id;
                if let Some(existing) = entries.iter_mut().find(|(t, _)| t == &tok_id) {
                    if record.available > existing.1 {
                        existing.1 = record.available;
                    }
                } else {
                    entries.push((tok_id, record.available));
                }
            }
        }
        Err(e) => {
            log::warn!(
                "[getAllBalancesStrict] list_balance_projections failed: {}",
                e
            );
        }
    }

    if !entries.iter().any(|(token_id, _)| token_id == "ERA") {
        entries.push(("ERA".to_string(), 0));
    }

    // 3. Ensure dBTC always appears (even with 0) so token picker works
    if !entries.iter().any(|(t, _)| t == "dBTC") {
        entries.push(("dBTC".to_string(), 0));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    log::info!(
        "[getAllBalancesStrict] returning {} entries: {:?}",
        entries.len(),
        entries
            .iter()
            .map(|(t, a)| format!("{}={}", t, a))
            .collect::<Vec<_>>()
    );

    // The fallback builds the same canonical rows, enriched from the same
    // registry the router uses, so a pre-genesis read is not a second shape.
    Ok(entries
        .into_iter()
        .map(|(token_id, available)| {
            let mut row = crate::generated::BalanceGetResponse {
                token_id,
                available,
                locked: 0,
                ..Default::default()
            };
            // Same registry the router reads. (Note: this crate and
            // dsm::types::proto each generate their own BalanceGetResponse from
            // the one .proto, so the router's enrichment helper is not directly
            // callable here — that duplication is worth collapsing separately.)
            match row.token_id.trim().to_uppercase().as_str() {
                "ERA" => {
                    row.symbol = "ERA".into();
                    row.token_name = "ERA".into();
                    row.decimals = 0;
                }
                "DBTC" => {
                    row.token_id = "dBTC".into();
                    row.symbol = "dBTC".into();
                    row.token_name = "dBTC".into();
                    row.decimals = 8;
                }
                _ => {
                    if let Ok(Some(t)) =
                        crate::storage::client_db::token_registry::get_token_by_ticker(
                            &row.token_id,
                        )
                    {
                        row.symbol = t.ticker.clone();
                        row.token_name = if t.alias.is_empty() {
                            t.ticker
                        } else {
                            t.alias
                        };
                        row.decimals = t.decimals;
                    }
                }
            }
            row
        })
        .collect())
}

/// Fetch wallet history as WalletHistoryResponse (strict, protobuf-encoded)
pub fn get_wallet_history_strict() -> Result<crate::generated::WalletHistoryResponse, String> {
    // Use the app router to query wallet.history
    let app_router = app_router().ok_or_else(|| "App router not available".to_string())?;

    // Create query for wallet.history with no limit/offset (empty params)
    let query = AppQuery {
        path: "wallet.history".to_string(),
        params: vec![], // Empty params means no limit/offset
    };

    // Query synchronously
    let result = futures::executor::block_on(app_router.query(query));

    if !result.success {
        return Err(result
            .error_message
            .unwrap_or_else(|| "Query failed".to_string()));
    }

    // app_router.query returns an ArgPack (codec=PROTO) where the body is the WalletHistoryResponse bytes.
    let arg = crate::generated::ArgPack::decode(&*result.data)
        .map_err(|e| format!("Failed to decode ArgPack for wallet.history: {e}"))?;

    if arg.body.is_empty() {
        return Ok(crate::generated::WalletHistoryResponse {
            transactions: vec![],
        });
    }

    crate::generated::WalletHistoryResponse::decode(&*arg.body)
        .map_err(|e| format!("Failed to decode WalletHistoryResponse from ArgPack body: {e}"))
}
// ---------- Bilateral Ops (offline) ----------

#[derive(Debug, Clone, Default)]
pub struct BiPrepare {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct BiTransfer {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BiResult {
    pub success: bool,
    pub result_data: Vec<u8>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BiAccept {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BiCommit {
    pub payload: Vec<u8>,
}

#[async_trait::async_trait]
pub trait BilateralHandler: Send + Sync {
    async fn prepare(&self, p: BiPrepare) -> BiResult;
    async fn transfer(&self, t: BiTransfer) -> BiResult;
    async fn accept(&self, a: BiAccept) -> BiResult;
    async fn commit(&self, c: BiCommit) -> BiResult;

    /// Retrieve pending transactions (beta requirement: strict sync).
    /// Returns serialized pb::OfflineBilateralTransaction messages.
    async fn get_pending_transactions(&self) -> Result<Vec<Vec<u8>>, String>;

    /// Allow downcasting to concrete type for SDK injection.
    fn as_any(&self) -> &dyn std::any::Any;
}

static BILATERAL_HANDLER: OnceCell<Arc<dyn BilateralHandler>> = OnceCell::new();

pub fn get_pending_bilateral_proposals_strict() -> Result<Vec<Vec<u8>>, String> {
    if let Some(h) = BILATERAL_HANDLER.get() {
        crate::runtime::get_runtime().block_on(h.get_pending_transactions())
    } else {
        Err("Bilateral handler not installed".to_string())
    }
}

pub fn install_bilateral_handler(handler: Arc<dyn BilateralHandler>) {
    let _ = BILATERAL_HANDLER.set(handler);
}

pub fn bilateral_handler() -> Option<Arc<dyn BilateralHandler>> {
    BILATERAL_HANDLER.get().cloned()
}

/// Inject the BleFrameCoordinator into the bilateral handler (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn inject_ble_coordinator(
    coordinator: std::sync::Arc<crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator>,
) -> Result<(), String> {
    use crate::handlers::BiImpl;

    let handler = BILATERAL_HANDLER
        .get()
        .ok_or_else(|| "Bilateral handler not installed".to_string())?;

    let bi_impl = handler
        .as_ref()
        .as_any()
        .downcast_ref::<BiImpl>()
        .ok_or_else(|| "Bilateral handler is not BiImpl".to_string())?;

    bi_impl.set_ble_coordinator(coordinator).await;
    log::info!("BleFrameCoordinator injected into BiImpl via bridge");
    Ok(())
}

/// Inject the bilateral transport adapter into the bilateral handler (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn inject_ble_transport_adapter(
    adapter: std::sync::Arc<
        crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter,
    >,
) -> Result<(), String> {
    use crate::handlers::BiImpl;

    let handler = BILATERAL_HANDLER
        .get()
        .ok_or_else(|| "Bilateral handler not installed".to_string())?;

    let bi_impl = handler
        .as_ref()
        .as_any()
        .downcast_ref::<BiImpl>()
        .ok_or_else(|| "Bilateral handler is not BiImpl".to_string())?;

    bi_impl.set_ble_transport_adapter(adapter).await;
    log::info!("Ble transport adapter injected into BiImpl via bridge");
    Ok(())
}

/// Get the BleFrameCoordinator from the bilateral handler (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn get_ble_coordinator(
) -> Result<std::sync::Arc<crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator>, String> {
    use crate::handlers::BiImpl;

    let handler = BILATERAL_HANDLER
        .get()
        .ok_or_else(|| "Bilateral handler not installed".to_string())?;

    let bi_impl = handler
        .as_ref()
        .as_any()
        .downcast_ref::<BiImpl>()
        .ok_or_else(|| "Bilateral handler is not BiImpl".to_string())?;

    bi_impl
        .get_ble_coordinator()
        .await
        .ok_or_else(|| "BleFrameCoordinator not injected yet".to_string())
}

/// Get the bilateral transport adapter from the bilateral handler (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn get_ble_transport_adapter() -> Result<
    std::sync::Arc<crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter>,
    String,
> {
    use crate::handlers::BiImpl;

    let handler = BILATERAL_HANDLER
        .get()
        .ok_or_else(|| "Bilateral handler not installed".to_string())?;

    let bi_impl = handler
        .as_ref()
        .as_any()
        .downcast_ref::<BiImpl>()
        .ok_or_else(|| "Bilateral handler is not BiImpl".to_string())?;

    bi_impl
        .get_ble_transport_adapter()
        .await
        .ok_or_else(|| "Ble transport adapter not injected yet".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;

    #[async_trait::async_trait]
    impl AppRouter for Dummy {
        async fn query(&self, _q: AppQuery) -> AppResult {
            AppResult {
                success: true,
                data: vec![],
                error_message: None,
            }
        }
        async fn invoke(&self, _i: AppInvoke) -> AppResult {
            AppResult {
                success: true,
                data: vec![],
                error_message: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl UnilateralHandler for Dummy {
        async fn handle(&self, _op: UniOp) -> UniResult {
            UniResult {
                success: true,
                result_data: vec![],
                error_message: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl BilateralHandler for Dummy {
        async fn prepare(&self, _p: BiPrepare) -> BiResult {
            BiResult {
                success: true,
                result_data: vec![],
                error_message: None,
            }
        }
        async fn transfer(&self, _t: BiTransfer) -> BiResult {
            BiResult {
                success: true,
                result_data: vec![],
                error_message: None,
            }
        }
        async fn accept(&self, _a: BiAccept) -> BiResult {
            BiResult {
                success: true,
                result_data: vec![],
                error_message: None,
            }
        }
        async fn commit(&self, _c: BiCommit) -> BiResult {
            BiResult {
                success: true,
                result_data: vec![],
                error_message: None,
            }
        }

        async fn get_pending_transactions(&self) -> Result<Vec<Vec<u8>>, String> {
            Ok(vec![])
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn installers_set_cells() {
        match install_app_router(Arc::new(Dummy)) {
            Ok(_) => {}
            Err(e) => panic!("Failed to install app router: {:?}", e),
        }
        install_unilateral_handler(Arc::new(Dummy));
        install_bilateral_handler(Arc::new(Dummy));
        assert!(app_router().is_some());
        assert!(unilateral_handler().is_some());
        assert!(bilateral_handler().is_some());
    }

    /// Reset all bridge handler singletons for testing.
    ///
    /// # Safety
    /// This function is UNSAFE and should ONLY be called in single-threaded test contexts.
    /// The bilateral handler uses OnceCell which requires unsafe pointer writes to reset.
    pub unsafe fn reset_bridge_handlers_for_tests() {
        // APP_ROUTER and UNILATERAL_HANDLER are RwLock-based — safe to clear.
        if let Ok(mut guard) = APP_ROUTER.write() {
            *guard = None;
        }
        if let Ok(mut guard) = FULL_APP_ROUTER_IDENTITY.write() {
            *guard = None;
        }
        if let Ok(mut guard) = UNILATERAL_HANDLER.write() {
            *guard = None;
        }
        // BILATERAL_HANDLER is still OnceCell — requires unsafe reset.
        std::ptr::write(
            std::ptr::addr_of!(BILATERAL_HANDLER) as *mut OnceCell<Arc<dyn BilateralHandler>>,
            OnceCell::new(),
        );
    }
}
