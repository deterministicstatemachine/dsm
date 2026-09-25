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
//!    - `"balance.list"`, `"wallet.history"`, `"contacts.list"`,
//!      `"bitcoin.balance"`, `"bilateral.pending_list"`, etc.
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
//! Defines the minimal router trait (`AppRouter`), dispatch types
//! (`AppQuery`, `AppInvoke`), the BLE runtime slot, and `OnceLock`-based installer functions
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
    fn sync_balance_cache(&self);

    /// Read-only snapshot of the canonical [`DeviceState`] head (§2.2 `r_A`).
    ///
    /// Used by settlement delegates to materialise display-layer projections
    /// from the device head's authoritative balance scalar — never to mutate
    /// it. `None` when the router does not yet hold an identity (the
    /// pre-genesis bootstrap router).
    fn device_head(&self) -> Option<dsm::types::device_state::DeviceState>;

    /// §9.5: resolve a token's canonical `policy_commit` from the local
    /// source-of-truth installed policy (builtins -> canonical constants;
    /// custom -> the device's own registration history). Returns `Err` when the
    /// policy is not locally installed — callers MUST fail closed and never
    /// absorb a peer-supplied commit.
    fn resolve_policy_commit_strict(
        &self,
        token_id: &[u8],
    ) -> Result<[u8; 32], dsm::types::error::DsmError>;

    /// Pure-prepare view of the canonical AdvanceOutcome — used by the BLE
    /// sender to build a stitched receipt with the real post-advance SMT
    /// roots/proofs before the canonical commit lands (canonical commit
    /// happens later inside `execute_on_relationship_for_bilateral`).
    /// Returns identical outcome for identical inputs, so the simulated
    /// receipt is byte-exact with the eventual real advance.
    #[allow(clippy::too_many_arguments)]
    fn simulate_advance_for_confirm(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, dsm::types::error::DsmError>;

    /// v2 producer phase 1 (Software-Authority / Hardware-Identity): stage the next offline-bearer
    /// transition from the appliance's active state — the transition `Δ`, the successor frontier,
    /// and the successor anchor-state leaf — WITHOUT any appliance mutation. The caller simulates
    /// the DSM advance over the returned leaf to get `R_i`/`R_{i+1}` + `Π_i`/`Π_{i+1}`, then calls
    /// [`release_offline_bearer`](Self::release_offline_bearer). Delegates to
    /// [`CoreSDK::stage_offline_bearer_transition`].
    #[allow(clippy::too_many_arguments)]
    fn stage_offline_bearer_transition(
        &self,
        relationship_id: [u8; 32],
        recipient_device_id: [u8; 32],
        object_id: [u8; 32],
        payload_hash: [u8; 32],
        authority_policy_hash: [u8; 32],
        action_type: u32,
        action_fields: Vec<u8>,
        receiver_challenge: [u8; 32],
    ) -> Result<crate::sdk::core_sdk::StagedBearerTransition, dsm::types::error::DsmError>;

    /// v2 producer phase 2: PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT → FINALIZE with the real
    /// device SMT roots from the caller's advance simulation, attaching `Π_i`/`Π_{i+1}` to the
    /// release package. Delegates to [`CoreSDK::release_offline_bearer`].
    fn release_offline_bearer(
        &self,
        staged: &crate::sdk::core_sdk::StagedBearerTransition,
        receiver_challenge: [u8; 32],
        sender_device_root_before: [u8; 32],
        sender_device_root_after: [u8; 32],
        anchor_smt_proof_before: Vec<u8>,
        anchor_smt_proof_after: Vec<u8>,
    ) -> Result<crate::sdk::core_sdk::OfflineBearerArtifacts, dsm::types::error::DsmError>;

    /// Cleanup: release an ABANDONED prepared bearer (e.g. the confirm build failed between
    /// PREPARE and COMMIT) so the appliance returns to `Ready` and future offline-bearer sends do
    /// not fail closed. Delegates to [`CoreSDK::cancel_offline_bearer_release`].
    fn cancel_offline_bearer_release(&self) -> Result<(), dsm::types::error::DsmError>;

    /// Execute a prepared bilateral advance through the canonical
    /// [`CoreSDK::execute_on_relationship`] chokepoint.
    ///
    /// This is the bilateral entry point into the §2.2 single Per-Device SMT
    /// advance (`prepare_advance_relationship → commit_advance`). It returns
    /// only the [`AdvanceOutcome`] — settlement and BLE paths do not need the
    /// compat `State` view. Callers feed in the tripwire-verified operation
    /// and balance deltas produced by
    /// `BilateralTransactionManager::prepare_bilateral_advance` (which mutates
    /// no SMT and resolves no entropy — Core derives the transition's one
    /// entropy inside `advance`), along with the parent chain tip for
    /// CAS-style linkage.
    ///
    /// `settle` writes the step's relationship tip, projection and history in
    /// the transaction that commits the head.
    ///
    /// Returns `Err` if the router is not yet attached to an identity, or if
    /// the underlying advance fails (§4.3 acceptance, §6.1 tripwire, §8
    /// balance binding) or `settle` does — then nothing is written.
    #[allow(clippy::too_many_arguments)]
    fn execute_on_relationship_for_bilateral(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
        settle: &dyn Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
        ) -> Result<(), dsm::types::error::DsmError>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, dsm::types::error::DsmError>;
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

/// A cache of the local device's ML-KEM-768 (Kyber) encapsulation key, the key derived from
/// `Smaster` under `DSM/kyber\0`. Installed by `AppRouterImpl::new` once `WalletSDK` has
/// derived the device keys; `kyber_identity::local_kyber_public_key` re-derives it when the
/// cache is cold.
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
/// release is built on: a client driving the physical RP2350/TROPIC01, installed by the device layer.
/// `build_offline_bearer_release` calls it ONCE and caches the result (the appliance is stateful —
/// its counter advances and its witness key erases on COMMIT).
///
/// `None` until installed, and no appliance transport exists yet to install: offline-bearer is
/// unavailable and the send FAILS CLOSED — "offline = chips". The factory returns `Result` so a
/// failed chip connect (e.g. STATUS unreadable) propagates as a fail-closed error.
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

#[cfg(test)]
pub(crate) unsafe fn reset_bridge_handlers_for_tests() {
    if let Ok(mut guard) = APP_ROUTER.write() {
        *guard = None;
    }
    if let Ok(mut guard) = FULL_APP_ROUTER_IDENTITY.write() {
        *guard = None;
    }
    std::ptr::write(
        std::ptr::addr_of!(BLE_RUNTIME) as *mut OnceCell<Arc<crate::handlers::BiImpl>>,
        OnceCell::new(),
    );
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

/// Every token balance, as the app router's `balance.list` answers it: the
/// CANONICAL `BalanceGetResponse` rows, never a surrogate.
///
/// There is no second source. Without a router, or when the router's answer
/// does not decode, this is an error — never rows assembled from projection
/// caches with zero balances filled in.
pub fn get_all_balances_strict() -> Result<Vec<crate::generated::BalanceGetResponse>, String> {
    let router =
        app_router().ok_or_else(|| "balance.list: app router not installed".to_string())?;
    let result = futures::executor::block_on(router.query(AppQuery {
        path: "balance.list".to_string(),
        params: vec![],
    }));
    if !result.success {
        return Err(format!(
            "balance.list: {}",
            result
                .error_message
                .unwrap_or_else(|| "the router refused without a reason".to_string())
        ));
    }
    let envelope = crate::handlers::response_helpers::decode_local_envelope(&result.data)
        .map_err(|e| format!("balance.list answer: {e}"))?;
    match envelope.payload {
        Some(dsm::types::proto::envelope::Payload::BalancesListResponse(list)) => {
            // This crate and `dsm::types::proto` each generate the message from
            // the one .proto; the bytes are the same message.
            crate::generated::BalancesListResponse::decode(list.encode_to_vec().as_slice())
                .map(|list| list.balances)
                .map_err(|e| format!("balance.list answer: {e}"))
        }
        other => Err(format!("balance.list answered {other:?}")),
    }
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
// ---------- The BLE runtime (offline) ----------

/// The slots the offline session engine's BLE carrier is injected into. Not
/// a protocol handler: offline bilateral steps run in `BilateralBleHandler`,
/// and the envelope bridge routes none of them.
static BLE_RUNTIME: OnceCell<Arc<crate::handlers::BiImpl>> = OnceCell::new();

pub fn install_ble_runtime(runtime: Arc<crate::handlers::BiImpl>) {
    if BLE_RUNTIME.set(runtime).is_err() {
        log::warn!("[SDK] BLE runtime already installed; the first one stays");
    }
}

pub fn ble_runtime() -> Option<Arc<crate::handlers::BiImpl>> {
    BLE_RUNTIME.get().cloned()
}

#[cfg(all(target_os = "android", feature = "bluetooth"))]
fn installed_ble_runtime() -> Result<Arc<crate::handlers::BiImpl>, String> {
    ble_runtime().ok_or_else(|| "BLE runtime not installed".to_string())
}

/// Inject the BleFrameCoordinator into the BLE runtime (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn inject_ble_coordinator(
    coordinator: std::sync::Arc<crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator>,
) -> Result<(), String> {
    installed_ble_runtime()?
        .set_ble_coordinator(coordinator)
        .await;
    log::info!("BleFrameCoordinator injected into the BLE runtime");
    Ok(())
}

/// Inject the bilateral transport adapter into the BLE runtime (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn inject_ble_transport_adapter(
    adapter: std::sync::Arc<
        crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter,
    >,
) -> Result<(), String> {
    installed_ble_runtime()?
        .set_ble_transport_adapter(adapter)
        .await;
    log::info!("Ble transport adapter injected into the BLE runtime");
    Ok(())
}

/// Get the BleFrameCoordinator from the BLE runtime (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn get_ble_coordinator(
) -> Result<std::sync::Arc<crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator>, String> {
    installed_ble_runtime()?
        .get_ble_coordinator()
        .await
        .ok_or_else(|| "BleFrameCoordinator not injected yet".to_string())
}

/// Get the bilateral transport adapter from the BLE runtime (Android only).
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn get_ble_transport_adapter() -> Result<
    std::sync::Arc<crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter>,
    String,
> {
    installed_ble_runtime()?
        .get_ble_transport_adapter()
        .await
        .ok_or_else(|| "Ble transport adapter not injected yet".to_string())
}
