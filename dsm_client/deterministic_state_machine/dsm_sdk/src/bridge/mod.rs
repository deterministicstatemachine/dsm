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
//! No JNI changes needed — `appRouterQueryFramed`/`appRouterInvokeFramed`
//! dispatch generically by path string.
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

// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// Reload in-memory balance cache from SQLite after external balance changes (e.g. BLE debit).
    fn sync_balance_cache(&self) {}
    /// Return the device's canonical tip state (authoritative token balances).
    ///
    /// Used by bilateral settlement to source B_n before applying the transfer
    /// delta.  Returns `None` if no canonical state is available yet.
    fn get_device_current_state(&self) -> Option<dsm::types::state_types::State> {
        None
    }

    /// Push a settled canonical state into CoreSDK's in-memory state machine.
    /// Must be called BEFORE sync_balance_cache() after bilateral settlement
    /// so the in-memory tip is ahead of any stale BCR archive entry.
    fn push_device_state(&self, _state: &dsm::types::state_types::State) {}
}

/// App router storage. Uses RwLock to allow replacement (MinimalBootstrapRouter → AppRouterImpl).
static APP_ROUTER: Lazy<RwLock<Option<Arc<dyn AppRouter>>>> = Lazy::new(|| RwLock::new(None));

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
pub fn get_all_balances_strict() -> Result<Vec<crate::generated::TokenBalanceEntry>, String> {
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
            if let Ok(envelope) = crate::generated::Envelope::decode(data) {
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
                    // Convert BalanceGetResponse → TokenBalanceEntry
                    return Ok(resp
                        .balances
                        .into_iter()
                        .map(|b| crate::generated::TokenBalanceEntry {
                            token_id: b.token_id,
                            amount: Some(u64_to_u128_le(b.available)),
                        })
                        .collect());
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

    Ok(entries
        .into_iter()
        .map(
            |(token_id, available)| crate::generated::TokenBalanceEntry {
                token_id,
                amount: Some(u64_to_u128_le(available)),
            },
        )
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

    /// Pre-flight reconciliation before initiating a new send.
    ///
    /// Ensures the sender's view of the counterparty's chain tip is current
    /// before constructing a BilateralPrepareRequest. This prevents TipMismatch
    /// rejections after role-swaps where the final ACK of the previous transaction
    /// was dropped.
    async fn reconcile_before_send(&self, counterparty_device_id: &[u8]) -> Result<(), String> {
        let _ = counterparty_device_id;
        Ok(())
    }

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
