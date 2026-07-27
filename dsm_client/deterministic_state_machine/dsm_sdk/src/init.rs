// SPDX-License-Identifier: MIT OR Apache-2.0

//! # SDK Handler Installation
//!
//! Configures and installs the core handler bridge that connects the SDK
//! layer to the pure `dsm` core library. This module:
//!
//! - Validates [`SdkConfig`] (node_id, storage endpoints, offline mode).
//! - Installs bilateral, unilateral, app-router, and recovery handlers
//!   into both the SDK dispatch layer and the core bridge layer.
//! - Registers the Android BLE backend and `BluetoothManager` when the
//!   `bluetooth` feature is enabled and device identity is available.
//! - Syncs persisted contacts from SQLite into the `BluetoothManager`.
//!
//! Pre-genesis, minimal bootstrap handlers are installed that return
//! deterministic errors for operations requiring identity, while still
//! serving `sys.tick` queries.

use std::sync::Arc;
use crate::bridge::install_bilateral_handler as install_sdk_bilateral_handler;
use crate::bridge::install_unilateral_handler as install_sdk_unilateral_handler;
use crate::bridge::install_app_router as install_sdk_app_router;
use crate::handlers::{
    handle_create_genesis_v2_query, handle_generate_mnemonic_query, handle_system_genesis_query,
    install_app_router_adapter, AppRouterImpl, BiImpl, UniImpl,
};
use dsm::types::proto as pb;
use prost::Message;

/// Deterministically derive the device's identity signing keypair (SPHINCS+), Genesis v2.
///
/// CANONICAL derivation — the AK keypair rooted in the BIP39 `wallet_seed` (NOT a device
/// secret): `device_seed = KDF(wallet_seed, "DSM/device-seed/v2" || G || 0)`,
/// `AK_seed = KDF(device_seed, "DSM/device-ak/v2" || authority_policy_hash)`,
/// `AK = SPHINCS+.KeyGen(AK_seed)`. Delegates to the SINGLE canonical
/// `dsm::core::identity::genesis_v2::derive_device_ak_keypair`, so the re-derived keypair is
/// byte-identical to the one `create_genesis_v2` registered. Both wallet-init and
/// recovery-authority anchoring MUST call it; a divergent copy would silently break every
/// EK-cert chain + recovery anchor, so the derivation is never duplicated inline. `device_slot`
/// is the primary device (0) and the default genesis authority policy is used — matching genesis.
pub fn derive_device_signing_keypair(
    wallet_seed: &[u8],
    genesis: &[u8; 32],
) -> Result<dsm::crypto::signatures::SignatureKeyPair, dsm::types::error::DsmError> {
    dsm::core::identity::genesis_v2::derive_device_ak_keypair(
        wallet_seed,
        genesis,
        0,
        &dsm::core::identity::genesis_session::genesis_authority_policy_hash(),
    )
}

/// Read a persisted 32-byte identity value from `AppState`, failing closed.
fn app_state_u32_bytes(
    value: Option<Vec<u8>>,
    what: &str,
) -> Result<[u8; 32], dsm::types::error::DsmError> {
    let v = value.ok_or_else(|| {
        dsm::types::error::DsmError::InvalidState(format!("{what} not initialized"))
    })?;
    if v.len() != 32 {
        return Err(dsm::types::error::DsmError::invalid_parameter(format!(
            "{what} must be 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Re-derive the device master seed `Smaster` for the unlocked wallet.
///
/// `s0 = derive_s0(wallet_seed, G, 0, aph)`; `Smaster = derive_smaster(s0, G, DevID, aph)`,
/// where `G` is the persisted genesis digest (`AppState` genesis_hash, == `GenesisV2.g`) and
/// `DevID` is the persisted device id (`AppState` device_id, == `GenesisV2.devid`) — both
/// registered by `create_genesis_v2`. Because `G` and `DevID` are persisted, the only secret
/// input needed is the session-cached `wallet_seed`; `network_id`/`wallet_index`/`atta`/
/// `genesis_nonce` are NOT required to reproduce `Smaster`.
///
/// `Smaster` roots per-step EK seeds and deterministic ML-KEM coins (authorship). It is NEVER
/// persisted and re-derives on demand; anti-clone is the fused anchor, not Smaster.
/// Fails closed when the wallet is locked.
pub fn current_smaster() -> Result<[u8; 32], dsm::types::error::DsmError> {
    use dsm::core::identity::genesis_v2::{derive_s0, derive_smaster};
    let g = app_state_u32_bytes(
        crate::sdk::app_state::AppState::get_genesis_hash(),
        "genesis_hash (G)",
    )?;
    let devid = app_state_u32_bytes(
        crate::sdk::app_state::AppState::get_device_id(),
        "device_id (DevID)",
    )?;
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            dsm::types::error::DsmError::InvalidState(
                "wallet seed unavailable for Smaster re-derivation (wallet locked)".into(),
            )
        })?;
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let s0 = derive_s0(&wallet_seed, &g, 0, &aph);
    Ok(derive_smaster(&s0, &g, &devid, &aph))
}

/// Derive the AEAD key for per-relationship chain-head SK storage at rest.
///
/// `K_at-rest = keyed-BLAKE3(s0, "DSM/chain-head-at-rest/v2" || G || DevID)`. Rooted in `s0`
/// (the recovery path) and domain-separated from authorship (`Smaster`): a copied database is
/// undecryptable without the wallet seed, and a leak of the at-rest key does not expose the
/// authorship root. Replaces the former C-DBRW binding key for SK-at-rest. Fails closed when
/// the wallet is locked.
pub fn current_chain_head_at_rest_key() -> Result<[u8; 32], dsm::types::error::DsmError> {
    use dsm::core::identity::genesis_v2::derive_s0;
    let g = app_state_u32_bytes(
        crate::sdk::app_state::AppState::get_genesis_hash(),
        "genesis_hash (G)",
    )?;
    let devid = app_state_u32_bytes(
        crate::sdk::app_state::AppState::get_device_id(),
        "device_id (DevID)",
    )?;
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            dsm::types::error::DsmError::InvalidState(
                "wallet seed unavailable for chain-head at-rest key (wallet locked)".into(),
            )
        })?;
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let s0 = derive_s0(&wallet_seed, &g, 0, &aph);
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher_keyed(
        dsm::common::domain_tags::TAG_DSM_CHAIN_HEAD_AT_REST_V2,
        &s0,
    );
    hasher.update(&g);
    hasher.update(&devid);
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Debug, Clone)]
pub struct SdkConfig {
    pub node_id: String,
    pub storage_endpoints: Vec<String>,
    pub enable_offline: bool,
}

impl SdkConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty() {
            return Err("node_id cannot be empty".to_string());
        }
        // Offline/BLE mode does not require storage endpoints —
        // the whole point is operating without network connectivity.
        if !self.enable_offline && self.storage_endpoints.is_empty() {
            return Err("storage_endpoints cannot be empty".to_string());
        }
        Ok(())
    }
}

/// Hot-swap the MinimalBootstrapRouter for the full [`AppRouterImpl`] once the canonical identity is
/// ready (device_id present + wallet seed cached). This is the single install path for the
/// *warm* swap — used by `system.createGenesisV2` (fresh wallet) and the JNI `ensureAppRouterInstalled`
/// (post-unlock on restart) — both of which have no [`SdkConfig`] in hand, so it derives one from the
/// storage-endpoint registry (falling back to env config). The cold-boot path in [`init_dsm_sdk`]
/// keeps its caller-supplied `SdkConfig`.
///
/// Idempotent: keyed off [`crate::bridge::full_app_router_installed`] so repeated calls don't rebuild
/// the router. The core adapter reads the router slot live, so the swap takes effect on the next
/// query without touching the adapter registration.
///
/// Returns `Ok(true)` when the full router is installed (now or already), `Ok(false)` when the
/// canonical identity is not yet ready, and `Err` on a hard construction/install failure.
pub(crate) fn install_full_app_router_self_config() -> Result<bool, String> {
    // Identity-keyed idempotency: true only when the installed full router was built for the
    // CURRENT identity (see bridge::full_app_router_installed) — an identity mismatch falls
    // through and rebuilds instead of serving routes under a stale snapshot.
    if crate::bridge::full_app_router_installed() {
        return Ok(true);
    }
    // has_identity participates so a rolled-back failed genesis (which clears it) reads as
    // not-ready here even while device_id/seed linger in the session.
    let device_id = match crate::sdk::app_state::AppState::get_device_id() {
        Some(d) => d,
        None => return Ok(false),
    };
    let canonical_identity_ready = crate::sdk::app_state::AppState::get_has_identity()
        && crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().is_some();
    if !canonical_identity_ready {
        return Ok(false);
    }
    // Storage endpoints: registry first, env config fallback (same source as cold boot).
    let storage_endpoints = match crate::network::list_storage_endpoints() {
        Ok(list) if !list.is_empty() => list,
        _ => match crate::network::NetworkConfigLoader::load_env_config() {
            Ok(env) => env.nodes.into_iter().map(|n| n.endpoint).collect(),
            Err(_) => Vec::new(),
        },
    };
    let cfg = SdkConfig {
        node_id: "default".to_string(),
        storage_endpoints,
        enable_offline: false,
    };
    let app_router = Arc::new(
        AppRouterImpl::new(cfg).map_err(|e| format!("Failed to create AppRouter: {:?}", e))?,
    );
    let app_router_for_rehydrate = Arc::clone(&app_router);
    install_sdk_app_router(app_router)
        .map_err(|e| format!("Failed to install app router: {:?}", e))?;
    install_app_router_adapter(crate::runtime::get_runtime().handle().clone());
    // Receiver-admit fold parity with the cold-boot full-router branch: pinned fused-anchor store so
    // an admitted counterparty pin survives restarts. Does NOT enable live offline-bearer acceptance
    // (the counter reader is a separate device-layer install; an incomplete pin fail-closes Path-B).
    crate::bridge::install_anchor_enrollment_store(Arc::new(
        crate::sdk::anchor_enrollment_store::SqliteAnchorEnrollmentStore::new(),
    ));
    crate::bridge::mark_full_app_router_installed(device_id);
    log::info!("[SDK] Full AppRouter hot-swapped in (canonical identity ready)");
    spawn_token_registry_rehydrate(app_router_for_rehydrate, "warm-swap");
    spawn_acceptance_recovery_sweep("warm-swap");
    Ok(true)
}

/// §16.6 startup acceptance recovery: finish applied-but-incomplete acceptance
/// journals from the durable `CanonicalApplyRecord` — no redelivery required.
/// This init path is SYNCHRONOUS (JNI-invoked) and may already be inside an
/// active Tokio runtime, so NEVER `block_on` here — schedule on the established
/// runtime (same pattern as `startPairingAll`). The wrap key is derived INSIDE
/// the spawned task and the sweep skips fail-closed when the wallet is locked
/// or the DB is not initialized — recovery runs only after the database, wallet
/// keys, and runtime all exist.
/// Re-register persisted tokens' policies after a restart.
///
/// The policy system is in-memory and fails closed for an unregistered token,
/// so without this a token created before the restart could not be transferred
/// and no vault could be built for it. The durable tables are the source of
/// truth; this only rebuilds the derived in-memory view.
fn spawn_token_registry_rehydrate(router: std::sync::Arc<AppRouterImpl>, origin: &'static str) {
    crate::runtime::get_runtime().spawn(async move {
        // Lazy rehydration first: it must be in place before anything can
        // enforce, so a token added after this point is covered too.
        router.install_policy_resolver();
        router.rehydrate_token_registry().await;
        // A token this device created is only adoptable while its policy is
        // fetchable, so make sure the network can still serve it.
        router.republish_owned_policies().await;
        log::debug!("[SDK] token registry rehydrate ({origin}) complete");
    });
}

fn spawn_acceptance_recovery_sweep(origin: &'static str) {
    crate::runtime::get_runtime().spawn(async move {
        match current_chain_head_at_rest_key() {
            Ok(wrap_key) => {
                if let Err(e) =
                    crate::handlers::recipient_receipt::recover_incomplete_acceptances(&wrap_key)
                        .await
                {
                    log::warn!(
                        "[SDK] §16.6 startup acceptance recovery ({origin}) errored (non-fatal): {e}"
                    );
                } else {
                    log::info!("[SDK] §16.6 startup acceptance recovery ({origin}) swept");
                }

                // Durable reconcile-forward. Post-commit projection/history
                // failures persist an intent row; drain it by rebuilding from
                // CANONICAL state. Without this the intent is just a log line
                // that dies with the process.
                let self_device: Option<[u8; 32]> = crate::sdk::app_state::AppState::get_device_id()
                    .and_then(|v| v.as_slice().try_into().ok());
                if let Some(device_id) = self_device {
                    match crate::storage::client_db::drain_projection_repairs(&device_id, |token| {
                        crate::policy::builtin_policy_commit(token)
                    }) {
                        Ok((0, 0)) => {}
                        Ok((repaired, remaining)) => log::info!(
                            "[SDK] projection repair ({origin}): {repaired} rebuilt from canonical, \
                             {remaining} retained"
                        ),
                        Err(e) => log::warn!(
                            "[SDK] projection repair ({origin}) errored (non-fatal): {e}"
                        ),
                    }

                    // Belt-and-braces: rebuild any projection that diverges from the
                    // canonical head, even if a failure was never queued (e.g. 8XK's
                    // projection was blanked out-of-band by the deleted rollback while
                    // its head kept 275). The head is authority; this only touches the
                    // cache.
                    match crate::storage::client_db::reconcile_projections_against_head(&device_id) {
                        Ok((0, _)) => {}
                        Ok((rebuilt, checked)) => log::info!(
                            "[SDK] projection reconcile ({origin}): {rebuilt}/{checked} rebuilt from canonical head"
                        ),
                        Err(e) => log::warn!(
                            "[SDK] projection reconcile ({origin}) errored (non-fatal): {e}"
                        ),
                    }

                    // Heal pre-existing symmetric-space residue: a contact whose
                    // chain_tip diverged from local_bilateral by one accepted
                    // transition (defect-1 era data) is converged from finalized-
                    // proposal evidence, so a send can proceed.
                    match crate::storage::client_db::reconcile_diverged_projection_tips() {
                        Ok(0) => {}
                        Ok(n) => log::info!("[SDK] tip reconcile ({origin}): {n} healed"),
                        Err(e) => log::warn!("[SDK] tip reconcile ({origin}) errored (non-fatal): {e}"),
                    }
                }
            }
            Err(_) => {
                log::debug!(
                    "[SDK] §16.6 startup acceptance recovery ({origin}) skipped (wallet locked)"
                );
            }
        }
    });
}

/// Core bilateral handler that wraps SDK's async BiImpl
struct CoreBilateralBridge {
    sdk_handler: Arc<dyn crate::bridge::BilateralHandler>,
}

/// Core unilateral handler that wraps SDK's async UniImpl
struct CoreUnilateralBridge {
    sdk_handler: Arc<dyn crate::bridge::UnilateralHandler>,
}

impl dsm::core::bridge::UnilateralHandler for CoreUnilateralBridge {
    fn handle_unilateral_invoke(&self, operation: pb::Invoke) -> Result<pb::OpResult, String> {
        // Convert gp::Invoke to UniOp
        // gp::Invoke.args is Option<ArgPack>. UniImpl expects raw bytes in 'data'.
        // For unilateral ops, the ArgPack body contains the payload.
        let data = operation.args.map(|a| a.body).unwrap_or_default();

        let op = crate::bridge::UniOp {
            operation_type: operation.method,
            data,
        };

        let result =
            crate::runtime::get_runtime().block_on(async { self.sdk_handler.handle(op).await });

        if result.success {
            Ok(pb::OpResult {
                op_id: None,
                accepted: true,
                post_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                result: Some(pb::ResultPack {
                    schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                    codec: pb::Codec::Proto as i32,
                    body: result.result_data,
                }),
                error: None,
            })
        } else {
            Err(result
                .error_message
                .unwrap_or_else(|| "Unilateral operation failed".to_string()))
        }
    }
}

impl dsm::core::bridge::BilateralHandler for CoreBilateralBridge {
    fn handle_bilateral_prepare(
        &self,
        operation: pb::BilateralPrepareRequest,
    ) -> Result<pb::OpResult, String> {
        let payload = operation.encode_to_vec();
        let req = crate::bridge::BiPrepare { payload };

        // Spawn async work and block on completion using channel
        let (tx, rx) = std::sync::mpsc::channel();
        let handler = self.sdk_handler.clone();

        crate::runtime::get_runtime().spawn(async move {
            let result = handler.prepare(req).await;
            let _ = tx.send(result);
        });

        let result = rx
            .recv()
            .map_err(|e| format!("Bilateral prepare channel error: {}", e))?;

        if result.success {
            Ok(pb::OpResult {
                op_id: None,
                accepted: true,
                post_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                result: Some(pb::ResultPack {
                    schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                    codec: pb::Codec::Proto as i32,
                    body: result.result_data,
                }),
                error: None,
            })
        } else {
            Err(result
                .error_message
                .unwrap_or_else(|| "Bilateral prepare failed".to_string()))
        }
    }

    fn handle_bilateral_transfer(
        &self,
        operation: pb::BilateralTransferRequest,
    ) -> Result<pb::OpResult, String> {
        let payload = operation.encode_to_vec();
        let req = crate::bridge::BiTransfer { payload };

        let (tx, rx) = std::sync::mpsc::channel();
        let handler = self.sdk_handler.clone();

        crate::runtime::get_runtime().spawn(async move {
            let result = handler.transfer(req).await;
            let _ = tx.send(result);
        });

        let result = rx
            .recv()
            .map_err(|e| format!("Bilateral transfer channel error: {}", e))?;

        if result.success {
            Ok(pb::OpResult {
                op_id: None,
                accepted: true,
                post_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                result: Some(pb::ResultPack {
                    schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                    codec: pb::Codec::Proto as i32,
                    body: result.result_data,
                }),
                error: None,
            })
        } else {
            Err(result
                .error_message
                .unwrap_or_else(|| "Bilateral transfer failed".to_string()))
        }
    }

    fn handle_bilateral_accept(
        &self,
        operation: pb::BilateralAcceptRequest,
    ) -> Result<pb::OpResult, String> {
        let payload = operation.encode_to_vec();
        let req = crate::bridge::BiAccept { payload };

        let (tx, rx) = std::sync::mpsc::channel();
        let handler = self.sdk_handler.clone();

        crate::runtime::get_runtime().spawn(async move {
            let result = handler.accept(req).await;
            let _ = tx.send(result);
        });

        let result = rx
            .recv()
            .map_err(|e| format!("Bilateral accept channel error: {}", e))?;

        if result.success {
            Ok(pb::OpResult {
                op_id: None,
                accepted: true,
                post_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                result: Some(pb::ResultPack {
                    schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                    codec: pb::Codec::Proto as i32,
                    body: result.result_data,
                }),
                error: None,
            })
        } else {
            Err(result
                .error_message
                .unwrap_or_else(|| "Bilateral accept failed".to_string()))
        }
    }

    fn handle_bilateral_commit(
        &self,
        operation: pb::BilateralCommitRequest,
    ) -> Result<pb::OpResult, String> {
        let payload = operation.encode_to_vec();
        let req = crate::bridge::BiCommit { payload };

        let (tx, rx) = std::sync::mpsc::channel();
        let handler = self.sdk_handler.clone();

        crate::runtime::get_runtime().spawn(async move {
            let result = handler.commit(req).await;
            let _ = tx.send(result);
        });

        let result = rx
            .recv()
            .map_err(|e| format!("Bilateral commit channel error: {}", e))?;

        if result.success {
            Ok(pb::OpResult {
                op_id: None,
                accepted: true,
                post_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                result: Some(pb::ResultPack {
                    schema_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
                    codec: pb::Codec::Proto as i32,
                    body: result.result_data,
                }),
                error: None,
            })
        } else {
            Err(result
                .error_message
                .unwrap_or_else(|| "Bilateral commit failed".to_string()))
        }
    }
}

pub fn init_dsm_sdk(cfg: &SdkConfig) -> Result<(), String> {
    // 1) Validate cfg strictly (no probing)
    cfg.validate()?;

    // 1.5) Initialize progress context for deterministic time (sys.tick queries)
    // This must happen before any handlers are installed that might need timing.
    // Initialize with default values - will be updated during bilateral interactions.
    if let Err(e) = dsm::utils::deterministic_time::update_progress_context([0u8; 32], 0) {
        log::warn!("[SDK Init] Failed to initialize progress context: {:?}", e);
    } else {
        log::info!("[SDK Init] Progress context initialized with defaults");
    }

    // 2) Install bilateral handler into BOTH SDK and core layers
    let bi_impl = Arc::new(BiImpl::new(cfg.clone()));

    // Install in SDK layer (for app router invoke paths)
    install_sdk_bilateral_handler(bi_impl.clone());

    // Install in core layer (for envelope-level bilateral operations)
    let core_bridge = Arc::new(CoreBilateralBridge {
        sdk_handler: bi_impl,
    });
    dsm::core::bridge::install_bilateral_handler(core_bridge);

    // 3) Install unilateral handler into BOTH SDK and core layers
    //    Pre-genesis: device identity may not exist yet, so we must not panic.
    //    Instead, install a minimal handler that returns a deterministic error.
    let uni_impl: Arc<dyn crate::bridge::UnilateralHandler + Send + Sync> =
        if crate::sdk::app_state::AppState::get_device_id().is_some() {
            Arc::new(
                UniImpl::new(cfg.clone()).map_err(|e| format!("Failed to create UniImpl: {e}"))?,
            )
        } else {
            struct MinimalUnilateral;

            #[async_trait::async_trait]
            impl crate::bridge::UnilateralHandler for MinimalUnilateral {
                async fn handle(&self, _op: crate::bridge::UniOp) -> crate::bridge::UniResult {
                    crate::bridge::UniResult {
                        success: false,
                        result_data: Vec::new(),
                        error_message: Some("unilateral handler unavailable pre-genesis".into()),
                    }
                }
            }

            Arc::new(MinimalUnilateral)
        };

    install_sdk_unilateral_handler(uni_impl.clone());

    let core_uni_bridge = Arc::new(CoreUnilateralBridge {
        sdk_handler: uni_impl,
    });
    dsm::core::bridge::install_unilateral_handler(core_uni_bridge);

    // 4) Install AppRouter into BOTH SDK and core layers
    //    - If canonical identity context is ready: full AppRouter
    //    - Otherwise: minimal bootstrap router (sys.tick + narrow bootstrap queries)
    //
    // IMPORTANT:
    // This init function can be called more than once per process lifetime (e.g. Android
    // WebView/bridge re-inits after createGenesisV2). Therefore, we must always prefer the
    // full router when identity is available, even if a MinimalBootstrapRouter was installed
    // earlier.
    let boot_device_id = crate::sdk::app_state::AppState::get_device_id();
    let canonical_identity_ready = boot_device_id.is_some()
        && crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().is_some();

    if let (true, Some(device_id)) = (canonical_identity_ready, boot_device_id) {
        let app_router = Arc::new(
            AppRouterImpl::new(cfg.clone())
                .map_err(|e| format!("Failed to create AppRouter: {:?}", e))?,
        );
        let app_router_for_rehydrate = Arc::clone(&app_router);
        install_sdk_app_router(app_router)
            .map_err(|e| format!("Failed to install app router: {:?}", e))?;
        install_app_router_adapter(crate::runtime::get_runtime().handle().clone());
        // Receiver-admit fold: persistent pinned-anchor store, so an admitted counterparty pin
        // survives restarts (a restart must never re-open the first-transfer TOFU window).
        crate::bridge::install_anchor_enrollment_store(Arc::new(
            crate::sdk::anchor_enrollment_store::SqliteAnchorEnrollmentStore::new(),
        ));
        crate::bridge::mark_full_app_router_installed(device_id);
        log::info!("[SDK Init] Full AppRouter installed (device identity ready)");
        spawn_token_registry_rehydrate(app_router_for_rehydrate, "cold-boot");
        spawn_acceptance_recovery_sweep("cold-boot");
    } else {
        // Install minimal bootstrap router for pre-genesis queries
        use crate::bridge::{AppQuery, AppInvoke, AppResult};
        use prost::Message;

        struct MinimalBootstrapRouter;

        #[async_trait::async_trait]
        impl crate::bridge::AppRouter for MinimalBootstrapRouter {
            async fn query(&self, q: AppQuery) -> AppResult {
                match q.path.as_str() {
                    "sys.tick" => {
                        let tick = dsm::performance::mono_commit_height();
                        let result_pack = dsm::types::proto::ResultPack {
                            schema_hash: Some(dsm::types::proto::Hash32 { v: vec![0u8; 32] }),
                            codec: dsm::types::proto::Codec::Proto as i32,
                            body: tick.to_le_bytes().to_vec(),
                        };
                        let mut data = Vec::new();
                        if let Err(e) = result_pack.encode(&mut data) {
                            return AppResult {
                                success: false,
                                data: Vec::new(),
                                error_message: Some(format!("Failed to encode ResultPack: {e}")),
                            };
                        }
                        AppResult {
                            success: true,
                            data,
                            error_message: None,
                        }
                    }
                    "system.genesis" => handle_system_genesis_query(q),
                    // Pre-genesis wallet CREATION is the bootstrap itself and must be allowed here:
                    // generateMnemonic is pure (OsRng -> BIP39), and createGenesisV2 derives the
                    // wallet seed + establishes the identity — after which a re-init installs the full
                    // router. Without these, a fresh device can never create a wallet (chicken-and-egg).
                    "system.generateMnemonic" => handle_generate_mnemonic_query(),
                    "system.createGenesisV2" => handle_create_genesis_v2_query(q),
                    _ => AppResult {
                        success: false,
                        data: Vec::new(),
                        error_message: Some(format!(
                            "MinimalBootstrapRouter: query '{}' requires genesis",
                            q.path
                        )),
                    },
                }
            }

            async fn invoke(&self, i: AppInvoke) -> AppResult {
                AppResult {
                    success: false,
                    data: Vec::new(),
                    error_message: Some(format!(
                        "MinimalBootstrapRouter: invoke '{}' requires genesis",
                        i.method
                    )),
                }
            }
        }

        install_sdk_app_router(Arc::new(MinimalBootstrapRouter))
            .map_err(|e| format!("Failed to install minimal bootstrap router: {:?}", e))?;
        install_app_router_adapter(crate::runtime::get_runtime().handle().clone());
        log::info!("[SDK Init] Minimal bootstrap router installed (awaiting genesis)");
    }

    // 5) Install recovery handler into core layer
    let recovery_impl = Arc::new(crate::handlers::RecoveryImpl::new());
    dsm::core::bridge::install_recovery_handler(recovery_impl);

    log::info!("[SDK Init] Core handlers (Unilateral, Bilateral, Recovery) installed successfully");

    // 6) Register BLE backend (Android only; protobuf-only). This wires router → BLE path.
    // IMPORTANT: BLE init can be deferred if identity is not ready, but the core handlers above
    // must remain installed so queries like sys.tick work before genesis.
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    {
        use crate::ble::android_backend::AndroidBleBackend;
        crate::ble::register_ble_backend(AndroidBleBackend::new());
        log::info!("[SDK Init] AndroidBleBackend registered");

        // Create and register BluetoothManager using AppState identity.
        // Identity MUST be available - this is called post-genesis only.
        use tokio::sync::RwLock as TokioRwLock;
        use dsm::core::{
            contact_manager::DsmContactManager,
            bilateral_transaction_manager::BilateralTransactionManager,
        };

        let (dev, gen) = match (
            crate::sdk::app_state::AppState::get_device_id(),
            crate::sdk::app_state::AppState::get_genesis_hash(),
        ) {
            (Some(d), Some(g)) => (d, g),
            _ => {
                // Identity not ready: Skip BT init but SDK is still functional for queries.
                // BLE can be late-initialized via initializeBilateralSdk once genesis is created.
                log::warn!("[SDK Init] BluetoothManager identity not ready (device_id/genesis missing). Skipping BT init; will allow late init.");
                return Ok(());
            }
        };

        let mut dev_fixed = [0u8; 32];
        let mut gen_fixed = [0u8; 32];
        if dev.len() != 32 || gen.len() != 32 {
            log::error!("[SDK Init] device_id and genesis_hash must be exactly 32 bytes");
            return Err("device_id and genesis_hash must be exactly 32 bytes".to_string());
        }
        dev_fixed.copy_from_slice(&dev);
        gen_fixed.copy_from_slice(&gen);

        // Backfill Device Tree root (§2.3) for existing identities created before this was
        // persisted at genesis time.  The root of a single-device tree is deterministic from
        // dev_fixed, so it is always safe to recompute and overwrite.
        // Without the root, build_bilateral_receipt_with_smt returns None → proof_data None →
        // settle() rejects every bilateral transfer → balance never updates.
        {
            let root = dsm::common::device_tree::DeviceTree::single(dev_fixed).root();
            crate::sdk::app_state::AppState::set_device_tree_root(root);
            log::info!(
                "[SDK Init] Device tree root computed and persisted (dev={})",
                crate::util::text_id::encode_base32_crockford(&dev_fixed)
            );
        }

        // Bootstrap-time validation gate (§2.3.1): Ensure device_tree_root is always present.
        // If any earlier initialization step is skipped or fails, recover here.
        // This prevents silent bilateral transfer failures post-initialization.
        if crate::sdk::app_state::AppState::get_device_tree_root().is_none() {
            log::warn!("[SDK Init Validation] device_tree_root is None — emergency backfill from device_id");
            let root = dsm::common::device_tree::DeviceTree::single(dev_fixed).root();
            crate::sdk::app_state::AppState::set_device_tree_root(root);
            log::info!("[SDK Init Validation] Emergency backfill successful — R_G now available");
        }

        let contact_manager =
            DsmContactManager::new(dev_fixed, vec![dsm::types::identifiers::NodeId::new("n")]);

        // Genesis v2: the device signing keypair is the AK keypair derived deterministically
        // from the BIP39 wallet seed (mnemonic.to_seed) — byte-identical to what
        // create_genesis_v2 registered. No DBRW / device secret. The wallet seed is the
        // unlocked-session secret; it is cached at unlock (RecoverySDK::derive_and_cache_key)
        // and sealed at rest, so on a cold start we first try the hardware seed vault before
        // demanding the mnemonic again. A missing/auth-gated bundle fails closed → locked UI.
        if crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().is_none() {
            match crate::sdk::recovery_sdk::RecoverySDK::load_and_cache_wallet_seed() {
                Ok(true) => log::info!("[SDK Init] Wallet seed unsealed from vault (cold start)"),
                Ok(false) => {
                    log::info!("[SDK Init] No sealed wallet seed — mnemonic unlock required")
                }
                Err(e) => {
                    log::warn!("[SDK Init] Seed vault unlock failed ({e}) — mnemonic required")
                }
            }
        }
        let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
            .ok_or_else(|| {
                "wallet seed not unlocked: cache the mnemonic (RecoverySDK::derive_and_cache_key) \
                 before initializing wallet/signing"
                    .to_string()
            })?;
        let keypair = derive_device_signing_keypair(&wallet_seed, &gen_fixed)
            .map_err(|e| format!("device signing keypair derivation failed: {e}"))?;
        log::info!(
            "[SDK Init] Derived signing keypair, pubkey_len={}",
            keypair.public_key.len()
        );

        // Persist the derived public key to AppState if missing or empty.
        // This fixes users whose genesis was created before signing key persistence was added,
        // or whose key generation silently failed during genesis.
        let stored_pk = crate::sdk::app_state::AppState::get_public_key();
        if stored_pk.as_ref().map_or(true, |v| v.is_empty()) {
            log::info!(
                "[SDK Init] Persisting derived signing public key to AppState (len={})",
                keypair.public_key.len()
            );
            let smt =
                crate::sdk::app_state::AppState::get_smt_root().unwrap_or_else(|| vec![0u8; 32]);
            crate::sdk::app_state::AppState::set_identity_info(
                dev.clone(),
                keypair.public_key.clone(),
                gen.clone(),
                smt,
            );
        }

        let chain_tip_store =
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new());
        let manager = BilateralTransactionManager::new_with_chain_tip_store(
            contact_manager,
            keypair,
            dev_fixed,
            gen_fixed,
            chain_tip_store,
        );
        let btx = std::sync::Arc::new(TokioRwLock::new(manager));
        let manager_arc =
            std::sync::Arc::new(crate::bluetooth::BluetoothManager::new(dev_fixed, btx));

        let _ = crate::bluetooth::register_global_bluetooth_manager(manager_arc.clone());
        log::info!("[SDK Init] BluetoothManager registered globally");

        // Inject BLE frame coordinator into BiImpl so offline sends dispatch over BLE.
        // Use a separate thread with its own runtime to avoid "Cannot start a runtime
        // within a runtime" when init_dsm_sdk is called from an async context (e.g.
        // createGenesis's block_on future).
        let coordinator = manager_arc.frame_coordinator().clone();
        let transport_adapter = manager_arc.transport_adapter().clone();
        let ble_inject_result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("ble coordinator runtime: {e}"))?;
            rt.block_on(async move {
                crate::bridge::inject_ble_coordinator(coordinator).await?;
                crate::bridge::inject_ble_transport_adapter(transport_adapter).await
            })
        })
        .join();
        match ble_inject_result {
            Ok(Ok(_)) => log::info!(
                "[SDK Init] BLE coordinator and transport adapter injected into bilateral handler"
            ),
            Ok(Err(e)) => log::warn!("[SDK Init] BLE injection failed: {e}"),
            Err(_) => log::warn!("[SDK Init] BLE injection thread panicked"),
        }

        // Load existing contacts from SQLite and sync to BluetoothManager SYNCHRONOUSLY
        // We're inside a tokio runtime context (from JNI), so we spawn a std::thread
        // that creates its own runtime to avoid "Cannot start a runtime within a runtime"
        let manager_for_sync = manager_arc.clone();
        let handle = std::thread::spawn(move || {
            // Create a fresh runtime just for this sync operation
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("[SDK Init] Failed to create sync runtime: {e}");
                    return;
                }
            };

            rt.block_on(async move {
                match crate::storage::client_db::get_all_contacts() {
                    Ok(contacts) => {
                        log::warn!(
                            "[SDK Init] 🔵 Syncing {} contacts to BluetoothManager",
                            contacts.len()
                        );
                        for c in contacts {
                            let Some(verified_contact) = c.to_verified_contact() else {
                                log::warn!("[SDK Init] ⚠️ Skipping contact with invalid lengths");
                                continue;
                            };
                            log::warn!(
                                "[SDK Init] 🔵 Syncing contact alias={} public_key_len={}",
                                c.alias,
                                c.public_key.len()
                            );
                            if let Err(e) = manager_for_sync
                                .add_verified_contact(verified_contact)
                                .await
                            {
                                log::warn!(
                                    "[SDK Init] ❌ Failed to sync contact {}: {}",
                                    c.alias,
                                    e
                                );
                            } else {
                                log::warn!(
                                    "[SDK Init] ✅ Synced contact {} to BluetoothManager",
                                    c.alias
                                );
                            }
                        }
                        log::warn!("[SDK Init] 🔵 Contact sync to BluetoothManager complete");
                    }
                    Err(e) => {
                        log::warn!("[SDK Init] ❌ Failed to load contacts for sync: {}", e);
                    }
                }
            });
        });

        // Block until contact sync completes. Without this, the BilateralBleHandler's
        // in-memory ContactManager is empty when the first BLE prepare arrives, causing
        // "Sender not found in verified contacts" rejections. The sync is fast (single
        // SQLite query + HashMap inserts) — typically <50ms even with dozens of contacts.
        match handle.join() {
            Ok(_) => log::info!("[SDK Init] Contact sync thread completed"),
            Err(_) => log::warn!("[SDK Init] Contact sync thread panicked"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::derive_device_signing_keypair;

    #[test]
    fn device_signing_keypair_derivation_is_deterministic_and_sensitive() {
        // Genesis v2: the device signing (AK) keypair derives from (wallet_seed, G).
        let wallet_seed = [0x33u8; 64];
        let g = [0x11u8; 32];
        let a = derive_device_signing_keypair(&wallet_seed, &g).expect("derive a");
        let b = derive_device_signing_keypair(&wallet_seed, &g).expect("derive b");
        // Deterministic: same inputs → byte-identical keypair (the property that lets
        // recovery re-derive the device key without persisting the secret).
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.secret_key, b.secret_key);
        // Sensitive: changing the wallet seed changes the keypair.
        assert_ne!(
            a.public_key,
            derive_device_signing_keypair(&[0x99; 64], &g)
                .unwrap()
                .public_key
        );
        // Sensitive: changing the genesis digest G changes the keypair.
        assert_ne!(
            a.public_key,
            derive_device_signing_keypair(&wallet_seed, &[0x99; 32])
                .unwrap()
                .public_key
        );
    }
}
