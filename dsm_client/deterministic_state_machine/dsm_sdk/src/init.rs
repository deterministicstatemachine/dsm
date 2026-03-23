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
use crate::handlers::{BiImpl, UniImpl, AppRouterImpl, install_app_router_adapter};
use dsm::types::proto as pb;
use prost::Message;

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
    //    - If device_id is ready: full AppRouter
    //    - If device_id is missing: minimal bootstrap router (sys.tick only)
    //
    // IMPORTANT:
    // This init function can be called more than once per process lifetime (e.g. Android
    // WebView/bridge re-inits after createGenesisV2). Therefore, we must always prefer the
    // full router when identity is available, even if a MinimalBootstrapRouter was installed
    // earlier.
    if crate::sdk::app_state::AppState::get_device_id().is_some() {
        let app_router = Arc::new(
            AppRouterImpl::new(cfg.clone())
                .map_err(|e| format!("Failed to create AppRouter: {:?}", e))?,
        );
        install_sdk_app_router(app_router)
            .map_err(|e| format!("Failed to install app router: {:?}", e))?;
        install_app_router_adapter(crate::runtime::get_runtime().handle().clone());
        log::info!("[SDK Init] Full AppRouter installed (device identity ready)");
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
        use dsm::crypto::signatures::SignatureKeyPair;

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

        let contact_manager =
            DsmContactManager::new(dev_fixed, vec![dsm::types::identifiers::NodeId::new("n")]);

        // CRITICAL: Derive signing keypair deterministically from genesis + device_id + DBRW.
        // DBRW is mandatory for wallet initialization/signing availability, but it must NOT
        // participate in genesis creation.
        //
        // Per whitepaper: S_master = HKDF(G || DevID || K_DBRW || s_0)
        let dbrw_key = crate::jni::cdbrw::get_cdbrw_binding_key().ok_or_else(|| {
            "C-DBRW not initialized: call sdkBootstrap (or platform C-DBRW init) before initializing wallet/signing"
                .to_string()
        })?;
        if dbrw_key.len() != 32 {
            return Err(format!(
                "DBRW binding key must be 32 bytes, got {}",
                dbrw_key.len()
            ));
        }
        let mut dbrw_fixed = [0u8; 32];
        dbrw_fixed.copy_from_slice(&dbrw_key);

        // Get DBRW binding key for bilateral transaction gating (Canon 1)
        // Note: Health state tracking removed - always proceed

        let mut key_entropy = Vec::with_capacity(96);
        key_entropy.extend_from_slice(&gen_fixed);
        key_entropy.extend_from_slice(&dev_fixed);
        key_entropy.extend_from_slice(&dbrw_fixed);
        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| format!("deterministic keypair derivation failed: {e}"))?;
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
        let btx = std::sync::Arc::new(TokioRwLock::new(
            BilateralTransactionManager::new_with_chain_tip_store(
                contact_manager,
                keypair,
                dev_fixed,
                gen_fixed,
                chain_tip_store,
            ),
        ));
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

        // Let contact sync complete asynchronously — it is not required for SDK
        // readiness and BluetoothManager is thread-safe (Arc<RwLock>).  Blocking
        // here delays the entire init pipeline and pushes the UI-thread callback
        // later, extending perceived unresponsiveness on slower devices.
        drop(handle);
    }

    Ok(())
}
