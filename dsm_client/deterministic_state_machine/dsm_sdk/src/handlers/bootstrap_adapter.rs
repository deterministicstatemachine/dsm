// dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bootstrap_adapter.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core bridge BootstrapHandler adapter implemented in the SDK.
//! Provides early handling for system.genesis before full AppRouter/SDK context.

use std::sync::Arc;

use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::proto as generated;
use prost::Message;

// ✅ IMPORTANT: bring the trait into scope so Arc<AppRouterImpl> gets .query/.invoke
use crate::bridge::AppRouter as SdkAppRouter;

use crate::bridge::install_unilateral_handler;
use crate::handlers::UniImpl;

/// Adapter that executes the real MPC genesis flow and returns a protobuf body
struct CoreBootstrapAdapter;

impl CoreBootstrapAdapter {
    fn new() -> Self {
        CoreBootstrapAdapter
    }

    fn run_system_genesis(req: generated::SystemGenesisRequest) -> Result<Vec<u8>, String> {
        // Validate entropy strictly
        let entropy = req.device_entropy.clone();
        if entropy.len() != 32 {
            return Err("system.genesis: device_entropy must be 32 bytes".to_string());
        }

        let fut = async move {
            log::info!(
                "Creating Genesis via MPC with storage nodes (permissionless entropy gathering)"
            );

            let storage_endpoints = crate::network::list_storage_endpoints().unwrap_or_default();
            let storage_node_ids: Vec<dsm::types::NodeId> = storage_endpoints
                .iter()
                .map(|url| dsm::types::NodeId::new(url.clone()))
                .collect();

            let device_id_array: [u8; 32] = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&entropy);
                arr
            };

            // Per whitepaper §2.5: n-of-n MPC; all storage nodes contribute.
            let participant_count = storage_node_ids.len() as u32;
            // Bootstrap K_DBRW per whitepaper §11.1 + §12 — deterministic
            // placeholder until real silicon fingerprinting wires here.
            let k_dbrw = dsm::crypto::cdbrw_binding::derive_bootstrap_k_dbrw(&device_id_array)
                .map_err(|e| format!("K_DBRW bootstrap derivation failed: {e}"))?;
            let genesis_state = dsm::core::identity::genesis::create_genesis_via_blind_mpc(
                device_id_array,
                storage_node_ids,
                k_dbrw,
                Some(entropy.clone()),
            )
            .await
            .map_err(|e| format!("MPC genesis failed: {e}"))?;

            let genesis_bytes = genesis_state.hash;
            log::info!("Genesis created via MPC (canonical root of all hash chains)");

            let device_id_label = String::from_utf8_lossy(&entropy[..8]).to_string();

            let device_id = dsm::core::identity::genesis::derive_device_sub_genesis(
                &genesis_state,
                &device_id_label,
                &entropy,
            )
            .map_err(|e| format!("Device ID derivation failed: {e}"))?;

            let device_id_bytes = device_id.hash;

            let public_key =
                crate::sdk::app_state::AppState::get_public_key().unwrap_or_else(|| {
                    let mut hasher = dsm_domain_hasher("DSM/device-key");
                    hasher.update(&device_id_bytes);
                    let seed = hasher.finalize();
                    seed.as_bytes()[0..32].to_vec()
                });

            let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
                dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
            )
            .to_vec();

            crate::sdk::app_state::AppState::set_identity_info(
                device_id_bytes.to_vec(),
                public_key.clone(),
                genesis_bytes.to_vec(),
                smt_root,
            );
            crate::sdk::app_state::AppState::set_has_identity(true);

            log::info!("Persisted identity: Genesis → DeviceID → SMT → HashChains");

            // ---- Persist genesis record to SQLite ----
            // Without this, local_genesis_hash() returns error, storage.sync fails,
            // and bilateral transfers are blocked.
            {
                let genesis_id_b32 = crate::util::text_id::encode_base32_crockford(&genesis_bytes);
                let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id_bytes);
                let genesis_record = crate::storage::client_db::GenesisRecord {
                    genesis_id: genesis_id_b32.clone(),
                    device_id: device_id_b32.clone(),
                    mpc_proof: String::new(),
                    dbrw_binding: crate::util::text_id::encode_base32_crockford(&entropy),
                    merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
                    participant_count,
                    progress_marker: "genesis".to_string(),
                    publication_hash: genesis_id_b32,
                    storage_nodes: storage_endpoints.clone(),
                    entropy_hash: crate::util::text_id::encode_base32_crockford(
                        dsm::crypto::blake3::domain_hash("DSM/genesis-entropy", &entropy)
                            .as_bytes(),
                    ),
                    protocol_version: "v3".to_string(),
                    hash_chain_proof: None,
                    smt_proof: None,
                    verification_step: None,
                };
                match crate::storage::client_db::store_genesis_record_with_verification(
                    &genesis_record,
                ) {
                    Ok(_) => log::info!("bootstrap: genesis record stored successfully"),
                    Err(e) => log::warn!("bootstrap: failed to store genesis record: {}", e),
                }
                match crate::storage::client_db::ensure_wallet_state_for_device(&device_id_b32) {
                    Ok(_) => log::info!(
                        "bootstrap: wallet_state ensured for device={}",
                        &device_id_b32[..8]
                    ),
                    Err(e) => {
                        log::warn!("bootstrap: failed to ensure wallet_state: {}", e)
                    }
                }
            }

            let init_result = crate::get_sdk_context().initialize(
                device_id_bytes.to_vec(),
                genesis_bytes.to_vec(),
                entropy.clone(),
            );

            if let Err(e) = init_result {
                log::warn!("SDK context re-init failed (may be harmless): {e}");
            } else {
                log::info!("SDK context initialized with genesis identity");
            }

            log::info!("Installing app router after genesis creation");

            let endpoints = crate::network::list_storage_endpoints().unwrap_or_default();
            let cfg = crate::init::SdkConfig {
                node_id: "default".to_string(),
                storage_endpoints: endpoints,
                enable_offline: false,
            };

            let cfg_for_router = cfg.clone();
            let sdk_router = Arc::new(
                crate::handlers::AppRouterImpl::new(cfg_for_router)
                    .map_err(|e| format!("Failed to create AppRouter after genesis: {:?}", e))?,
            );

            struct CoreRouterAdapter {
                sdk_router: Arc<crate::handlers::AppRouterImpl>,
                runtime: &'static tokio::runtime::Runtime,
            }

            impl dsm::core::AppRouter for CoreRouterAdapter {
                fn handle_query(&self, path: &str, params_proto: &[u8]) -> Result<Vec<u8>, String> {
                    log::info!(
                        "[CORE_BOOTSTRAP_ROUTER_ADAPTER] handle_query path={} params_len={}",
                        path,
                        params_proto.len()
                    );

                    let query = crate::bridge::AppQuery {
                        path: path.to_string(),
                        params: params_proto.to_vec(),
                    };

                    // ✅ trait is in scope => .query resolves
                    let result = self
                        .runtime
                        .block_on(async { self.sdk_router.query(query).await });

                    if result.success {
                        log::info!(
                            "[CORE_BOOTSTRAP_ROUTER_ADAPTER] query success path={} data_len={}",
                            path,
                            result.data.len()
                        );
                        Ok(result.data)
                    } else {
                        log::warn!(
                            "[CORE_BOOTSTRAP_ROUTER_ADAPTER] query error path={} err={:?}",
                            path,
                            result.error_message
                        );
                        Err(result
                            .error_message
                            .unwrap_or_else(|| "Query failed".to_string()))
                    }
                }

                fn handle_invoke(
                    &self,
                    method: &str,
                    args_proto: &[u8],
                ) -> Result<(Vec<u8>, Vec<u8>), String> {
                    let invoke = crate::bridge::AppInvoke {
                        method: method.to_string(),
                        args: args_proto.to_vec(),
                    };

                    // ✅ trait is in scope => .invoke resolves
                    let result = self
                        .runtime
                        .block_on(async { self.sdk_router.invoke(invoke).await });

                    if result.success {
                        let post_state = vec![0u8; 32];
                        Ok((result.data, post_state))
                    } else {
                        Err(result
                            .error_message
                            .unwrap_or_else(|| "Invoke failed".to_string()))
                    }
                }
            }

            let runtime = crate::runtime::get_runtime();
            let adapter = Arc::new(CoreRouterAdapter {
                sdk_router,
                runtime,
            });

            dsm::core::install_app_router(adapter)
                .map_err(|e| format!("Failed to install app router: {e}"))?;

            log::info!("App router installed into CORE bridge - SDK is now fully operational");

            log::info!("Installing unilateral handler post-genesis");
            let uni_impl =
                UniImpl::new(cfg.clone()).map_err(|e| format!("Failed to create UniImpl: {e}"))?;
            install_unilateral_handler(Arc::new(uni_impl));
            log::info!("Unilateral handler installed post-genesis");

            log::info!(
                "Genesis creation complete: MPC canonical root → cached locally + stored on storage nodes"
            );

            let resp = generated::SystemGenesisResponse {
                genesis_hash: Some(generated::Hash32 {
                    v: genesis_bytes.to_vec(),
                }),
                public_key,
            };

            let mut out = Vec::new();
            resp.encode(&mut out)
                .map_err(|e| format!("encode SystemGenesisResponse failed: {e}"))?;

            Ok::<Vec<u8>, String>(out)
        };

        crate::runtime::get_runtime().block_on(fut)
    }
}

impl dsm::core::BootstrapHandler for CoreBootstrapAdapter {
    fn handle_system_genesis(
        &self,
        req: generated::SystemGenesisRequest,
    ) -> Result<Vec<u8>, String> {
        Self::run_system_genesis(req)
    }
}

/// Idempotent installation exposed to JNI/init layer
pub fn install_bootstrap_adapter() {
    use dsm::core::install_bootstrap_handler;
    install_bootstrap_handler(Arc::new(CoreBootstrapAdapter::new()));
}
