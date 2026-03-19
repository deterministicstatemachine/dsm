// SPDX-License-Identifier: MIT OR Apache-2.0
//! System, state, and sys route handlers.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use crate::storage::client_db::export_state_blob;
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, pack_bytes_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for `state.*` and `sys.*` query routes.
    pub(crate) async fn handle_state_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- state.export (QueryOp) --------
            "state.export" => match export_state_blob() {
                Ok(bytes) => pack_bytes_ok(bytes, generated::Hash32 { v: vec![0u8; 32] }),
                Err(e) => err(format!("state.export failed: {e}")),
            },
            // -------- state.info (QueryOp) --------
            "state.info" => match crate::storage::client_db::export_state_info() {
                Ok(info) => {
                    // Convert from generated::StateInfoResponse to dsm::types::proto::StateInfoResponse
                    // (both are from same proto, just different crate scopes)
                    let dsm_info = dsm::types::proto::StateInfoResponse {
                        has_genesis: info.has_genesis,
                        has_wallet: info.has_wallet,
                        contacts_count: info.contacts_count,
                        transactions_count: info.transactions_count,
                        preferences_count: info.preferences_count,
                    };
                    pack_envelope_ok(generated::envelope::Payload::StateInfoResponse(dsm_info))
                }
                Err(e) => err(format!("state.info failed: {e}")),
            },
            // -------- sys.tick (QueryOp) --------
            "sys.tick" => {
                let tick = dsm::performance::mono_commit_height();
                pack_bytes_ok(
                    tick.to_le_bytes().to_vec(),
                    generated::Hash32 { v: vec![0u8; 32] },
                )
            }
            _ => err(format!("unknown state query: {}", q.path)),
        }
    }

    /// Dispatch handler for `system.*` query routes.
    pub(crate) async fn handle_system_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- system.genesis (QueryOp) --------
            "system.genesis" => {
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("system.genesis: ArgPack.codec must be PROTO".into());
                }
                // Decode SystemGenesisRequest
                let req = match generated::SystemGenesisRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode SystemGenesisRequest failed: {e}")),
                };

                // Validate entropy
                let entropy = req.device_entropy.clone();
                if entropy.len() != 32 {
                    return err("system.genesis: device_entropy must be 32 bytes".into());
                }

                // Perform MPC-only genesis using storage node SDK
                let fut = async move {
                    let cfg =
                        match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                            .await
                        {
                            Ok(cfg) => cfg,
                            Err(e) => {
                                return Err(format!("No storage node config available: {}", e))
                            }
                        };
                    let res = crate::sdk::storage_node_sdk::StorageNodeSDK::new(cfg)
                        .await
                        .map_err(|e| format!("sdk.new: {e}"))?
                        .create_genesis_with_mpc(Some(3), Some(entropy.clone()))
                        .await
                        .map_err(|e| {
                            format!("MPC genesis failed (strict; no alternate path): {e}")
                        })?;

                    // Persist identity immediately
                    let device_id = res.genesis_device_id.clone();
                    let genesis_hash = res.genesis_hash.clone().unwrap_or_else(|| vec![0u8; 32]);
                    let public_key =
                        crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
                    let smt_root = vec![0u8; 32];

                    crate::sdk::app_state::AppState::set_identity_info(
                        device_id.clone(),
                        public_key.clone(),
                        genesis_hash.clone(),
                        smt_root.clone(),
                    );
                    crate::sdk::app_state::AppState::set_has_identity(true);

                    let _ = crate::initialize_sdk_context(
                        device_id.clone(),
                        genesis_hash.clone(),
                        entropy.clone(),
                    );

                    // Build GenesisCreated (full response for Envelope payload)
                    let resp = generated::GenesisCreated {
                        device_id: device_id.clone(),
                        genesis_hash: Some(generated::Hash32 {
                            v: genesis_hash.clone(),
                        }),
                        public_key: public_key.clone(),
                        smt_root: Some(generated::Hash32 {
                            v: smt_root.clone(),
                        }),
                        device_entropy: entropy.clone(),
                        session_id: String::new(),
                        threshold: 3,
                        storage_nodes: vec![],
                        network_id: req.network_id.clone(),
                        locale: req.locale.clone(),
                    };

                    Ok::<generated::GenesisCreated, String>(resp)
                };

                let resp = match crate::runtime::get_runtime().block_on(fut) {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };

                // Return as Envelope.genesisCreatedResponse (field 25)
                pack_envelope_ok(generated::envelope::Payload::GenesisCreatedResponse(resp))
            }
            // -------- system.secondary_device (Add device to existing genesis) --------
            "system.secondary_device" => {
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("system.secondary_device: ArgPack.codec must be PROTO".into());
                }
                // Decode SecondaryDeviceRequest
                let req = match generated::SecondaryDeviceRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode SecondaryDeviceRequest failed: {e}")),
                };

                // Validate inputs
                if req.genesis_hash.len() != 32 {
                    return err("system.secondary_device: genesis_hash must be 32 bytes".into());
                }
                if req.device_entropy.len() != 32 {
                    return err("system.secondary_device: device_entropy must be 32 bytes".into());
                }

                let fut = async move {
                    let cfg =
                        match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                            .await
                        {
                            Ok(cfg) => cfg,
                            Err(e) => {
                                return Err(format!("No storage node config available: {}", e))
                            }
                        };
                    let res = crate::sdk::storage_node_sdk::StorageNodeSDK::new(cfg)
                        .await
                        .map_err(|e| format!("sdk.new: {e}"))?
                        .add_secondary_device(req.genesis_hash.clone(), req.device_entropy.clone())
                        .await
                        .map_err(|e| format!("Secondary device binding failed: {e}"))?;

                    // Persist identity
                    let device_id = res.genesis_device_id.clone();
                    let genesis_hash = req.genesis_hash.clone();
                    let public_key =
                        crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
                    let smt_root = vec![0u8; 32];

                    crate::sdk::app_state::AppState::set_identity_info(
                        device_id.clone(),
                        public_key.clone(),
                        genesis_hash.clone(),
                        smt_root,
                    );
                    crate::sdk::app_state::AppState::set_has_identity(true);

                    let _ = crate::initialize_sdk_context(
                        device_id.clone(),
                        genesis_hash.clone(),
                        req.device_entropy.clone(),
                    );

                    // Build SecondaryDeviceResponse
                    let resp = generated::SecondaryDeviceResponse {
                        device_id,
                        genesis_hash: Some(generated::Hash32 { v: genesis_hash }),
                        success: true,
                    };
                    Ok::<generated::SecondaryDeviceResponse, String>(resp)
                };

                let resp = match crate::runtime::get_runtime().block_on(fut) {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };

                // Return as Envelope.secondaryDeviceResponse (field 43)
                pack_envelope_ok(generated::envelope::Payload::SecondaryDeviceResponse(resp))
            }
            _ => err(format!("unknown system query: {}", q.path)),
        }
    }
}
