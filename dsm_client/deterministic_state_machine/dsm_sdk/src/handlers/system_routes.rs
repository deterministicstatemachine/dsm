// SPDX-License-Identifier: MIT OR Apache-2.0
//! System, state, and sys route handlers.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::storage::client_db::export_state_blob;
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, pack_bytes_ok, err};

pub(crate) fn handle_system_genesis_query(q: AppQuery) -> AppResult {
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

    // Validate entropy before touching the network.
    let entropy = req.device_entropy.clone();
    if entropy.len() != 32 {
        return err("system.genesis: device_entropy must be 32 bytes".into());
    }
    if req.cdbrw_hw_entropy.is_empty() {
        return err("system.genesis: cdbrw_hw_entropy is required".into());
    }
    if req.cdbrw_env_fingerprint.is_empty() {
        return err("system.genesis: cdbrw_env_fingerprint is required".into());
    }
    // Stage the silicon-binding inputs in the platform-entropy slot so the
    // inner MPC genesis path (StorageNodeSDK::create_genesis_with_mpc →
    // core_sdk::create_genesis_with_passive_contributors) can derive the
    // canonical K_DBRW post-MPC from
    //   `derive_cdbrw_binding_key(genesis_hash, device_id = genesis_hash, hw, env)`
    // and stash it via `binding_key::install_binding_key`. We DO NOT pre-derive
    // K_DBRW here — the canonical preimage requires `genesis_hash` which is an
    // MPC output, not an input.
    if let Err(e) = crate::sdk::app_state::AppState::set_platform_entropy_inputs(
        req.cdbrw_hw_entropy.clone(),
        req.cdbrw_env_fingerprint.clone(),
    ) {
        return err(format!(
            "system.genesis: failed to stage platform entropy inputs: {e}"
        ));
    }

    // Perform MPC-only genesis using storage node SDK.
    let fut = async move {
        let cfg = match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
            Ok(cfg) => cfg,
            Err(e) => return Err(format!("No storage node config available: {}", e)),
        };
        let res = crate::sdk::storage_node_sdk::StorageNodeSDK::new(cfg)
            .await
            .map_err(|e| format!("sdk.new: {e}"))?
            .create_genesis_with_mpc(Some(entropy.clone()))
            .await
            .map_err(|e| format!("MPC genesis failed (strict; no alternate path): {e}"))?;

        let device_id = res.genesis_device_id.clone();
        let genesis_hash = res.genesis_hash.clone().ok_or_else(|| {
            "system.genesis: storage SDK returned missing genesis_hash".to_string()
        })?;
        if genesis_hash.len() != 32 {
            return Err(format!(
                "system.genesis: storage SDK returned invalid genesis_hash length {}, expected 32",
                genesis_hash.len()
            ));
        }
        // K_DBRW is installed by `core_sdk::create_genesis_with_passive_contributors`
        // post-MPC using the canonical
        //   derive_cdbrw_binding_key(genesis_hash, device_id = genesis_hash,
        //                            hw, env)
        // preimage. Pull it back out here for downstream uses (JNI
        // installation, binding_record digest stamped into the genesis
        // record).
        let k_dbrw_vec = crate::binding_key::get_binding_key().ok_or_else(|| {
            "system.genesis: canonical K_DBRW slot empty after MPC genesis".to_string()
        })?;
        if k_dbrw_vec.len() != 32 {
            return Err(format!(
                "system.genesis: canonical K_DBRW length must be 32, got {}",
                k_dbrw_vec.len()
            ));
        }
        let mut k_dbrw_arr = [0u8; 32];
        k_dbrw_arr.copy_from_slice(&k_dbrw_vec);
        let binding_record = crate::util::text_id::encode_base32_crockford(
            dsm::crypto::blake3::domain_hash(
                dsm::common::domain_tags::TAG_DSM_CDBRW_BINDING_RECORD,
                &k_dbrw_arr,
            )
            .as_bytes(),
        );
        #[cfg(all(target_os = "android", feature = "jni"))]
        crate::jni::cdbrw::set_cdbrw_binding_key(k_dbrw_vec.clone());
        let public_key = crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
        let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
            dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
        )
        .to_vec();

        // ---- Persist genesis record to SQLite so local_genesis_hash() succeeds ----
        // Without this, storage.sync fails with "no genesis record found" and
        // bilateral transfers are impossible.
        let genesis_id_b32 = crate::util::text_id::encode_base32_crockford(&genesis_hash);
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
        let genesis_record = crate::storage::client_db::GenesisRecord {
            genesis_id: genesis_id_b32.clone(),
            device_id: device_id_b32.clone(),
            mpc_proof: res.session_id.clone(),
            dbrw_binding: binding_record,
            merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
            participant_count: res.participating_nodes.len() as u32,
            progress_marker: "genesis".to_string(),
            publication_hash: genesis_id_b32,
            storage_nodes: res.participating_nodes.clone(),
            entropy_hash: crate::util::text_id::encode_base32_crockford(
                dsm::crypto::blake3::domain_hash(
                    dsm::common::domain_tags::TAG_DSM_GENESIS_ENTROPY,
                    &entropy,
                )
                .as_bytes(),
            ),
            protocol_version: "v3".to_string(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
        };

        crate::storage::client_db::store_genesis_record_with_verification(&genesis_record)
            .map_err(|e| format!("system.genesis: failed to store genesis record: {e}"))?;
        log::info!("system.genesis: genesis record stored successfully");

        crate::storage::client_db::ensure_wallet_state_for_device(&device_id_b32)
            .map_err(|e| format!("system.genesis: failed to ensure wallet_state: {e}"))?;
        log::info!(
            "system.genesis: wallet_state ensured for device={}",
            &device_id_b32[..8]
        );

        // Register the new device with each storage node's auth endpoint so
        // subsequent authenticated PUTs (routing-advertisement publish,
        // external-commitment publish, etc.) succeed.  Without this every
        // storage write returns 401 Unauthorized because the per-node auth
        // token slot is empty.  `register_device_for_auth` is idempotent at
        // the storage-node level and persists the token via
        // `store_auth_token`, which `resolve_storage_auth` reads on every
        // PUT path.  Best-effort: a single-node failure is logged but does
        // NOT roll back genesis — the genesis record is already durable
        // and a later retry on the same node will get the token.
        {
            let cfg_for_auth =
                match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        log::warn!(
                            "system.genesis: auth-registration cfg load failed (genesis still durable): {e}"
                        );
                        None
                    }
                };
            if let Some(cfg) = cfg_for_auth {
                let public_key_b32 = crate::util::text_id::encode_base32_crockford(&public_key);
                match crate::sdk::storage_node_sdk::StorageNodeSDK::new(cfg).await {
                    Ok(auth_sdk) => match auth_sdk
                        .register_device_for_auth(
                            &device_id_b32,
                            &public_key_b32,
                            &crate::util::text_id::encode_base32_crockford(&genesis_hash),
                        )
                        .await
                    {
                        Ok(_token) => {
                            log::info!(
                                "system.genesis: auth-registration completed for device={}",
                                &device_id_b32[..8]
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "system.genesis: auth-registration failed (subsequent PUTs may 401 until retry): {e}"
                            );
                        }
                    },
                    Err(e) => {
                        log::warn!("system.genesis: auth-registration SDK init failed: {e}");
                    }
                }
            }
        }

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
            session_id: res.session_id,
            threshold: 3,
            storage_nodes: res.participating_nodes,
            network_id: req.network_id.clone(),
            locale: req.locale.clone(),
        };

        Ok::<generated::GenesisCreated, String>(resp)
    };

    let resp = match crate::runtime::get_runtime().block_on(fut) {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    pack_envelope_ok(generated::envelope::Payload::GenesisCreatedResponse(resp))
}

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
            "system.genesis" => handle_system_genesis_query(q),
            _ => err(format!("unknown system query: {}", q.path)),
        }
    }

    /// Dispatch handler for `device.*` invoke routes — secondary-device admission handshake.
    /// All logic is in `DeviceAdmissionSDK`; these arms decode args + drive the BLE send.
    pub(crate) async fn handle_device_invoke(&self, i: AppInvoke) -> AppResult {
        let body = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p.body,
            Err(e) => return err(format!("{}: decode ArgPack failed: {e}", i.method)),
        };
        match i.method.as_str() {
            // EXISTING device: which device (if any) is awaiting the owner's approval (poll).
            "device.pendingAdmission" => {
                let v =
                    crate::sdk::DeviceAdmissionSDK::pending_admission_device_id().unwrap_or_default();
                device_ok("device.pendingAdmission", &v)
            }
            // NEW device: start the handshake (build request + send over BLE to the existing device).
            "device.requestAdmission" => {
                #[cfg(all(target_os = "android", feature = "bluetooth"))]
                {
                    let req = match generated::AddDeviceAdmissionInitiateV1::decode(&*body) {
                        Ok(r) => r,
                        Err(e) => return err(format!("device.requestAdmission: decode: {e}")),
                    };
                    if req.genesis_hash.len() != 32 {
                        return err("device.requestAdmission: genesis_hash must be 32 bytes".into());
                    }
                    if req.entropy.len() != 32 {
                        return err("device.requestAdmission: entropy must be 32 bytes".into());
                    }
                    if req.signer_signing_pubkey.is_empty() {
                        return err("device.requestAdmission: signer pubkey required".into());
                    }
                    if req.ble_address.is_empty() {
                        return err("device.requestAdmission: ble_address required".into());
                    }
                    let mut g = [0u8; 32];
                    g.copy_from_slice(&req.genesis_hash);
                    let env = match crate::sdk::DeviceAdmissionSDK::begin_admission(
                        g,
                        req.entropy,
                        req.signer_signing_pubkey,
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(e) => return err(format!("device.requestAdmission: {e}")),
                    };
                    let adapter = match crate::bridge::get_ble_transport_adapter().await {
                        Ok(a) => a,
                        Err(e) => {
                            return err(format!(
                                "device.requestAdmission: BLE transport not ready: {e}"
                            ))
                        }
                    };
                    match adapter.send_admission_request(&req.ble_address, &env).await {
                        Ok(()) => device_ok("device.requestAdmission", "request-sent"),
                        Err(e) => err(format!("device.requestAdmission: send failed: {e}")),
                    }
                }
                #[cfg(not(all(target_os = "android", feature = "bluetooth")))]
                {
                    let _ = body;
                    err("device.requestAdmission: BLE admission requires the Android build".into())
                }
            }
            // EXISTING device: owner approves → gate-sign + insert + send the response back.
            "device.approveAdmission" => {
                #[cfg(all(target_os = "android", feature = "bluetooth"))]
                {
                    let (env, peer) =
                        match crate::sdk::DeviceAdmissionSDK::approve_pending_admission().await {
                            Ok(v) => v,
                            Err(e) => return err(format!("device.approveAdmission: {e}")),
                        };
                    let adapter = match crate::bridge::get_ble_transport_adapter().await {
                        Ok(a) => a,
                        Err(e) => {
                            return err(format!(
                                "device.approveAdmission: BLE transport not ready: {e}"
                            ))
                        }
                    };
                    match adapter.send_admission_response(&peer, &env).await {
                        Ok(()) => device_ok("device.approveAdmission", "approved"),
                        Err(e) => err(format!("device.approveAdmission: send failed: {e}")),
                    }
                }
                #[cfg(not(all(target_os = "android", feature = "bluetooth")))]
                {
                    err("device.approveAdmission: BLE admission requires the Android build".into())
                }
            }
            _ => err(format!("unknown device invoke: {}", i.method)),
        }
    }
}

fn device_ok(key: &str, value: &str) -> AppResult {
    pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
        generated::AppStateResponse {
            key: key.to_string(),
            value: Some(value.to_string()),
        },
    ))
}
