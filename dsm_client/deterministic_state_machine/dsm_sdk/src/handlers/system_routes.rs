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
    // Optional high-assurance / legacy profile: n-of-n commit-reveal multipart-entropy genesis
    // (GenesisEntropyProfile::CommitRevealMpcV1). No silicon binding and no C-DBRW — the canonical
    // wallet path is mnemonic-rooted Genesis v2. `req.cdbrw_hw_entropy` / `req.cdbrw_env_fingerprint`
    // are reserved/ignored legacy fields.

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
            // Legacy C-DBRW binding-record column (Genesis v2 has no silicon binding);
            // retained empty until the GenesisRecord schema column is dropped.
            device_birth_binding: String::new(),
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
            // Legacy / optional MPC profile: no public mnemonic nonce.
            genesis_nonce: String::new(),
            genesis_profile: "CommitRevealMpcV1".to_string(),
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

/// system.generateMnemonic — return a fresh BIP39 mnemonic for display/backup at wallet creation.
/// Stateless: the wallet seed is derived + cached at `system.createGenesisV2` time.
pub(crate) fn handle_generate_mnemonic_query() -> AppResult {
    match crate::sdk::recovery_sdk::RecoverySDK::generate_mnemonic() {
        Ok(m) => pack_bytes_ok(m.into_bytes(), generated::Hash32 { v: vec![0u8; 32] }),
        Err(e) => err(format!("system.generateMnemonic: {e}")),
    }
}

/// system.createGenesisV2 — canonical mnemonic-rooted wallet creation (whitepaper §2.5,
/// GenesisEntropyProfile::MnemonicV2). The BIP39 mnemonic is the sole root: derive `wallet_seed`,
/// cache it in the unlocked session, then run `create_genesis_v2_self_attested` and install the
/// resulting GenesisState. No storage nodes, no MPC, no silicon, no random genesis entropy, no
/// C-DBRW, no persisted s0/Smaster. Fails closed if the wallet seed cannot be derived/cached.
pub(crate) fn handle_create_genesis_v2_query(q: AppQuery) -> AppResult {
    let pack = match generated::ArgPack::decode(&*q.params) {
        Ok(p) => p,
        Err(e) => return err(format!("decode ArgPack failed: {e}")),
    };
    if pack.codec != generated::Codec::Proto as i32 {
        return err("system.createGenesisV2: ArgPack.codec must be PROTO".into());
    }
    let req = match generated::WalletCreateGenesisV2Request::decode(&*pack.body) {
        Ok(r) => r,
        Err(e) => return err(format!("decode WalletCreateGenesisV2Request failed: {e}")),
    };
    if req.mnemonic.trim().is_empty() {
        return err("system.createGenesisV2: mnemonic is required".into());
    }
    let network_id = if req.network_id.is_empty() {
        "mainnet".to_string()
    } else {
        req.network_id.clone()
    };

    // Genesis v2 lifecycle rail: drive the frontend securing screen through the SAME native
    // events as the legacy bootstrap path (EventBridge maps these to `genesis.securing-device*`
    // topics the useGenesisFlow hook already renders). The frontend is pure rendering — progress
    // truth lives here. Emission is best-effort: a failed WebView dispatch must never fail the
    // wallet creation itself.
    use crate::generated::genesis_lifecycle_event::Kind as LifecycleKind;
    let emit = |kind: LifecycleKind, progress: u32| {
        if let Err(e) = crate::ingress::push_genesis_lifecycle_event(kind as i32, progress) {
            log::warn!(
                "system.createGenesisV2: lifecycle event dispatch failed (non-fatal): {:?}",
                e
            );
        }
    };
    // Hold phase=securing_device for any concurrent session-state read until this function
    // exits (success OR error), mirroring the finalize_bootstrap_core scope-guard discipline —
    // otherwise a mid-genesis snapshot would report needs_genesis and flash the start screen.
    crate::sdk::session_manager::BOOTSTRAP_SECURING.store(true, std::sync::atomic::Ordering::SeqCst);
    struct ClearSecuringOnDrop;
    impl Drop for ClearSecuringOnDrop {
        fn drop(&mut self) {
            crate::sdk::session_manager::BOOTSTRAP_SECURING
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let _clear_securing = ClearSecuringOnDrop;
    emit(LifecycleKind::GenesisKindStarted, 0);
    emit(LifecycleKind::GenesisKindSecuringDevice, 0);

    // 1. Derive + cache the wallet seed from the mnemonic (the unlocked-session secret).
    if let Err(e) = crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(&req.mnemonic) {
        return err(format!(
            "system.createGenesisV2: wallet seed derivation failed: {e}"
        ));
    }
    let wallet_seed = match crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed() {
        Some(s) => s,
        None => {
            return err(
                "system.createGenesisV2: wallet seed unavailable after unlock (fail closed)".into(),
            )
        }
    };
    emit(LifecycleKind::GenesisKindSecuringProgress, 30);

    // 2. Canonical mnemonic-rooted genesis (self-attested AttA; no silicon/random/MPC).
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let outcome = match dsm::core::identity::genesis::create_genesis_v2_self_attested(
        &wallet_seed,
        network_id.as_bytes(),
        0,
        0,
        2,
        &aph,
    ) {
        Ok(o) => o,
        Err(e) => {
            return err(format!(
                "system.createGenesisV2: genesis derivation failed: {e}"
            ))
        }
    };
    emit(LifecycleKind::GenesisKindSecuringProgress, 60);
    let genesis_state = &outcome.state;
    let devid = match genesis_state.device_id {
        Some(d) => d,
        None => return err("system.createGenesisV2: v2 genesis missing device_id".into()),
    };
    let g = genesis_state.hash;
    let ak_pk = genesis_state.signing_key.public_key.clone();
    let smt_root = genesis_state.merkle_root.unwrap_or([0u8; 32]);

    // 3. Install the genesis state + device head under the canonical v2 identity.
    let device_info = dsm::types::state_types::DeviceInfo::new(devid, ak_pk.clone());
    let core = match crate::sdk::core_sdk::CoreSDK::new_with_device(device_info) {
        Ok(c) => c,
        Err(e) => return err(format!("system.createGenesisV2: CoreSDK init failed: {e}")),
    };
    if let Err(e) = core.install_v2_genesis(genesis_state) {
        return err(format!(
            "system.createGenesisV2: genesis install failed: {e}"
        ));
    }

    // 4. Persist the public Genesis v2 record (genesis_nonce + profile + version).
    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&devid);
    let genesis_id_b32 = crate::util::text_id::encode_base32_crockford(&g);
    let nonce_b32 = crate::util::text_id::encode_base32_crockford(&outcome.genesis_nonce);
    let record = crate::storage::client_db::GenesisRecord {
        genesis_id: genesis_id_b32.clone(),
        device_id: device_id_b32.clone(),
        mpc_proof: String::new(),
        device_birth_binding: String::new(),
        merkle_root: crate::util::text_id::encode_base32_crockford(&smt_root),
        participant_count: 0,
        progress_marker: "genesis".to_string(),
        publication_hash: genesis_id_b32,
        storage_nodes: Vec::new(),
        entropy_hash: nonce_b32.clone(),
        protocol_version: "genesis-v2".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
        genesis_nonce: nonce_b32,
        genesis_profile: "MnemonicV2".to_string(),
    };
    if let Err(e) = crate::storage::client_db::store_genesis_record_with_verification(&record) {
        return err(format!(
            "system.createGenesisV2: store genesis record failed: {e}"
        ));
    }
    if let Err(e) = crate::storage::client_db::ensure_wallet_state_for_device(&device_id_b32) {
        return err(format!(
            "system.createGenesisV2: ensure wallet_state failed: {e}"
        ));
    }

    // 5. Install identity into AppState + SDK context (entropy rooted in the wallet seed).
    crate::sdk::app_state::AppState::set_identity_info(
        devid.to_vec(),
        ak_pk.clone(),
        g.to_vec(),
        smt_root.to_vec(),
    );
    crate::sdk::app_state::AppState::set_has_identity(true);
    let entropy = crate::derive_production_entropy(&devid, &g, &wallet_seed);
    if let Err(e) = crate::initialize_sdk_context(devid.to_vec(), g.to_vec(), entropy) {
        return err(format!(
            "system.createGenesisV2: SDK context init failed: {e}"
        ));
    }
    emit(LifecycleKind::GenesisKindSecuringProgress, 85);

    // 5b. Hot-swap the MinimalBootstrapRouter for the full AppRouter now that the canonical identity
    //     exists (device_id set + wallet seed cached above). Without this the bootstrap router stays
    //     installed for the rest of the session and every post-genesis route (identity.pairingQR,
    //     wallet.*, contacts.*) fails with "requires genesis". The core adapter reads the router slot
    //     live, so the swap takes effect on the very next query.
    match crate::init::install_full_app_router_self_config() {
        Ok(true) => {}
        Ok(false) => {
            return err(
                "system.createGenesisV2: canonical identity not ready after genesis (fail closed)"
                    .into(),
            )
        }
        Err(e) => {
            return err(format!(
                "system.createGenesisV2: full AppRouter install failed: {e}"
            ))
        }
    }

    // Success rail (mirrors finalize_bootstrap_core): complete → ok. The wallet_ready screen
    // transition itself rides the fresh session snapshot Kotlin publishes after this response.
    emit(LifecycleKind::GenesisKindSecuringComplete, 0);
    emit(LifecycleKind::GenesisKindOk, 0);

    // 6. Return the genesis envelope (device_entropy carries the PUBLIC genesis_nonce in v2).
    let resp = generated::GenesisCreated {
        device_id: devid.to_vec(),
        genesis_hash: Some(generated::Hash32 { v: g.to_vec() }),
        public_key: ak_pk,
        smt_root: Some(generated::Hash32 {
            v: smt_root.to_vec(),
        }),
        device_entropy: outcome.genesis_nonce.to_vec(),
        session_id: String::new(),
        threshold: 0,
        storage_nodes: Vec::new(),
        network_id,
        locale: req.locale.clone(),
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
            // -------- system.genesis (legacy/optional MPC profile) --------
            "system.genesis" => handle_system_genesis_query(q),
            // -------- canonical mnemonic-rooted Genesis v2 (QueryOp) --------
            "system.generateMnemonic" => handle_generate_mnemonic_query(),
            "system.createGenesisV2" => handle_create_genesis_v2_query(q),
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
                let v = crate::sdk::DeviceAdmissionSDK::pending_admission_device_id()
                    .unwrap_or_default();
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
