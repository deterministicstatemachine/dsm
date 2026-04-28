//! # JNI Genesis Creation
//!
//! Android JNI entry point for MPC-based genesis creation. Accepts SPHINCS+
//! public key bytes and DBRW binding material from Kotlin, runs the blind
//! MPC protocol, and returns a prost-encoded Envelope v3 containing the
//! `GenesisCreated` payload.

// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::too_many_arguments)]

use crate::generated as pb;
use jni::objects::{JByteArray, JClass, JString};
use jni::JNIEnv;
use prost::Message;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::task;

use dsm::crypto::blake3::dsm_domain_hasher;
use crate::storage::{store_genesis_record_with_verification, GenesisRecord};

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_createGenesis<'a>(
    mut env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    j_locale: JString<'a>,
    j_network: JString<'a>,
    _entropy_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    log::info!("createGenesis: JNI function called");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ---- Extract inputs (UTF-8 strings are UI-only; no encoding semantics) ----
        let locale = match env.get_string(&j_locale) {
            Ok(s) => s.to_string_lossy().to_string(),
            Err(e) => {
                log::error!("createGenesis: failed to read locale: {:?}", e);
                return encode_env_as_bytes(
                    &mut env,
                    crate::jni::helpers::encode_error_transport(400, "invalid locale"),
                );
            }
        };
        let network_id = match env.get_string(&j_network) {
            Ok(s) => s.to_string_lossy().to_string(),
            Err(e) => {
                log::error!("createGenesis: failed to read networkId: {:?}", e);
                return encode_env_as_bytes(
                    &mut env,
                    crate::jni::helpers::encode_error_transport(400, "invalid networkId"),
                );
            }
        };

        // ---- Convert Java byte[] -> Vec<u8> (strict 32B) ----
        // Genesis creation must NOT depend on DBRW being initialized.
        // DBRW remains mandatory for wallet initialization / signing, but first-time genesis
        // needs to be able to run on a fresh device.
        let entropy = match env.convert_byte_array(unsafe { JByteArray::from_raw(_entropy_bytes) })
        {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    log::error!(
                        "createGenesis: device entropy invalid length: {}",
                        bytes.len()
                    );
                    return encode_env_as_bytes(
                        &mut env,
                        crate::jni::helpers::encode_error_transport(
                            422,
                            "device entropy must be 32 bytes",
                        ),
                    );
                }
                bytes
            }
            Err(e) => {
                log::error!("createGenesis: failed to read entropy bytes: {:?}", e);
                return encode_env_as_bytes(
                    &mut env,
                    crate::jni::helpers::encode_error_transport(400, "invalid device entropy"),
                );
            }
        };

        // ---- Ensure runtime for async work ----
        crate::runtime::dsm_init_runtime();

        // Build the future with owned captures to avoid borrow issues.
        let fut = {
            let locale = locale.clone();
            let network_id = network_id.clone();
            let entropy = entropy.clone();

            async move {
                use crate::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
                // Diagnostics: log env config and localhost policy before attempting to load config
                let env_cfg_path_env = std::env::var("DSM_ENV_CONFIG_PATH").ok();
                let env_cfg_path_global = crate::network::get_env_config_path();
                let allow_localhost_env = std::env::var("DSM_ALLOW_LOCALHOST").ok();
                log::info!(
                    "createGenesis: DSM_ENV_CONFIG_PATH(env)={:?}, ENV_CONFIG_PATH(global)={:?}, DSM_ALLOW_LOCALHOST={:?}",
                    env_cfg_path_env,
                    env_cfg_path_global,
                    allow_localhost_env
                );

                // Storage-node config + SDK
                let cfg = StorageNodeConfig::from_env_config()
                    .await
                    .map_err(|e| format!("storage config: {e}"))?;
                // Preserve endpoints for later SDK AppRouter configuration
                let storage_endpoints_snapshot = cfg.node_urls.clone();
                let sdk = StorageNodeSDK::new(cfg)
                    .await
                    .map_err(|e| format!("sdk.new: {e}"))?;

                // MPC-only genesis (strict mode): local bootstrap path is not permitted.
                let mpc_res = sdk
                    .create_genesis_with_mpc(Some(3), Some(entropy.clone()))
                    .await;

                let (
                    genesis_device_id,
                    session_id,
                    threshold_usize,
                    genesis_hash_bytes,
                    participating_nodes,
                ): (Vec<u8>, String, usize, Vec<u8>, Vec<String>) = match mpc_res {
                    Ok(resp) => (
                        resp.genesis_device_id.clone(),
                        resp.session_id.clone(),
                        resp.threshold as usize,
                        resp.genesis_hash.clone().unwrap_or_else(|| vec![0u8; 32]),
                        resp.participating_nodes.clone(),
                    ),
                    Err(e) => {
                        // Fail-closed: do not use local bootstrap.
                        let msg = format!("MPC genesis failed (strict mode): {e}");
                        return Err(msg);
                    }
                };

                // CRITICAL: Derive signing keypair deterministically from genesis + device_id
                // plus the DBRW binding key.
                // This ensures the same key is derived every time for a given identity.
                //
                // The live path concatenates `genesis || device_id || K_DBRW`, then
                // `SignatureKeyPair::generate_from_entropy()` compresses that material with
                // `domain_hash("DSM/sphincs-seed", ...)` before deterministic SPHINCS keygen.
                //
                // NOTE: The `entropy` passed here is the DBRW binding key derived in the JNI layer
                // via DbrwInstance::initialize -> DbrwCommitment::derive_binding_key.
                // It is the DBRW component of the combined deterministic seed material.
                let public_key = {
                    let mut key_entropy = Vec::with_capacity(96);
                    key_entropy.extend_from_slice(&genesis_hash_bytes);
                    key_entropy.extend_from_slice(&genesis_device_id);
                    key_entropy.extend_from_slice(&entropy); // DBRW binding key

                    match dsm::crypto::SignatureKeyPair::generate_from_entropy(&key_entropy) {
                        Ok(kp) => {
                            log::info!(
                                "createGenesis: derived signing keypair, pubkey_len={}",
                                kp.public_key.len()
                            );
                            kp.public_key.clone()
                        }
                        Err(e) => {
                            return Err(format!(
                                "createGenesis: failed to derive signing keypair: {e}"
                            ));
                        }
                    }
                };

                // ---- Build prost GenesisCreated payload (bytes-only) ----
                let gc = pb::GenesisCreated {
                    device_id: genesis_device_id.clone(),
                    genesis_hash: Some(pb::Hash32 {
                        v: genesis_hash_bytes.clone(),
                    }),
                    public_key,
                    smt_root: Some(pb::Hash32 {
                        v: dsm::merkle::sparse_merkle_tree::empty_root(
                            dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
                        )
                        .to_vec(),
                    }),
                    device_entropy: entropy.clone(),
                    session_id: session_id.clone(),
                    threshold: threshold_usize as u32,
                    storage_nodes: participating_nodes.clone(),
                    network_id: network_id.clone(),
                    locale: locale.clone(),
                };

                // --- Publish genesis to storage nodes ---
                //
                // Publish failures do NOT abort genesis creation: the local
                // keys/state are still valid and we want the user to end up
                // with a persisted identity they can recover. The self-heal
                // path in the bootstrap ingress path retries on every
                // subsequent app start via `storage_node_sdk::ensure_device_in_tree`.
                let publish_result = sdk.publish_genesis_to_nodes(gc.clone()).await;
                match &publish_result {
                    Ok(resp) => {
                        log::info!("Genesis published to storage nodes: {:?}", resp);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to publish genesis to storage nodes: {}. \
                             Identity will be healed on next successful bootstrap.",
                            e
                        );
                    }
                }

                // --- Register device in device tree ---
                //
                // `register_device_in_tree` enforces quorum (>=3 nodes) and
                // returns Err when fewer succeed. We deliberately don't fail
                // genesis creation on error — the bootstrap self-heal will
                // re-attempt on the next app start when the network recovers.
                let register_result = sdk
                    .register_device_in_tree(&genesis_device_id, &genesis_hash_bytes)
                    .await;
                match &register_result {
                    Ok(resp) => {
                        log::info!("Device registered in tree: {:?}", resp);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to register device in tree: {}. \
                             Identity will be healed on next successful bootstrap.",
                            e
                        );
                    }
                }

                // Persist identity immediately to stop bootstrap warnings and enable headers
                {
                    let pubkey = gc.public_key.clone();
                    let smt_root = gc
                        .smt_root
                        .as_ref()
                        .map(|h| h.v.clone())
                        .unwrap_or_else(|| {
                            dsm::merkle::sparse_merkle_tree::empty_root(
                                dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
                            )
                            .to_vec()
                        });
                    crate::sdk::app_state::AppState::set_identity_info(
                        gc.device_id.clone(),
                        pubkey,
                        gc.genesis_hash
                            .as_ref()
                            .map(|h| h.v.clone())
                            .unwrap_or_else(|| vec![0u8; 32]),
                        smt_root,
                    );
                    crate::sdk::app_state::AppState::set_has_identity(true);
                    // Compute and persist Device Tree root (§2.3) so that
                    // build_bilateral_receipt_with_smt can verify DevID ∈ R_G.
                    // Without this, get_device_tree_root() always returns None,
                    // causing every bilateral receipt build to fail → proof_data None →
                    // settle() rejects the transfer → balance never updates.
                    if gc.device_id.len() == 32 {
                        let mut dev_arr = [0u8; 32];
                        dev_arr.copy_from_slice(&gc.device_id);
                        let root = dsm::common::device_tree::DeviceTree::single(dev_arr).root();
                        crate::sdk::app_state::AppState::set_device_tree_root(root);
                        log::info!("[Genesis] Device tree root computed and persisted for bilateral receipt verification");
                    }
                    // Initialize SDK context so header fetch works immediately
                    let _ = crate::initialize_sdk_context(
                        gc.device_id.clone(),
                        gc.genesis_hash
                            .as_ref()
                            .map(|h| h.v.clone())
                            .unwrap_or_else(|| vec![0u8; 32]),
                        entropy.clone(),
                    );

                    // Initialize SDK handlers (bilateral/unilateral/app router) and BLE path if available.
                    // This ensures the bilateral handler exists before BLE coordinator injection.
                    let sdk_cfg = crate::init::SdkConfig {
                        node_id: "default".to_string(),
                        storage_endpoints: storage_endpoints_snapshot,
                        enable_offline: true,
                    };
                    match crate::init::init_dsm_sdk(&sdk_cfg) {
                        Ok(_) => log::info!("createGenesis: init_dsm_sdk completed successfully"),
                        Err(e) => {
                            // Non-fatal: strict bootstrap has not yet finalized on a fresh device.
                            // The host now forwards measurement envelopes through ingress, and Rust
                            // completes binding + identity installation during bootstrap finalize.
                            log::warn!("createGenesis: init_dsm_sdk deferred (expected on fresh device): {}", e);
                        }
                    }

                    // Initialize BLE coordinator for bilateral offline transfers
                    #[cfg(all(target_os = "android", feature = "bluetooth"))]
                    {
                        use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
                        use crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator;
                        use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
                        use dsm::core::contact_manager::DsmContactManager;
                        // Note: Health state tracking removed - always proceed
                        use dsm::crypto::SignatureKeyPair;

                        // Build bilateral manager with genesis context
                        let mut device_id_arr = [0u8; 32];
                        device_id_arr.copy_from_slice(&genesis_device_id[..32]);
                        let mut genesis_arr = [0u8; 32];
                        genesis_arr.copy_from_slice(&genesis_hash_bytes[..32]);

                        // Create contact manager (empty at genesis)
                        let storage_nodes: Vec<dsm::types::identifiers::NodeId> =
                            participating_nodes
                                .iter()
                                .map(|s| dsm::types::identifiers::NodeId::new(s))
                                .collect();
                        let contact_mgr = DsmContactManager::new(device_id_arr, storage_nodes);

                        // CRITICAL: Generate keypair using SAME derivation as stored public key
                        // Must match lines 119-129 where we derive: genesis_hash || device_id
                        let mut key_entropy_ble = Vec::with_capacity(64);
                        key_entropy_ble.extend_from_slice(&genesis_hash_bytes);
                        key_entropy_ble.extend_from_slice(&genesis_device_id);
                        let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy_ble)
                            .map_err(|e| format!("keypair generation failed: {e}"))?;
                        log::info!(
                            "createGenesis: BLE keypair derived from genesis_hash||device_id, pubkey_len={}",
                            keypair.public_key.len()
                        );

                        // Create bilateral transaction manager
                        let bilateral_mgr =
                            Arc::new(tokio::sync::RwLock::new(BilateralTransactionManager::new(
                                contact_mgr,
                                keypair,
                                device_id_arr,
                                genesis_arr,
                            )));

                        // Create BLE handler with event callback for UI notifications
                        let mut ble_handler =
                            BilateralBleHandler::new(bilateral_mgr, device_id_arr);

                        // CRITICAL: Install settlement delegate so balance updates happen
                        // after bilateral transfers. Without this, the 3-phase commit
                        // completes but balances never change.
                        ble_handler.set_settlement_delegate(std::sync::Arc::new(
                            crate::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate,
                        ));

                        // CRITICAL: Set event callback to forward bilateral events to WebView
                        // Without this, prepare_received and other events won't reach the UI
                        let callback: std::sync::Arc<dyn Fn(&[u8]) + Send + Sync> =
                            std::sync::Arc::new(|event_bytes: &[u8]| {
                                let data = event_bytes.to_vec();
                                // Use global runtime to avoid runtime drop panics
                                crate::runtime::get_runtime().spawn(async move {
                                use prost::Message;
                                if let Ok(event) = crate::generated::BilateralEventNotification::decode(&data[..]) {
                                    log::info!(
                                        "[createGenesis] Bilateral event: type={:?}, counterparty_len={}, status={}",
                                        event.event_type,
                                        event.counterparty_device_id.len(),
                                        event.status
                                    );
                                }
                                // Post to WebView via JNI
                                if let Err(e) = crate::bluetooth::post_bilateral_event_to_webview_jni(data) {
                                    log::warn!("[createGenesis] WebView post failed: {}", e);
                                }
                            });
                            });
                        ble_handler.set_event_callback(callback);

                        let ble_handler = std::sync::Arc::new(ble_handler);
                        let transport_adapter = std::sync::Arc::new(
                            crate::bluetooth::BilateralTransportAdapter::new(ble_handler.clone()),
                        );
                        let coordinator =
                            std::sync::Arc::new(BleFrameCoordinator::new(device_id_arr));

                        // Inject into BiImpl if available
                        match crate::bridge::inject_ble_coordinator(coordinator).await {
                            Ok(_) => {
                                log::info!("createGenesis: BLE coordinator injected successfully")
                            }
                            Err(e) => {
                                log::warn!("createGenesis: Failed to inject BLE coordinator: {}", e)
                            }
                        }
                        match crate::bridge::inject_ble_transport_adapter(transport_adapter).await {
                            Ok(_) => {
                                log::info!(
                                    "createGenesis: BLE transport adapter injected successfully"
                                )
                            }
                            Err(e) => {
                                log::warn!(
                                    "createGenesis: Failed to inject BLE transport adapter: {}",
                                    e
                                )
                            }
                        }
                    }

                    // Atomic post-genesis barrier: warm transport headers and mark SDK initialized
                    // so the UI can proceed without racing background setup. This does not require
                    // DBRW; signing/wallet operations remain gated elsewhere.
                    match crate::get_transport_headers_v3_bytes() {
                        Ok(_) => log::info!("createGenesis: transport headers warmed successfully"),
                        Err(e) => {
                            log::warn!("createGenesis: failed to warm transport headers: {}", e)
                        }
                    }
                    crate::sdk::app_state::AppState::set_sdk_initialized(true);

                    // CRITICAL: Set SDK_READY so getAllBalancesStrict and other
                    // JNI exports succeed immediately after genesis.
                    crate::sdk::session_manager::set_sdk_ready(true);
                }

                // ---- Store genesis record in database for persistence ----
                {
                    let genesis_record = GenesisRecord {
                        genesis_id: crate::util::text_id::encode_base32_crockford(
                            &genesis_hash_bytes,
                        ),
                        device_id: crate::util::text_id::encode_base32_crockford(
                            &genesis_device_id,
                        ),
                        mpc_proof: session_id.clone(),
                        dbrw_binding: crate::util::text_id::encode_base32_crockford(&entropy),
                        merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]), // Initial empty SMT root
                        participant_count: threshold_usize as u32,
                        // Deterministic, clockless marker (no wall-clock time).
                        progress_marker: "genesis".to_string(),
                        publication_hash: crate::util::text_id::encode_base32_crockford(
                            &genesis_hash_bytes,
                        ), // Use genesis hash as publication hash
                        storage_nodes: participating_nodes.clone(),
                        entropy_hash: crate::util::text_id::encode_base32_crockford(
                            dsm::crypto::blake3::domain_hash("DSM/genesis-entropy", &entropy)
                                .as_bytes(),
                        ),
                        protocol_version: "v3".to_string(),
                        hash_chain_proof: None,
                        smt_proof: None,
                        verification_step: None,
                    };

                    match store_genesis_record_with_verification(&genesis_record) {
                        Ok(_) => log::info!("createGenesis: genesis record stored successfully"),
                        Err(e) => {
                            log::warn!("createGenesis: failed to store genesis record: {}", e)
                        }
                    }

                    // Ensure wallet metadata exists for the newly-created identity.
                    // Token balances are derived later from canonical state/projection sync.
                    match crate::storage::client_db::ensure_wallet_state_for_device(
                        &genesis_record.device_id,
                    ) {
                        Ok(_) => log::info!(
                            "createGenesis: wallet_state ensured for device={}",
                            genesis_record.device_id
                        ),
                        Err(e) => log::warn!(
                            "createGenesis: failed to ensure wallet_state for device {}: {}",
                            genesis_record.device_id,
                            e
                        ),
                    }
                }

                // ---- Envelope v3 headers (bytes-only) ----
                let headers = pb::Headers {
                    device_id: genesis_device_id.clone(),
                    chain_tip: vec![0u8; 32],
                    // Headers.genesis_hash uses raw bytes in this proto (not Hash32).
                    genesis_hash: genesis_hash_bytes.clone(),
                    seq: 0,
                };

                // message_id: blake3("DSM/envelope-msgid\0" || device_id || session_id)[0..16]
                let mut hasher = dsm_domain_hasher("DSM/envelope-msgid");
                hasher.update(genesis_device_id.as_slice());
                hasher.update(session_id.as_bytes());
                let message_id = hasher.finalize().as_bytes()[..16].to_vec();

                Ok(pb::Envelope {
                    version: 3,
                    headers: Some(headers),
                    message_id,
                    payload: Some(pb::envelope::Payload::GenesisCreatedResponse(gc)),
                })
            }
        };

        // ---- Run future safely on/with a Tokio runtime ----
        let result = if Handle::try_current().is_ok() {
            task::block_in_place(|| Handle::current().block_on(fut))
        } else {
            crate::runtime::get_runtime().block_on(fut)
        };

        // ---- Encode as prost bytes (or prost-encoded error transport) ----
        let envl = match result {
            Ok(e) => e,
            Err(err) => {
                log::warn!("createGenesis: helper failed: {}", err);
                crate::jni::helpers::encode_error_transport(
                    500,
                    &format!("create_genesis failed: {err}"),
                )
            }
        };
        log::info!("createGenesis: encoding envelope to bytes");
        encode_env_as_bytes(&mut env, envl)
    }));

    match result {
        Ok(value) => value,
        Err(panic) => {
            let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            log::error!("createGenesis: panic captured: {}", panic_msg);
            encode_env_as_bytes(
                &mut env,
                crate::jni::helpers::encode_error_transport(
                    500,
                    &format!("create_genesis panic: {panic_msg}"),
                ),
            )
        }
    }
}

fn encode_env_as_bytes(env: &mut JNIEnv<'_>, envl: pb::Envelope) -> jni::sys::jbyteArray {
    let mut out = Vec::new();
    out.push(0x03); // Canonical framing byte for FramedEnvelopeV3
    envl.encode(&mut out).unwrap_or(());
    log::info!(
        "createGenesis: envelope encoded to {} bytes (with framing)",
        out.len()
    );
    if out.is_empty() {
        log::error!("createGenesis: envelope encoded to empty bytes!");
        return env
            .new_byte_array(0)
            .map(|arr| arr.into_raw())
            .unwrap_or_else(|e| {
                log::error!("create_genesis: new_byte_array(0) failed: {e}");
                std::ptr::null_mut()
            });
    }

    // Log Crockford Base32 prefix for cross-layer diagnostics (no hex/base64).
    let prefix_len = std::cmp::min(10, out.len());
    let prefix_b32 = crate::util::text_id::encode_base32_crockford(&out[..prefix_len]);
    log::info!("createGenesis: envelope prefix (b32c): {}", prefix_b32);

    // Create a Java byte[] with the correct length (keep as a local JNI reference)
    let jarray = match env.new_byte_array(out.len() as i32) {
        Ok(arr) => arr,
        Err(e) => {
            log::error!("create_genesis: new_byte_array({}) failed: {e}", out.len());
            return std::ptr::null_mut();
        }
    };

    // Convert Vec<u8> -> &[i8] for the JNI set call
    let i8_slice = unsafe { std::slice::from_raw_parts(out.as_ptr() as *const i8, out.len()) };

    // Copy data into the Java array
    if let Err(e) = env.set_byte_array_region(&jarray, 0, i8_slice) {
        log::error!("create_genesis: set_byte_array_region failed: {e}");
        return std::ptr::null_mut();
    }

    // Convert local JNI reference into a raw jbyteArray to return to Java
    let raw = jarray.into_raw();
    log::info!("createGenesis: created byte array successfully");
    raw
}
