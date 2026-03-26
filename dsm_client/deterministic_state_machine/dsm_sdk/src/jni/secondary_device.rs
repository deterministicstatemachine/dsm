//! # JNI Secondary Device Registration
//!
//! Android JNI entry point for `addSecondaryDevice`. Returns a prost-encoded
//! Envelope v3 with headers populated (device_id + genesis_hash) for
//! secondary device pairing.

// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::too_many_arguments)]

use crate::generated as pb;
use jni::objects::{JByteArray, JClass, JObject};
use jni::JNIEnv;
use prost::Message;

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_addSecondaryDevice<'a>(
    mut env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    genesis_hash_bytes: jni::sys::jbyteArray,
    entropy_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "addSecondaryDevice",
        std::panic::AssertUnwindSafe(|| {
            // ---- Extract genesis_hash (strict 32B) ----
            let genesis_hash = {
                let jobj: JObject<'a> = unsafe { JObject::from_raw(genesis_hash_bytes) };
                let jba: JByteArray = JByteArray::from(jobj);
                match env.convert_byte_array(&jba) {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("addSecondaryDevice: failed to read genesisHash: {:?}", e);
                        return encode_env_as_bytes(
                            &mut env,
                            crate::jni::helpers::encode_error_transport(400, "invalid genesisHash"),
                        );
                    }
                }
            };
            if genesis_hash.len() != 32 {
                return encode_env_as_bytes(
                    &mut env,
                    crate::jni::helpers::encode_error_transport(
                        422,
                        "genesisHash must be 32 bytes",
                    ),
                );
            }

            // ---- Extract device_entropy (strict 32B) ----
            let entropy = {
                let jobj: JObject<'a> = unsafe { JObject::from_raw(entropy_bytes) };
                let jba: JByteArray = JByteArray::from(jobj);
                match env.convert_byte_array(&jba) {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("addSecondaryDevice: failed to read deviceEntropy: {:?}", e);
                        return encode_env_as_bytes(
                            &mut env,
                            crate::jni::helpers::encode_error_transport(
                                400,
                                "invalid deviceEntropy",
                            ),
                        );
                    }
                }
            };
            if entropy.len() != 32 {
                return encode_env_as_bytes(
                    &mut env,
                    crate::jni::helpers::encode_error_transport(
                        422,
                        "deviceEntropy must be 32 bytes",
                    ),
                );
            }

            // ---- Ensure runtime for async work ----
            crate::runtime::dsm_init_runtime();

            // Build the future with owned captures to avoid borrow issues.
            let fut = {
                let genesis_hash = genesis_hash.clone();
                let entropy = entropy.clone();

                async move {
                    use crate::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};

                    // Storage-node config + SDK
                    let cfg = StorageNodeConfig::from_env_config()
                        .await
                        .map_err(|e| format!("storage config: {e}"))?;
                    let sdk = StorageNodeSDK::new(cfg)
                        .await
                        .map_err(|e| format!("sdk.new: {e}"))?;

                    // Bind new device to existing genesis
                    let res = sdk
                        .add_secondary_device(genesis_hash.clone(), entropy.clone())
                        .await
                        .map_err(|e| format!("add_secondary_device: {e}"))?;

                    // Extract device_id from response
                    let device_id = res.genesis_device_id.clone();

                    // Persist identity to AppState (mirrors create_genesis flow)
                    let public_key =
                        crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
                    let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
                        dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
                    )
                    .to_vec();
                    crate::sdk::app_state::AppState::set_identity_info(
                        device_id.clone(),
                        public_key,
                        genesis_hash.clone(),
                        smt_root,
                    );
                    crate::sdk::app_state::AppState::set_has_identity(true);
                    // Compute and persist Device Tree root (§2.3) — same as primary genesis path.
                    if device_id.len() == 32 {
                        let mut dev_arr = [0u8; 32];
                        dev_arr.copy_from_slice(&device_id);
                        let root =
                            dsm::common::device_tree::DeviceTree::single(dev_arr).root();
                        crate::sdk::app_state::AppState::set_device_tree_root(root);
                        log::info!("[SecondaryDevice] Device tree root persisted for bilateral receipt verification");
                    }
                    let _ = crate::initialize_sdk_context(
                        device_id.clone(),
                        genesis_hash.clone(),
                        entropy.clone(),
                    );

                    // Prepare headers (bytes-only)
                    let headers = pb::Headers {
                        device_id: device_id.clone(),
                        chain_tip: vec![0u8; 32],
                        genesis_hash: genesis_hash.clone(),
                        seq: 0,
                    };

                    // message_id = blake3("DSM/envelope-msgid\0" || device_id || genesis_hash)[0..16]
                    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/envelope-msgid");
                    hasher.update(device_id.as_slice());
                    hasher.update(genesis_hash.as_slice());
                    let message_id = hasher.finalize().as_bytes()[..16].to_vec();

                    Ok::<pb::Envelope, String>(pb::Envelope {
                        version: 3,
                        headers: Some(headers),
                        message_id,
                        payload: None,
                    })
                }
            };

            // ---- Run future safely on/with a Tokio runtime ----
            let result = if tokio::runtime::Handle::try_current().is_ok() {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
            } else {
                crate::runtime::get_runtime().block_on(fut)
            };

            // ---- Encode as prost bytes (or error transport) ----
            let envl = match result {
                Ok(e) => e,
                Err(err) => {
                    log::warn!("addSecondaryDevice: helper failed: {}", err);
                    crate::jni::helpers::encode_error_transport(
                        500,
                        &format!("add_secondary_device failed: {err}"),
                    )
                }
            };
            encode_env_as_bytes(&mut env, envl)
        }),
    )
}

fn encode_env_as_bytes(env: &mut JNIEnv<'_>, envl: pb::Envelope) -> jni::sys::jbyteArray {
    let mut out = Vec::new();
    out.push(0x03); // Canonical framing byte for FramedEnvelopeV3
    envl.encode(&mut out).unwrap_or(());
    // Old: let out = envl.encode_to_vec();
    env.byte_array_from_slice(&out)
        .map(|a| a.into_raw())
        .unwrap_or_else(|e| {
            log::error!("encode_env_as_bytes: byte_array_from_slice failed: {e}");
            env.new_byte_array(0)
                .unwrap_or_else(|e2| {
                    log::error!("encode_env_as_bytes: new_byte_array failed: {e2}");
                    unsafe { JByteArray::from_raw(std::ptr::null_mut()) }
                })
                .into_raw()
        })
}
