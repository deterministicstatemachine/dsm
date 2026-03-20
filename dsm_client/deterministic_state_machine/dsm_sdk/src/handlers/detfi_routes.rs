// SPDX-License-Identifier: MIT OR Apache-2.0
//! DeTFi route handlers for AppRouterImpl.
//!
//! Handles `detfi.launch` invoke route.
//!
//! The phone UI sends a 3-byte header followed by a payload wrapped in an
//! `ArgPack`.  Byte 0 = version (must be 1), byte 1 = mode (0=local,
//! 1=posted), byte 2 = type (0=vault, 1=policy).
//!
//! For vault payloads the blob carries a template `DlvCreateV3` with a
//! zeroed device_id.  Rust fills the real device_id from app-state,
//! recomputes the vault_id via BLAKE3, persists the descriptor, and
//! optionally mirrors it to the DLV namespace when mode=posted.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

const DETFI_PREFIX: &str = "dsm.detfi.";
const DETFI_INDEX_KEY: &str = "dsm.detfi.index";
const DETFI_POLICY_PREFIX: &str = "dsm.detfi.policy.";
const DLV_PREFIX: &str = "dsm.dlv.";
const DLV_INDEX_KEY: &str = "dsm.dlv.index";

fn app_state_get(key: &str) -> String {
    crate::sdk::app_state::AppState::handle_app_state_request(key, "get", "")
}

fn app_state_set(key: &str, value: &str) {
    let _ = crate::sdk::app_state::AppState::handle_app_state_request(key, "set", value);
}

/// Recompute vault_id: BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)
fn compute_vault_id(device_id: &[u8], policy_digest: &[u8], precommit: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"DSM/dlv\0");
    hasher.update(device_id);
    hasher.update(policy_digest);
    hasher.update(precommit);
    *hasher.finalize().as_bytes()
}

impl AppRouterImpl {
    /// Dispatch handler for `detfi.*` invoke routes.
    pub(crate) async fn handle_detfi_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            // -------- detfi.launch --------
            "detfi.launch" => {
                // Unwrap ArgPack if present, fall back to bare bytes.
                let blob: Vec<u8> = if let Ok(pack) = generated::ArgPack::decode(&*i.args) {
                    if pack.codec != generated::Codec::Proto as i32 {
                        return err("detfi.launch: ArgPack.codec must be PROTO".into());
                    }
                    pack.body
                } else {
                    i.args.clone()
                };

                if blob.len() < 3 {
                    return err("detfi.launch: payload must have at least 3-byte header".into());
                }

                let version = blob[0];
                let mode = blob[1];
                let typ = blob[2];

                if version != 1 {
                    return err(format!(
                        "detfi.launch: unsupported version {version}, expected 1"
                    ));
                }
                if mode > 1 {
                    return err(format!(
                        "detfi.launch: invalid mode {mode}, expected 0 (local) or 1 (posted)"
                    ));
                }

                match typ {
                    // ---- vault (type=0) ----
                    0 => {
                        let dlv_bytes = &blob[3..];
                        if dlv_bytes.is_empty() {
                            return err(
                                "detfi.launch: empty DlvCreateV3 payload after header".into()
                            );
                        }

                        let create = match generated::DlvCreateV3::decode(dlv_bytes) {
                            Ok(c) => c,
                            Err(e) => {
                                return err(format!("detfi.launch: decode DlvCreateV3 failed: {e}"))
                            }
                        };

                        // Validate required fixed-length fields.
                        if create.device_id.len() != 32 {
                            return err("detfi.launch: device_id must be 32 bytes".into());
                        }
                        if create.policy_digest.len() != 32 {
                            return err("detfi.launch: policy_digest must be 32 bytes".into());
                        }
                        if create.precommit.len() != 32 {
                            return err("detfi.launch: precommit must be 32 bytes".into());
                        }
                        if create.vault_id.len() != 32 {
                            return err("detfi.launch: vault_id must be 32 bytes".into());
                        }
                        if !create.parent_digest.is_empty() && create.parent_digest.len() != 32 {
                            return err(
                                "detfi.launch: parent_digest must be 32 bytes when set".into()
                            );
                        }

                        // Resolve device_id: template blob has all-zeros; fill
                        // from app-state when available.
                        let device_id = {
                            let stored = app_state_get("dsm.device_id");
                            if stored.is_empty() {
                                // Dev mode: keep the zero device_id from the template.
                                create.device_id.clone()
                            } else {
                                match crate::util::text_id::decode_base32_crockford(&stored) {
                                    Some(id) => id,
                                    None => {
                                        return err(
                                            "detfi.launch: failed to decode dsm.device_id".into()
                                        )
                                    }
                                }
                            }
                        };

                        // Recompute vault_id deterministically.
                        let vault_id =
                            compute_vault_id(&device_id, &create.policy_digest, &create.precommit);

                        // Rebuild DlvCreateV3 with filled device_id and recomputed vault_id.
                        let filled = generated::DlvCreateV3 {
                            device_id: device_id.clone(),
                            vault_id: vault_id.to_vec(),
                            policy_digest: create.policy_digest.clone(),
                            precommit: create.precommit.clone(),
                            parent_digest: create.parent_digest.clone(),
                            ..create
                        };

                        let filled_bytes = filled.encode_to_vec();
                        let vault_id_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);
                        let encoded = crate::util::text_id::encode_base32_crockford(&filled_bytes);

                        // Persist under detfi namespace.
                        let detfi_key = format!("{DETFI_PREFIX}{vault_id_b32}");
                        app_state_set(&detfi_key, &encoded);

                        // Update detfi index.
                        let existing_index = app_state_get(DETFI_INDEX_KEY);
                        let mut ids: Vec<String> = if existing_index.is_empty() {
                            Vec::new()
                        } else {
                            existing_index.split(',').map(|s| s.to_string()).collect()
                        };
                        if !ids.iter().any(|id| id == &vault_id_b32) {
                            ids.push(vault_id_b32.clone());
                        }
                        app_state_set(DETFI_INDEX_KEY, &ids.join(","));

                        // If mode=posted, also persist under dlv namespace so
                        // storage sync picks it up.
                        if mode == 1 {
                            let dlv_key = format!("{DLV_PREFIX}{vault_id_b32}");
                            app_state_set(&dlv_key, &encoded);

                            let dlv_existing = app_state_get(DLV_INDEX_KEY);
                            let mut dlv_ids: Vec<String> = if dlv_existing.is_empty() {
                                Vec::new()
                            } else {
                                dlv_existing.split(',').map(|s| s.to_string()).collect()
                            };
                            if !dlv_ids.iter().any(|id| id == &vault_id_b32) {
                                dlv_ids.push(vault_id_b32.clone());
                            }
                            app_state_set(DLV_INDEX_KEY, &dlv_ids.join(","));
                        }

                        log::info!(
                            "[DeTFi] detfi.launch: vault registered vault_id={} mode={} device_id_b32={}",
                            vault_id_b32,
                            if mode == 0 { "local" } else { "posted" },
                            crate::util::text_id::encode_base32_crockford(&device_id),
                        );

                        let resp = generated::AppStateResponse {
                            key: "detfi.launch".to_string(),
                            value: Some(vault_id_b32),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }

                    // ---- policy (type=1) ----
                    1 => {
                        let policy_bytes = &blob[3..];
                        if policy_bytes.is_empty() {
                            return err("detfi.launch: empty policy payload after header".into());
                        }

                        let anchor = blake3::hash(policy_bytes);
                        let anchor_b32 =
                            crate::util::text_id::encode_base32_crockford(anchor.as_bytes());

                        let key = format!("{DETFI_POLICY_PREFIX}{anchor_b32}");
                        let encoded = crate::util::text_id::encode_base32_crockford(policy_bytes);
                        app_state_set(&key, &encoded);

                        log::info!(
                            "[DeTFi] detfi.launch: policy persisted anchor={}",
                            anchor_b32,
                        );

                        let resp = generated::AppStateResponse {
                            key: "detfi.launch".to_string(),
                            value: Some(anchor_b32),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }

                    _ => err(format!(
                        "detfi.launch: unknown type byte {typ}, expected 0 (vault) or 1 (policy)"
                    )),
                }
            }

            other => err(format!("unknown detfi invoke method: {other}")),
        }
    }
}
