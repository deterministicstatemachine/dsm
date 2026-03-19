// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV (Deterministic Limbo Vault) route handlers for AppRouterImpl.
//!
//! Handles `dlv.create` and (reserved) `dlv.open` invoke routes.
//!
//! The developer tooling path (DevDlvScreen) sends a Base32-encoded `DlvCreateV3`
//! proto wrapped in an `ArgPack`.  Rust validates the fields, persists the vault
//! descriptor under `dsm.dlv.<vault_id_b32>`, and returns the vault_id as
//! Base32 in an `AppStateResponse`.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

const DLV_PREFIX: &str = "dsm.dlv.";
const DLV_INDEX_KEY: &str = "dsm.dlv.index";

fn app_state_get(key: &str) -> String {
    crate::sdk::app_state::AppState::handle_app_state_request(key, "get", "")
}

fn app_state_set(key: &str, value: &str) {
    let _ = crate::sdk::app_state::AppState::handle_app_state_request(key, "set", value);
}

impl AppRouterImpl {
    /// Dispatch handler for `dlv.*` invoke routes.
    pub(crate) async fn handle_dlv_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            // -------- dlv.create --------
            // Expects ArgPack{ codec=PROTO, body=DlvCreateV3 bytes }
            "dlv.create" => {
                // Unwrap ArgPack if present, fall back to bare bytes.
                let dlv_bytes: Vec<u8> = if let Ok(pack) = generated::ArgPack::decode(&*i.args) {
                    if pack.codec != generated::Codec::Proto as i32 {
                        return err("dlv.create: ArgPack.codec must be PROTO".into());
                    }
                    pack.body
                } else {
                    i.args.clone()
                };

                if dlv_bytes.is_empty() {
                    return err("dlv.create: empty DlvCreateV3 payload".into());
                }

                let create = match generated::DlvCreateV3::decode(&*dlv_bytes) {
                    Ok(c) => c,
                    Err(e) => return err(format!("dlv.create: decode DlvCreateV3 failed: {e}")),
                };

                // Validate required fixed-length fields.
                if create.device_id.len() != 32 {
                    return err("dlv.create: device_id must be 32 bytes".into());
                }
                if create.policy_digest.len() != 32 {
                    return err("dlv.create: policy_digest must be 32 bytes".into());
                }
                if create.precommit.len() != 32 {
                    return err("dlv.create: precommit must be 32 bytes".into());
                }
                if create.vault_id.len() != 32 {
                    return err("dlv.create: vault_id must be 32 bytes".into());
                }
                // parent_digest is optional; if present must be 32 bytes.
                if !create.parent_digest.is_empty() && create.parent_digest.len() != 32 {
                    return err("dlv.create: parent_digest must be 32 bytes when set".into());
                }

                let vault_id_b32 = crate::util::text_id::encode_base32_crockford(&create.vault_id);

                // Persist DLV descriptor keyed by vault_id.
                let key = format!("{DLV_PREFIX}{vault_id_b32}");
                let encoded = crate::util::text_id::encode_base32_crockford(&dlv_bytes);
                app_state_set(&key, &encoded);

                // Update the DLV index (comma-separated list of vault_id B32).
                let existing_index = app_state_get(DLV_INDEX_KEY);
                let mut ids: Vec<String> = if existing_index.is_empty() {
                    Vec::new()
                } else {
                    existing_index.split(',').map(|s| s.to_string()).collect()
                };
                if !ids.iter().any(|id| id == &vault_id_b32) {
                    ids.push(vault_id_b32.clone());
                }
                app_state_set(DLV_INDEX_KEY, &ids.join(","));

                log::info!(
                    "[DLV] dlv.create: registered vault_id={} device_id_b32={}",
                    vault_id_b32,
                    crate::util::text_id::encode_base32_crockford(&create.device_id),
                );

                let resp = generated::AppStateResponse {
                    key: "dlv.create".to_string(),
                    value: Some(vault_id_b32),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            other => err(format!("unknown dlv invoke method: {other}")),
        }
    }
}
