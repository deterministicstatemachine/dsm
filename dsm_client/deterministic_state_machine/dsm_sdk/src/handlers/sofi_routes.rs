// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi route handlers for AppRouterImpl.
//!
//! Handles `sofi.launch`.  Payload shape:
//!
//!   byte 0 = version (must be 1)
//!   byte 1 = mode    (0 = local, 1 = posted)
//!   byte 2 = type    (0 = vault, 1 = policy)
//!   rest   = proto-encoded body:
//!             type=0 → DlvInstantiateV1 (delegated to dlv.create)
//!             type=1 → TokenPolicyV3    (delegated to tokens.publishPolicy)
//!
//! Per plan Part D.5 this handler owns ONLY header parse + routing; the
//! actual state-machine work lives behind the two delegate routes so
//! SoFi stays a composition layer with no parallel legacy path.  Posted
//! mode additionally mirrors the resulting vault artifact via the DLV
//! manager's `create_vault_post` so the storage-sync pipeline can pick
//! it up after the core transition commits.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::err;

/// Extract the `value` field from an AppStateResponse buried in a framed
/// Envelope v3 result payload.  Returns `None` for any decode failure or
/// non-AppStateResponse payload.  Used by posted-mode mirroring.
fn extract_app_state_response_value(data: &[u8]) -> Option<String> {
    let payload = data.strip_prefix(&[0x03])?;
    let env = generated::Envelope::decode(payload).ok()?;
    match env.payload? {
        generated::envelope::Payload::AppStateResponse(asr) => asr.value,
        _ => None,
    }
}

impl AppRouterImpl {
    /// Dispatch handler for `sofi.*` invoke routes.
    pub(crate) async fn handle_sofi_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "sofi.launch" => self.sofi_launch(i).await,
            other => err(format!("unknown sofi invoke method: {other}")),
        }
    }

    async fn sofi_launch(&self, i: AppInvoke) -> AppResult {
        // Unwrap ArgPack if present; outer body is still header + proto payload.
        let blob: Vec<u8> = if let Ok(pack) = generated::ArgPack::decode(&*i.args) {
            if pack.codec != generated::Codec::Proto as i32 {
                return err("sofi.launch: ArgPack.codec must be PROTO".into());
            }
            pack.body
        } else {
            i.args.clone()
        };

        if blob.len() < 3 {
            return err("sofi.launch: payload must have at least 3-byte header".into());
        }

        let version = blob[0];
        let mode = blob[1];
        let typ = blob[2];

        if version != 1 {
            return err(format!(
                "sofi.launch: unsupported version {version}, expected 1"
            ));
        }
        if mode > 1 {
            return err(format!(
                "sofi.launch: invalid mode {mode}, expected 0 (local) or 1 (posted)"
            ));
        }

        let payload = &blob[3..];
        if payload.is_empty() {
            return err("sofi.launch: empty payload after header".into());
        }

        match typ {
            // ---- vault (type=0) ----
            0 => {
                // Pre-decode so a malformed body fails here with a targeted
                // error rather than inside dlv.create.
                if let Err(e) = generated::DlvInstantiateV1::decode(payload) {
                    return err(format!("sofi.launch: decode DlvInstantiateV1 failed: {e}"));
                }

                let argpack = generated::ArgPack {
                    schema_hash: None,
                    codec: generated::Codec::Proto as i32,
                    body: payload.to_vec(),
                };
                let inner = AppInvoke {
                    method: "dlv.create".to_string(),
                    args: argpack.encode_to_vec(),
                };
                let resp = self.handle_dlv_invoke(inner).await;

                if mode == 1 && resp.success {
                    // Posted mode: mirror the vault artifact.  The vault_id
                    // is carried back in the AppStateResponse from dlv.create
                    // inside a framed Envelope v3 payload.
                    if let Some(vid_b32) = extract_app_state_response_value(&resp.data) {
                        self.mirror_vault_post_best_effort(&vid_b32).await;
                    }
                }

                resp
            }

            // ---- policy (type=1) ----
            1 => {
                if let Err(e) = generated::TokenPolicyV3::decode(payload) {
                    return err(format!("sofi.launch: decode TokenPolicyV3 failed: {e}"));
                }
                let inner = AppInvoke {
                    method: "tokens.publishPolicy".to_string(),
                    args: payload.to_vec(),
                };
                self.handle_token_invoke(inner).await
            }

            _ => err(format!(
                "sofi.launch: unknown type byte {typ}, expected 0 (vault) or 1 (policy)"
            )),
        }
    }

    /// Posted-mode vault mirroring.  Best-effort: failure here does not
    /// fail the overall launch — the core transition has already committed
    /// and the vault is addressable locally.  The actual network POST is
    /// driven by the storage-sync pipeline reading from the DLV manager.
    async fn mirror_vault_post_best_effort(&self, vault_id_b32: &str) {
        let vid32 = match crate::util::text_id::decode_bytes32(vault_id_b32) {
            Some(v) => v,
            None => {
                log::warn!(
                    "[sofi.launch] posted-mode mirror skipped: invalid Base32 vault_id {vault_id_b32}"
                );
                return;
            }
        };
        let dlv_manager = self.bitcoin_tap.dlv_manager();
        match dlv_manager
            .create_vault_post(&vid32, "sofi-launch", None)
            .await
        {
            Ok(_) => {
                log::info!("[sofi.launch] posted-mode vault post prepared for {vault_id_b32}");
            }
            Err(e) => {
                log::warn!("[sofi.launch] posted-mode mirror failed to build vault post: {e}");
            }
        }
    }
}
