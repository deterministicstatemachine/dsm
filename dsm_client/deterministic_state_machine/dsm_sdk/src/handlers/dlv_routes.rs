// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV (Deterministic Limbo Vault) route handlers for AppRouterImpl.
//!
//! Handles `dlv.*` invoke routes.  Post commit 5 the handlers delegate to
//! DlvSdk::create_vault (and the matching DLVManager methods) so the
//! creator self-loop advances a real Operation::Dlv* on the chain.
//!
//! In commit 1 the handler decodes the new DlvInstantiateV1 contract but
//! returns an explicit "not yet wired" error.  The prefs-KV shim paths
//! (dsm.dlv.*) are already deleted; no fallback, no parallel legacy.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::err;

impl AppRouterImpl {
    /// Dispatch handler for `dlv.*` invoke routes.
    pub(crate) async fn handle_dlv_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            // -------- dlv.create --------
            // Expects ArgPack{ codec=PROTO, body=DlvInstantiateV1 bytes }.
            // Real wiring lands in commit 5 (Operation::DlvCreate on actor
            // self-loop via core_sdk.execute_on_relationship).
            "dlv.create" => {
                let dlv_bytes: Vec<u8> = if let Ok(pack) = generated::ArgPack::decode(&*i.args) {
                    if pack.codec != generated::Codec::Proto as i32 {
                        return err("dlv.create: ArgPack.codec must be PROTO".into());
                    }
                    pack.body
                } else {
                    i.args.clone()
                };

                if dlv_bytes.is_empty() {
                    return err("dlv.create: empty DlvInstantiateV1 payload".into());
                }

                let _req = match generated::DlvInstantiateV1::decode(&*dlv_bytes) {
                    Ok(c) => c,
                    Err(e) => {
                        return err(format!("dlv.create: decode DlvInstantiateV1 failed: {e}"))
                    }
                };

                err("dlv.create: not yet wired — see commit 5 (Operation::DlvCreate)".into())
            }

            "dlv.invalidate" | "dlv.claim" | "dlv.unlock" => err(format!(
                "{}: not yet wired — see commit 5",
                i.method,
            )),

            other => err(format!("unknown dlv invoke method: {other}")),
        }
    }
}
