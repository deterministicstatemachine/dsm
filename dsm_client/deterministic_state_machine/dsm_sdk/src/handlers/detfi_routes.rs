// SPDX-License-Identifier: MIT OR Apache-2.0
//! DeTFi route handlers for AppRouterImpl.
//!
//! Handles `detfi.launch` invoke route.  Byte 0 = version (must be 1),
//! byte 1 = mode (0=local, 1=posted), byte 2 = type (0=vault, 1=policy).
//! Type=0 payload is DlvInstantiateV1; type=1 payload is TokenPolicyV3.
//!
//! Post commit 6 the handler delegates to `dlv.create` and
//! `tokens.publishPolicy`.  In commit 1 the handler decodes the new
//! contract but returns "not yet wired".  The prefs-KV shim paths
//! (dsm.detfi.*, dsm.dlv.*) are deleted; no fallback, no parallel legacy.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::err;

impl AppRouterImpl {
    /// Dispatch handler for `detfi.*` invoke routes.
    pub(crate) async fn handle_detfi_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "detfi.launch" => {
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
                    0 => {
                        let payload = &blob[3..];
                        if payload.is_empty() {
                            return err(
                                "detfi.launch: empty DlvInstantiateV1 payload after header".into(),
                            );
                        }
                        let _req = match generated::DlvInstantiateV1::decode(payload) {
                            Ok(c) => c,
                            Err(e) => {
                                return err(format!(
                                    "detfi.launch: decode DlvInstantiateV1 failed: {e}"
                                ))
                            }
                        };
                        err("detfi.launch (vault): not yet wired — see commit 6".into())
                    }
                    1 => {
                        let payload = &blob[3..];
                        if payload.is_empty() {
                            return err("detfi.launch: empty policy payload after header".into());
                        }
                        let _p = match generated::TokenPolicyV3::decode(payload) {
                            Ok(p) => p,
                            Err(e) => {
                                return err(format!(
                                    "detfi.launch: decode TokenPolicyV3 failed: {e}"
                                ))
                            }
                        };
                        err("detfi.launch (policy): not yet wired — see commit 6".into())
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
