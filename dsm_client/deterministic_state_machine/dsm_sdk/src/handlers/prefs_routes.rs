// SPDX-License-Identifier: MIT OR Apache-2.0
//! Preferences route handlers.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for all `prefs.*` query routes.
    pub(crate) async fn handle_prefs_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- prefs.get (QueryOp) --------
            "prefs.get" => {
                // Expect ArgPack with AppStateRequest{key, operation?}
                let (key, _op): (String, String) = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::AppStateRequest::decode(&*pack.body) {
                            Ok(req) => (req.key, req.operation),
                            Err(e) => return err(format!("decode AppStateRequest failed: {e}")),
                        }
                    }
                    _ => return err("prefs.get: expected ArgPack(codec=PROTO)".into()),
                };

                let val =
                    crate::sdk::app_state::AppState::handle_app_state_request(&key, "get", "");
                let resp = generated::AppStateResponse {
                    key,
                    value: if val.is_empty() { None } else { Some(val) },
                };
                // NEW: Return as Envelope.appStateResponse (field 22)
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- prefs.set (QueryOp) --------
            "prefs.set" => {
                // Expect ArgPack with AppStateRequest{key, value}
                let (key, value): (String, String) = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::AppStateRequest::decode(&*pack.body) {
                            Ok(req) => (req.key, req.value),
                            Err(e) => return err(format!("decode AppStateRequest failed: {e}")),
                        }
                    }
                    _ => return err("prefs.set: expected ArgPack(codec=PROTO)".into()),
                };

                let new_val =
                    crate::sdk::app_state::AppState::handle_app_state_request(&key, "set", &value);
                let resp = generated::AppStateResponse {
                    key,
                    value: if new_val.is_empty() {
                        None
                    } else {
                        Some(new_val)
                    },
                };
                // NEW: Return as Envelope.appStateResponse (field 22)
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            _ => err(format!("unknown prefs query: {}", q.path)),
        }
    }
}
