// SPDX-License-Identifier: MIT OR Apache-2.0
//! Preferences route handlers.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};

/// The `AppStateRequest` in a PROTO `ArgPack`.
fn decode_request(params: &[u8], route: &str) -> Result<generated::AppStateRequest, String> {
    let pack = generated::ArgPack::decode(params)
        .map_err(|e| format!("{route}: decode ArgPack failed: {e}"))?;
    if pack.codec != generated::Codec::Proto as i32 {
        return Err(format!("{route}: expected ArgPack(codec=PROTO)"));
    }
    generated::AppStateRequest::decode(&*pack.body)
        .map_err(|e| format!("{route}: decode AppStateRequest failed: {e}"))
}

impl AppRouterImpl {
    /// Dispatch handler for all `prefs.*` query routes.
    pub(crate) async fn handle_prefs_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- prefs.get (QueryOp) --------
            "prefs.get" => {
                let req = match decode_request(&q.params, "prefs.get") {
                    Ok(req) => req,
                    Err(e) => return err(e),
                };
                let value = crate::sdk::app_state::AppState::get_pref(&req.key);
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: req.key,
                        value,
                    },
                ))
            }

            // -------- prefs.set (QueryOp) --------
            "prefs.set" => {
                let req = match decode_request(&q.params, "prefs.set") {
                    Ok(req) => req,
                    Err(e) => return err(e),
                };
                if let Err(e) = crate::sdk::app_state::AppState::set_pref(&req.key, &req.value) {
                    return err(format!("prefs.set: {e}"));
                }
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: req.key,
                        value: Some(req.value),
                    },
                ))
            }

            _ => err(format!("unknown prefs query: {}", q.path)),
        }
    }
}
