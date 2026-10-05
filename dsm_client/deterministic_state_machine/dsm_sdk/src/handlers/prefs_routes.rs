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

/// The app lock's settings are Rust's alone (`sdk::app_lock`): a caller that
/// could read its hash or write "unlocked" would not need the PIN.
fn not_the_locks(key: &str, route: &str) -> Result<(), String> {
    if crate::sdk::app_lock::OWNED_KEYS.contains(&key) {
        return Err(format!(
            "{route}: {key} belongs to the app lock, which only Rust reads and writes"
        ));
    }
    Ok(())
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
                if let Err(e) = not_the_locks(&req.key, "prefs.get") {
                    return err(e);
                }
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
                if let Err(e) = not_the_locks(&req.key, "prefs.set") {
                    return err(e);
                }
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

#[cfg(test)]
mod tests {
    use super::not_the_locks;

    /// The app lock's settings never pass through the preferences route: not
    /// its hash, its miss count, nor its locked flag. The frontend's own
    /// settings do.
    #[test]
    fn the_preferences_route_refuses_every_setting_of_the_app_lock() {
        for key in crate::sdk::app_lock::OWNED_KEYS {
            let refused = not_the_locks(key, "prefs.set").expect_err(key);
            assert!(refused.contains("belongs to the app lock"), "{refused}");
        }
        not_the_locks("lock_timeout_ms", "prefs.set").expect("a frontend setting");
    }
}
