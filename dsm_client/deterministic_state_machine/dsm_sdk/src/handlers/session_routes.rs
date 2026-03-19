// SPDX-License-Identifier: MIT OR Apache-2.0
//! Session route handlers for the app router.
//!
//! Query routes:
//! - `session.status` → returns envelope-wrapped `AppSessionStateProto`
//!
//! Invoke routes:
//! - `session.lock` → lock the session
//! - `session.unlock` → unlock the session
//! - `session.configure_lock` → configure lock policy owned by Rust
//! - `session.hardware_update` → update hardware facts from Kotlin
//! - `session.set_fatal_error` → set fatal error
//! - `session.clear_fatal_error` → clear fatal error

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::sdk::session_manager::SESSION_MANAGER;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    /// Dispatch handler for `session.*` query routes.
    pub(crate) async fn handle_session_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "session.status" => {
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }
            _ => err(format!("unknown session query: {}", q.path)),
        }
    }

    /// Dispatch handler for `session.*` invoke routes.
    pub(crate) async fn handle_session_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "session.lock" => {
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                mgr.lock_locked = true;
                log::info!("SessionRoutes: session locked via invoke");
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            "session.unlock" => {
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                mgr.lock_locked = false;
                log::info!("SessionRoutes: session unlocked via invoke");
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            "session.configure_lock" => {
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("session.configure_lock: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::SessionConfigureLockRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "session.configure_lock: decode SessionConfigureLockRequest failed: {e}"
                        ))
                    }
                };

                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.configure_lock(req.enabled, &req.method, req.lock_on_pause);
                mgr.persist_lock_config_to_app_state();
                log::info!(
                    "SessionRoutes: lock configured enabled={} method={} lock_on_pause={}",
                    mgr.lock_enabled,
                    mgr.lock_method,
                    mgr.lock_on_pause
                );
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            "session.hardware_update" => {
                let facts = match generated::SessionHardwareFactsProto::decode(&*i.args) {
                    Ok(f) => f,
                    Err(e) => {
                        return err(format!(
                            "session.hardware_update: decode SessionHardwareFactsProto failed: {e}"
                        ))
                    }
                };
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                mgr.apply_hardware_facts(&facts);
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            "session.set_fatal_error" => {
                // args = ArgPack with body = error message string (UTF-8 bytes)
                let error_msg = match generated::ArgPack::decode(&*i.args) {
                    Ok(pack) => String::from_utf8_lossy(&pack.body).to_string(),
                    Err(_) => {
                        // Fallback: treat raw args as UTF-8 error message
                        String::from_utf8_lossy(&i.args).to_string()
                    }
                };
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                mgr.fatal_error = if error_msg.is_empty() {
                    None
                } else {
                    Some(error_msg.clone())
                };
                log::error!("SessionRoutes: fatal error set: {}", error_msg);
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            "session.clear_fatal_error" => {
                let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
                mgr.sync_lock_config_from_app_state();
                mgr.fatal_error = None;
                log::info!("SessionRoutes: fatal error cleared");
                let snapshot = mgr.compute_snapshot();
                pack_envelope_ok(generated::envelope::Payload::SessionStateResponse(snapshot))
            }

            _ => err(format!("unknown session invoke: {}", i.method)),
        }
    }
}
