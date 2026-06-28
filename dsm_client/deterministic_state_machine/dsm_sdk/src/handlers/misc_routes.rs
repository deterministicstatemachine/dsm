// SPDX-License-Identifier: MIT OR Apache-2.0
//! Miscellaneous route handlers for AppRouterImpl.
//!
//! Handles `debug.*` query routes and the `ble.command` invoke route.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};

impl AppRouterImpl {
    /// Dispatch handler for `debug.dump_state` and `debug.trigger_genesis` query routes.
    pub(crate) async fn handle_debug_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "debug.dump_state" => {
                // Forensic: dump entire in-memory state to logs (sensitive!)
                // Must be explicitly enabled with a query param: ?enable_debug_dump=1
                if !q.params.is_empty() && q.params == b"enable_debug_dump=1" {
                    use crate::sdk::app_state::AppState;
                    use crate::storage::client_db::{get_all_contacts, get_wallet_state};

                    // Dump AppState (forensic: sensitive!)
                    let device_id = AppState::get_device_id().unwrap_or_default();
                    let genesis_hash = AppState::get_genesis_hash().unwrap_or_default();
                    let public_key = AppState::get_public_key().unwrap_or_default();
                    let smt_root = AppState::get_smt_root().unwrap_or_default();
                    log::info!("[DEBUG_DUMP] AppState:");
                    log::info!(
                        "[DEBUG_DUMP] - device_id: {}",
                        crate::util::text_id::encode_base32_crockford(&device_id)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - genesis_hash: {}",
                        crate::util::text_id::encode_base32_crockford(&genesis_hash)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - public_key: {}",
                        crate::util::text_id::encode_base32_crockford(&public_key)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - smt_root: {}",
                        crate::util::text_id::encode_base32_crockford(&smt_root)
                    );

                    // Dump all contacts (forensic: sensitive!)
                    match get_all_contacts() {
                        Ok(contacts) => {
                            log::info!("[DEBUG_DUMP] Contacts ({}):", contacts.len());
                            for c in contacts {
                                log::info!(
                                    "[DEBUG_DUMP] - {}: device_id={}, genesis_hash={}",
                                    c.alias,
                                    crate::util::text_id::encode_base32_crockford(&c.device_id),
                                    crate::util::text_id::encode_base32_crockford(&c.genesis_hash)
                                );
                            }
                        }
                        Err(e) => log::warn!("[DEBUG_DUMP] Failed to dump contacts: {}", e),
                    }

                    // Dump wallet state (forensic: sensitive!)
                    let device_id_txt =
                        crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                    match get_wallet_state(&device_id_txt) {
                        Ok(state) => {
                            log::info!("[DEBUG_DUMP] WalletState:");
                            log::info!("[DEBUG_DUMP] - state: {:?}", state);
                        }
                        Err(e) => log::warn!("[DEBUG_DUMP] Failed to dump wallet state: {}", e),
                    }

                    pack_bytes_ok(
                        b"debug dump complete".to_vec(),
                        generated::Hash32 { v: vec![0u8; 32] },
                    )
                } else {
                    err("debug.dump_state requires ?enable_debug_dump=1".into())
                }
            }

            // -------- debug.trigger_genesis --------
            "debug.trigger_genesis" => {
                // Forensic: trigger a new genesis (MPC) from an existing device
                // WARNING: this is a destructive operation that resets state!
                if !q.params.is_empty() && q.params == b"enable_debug_genesis=1" {
                    // Get device identity (MUST be valid)
                    let device_id = match crate::sdk::app_state::AppState::get_device_id() {
                        Some(dev) if dev.len() == 32 => dev,
                        _ => {
                            return err("debug.trigger_genesis: invalid or missing device_id".into())
                        }
                    };
                    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);

                    // Confirm with the user (forensic: sensitive!)
                    log::warn!("[DEBUG_GENESIS] WARNING: This will RESET the device state and TRIGGER A NEW GENESIS!");
                    log::warn!("[DEBUG_GENESIS] Device ID (b32): {}", device_id_b32);
                    log::warn!("[DEBUG_GENESIS] To proceed, re-send this request with ?enable_debug_genesis=1");

                    err("debug.trigger_genesis: awaiting confirmation".into())
                } else {
                    err("debug.trigger_genesis requires ?enable_debug_genesis=1".into())
                }
            }

            other => err(format!("unknown debug query: {other}")),
        }
    }
}

impl AppRouterImpl {
    /// Dispatch handler for `ble.command` invoke route.
    pub(crate) async fn handle_ble_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "ble.command" => {
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("ble.command: ArgPack.codec must be PROTO".into());
                }
                // Decode BleCommand
                let cmd = match generated::BleCommand::decode(&*pack.body) {
                    Ok(c) => c,
                    Err(e) => return err(format!("decode BleCommand failed: {e}")),
                };

                // Dispatch to registered backend
                if let Some(backend) = crate::ble::get_ble_backend() {
                    let resp = backend.handle_command(cmd);
                    // NEW: Return as Envelope.bleCommandResponse (field 48)
                    pack_envelope_ok(generated::envelope::Payload::BleCommandResponse(resp))
                } else {
                    err("no BLE backend registered".into())
                }
            }

            other => err(format!("unknown ble invoke: {other}")),
        }
    }
}
