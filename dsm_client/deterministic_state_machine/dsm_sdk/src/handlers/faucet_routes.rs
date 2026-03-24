// SPDX-License-Identifier: MIT OR Apache-2.0
//! Faucet route handlers for AppRouterImpl.
//!
//! Handles `faucet.check_nearby` (query) and `faucet.claim`, `faucet.clean` (invoke).

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::{AppRouterImpl, FaucetState, build_testnet_faucet_policy};
use super::response_helpers::{pack_envelope_ok, err};
use crate::util::deterministic_time as dt;

impl AppRouterImpl {
    /// Dispatch handler for `faucet.check_nearby` query route.
    pub(crate) async fn handle_faucet_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "faucet.check_nearby" => {
                // Testnet faucet - always available
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("faucet.check_nearby: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::FaucetClaimRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode FaucetClaimRequest failed: {e}")),
                };

                // Validate device_id only
                let dev = req.device_id.clone();
                if dev.len() != 32 {
                    return err("faucet.check_nearby: device_id must be 32 bytes".into());
                }

                // Testnet faucet - always available
                let resp = generated::FaucetClaimResponse {
                    success: true,
                    tokens_received: 0,
                    next_available_index: 0,
                    message: "Testnet faucet available".to_string(),
                };
                // Return as Envelope.faucetClaimResponse (field 24)
                pack_envelope_ok(generated::envelope::Payload::FaucetClaimResponse(resp))
            }

            other => err(format!("unknown faucet query: {other}")),
        }
    }

    /// Dispatch handler for `faucet.claim` and `faucet.clean` invoke routes.
    pub(crate) async fn handle_faucet_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "faucet.claim" => {
                log::info!("[faucet.claim] invoke received");
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("faucet.claim: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::FaucetClaimRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode FaucetClaimRequest failed: {e}")),
                };

                // Validate device_id only (no geo checks for testnet faucet)
                let dev = req.device_id.clone();
                if dev.len() != 32 {
                    return err("faucet.claim: device_id must be 32 bytes".into());
                }

                log::info!(
                    "[faucet.claim] device_id_b32={}",
                    crate::util::text_id::encode_base32_crockford(&dev)
                );

                let identity = crate::util::text_id::encode_base32_crockford(&dev);
                let now = dt::tick();

                let (amount, next_available) = {
                    let mut faucet = self.faucet_state.lock().await;
                    match faucet.claim(&identity, now) {
                        Ok(v) => v,
                        Err(msg) => return err(format!("faucet.claim: {msg}")),
                    }
                };

                log::info!(
                    "[faucet.claim] granted amount={} next_available_index={}",
                    amount,
                    next_available
                );

                match self.wallet.mint_for_self(amount, Some("ERA")).await {
                    Ok(_) => {
                        log::error!(
                            "[faucet.claim] ❗ mint_for_self succeeded, amount={}",
                            amount
                        );

                        // Verify the canonical projection row was updated.
                        let device_id_txt =
                            crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                        if let Ok(Some(record)) =
                            crate::storage::client_db::get_balance_projection(&device_id_txt, "ERA")
                        {
                            log::error!("[faucet.claim] ❗ Post-mint ERA projection verification: device_id={} available={} locked={}", 
                                device_id_txt, record.available, record.locked);
                        } else {
                            log::error!("[faucet.claim] ❌ Post-mint ERA projection verification FAILED: projection not found");
                        }

                        let resp = generated::FaucetClaimResponse {
                            success: true,
                            tokens_received: amount,
                            next_available_index: next_available,
                            message: "Faucet claim successful".to_string(),
                        };
                        // NEW: Return as Envelope.faucetClaimResponse (field 24)
                        pack_envelope_ok(generated::envelope::Payload::FaucetClaimResponse(resp))
                    }
                    Err(e) => err(format!("faucet.claim failed: {e}")),
                }
            }

            // -------- faucet.clean (InvokeOp) --------
            "faucet.clean" => {
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("faucet.clean: ArgPack.codec must be PROTO".into());
                }

                log::info!("faucet.clean: resetting faucet state");
                {
                    let mut faucet = self.faucet_state.lock().await;
                    *faucet = FaucetState::new_with_policy(build_testnet_faucet_policy());
                }

                let resp = generated::AppStateResponse {
                    key: "faucet.clean".to_string(),
                    value: Some("cleanup_completed".to_string()),
                };
                // NEW: Return as Envelope.appStateResponse (field 22)
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            other => err(format!("unknown faucet invoke: {other}")),
        }
    }
}
