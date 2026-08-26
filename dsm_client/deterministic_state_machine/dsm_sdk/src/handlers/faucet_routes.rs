// SPDX-License-Identifier: Apache-2.0

//! Faucet routes — orchestration ONLY.
//!
//! `faucet.claim` drives the deterministic claim flow in
//! [`crate::sdk::faucet_claim_flow`]: win one single-use ticket of the
//! network's finite bootstrap allocation, advance the fence-coupled
//! `FaucetClaim` operation, publish the admission evidence, register the
//! economic root, and verify the result with the SAME predicate any foreign
//! device runs. Validity lives in Rust core and the economic verifier — this
//! file decodes a request and reports an outcome, nothing more.
//!
//! There is deliberately NO cooldown, NO per-identity quota, NO rate limiter
//! and NO claim history here. V1 has none of those policies, and machinery
//! for a policy V1 does not have would define it by accident. Repeated claims
//! by one identity are allowed while tickets remain.

use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};
use crate::bridge::{AppInvoke, AppQuery, AppResult};

impl AppRouterImpl {
    /// `faucet.check_nearby`: whether a claim is currently possible. With the
    /// ticket model there is no "nearby" and no cooldown — availability is
    /// "the flow is wired and the device has an identity".
    pub(crate) async fn handle_faucet_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "faucet.check_nearby" => {
                let pack = match generated::ArgPack::decode(&q.params[..]) {
                    Ok(p) => p,
                    Err(e) => return err(format!("faucet.check_nearby: bad ArgPack: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("faucet.check_nearby: params must be PROTO".to_string());
                }
                let req = match generated::FaucetClaimRequest::decode(&pack.body[..]) {
                    Ok(r) => r,
                    Err(e) => return err(format!("faucet.check_nearby: bad request: {e}")),
                };
                if req.device_id.len() != 32 {
                    return err("faucet.check_nearby: device_id must be 32 bytes".to_string());
                }
                let resp = generated::FaucetClaimResponse {
                    success: true,
                    tokens_received: 0,
                    next_available_index: 0,
                    message: format!(
                        "ERA faucet available: {} per claim from the network's finite ticket \
                         allocation",
                        dsm::economic::faucet::ERA_FAUCET_PAYOUT
                    ),
                };
                pack_envelope_ok(generated::envelope::Payload::FaucetClaimResponse(resp))
            }
            other => err(format!("unknown faucet query: {other}")),
        }
    }

    pub(crate) async fn handle_faucet_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "faucet.claim" => {
                let pack = match generated::ArgPack::decode(&i.args[..]) {
                    Ok(p) => p,
                    Err(e) => return err(format!("faucet.claim: bad ArgPack: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("faucet.claim: params must be PROTO".to_string());
                }
                let req = match generated::FaucetClaimRequest::decode(&pack.body[..]) {
                    Ok(r) => r,
                    Err(e) => return err(format!("faucet.claim: bad request: {e}")),
                };
                if req.device_id.len() != 32 {
                    return err("faucet.claim: device_id must be 32 bytes".to_string());
                }

                // The claimant's committed network, from the stored genesis
                // record — the same value Genesis v3 committed. Fail closed:
                // no record, no claim.
                let g_vec = crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();
                let genesis_b32 = match <[u8; 32]>::try_from(g_vec.as_slice()) {
                    Ok(g) => crate::util::text_id::encode_base32_crockford(&g),
                    Err(_) => return err("faucet.claim: no genesis identity".to_string()),
                };
                let network_id =
                    match crate::storage::client_db::get_genesis_record_by_id(&genesis_b32) {
                        Ok(Some(rec)) => rec.network_id.into_bytes(),
                        Ok(None) => {
                            return err(
                                "faucet.claim: no stored genesis record — cannot determine the \
                             committed network"
                                    .to_string(),
                            )
                        }
                        Err(e) => return err(format!("faucet.claim: genesis record: {e}")),
                    };

                match crate::sdk::faucet_claim_flow::claim_era_faucet(&self.core_sdk, &network_id)
                    .await
                {
                    Ok(outcome) => {
                        let resp = generated::FaucetClaimResponse {
                            success: true,
                            tokens_received: outcome.tokens_received,
                            next_available_index: 0,
                            message: format!(
                                "claimed {} ERA (economic position {})",
                                outcome.tokens_received, outcome.economic_position
                            ),
                        };
                        pack_envelope_ok(generated::envelope::Payload::FaucetClaimResponse(resp))
                    }
                    Err(e) => err(format!("faucet.claim: {e}")),
                }
            }
            other => err(format!("unknown faucet invoke: {other}")),
        }
    }
}
