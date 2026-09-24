// SPDX-License-Identifier: Apache-2.0

//! Faucet routes — orchestration ONLY.
//!
//! `faucet.claim` drives the deterministic claim flow in
//! [`crate::sdk::faucet_claim_flow`]: win one generation of the network's
//! native ERA reserve with a release naming this device, advance the
//! fence-coupled `FaucetClaim` operation, publish the admission evidence,
//! register the economic root, and verify the result with the SAME predicate
//! any foreign device runs. Validity lives in Rust core and the economic verifier — this
//! file decodes a request and reports an outcome, nothing more.
//!
//! There is deliberately NO cooldown, NO per-identity quota, NO rate limiter
//! and NO claim history here. V1 has none of those policies, and machinery
//! for a policy the beta does not have would define it by accident. Repeated
//! claims by one identity are allowed while the reserve holds units.

use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};
use crate::bridge::{AppInvoke, AppResult};

impl AppRouterImpl {
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
                // A claim releases to the device that makes it: the request
                // names this device, or it is not this device's claim.
                if req.device_id.as_slice() != self.device_id_bytes.as_slice() {
                    return err(
                        "faucet.claim: the request names another device — a device claims only \
                         for itself"
                            .to_string(),
                    );
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
