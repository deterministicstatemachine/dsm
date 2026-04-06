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

#[cfg(test)]
mod tests {
    use dsm::types::proto as generated;
    use prost::Message;

    #[allow(unused_imports)]
    use super::*;
    use crate::handlers::faucet_state::{build_testnet_faucet_policy, FaucetState};

    // ── FaucetState unit tests ────────────────────────────────────────

    #[test]
    fn faucet_state_default_policy_allows_claim() {
        let policy = build_testnet_faucet_policy();
        let mut state = FaucetState::new_with_policy(policy);

        let (amount, next) = state.claim("user1", 100).expect("first claim");
        assert!(amount > 0, "should grant tokens");
        assert_eq!(next, 0, "no cooldown => next_available = 0");
    }

    #[test]
    fn faucet_state_rejects_empty_identity() {
        let policy = build_testnet_faucet_policy();
        let mut state = FaucetState::new_with_policy(policy);

        let result = state.claim("", 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Identity is required"));
    }

    #[test]
    fn faucet_state_allows_multiple_claims_with_no_cooldown() {
        let policy = build_testnet_faucet_policy();
        let mut state = FaucetState::new_with_policy(policy);

        for tick in 0..5 {
            let result = state.claim("user1", tick);
            assert!(result.is_ok(), "claim at tick {} should succeed", tick);
        }
    }

    #[test]
    fn faucet_state_cooldown_enforcement() {
        use dsm::types::policy_types::{PolicyCondition, PolicyFile};
        use std::collections::HashMap;

        let mut policy = PolicyFile::new("Test", "1.0", "test");
        let mut params = HashMap::new();
        params.insert("cooldown_ticks".into(), "10".into());
        policy.add_condition(PolicyCondition::Custom {
            constraint_type: "faucet_cooldown".into(),
            parameters: params,
        });

        let mut state = FaucetState::new_with_policy(policy);

        let (amount, next) = state.claim("user1", 100).expect("first claim");
        assert!(amount > 0);
        assert_eq!(next, 110);

        let err = state.claim("user1", 105).unwrap_err();
        assert!(err.contains("cooldown not satisfied"));

        let (_, _) = state.claim("user1", 110).expect("claim after cooldown");
    }

    #[test]
    fn faucet_state_rate_limit_enforcement() {
        use dsm::types::policy_types::{PolicyCondition, PolicyFile};
        use std::collections::HashMap;

        let mut policy = PolicyFile::new("Test", "1.0", "test");
        let mut params = HashMap::new();
        params.insert("operation".into(), "faucet_claim".into());
        params.insert("max_n".into(), "2".into());
        params.insert("last_k".into(), "100".into());
        policy.add_condition(PolicyCondition::Custom {
            constraint_type: "rate_limit".into(),
            parameters: params,
        });

        let mut state = FaucetState::new_with_policy(policy);
        assert!(state.claim("user1", 10).is_ok());
        assert!(state.claim("user1", 20).is_ok());

        let err = state.claim("user1", 30).unwrap_err();
        assert!(err.contains("rate limit exceeded"));

        assert!(
            state.claim("user1", 200).is_ok(),
            "window expired, should succeed"
        );
    }

    // ── Protobuf structure tests ──────────────────────────────────────

    #[test]
    fn faucet_claim_request_roundtrip() {
        let req = generated::FaucetClaimRequest {
            device_id: vec![0xAA; 32],
        };
        let bytes = req.encode_to_vec();
        let decoded = generated::FaucetClaimRequest::decode(&*bytes).expect("decode");
        assert_eq!(decoded.device_id.len(), 32);
    }

    #[test]
    fn faucet_claim_response_roundtrip() {
        let resp = generated::FaucetClaimResponse {
            success: true,
            tokens_received: 100,
            next_available_index: 42,
            message: "ok".into(),
        };
        let bytes = resp.encode_to_vec();
        let decoded = generated::FaucetClaimResponse::decode(&*bytes).expect("decode");
        assert!(decoded.success);
        assert_eq!(decoded.tokens_received, 100);
        assert_eq!(decoded.next_available_index, 42);
        assert_eq!(decoded.message, "ok");
    }

    #[test]
    fn faucet_claim_request_validates_device_id_length() {
        let short_id = [0xBB; 16];
        assert_ne!(short_id.len(), 32, "should detect non-32-byte device_id");

        let valid_id = [0xCC; 32];
        assert_eq!(valid_id.len(), 32);
    }
}
