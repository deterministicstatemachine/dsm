// SPDX-License-Identifier: MIT OR Apache-2.0

//! SoFi routes (SoFi §27). The app reaches SoFi only through these. Each route
//! decodes the user's intent, checks its shape, and hands it to its
//! orchestration entry in `sdk::sofi_flow`; producers assemble, Core decides
//! (§26). A route never interprets a storage read.

use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};
use crate::bridge::{AppInvoke, AppResult};
use crate::sdk::sofi_flow::{
    CloseIntent, CreateVaultIntent, FindRouteIntent, PositionOutcome, PositionState, RelayIntent,
    SetupIntent, TradeIntent,
};

/// The most hops a route may have (`ROUTE_MAX_LEGS`, SoFi §31).
const ROUTE_MAX_LEGS: usize = dsm::sofi::wire::ROUTE_MAX_LEGS;

fn d32(bytes: &[u8], what: &str, route: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|_| format!("{route}: {what} must be 32 bytes"))
}

fn request<T: Message + Default>(i: &AppInvoke) -> Result<T, String> {
    let arg_pack = generated::ArgPack::decode(&*i.args)
        .map_err(|e| format!("{}: decode ArgPack failed: {e}", i.method))?;
    T::decode(&*arg_pack.body).map_err(|e| format!("{}: decode request failed: {e}", i.method))
}

fn position_response(outcome: PositionOutcome) -> AppResult {
    let state = match outcome.state {
        PositionState::Realized => generated::SofiPositionState::Realized,
        PositionState::Void => generated::SofiPositionState::Void,
        PositionState::Invalid => generated::SofiPositionState::Invalid,
        PositionState::RetriesExhausted => generated::SofiPositionState::RetriesExhausted,
    };
    pack_envelope_ok(generated::envelope::Payload::SofiPositionResponse(
        generated::SofiPositionResponse {
            position: outcome.position,
            state: state as i32,
        },
    ))
}

impl AppRouterImpl {
    pub(crate) async fn handle_sofi_invoke(&self, i: AppInvoke) -> AppResult {
        let network = match crate::sdk::economic_admission_flow::committed_network_id() {
            Ok(n) => n,
            Err(e) => return err(format!("{}: no committed network: {e}", i.method)),
        };
        // The network's pinned set (DSM Amendment A5): every SoFi cell and
        // object lives on it.
        let set = match crate::sdk::storage_set::canonical_set(&network) {
            Ok(s) => s,
            Err(e) => return err(format!("{}: no pinned storage set: {e}", i.method)),
        };
        match i.method.as_str() {
            "sofi.createVault" => self.sofi_create_vault(&i, &set).await,
            "sofi.setup" => self.sofi_setup(&i, &set).await,
            "sofi.findRoute" => self.sofi_find_route(&i, &set).await,
            "sofi.trade" => self.sofi_trade(&i, &set).await,
            "sofi.route" => self.sofi_route(&i, &set).await,
            "sofi.close" => self.sofi_close(&i, &set).await,
            "sofi.relay" => self.sofi_relay(&i, &set).await,
            "sofi.resolve" => self.sofi_resolve(&set).await,
            other => err(format!("unknown SoFi route: {other}")),
        }
    }

    async fn sofi_create_vault(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.createVault";
        let req: generated::SofiCreateVaultRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<CreateVaultIntent, String> {
            let a = d32(&req.token_a_policy_commit, "token_a_policy_commit", ROUTE)?;
            let b = d32(&req.token_b_policy_commit, "token_b_policy_commit", ROUTE)?;
            if a >= b {
                return Err(format!(
                    "{ROUTE}: the pair must be ordered, token_a < token_b"
                ));
            }
            if req.reserve_a == 0 || req.reserve_b == 0 {
                return Err(format!("{ROUTE}: both reserves must be positive"));
            }
            Ok(CreateVaultIntent {
                token_a_policy_commit: a,
                token_b_policy_commit: b,
                reserve_a: req.reserve_a,
                reserve_b: req.reserve_b,
                fee_bps: req.fee_bps,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::create_vault(&self.core_sdk, set, &intent).await {
            Ok(done) => pack_envelope_ok(generated::envelope::Payload::SofiVaultCreatedResponse(
                generated::SofiVaultCreatedResponse {
                    vault_id: done.vault_id.to_vec(),
                    position: done.position,
                },
            )),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_setup(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.setup";
        let req: generated::SofiSetupRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let vault_id = match d32(&req.vault_id, "vault_id", ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::setup(&self.core_sdk, set, &SetupIntent { vault_id }).await {
            Ok(done) => pack_envelope_ok(generated::envelope::Payload::SofiSetupResponse(
                generated::SofiSetupResponse {
                    setup_ref: done.setup_ref.to_vec(),
                    position: done.position,
                },
            )),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_find_route(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.findRoute";
        let req: generated::SofiFindRouteRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<FindRouteIntent, String> {
            let token_in = d32(&req.token_in_policy_commit, "token_in_policy_commit", ROUTE)?;
            let token_out = d32(
                &req.token_out_policy_commit,
                "token_out_policy_commit",
                ROUTE,
            )?;
            if token_in == token_out {
                return Err(format!("{ROUTE}: the two tokens must differ"));
            }
            if req.amount_in == 0 {
                return Err(format!("{ROUTE}: amount_in must be positive"));
            }
            Ok(FindRouteIntent {
                token_in_policy_commit: token_in,
                token_out_policy_commit: token_out,
                amount_in: req.amount_in,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::find_route(&self.core_sdk, set, &intent).await {
            Ok(hops) => pack_envelope_ok(generated::envelope::Payload::SofiFindRouteResponse(
                generated::SofiFindRouteResponse {
                    hops: hops
                        .into_iter()
                        .map(|h| generated::SofiHopV1 {
                            vault_id: h.vault_id.to_vec(),
                            parent_root: h.parent_root.to_vec(),
                            token_in_policy_commit: h.token_in_policy_commit.to_vec(),
                            token_out_policy_commit: h.token_out_policy_commit.to_vec(),
                            amount_in: h.amount_in,
                            amount_out: h.amount_out,
                        })
                        .collect(),
                },
            )),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_trade(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.trade";
        let req: generated::SofiTradeRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<TradeIntent, String> {
            let vault_id = d32(&req.vault_id, "vault_id", ROUTE)?;
            let token_in = d32(&req.token_in_policy_commit, "token_in_policy_commit", ROUTE)?;
            if req.amount_in == 0 {
                return Err(format!("{ROUTE}: amount_in must be positive"));
            }
            Ok(TradeIntent {
                vault_ids: vec![vault_id],
                token_in_policy_commit: token_in,
                amount_in: req.amount_in,
                min_amount_out: req.min_amount_out,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::trade(&self.core_sdk, set, &intent).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_route(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.route";
        let req: generated::SofiRouteRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<TradeIntent, String> {
            if req.vault_ids.is_empty() || req.vault_ids.len() > ROUTE_MAX_LEGS {
                return Err(format!("{ROUTE}: a route has 1..={ROUTE_MAX_LEGS} hops"));
            }
            let mut vault_ids = Vec::with_capacity(req.vault_ids.len());
            for v in &req.vault_ids {
                let v = d32(v, "vault_id", ROUTE)?;
                if vault_ids.contains(&v) {
                    return Err(format!("{ROUTE}: a route's vaults must be distinct"));
                }
                vault_ids.push(v);
            }
            let token_in = d32(&req.token_in_policy_commit, "token_in_policy_commit", ROUTE)?;
            if req.amount_in == 0 {
                return Err(format!("{ROUTE}: amount_in must be positive"));
            }
            Ok(TradeIntent {
                vault_ids,
                token_in_policy_commit: token_in,
                amount_in: req.amount_in,
                min_amount_out: req.min_amount_out,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::trade(&self.core_sdk, set, &intent).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_close(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.close";
        let req: generated::SofiCloseRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let vault_id = match d32(&req.vault_id, "vault_id", ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::close(&self.core_sdk, set, &CloseIntent { vault_id }).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_relay(
        &self,
        i: &AppInvoke,
        set: &crate::sdk::storage_set::StorageSet,
    ) -> AppResult {
        const ROUTE: &str = "sofi.relay";
        let req: generated::SofiRelayRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<RelayIntent, String> {
            Ok(RelayIntent {
                trader_genesis: d32(&req.trader_genesis, "trader_genesis", ROUTE)?,
                trader_device_id: d32(&req.trader_device_id, "trader_device_id", ROUTE)?,
                position: req.position,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::sofi_flow::relay(set, &intent).await {
            Ok(done) => pack_envelope_ok(generated::envelope::Payload::SofiRelayResponse(
                generated::SofiRelayResponse {
                    cells_written: done.cells_written,
                },
            )),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn sofi_resolve(&self, set: &crate::sdk::storage_set::StorageSet) -> AppResult {
        match crate::sdk::sofi_flow::resolve(&self.core_sdk, set).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("sofi.resolve: {e}")),
        }
    }
}
