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
use super::wallet_routes::{
    format_base_units_for_display, parse_display_amount_to_base_units, token_of_commit,
};
use crate::sdk::sofi_flow::{
    CloseIntent, CreateVaultIntent, FindRouteIntent, PositionOutcome, PositionState, RelayIntent,
    Search, TradeIntent,
};

/// The most hops a route may have (`ROUTE_MAX_LEGS`, SoFi §31).
const ROUTE_MAX_LEGS: usize = dsm::sofi::wire::ROUTE_MAX_LEGS;

fn d32(bytes: &[u8], what: &str, route: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|_| format!("{route}: {what} must be 32 bytes"))
}

/// An amount the user entered for `token`, in token units, as base units: the
/// one parser, against the decimals of the token's committed policy.
fn entered(text: &str, token: &[u8; 32], what: &str, route: &str) -> Result<u64, String> {
    let (ticker, decimals) = token_of_commit(token).map_err(|e| format!("{route}: {what}: {e}"))?;
    parse_display_amount_to_base_units(text, decimals)
        .map_err(|e| format!("{route}: {what} {text:?} in {ticker}: {e}"))
}

/// Base units of `token`, rendered for display.
fn shown(amount: u64, token: &[u8; 32], route: &str) -> Result<String, String> {
    let (.., decimals) = token_of_commit(token).map_err(|e| format!("{route}: {e}"))?;
    Ok(format_base_units_for_display(amount, decimals))
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

/// A trade or route's intent: the tokens it names and the amounts the user
/// entered, parsed against each token's decimals.
fn trade_intent(
    vault_ids: Vec<[u8; 32]>,
    token_in: &[u8],
    token_out: &[u8],
    amount_in: &str,
    min_amount_out: &str,
    route: &str,
) -> Result<TradeIntent, String> {
    let token_in = d32(token_in, "token_in_policy_commit", route)?;
    let token_out = d32(token_out, "token_out_policy_commit", route)?;
    if token_in == token_out {
        return Err(format!("{route}: the two tokens must differ"));
    }
    let amount_in = entered(amount_in, &token_in, "amount in", route)?;
    if amount_in == 0 {
        return Err(format!("{route}: amount in must be positive"));
    }
    Ok(TradeIntent {
        vault_ids,
        token_in_policy_commit: token_in,
        token_out_policy_commit: token_out,
        amount_in,
        min_amount_out: entered(min_amount_out, &token_out, "minimum out", route)?,
    })
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
            "sofi.findRoute" => self.sofi_find_route(&i, &set).await,
            "sofi.trade" => self.sofi_trade(&i, &set).await,
            "sofi.route" => self.sofi_route(&i, &set).await,
            "sofi.close" => self.sofi_close(&i, &set).await,
            "sofi.relay" => self.sofi_relay(&i, &set).await,
            "sofi.resolve" => self.sofi_resolve(&set).await,
            "sofi.vaults" => self.sofi_vaults(&set).await,
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
            let reserve_a = entered(&req.reserve_a_entered, &a, "reserve A", ROUTE)?;
            let reserve_b = entered(&req.reserve_b_entered, &b, "reserve B", ROUTE)?;
            if reserve_a == 0 || reserve_b == 0 {
                return Err(format!("{ROUTE}: both reserves must be positive"));
            }
            Ok(CreateVaultIntent {
                token_a_policy_commit: a,
                token_b_policy_commit: b,
                reserve_a,
                reserve_b,
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
            let amount_in = entered(&req.amount_in_entered, &token_in, "amount in", ROUTE)?;
            if amount_in == 0 {
                return Err(format!("{ROUTE}: amount in must be positive"));
            }
            Ok(FindRouteIntent {
                token_in_policy_commit: token_in,
                token_out_policy_commit: token_out,
                amount_in,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let found = match crate::sdk::sofi_flow::find_route(&self.core_sdk, set, &intent).await {
            Ok(found) => found,
            Err(e) => return err(format!("{ROUTE}: {e}")),
        };
        let mut hops = Vec::with_capacity(found.hops.len());
        for h in found.hops {
            let (amount_in_display, amount_out_display) = match (
                shown(h.amount_in, &h.token_in_policy_commit, ROUTE),
                shown(h.amount_out, &h.token_out_policy_commit, ROUTE),
            ) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return err(e),
            };
            hops.push(generated::SofiHopV1 {
                vault_id: h.vault_id.to_vec(),
                parent_root: h.parent_root.to_vec(),
                token_in_policy_commit: h.token_in_policy_commit.to_vec(),
                token_out_policy_commit: h.token_out_policy_commit.to_vec(),
                amount_in: h.amount_in,
                amount_out: h.amount_out,
                amount_in_display,
                amount_out_display,
            });
        }
        let search = match found.search {
            Search::Complete => generated::SofiSearch::Complete,
            Search::Partial => generated::SofiSearch::Partial,
        };
        pack_envelope_ok(generated::envelope::Payload::SofiFindRouteResponse(
            generated::SofiFindRouteResponse {
                hops,
                search: search as i32,
            },
        ))
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
            trade_intent(
                vec![vault_id],
                &req.token_in_policy_commit,
                &req.token_out_policy_commit,
                &req.amount_in_entered,
                &req.min_amount_out_entered,
                ROUTE,
            )
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
            trade_intent(
                vault_ids,
                &req.token_in_policy_commit,
                &req.token_out_policy_commit,
                &req.amount_in_entered,
                &req.min_amount_out_entered,
                ROUTE,
            )
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

    async fn sofi_vaults(&self, set: &crate::sdk::storage_set::StorageSet) -> AppResult {
        const ROUTE: &str = "sofi.vaults";
        let owned = match crate::sdk::sofi_flow::owned_vaults(&self.core_sdk, set).await {
            Ok(owned) => owned,
            Err(e) => return err(format!("{ROUTE}: {e}")),
        };
        let mut vaults = Vec::with_capacity(owned.len());
        for v in owned {
            let row = (|| -> Result<generated::SofiOwnedVaultV1, String> {
                let (token_a_symbol, ..) = token_of_commit(&v.token_a_policy_commit)
                    .map_err(|e| format!("{ROUTE}: {e}"))?;
                let (token_b_symbol, ..) = token_of_commit(&v.token_b_policy_commit)
                    .map_err(|e| format!("{ROUTE}: {e}"))?;
                let status = match v.status {
                    dsm::sofi::wire::VAULT_STATUS_ACTIVE => generated::SofiVaultStatus::Active,
                    dsm::sofi::wire::VAULT_STATUS_RETIRED => generated::SofiVaultStatus::Retired,
                    other => {
                        return Err(format!(
                            "{ROUTE}: vault status {other:#06x} is not declared"
                        ))
                    }
                };
                Ok(generated::SofiOwnedVaultV1 {
                    vault_id: v.vault_id.to_vec(),
                    token_a_policy_commit: v.token_a_policy_commit.to_vec(),
                    token_b_policy_commit: v.token_b_policy_commit.to_vec(),
                    token_a_symbol,
                    token_b_symbol,
                    reserve_a: v.reserve_a,
                    reserve_b: v.reserve_b,
                    reserve_a_display: shown(v.reserve_a, &v.token_a_policy_commit, ROUTE)?,
                    reserve_b_display: shown(v.reserve_b, &v.token_b_policy_commit, ROUTE)?,
                    fee_bps: v.fee_bps,
                    generation: v.generation,
                    status: status as i32,
                })
            })();
            match row {
                Ok(row) => vaults.push(row),
                Err(e) => return err(e),
            }
        }
        pack_envelope_ok(generated::envelope::Payload::SofiVaultsResponse(
            generated::SofiVaultsResponse { vaults },
        ))
    }

    async fn sofi_resolve(&self, set: &crate::sdk::storage_set::StorageSet) -> AppResult {
        match crate::sdk::sofi_flow::resolve(&self.core_sdk, set).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("sofi.resolve: {e}")),
        }
    }
}
