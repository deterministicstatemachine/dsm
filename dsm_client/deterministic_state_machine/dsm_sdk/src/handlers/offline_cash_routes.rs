// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-cash route handlers (two-regime money model).
//!
//! Invoke routes:
//! - `wallet.loadOffline`  → move `amount` of an asset from the online balance into this device's
//!   device-bound offline-bearer pool ("cash in hand"). A conserved regime shift: online
//!   `available` drops, the pool rises, the device root advances + persists.
//! - `wallet.unloadOffline` → reconcile: move `amount` from the pool back to online `available`.
//!
//! The pool is keyed by the device's enrolled anchor bundle `B`, so managing it requires the
//! anchor device to be present (its `B` identifies which pool to touch). The online balance debit
//! itself is the network witness that those units left online-spendable liquidity.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppResult};

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    /// Dispatch handler for `wallet.loadOffline` / `wallet.unloadOffline` invoke routes.
    pub(crate) async fn handle_offline_cash_invoke(&self, i: AppInvoke) -> AppResult {
        let is_load = i.method == "wallet.loadOffline";
        let verb = if is_load {
            "loadOffline"
        } else {
            "unloadOffline"
        };

        // Decode ArgPack -> OfflineCashRequest.
        let arg_pack = match generated::ArgPack::decode(&*i.args) {
            Ok(a) => a,
            Err(e) => return err(format!("wallet.{verb}: decode ArgPack failed: {e}")),
        };
        let req = match generated::OfflineCashRequest::decode(&*arg_pack.body) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "wallet.{verb}: decode OfflineCashRequest failed: {e}"
                ))
            }
        };
        if req.amount == 0 {
            return err(format!("wallet.{verb}: amount must be > 0"));
        }

        // Resolve the asset's CPTA policy_commit (strict — no silent fallback).
        let asset = match self
            .core_sdk
            .resolve_policy_commit_strict(req.token_id.as_bytes())
        {
            Ok(pc) => pc,
            Err(e) => return err(format!("wallet.{verb}: policy_commit resolve failed: {e}")),
        };

        // The pool is bound to the enrolled anchor bundle B — resolve it from the connected anchor
        // device. Offline cash is the appliance-gated regime, so managing it needs the anchor present.
        let snap = self.core_sdk.anchor_appliance_status();
        if !snap.connected {
            return err(format!(
                "wallet.{verb}: connect your anchor device to manage offline cash"
            ));
        }
        let bundle = snap.bundle;

        // Apply the conserved regime shift (fail-closed persist-before-install in CoreSDK).
        let outcome = if is_load {
            self.core_sdk.load_offline_cash(bundle, asset, req.amount)
        } else {
            self.core_sdk.unload_offline_cash(bundle, asset, req.amount)
        };
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => return err(format!("wallet.{verb}: {e}")),
        };

        let online_balance = self.core_sdk.get_device_balance(&asset);
        let resp = generated::OfflineCashResponse {
            success: true,
            online_balance,
            pool_balance: outcome.amount,
            device_root: outcome.new_root.to_vec(),
            message: format!(
                "{} {} of {} — offline pool now {}, online {}",
                if is_load { "loaded" } else { "unloaded" },
                req.amount,
                req.token_id,
                outcome.amount,
                online_balance,
            ),
        };
        pack_envelope_ok(generated::envelope::Payload::OfflineCashResponse(resp))
    }
}
