// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-cash route handlers (two-regime money model).
//!
//! Invoke routes:
//! - `wallet.loadOffline`  → move `amount` of an asset from the online balance into this device's
//!   device-bound offline-bearer allocation ("cash in hand"). A conserved regime shift: online
//!   `available` drops, the allocation rises, the device root advances + persists.
//! - `wallet.unloadOffline` → reconcile: move `amount` from the allocation back to online `available`.
//!
//! The allocation is keyed by the device's enrolled anchor bundle `B`, so managing it requires the
//! anchor device to be present (its `B` identifies which allocation to touch). The online balance debit
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

        // The allocation is bound to the enrolled anchor bundle B — resolve it from the connected anchor
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
            allocation_balance: outcome.amount,
            device_root: outcome.new_root.to_vec(),
            message: format!(
                "{} {} of {} — offline allocation now {}, online {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::app_router_impl::AppRouterImpl;
    use crate::init::SdkConfig;

    /// A router on a device created as wallet creation creates it. No anchor
    /// appliance is attached — no transport to one exists — and that absence
    /// is the condition under test.
    fn router_on_a_device() -> AppRouterImpl {
        crate::economic_fixtures::local_device(0x0A);
        AppRouterImpl::new(SdkConfig {
            node_id: "offline-cash-gate-test".to_string(),
            storage_endpoints: Vec::new(),
            enable_offline: true,
        })
        .expect("router init")
    }

    async fn invoke(router: &AppRouterImpl, method: &str) -> AppResult {
        router
            .handle_offline_cash_invoke(AppInvoke {
                method: method.to_string(),
                args: generated::ArgPack {
                    codec: generated::Codec::Proto as i32,
                    body: generated::OfflineCashRequest {
                        token_id: "ERA".to_string(),
                        amount: 10,
                    }
                    .encode_to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            })
            .await
    }

    /// GATE 1 — REGIME ENTRY. Offline cash is the appliance-gated regime: with
    /// no anchor appliance reachable, no allocation can be created, so no
    /// bearer spend can ever have anything to draw from. Delete the
    /// `!snap.connected` refusal and this test goes red.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn load_offline_refuses_when_the_anchor_appliance_cannot_be_reached() {
        let r = router_on_a_device();
        let res = invoke(&r, "wallet.loadOffline").await;
        assert!(!res.success, "load must refuse when no appliance answers");
        let msg = res.error_message.unwrap_or_default();
        assert!(
            msg.contains("connect your anchor device"),
            "the refusal must be the appliance gate, not a later balance/resolve error — got: {msg}"
        );
    }

    /// The same gate gates the reverse direction: unload also crosses the
    /// regime boundary and is bound to the enrolled bundle B.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn unload_offline_refuses_when_the_anchor_appliance_cannot_be_reached() {
        let r = router_on_a_device();
        let res = invoke(&r, "wallet.unloadOffline").await;
        assert!(!res.success);
        assert!(res
            .error_message
            .unwrap_or_default()
            .contains("connect your anchor device"));
    }
}
