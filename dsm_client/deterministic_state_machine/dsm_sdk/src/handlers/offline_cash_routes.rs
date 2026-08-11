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
    use crate::init::SdkConfig;
    use crate::handlers::app_router_impl::AppRouterImpl;

    /// Minimal process-global identity + storage, as every route test needs.
    /// Deliberately NOT installing an anchor appliance factory — that absence IS the
    /// condition under test.
    fn install_identity() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        crate::storage::client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_offline_cash_gate",
        ));
        crate::reset_sdk_context_for_testing();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (device_id, genesis_hash, binding_key) =
            (vec![0x0Au8; 32], vec![0x0Bu8; 32], vec![0x0Cu8; 32]);
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("derive signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key,
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        crate::storage::client_db::init_database().expect("init db");
    }

    fn router() -> AppRouterImpl {
        AppRouterImpl::new(SdkConfig {
            node_id: "offline-cash-gate-test".to_string(),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn pack(body: Vec<u8>) -> Vec<u8> {
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    }

    /// Install a factory that FAILS to attach — a chip that is absent or unreadable.
    ///
    /// This is the only way to reach the entry gate from a test build. With no factory
    /// installed, `anchor_appliance_status` falls back to `hardware_appliance_or_fail`,
    /// whose `#[cfg(test)]` arm returns the in-process mock and reports connected. The
    /// fail-closed `#[cfg(not(test))]` arm that real device builds get is unreachable
    /// here by construction, so a failing factory stands in for "no chip".
    /// Restores on drop, panic included — the factory is process-global, and leaving one
    /// installed silently changes anchor attachment for every later test.
    struct FailingApplianceFactory;

    impl FailingApplianceFactory {
        fn install() -> Self {
            crate::bridge::install_anchor_appliance_factory(std::sync::Arc::new(|| {
                Err(dsm::types::error::DsmError::invalid_operation(
                    "test: no anchor appliance attached",
                ))
            }));
            Self
        }
    }

    impl Drop for FailingApplianceFactory {
        fn drop(&mut self) {
            crate::bridge::clear_anchor_appliance_factory_for_tests();
        }
    }

    /// GATE 1 — REGIME ENTRY. Offline cash is the appliance-gated regime: with no anchor
    /// appliance reachable, no allocation can be created, so no bearer spend can ever
    /// have anything to draw from.
    ///
    /// This is one of the three live gates carrying offline-bearer authority after the
    /// vestigial `offline_bearer_attestation` flag was deleted. The flag could only
    /// remember a past belief; this requires the appliance to answer NOW, on this
    /// attempt. Delete the `!snap.connected` refusal and this test goes red.
    #[test]
    #[serial_test::serial]
    fn load_offline_refuses_when_the_anchor_appliance_cannot_be_reached() {
        install_identity();
        let _factory = FailingApplianceFactory::install();
        let r = router();
        let req = generated::OfflineCashRequest {
            token_id: "ERA".to_string(),
            amount: 10,
        };

        let res = futures::executor::block_on(r.handle_offline_cash_invoke(AppInvoke {
            method: "wallet.loadOffline".to_string(),
            args: pack(req.encode_to_vec()),
        }));

        assert!(!res.success, "load must refuse when no appliance answers");
        let msg = res.error_message.unwrap_or_default();
        assert!(
            msg.contains("connect your anchor device"),
            "the refusal must be the appliance gate, not a later balance/resolve error — got: {msg}"
        );
    }

    /// The same gate gates the reverse direction: unload also crosses the regime
    /// boundary and is bound to the enrolled bundle B.
    #[test]
    #[serial_test::serial]
    fn unload_offline_refuses_when_the_anchor_appliance_cannot_be_reached() {
        install_identity();
        let _factory = FailingApplianceFactory::install();
        let r = router();
        let req = generated::OfflineCashRequest {
            token_id: "ERA".to_string(),
            amount: 10,
        };

        let res = futures::executor::block_on(r.handle_offline_cash_invoke(AppInvoke {
            method: "wallet.unloadOffline".to_string(),
            args: pack(req.encode_to_vec()),
        }));

        assert!(!res.success);
        assert!(res
            .error_message
            .unwrap_or_default()
            .contains("connect your anchor device"));
    }
}
