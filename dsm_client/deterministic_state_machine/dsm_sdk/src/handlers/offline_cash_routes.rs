// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-cash route handlers (two-regime money model).
//!
//! Invoke routes:
//! - `wallet.loadOffline`  → move `amount` of an asset from the online balance into this device's
//!   offline account ("cash in hand"): an admitted economic transition that debits the online
//!   balance and credits the account by the same amount.
//! - `wallet.unloadOffline` → move `amount` from the offline account back to the online balance:
//!   an admitted transition whose online credit is funded by exactly that account debit.
//!
//! The offline account is the one of the device's enrolled anchor bundle `B`, so managing it
//! requires the anchor device to be present, standing where the account does.

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
        // The amount as the user typed it, scaled by the token's decimals here:
        // the parser the sends use, so one rule owns the unit in both directions.
        let decimals = match super::wallet_routes::token_decimals(&req.token_id) {
            Ok(d) => d,
            Err(e) => return err(format!("wallet.{verb}: {e}")),
        };
        let amount =
            match super::wallet_routes::parse_display_amount_to_base_units(&req.amount, decimals) {
                Ok(a) => a,
                Err(e) => return err(format!("wallet.{verb}: invalid amount: {e}")),
            };
        if amount == 0 {
            return err(format!("wallet.{verb}: amount must be > 0"));
        }

        // Resolve the asset's CPTA policy_commit (strict — no silent fallback).
        let asset = match crate::policy::resolve_policy_commit_strict(req.token_id.as_bytes()) {
            Ok(pc) => pc,
            Err(e) => return err(format!("wallet.{verb}: policy_commit resolve failed: {e}")),
        };

        // The offline account is the one of the enrolled anchor bundle B — resolve it from the
        // connected anchor device. Offline cash is the appliance-gated regime, so managing it needs
        // the anchor present, standing where the account does.
        let snap = self.core_sdk.anchor_appliance_status();
        if snap.awaiting_install {
            return err(format!(
                "wallet.{verb}: this anchor is not installed yet: try it and install it first"
            ));
        }
        if !snap.connected {
            return err(format!(
                "wallet.{verb}: connect your anchor device to manage offline cash"
            ));
        }
        let bundle = snap.bundle;
        if let Err(e) = self.core_sdk.require_offline_account_at(
            &bundle,
            &snap.frontier_root,
            snap.anchor_counter,
        ) {
            return err(format!("wallet.{verb}: {e}"));
        }

        // The account holds one offline payment in flight (SA-10): a boundary beside one would
        // move the allocation that payment was checked against, between its proposal and its
        // acknowledgment. Decided from the durable rows under the step door, held through the
        // boundary, so no payment is proposed between the check and the boundary's commit.
        let door = crate::security::modal_sync_lock::STEP_DOOR.lock().await;
        match crate::storage::client_db::offline_spend_in_flight(&self.device_id_bytes) {
            Ok(None) => {}
            Ok(Some((_, phase))) => {
                return err(format!(
                    "wallet.{verb}: an offline payment from this device is in progress \
                     (phase={phase}); it completes or is resolved before offline cash moves"
                ))
            }
            Err(e) => return err(format!("wallet.{verb}: the offline payment in flight: {e}")),
        }

        // The boundary is an admitted economic transition: taken by Core, made durable with its
        // admission, registered and validated before this route reports success.
        let kind = if is_load {
            dsm::types::device_state::OfflineBoundaryKind::Load
        } else {
            dsm::types::device_state::OfflineBoundaryKind::Unload
        };
        let outcome = match crate::sdk::economic_admission_flow::admitted_offline_boundary(
            &self.core_sdk,
            bundle,
            kind,
            asset,
            amount,
        )
        .await
        {
            Ok((outcome, _admitted)) => outcome,
            Err(e) => return err(format!("wallet.{verb}: {e}")),
        };
        // The door was held through the boundary's commit; a contact's notice waits on nothing.
        drop(door);
        // The boundary is admitted whatever becomes of its notices. What is not delivered here
        // stays owed, the next sync delivers it, and the holder is told: a contact not told cannot
        // be paid offline from this boundary, so it matters before they leave coverage.
        let untold = match crate::sdk::storage_set::pinned_endpoints() {
            Ok(endpoints) => self.tell_contacts_of_offline_boundaries(&endpoints).await,
            Err(e) => vec![format!("the pinned storage set: {e}")],
        };
        let untold = if untold.is_empty() {
            String::new()
        } else {
            format!(
                ". Not every contact is told of it yet, so those cannot be paid from it offline; \
                 this device tells them at its next sync online: {}",
                untold.join("; ")
            )
        };
        let allocation = outcome
            .new_device_state
            .offline_allocation(&bundle, &asset)
            .ok_or_else(|| "the boundary left no allocation of the asset".to_string());
        let allocation = match allocation {
            Ok(a) => a,
            Err(e) => return err(format!("wallet.{verb}: {e}")),
        };

        let online_balance = self.core_sdk.get_device_balance(&asset);
        // Rendered here, in the token's units: the wallet prints these and
        // computes nothing.
        let render = |base_units: u64| {
            super::wallet_routes::format_base_units_for_display(base_units, decimals)
        };
        let online_display = render(online_balance);
        let allocation_display = render(allocation);
        let resp = generated::OfflineCashResponse {
            success: true,
            online_balance,
            allocation_balance: allocation,
            device_root: outcome.post_device_root.to_vec(),
            message: format!(
                "{} {} {} — offline allocation now {}, online {}{}",
                if is_load { "loaded" } else { "unloaded" },
                render(amount),
                req.token_id,
                allocation_display,
                online_display,
                untold,
            ),
            online_display,
            allocation_display,
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

    async fn invoke(router: &AppRouterImpl, method: &str, amount: &str) -> AppResult {
        router
            .handle_offline_cash_invoke(AppInvoke {
                method: method.to_string(),
                args: generated::ArgPack {
                    codec: generated::Codec::Proto as i32,
                    body: generated::OfflineCashRequest {
                        token_id: "ERA".to_string(),
                        amount: amount.to_string(),
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
        let res = invoke(&r, "wallet.loadOffline", "10").await;
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
        let res = invoke(&r, "wallet.unloadOffline", "10").await;
        assert!(!res.success);
        assert!(res
            .error_message
            .unwrap_or_default()
            .contains("connect your anchor device"));
    }

    /// The amount is the user's decimal text, scaled by Rust: text that is not
    /// an amount is refused as one, before any gate that needs the appliance.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn an_amount_that_is_not_a_number_is_refused_as_an_amount() {
        let r = router_on_a_device();
        let res = invoke(&r, "wallet.loadOffline", "ten").await;
        assert!(!res.success);
        let msg = res.error_message.unwrap_or_default();
        assert!(msg.contains("invalid amount"), "{msg}");
    }

    /// Connecting a new anchor does nothing permanent. A status read reports it as awaiting its install
    /// and binds nothing, however often; a load refuses and moves nothing; a try-run goes through the
    /// install and leaves it as it was. Only being told to installs it, and then its bundle binds this
    /// device's id, its online key and the offline-bearer policy, and it serves this device.
    ///
    /// MUTATION CONTROL: provisioning restored to `anchor_for_this_device` installs on the first status
    /// read and turns this red at "a status read binds nothing".
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn connecting_an_anchor_binds_nothing_until_it_is_told_to_install() {
        let r = router_on_a_device();
        let core = &r.core_sdk;
        let appliance =
            crate::test_support::appliance::HostAppliance::unprovisioned([0xD1; 32], 16).install();
        for _read in 0..3 {
            let snap = core.anchor_appliance_status();
            assert!(!snap.connected, "{}", snap.status);
            assert!(snap.awaiting_install, "{}", snap.status);
        }
        assert!(
            matches!(appliance.provisioned(), None),
            "a status read binds nothing"
        );

        let res = invoke(&r, "wallet.loadOffline", "10").await;
        assert!(!res.success, "no offline cash on an anchor not installed");
        assert!(
            res.error_message
                .as_deref()
                .is_some_and(|message| message.contains("not installed")),
            "{:?}",
            res.error_message
        );

        let report = core.anchor_try_run().expect("the try-run ran");
        assert!(report.passed, "{report:?}");
        assert!(!report.steps.is_empty(), "it reports what it went through");
        assert!(
            !report.permanent.is_empty(),
            "it says what would be permanent"
        );
        assert!(
            matches!(appliance.provisioned(), None),
            "a try-run binds nothing"
        );

        let snap = core.anchor_install().expect("told to install");
        assert!(snap.connected, "{}", snap.status);
        assert!(!snap.awaiting_install, "{}", snap.status);
        let pin = appliance.pin();
        assert_eq!(snap.bundle, pin.bundle, "the anchor it installed");
        let device = core.device_head().expect("a head");
        assert_eq!(
            anchor_core::enrollment::anchor_bundle(
                &crate::sdk::app_state::AppState::get_public_key().expect("the device's AK"),
                &pin.anchor_id,
                &pin.pk_chip,
                &pin.partition_pk,
                16,
                &device.devid(),
                &dsm::types::operations::canonical_offline_bearer_policy().policy_id,
                &pin.birth_commitment,
            ),
            pin.bundle,
            "B binds this device, its online key and the offline-bearer policy"
        );
        assert!(
            matches!(core.anchor_try_run(), Err(e) if e.to_string().contains("already installed")),
            "an installed anchor has nothing to try"
        );
    }

    /// Phase 3, provisioning. An anchor provisioned for another device is never
    /// attached: no status, no offline cash, and no offline account opens on it.
    /// MUTATION CONTROL: dropping the bundle check in `anchor_for_this_device`
    /// attaches the other device's anchor and turns this red.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn an_anchor_provisioned_for_another_device_is_not_attached() {
        use crate::anchor::AnchorAppliance;

        let r = router_on_a_device();
        let mut chip = crate::test_support::appliance::HostAppliance::unprovisioned([0xD2; 32], 16);
        let other = chip
            .provision(&anchor_core::enrollment::Provisioning {
                device_id: *blake3::hash(b"another device").as_bytes(),
                online_id_pk: blake3::hash(b"another device's online key")
                    .as_bytes()
                    .to_vec(),
                policy_hash: dsm::types::operations::canonical_offline_bearer_policy().policy_id,
                genesis_root: *blake3::hash(b"another device's genesis").as_bytes(),
            })
            .expect("provisioned for the other device");
        let installed = chip.install();
        let snap = r.core_sdk.anchor_appliance_status();
        assert!(!snap.connected, "the other device's anchor is not attached");
        assert!(
            snap.status.contains("not provisioned for this device"),
            "{}",
            snap.status
        );
        let res = invoke(&r, "wallet.loadOffline", "10").await;
        assert!(!res.success, "no offline cash on another device's anchor");
        assert!(
            r.core_sdk
                .device_head()
                .expect("a head")
                .offline_account(&other.bundle)
                .is_none(),
            "no offline account opened under its bundle"
        );
        drop(installed);
    }

    /// The software counter is the authority and the chip its mirror: an
    /// account opens only at a chip that has never released, and once open
    /// the chip must stand exactly where the account does. Nothing is
    /// rewritten to follow the chip.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    async fn the_offline_account_is_never_rewritten_to_follow_the_chip() {
        let r = router_on_a_device();
        let core = &r.core_sdk;
        let refused = |result: Result<(), dsm::types::error::DsmError>, reason: &str| {
            let e = result.expect_err(reason);
            assert!(e.to_string().contains(reason), "{e}");
        };
        refused(
            core.require_offline_account_at(&[0xB1; 32], &[0x01; 32], 3),
            "a counter with no software record",
        );
        core.require_offline_account_at(&[0xB1; 32], &[0x01; 32], 0)
            .expect("the account opens at the chip's enrolled origin");
        core.require_offline_account_at(&[0xB1; 32], &[0x01; 32], 0)
            .expect("the chip stands where the account does");
        refused(
            core.require_offline_account_at(&[0xB1; 32], &[0x01; 32], 1),
            "the software counter is the authority",
        );
        refused(
            core.require_offline_account_at(&[0xB1; 32], &[0x02; 32], 0),
            "the software counter is the authority",
        );
        let account = core
            .device_head()
            .and_then(|head| head.offline_account(&[0xB1; 32]).cloned())
            .expect("the account is open");
        assert_eq!((account.counter(), account.frontier()), (0, [0x01; 32]));
    }
}
