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

    /// `wallet.unloadReceived` (owner, 2026-11-07: "One tap, all ready"): every payment this device
    /// received offline whose payer has been back online moves out of its offline account's
    /// received amount into its online balance, each as its own checked step — its settlement, which
    /// a contact takes only once the payer's own online history shows the spend. The rest stay in
    /// the offline balance, waiting. Nothing moves without being asked: the sync settles nothing.
    pub(crate) async fn handle_unload_received_invoke(&self, _i: AppInvoke) -> AppResult {
        let door = crate::security::modal_sync_lock::STEP_DOOR.lock().await;
        match crate::storage::client_db::offline_spend_in_flight(&self.device_id_bytes) {
            Ok(None) => {}
            Ok(Some((_, phase))) => {
                return err(format!(
                    "wallet.unloadReceived: an offline payment of this device's is in progress \
                     (phase={phase}); it completes or is resolved before received money moves"
                ))
            }
            Err(e) => {
                return err(format!(
                    "wallet.unloadReceived: the offline payment in flight: {e}"
                ))
            }
        }
        let (moved, failures) =
            crate::sdk::economic_admission_flow::settle_received_offline(&self.core_sdk).await;
        drop(door);
        let waiting = match crate::storage::client_db::offline_receipts::pending_offline_receipts()
            .map_err(|e| e.to_string())
            .and_then(|receipts| u32::try_from(receipts.len()).map_err(|e| e.to_string()))
        {
            Ok(waiting) => waiting,
            Err(e) => {
                return err(format!(
                    "wallet.unloadReceived: the payments still waiting: {e}"
                ))
            }
        };
        let mut message = match (moved, waiting) {
            (0, 0) => "No money received offline is waiting.".to_string(),
            (0, w) => format!(
                "{w} payment(s) received offline are still waiting: each moves online once its \
                 payer has been back online"
            ),
            (m, 0) => format!("{m} payment(s) received offline moved online"),
            (m, w) => format!(
                "{m} payment(s) received offline moved online; {w} still waiting for their payers \
                 to be back online"
            ),
        };
        if !failures.is_empty() {
            message.push_str(&format!(" ({})", failures.join("; ")));
        }
        pack_envelope_ok(generated::envelope::Payload::UnloadReceivedResponse(
            generated::UnloadReceivedResponse {
                moved,
                waiting,
                message,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::app_router_impl::AppRouterImpl;
    use crate::init::SdkConfig;
    use dsm::types::error::DsmError;

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

    /// An anchor told to install finishes, or refuses, whatever happens to its answer.
    #[derive(Clone)]
    struct OnTheCable {
        anchor: crate::test_support::appliance::HostAppliance,
        /// Whether the install's answer arrives: the anchor is told either way.
        what_happens: AnswerTo,
    }

    #[derive(Clone, Copy)]
    enum AnswerTo {
        /// It finishes and its answer never arrives: the cable went, or the wait ran out.
        LostAfterInstalling,
        /// It refuses, and that answer arrives.
        Refused,
    }

    impl crate::anchor::AnchorAppliance for OnTheCable {
        fn status(&mut self) -> Result<crate::anchor::ApplianceStatus, DsmError> {
            self.anchor.status()
        }
        fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), DsmError> {
            self.anchor.authorize(digest, signature)
        }
        fn prepare(
            &mut self,
            t: &anchor_core::root_advance::Transition,
            receiver_challenge: &[u8; 32],
            sender_device_root_before: &[u8; 32],
            sender_device_root_after: &[u8; 32],
        ) -> Result<(), DsmError> {
            self.anchor.prepare(
                t,
                receiver_challenge,
                sender_device_root_before,
                sender_device_root_after,
            )
        }
        fn commit(&mut self) -> Result<(), DsmError> {
            self.anchor.commit()
        }
        fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
            self.anchor.emit()
        }
        fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
            self.anchor.finalize()
        }
        fn cancel(&mut self) -> Result<(), DsmError> {
            self.anchor.cancel()
        }
        fn provisioned_pin(&mut self) -> Result<Option<crate::anchor::AnchorPin>, DsmError> {
            self.anchor.provisioned_pin()
        }
        fn draw_challenge(&mut self) -> Result<[u8; 32], DsmError> {
            self.anchor.draw_challenge()
        }
        fn check_payment(
            &mut self,
            payment: &anchor_core::root_advance::OfflineRelease,
            payer: &anchor_core::receive::PayerDisclosure,
        ) -> Result<(), DsmError> {
            self.anchor.check_payment(payment, payer)
        }
        fn try_run(
            &mut self,
            provisioning: &anchor_core::enrollment::Provisioning,
            rehearsal: &crate::anchor::RehearsalOwner,
        ) -> Result<crate::anchor::TryRunReport, DsmError> {
            self.anchor.try_run(provisioning, rehearsal)
        }
        fn provision(
            &mut self,
            provisioning: &anchor_core::enrollment::Provisioning,
            rehearsal: &crate::anchor::RehearsalOwner,
        ) -> Result<crate::anchor::AnchorPin, DsmError> {
            match self.what_happens {
                AnswerTo::LostAfterInstalling => {
                    self.anchor.provision(provisioning, rehearsal)?;
                    Err(DsmError::invalid_operation(
                        "USB: no answer from the anchor",
                    ))
                }
                AnswerTo::Refused => Err(DsmError::invalid_operation(
                    "anchor appliance: the try-run did not pass",
                )),
            }
        }
        fn recover(&mut self) -> Result<anchor_core::appliance::RecoverOutcome, DsmError> {
            self.anchor.recover()
        }
    }

    fn installing_through(
        anchor: crate::test_support::appliance::HostAppliance,
        what_happens: AnswerTo,
    ) {
        crate::bridge::install_anchor_appliance_factory(std::sync::Arc::new(move || {
            Ok(Box::new(OnTheCable {
                anchor: anchor.clone(),
                what_happens,
            })
                as Box<dyn crate::anchor::AnchorAppliance + Send>)
        }));
    }

    /// A burned chip is never reported as a failed install. The install finished and its answer was
    /// lost: what the anchor now holds says so, and the wallet attaches it. MUTATION CONTROL: dropping
    /// the read-back in `anchor_install` reports the failure and turns this red.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_install_whose_answer_was_lost_is_read_back_from_the_anchor() {
        let r = router_on_a_device();
        let core = &r.core_sdk;
        let appliance =
            crate::test_support::appliance::HostAppliance::unprovisioned([0xD2; 32], 16).install();
        installing_through((*appliance).clone(), AnswerTo::LostAfterInstalling);
        let snap = core.anchor_install().expect("the anchor holds the install");
        assert!(snap.connected, "{}", snap.status);
        assert!(!snap.awaiting_install, "{}", snap.status);
        assert_eq!(snap.bundle, appliance.pin().bundle);
    }

    /// An install the anchor refused stays refused, with its reason, and attaches nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_install_the_anchor_refused_stays_refused_and_attaches_nothing() {
        let r = router_on_a_device();
        let core = &r.core_sdk;
        let appliance =
            crate::test_support::appliance::HostAppliance::unprovisioned([0xD3; 32], 16).install();
        installing_through((*appliance).clone(), AnswerTo::Refused);
        let refused = core.anchor_install().expect_err("the anchor refused");
        assert!(refused.to_string().contains("try-run"), "{refused}");
        assert!(appliance.provisioned().is_none());
        assert!(core.anchor_appliance_status().awaiting_install);
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
            appliance.provisioned().is_none(),
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
        assert!(appliance.provisioned().is_none(), "a try-run binds nothing");

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
            .provision(
                &anchor_core::enrollment::Provisioning {
                    device_id: *blake3::hash(b"another device").as_bytes(),
                    online_id_pk: blake3::hash(b"another device's online key")
                        .as_bytes()
                        .to_vec(),
                    policy_hash: dsm::types::operations::canonical_offline_bearer_policy()
                        .policy_id,
                    genesis_root: *blake3::hash(b"another device's genesis").as_bytes(),
                },
                &crate::anchor::RehearsalOwner::derive(
                    blake3::hash(b"another device's secret").as_bytes(),
                )
                .expect("a rehearsal owner"),
            )
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
