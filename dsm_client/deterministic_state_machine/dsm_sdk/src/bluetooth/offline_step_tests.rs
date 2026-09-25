// SPDX-License-Identifier: MIT OR Apache-2.0

//! The offline bilateral protocol run between two devices with no BLE at all:
//! a carrier that hands each frame's bytes from one device's handler to the
//! other's, unchanged. Each device is its own process state (its database
//! slot, identity, wallet and router — `TestDevice::enter`), its handler is
//! built as production builds it, and every step is the handler's own path.

use std::sync::Arc;

use serial_test::serial;
use tokio::sync::RwLock;

use crate::bluetooth::bilateral_ble_handler::{BilateralBleHandler, BilateralPhase};
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::types::operations::Operation;

/// One device's offline handler, built as `init_dsm_sdk` builds it: its
/// transaction manager signs with the device's AK and keeps tips in the
/// device's SQLite store.
struct OfflineDevice {
    device: TestDevice,
    handler: BilateralBleHandler,
}

impl OfflineDevice {
    fn new(device: &TestDevice) -> Self {
        device.enter();
        let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
            .expect("the entered device's wallet is unlocked");
        let keypair = crate::init::derive_device_signing_keypair(&wallet_seed, &device.genesis)
            .expect("the device's AK");
        let manager = BilateralTransactionManager::new(
            DsmContactManager::new(device.device_id),
            keypair,
            device.device_id,
            device.genesis,
            Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        );
        let mut handler =
            BilateralBleHandler::new(Arc::new(RwLock::new(manager)), device.device_id);
        handler.set_settlement_delegate(Arc::new(
            crate::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate,
        ));
        Self {
            device: device.clone(),
            handler,
        }
    }

    /// The relationship tip this device holds with `peer`.
    fn tip_with(&self, peer: &OfflineDevice) -> [u8; 32] {
        self.device.enter();
        crate::storage::client_db::get_contact_chain_tip(&peer.device.device_id)
            .expect("read the tip")
            .expect("the peer is a contact")
    }
}

/// One offline step of `operation` from `sender` to `receiver`, every frame
/// carried as bytes: prepare → accept → confirm → ack. Returns the commitment.
async fn offline_step(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: Operation,
) -> [u8; 32] {
    sender.device.enter();
    let (prepare, commitment) = sender
        .handler
        .prepare_bilateral_transaction(receiver.device.device_id, operation)
        .await
        .expect("the sender prepares");

    receiver.device.enter();
    let (answer, _meta) = receiver
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    assert!(answer.is_empty(), "the proposal waits for the user");
    let response = receiver
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("the receiver's user accepts");

    sender.device.enter();
    let (confirm, _meta) = sender
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("the sender takes the acceptance and confirms");

    receiver.device.enter();
    let ack = receiver
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the receiver commits and acknowledges");

    sender.device.enter();
    sender
        .handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender takes the acknowledgment and commits");
    commitment
}

/// Two offline steps between two devices over a byte carrier: each commits on
/// both devices, both hold the same relationship tip after it, and the tip
/// moves with each step. The second step chains each side's EK from the head
/// the first one left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn offline_steps_commit_on_both_devices_over_a_byte_carrier() {
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let mut tip = a.tip_with(&b);
    assert_eq!(tip, b.tip_with(&a), "both devices start at h_0");
    for step in 0..2 {
        let commitment = offline_step(&a, &b, Operation::Noop).await;

        let (tip_a, tip_b) = (a.tip_with(&b), b.tip_with(&a));
        assert_eq!(tip_a, tip_b, "step {step}: the devices disagree on the tip");
        assert_ne!(tip_a, tip, "step {step}: the tip did not move");
        tip = tip_a;

        for device in [&a, &b] {
            device.device.enter();
            assert!(
                crate::storage::client_db::transaction_exists(
                    &crate::util::text_id::encode_base32_crockford(&commitment)
                ),
                "step {step}: {} holds no history row",
                device.device.slot
            );
            assert_ne!(
                device.handler.get_session_phase(&commitment).await,
                Some(BilateralPhase::ConfirmPending),
                "step {step}: {} is still awaiting",
                device.device.slot
            );
        }
    }
}
