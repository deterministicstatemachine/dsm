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

    /// The latest EK step this device has recorded for itself and for `peer`
    /// on their relationship: `(step address, EK)` each.
    fn ek_steps_with(&self, peer: &OfflineDevice) -> ([u8; 32], Vec<u8>, [u8; 32], Vec<u8>) {
        use crate::storage::client_db::economic_lineage::latest_ek_step;
        self.device.enter();
        let rel_key = self.device.rel_key_with(&peer.device);
        let (_, own_addr, own_ek) = latest_ek_step(&rel_key, &self.device.device_id)
            .expect("read")
            .expect("this device's EK step");
        let (_, peer_addr, peer_ek) = latest_ek_step(&rel_key, &peer.device.device_id)
            .expect("read")
            .expect("the peer's EK step");
        (own_addr, own_ek, peer_addr, peer_ek)
    }

    /// The roots the entered device's two newest EK step objects are frozen
    /// under.
    fn newest_ek_step_roots(&self) -> Vec<[u8; 32]> {
        self.device.enter();
        let mut steps: Vec<_> =
            crate::storage::client_db::frozen_publication_artifact::list_unpublished_artifacts(
                1000,
            )
            .expect("read the artifacts")
            .into_iter()
            .filter(|a| a.purpose == "ek-cert-step")
            .collect();
        steps.sort_by_key(|a| std::cmp::Reverse(a.insertion_ordinal));
        steps.iter().take(2).map(|a| a.bound_root).collect()
    }

    /// This device's EK chain head and its mirror of `peer`'s, on their
    /// relationship.
    fn cert_heads_with(&self, peer: &OfflineDevice) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        use crate::storage::client_db::{load_cert_chain_head_pubkey, CertChainSide};
        self.device.enter();
        let rel_key = self.device.rel_key_with(&peer.device);
        (
            load_cert_chain_head_pubkey(&rel_key, CertChainSide::Local).expect("read"),
            load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty).expect("read"),
        )
    }
}

/// An offline step of `operation` from `sender` to `receiver` up to the
/// receiver's commit, every frame carried as bytes: prepare → accept →
/// confirm, which the receiver commits. Returns the commitment and the ack the
/// receiver answers with.
async fn to_the_ack(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: Operation,
) -> ([u8; 32], Vec<u8>) {
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
    (commitment, ack)
}

/// One offline step of `operation` from `sender` to `receiver`, every frame
/// carried as bytes: prepare → accept → confirm → ack. Returns the commitment.
async fn offline_step(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: Operation,
) -> [u8; 32] {
    let (commitment, ack) = to_the_ack(sender, receiver, operation).await;
    sender.device.enter();
    sender
        .handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender takes the acknowledgment and commits");
    commitment
}

/// The receipt the entered device keeps in its history for the step
/// `commitment`.
fn kept_receipt(commitment: &[u8; 32]) -> dsm::types::receipt_types::StitchedReceiptV2 {
    let tx_id = crate::util::text_id::encode_base32_crockford(commitment);
    let row = crate::storage::client_db::get_transaction_history(None, Some(1000))
        .expect("read the history")
        .into_iter()
        .find(|row| row.tx_id == tx_id)
        .expect("the step's history row");
    dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &row.proof_data.expect("the step's receipt"),
    )
    .expect("the kept receipt decodes")
}

/// Two offline steps between two devices over a byte carrier: each commits on
/// both devices, both hold the same relationship tip after it, and the tip
/// moves with each step. Each commit ends its session and moves both EK chain
/// heads, so each device's head is the one the other mirrors; the second step
/// chains each side's EK from the head the first one left. The receiver's
/// receipt names the root its committed head holds.
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
            assert!(
                crate::storage::client_db::get_bilateral_session(&commitment)
                    .expect("read the session")
                    .is_none(),
                "step {step}: {} kept the committed step's session",
                device.device.slot
            );
        }
        // The receiver signed its receipt from the advance it committed: the
        // receipt names the root its head holds.
        b.device.enter();
        assert_eq!(
            kept_receipt(&commitment).child_root,
            b.device
                .router()
                .core_sdk
                .device_smt_root()
                .expect("B's head"),
            "step {step}: B's receipt is not the advance B committed"
        );
        // Each device's EK chain head is the one the other mirrors: both
        // chains moved with the step, in each device's commit.
        let ((a_local, a_mirror), (b_local, b_mirror)) =
            (a.cert_heads_with(&b), b.cert_heads_with(&a));
        assert!(
            a_local.is_some() && b_local.is_some(),
            "step {step}: an EK head is missing"
        );
        assert_eq!(
            a_local, b_mirror,
            "step {step}: B does not mirror A's EK head"
        );
        assert_eq!(
            b_local, a_mirror,
            "step {step}: A does not mirror B's EK head"
        );

        // Both devices recorded the same two EK step objects, each signer's
        // under its own id and carrying the EK its chain head moved to, frozen
        // under the root the device's commit produced.
        let (a_own_addr, a_own_ek, a_peer_addr, a_peer_ek) = a.ek_steps_with(&b);
        let (b_own_addr, b_own_ek, b_peer_addr, b_peer_ek) = b.ek_steps_with(&a);
        assert_eq!(
            Some(&a_own_ek),
            a_local.as_ref(),
            "step {step}: A's EK step is not A's head"
        );
        assert_eq!(
            Some(&b_own_ek),
            b_local.as_ref(),
            "step {step}: B's EK step is not B's head"
        );
        assert_eq!(
            a_peer_ek, b_own_ek,
            "step {step}: A recorded another EK for B"
        );
        assert_eq!(
            b_peer_ek, a_own_ek,
            "step {step}: B recorded another EK for A"
        );
        assert_eq!(
            a_own_addr, b_peer_addr,
            "step {step}: A's EK step differs between devices"
        );
        assert_eq!(
            b_own_addr, a_peer_addr,
            "step {step}: B's EK step differs between devices"
        );
        for device in [&a, &b] {
            let root = {
                device.device.enter();
                device
                    .device
                    .router()
                    .core_sdk
                    .device_smt_root()
                    .expect("the head")
            };
            assert_eq!(
                device.newest_ek_step_roots(),
                vec![root, root],
                "step {step}: {}'s EK steps are not bound to its committed root",
                device.device.slot
            );
        }
    }
}

/// A sender whose head moved after it built its confirm — here it added a
/// contact, which commits that relationship's leaf — cannot commit the step
/// the receiver accepted: its advance would not be the one the receipt names.
/// It commits nothing: its tip, its history and its EK chain head stay where
/// they were, the session fails and the relationship is held for online
/// reconcile.
/// MUTATION CONTROL: dropping the root check from the sender's commit lets the
/// step commit and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_whose_head_moved_since_its_confirm_commits_nothing() {
    let pair = Pair::boot(0, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&pair.fleet).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let h_0 = a.tip_with(&b);
    let (a_head_before, _) = a.cert_heads_with(&b);

    let (commitment, ack) = to_the_ack(&a, &b, Operation::Noop).await;
    assert_ne!(b.tip_with(&a), h_0, "the receiver committed");
    pair.a.add_contact(&c).await;

    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect_err("a sender whose head moved commits nothing");
    assert_eq!(a.tip_with(&b), h_0, "the sender's tip moved");
    a.device.enter();
    assert!(
        !crate::storage::client_db::transaction_exists(
            &crate::util::text_id::encode_base32_crockford(&commitment)
        ),
        "the sender kept a history row"
    );
    assert_eq!(
        a.cert_heads_with(&b).0,
        a_head_before,
        "the sender's EK chain head moved"
    );
    assert_eq!(
        crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("read the session")
            .expect("the failed session is kept")
            .phase,
        "failed"
    );
    assert!(
        crate::storage::client_db::get_contact_by_device_id(&b.device.device_id)
            .expect("read the contact")
            .expect("B is a contact")
            .needs_online_reconcile,
        "the relationship is not held for online reconcile"
    );
}
