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
use crate::bluetooth::bilateral_transport_adapter::{
    BilateralTransportAdapter, BleTransportDelegate, TransportInboundMessage, TransportOutbound,
};
use crate::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType};
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::types::operations::Operation;

/// One device's offline handler, built as `init_dsm_sdk` builds it: its
/// transaction manager signs with the device's AK and keeps tips in the
/// device's SQLite store, and holds the device's persisted contacts, loaded
/// before any frame arrives. Beside it, the device's BLE frame coordinator,
/// which chunks the frames it writes and reassembles the frames it reads.
struct OfflineDevice {
    device: TestDevice,
    handler: Arc<BilateralBleHandler>,
    ble: BleFrameCoordinator,
}

impl OfflineDevice {
    fn new(device: &TestDevice) -> Self {
        device.enter();
        let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
            .expect("the entered device's wallet is unlocked");
        let keypair = crate::init::derive_device_signing_keypair(&wallet_seed, &device.genesis)
            .expect("the device's AK");
        let mut manager = BilateralTransactionManager::new(
            DsmContactManager::new(device.device_id),
            keypair,
            device.device_id,
            device.genesis,
            Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        );
        for record in crate::storage::client_db::get_all_contacts().expect("the device's contacts")
        {
            manager
                .add_verified_contact(record.to_verified_contact().expect("a persisted contact"))
                .expect("the contact is loaded");
        }
        let mut handler =
            BilateralBleHandler::new(Arc::new(RwLock::new(manager)), device.device_id);
        handler.set_settlement_delegate(Arc::new(
            crate::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate,
        ));
        Self {
            device: device.clone(),
            handler: Arc::new(handler),
            ble: BleFrameCoordinator::new(device.device_id),
        }
    }

    /// `proposal`, proposed to `to` through this device's sender door.
    async fn propose(
        &self,
        to: &OfflineDevice,
        proposal: Proposal,
    ) -> Result<(Vec<u8>, [u8; 32]), dsm::types::error::DsmError> {
        self.handler
            .prepare_bilateral_step(to.device.device_id, proposal.operation, proposal.terms)
            .await
    }

    /// The bilateral transport adapter the BLE bridge hands this device's
    /// reassembled frames to.
    fn adapter(&self) -> BilateralTransportAdapter {
        BilateralTransportAdapter::new(Arc::clone(&self.handler))
    }

    /// This device after a restart: a new handler and manager over the same
    /// durable state, its sessions restored from storage.
    async fn restarted(&self) -> OfflineDevice {
        let restarted = OfflineDevice::new(&self.device);
        restarted
            .handler
            .restore_sessions_from_storage()
            .await
            .expect("restore the sessions");
        restarted
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

/// What a step proposes: its operation and, for a transfer, the terms that
/// ride beside it (pre-audit item 4).
#[derive(Clone)]
struct Proposal {
    operation: Operation,
    terms: Option<dsm::types::operations::TransferTerms>,
}

impl From<Operation> for Proposal {
    fn from(operation: Operation) -> Self {
        Self {
            operation,
            terms: None,
        }
    }
}

/// An offline step of `operation` from `sender` to `receiver` up to the
/// receiver's commit, every frame carried as bytes: prepare → accept →
/// confirm, which the receiver commits. Returns the commitment and the ack the
/// receiver answers with.
async fn to_the_ack(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: impl Into<Proposal>,
) -> ([u8; 32], Vec<u8>) {
    let (commitment, confirm) = to_the_confirm(sender, receiver, operation).await;
    receiver.device.enter();
    let ack = receiver
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the receiver commits and acknowledges");
    (commitment, ack)
}

/// An offline step of `operation` from `sender` to `receiver` up to the
/// sender's confirm, every frame carried as bytes: prepare → accept →
/// confirm. Returns the commitment and the confirm.
async fn to_the_confirm(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: impl Into<Proposal>,
) -> ([u8; 32], Vec<u8>) {
    let proposal = operation.into();
    sender.device.enter();
    let (prepare, commitment) = sender
        .handler
        .prepare_bilateral_step(
            receiver.device.device_id,
            proposal.operation,
            proposal.terms,
        )
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
    (commitment, confirm)
}

/// One offline step of `operation` from `sender` to `receiver`, every frame
/// carried as bytes: prepare → accept → confirm → ack. Returns the commitment.
async fn offline_step(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: impl Into<Proposal>,
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
    let row = crate::storage::client_db::get_transaction_history(None, Some(1000), None)
        .expect("read the history")
        .into_iter()
        .find(|row| row.tx_id == tx_id)
        .expect("the step's history row");
    dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &row.proof_data.expect("the step's receipt"),
    )
    .expect("the kept receipt decodes")
}

/// A stale proposal's claimed tip is kept as evidence of the sender's tip
/// only when the proposal's commitment recomputes on it. A's prepare for B
/// with its claimed tip replaced (the claim travels outside σ_A) is refused
/// as stale, and B keeps nothing of the claim. MUTATION CONTROL: keeping the
/// claim whether or not it recomputes turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_claimed_tip_that_does_not_recompute_is_not_kept() {
    use crate::generated;
    use prost::Message;

    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, _commitment) = a
        .propose(&b, payment.clone())
        .await
        .expect("A prepares for B");

    let mut envelope =
        crate::envelope::from_canonical_bytes(&prepare).expect("the prepare decodes");
    let Some(generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut() else {
        panic!("a prepare is a UniversalTx");
    };
    let Some(generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a prepare is an Invoke");
    };
    let args = invoke.args.as_mut().expect("the prepare's args");
    let mut request = generated::BilateralPrepareRequest::decode(args.body.as_slice())
        .expect("the prepare request");
    request.expected_counterparty_state_hash = Some(generated::Hash32 { v: vec![0x5E; 32] });
    args.body = request.encode_to_vec();
    let tampered = envelope.encode_to_vec();

    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&tampered, None)
        .await
        .expect("a stale proposal is answered");
    assert!(
        !answer.is_empty(),
        "a stale proposal is answered with a signed rejection"
    );
    assert_eq!(
        crate::storage::client_db::get_observed_remote_chain_tip(&a.device.device_id)
            .expect("read the observed tip"),
        None,
        "B kept a claimed tip the proposal's commitment does not recompute on"
    );
}

/// A prepare addressed to another device is meaningless bytes to the one it
/// reached: C, which holds A as a contact, is handed A's prepare for B. C
/// answers nothing and writes nothing — no session, no tip, no observed tip
/// — where, deciding the prepare as its own, it would answer a signed
/// rejection of a proposal that does not extend its tip with A. MUTATION
/// CONTROL: dropping Core's address check makes C answer, and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_prepare_addressed_to_another_device_answers_nothing_and_writes_nothing() {
    let (pair, a, b, _appliance, payment) = bearer_pair().await;
    let mut c_device = TestDevice::create("C", 0x0C);
    c_device.boot(&pair.fleet).await;
    c_device.add_contact(&pair.a).await;
    let c = OfflineDevice::new(&c_device);
    let c_tip_before = c.tip_with(&a);

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment).await.expect("A prepares for B");

    c.device.enter();
    let (answer, _meta) = c
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("a misaddressed prepare is dropped, not refused");
    assert!(answer.is_empty(), "C answered a prepare addressed to B");
    assert!(
        crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("read the session")
            .is_none(),
        "C recorded a session for a prepare addressed to B"
    );
    assert_eq!(c.handler.get_session_phase(&commitment).await, None);
    assert_eq!(c.tip_with(&a), c_tip_before, "C's tip with A moved");
    assert_eq!(
        crate::storage::client_db::get_observed_remote_chain_tip(&a.device.device_id)
            .expect("read the observed tip"),
        None,
        "C recorded A's claimed tip from a prepare addressed to B"
    );
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
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let mut tip = a.tip_with(&b);
    assert_eq!(tip, b.tip_with(&a), "both devices start at h_0");
    for step in 0..2 {
        let commitment = offline_step(&a, &b, payment.clone()).await;

        let (tip_a, tip_b) = (a.tip_with(&b), b.tip_with(&a));
        assert_eq!(tip_a, tip_b, "step {step}: the devices disagree on the tip");
        assert_ne!(tip_a, tip, "step {step}: the tip did not move");
        tip = tip_a;

        for device in [&a, &b] {
            device.device.enter();
            assert!(
                crate::storage::client_db::transaction_exists(
                    &crate::util::text_id::encode_base32_crockford(&commitment)
                )
                .expect("read the history"),
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

/// The step's history row on the entered device, if it has one.
fn history_row_exists(commitment: &[u8; 32]) -> bool {
    crate::storage::client_db::transaction_exists(&crate::util::text_id::encode_base32_crockford(
        commitment,
    ))
    .expect("read the history")
}

/// Both devices hold the step: one history row each, the same tip, no
/// session left.
fn assert_committed_on_both(a: &OfflineDevice, b: &OfflineDevice, commitment: &[u8; 32]) {
    assert_eq!(
        a.tip_with(b),
        b.tip_with(a),
        "the devices disagree on the tip"
    );
    for device in [a, b] {
        device.device.enter();
        assert!(
            history_row_exists(commitment),
            "{} holds no history row",
            device.device.slot
        );
        assert!(
            crate::storage::client_db::get_bilateral_session(commitment)
                .expect("read the session")
                .is_none(),
            "{} kept the committed step's session",
            device.device.slot
        );
    }
}

/// A receiver that restarts after accepting takes the proposal up again as it
/// was — the acceptance and its challenge were durable before the response
/// went out — and commits the confirm when it arrives.
/// MUTATION CONTROL: failing in-flight sessions on restart turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_restarted_after_accepting_commits_the_confirm() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a
        .propose(&b, payment.clone())
        .await
        .expect("the sender prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("the receiver's user accepts");

    let b = b.restarted().await;

    a.device.enter();
    let (confirm, _meta) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("the sender confirms");
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the restarted receiver commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A sender that restarts after its confirm went out — its step committed when
/// its anchor committed, with the confirm it owes — takes the step up again
/// awaiting its acknowledgment, and files the ack when it arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_restarted_after_its_confirm_files_the_ack() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (commitment, ack) = to_the_ack(&a, &b, payment.clone()).await;
    let a = a.restarted().await;
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("the restarted sender files the ack");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A sender that restarts holding a verified ack it had not yet filed files it
/// on restart, through the one filing path (the ack is verified again first).
/// MUTATION CONTROL: not taking up a held ack on restart turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_restarted_holding_its_ack_files_it_on_restart() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (commitment, ack) = to_the_ack(&a, &b, payment.clone()).await;
    let envelope = crate::envelope::from_canonical_bytes(&ack).expect("the ack decodes");
    let Some(crate::generated::envelope::Payload::BilateralCommitResponse(response)) =
        envelope.payload
    else {
        panic!("the ack is a commit response");
    };
    a.device.enter();
    assert!(a
        .handler
        .record_commit_ack(commitment, &response.counter_signed_receipt)
        .await
        .expect("the sender records the verified ack"));
    assert_eq!(
        stored_phase(&commitment),
        "confirm_pending",
        "a recorded ack is not filed"
    );

    let a = a.restarted().await;
    assert_committed_on_both(&a, &b, &commitment);
}

/// A persisted proposal whose parent tip and operation do not hash to its
/// commitment is not taken up again on restart: it fails, and an acceptance
/// arriving for it releases nothing — the anchor's counter does not move and
/// no history row is kept.
/// MUTATION CONTROL: holding the precommitment without checking it against
/// the commitment turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_restored_step_that_does_not_hash_to_its_commitment_commits_nothing() {
    let (_pair, a, b, appliance, payment) = bearer_pair().await;
    let h_0 = a.tip_with(&b);
    let before = chip(&appliance);

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment).await.expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    {
        let conn = crate::storage::client_db::get_connection().expect("db connection");
        let conn = conn.lock().expect("db lock");
        let rows = conn
            .execute(
                "UPDATE bilateral_sessions SET parent_tip = ?1 WHERE commitment_hash = ?2",
                rusqlite::params![vec![0x5A_u8; 32], commitment.to_vec()],
            )
            .expect("rewrite the stored parent tip");
        assert_eq!(rows, 1);
    }

    let a = a.restarted().await;
    a.device.enter();
    assert_eq!(
        crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("read the session")
            .expect("the session row is kept")
            .phase,
        "failed"
    );
    a.handler
        .handle_prepare_response(&response)
        .await
        .expect_err("an acceptance for a step not taken up releases nothing");
    assert_eq!(
        chip(&appliance).anchor_counter,
        before.anchor_counter,
        "the anchor's counter moved"
    );
    assert_eq!(a.tip_with(&b), h_0, "the sender's tip moved");
    a.device.enter();
    assert!(
        !history_row_exists(&commitment),
        "the sender kept a history row"
    );
}

/// The confirm frame `confirm` with its sender signature replaced.
fn with_sender_signature(confirm: &[u8], signature: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let mut envelope = crate::envelope::from_canonical_bytes(confirm).expect("the confirm decodes");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a confirm is a universal transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a confirm invokes bilateral.confirm");
    };
    let args = invoke.args.as_mut().expect("the confirm's arguments");
    let mut request =
        crate::generated::BilateralConfirmRequest::decode(args.body.as_slice()).expect("decodes");
    request.sender_signature = signature;
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// `confirm` with the stitched receipt its request carries replaced by
/// `receipt`. The sender's signature covers the commitment, which the receipt
/// is not part of.
fn with_receipt(confirm: &[u8], receipt: &dsm::types::receipt_types::StitchedReceiptV2) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(confirm).expect("the confirm's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a confirm carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a confirm is an invoke");
    };
    let args = invoke.args.as_mut().expect("the confirm's arguments");
    let mut request =
        crate::generated::BilateralConfirmRequest::decode(args.body.as_slice()).expect("decodes");
    request.stitched_receipt = receipt
        .to_canonical_protobuf()
        .expect("the receipt encodes");
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// MR-DSM-0028, MR-DSM-0116: the receiver takes a bearer step only on its
/// sender's receipt, from this session's sender to this device, whose writes
/// fold from its parent root to its child root — checked by Core before
/// anything commits. A confirm whose receipt's child root is not its writes'
/// fold, and one whose receipt names another sender, are each refused, and B
/// keeps nothing of them; the honest confirm then commits.
/// MUTATION CONTROL: deleting `verify_receipt_state` from Core's
/// `decide_confirm` lets the bent receipt through and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_confirm_whose_receipt_does_not_hold_is_refused_before_anything_commits() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;
    let request = {
        use prost::Message;
        let envelope = crate::envelope::from_canonical_bytes(&confirm).expect("the confirm");
        let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload else {
            panic!("a confirm carries a transaction");
        };
        let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = &tx.ops[0].kind else {
            panic!("a confirm is an invoke");
        };
        crate::generated::BilateralConfirmRequest::decode(
            invoke.args.as_ref().expect("arguments").body.as_slice(),
        )
        .expect("decodes")
    };
    let honest = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &request.stitched_receipt,
    )
    .expect("the sender's receipt");

    let mut bent = honest.clone();
    bent.child_root = bent.parent_root;
    let mut foreign = honest.clone();
    foreign.devid_a = [0x79; 32];
    b.device.enter();
    for (receipt, why) in [
        (bent, "do not fold from its parent root to its child root"),
        (foreign, "not from this session's sender"),
    ] {
        let refused = b
            .handler
            .handle_confirm_request(&with_receipt(&confirm, &receipt))
            .await
            .expect_err("a receipt that does not hold is refused");
        assert!(refused.to_string().contains(why), "{why}: {refused}");
        assert!(!history_row_exists(&commitment), "{why}: B kept the step");
        assert_eq!(pending_era(), 0, "{why}: B holds a payment");
    }
    b.handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the honest confirm commits");
    assert!(history_row_exists(&commitment), "B holds the step");
}

/// A bearer pair, funded 100 ERA on A ([`loaded_pair`]).
async fn bearer_pair() -> (
    Pair,
    OfflineDevice,
    OfflineDevice,
    crate::test_support::appliance::InstalledAppliance,
    Proposal,
) {
    loaded_pair(100, 0).await
}

/// A loaded pair: A funded and its offline allocation of 20 ERA loaded under
/// its anchor — the real anchor-core appliance on a software chip, whose
/// seed is the appliance's only typed-in value — B having validated A's online
/// history through the load, so it holds the account the load opened, and the
/// transfer of 7 base units of ERA from it to B.
async fn loaded_pair(
    a_funding: u64,
    b_funding: u64,
) -> (
    Pair,
    OfflineDevice,
    OfflineDevice,
    crate::test_support::appliance::InstalledAppliance,
    Proposal,
) {
    let pair = Pair::boot(a_funding, b_funding).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let appliance =
        crate::test_support::appliance::HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    a.device.enter();
    let loaded = a
        .device
        .invoke(
            "wallet.loadOffline",
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: "20.00".to_string(),
            },
        )
        .await;
    assert!(loaded.success, "the load: {:?}", loaded.error_message);
    let (genesis, devid) = {
        let head = a.device.router().core_sdk.device_head().expect("A's head");
        (head.genesis_digest(), head.devid())
    };
    let loaded_at = crate::economic_fixtures::admitted_position().expect("A is activated");
    b.device.enter();
    crate::economic_fixtures::foreign_walk(genesis, devid, loaded_at).await;
    let operation = bearer_transfer(&b, 7);
    (pair, a, b, appliance, operation)
}

/// `prepare` with the transfer terms its request carries replaced by
/// `terms`. The envelope carries no signature of its own: the proposal's
/// signature covers its commitment, which the terms are not part of.
fn with_terms(prepare: &[u8], terms: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(prepare).expect("the prepare's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a prepare carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a prepare is an invoke");
    };
    let args = invoke.args.as_mut().expect("the prepare's arguments");
    let mut request = crate::generated::BilateralPrepareRequest::decode(args.body.as_slice())
        .expect("the prepare request");
    request.transfer_terms = terms;
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// Pre-audit item 4 (owner ruling 2026-10-02): a bearer transfer's terms ride
/// beside its operation over BLE, and a prepare whose terms are missing, name
/// a memo the sender never signed, or do not decode, is refused before any
/// session exists. The honest prepare is taken and waits for B's user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_prepare_without_terms_that_open_it_is_refused() {
    let (_pair, a, b, _appliance, operation) = bearer_pair().await;
    let terms = operation.terms.clone().expect("a transfer's terms");
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");

    let mut tampered = terms.clone();
    tampered.memo = "a memo A never signed".to_string();
    b.device.enter();
    for (carried, why) in [
        (Vec::new(), "carries no terms"),
        (tampered.to_bytes(), "do not open"),
        (vec![0x01, 0x02], "transfer terms"),
    ] {
        let refused = b
            .handler
            .handle_prepare_request(&with_terms(&prepare, carried), None)
            .await
            .expect_err("refused");
        assert!(refused.to_string().contains(why), "{why}: {refused}");
        assert!(
            crate::storage::client_db::get_bilateral_session(&commitment)
                .expect("B's sessions")
                .is_none(),
            "{why}: B holds no session"
        );
    }
    let (answer, _) = b
        .handler
        .handle_prepare_request(&with_terms(&prepare, terms.to_bytes()), None)
        .await
        .expect("the terms that open the transfer are taken");
    assert!(answer.is_empty(), "the proposal waits for B's user");
    assert!(
        crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("B's sessions")
            .is_some(),
        "B holds the proposal for its user"
    );
}

/// `prepare` with the operation its request carries replaced by `operation`.
fn with_operation(prepare: &[u8], operation: &Operation) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(prepare).expect("the prepare's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a prepare carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a prepare is an invoke");
    };
    let args = invoke.args.as_mut().expect("the prepare's arguments");
    let mut request = crate::generated::BilateralPrepareRequest::decode(args.body.as_slice())
        .expect("the prepare request");
    request.operation_data = operation.to_bytes();
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// One operation of each class the offline door refuses, to `to`, with the
/// class its refusal names (MR-DSM-0219; Core's `offline_door`).
fn one_of_each_refused_class(to: &OfflineDevice) -> Vec<(Operation, &'static str)> {
    use dsm::types::operations::TransactionMode::Bilateral;
    let mut online = bearer_transfer(to, 7).operation;
    if let Operation::Transfer {
        authority_policy, ..
    } = &mut online
    {
        *authority_policy = None;
    }
    vec![
        (
            Operation::SofiSetup {
                setup_body: vec![0x36, 0x01],
                signature: vec![0xA1; 64],
            },
            "a SoFi operation",
        ),
        (
            Operation::SofiFulfill {
                fulfillment_body: vec![0x39, 0x01],
                precommit_id: vec![0x11; 32],
                signature: vec![0xA3; 64],
            },
            "a SoFi operation",
        ),
        (
            Operation::DlvCreate {
                vault_id: vec![0x01; 32],
                creator_public_key: vec![0x02; 64],
                parameters_hash: vec![0x03; 32],
                fulfillment_condition: vec![0x04; 16],
                intended_recipient: None,
                signature: vec![0x06; 48],
                mode: Bilateral,
            },
            "a vault operation",
        ),
        (
            Operation::Burn {
                amount: dsm::types::token_types::Balance::amount(7),
                token_id: b"ERA".to_vec(),
                policy_commit: dsm::core::token::token_state_manager::era_policy_commit(),
                token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
                message: "burn".into(),
            },
            "a token operation",
        ),
        (
            Operation::CreateRelationship {
                message: "re-establish".into(),
                counterparty_id: to.device.device_id.to_vec(),
                commitment: vec![0x02; 16],
                proof: vec![0x03; 64],
                mode: Bilateral,
            },
            "an identity or relationship operation",
        ),
        (Operation::Noop, "a step that moves no value"),
        (
            Operation::Generic {
                operation_type: b"offline-step-test".to_vec(),
                data: vec![0x01],
                message: String::new(),
                signature: Vec::new(),
            },
            "a step that moves no value",
        ),
        (online, "an online-tier transfer"),
    ]
}

/// MR-DSM-0219 (§6.105 C1), the receiver's door: a prepare carrying anything
/// but the offline-bearer transfer — a SoFi or vault operation, a token or
/// relationship operation, a step that moves no value, an online-tier
/// transfer — is refused by its class, through the byte carrier, before
/// anything is verified or written. B holds no session for it and is credited
/// nothing; the honest bearer prepare is taken.
/// MUTATION CONTROL: a wildcard arm in Core's `offline_door` (`door_wildcard`)
/// admits the SoFi operation and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_receivers_door_refuses_every_class_the_offline_rulings_do_not_name() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment).await.expect("A prepares");
    b.device.enter();
    for (operation, class) in one_of_each_refused_class(&b) {
        let refused = b
            .handler
            .handle_prepare_request(&with_operation(&prepare, &operation), None)
            .await
            .expect_err("refused at the receiver's door");
        assert!(
            refused.to_string().contains(&format!("{class} is refused")),
            "{class}: {refused}"
        );
        assert!(
            crate::storage::client_db::get_all_bilateral_sessions()
                .expect("B's sessions")
                .is_empty(),
            "{class}: B holds no session"
        );
    }
    assert_eq!(pending_era(), 0, "B is credited nothing");
    let (answer, _) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the bearer transfer passes the door");
    assert!(answer.is_empty(), "the proposal waits for B's user");
    assert!(
        crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("B's sessions")
            .is_some(),
        "B holds the bearer proposal"
    );
}

/// MR-DSM-0219 (§6.105 C1), the sender's door: a proposal of anything but the
/// offline-bearer transfer is refused by its class before any session state
/// exists, and A's anchor spends nothing.
/// MUTATION CONTROL: a wildcard arm in Core's `offline_door` (`door_wildcard`)
/// lets A propose the SoFi operation and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_senders_door_refuses_every_class_the_offline_rulings_do_not_name() {
    let (_pair, a, b, appliance, _payment) = bearer_pair().await;
    let before = chip(&appliance);
    a.device.enter();
    for (operation, class) in one_of_each_refused_class(&b) {
        let refused = a
            .handler
            .prepare_bilateral_step(b.device.device_id, operation, None)
            .await
            .expect_err("refused at the sender's door");
        assert!(
            refused.to_string().contains(&format!("{class} is refused")),
            "{class}: {refused}"
        );
        assert!(
            crate::storage::client_db::get_all_bilateral_sessions()
                .expect("A's sessions")
                .is_empty(),
            "{class}: A holds no session"
        );
    }
    assert_eq!(chip(&appliance), before, "A's anchor spent nothing");
}

/// `payload`, a frame of `frame_type`, written from `from` to `to` over BLE:
/// chunked by the sender's frame coordinator as the radio writes it, every
/// chunk taken in by the receiver's on the link from the sender, and the frame
/// reassembled whole. Returns the frame as the receiver's radio hands it on.
async fn over_ble(
    from: &OfflineDevice,
    to: &OfflineDevice,
    frame_type: BleFrameType,
    payload: &[u8],
) -> TransportInboundMessage {
    use crate::bluetooth::ble_frame_coordinator::FrameIngressResult;
    from.device.enter();
    let chunks = from
        .ble
        .encode_message(frame_type, payload)
        .expect("the frame is chunked");
    to.device.enter();
    let link = from.device.slot.to_string();
    let mut reassembled = None;
    for chunk in &chunks {
        match to
            .ble
            .ingest_chunk(&link, chunk)
            .await
            .expect("the chunk is taken in")
        {
            FrameIngressResult::NeedMoreChunks => {}
            FrameIngressResult::MessageComplete { message } => reassembled = Some(message),
            FrameIngressResult::ProtocolControl(control) => {
                panic!("a frame's chunk answered as transport control: {control:?}")
            }
        }
    }
    let message = reassembled.expect("the frame reassembles once its last chunk is in");
    assert_eq!(
        message.payload, payload,
        "the frame reassembles to the bytes written"
    );
    TransportInboundMessage {
        peer_address: link,
        frame_type: message.frame_type,
        payload: message.payload,
    }
}

/// `payload` delivered from `from` to `to` over BLE and handed to `to`'s
/// bilateral transport adapter, as the BLE bridge hands it a reassembled
/// frame. Returns what the adapter sends back.
async fn delivered_over_ble(
    from: &OfflineDevice,
    to: &OfflineDevice,
    frame_type: BleFrameType,
    payload: &[u8],
) -> Vec<TransportOutbound> {
    let message = over_ble(from, to, frame_type, payload).await;
    to.adapter()
        .on_transport_message(message)
        .await
        .expect("the receiver's transport takes the frame")
}

/// A's bearer `payment` to B, every frame carried over BLE: A's prepare, B's
/// acceptance answered with A's confirm — its release on A's anchor — B's
/// commit, and B's acknowledgment, on which A commits. The adapter hands a
/// confirm to a task it spawns, which acknowledges over the radio; here that
/// task's call runs in place, on B. Returns the step's commitment.
async fn bearer_payment_over_ble(
    a: &OfflineDevice,
    b: &OfflineDevice,
    payment: &Proposal,
) -> [u8; 32] {
    a.device.enter();
    let (prepare, commitment) = a
        .adapter()
        .create_transfer_prepare_with_commitment(
            b.device.device_id,
            payment.operation.clone(),
            payment.terms.clone().expect("a transfer's terms"),
        )
        .await
        .expect("A prepares the payment");
    let answered = delivered_over_ble(a, b, BleFrameType::BilateralPrepare, &prepare).await;
    assert!(answered.is_empty(), "the proposal waits for B's user");
    b.device.enter();
    let response = b
        .adapter()
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    let confirm = match delivered_over_ble(b, a, BleFrameType::BilateralPrepareResponse, &response)
        .await
        .as_slice()
    {
        [outbound] if outbound.frame_type == BleFrameType::BilateralConfirm => {
            outbound.payload.clone()
        }
        other => panic!("A answers the acceptance with its confirm, not {other:?}"),
    };
    let carried = over_ble(a, b, BleFrameType::BilateralConfirm, &confirm).await;
    let envelope =
        crate::envelope::from_canonical_bytes(&carried.payload).expect("the confirm's envelope");
    assert_eq!(
        crate::bluetooth::bilateral_transport_adapter::BilateralFrame::of(&envelope),
        Some(crate::bluetooth::bilateral_transport_adapter::BilateralFrame::Confirm),
        "the frame carried is the confirm"
    );
    let ack = b
        .handler
        .handle_confirm_request(&carried.payload)
        .await
        .expect("B commits the payment and acknowledges it");
    let answered = delivered_over_ble(b, a, BleFrameType::BilateralCommitResponse, &ack).await;
    assert!(answered.is_empty(), "the acknowledgment ends the step");
    commitment
}

/// A bearer transfer of `amount` base units of ERA from A to `to`.
fn bearer_transfer(to: &OfflineDevice, amount: u64) -> Proposal {
    let (bytes, terms) =
        crate::handlers::wallet_routes::encode_offline_transfer_operation_canonical(
            &to.device.device_id,
            amount,
            "ERA",
            "",
            &dsm::core::token::token_state_manager::era_policy_commit(),
            dsm::core::token::era_policy::era_policy_bytes().to_vec(),
        );
    Proposal {
        operation: Operation::from_bytes(&bytes).expect("the bearer transfer"),
        terms: Some(terms),
    }
}

/// The value of ERA the entered device received offline and has not settled.
fn pending_era() -> u64 {
    crate::storage::client_db::offline_receipts::pending_offline_value(
        &dsm::core::token::token_state_manager::era_policy_commit(),
    )
    .expect("the payments received offline")
}

/// The spends A's anchor released that no boundary of A's online history has
/// exposed yet.
fn unexposed_spends(
    a: &OfflineDevice,
    appliance: &crate::test_support::appliance::InstalledAppliance,
) -> usize {
    a.device.enter();
    crate::storage::client_db::offline_spends::own_offline_spends(&appliance.pin().bundle)
        .expect("A's spends")
        .len()
}

/// Phases 2–4, SA-61 opened: A's bearer payment of 7 to B, every frame over
/// BLE, commits on both devices. B credits nothing online — its ERA balance is
/// what it was, and an online send of what it received is refused — and holds
/// the payment pending until it is settled online (SA-91). A's anchor moved its
/// counter once, B pinned A's anchor from the payment's disclosure, and A
/// records the spend, unexposed, for its next boundary to carry (SA-116).
/// MUTATION CONTROL: the receiver not recording the payment it commits
/// (`receipt_unrecorded`) leaves nothing pending and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_offline_payment_over_ble_is_held_pending_and_credits_nothing_online() {
    let (pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let commitment = bearer_payment_over_ble(&a, &b, &operation).await;
    assert_committed_on_both(&a, &b, &commitment);

    b.device.enter();
    assert_eq!(pair.b.era_balance(), 0, "B is credited nothing online");
    b.device.enter();
    assert_eq!(pending_era(), 7, "B holds the payment pending");
    let refused = pair.b.send(&pair.a, 7).await;
    assert!(
        !refused.success,
        "B spent online what it received offline before it was settled"
    );
    assert!(
        crate::bridge::anchor_enrollment_store()
            .expect("the enrollment store")
            .get(&a.device.device_id)
            .is_some(),
        "B pinned A's anchor from the payment"
    );
    assert_eq!(
        chip(&appliance).anchor_counter,
        before.anchor_counter + 1,
        "A's anchor moved its counter once"
    );
    assert_eq!(unexposed_spends(&a, &appliance), 1, "A records its spend");
}

/// SA-112, a response delivered twice: B's acceptance reaches A twice. A
/// releases once — its anchor's counter moves once — and answers the second
/// copy with the confirm it sent for the first, byte for byte. B commits the
/// payment once, from either copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_response_delivered_twice_releases_once_and_is_answered_with_the_same_confirm() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    let (confirm, _) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("A releases and confirms");
    let (again, _) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("the response delivered again is answered");
    assert_eq!(again, confirm, "the confirm owed is the confirm sent");
    assert_eq!(
        chip(&appliance).anchor_counter,
        before.anchor_counter + 1,
        "A's anchor moved its counter once for the two copies"
    );

    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&again)
        .await
        .expect("B commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);
    b.device.enter();
    assert_eq!(pending_era(), 7, "B holds the payment once");
}

/// The acknowledgment filed, and a crash boundary on the receiver: B commits
/// A's payment and its ack is lost; B restarts. A still owes its confirm and
/// delivers it again; the restarted B answers with the ack the step committed,
/// from its history, and records nothing again. A files the ack and commits.
/// Each device holds the step once, B holds the payment once, and A records
/// its spend once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_payment_whose_ack_is_lost_is_answered_again_after_the_receiver_restarts() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let (commitment, _lost_ack) = to_the_ack(&a, &b, operation).await;
    let b = b.restarted().await;
    a.device.enter();
    let owed = a.handler.frames_owed_to(&b.device.device_id).await;
    assert_eq!(owed.len(), 1, "A owes its confirm");
    assert_eq!(
        owed[0].kind,
        crate::bluetooth::bilateral_session::OfflineFrameKind::Confirm
    );
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&owed[0].bytes)
        .await
        .expect("the restarted receiver answers its committed step again");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files the ack and commits");
    assert_committed_on_both(&a, &b, &commitment);
    for device in [&a, &b] {
        device.device.enter();
        assert_eq!(
            history_rows(&commitment),
            1,
            "{} holds the step twice",
            device.device.slot
        );
    }
    b.device.enter();
    assert_eq!(pending_era(), 7, "B holds the payment once");
    assert_eq!(
        unexposed_spends(&a, &appliance),
        1,
        "A records its spend once"
    );
    a.device.enter();
    assert!(a
        .handler
        .frames_owed_to(&b.device.device_id)
        .await
        .is_empty());
}

/// A crash boundary on the receiver before its commit: B accepts A's payment
/// and restarts before the confirm arrives. The restarted B takes the step up
/// again as it was — the acceptance and its challenge were durable before the
/// response went out — and commits the confirm, holding the payment pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_restarted_after_accepting_a_bearer_payment_commits_its_confirm() {
    let (_pair, a, b, _appliance, operation) = bearer_pair().await;
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    let b = b.restarted().await;
    a.device.enter();
    let (confirm, _) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("A releases and confirms");
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the restarted receiver commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);
    b.device.enter();
    assert_eq!(pending_era(), 7, "B holds the payment pending");
}

/// Restart recovery of a releasing step, through the handler: the power goes
/// off as A's anchor writes its committed candidate, while A answers B's
/// acceptance, so A sends nothing and the step stays releasing. A restarts
/// with its appliance booted again: the appliance completed the commit from its
/// record, and A's handler settles the step by the recovery table — the release
/// prepared for this step, emitted again — and owes B the confirm. B commits
/// it, A files the ack, and the counter moved once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_restarted_mid_release_settles_it_and_the_payment_commits_once() {
    use crate::test_support::appliance::Cut;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let counter_before = appliance.chip_counter();
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    // Record writes from here: 1 prepared, 2 the committed candidate.
    appliance.cut(Cut::AfterWrite(2));
    a.handler
        .handle_prepare_response(&response)
        .await
        .expect_err("the release cannot finish without power");
    assert_eq!(stored_phase(&commitment), "releasing");
    assert!(
        a.handler
            .frames_owed_to(&b.device.device_id)
            .await
            .is_empty(),
        "A owes nothing it has not released"
    );

    appliance.reboot();
    let a = a.restarted().await;
    a.device.enter();
    let owed = a.handler.frames_owed_to(&b.device.device_id).await;
    assert_eq!(owed.len(), 1, "the restarted A owes its confirm");
    assert_eq!(
        owed[0].kind,
        crate::bluetooth::bilateral_session::OfflineFrameKind::Confirm
    );
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&owed[0].bytes)
        .await
        .expect("B commits the release emitted again");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files the ack");
    assert_committed_on_both(&a, &b, &commitment);
    assert_eq!(
        appliance.chip_counter(),
        counter_before - 1,
        "the counter moved once"
    );
    assert_eq!(
        chip(&appliance).anchor_counter,
        before.anchor_counter + 1,
        "one counter step for the payment"
    );
    b.device.enter();
    assert_eq!(pending_era(), 7, "B holds the payment pending");
}

/// A bearer transfer B's user rejects spends no counter step on A's appliance:
/// nothing irreversible runs before an acceptance, and none comes. A takes the
/// rejection, and the relationship takes its next step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_rejected_bearer_transfer_spends_no_counter_step_and_frees_the_relationship() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let rejection = b
        .handler
        .create_prepare_reject_envelope_with_cleanup(commitment, "not now".to_string())
        .await
        .expect("B's user rejects");
    a.device.enter();
    a.handler
        .handle_prepare_reject(&rejection)
        .await
        .expect("the rejection ends A's side");
    let after = chip(&appliance);
    assert_eq!(
        after.anchor_counter, before.anchor_counter,
        "no counter step was spent"
    );
    assert_eq!(after.root, before.root, "the frontier did not move");
    b.device.enter();
    assert_eq!(pending_era(), 0, "B holds nothing pending");
    let next = offline_step(&a, &b, marked(&b, 0x61)).await;
    assert_committed_on_both(&a, &b, &next);
}

/// Phases 2–4 end to end (§5A "Offline, end to end"), every offline frame
/// over BLE between the two devices on the node harness: A loads 20 ERA into
/// its offline account; B validates A's online history through the load. A
/// pays B 7, then 3 more before A goes online again — the second payment
/// carries A's chain of spends from the account B recorded (SA-116). B holds
/// 10 pending and spends none of it online. A unloads what is left; that
/// boundary carries both spends and exposes them online. B's sync walks A's
/// history and settles each payment by an admitted transition of its own,
/// once (SA-91); a second sync settles nothing more. B then spends the result
/// online, and A takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_offline_payment_runs_end_to_end_load_spend_receive_unload_settle_and_spend_online() {
    use crate::economic_fixtures::whole_era;

    let (pair, a, b, appliance, _) = bearer_pair().await;
    let first = bearer_payment_over_ble(&a, &b, &bearer_transfer(&b, whole_era(7))).await;
    assert_committed_on_both(&a, &b, &first);
    let second = bearer_payment_over_ble(&a, &b, &bearer_transfer(&b, whole_era(3))).await;
    assert_committed_on_both(&a, &b, &second);
    assert_eq!(unexposed_spends(&a, &appliance), 2, "A's two spends wait");

    b.device.enter();
    assert_eq!(
        pending_era(),
        whole_era(10),
        "B holds both payments pending"
    );
    assert_eq!(pair.b.era_balance(), 0, "B is credited nothing online");
    let refused = pair.b.send(&pair.a, whole_era(1)).await;
    assert!(
        !refused.success,
        "B spent online what it received offline before it was settled"
    );

    a.device.enter();
    let unloaded = a
        .device
        .invoke(
            "wallet.unloadOffline",
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: "10.00".to_string(),
            },
        )
        .await;
    assert!(unloaded.success, "the unload: {:?}", unloaded.error_message);
    assert_eq!(
        unexposed_spends(&a, &appliance),
        0,
        "the unload carried A's spends online"
    );
    assert_eq!(
        pair.a.era_balance(),
        whole_era(90),
        "A's online balance: 100 funded, 20 loaded, 10 unloaded"
    );

    pair.b.sync().await;
    b.device.enter();
    assert_eq!(pending_era(), 0, "B settled both payments");
    assert_eq!(
        pair.b.era_balance(),
        whole_era(10),
        "B's online balance holds what it was paid offline"
    );
    pair.b.sync().await;
    assert_eq!(
        pair.b.era_balance(),
        whole_era(10),
        "a second sync settles nothing again"
    );

    let sent = pair.b.send(&pair.a, whole_era(10)).await;
    assert!(sent.success, "B spends online: {:?}", sent.error_message);
    assert_eq!(pair.b.era_balance(), 0, "B's online send debited");
    let synced = pair.a.sync().await;
    assert_eq!(
        pair.a.era_balance(),
        whole_era(100),
        "A received B's online payment: {synced:?}"
    );
}

/// The history rows the entered device holds for the step.
fn history_rows(commitment: &[u8; 32]) -> usize {
    let tx_id = crate::util::text_id::encode_base32_crockford(commitment);
    crate::storage::client_db::get_transaction_history(None, Some(1000), None)
        .expect("read the history")
        .into_iter()
        .filter(|row| row.tx_id == tx_id)
        .count()
}

/// The ack is lost after the receiver committed. The sender still owes its
/// confirm; when the link returns it delivers it again, and the receiver —
/// whose session ended in its commit — answers with the ack the step
/// committed, from its history. The sender commits; each device holds the
/// step once.
/// MUTATION CONTROL: answering a committed step's confirm with "no session"
/// (the behaviour replaced) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_lost_ack_is_answered_again_and_the_step_commits_once_on_each_side() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (commitment, _lost_ack) = to_the_ack(&a, &b, payment.clone()).await;
    let owed = a.handler.frames_owed_to(&b.device.device_id).await;
    assert_eq!(owed.len(), 1, "the sender owes its confirm");
    assert_eq!(
        owed[0].kind,
        crate::bluetooth::bilateral_session::OfflineFrameKind::Confirm
    );

    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&owed[0].bytes)
        .await
        .expect("the receiver answers its committed step again");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender files the ack answered again");
    assert_committed_on_both(&a, &b, &commitment);
    for device in [&a, &b] {
        device.device.enter();
        assert_eq!(
            history_rows(&commitment),
            1,
            "{} holds the step twice",
            device.device.slot
        );
    }
    assert!(a
        .handler
        .frames_owed_to(&b.device.device_id)
        .await
        .is_empty());
}

/// A confirm for a committed step is answered again only as its pinned
/// sender signed it: one carrying another signature gets no ack.
/// MUTATION CONTROL: answering without Core's `decide_committed_confirm`
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_committed_steps_confirm_not_signed_by_its_sender_is_not_answered() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (_commitment, _lost_ack) = to_the_ack(&a, &b, payment.clone()).await;
    let owed = a.handler.frames_owed_to(&b.device.device_id).await;
    let forged = with_sender_signature(&owed[0].bytes, vec![0x5A; 64]);
    b.device.enter();
    let refused = b
        .handler
        .handle_confirm_request(&forged)
        .await
        .expect_err("a confirm its sender did not sign is not answered");
    assert!(
        refused
            .to_string()
            .contains("not signed over its commitment by the pinned AK"),
        "{refused}"
    );
}

/// The acceptance delivered again is answered with the confirm it was
/// answered with the first time; the step completes on either copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_response_delivered_again_is_answered_with_the_confirm_it_owes() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a
        .propose(&b, payment.clone())
        .await
        .expect("the sender prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("the receiver's user accepts");
    a.device.enter();
    let (confirm, _) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("the sender confirms");
    let (again, _) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("the response delivered again is answered");
    assert_eq!(again, confirm, "the confirm owed is the confirm sent");

    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&again)
        .await
        .expect("the receiver commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// The proposal delivered again to a receiver that accepted it is answered
/// with the response it owes — also after the receiver restarts, since the
/// response is written with the acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_prepare_delivered_again_to_an_acceptance_is_answered_with_its_response() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a
        .propose(&b, payment.clone())
        .await
        .expect("the sender prepares");
    b.device.enter();
    let (first, _) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    assert!(first.is_empty(), "the proposal waits for the user");
    let (again, _) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the proposal delivered again");
    assert!(
        again.is_empty(),
        "a proposal awaiting its user has nothing to send"
    );
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("the receiver's user accepts");

    let b = b.restarted().await;
    let owed = b.handler.frames_owed_to(&a.device.device_id).await;
    assert_eq!(owed.len(), 1);
    assert_eq!(
        owed[0].bytes, response,
        "the restarted receiver owes its response"
    );
    let (answered, _) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the proposal delivered again after the restart");
    assert_eq!(answered, response, "answered with the response it owes");
}

/// The rejection frame `rejection` with its rejector signature replaced.
fn with_rejector_signature(rejection: &[u8], signature: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(rejection).expect("the rejection decodes");
    let Some(crate::generated::envelope::Payload::BilateralPrepareReject(reject)) =
        envelope.payload.as_mut()
    else {
        panic!("a rejection is a BilateralPrepareReject");
    };
    reject.rejector_signature = signature;
    envelope.encode_to_vec()
}

/// A proposal accepted by a receiver whose response is lost, up to that
/// response: the sender holds the proposal Prepared, the receiver Accepted.
async fn to_a_lost_response(
    a: &OfflineDevice,
    b: &OfflineDevice,
    proposal: Proposal,
) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    a.device.enter();
    let (prepare, commitment) = a.propose(b, proposal).await.expect("the sender prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("the receiver's user accepts");
    (commitment, prepare, response)
}

/// A proposer whose proposal went unanswered cancels it: the relationship is
/// free for the next step at once. The receiver, still holding its
/// acceptance, delivers its response again when the link returns; the
/// proposer answers with the signed cancellation, which ends the receiver's
/// side. Nothing moved on either side.
/// MUTATION CONTROL: refusing a rejection outside the proposer's phases (the
/// behaviour replaced) leaves the receiver's acceptance standing and turns
/// this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_proposer_cancels_an_unanswered_proposal_and_the_receiver_ends_it_on_its_next_frame() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    let h_0 = a.tip_with(&b);

    let (commitment, _prepare, _lost_response) = to_a_lost_response(&a, &b, payment.clone()).await;
    a.device.enter();
    a.handler
        .cancel_proposal(commitment, "no answer".to_string())
        .await
        .expect("the proposer cancels its unanswered proposal");
    assert!(
        a.handler
            .frames_owed_to(&b.device.device_id)
            .await
            .is_empty(),
        "a cancelled proposal owes nothing"
    );

    b.device.enter();
    let owed = b.handler.frames_owed_to(&a.device.device_id).await;
    assert_eq!(owed.len(), 1, "the receiver still owes its response");
    a.device.enter();
    let (answer, _) = a
        .handler
        .handle_prepare_response(&owed[0].bytes)
        .await
        .expect("the response is answered");
    b.device.enter();
    b.handler
        .handle_prepare_reject(&answer)
        .await
        .expect("the proposer's signed cancellation ends the receiver's side");
    assert!(
        b.handler
            .frames_owed_to(&a.device.device_id)
            .await
            .is_empty(),
        "the receiver owes nothing after the cancellation"
    );
    assert_eq!(a.tip_with(&b), h_0, "nothing moved on the proposer");
    assert_eq!(b.tip_with(&a), h_0, "nothing moved on the receiver");

    // The relationship is free for the next step: no step is in flight. The
    // same operation on the same tip is the cancelled step again, and is
    // refused as that — not as a step in progress.
    a.device.enter();
    let again = a
        .propose(&b, payment.clone())
        .await
        .expect_err("the cancelled step is not proposed again");
    assert!(again.to_string().contains("already proposed"), "{again}");
}

/// A cancellation its proposer did not sign ends nothing: the receiver keeps
/// its acceptance and still owes its response.
/// MUTATION CONTROL: ending the step without the rejector's signature
/// verified turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_cancellation_its_proposer_did_not_sign_ends_nothing() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (commitment, _prepare, _lost_response) = to_a_lost_response(&a, &b, payment).await;
    a.device.enter();
    let cancellation = a
        .handler
        .cancel_proposal(commitment, "no answer".to_string())
        .await
        .expect("the proposer cancels");
    let forged = with_rejector_signature(&cancellation, vec![0x5A; 64]);
    b.device.enter();
    b.handler
        .handle_prepare_reject(&forged)
        .await
        .expect_err("a cancellation its proposer did not sign");
    assert_eq!(
        b.handler.frames_owed_to(&a.device.device_id).await.len(),
        1,
        "the receiver's acceptance stands"
    );
}

/// A step past its confirm is not cancelled: its receiver may have committed.
/// MUTATION CONTROL: allowing a cancellation in ConfirmPending turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_confirmed_step_cannot_be_cancelled() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    let (commitment, _ack) = to_the_ack(&a, &b, payment.clone()).await;
    a.device.enter();
    let refused = a
        .handler
        .cancel_proposal(commitment, "too late".to_string())
        .await
        .expect_err("a confirmed step is not cancelled");
    assert!(
        refused.to_string().contains("receiver may have committed"),
        "{refused}"
    );
    assert_eq!(
        a.handler.frames_owed_to(&b.device.device_id).await.len(),
        1,
        "the confirm is still owed"
    );
}

/// A receiver that rejected a proposal answers the proposal delivered again
/// with its signed rejection, which ends the proposer's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_that_rejected_answers_the_prepare_again_with_its_rejection() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a
        .propose(&b, payment.clone())
        .await
        .expect("the sender prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the receiver takes the proposal");
    let rejection = b
        .handler
        .create_prepare_reject_envelope_with_cleanup(commitment, "no thanks".to_string())
        .await
        .expect("the receiver's user rejects");
    let (answer, _) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("the proposal delivered again");
    assert_eq!(answer, rejection, "answered with the rejection");
    a.device.enter();
    a.handler
        .handle_prepare_reject(&answer)
        .await
        .expect("the rejection ends the proposer's side");
    assert!(a
        .handler
        .frames_owed_to(&b.device.device_id)
        .await
        .is_empty());
}

/// Online after offline, on one relationship. Chain tips are per-device
/// values: each device's next online step is signed under the relationship
/// leaf its offline step ended at, and its peer pins that leaf from the step's
/// verified receipts — the sender's confirm at the receiver's commit, the
/// receiver's acknowledgment at the sender's. After an offline step from A to
/// B, A's online send to B is taken by B, and B's back to A by A.
/// MUTATION CONTROL: the receiver not moving its pin of the sender's head at
/// its commit (`peer_pin_receiver`), or the sender not moving its pin of the
/// receiver's head on the acknowledgment (`peer_pin_sender_ack`), leaves that
/// device refusing its peer's online send and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn online_sends_after_an_offline_step_are_taken_in_both_directions() {
    use crate::economic_fixtures::whole_era;

    let (pair, a, b, _appliance, _payment) = loaded_pair(100, 100).await;
    let (a_before, b_before) = (pair.a.era_balance(), pair.b.era_balance());
    let step = offline_step(&a, &b, marked(&b, 1)).await;
    assert_committed_on_both(&a, &b, &step);

    let sent = pair.a.send(&pair.b, whole_era(1)).await;
    assert!(sent.success, "A sends online: {:?}", sent.error_message);
    let synced = pair.b.sync().await;
    assert_eq!(
        pair.b.era_balance(),
        b_before + whole_era(1),
        "B took A's online send: {synced:?}"
    );
    pair.a.sync().await;
    let sent = pair.b.send(&pair.a, whole_era(2)).await;
    assert!(sent.success, "B sends online: {:?}", sent.error_message);
    let synced = pair.a.sync().await;
    assert_eq!(
        pair.a.era_balance(),
        a_before - whole_era(1) + whole_era(2),
        "A took B's online send: {synced:?}"
    );
}

/// SA-114. A proposal its receiver never saw, delivered after the
/// relationship moved past the tip it was made on, is refused as stale and
/// changes nothing else: the tip it claims is one this relationship has
/// passed, so it is not kept as the sender's tip. Kept, it tripped the
/// divergence check, and online sends to the contact stopped for good.
/// MUTATION CONTROL: keeping every claimed tip that its commitment
/// recomputes on, as the receiver did, records the passed tip and turns this
/// red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_old_proposal_delivered_after_the_tip_moved_is_not_kept_as_the_senders_tip() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;
    let old_tip = b.tip_with(&a);

    a.device.enter();
    let (old_prepare, old_commitment) = a
        .propose(&b, marked(&b, 0x51))
        .await
        .expect("a proposal its receiver never sees");
    a.handler
        .cancel_proposal(old_commitment, "never sent".to_string())
        .await
        .expect("the proposer ends it");
    offline_step(&a, &b, marked(&b, 0x52)).await;
    assert_ne!(b.tip_with(&a), old_tip, "the relationship moved");

    b.device.enter();
    let (answer, _) = b
        .handler
        .handle_prepare_request(&old_prepare, None)
        .await
        .expect("the old proposal is answered");
    let reply = crate::envelope::from_canonical_bytes(&answer).expect("decode the reply");
    match reply.payload {
        Some(crate::generated::envelope::Payload::BilateralPrepareReject(reject)) => {
            assert!(
                reject.reason.contains("Chain tip mismatch"),
                "{}",
                reject.reason
            )
        }
        other => panic!("the old proposal is refused as stale, not {other:?}"),
    }
    let observed = crate::storage::client_db::get_observed_remote_tip_record(&a.device.device_id)
        .expect("read the observed tip");
    assert!(
        observed.as_ref().map(|record| record.tip) != Some(old_tip),
        "the passed tip is kept as the sender's: {observed:?}"
    );
}

/// A step of its own to `to`: a bearer transfer of `mark` base units of ERA.
/// Two steps on one tip are two steps only if their operations differ.
fn marked(to: &OfflineDevice, mark: u8) -> Proposal {
    bearer_transfer(to, u64::from(mark))
}

/// Two proposals that cross — each device proposes before the other's
/// proposal arrives — are each refused by its receiver with a signed
/// rejection: the receiver has a step of its own in flight, and the
/// relationship takes one step at a time at both doors. Each proposer ends its
/// step on that rejection; nothing commits and no tip moves. The refusal is
/// kept: the proposal delivered again, once nothing is in flight, is refused
/// the same way rather than taken, since its proposer has ended it. The
/// relationship is then free, and the next step commits on both devices.
/// MUTATION CONTROLS: dropping the in-flight arm from Core's `decide_prepare`
/// lets each receiver hold the other's proposal for its user (were both
/// accepted and confirmed, each would commit the other's step and the
/// relationship would fork); not keeping the refusal lets the proposal
/// delivered again be taken. Each turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn proposals_that_cross_are_each_refused_and_nothing_commits() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;
    let tip = a.tip_with(&b);

    a.device.enter();
    let (a_prepare, a_step) = a.propose(&b, marked(&b, 1)).await.expect("A proposes");
    b.device.enter();
    let (b_prepare, b_step) = b
        .propose(&a, marked(&a, 2))
        .await
        .expect("B proposes before A's proposal arrives");

    b.device.enter();
    let (b_refusal, _meta) = b
        .handler
        .handle_prepare_request(&a_prepare, None)
        .await
        .expect("B answers A's proposal");
    assert!(
        !b_refusal.is_empty(),
        "B, with its own step in flight, holds A's proposal for its user"
    );
    a.device.enter();
    let (a_refusal, _meta) = a
        .handler
        .handle_prepare_request(&b_prepare, None)
        .await
        .expect("A answers B's proposal");
    assert!(
        !a_refusal.is_empty(),
        "A, with its own step in flight, holds B's proposal for its user"
    );

    a.device.enter();
    a.handler
        .handle_prepare_reject(&b_refusal)
        .await
        .expect("A takes B's signed refusal");
    b.device.enter();
    b.handler
        .handle_prepare_reject(&a_refusal)
        .await
        .expect("B takes A's signed refusal");

    for (device, own, refused) in [(&a, a_step, b_step), (&b, b_step, a_step)] {
        device.device.enter();
        assert_eq!(
            device.handler.get_session_phase(&own).await,
            Some(BilateralPhase::Rejected),
            "{}: its own step did not end on the refusal",
            device.device.slot
        );
        let kept = crate::storage::client_db::get_bilateral_session(&refused)
            .expect("read the session")
            .unwrap_or_else(|| panic!("{}: the refusal is not kept", device.device.slot));
        assert_eq!(kept.phase, "rejected", "{}", device.device.slot);
        for step in [own, refused] {
            assert!(
                !history_row_exists(&step),
                "{}: a refused step committed",
                device.device.slot
            );
        }
    }
    assert_eq!(
        (a.tip_with(&b), b.tip_with(&a)),
        (tip, tip),
        "a refused step moved a tip"
    );

    b.device.enter();
    let (again, _meta) = b
        .handler
        .handle_prepare_request(&a_prepare, None)
        .await
        .expect("B answers A's proposal delivered again");
    assert_eq!(
        again, b_refusal,
        "B did not answer the proposal delivered again with the refusal it kept"
    );

    let commitment = offline_step(&a, &b, marked(&b, 3)).await;
    assert_committed_on_both(&a, &b, &commitment);
    assert_ne!(a.tip_with(&b), tip, "the next step did not move the tip");
}

/// Only a proposal awaiting this device's decision can be rejected. Once the
/// receiver has accepted, its proposer may confirm and it may commit: its
/// user's rejection is refused and changes nothing. A proposer's own step past
/// its confirm is not rejected either — a proposer ends its proposal by
/// cancelling it, and only before its confirm. The step then commits on both
/// devices.
/// MUTATION CONTROL: dropping the awaiting-decision guard from
/// `create_prepare_reject_envelope_with_cleanup` lets both rejections through
/// and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn only_a_proposal_awaiting_its_user_can_be_rejected() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment.clone()).await.expect("A proposes");
    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    assert!(answer.is_empty(), "the proposal waits for B's user");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    let refused = b
        .handler
        .create_prepare_reject_envelope_with_cleanup(commitment, "changed my mind".to_string())
        .await
        .expect_err("an accepted step is not rejected");
    assert!(
        refused
            .to_string()
            .contains("not a proposal awaiting this device's decision"),
        "unexpected refusal: {refused}"
    );
    assert_eq!(
        b.handler.get_session_phase(&commitment).await,
        Some(BilateralPhase::Accepted)
    );

    a.device.enter();
    let (confirm, _meta) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("A confirms");
    let refused = a
        .handler
        .create_prepare_reject_envelope_with_cleanup(commitment, "no".to_string())
        .await
        .expect_err("a confirmed step is not rejected");
    assert!(
        refused
            .to_string()
            .contains("not a proposal awaiting this device's decision"),
        "unexpected refusal: {refused}"
    );
    assert_eq!(
        a.handler.get_session_phase(&commitment).await,
        Some(BilateralPhase::ConfirmPending)
    );

    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("B commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// The relationship's step in flight is the durable one, whichever handler
/// holds it: production can build a second handler over the same store (the
/// late BLE init), and a step in flight through one blocks the next through
/// the other — at this device's own door and at the peer's.
/// MUTATION CONTROLS: reading the step in flight from the handler's own
/// sessions instead of the durable rows, at either door, lets the second step
/// through and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_step_in_flight_through_one_handler_blocks_the_next_through_another() {
    let (pair, a, b, _appliance, _payment) = bearer_pair().await;
    let a_again = OfflineDevice::new(&pair.a);

    a.device.enter();
    a.propose(&b, marked(&b, 1))
        .await
        .expect("A proposes through one handler");
    a_again.device.enter();
    let refused = a_again
        .propose(&b, marked(&b, 2))
        .await
        .expect_err("the step in flight blocks the next through another handler");
    assert!(
        refused.to_string().contains("in progress"),
        "unexpected refusal: {refused}"
    );

    b.device.enter();
    let (b_prepare, _b_step) = b.propose(&a, marked(&a, 3)).await.expect("B proposes");
    a_again.device.enter();
    let (answer, _meta) = a_again
        .handler
        .handle_prepare_request(&b_prepare, None)
        .await
        .expect("A's other handler answers B's proposal");
    assert!(
        !answer.is_empty(),
        "A's other handler held B's proposal for its user while A's step is in flight"
    );
}

/// A prepare delivered again after its step committed is answered with
/// nothing: the step's ack answers its confirm, and a device never signs a
/// rejection of a step it committed — though the prepare no longer extends
/// its tip. Delivered after a restart, when the step's history row is all the
/// receiver holds of it.
/// MUTATION CONTROL: dropping the committed-step answer lets the prepare be
/// refused as stale and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_committed_steps_prepare_delivered_again_is_not_refused() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment.clone()).await.expect("A proposes");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    let (confirm, _meta) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("A confirms");
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("B commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);

    let b = b.restarted().await;
    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B answers the prepare delivered again");
    assert!(
        answer.is_empty(),
        "B refused a step it committed ({} bytes)",
        answer.len()
    );
}

/// One step at a time holds across the online and offline processes. While an
/// offline step with a contact is in flight — this device's proposal, or the
/// contact's proposal it holds — the relationship is not send-ready, and an
/// online send to that contact is refused before any mutation. Once the step
/// ends, the online send goes.
/// MUTATION CONTROL: dropping the offline-step clause from the send-ready
/// authority lets the online sends through and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_online_send_waits_for_the_offline_step_in_flight() {
    let (pair, a, b, _appliance, _payment) = loaded_pair(1_000, 1_000).await;
    let (a_before, b_before) = (pair.a.era_balance(), pair.b.era_balance());

    a.device.enter();
    let (prepare, step) = a
        .propose(&b, marked(&b, 1))
        .await
        .expect("A proposes offline");
    let status = crate::handlers::relationship_status::derive_local_send_status_for_device_id(
        &b.device.device_id,
    );
    assert!(
        !status.send_ready && status.send_block_message.contains("offline step"),
        "A's relationship is send-ready with its offline step in flight: {status:?}"
    );
    let refused = pair.a.send(&pair.b, 10).await;
    assert!(
        !refused.success,
        "A sent online with its offline step in flight"
    );
    assert_eq!(pair.a.era_balance(), a_before, "a refused send debited");

    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B holds A's proposal for its user");
    let refused = pair.b.send(&pair.a, 10).await;
    assert!(
        !refused.success,
        "B sent online while it held A's offline proposal"
    );
    assert_eq!(pair.b.era_balance(), b_before, "a refused send debited");

    a.device.enter();
    let cancellation = a
        .handler
        .cancel_proposal(step, "changed my mind".to_string())
        .await
        .expect("A cancels its proposal");
    b.device.enter();
    b.handler
        .handle_prepare_reject(&cancellation)
        .await
        .expect("B takes the cancellation");

    let sent = pair.a.send(&pair.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
}

/// And the other way: while an online send on the relationship holds its
/// reservation, an offline proposal to that contact is refused; once the
/// reservation is released, it is proposed.
/// MUTATION CONTROL: dropping the reservation check from the offline
/// proposer's door lets the proposal through and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_offline_proposal_waits_for_an_online_send_in_progress() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;

    a.device.enter();
    let reservation = crate::security::modal_sync_lock::PendingOnlineGuard::acquire(
        &dsm::core::bilateral_transaction_manager::compute_smt_key(
            &a.device.device_id,
            &b.device.device_id,
        ),
    )
    .expect("the online send's reservation");
    let refused = a
        .propose(&b, marked(&b, 1))
        .await
        .expect_err("an online send is in progress");
    assert!(
        refused.to_string().contains("online send"),
        "unexpected refusal: {refused}"
    );
    drop(reservation);
    a.propose(&b, marked(&b, 1))
        .await
        .expect("A proposes once the online send is done");
}

/// SA-54. A device whose identity recovery is under way moves no value out.
/// Recovery under way before a proposal stops the proposal. Recovery that
/// begins after the receiver accepted stops the release: A's anchor spends
/// nothing, A sends no confirm, and B is paid nothing.
/// MUTATION CONTROL: dropping the gate before the prepare lets A propose
/// while recovering and turns the first refusal red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_recovering_device_neither_proposes_nor_releases_an_offline_spend() {
    use crate::storage::client_db::recovery::{set_recovery_state, RecoveryState};

    let (_pair, a, b, appliance, operation) = bearer_pair().await;

    a.device.enter();
    set_recovery_state(RecoveryState::Polling).expect("A's recovery begins");
    let refused = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect_err("no proposal while recovering");
    assert!(
        refused.to_string().contains("recovery in progress"),
        "{refused}"
    );
    set_recovery_state(RecoveryState::None).expect("A's recovery is not under way");

    let before = chip(&appliance);
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_step(
            b.device.device_id,
            operation.operation.clone(),
            operation.terms.clone(),
        )
        .await
        .expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    set_recovery_state(RecoveryState::Polling).expect("A's recovery begins");
    let refused = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect_err("no release while recovering");
    assert!(
        refused.to_string().contains("recovery in progress"),
        "{refused}"
    );
    assert_eq!(
        chip(&appliance).anchor_counter,
        before.anchor_counter,
        "no counter step was spent"
    );
    assert!(
        a.handler
            .frames_owed_to(&b.device.device_id)
            .await
            .iter()
            .all(|owed| owed.kind
                != crate::bluetooth::bilateral_session::OfflineFrameKind::Confirm),
        "A owes no confirm"
    );
    b.device.enter();
    assert_eq!(pending_era(), 0, "B is paid nothing");
}

/// The phase stored for the step `commitment` on the entered device.
fn stored_phase(commitment: &[u8; 32]) -> String {
    crate::storage::client_db::get_bilateral_session(commitment)
        .expect("read the session")
        .expect("the session is stored")
        .phase
}

/// Move the step `commitment`'s stored phase on the entered device to
/// `phase`, as another path's write made in the meantime does.
fn another_path_wrote(commitment: &[u8; 32], phase: &str) {
    let binding = crate::storage::client_db::get_connection().expect("the database");
    let conn = binding.lock().expect("the connection");
    let moved = conn
        .execute(
            "UPDATE bilateral_sessions SET phase = ?1 WHERE commitment_hash = ?2",
            rusqlite::params![phase, commitment.as_slice()],
        )
        .expect("move the stored phase");
    assert_eq!(moved, 1, "the session is stored");
}

/// SA-54. A cancellation is decided on a proposal not yet confirmed, then
/// signed; a confirm that went out while it was signed has moved the stored
/// phase. The cancellation is refused and the confirm's phase stands — it
/// used to be overwritten (last writer wins), ending a step its receiver may
/// commit.
/// MUTATION CONTROL: writing the cancellation whatever the stored phase
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_cancellation_does_not_overwrite_a_confirm_made_meanwhile() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (_prepare, commitment) = a.propose(&b, payment.clone()).await.expect("A prepares");
    another_path_wrote(&commitment, "confirm_pending");
    let refused = a
        .handler
        .cancel_proposal(commitment, "the user cancels".to_string())
        .await
        .expect_err("the confirm went out first");
    assert!(
        refused.to_string().contains("moved to confirm_pending"),
        "{refused}"
    );
    assert_eq!(stored_phase(&commitment), "confirm_pending");
}

/// SA-54. A rejection is checked against the proposal's phase, then its
/// signature verified; a confirm made meanwhile has moved the stored phase.
/// The rejection is refused and the confirm's phase stands.
/// MUTATION CONTROL: writing the rejection whatever the stored phase turns
/// this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_rejection_does_not_overwrite_a_confirm_made_meanwhile() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment.clone()).await.expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let rejection = b
        .handler
        .create_prepare_reject_envelope_with_cleanup(commitment, "B's user declines".to_string())
        .await
        .expect("B's user rejects");

    a.device.enter();
    another_path_wrote(&commitment, "confirm_pending");
    let refused = a
        .handler
        .handle_prepare_reject(&rejection)
        .await
        .expect_err("the confirm went out first");
    assert!(
        refused.to_string().contains("moved to confirm_pending"),
        "{refused}"
    );
    assert_eq!(stored_phase(&commitment), "confirm_pending");
}

/// SA-54. A confirm is built on a proposal its sender holds as prepared; a
/// cancellation written meanwhile ended the step. The confirm is refused
/// before it is sent and the cancellation stands.
/// MUTATION CONTROL: writing the confirm's state whatever the stored phase
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_confirm_does_not_overwrite_a_cancellation_made_meanwhile() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment.clone()).await.expect("A prepares");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");

    a.device.enter();
    another_path_wrote(&commitment, "rejected");
    let refused = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect_err("the cancellation was written first");
    assert!(
        refused.to_string().contains("moved to rejected"),
        "{refused}"
    );
    assert_eq!(stored_phase(&commitment), "rejected");
}

// --- The sender's release on its anchor, by the recovery table ---
//
// These drive the sender's half on its own: the staging and the canonical
// advance simulation the confirm builder runs (`stage_bearer_spend`,
// `simulate_advance_for_confirm`), the real anchor-core appliance on a
// software chip, and the recovery rules the sender settles a releasing step
// by. The receiver challenge is drawn the way a receiver draws it. The whole
// payment through the receiver — its acknowledgment, a response delivered
// twice (SA-112), restarts on either side — is exercised above.

/// A's bearer transfer to B staged on A's anchor under a fresh receiver
/// challenge, and the device roots its canonical advance simulation produces:
/// the sender's half of its confirm, up to the anchor's PREPARE.
struct StagedRelease {
    spend: crate::bluetooth::bilateral_ble_handler::StagedBearerSpend,
    challenge: [u8; 32],
    root_before: [u8; 32],
    root_after: [u8; 32],
    advance: dsm::types::device_state::AdvanceOutcome,
}

fn stage_release(a: &OfflineDevice, b: &OfflineDevice, operation: &Proposal) -> StagedRelease {
    a.device.enter();
    let router = crate::bridge::app_router().expect("A's router");
    let rel_key = a.device.rel_key_with(&b.device);
    let challenge: [u8; 32] = dsm::crypto::rng::random_bytes(32)
        .try_into()
        .expect("a 32-byte challenge");
    let spend = crate::bluetooth::bilateral_ble_handler::stage_bearer_spend(
        router.as_ref(),
        rel_key,
        b.device.device_id,
        &operation.operation,
        operation.terms.as_ref().expect("a transfer's terms"),
        challenge,
    )
    .expect("A stages the transfer on its anchor");
    let advance = router
        .simulate_advance_for_confirm(
            rel_key,
            b.device.device_id,
            operation.operation.clone(),
            &[],
            Some(spend.spend),
        )
        .expect("A simulates the step's advance");
    StagedRelease {
        root_before: advance.transition.pre_root(),
        root_after: advance.child_r_a,
        spend,
        challenge,
        advance,
    }
}

fn chip(
    appliance: &crate::test_support::appliance::InstalledAppliance,
) -> crate::anchor::ApplianceStatus {
    use crate::anchor::AnchorAppliance;
    (**appliance).clone().status().expect("the chip's status")
}

fn release(staged: &StagedRelease) -> crate::sdk::core_sdk::OfflineBearerArtifacts {
    crate::bridge::app_router()
        .expect("A's router")
        .release_offline_bearer(
            &staged.spend.staged,
            staged.challenge,
            staged.root_before,
            staged.root_after,
        )
        .expect("A's anchor prepares, commits and emits")
}

fn settle(
    staged: &StagedRelease,
) -> Result<crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance, dsm::types::error::DsmError>
{
    crate::bluetooth::bilateral_ble_handler::settle_release_on_appliance(
        crate::bridge::app_router().expect("A's router").as_ref(),
        staged.spend.staged.appliance_next_root,
    )
}

/// The owner's rulings: the anchor's counter moves once for a payment, and
/// re-emit retransmits the exact same signed payment — never a second one, and
/// the chip does not advance again. A releasing step whose release committed
/// is settled by emitting that release again, byte for byte, with the counter
/// where the commit left it; the frontier then advances to the step's own
/// successor, once.
/// MUTATION CONTROL: settling a committed release as if nothing were released
/// (it would be reset and released again) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_released_spend_moves_the_counter_once_and_is_emitted_again_unchanged() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let staged = stage_release(&a, &b, &operation);
    let released = release(&staged);
    let committed = chip(&appliance);
    assert_eq!(
        committed.anchor_counter,
        before.anchor_counter + 1,
        "the commit moves the counter one step"
    );
    assert_eq!(
        committed.root, before.root,
        "the frontier waits for the step"
    );

    let crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Committed(again) =
        settle(&staged).expect("the committed release is taken up")
    else {
        panic!("a committed release is emitted again, not reset");
    };
    assert_eq!(
        again.offline_release, released.offline_release,
        "the same signed release, byte for byte"
    );
    assert_eq!(
        chip(&appliance).anchor_counter,
        committed.anchor_counter,
        "emitting again does not move the counter"
    );

    let next = staged.spend.staged.appliance_next_root;
    let router = crate::bridge::app_router().expect("A's router");
    crate::bluetooth::bilateral_ble_handler::advance_committed_frontier(router.as_ref(), next)
        .expect("the frontier advances to the step's successor");
    let advanced = chip(&appliance);
    assert_eq!(advanced.root, next, "the frontier is the step's successor");
    crate::bluetooth::bilateral_ble_handler::advance_committed_frontier(router.as_ref(), next)
        .expect("an advanced frontier is the step's successor already");
    assert_eq!(
        chip(&appliance),
        advanced,
        "advancing again changes nothing"
    );
}

/// Phase 3, crash point 1 inside the anchor's own commit: the committed
/// candidate is written and the power goes off before the counter moves. The
/// release does not finish; nothing settles while the appliance is unpowered;
/// once it boots it has completed the commit from its durable record — the
/// counter moved once — and settling takes up the release prepared for this
/// step, never a new one.
/// MUTATION CONTROL: the appliance not writing the candidate before the counter
/// moves (anchor-core `commit_no_candidate_record`) leaves nothing to complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_power_cut_before_the_counter_moves_is_completed_at_boot_and_released_once() {
    use crate::test_support::appliance::{Cut, Power};
    use prost::Message;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let counter_before = appliance.chip_counter();
    let staged = stage_release(&a, &b, &operation);
    // Record writes from here: 1 prepared, 2 the committed candidate, 3 the counter moved.
    appliance.cut(Cut::AfterWrite(2));
    let router = crate::bridge::app_router().expect("A's router");
    router
        .release_offline_bearer(
            &staged.spend.staged,
            staged.challenge,
            staged.root_before,
            staged.root_after,
        )
        .expect_err("the commit cannot finish without power");
    assert_eq!(appliance.power(), Power::Off);
    assert_eq!(
        appliance.chip_counter(),
        counter_before,
        "the counter has not moved"
    );
    settle(&staged).expect_err("nothing settles while the appliance is unpowered");

    appliance.reboot();
    assert_eq!(
        appliance.chip_counter(),
        counter_before - 1,
        "boot recovery completed the commit: the counter moved once"
    );
    let crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Committed(again) =
        settle(&staged).expect("the completed release is taken up")
    else {
        panic!("a completed commit is emitted again, not reset");
    };
    let release = anchor_core::proto::pb::OfflineRelease::decode(again.offline_release.as_slice())
        .expect("a release")
        .to_release()
        .expect("a valid release");
    assert_eq!(release.cert.prev_frontier, before.root);
    assert_eq!(
        release.cert.next_frontier, staged.spend.staged.appliance_next_root,
        "the release is this step's"
    );
    assert_eq!(
        (
            release.cert.anchor_counter,
            release.cert.next_anchor_counter
        ),
        (before.anchor_counter, before.anchor_counter + 1)
    );
    settle(&staged).expect("settling again takes up the same release");
    assert_eq!(
        appliance.chip_counter(),
        counter_before - 1,
        "and moves the counter no further"
    );
    crate::bluetooth::bilateral_ble_handler::advance_committed_frontier(
        router.as_ref(),
        staged.spend.staged.appliance_next_root,
    )
    .expect("the frontier advances to the step's successor");
    assert_eq!(
        chip(&appliance).root,
        staged.spend.staged.appliance_next_root
    );
}

/// Phase 3, crash point 2 inside the anchor's own commit: the counter moved
/// and the power goes off as the counter-committed record is written. At boot
/// the appliance marks the commit from its durable candidate without moving the
/// counter again, and settling takes up this step's release.
/// MUTATION CONTROL: the appliance's counter phase not refusing a candidate
/// whose counter moved (anchor-core `commit_counter_unpinned`) is covered in
/// anchor-core; here boot recovery must not move the counter a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_power_cut_after_the_counter_moved_is_completed_at_boot_without_moving_it_again() {
    use crate::test_support::appliance::{Cut, Power};
    use prost::Message;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let counter_before = appliance.chip_counter();
    let staged = stage_release(&a, &b, &operation);
    appliance.cut(Cut::AtWrite(3));
    let router = crate::bridge::app_router().expect("A's router");
    router
        .release_offline_bearer(
            &staged.spend.staged,
            staged.challenge,
            staged.root_before,
            staged.root_after,
        )
        .expect_err("the counter-committed record did not land");
    assert_eq!(appliance.power(), Power::Off);
    assert_eq!(
        appliance.chip_counter(),
        counter_before - 1,
        "the counter moved before the power went"
    );

    appliance.reboot();
    assert_eq!(
        appliance.chip_counter(),
        counter_before - 1,
        "boot recovery marks the commit without moving the counter again"
    );
    let crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Committed(again) =
        settle(&staged).expect("the commit is taken up")
    else {
        panic!("a committed release is emitted again, not reset");
    };
    let release = anchor_core::proto::pb::OfflineRelease::decode(again.offline_release.as_slice())
        .expect("a release")
        .to_release()
        .expect("a valid release");
    assert_eq!(
        release.cert.next_frontier,
        staged.spend.staged.appliance_next_root
    );
}

/// Phase 3: a power cut while the anchor holds a prepared release and before
/// its commit starts. At boot no session can own the prepared record across the
/// reboot, so the appliance resets it durably; the counter never moved, and the
/// step settles as nothing released — it goes back to waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_power_cut_while_prepared_is_reset_at_boot_with_nothing_released() {
    use crate::test_support::appliance::Cut;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let counter_before = appliance.chip_counter();
    let staged = stage_release(&a, &b, &operation);
    appliance.cut(Cut::AfterWrite(1));
    crate::bridge::app_router()
        .expect("A's router")
        .release_offline_bearer(
            &staged.spend.staged,
            staged.challenge,
            staged.root_before,
            staged.root_after,
        )
        .expect_err("nothing commits without power");
    appliance.reboot();
    assert!(
        matches!(
            settle(&staged).expect("settled"),
            crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Unreleased
        ),
        "nothing was released"
    );
    assert_eq!(
        appliance.chip_counter(),
        counter_before,
        "the counter never moved"
    );
    assert_eq!(chip(&appliance), before, "the frontier is where it was");
}

/// The recovery table: prepared, and the counter unchanged — reset. A release
/// cut off after its anchor prepared goes back to waiting only once the
/// appliance reports no transaction with its counter unmoved: the prepared
/// record is cancelled, and the counter and the frontier are where they were.
/// MUTATION CONTROL: not cancelling the prepared record leaves the appliance
/// prepared, so settling fails closed and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_cut_off_after_its_prepare_goes_back_to_waiting_with_the_counter_unmoved() {
    use crate::anchor::AnchorAppliance;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let staged = stage_release(&a, &b, &operation);
    (*appliance)
        .clone()
        .prepare(
            &staged.spend.staged.transition.as_transition(),
            &staged.challenge,
            &staged.root_before,
            &staged.root_after,
        )
        .expect("A's anchor prepares");
    assert!(
        matches!(
            settle(&staged).expect("a prepared release is settled"),
            crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Unreleased
        ),
        "nothing was released"
    );
    assert_eq!(chip(&appliance), before, "counter and frontier are unmoved");
    assert_eq!(
        (*appliance)
            .clone()
            .recover()
            .expect("the appliance reports"),
        anchor_core::appliance::RecoverOutcome::Accept(before.root),
        "the appliance holds no transaction"
    );
}

/// The recovery table: no durable transaction, and the counter unchanged —
/// start again. A spend staged but never handed to the anchor released
/// nothing.
/// MUTATION CONTROL: settling an appliance with no transaction as committed
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_spend_staged_but_never_released_goes_back_to_waiting() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = chip(&appliance);
    let staged = stage_release(&a, &b, &operation);
    assert!(
        matches!(
            settle(&staged).expect("an unreleased spend is settled"),
            crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Unreleased
        ),
        "nothing was released"
    );
    assert_eq!(chip(&appliance), before, "counter and frontier are unmoved");
}

/// The recovery table: missing or inconsistent, and the counter advanced —
/// fail closed. An anchor whose frontier already advanced to the step's
/// successor, for a step recorded as releasing and never committed, is not
/// read as "nothing released": the counter moved for that step.
/// MUTATION CONTROL: dropping the check that an accepted frontier is not the
/// step's successor reads it as unreleased and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_frontier_advanced_for_a_step_never_committed_fails_closed() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let staged = stage_release(&a, &b, &operation);
    release(&staged);
    let router = crate::bridge::app_router().expect("A's router");
    router
        .finalize_offline_bearer(staged.spend.staged.appliance_next_root)
        .expect("the anchor's frontier advances");
    let advanced = chip(&appliance);
    let refused = settle(&staged).expect_err("an advanced counter is never reset");
    assert!(refused.to_string().contains("fail closed"), "{refused}");
    assert_eq!(chip(&appliance), advanced, "settling changed nothing");
}

/// The recovery table: a committed release is this step's only if it is this
/// step's successor. Two spends staged from the same frontier under different
/// challenges have different successors; with the first released, the second
/// step neither takes the first's release up nor goes back to waiting.
/// MUTATION CONTROL: dropping the check that a committed release is the step's
/// own successor takes the first's release up as the second's and turns this
/// red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn another_steps_committed_release_is_not_taken_up_as_this_steps() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let first = stage_release(&a, &b, &operation);
    let second = stage_release(&a, &b, &operation);
    assert_ne!(
        first.spend.staged.appliance_next_root, second.spend.staged.appliance_next_root,
        "different challenges stage different successors"
    );
    release(&first);
    let committed = chip(&appliance);
    let refused = settle(&second).expect_err("another step's release is not this step's");
    assert!(refused.to_string().contains("fail closed"), "{refused}");
    assert_eq!(chip(&appliance), committed, "settling changed nothing");
    assert!(
        matches!(
            settle(&first).expect("the first step's release is its own"),
            crate::bluetooth::bilateral_ble_handler::ReleaseOnAppliance::Committed(_)
        ),
        "the first step takes up its own release"
    );
}

/// A committed step's frontier advances only to that step's successor: the
/// anchor holding the first step's committed release refuses to advance for
/// another step's successor, and changes nothing.
/// MUTATION CONTROL: dropping the successor check in
/// `advance_committed_frontier` advances the frontier for the wrong step and
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_committed_frontier_advances_only_to_its_own_successor() {
    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let first = stage_release(&a, &b, &operation);
    let second = stage_release(&a, &b, &operation);
    release(&first);
    let committed = chip(&appliance);
    let router = crate::bridge::app_router().expect("A's router");
    crate::bluetooth::bilateral_ble_handler::advance_committed_frontier(
        router.as_ref(),
        second.spend.staged.appliance_next_root,
    )
    .expect_err("another step's successor is refused");
    assert_eq!(chip(&appliance), committed, "the refusal changed nothing");
    crate::bluetooth::bilateral_ble_handler::advance_committed_frontier(
        router.as_ref(),
        first.spend.staged.appliance_next_root,
    )
    .expect("the step's own successor");
    assert_eq!(
        chip(&appliance).root,
        first.spend.staged.appliance_next_root
    );
}

/// A's staged spend as A's device signs it over to B: the stitched receipt of
/// the step's write set, built and held to its state rules exactly as A's
/// confirm builds and holds it before the anchor commits, and the anchor-state
/// leaves the receipt moves.
fn spend_receipt(
    a: &OfflineDevice,
    b: &OfflineDevice,
    operation: &Proposal,
    staged: &StagedRelease,
) -> (
    dsm::types::receipt_types::StitchedReceiptV2,
    dsm::verification::receipt_verification::BearerLeaves,
) {
    a.device.enter();
    let leaves = dsm::verification::receipt_verification::BearerLeaves {
        bundle: staged.spend.staged.pin.bundle,
        counter: staged.spend.staged.transition.anchor_counter,
        frontier: staged.spend.staged.appliance_prev_root,
        next_frontier: staged.spend.staged.appliance_next_root,
    };
    let device_tree = crate::sdk::app_state::AppState::get_device_tree_commitment()
        .expect("A's Device Tree commitment");
    let bytes = crate::sdk::receipts::build_bilateral_receipt(
        a.device.device_id,
        b.device.device_id,
        &staged.advance,
        Some(leaves),
        &device_tree,
    )
    .expect("A builds the step's receipt");
    let receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&bytes)
        .expect("the receipt decodes");
    let genesis = a
        .device
        .router()
        .core_sdk
        .device_head()
        .expect("A's head")
        .genesis_digest();
    dsm::verification::receipt_verification::verify_receipt_state(
        &receipt,
        &dsm::verification::receipt_verification::ReceiptStateContext {
            device_tree_commitment: &device_tree,
            author_genesis: genesis,
            operation: &operation.operation,
            bearer: Some(leaves),
        },
    )
    .expect("the receipt holds its state rules");
    (receipt, leaves)
}

/// The owner's receive rule (2026-10-22): an offline payment is taken only
/// from the offline account its receiver validated itself, from the sender's
/// online history. B walks A's history through A's load; a spend A stages from
/// the account the load left starts from B's record. After A's unload, a spend
/// from the account the unload left is refused against B's stale record, and
/// taken once B's next walk records the unload — when the spend from the
/// load's account is refused in turn. A record of another sender, or under
/// another anchor bundle, is no origin for A's spend.
/// MUTATION CONTROL: dropping the pre-root comparison from Core's
/// `spend_starts_at_the_record` takes the spend from the unload's account
/// against B's record of the load and turns this red; dropping its sender and
/// bundle check takes the record under another bundle and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_offline_spend_is_taken_only_from_the_account_its_receiver_recorded() {
    use dsm::bilateral::offline::spend_starts_at_the_record;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    a.device.enter();
    let (genesis, devid) = {
        let head = a.device.router().core_sdk.device_head().expect("A's head");
        (head.genesis_digest(), head.devid())
    };
    let loaded_at = crate::economic_fixtures::admitted_position().expect("A is activated");
    let recorded = |position: u64| {
        b.device.enter();
        crate::storage::client_db::economic_lineage::latest_offline_account(
            &genesis,
            &devid,
            &appliance.pin().bundle,
        )
        .expect("B's store reads")
        .filter(|account| account.economic_position() == position)
        .expect("B recorded the boundary it walked")
    };
    // B's origin for A's spends: its record, A's anchor as B pins it, and no
    // spends of A's since the record.
    let pin = appliance.pin();
    let origin = |recorded: dsm::economic::peer_lineage::PeerOfflineAccount| {
        dsm::bilateral::offline::BearerOrigin {
            recorded: Some(recorded),
            anchor: dsm::types::offline_chain::ChainAnchor {
                bundle: pin.bundle,
                anchor_id: pin.anchor_id,
                pk_chip: pin.pk_chip.clone(),
                pk_host: pin.partition_pk.clone(),
            },
            chain: &[],
            accepted: None,
        }
    };

    b.device.enter();
    crate::economic_fixtures::foreign_walk(genesis, devid, loaded_at).await;
    let after_load = origin(recorded(loaded_at));
    let from_load = stage_release(&a, &b, &operation);
    let (load_receipt, load_leaves) = spend_receipt(&a, &b, &operation, &from_load);
    spend_starts_at_the_record(&load_receipt, &load_leaves, &genesis, &after_load)
        .expect("a spend from the account B recorded is taken");

    a.device.enter();
    let unloaded = a
        .device
        .invoke(
            "wallet.unloadOffline",
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: "5.00".to_string(),
            },
        )
        .await;
    assert!(unloaded.success, "the unload: {:?}", unloaded.error_message);
    let from_unload = stage_release(&a, &b, &operation);
    let (unload_receipt, unload_leaves) = spend_receipt(&a, &b, &operation, &from_unload);
    let refused =
        spend_starts_at_the_record(&unload_receipt, &unload_leaves, &genesis, &after_load)
            .expect_err("a spend from an account B has not validated");
    assert!(
        refused
            .to_string()
            .contains("does not start from the offline account"),
        "{refused}"
    );

    b.device.enter();
    crate::economic_fixtures::foreign_walk(genesis, devid, loaded_at + 1).await;
    let after_unload = origin(recorded(loaded_at + 1));
    spend_starts_at_the_record(&unload_receipt, &unload_leaves, &genesis, &after_unload)
        .expect("taken once B recorded the unload");
    spend_starts_at_the_record(&load_receipt, &load_leaves, &genesis, &after_unload)
        .expect_err("the spend from the load's account starts from a state B moved past");

    let mut other_bundle = unload_leaves;
    other_bundle.bundle[0] ^= 0x01;
    let refused =
        spend_starts_at_the_record(&unload_receipt, &other_bundle, &genesis, &after_unload)
            .expect_err("a record under another bundle");
    assert!(
        refused.to_string().contains("is not the sender's"),
        "{refused}"
    );
    let refused = spend_starts_at_the_record(
        &unload_receipt,
        &unload_leaves,
        &b.device.genesis,
        &after_unload,
    )
    .expect_err("a record of another sender");
    assert!(
        refused.to_string().contains("is not the sender's"),
        "{refused}"
    );
}

// ---------------------------------------------------------------------------
// The validation harness's confirm cases, on real bearer pairs (§6.103): each
// is the harness's attack, trace or property as production's two devices run
// it, every frame carried as bytes through the doors.
// ---------------------------------------------------------------------------

/// The prepare request `prepare` carries.
fn prepare_request(prepare: &[u8]) -> crate::generated::BilateralPrepareRequest {
    use prost::Message;
    let envelope = crate::envelope::from_canonical_bytes(prepare).expect("the prepare's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload else {
        panic!("a prepare carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = &tx.ops[0].kind else {
        panic!("a prepare is an invoke");
    };
    crate::generated::BilateralPrepareRequest::decode(
        invoke.args.as_ref().expect("arguments").body.as_slice(),
    )
    .expect("the prepare request decodes")
}

/// `prepare` with σ_A, its proposer's signature over the commitment, replaced
/// by `signature`.
fn with_prepare_signature(prepare: &[u8], signature: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(prepare).expect("the prepare's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a prepare carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a prepare is an invoke");
    };
    let args = invoke.args.as_mut().expect("the prepare's arguments");
    let mut request =
        crate::generated::BilateralPrepareRequest::decode(args.body.as_slice()).expect("decodes");
    request.sender_signature = signature;
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// `confirm` carrying `receipt` as the wire carries a confirm's receipt: in
/// full, its per-step EK artifacts and signatures with it.
fn with_signed_receipt(
    confirm: &[u8],
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
) -> Vec<u8> {
    use prost::Message;
    let mut envelope =
        crate::envelope::from_canonical_bytes(confirm).expect("the confirm's envelope");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload.as_mut()
    else {
        panic!("a confirm carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = tx.ops[0].kind.as_mut() else {
        panic!("a confirm is an invoke");
    };
    let args = invoke.args.as_mut().expect("the confirm's arguments");
    let mut request =
        crate::generated::BilateralConfirmRequest::decode(args.body.as_slice()).expect("decodes");
    request.stitched_receipt = receipt.to_full_protobuf().expect("the receipt encodes");
    args.body = request.encode_to_vec();
    envelope.encode_to_vec()
}

/// The stitched receipt `confirm` carries.
fn confirm_receipt(confirm: &[u8]) -> dsm::types::receipt_types::StitchedReceiptV2 {
    use prost::Message;
    let envelope = crate::envelope::from_canonical_bytes(confirm).expect("the confirm");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload else {
        panic!("a confirm carries a transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = &tx.ops[0].kind else {
        panic!("a confirm is an invoke");
    };
    let request = crate::generated::BilateralConfirmRequest::decode(
        invoke.args.as_ref().expect("arguments").body.as_slice(),
    )
    .expect("decodes");
    dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&request.stitched_receipt)
        .expect("the sender's receipt")
}

/// `receipt`, altered by its own sender, signed again on A's side by the
/// per-step EK `sender`'s chain derives for the step `commitment`: what a
/// sender that alters its own receipt can sign.
fn resigned_by(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    commitment: &[u8; 32],
) -> dsm::types::receipt_types::StitchedReceiptV2 {
    sender.device.enter();
    let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
        .expect("the sender's wallet is unlocked");
    let ak = crate::init::derive_device_signing_keypair(&wallet_seed, &sender.device.genesis)
        .expect("the sender's AK");
    let recipient_kyber_pk =
        crate::storage::client_db::get_contact_by_device_id(&receiver.device.device_id)
            .expect("read the contact")
            .expect("the receiver is a contact")
            .kyber_public_key;
    let mut resigned = receipt.clone();
    let signed = crate::sdk::receipts::sign_receipt_with_per_step_ek(
        &crate::sdk::receipts::PerStepSigningInputs {
            commitment: &resigned
                .compute_commitment()
                .expect("the receipt's commitment"),
            h_n: resigned.parent_tip,
            c_pre: *commitment,
            devid_sender: sender.device.device_id,
            relationship_key: sender.device.rel_key_with(&receiver.device),
            root_ak_keypair: Some((ak.public_key.as_slice(), ak.secret_key())),
            recipient_kyber_pk: &recipient_kyber_pk,
            session_binding: commitment,
        },
    )
    .expect("the sender's per-step EK signs");
    resigned.set_ek_pk_a(signed.ek_pk);
    resigned.set_ek_cert_a(signed.ek_cert);
    resigned.set_kyber_ct_a(signed.kyber_ct);
    resigned.sig_a.clear();
    resigned.add_sig_a(signed.sig);
    resigned
}

/// `receipt` signed under a fresh EK that `certifier`'s key certifies over the
/// receipt's parent tip: an EK the sender's own chain never certified, every
/// other artifact of the receipt genuine.
fn under_a_foreign_ek(
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    commitment: &[u8; 32],
    certifier: &dsm::crypto::signatures::SignatureKeyPair,
) -> dsm::types::receipt_types::StitchedReceiptV2 {
    let (ek_pk, ek_sk) = dsm::crypto::ephemeral_key::generate_ephemeral_keypair(
        &blake3::derive_key("DSM SDK offline test foreign EK", commitment),
    )
    .expect("the foreign EK");
    let mut foreign = receipt.clone();
    foreign.set_ek_cert_a(
        dsm::crypto::ephemeral_key::sign_ek_cert(
            certifier.secret_key(),
            &ek_pk,
            &foreign.parent_tip,
        )
        .expect("the certifier certifies the EK"),
    );
    foreign.set_ek_pk_a(ek_pk);
    let target = dsm::types::receipt_types::compute_receipt_challenge_response_target(
        &foreign
            .compute_commitment()
            .expect("the receipt's commitment"),
        commitment,
    );
    foreign.sig_a.clear();
    foreign.add_sig_a(dsm::crypto::sphincs::sphincs_sign(&ek_sk, &target).expect("the EK signs"));
    foreign
}

/// `prepare`, proposed by `sender` as the step `commitment`, taken by
/// `receiver`, accepted by its user, confirmed, committed and acknowledged:
/// every frame carried as bytes.
async fn deliver_and_commit(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    prepare: &[u8],
    commitment: [u8; 32],
) {
    receiver.device.enter();
    let (answer, _meta) = receiver
        .handler
        .handle_prepare_request(prepare, None)
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
        .expect("the sender confirms");
    receiver.device.enter();
    let ack = receiver
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the receiver commits");
    sender.device.enter();
    sender
        .handler
        .handle_commit_response(&ack)
        .await
        .expect("the sender commits");
    assert_committed_on_both(sender, receiver, &commitment);
}

/// `answer` is a signed refusal of a proposal that does not extend the tip its
/// receiver holds.
fn refused_as_stale(answer: &[u8], what: &str) {
    let reply = crate::envelope::from_canonical_bytes(answer).expect("decode the reply");
    match reply.payload {
        Some(crate::generated::envelope::Payload::BilateralPrepareReject(reject)) => assert!(
            reject.reason.contains("Chain tip mismatch"),
            "{what}: {}",
            reject.reason
        ),
        other => panic!("{what} is refused as stale, not {other:?}"),
    }
}

/// Two fully signed children of one tip — A's bearer payments of 1 and 2 base
/// units on the tip it holds with B — and B takes one: the first commits on
/// both devices, and the second, delivered after, does not extend the tip B
/// holds and is refused as stale, with nothing of it kept and B's tip where
/// the first left it.
/// (Moved from the validation harness: adversarial_bilateral's
/// `double_spend_second_child` and implementation_traces'
/// `state_machine_fork_divergence`, §6.103.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn two_signed_children_of_one_tip_the_first_commits_and_the_second_is_refused_as_stale() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;
    let tip = b.tip_with(&a);

    // The second child is signed first and held back: A's own door takes one
    // proposal at a time, so it ends the step it will not send.
    a.device.enter();
    let (second, second_commitment) = a
        .propose(&b, marked(&b, 0x02))
        .await
        .expect("the second child");
    a.handler
        .cancel_proposal(second_commitment, "held back".to_string())
        .await
        .expect("A ends the held-back child");
    let (first, first_commitment) = a
        .propose(&b, marked(&b, 0x01))
        .await
        .expect("the first child");
    let tip_claimed = |prepare: &[u8]| {
        prepare_request(prepare)
            .expected_counterparty_state_hash
            .map(|h| h.v)
    };
    assert_eq!(
        (tip_claimed(&first), tip_claimed(&second)),
        (Some(tip.to_vec()), Some(tip.to_vec())),
        "the two steps are not two children of one tip"
    );
    assert_ne!(
        first_commitment, second_commitment,
        "two different operations on one tip are one step"
    );

    deliver_and_commit(&a, &b, &first, first_commitment).await;
    let successor = b.tip_with(&a);
    assert_ne!(successor, tip, "the first child did not move the tip");

    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&second, None)
        .await
        .expect("the second child is answered");
    refused_as_stale(&answer, "the second child of a committed tip");
    assert!(
        crate::storage::client_db::get_bilateral_session(&second_commitment)
            .expect("read the session")
            .is_none(),
        "B holds a session for the second child"
    );
    assert!(
        !history_row_exists(&second_commitment),
        "B kept the second child"
    );
    assert_eq!(b.tip_with(&a), successor, "the second child moved B's tip");
}

/// A step whose σ_A is not its pinned sender's — a valid signature over the
/// right commitment by another key, or bytes that are no signature at all at
/// the production size — is refused at B's door before anything is kept, and
/// a confirm whose receipt is signed under an EK the sender's chain never
/// certified is refused before anything commits. The honest step is then
/// taken and commits, so each refusal is of its forgery and not of the step.
/// (Moved from the validation harness: adversarial_bilateral's
/// `forged_sender_signature`, §6.103. The harness decided the honest step
/// first; here it goes last, since a receiver that holds a proposal answers
/// its commitment from the session it holds.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_step_its_pinned_sender_did_not_sign_or_whose_ek_its_chain_never_certified_is_refused() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    let mallory = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(
        b"DSM SDK offline test mallory",
    )
    .expect("Mallory's key");

    a.device.enter();
    let (prepare, commitment) = a.propose(&b, payment).await.expect("A proposes");
    let honest_signature = prepare_request(&prepare).sender_signature;
    let wrong_signer = with_prepare_signature(
        &prepare,
        mallory
            .sign(&dsm::core::bilateral_transaction_manager::bilateral_sign_message(&commitment))
            .expect("Mallory signs the commitment"),
    );
    let garbage = with_prepare_signature(&prepare, vec![0xDE; honest_signature.len()]);

    b.device.enter();
    for (forged, what) in [
        (wrong_signer, "a step signed by the wrong key"),
        (garbage, "a garbage signature"),
    ] {
        let refused = b
            .handler
            .handle_prepare_request(&forged, None)
            .await
            .expect_err(what);
        assert!(
            refused
                .to_string()
                .contains("is not signed over its commitment by the pinned AK"),
            "{what}: {refused}"
        );
        assert!(
            crate::storage::client_db::get_bilateral_session(&commitment)
                .expect("read the session")
                .is_none(),
            "{what}: B holds a session"
        );
    }

    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the honest proposal");
    assert!(answer.is_empty(), "the honest proposal waits for the user");
    let response = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("B's user accepts");
    a.device.enter();
    let (confirm, _meta) = a
        .handler
        .handle_prepare_response(&response)
        .await
        .expect("A confirms");

    let foreign = under_a_foreign_ek(&confirm_receipt(&confirm), &commitment, &mallory);
    b.device.enter();
    let refused = b
        .handler
        .handle_confirm_request(&with_signed_receipt(&confirm, &foreign))
        .await
        .expect_err("a receipt under a foreign EK");
    assert!(
        refused.to_string().contains("does NOT chain"),
        "a receipt under a foreign EK: {refused}"
    );
    assert!(
        !history_row_exists(&commitment),
        "B kept the forged confirm"
    );
    assert_eq!(
        pending_era(),
        0,
        "B holds a payment from the forged confirm"
    );

    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the honest confirm commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A receipt its sender signs over roots the step's writes do not produce is
/// refused before anything commits: a child root one bit off, and a write's
/// path with one sibling changed, each signed again by the sender's own
/// per-step EK, so the signature holds and the state does not. So is a receipt
/// whose offline account advances to a frontier the step's release did not
/// sign. The honest confirm then commits.
/// (Moved from the validation harness: adversarial_bilateral's
/// `forged_post_state`, §6.103; the offline-account case is added, since the
/// harness's steps wrote no account.)
/// MUTATION CONTROL: dropping the comparison of the receipt's offline account
/// with the release's leaves in Core's `decide_confirm` turns the last case
/// red: the forgery is then refused by the fold instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_signed_receipt_whose_roots_its_writes_do_not_produce_is_refused() {
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;
    let honest = confirm_receipt(&confirm);

    let mut forged = honest.clone();
    forged.child_root[0] ^= 0x01;
    let forged = resigned_by(&a, &b, &forged, &commitment);
    let mut bent = honest.clone();
    let siblings = &mut bent.step_writes[0].path.siblings;
    assert!(
        !siblings.is_empty(),
        "the write's path carries no sibling to bend"
    );
    siblings[0] ^= 0x01;
    let bent = resigned_by(&a, &b, &bent, &commitment);
    let mut unreleased = honest.clone();
    let witness = unreleased
        .step_writes
        .iter_mut()
        .find_map(|write| match &mut write.leaf {
            dsm::types::receipt_types::ReceiptLeaf::OfflineAccount(witness) => Some(witness),
            dsm::types::receipt_types::ReceiptLeaf::Relationship => None,
        })
        .expect("a bearer step writes its offline account");
    witness.next_frontier[0] ^= 0x01;
    let unreleased = resigned_by(&a, &b, &unreleased, &commitment);

    b.device.enter();
    for (receipt, what, why) in [
        (
            forged,
            "a signed receipt over a forged post-state root",
            "do not fold from its parent root to its child root",
        ),
        // A bearer step writes two leaves; one bent sibling makes their paths
        // disagree, which the batch fold refuses before it reaches a root.
        (
            bent,
            "a signed receipt over a bent path",
            "the receipt's writes: ",
        ),
        (
            unreleased,
            "a signed receipt whose offline account its release did not advance",
            "is not the one its release advances",
        ),
    ] {
        let refused = b
            .handler
            .handle_confirm_request(&with_signed_receipt(&confirm, &receipt))
            .await
            .expect_err(what);
        assert!(refused.to_string().contains(why), "{what}: {refused}");
        assert!(!history_row_exists(&commitment), "{what}: B kept the step");
        assert_eq!(pending_era(), 0, "{what}: B holds a payment");
    }
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the honest confirm commits");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A genuine step on a tip its receiver does not hold is refused as stale: B
/// restored from a backup taken before the relationship's first step holds
/// the tip as it stood then, and A's second step — taken by B at its own tip —
/// is refused by the restored B, whose tip does not move.
/// (Moved from the validation harness: adversarial_bilateral's
/// `receiver_behind`, §6.103.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_genuine_step_on_a_tip_a_restored_receiver_does_not_hold_is_refused_as_stale() {
    let (pair, a, b, _appliance, payment) = bearer_pair().await;
    let mut restored = b.device.backed_up_into("B-restored");
    let behind = b.tip_with(&a);

    offline_step(&a, &b, payment.clone()).await;
    a.device.enter();
    let (second, second_commitment) = a.propose(&b, payment).await.expect("A's second step");
    deliver_and_commit(&a, &b, &second, second_commitment).await;

    restored.boot(&pair.fleet).await;
    let restored = OfflineDevice::new(&restored);
    assert_eq!(
        restored.tip_with(&a),
        behind,
        "the restored B does not hold the tip from before the first step"
    );
    restored.device.enter();
    let (answer, _meta) = restored
        .handler
        .handle_prepare_request(&second, None)
        .await
        .expect("the restored B answers");
    refused_as_stale(&answer, "a step on a tip the receiver does not hold");
    assert_eq!(
        restored.tip_with(&a),
        behind,
        "the refused step moved the restored B's tip"
    );
    assert!(
        crate::storage::client_db::get_bilateral_session(&second_commitment)
            .expect("read the session")
            .is_none(),
        "the restored B holds a session for the step"
    );
}

/// The validation harness's seed for its properties, and the iterations CI
/// ran them for (`property-tests --iterations 5 --seed 42`).
const FORK_EXCLUSION_SEED: u64 = 42;
const FORK_EXCLUSION_ITERATIONS: u64 = 5;

/// Of two children of one tip, the receiver takes one: over seeded rounds, A
/// signs two bearer payments of different amounts on the tip it holds with B;
/// the first commits on both devices and the second, delivered after, is
/// refused as stale. The amounts are drawn from the harness's ChaCha20 stream
/// under its seed, each round's pair funded by A's load.
/// (Moved from the validation harness: property_tests' `fork_exclusion`,
/// §6.103.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn of_two_children_of_one_tip_the_receiver_takes_one() {
    use rand::{Rng, SeedableRng};
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(FORK_EXCLUSION_SEED ^ 0x464f_524b);

    for round in 0..FORK_EXCLUSION_ITERATIONS {
        // The harness's mark: the first byte of an eight-byte draw, even. Its
        // pair of amounts is the mark and the next unit, kept above zero.
        let draw: Vec<u8> = (0..8).map(|_| rng.random()).collect();
        let first_amount = u64::from(draw[0] & 0xFE) + 2;
        let tip = b.tip_with(&a);

        a.device.enter();
        let (second, second_commitment) = a
            .propose(&b, bearer_transfer(&b, first_amount + 1))
            .await
            .expect("the second child");
        a.handler
            .cancel_proposal(second_commitment, "held back".to_string())
            .await
            .expect("A ends the held-back child");
        let (first, first_commitment) = a
            .propose(&b, bearer_transfer(&b, first_amount))
            .await
            .expect("the first child");
        assert_ne!(
            first_commitment, second_commitment,
            "round {round}: two different operations on one tip are one step"
        );

        deliver_and_commit(&a, &b, &first, first_commitment).await;
        assert_ne!(b.tip_with(&a), tip, "round {round}: the tip did not move");

        b.device.enter();
        let (answer, _meta) = b
            .handler
            .handle_prepare_request(&second, None)
            .await
            .expect("the second child is answered");
        refused_as_stale(&answer, &format!("round {round}: the second child"));
        assert!(
            !history_row_exists(&second_commitment),
            "round {round}: FORK: B kept a second child of one tip"
        );
    }
}

/// The receiver holds one successor of its tip and nothing moves it after: A's
/// step commits and both devices hold its successor; the step delivered again
/// is answered with nothing (a device never signs a rejection of a step it
/// committed) and commits nothing more; a second child of the committed
/// step's tip is refused as stale; and a later step's confirm, whose receipt
/// its sender signs over a write path with one sibling changed, is refused —
/// none of them moves B's tip.
/// (Moved from the validation harness: implementation_traces'
/// `receiver_tripwire`, formerly a linked trace of the Tripwire model, §6.103.
/// The harness's replay was refused by Core as a stale tip; production answers
/// a committed step's prepare before Core decides it.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_holds_one_successor_and_refuses_a_sibling_and_a_bent_receipt() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;

    a.device.enter();
    let (sibling, sibling_commitment) = a
        .propose(&b, marked(&b, 0xB1))
        .await
        .expect("the step's sibling");
    a.handler
        .cancel_proposal(sibling_commitment, "held back".to_string())
        .await
        .expect("A ends the held-back sibling");
    let (step, commitment) = a.propose(&b, marked(&b, 0xA1)).await.expect("the step");
    deliver_and_commit(&a, &b, &step, commitment).await;
    let successor = b.tip_with(&a);
    assert_eq!(
        a.tip_with(&b),
        successor,
        "the two devices do not hold the committed successor"
    );

    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&step, None)
        .await
        .expect("its replay is answered");
    assert!(
        answer.is_empty(),
        "B refused a step it committed ({} bytes)",
        answer.len()
    );
    assert_eq!(history_rows(&commitment), 1, "the replay committed again");
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&sibling, None)
        .await
        .expect("a second child of the tip is answered");
    refused_as_stale(&answer, "a second child of the tip");

    let (later, confirm) = to_the_confirm(&a, &b, marked(&b, 0xC1)).await;
    let mut bent = confirm_receipt(&confirm);
    bent.step_writes[0].path.siblings[0] ^= 0x01;
    let bent = resigned_by(&a, &b, &bent, &later);
    b.device.enter();
    let refused = b
        .handler
        .handle_confirm_request(&with_signed_receipt(&confirm, &bent))
        .await
        .expect_err("a signed receipt over a bent path");
    // A bearer step writes two leaves; one bent sibling makes their paths
    // disagree, which the batch fold refuses before it reaches a root.
    assert!(
        refused.to_string().contains("the receipt's writes: "),
        "a signed receipt over a bent path: {refused}"
    );
    assert_eq!(b.tip_with(&a), successor, "a refused step moved B's tip");
}

/// First contact binds the relationship's `h_0`: both devices hold one `h_0`,
/// and a first step and an alternate first step both extend it. The first
/// commits; the next step extends the first's successor and commits; the
/// alternate first-contact branch, delivered after, is refused as stale, and B
/// holds the extension's successor.
/// (Moved from the validation harness: implementation_traces'
/// `tripwire_first_contact_binding`, formerly a linked trace of the Tripwire
/// model, §6.103.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_first_contact_step_extends_h_0_and_an_alternate_first_step_is_refused_after_it() {
    let (_pair, a, b, _appliance, _payment) = bearer_pair().await;
    let h0 = b.tip_with(&a);
    assert_eq!(a.tip_with(&b), h0, "the two devices do not hold one h_0");
    let tip_claimed = |prepare: &[u8]| {
        prepare_request(prepare)
            .expected_counterparty_state_hash
            .map(|h| h.v)
    };

    a.device.enter();
    let (alternate, alternate_commitment) = a
        .propose(&b, marked(&b, 0x52))
        .await
        .expect("the alternate first step");
    a.handler
        .cancel_proposal(alternate_commitment, "held back".to_string())
        .await
        .expect("A ends the alternate");
    let (first, first_commitment) = a
        .propose(&b, marked(&b, 0x51))
        .await
        .expect("the first step");
    assert_eq!(
        (tip_claimed(&first), tip_claimed(&alternate)),
        (Some(h0.to_vec()), Some(h0.to_vec())),
        "a first step does not extend the relationship's h_0"
    );
    deliver_and_commit(&a, &b, &first, first_commitment).await;
    let first_successor = b.tip_with(&a);

    a.device.enter();
    let (extension, extension_commitment) = a
        .propose(&b, marked(&b, 0x53))
        .await
        .expect("the extension");
    assert_eq!(
        tip_claimed(&extension),
        Some(first_successor.to_vec()),
        "the extension does not extend the first step's successor"
    );
    deliver_and_commit(&a, &b, &extension, extension_commitment).await;
    let extension_successor = b.tip_with(&a);

    b.device.enter();
    let (answer, _meta) = b
        .handler
        .handle_prepare_request(&alternate, None)
        .await
        .expect("the alternate first-contact branch is answered");
    refused_as_stale(&answer, "an alternate first-contact branch");
    assert_eq!(
        b.tip_with(&a),
        extension_successor,
        "the receiver does not hold the extension's successor"
    );
}
