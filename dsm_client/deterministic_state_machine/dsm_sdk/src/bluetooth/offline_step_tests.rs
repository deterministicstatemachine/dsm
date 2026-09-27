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

/// An offline step of `operation` from `sender` to `receiver` up to the
/// receiver's commit, every frame carried as bytes: prepare → accept →
/// confirm, which the receiver commits. Returns the commitment and the ack the
/// receiver answers with.
async fn to_the_ack(
    sender: &OfflineDevice,
    receiver: &OfflineDevice,
    operation: Operation,
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
    (commitment, confirm)
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

    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, _commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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
    let pair = Pair::boot(0, 0).await;
    let mut c_device = TestDevice::create("C", 0x0C);
    c_device.boot(&pair.fleet).await;
    c_device.add_contact(&pair.a).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let c = OfflineDevice::new(&c_device);
    let c_tip_before = c.tip_with(&a);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
        .await
        .expect("A prepares for B");

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
        )
        .expect("read the history"),
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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

/// A sender that restarts after its confirm went out holds its step again —
/// its precommitment, checked against the commitment, and every commit input
/// were durable before the confirm — and commits when the ack arrives.
/// MUTATION CONTROL: not holding the precommitment again on restart turns
/// this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_restarted_after_its_confirm_commits_on_the_ack() {
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (commitment, ack) = to_the_ack(&a, &b, Operation::Noop).await;
    let a = a.restarted().await;
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("the restarted sender commits");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A sender that restarts holding a verified ack it had not yet committed
/// commits the step on restart, through the one commit path (the ack is
/// verified again first).
/// MUTATION CONTROL: not finalizing a held ack on restart turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sender_restarted_holding_its_ack_commits_on_restart() {
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (commitment, ack) = to_the_ack(&a, &b, Operation::Noop).await;
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
    assert!(
        !history_row_exists(&commitment),
        "recorded is not committed"
    );

    let a = a.restarted().await;
    assert_committed_on_both(&a, &b, &commitment);
}

/// A persisted sender step whose parent tip and operation do not hash to its
/// commitment is not taken up again on restart: it fails, the relationship
/// is held for online reconcile (the receiver may have committed), and an ack
/// arriving for it commits nothing.
/// MUTATION CONTROL: holding the precommitment without checking it against
/// the commitment turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_restored_step_that_does_not_hash_to_its_commitment_commits_nothing() {
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let h_0 = a.tip_with(&b);

    let (commitment, ack) = to_the_ack(&a, &b, Operation::Noop).await;
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
    assert!(
        crate::storage::client_db::get_contact_by_device_id(&b.device.device_id)
            .expect("read the contact")
            .expect("B is a contact")
            .needs_online_reconcile,
        "the relationship is not held for online reconcile"
    );
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect_err("an ack for a step not taken up commits nothing");
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

/// The request a confirm carries.
fn confirm_request(confirm: &[u8]) -> crate::generated::BilateralConfirmRequest {
    use prost::Message;
    let envelope = crate::envelope::from_canonical_bytes(confirm).expect("the confirm decodes");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload else {
        panic!("a confirm is a universal transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = &tx.ops[0].kind else {
        panic!("a confirm invokes bilateral.confirm");
    };
    let args = invoke.args.as_ref().expect("the confirm's arguments");
    crate::generated::BilateralConfirmRequest::decode(args.body.as_slice()).expect("decodes")
}

/// The stitched receipt a confirm carries.
fn confirm_receipt(confirm: &[u8]) -> dsm::types::receipt_types::StitchedReceiptV2 {
    dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &confirm_request(confirm).stitched_receipt,
    )
    .expect("the confirm's receipt decodes")
}

/// A bearer pair: A funded and its offline allocation of 20 ERA loaded under
/// its anchor — the real anchor-core appliance on a software chip, whose
/// seed is the appliance's only typed-in value — and the transfer of 7 ERA
/// from it to B.
async fn bearer_pair() -> (
    Pair,
    OfflineDevice,
    OfflineDevice,
    crate::test_support::appliance::HostAppliance,
    Operation,
) {
    let pair = Pair::boot(100, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let appliance = crate::test_support::appliance::HostAppliance::birth(&pair.a, [0xC4; 32], 16);
    appliance.install();
    a.device.enter();
    let loaded = a
        .device
        .invoke(
            "wallet.loadOffline",
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: 20,
            },
        )
        .await;
    assert!(loaded.success, "the load: {:?}", loaded.error_message);
    let operation = Operation::from_bytes(
        &crate::handlers::wallet_routes::encode_offline_transfer_operation_canonical(
            &b.device.device_id,
            7,
            "ERA",
            "",
            &dsm::core::token::token_state_manager::era_policy_commit(),
        ),
    )
    .expect("the bearer transfer");
    (pair, a, b, appliance, operation)
}

/// A bearer step between two devices, every frame carried as bytes, the
/// sender's anchor the real anchor-core appliance on a software chip. A loads
/// an offline allocation from its admitted ERA under that anchor and spends
/// from it to B. A's receipt proves the three leaves the spend writes — its
/// relationship tip, its anchor-state leaf and its allocation — and it is built
/// and checked before the appliance commits a counter step; B derives the
/// anchor leaves from the release, pins A's anchor and commits; A commits on
/// B's acknowledgment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_step_proves_its_whole_write_set_and_commits_on_both() {
    use dsm::types::receipt_types::ReceiptLeaf;

    let (_pair, a, b, _appliance, operation) = bearer_pair().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, operation).await;

    let receipt = confirm_receipt(&confirm);
    let kinds: Vec<ReceiptLeaf> = receipt.step_writes.iter().map(|w| w.leaf).collect();
    assert_eq!(kinds.len(), 3, "the spend writes three leaves: {kinds:?}");
    assert!(kinds.contains(&ReceiptLeaf::Relationship), "{kinds:?}");
    assert!(kinds.contains(&ReceiptLeaf::AnchorState), "{kinds:?}");
    assert!(
        kinds.contains(&ReceiptLeaf::OfflineAllocation {
            pre_amount: 20,
            pre_sequence: 1,
        }),
        "the allocation's pre-state is the load: {kinds:?}"
    );

    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("B commits and acknowledges");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A takes the acknowledgment and commits");
    assert_committed_on_both(&a, &b, &commitment);
    b.device.enter();
    assert_eq!(b.device.era_balance(), 7, "B holds the spend");
}

/// The bearer arm of the receipt's state rules, on a real spend. A's receipt,
/// judged as B judges it — under A's pinned genesis and Device Tree, the
/// operation, and the anchor leaves B derives from the release under its own
/// challenge — holds. Each forgery is refused for its own rule: the forger
/// holds A's keys and recomputes the child root over what it keeps, so only
/// the named rule stands.
///
/// MUTATION CONTROLS (run 2026-09-27): deleting the write-count check (with it
/// gone, the receipt that omits the allocation's debit is accepted), the
/// refusal of an allocation smaller than the spend, the refusal of anchor
/// leaves that do not move, the key-order check, the refusal of a bearer spend
/// judged without its anchor leaves, or `bearer_leaves_of_release`'s successor
/// check each turns its named assertion red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_receipt_holds_only_for_the_write_set_its_spend_makes() {
    use dsm::core::bilateral_transaction_manager::{anchor_state_leaf_key, compute_smt_key};
    use dsm::merkle::batch_fold::{verify_batch, FoldEntry};
    use dsm::merkle::sparse_merkle_tree::DeviceSmtHashes;
    use dsm::types::offline_allocation_leaf::{offline_allocation_key, offline_allocation_value};
    use dsm::types::receipt_types::{DeviceTreeAcceptanceCommitment, ReceiptLeaf, StitchedReceiptV2};
    use dsm::verification::receipt_verification::{
        verify_receipt_state, BearerLeaves, ReceiptStateContext,
    };

    let (_pair, a, b, _appliance, operation) = bearer_pair().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, operation.clone()).await;
    let request = confirm_request(&confirm);
    let receipt = confirm_receipt(&confirm);

    b.device.enter();
    let challenge: [u8; 32] = crate::storage::client_db::get_bilateral_session(&commitment)
        .expect("read B's session")
        .expect("B's session")
        .receiver_challenge
        .expect("B's challenge")
        .try_into()
        .expect("32 bytes");
    let bundle: [u8; 32] = request
        .anchor_disclosure
        .as_ref()
        .expect("the confirm discloses A's anchor")
        .bundle
        .as_slice()
        .try_into()
        .expect("32 bytes");
    let leaves = crate::bluetooth::anchor_accept::bearer_leaves_of_release(
        &request.offline_release,
        &bundle,
        &challenge,
    )
    .expect("the leaves B derives from the release");
    // A release whose carried successor is not the one B derives names no
    // leaves: the counter's successor, or the frontier's.
    {
        use prost::Message;
        let bent = |bend: &dyn Fn(&mut anchor_core::proto::pb::TransitionPackage)| {
            let mut release =
                anchor_core::proto::pb::OfflineRelease::decode(request.offline_release.as_slice())
                    .expect("the release decodes");
            bend(
                release
                    .transition
                    .as_mut()
                    .expect("the release's transition"),
            );
            release.encode_to_vec()
        };
        for (why, release) in [
            ("a counter successor", bent(&|t| t.next_anchor_counter += 1)),
            (
                "a frontier successor",
                bent(&|t| t.next_root = leaves.anchor_before.to_vec()),
            ),
        ] {
            assert!(
                crate::bluetooth::anchor_accept::bearer_leaves_of_release(
                    &release, &bundle, &challenge
                )
                .is_err(),
                "a release carrying {why} it does not derive"
            );
        }
        let mut another_challenge = challenge;
        another_challenge[0] ^= 1;
        assert!(
            crate::bluetooth::anchor_accept::bearer_leaves_of_release(
                &request.offline_release,
                &bundle,
                &another_challenge,
            )
            .is_err(),
            "the release under another challenge"
        );
    }
    let tree = DeviceTreeAcceptanceCommitment::from_root(
        dsm::common::device_tree::DeviceTree::single(a.device.device_id).root(),
    );
    let context = ReceiptStateContext {
        device_tree_commitment: &tree,
        author_genesis: a.device.genesis,
        operation: &operation,
        bearer: Some(leaves),
    };
    verify_receipt_state(&receipt, &context).expect("the honest bearer receipt holds");

    let refusal = |r: &StitchedReceiptV2, context: &ReceiptStateContext<'_>| {
        verify_receipt_state(r, context)
            .expect_err("a forged receipt is refused")
            .to_string()
    };
    let refused_for = |why: &str, r: &StitchedReceiptV2, context: &ReceiptStateContext<'_>| {
        let reason = refusal(r, context);
        assert!(reason.contains(why), "refused for another reason: {reason}");
    };

    // The forger's fold: the writes it keeps, each with the values the rules
    // derive, folded from the receipt's parent root.
    let (amount, asset) = match &operation {
        Operation::Transfer {
            amount,
            policy_commit,
            ..
        } => (amount.value(), *policy_commit),
        _ => unreachable!("a bearer transfer"),
    };
    let refold = |r: &mut StitchedReceiptV2| {
        let mut entries: Vec<FoldEntry> = r
            .step_writes
            .iter()
            .map(|w| {
                let (key, pre, post) = match w.leaf {
                    ReceiptLeaf::Relationship => (
                        compute_smt_key(&r.devid_a, &r.devid_b),
                        r.parent_tip,
                        r.child_tip,
                    ),
                    ReceiptLeaf::AnchorState => (
                        anchor_state_leaf_key(&bundle),
                        leaves.anchor_before,
                        leaves.anchor_after,
                    ),
                    ReceiptLeaf::OfflineAllocation {
                        pre_amount,
                        pre_sequence,
                    } => (
                        offline_allocation_key(&r.genesis, &r.devid_a, &bundle, &asset),
                        offline_allocation_value(pre_amount, pre_sequence),
                        offline_allocation_value(pre_amount - amount, pre_sequence + 1),
                    ),
                };
                FoldEntry {
                    key,
                    pre: Some(pre),
                    post: Some(post),
                    path: dsm::merkle::smt_path::decode::<DeviceSmtHashes>(
                        &w.path.explicit_heights,
                        &w.path.siblings,
                    )
                    .expect("the path decodes"),
                }
            })
            .collect();
        entries.sort_by_key(|e| e.key);
        r.child_root = verify_batch::<DeviceSmtHashes>(&r.parent_root, &entries)
            .expect("the kept writes fold from the parent root");
    };
    let without = |leaf: fn(&ReceiptLeaf) -> bool| {
        let mut r = receipt.clone();
        r.step_writes.retain(|w| !leaf(&w.leaf));
        refold(&mut r);
        r
    };

    refused_for(
        "the step writes 3 leaves; the receipt proves 2",
        &without(|l| matches!(l, ReceiptLeaf::OfflineAllocation { .. })),
        &context,
    );
    refused_for(
        "the step writes 3 leaves; the receipt proves 2",
        &without(|l| matches!(l, ReceiptLeaf::AnchorState)),
        &context,
    );

    let mut understated = receipt.clone();
    for w in understated.step_writes.iter_mut() {
        if let ReceiptLeaf::OfflineAllocation { pre_sequence, .. } = w.leaf {
            w.leaf = ReceiptLeaf::OfflineAllocation {
                pre_amount: amount - 1,
                pre_sequence,
            };
        }
    }
    refused_for(
        "holds less than the operation spends",
        &understated,
        &context,
    );

    let mut reordered = receipt.clone();
    reordered.step_writes.reverse();
    refused_for("not in the order of their keys", &reordered, &context);

    let mut doubled = receipt.clone();
    let again = doubled.step_writes[0].clone();
    doubled.step_writes.push(again);
    refused_for(
        "the step writes 3 leaves; the receipt proves 4",
        &doubled,
        &context,
    );

    refused_for(
        "moves its anchor-state leaf",
        &receipt,
        &ReceiptStateContext {
            bearer: Some(BearerLeaves {
                anchor_after: leaves.anchor_before,
                ..leaves
            }),
            ..context
        },
    );
    refused_for(
        "is verified against its anchor-state leaves",
        &receipt,
        &ReceiptStateContext {
            bearer: None,
            ..context
        },
    );
    for (why, other) in [
        (
            "an anchor pre-state that is not the release's",
            BearerLeaves {
                anchor_before: leaves.anchor_after,
                anchor_after: leaves.anchor_before,
                ..leaves
            },
        ),
        (
            "another bundle",
            BearerLeaves {
                bundle: a.device.genesis,
                ..leaves
            },
        ),
    ] {
        assert!(
            verify_receipt_state(
                &receipt,
                &ReceiptStateContext {
                    bearer: Some(other),
                    ..context
                }
            )
            .is_err(),
            "{why}"
        );
    }
}

/// A bearer confirm whose receipt does not hold spends no counter step: the
/// sender checks its receipt before the appliance's COMMIT, so a refused
/// receipt leaves the chip's counter and frontier where they were. Here A's
/// Device Tree commitment is not the one its receipt's device proof is under.
/// MUTATION CONTROL: building the receipt after the release (the order this
/// replaced) moves the counter and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_bearer_receipt_that_does_not_hold_spends_no_counter_step() {
    use crate::anchor::AnchorAppliance;

    let (_pair, a, b, appliance, operation) = bearer_pair().await;
    let before = appliance.clone().status().expect("the chip's status");

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, operation)
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
    crate::sdk::app_state::AppState::set_device_tree_root(
        dsm::common::device_tree::DeviceTree::single(b.device.device_id).root(),
    )
    .expect("set A's Device Tree root");
    a.handler
        .handle_prepare_response(&response)
        .await
        .expect_err("a receipt that does not hold is not confirmed");

    let after = appliance.clone().status().expect("the chip's status");
    assert_eq!(
        after.anchor_counter, before.anchor_counter,
        "no counter step was spent"
    );
    assert_eq!(after.root, before.root, "the frontier did not move");
}

/// The history rows the entered device holds for the step.
fn history_rows(commitment: &[u8; 32]) -> usize {
    let tx_id = crate::util::text_id::encode_base32_crockford(commitment);
    crate::storage::client_db::get_transaction_history(None, Some(1000))
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (commitment, _lost_ack) = to_the_ack(&a, &b, Operation::Noop).await;
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
        .expect("the sender commits on the ack answered again");
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (_commitment, _lost_ack) = to_the_ack(&a, &b, Operation::Noop).await;
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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
async fn to_a_lost_response(a: &OfflineDevice, b: &OfflineDevice) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let h_0 = a.tip_with(&b);

    let (commitment, _prepare, _lost_response) = to_a_lost_response(&a, &b).await;
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
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (commitment, _prepare, _lost_response) = to_a_lost_response(&a, &b).await;
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    let (commitment, _ack) = to_the_ack(&a, &b, Operation::Noop).await;
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
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

/// An operation of its own for a step: two steps on one tip are two steps
/// only if their operations differ.
fn marked(mark: u8) -> Operation {
    Operation::Generic {
        operation_type: b"offline-step-test".to_vec(),
        data: vec![mark],
        message: String::new(),
        signature: Vec::new(),
    }
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let tip = a.tip_with(&b);

    a.device.enter();
    let (a_prepare, a_step) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, marked(1))
        .await
        .expect("A proposes");
    b.device.enter();
    let (b_prepare, b_step) = b
        .handler
        .prepare_bilateral_transaction(a.device.device_id, marked(2))
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

    let commitment = offline_step(&a, &b, marked(3)).await;
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
        .await
        .expect("A proposes");
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let a_again = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    a.handler
        .prepare_bilateral_transaction(b.device.device_id, marked(1))
        .await
        .expect("A proposes through one handler");
    a_again.device.enter();
    let refused = a_again
        .handler
        .prepare_bilateral_transaction(b.device.device_id, marked(2))
        .await
        .expect_err("the step in flight blocks the next through another handler");
    assert!(
        refused.to_string().contains("in progress"),
        "unexpected refusal: {refused}"
    );

    b.device.enter();
    let (b_prepare, _b_step) = b
        .handler
        .prepare_bilateral_transaction(a.device.device_id, marked(3))
        .await
        .expect("B proposes");
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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, commitment) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, Operation::Noop)
        .await
        .expect("A proposes");
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
    let pair = Pair::boot(1_000, 1_000).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let (prepare, step) = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, marked(1))
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
    assert_eq!(pair.a.era_balance(), 1_000, "a refused send debited");

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
    assert_eq!(pair.b.era_balance(), 1_000, "a refused send debited");

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
    let pair = Pair::boot(0, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);

    a.device.enter();
    let reservation = crate::security::modal_sync_lock::PendingOnlineGuard::acquire(
        &dsm::core::bilateral_transaction_manager::compute_smt_key(
            &a.device.device_id,
            &b.device.device_id,
        ),
    )
    .expect("the online send's reservation");
    let refused = a
        .handler
        .prepare_bilateral_transaction(b.device.device_id, marked(1))
        .await
        .expect_err("an online send is in progress");
    assert!(
        refused.to_string().contains("online send"),
        "unexpected refusal: {refused}"
    );
    drop(reservation);
    a.handler
        .prepare_bilateral_transaction(b.device.device_id, marked(1))
        .await
        .expect("A proposes once the online send is done");
}
