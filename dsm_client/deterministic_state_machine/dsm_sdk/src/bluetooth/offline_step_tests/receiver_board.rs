// SPDX-License-Identifier: MIT OR Apache-2.0

//! The receiver's board (owner, 2026-11-07: "you have to have the board, man, for it to work
//! offline. You can't receive either."). Each test here drives the production receive: B's board
//! draws the challenge at B's acceptance, checks A's release itself and commits the receive, and its
//! certificate is the acknowledgement A checks. A phone without a board receives nothing; a power
//! cut on B's board at each of its record writes, a restart, a finalize that did not land, and a
//! forged acknowledgement each end with the payment received once or not at all.

use super::*;
use crate::anchor::{AnchorAppliance, ApplianceStatus};
use crate::economic_fixtures::whole_era;
use crate::test_support::appliance::{Cut, HostAppliance, Power};

/// Where `board` stands.
fn board(board: &HostAppliance) -> ApplianceStatus {
    board.clone().status().expect("the board's status")
}

/// The entered device's offline account under `board`'s bundle, in its current head.
fn account_of(
    device: &OfflineDevice,
    board: &HostAppliance,
) -> dsm::types::offline_account::OfflineAccount {
    device
        .device
        .router()
        .core_sdk
        .device_head()
        .expect("the device's head")
        .offline_account(&board.pin().bundle)
        .expect("the device's offline account under its board")
        .clone()
}

/// B holds `amount` base units of ERA received offline, once: in what its offline account holds
/// received and in the payments it holds waiting for their unload, its board's counter `receives`
/// steps from `before`, its challenge used up and its frontier where its account stands.
fn received(
    b: &OfflineDevice,
    receiver: &HostAppliance,
    before: &ApplianceStatus,
    amount: u64,
    receives: u64,
) {
    b.device.enter();
    assert_eq!(
        pending_era(),
        amount,
        "B holds what it received, waiting for its unload"
    );
    let after = board(receiver);
    assert_eq!(
        after.anchor_counter,
        before.anchor_counter + receives,
        "B's board moved its counter once for each receive"
    );
    assert_eq!(
        after.open_challenge, None,
        "the receive used B's challenge up"
    );
    let era = crate::policy::resolve_policy_commit_strict(b"ERA").expect("ERA");
    let account = account_of(b, receiver);
    assert_eq!(
        account.received(&era),
        Some(amount),
        "B's account holds it received"
    );
    assert_eq!(
        (account.counter(), account.frontier()),
        (after.anchor_counter, after.root),
        "B's account stands where its board does"
    );
}

/// A phone with no board of its own cannot receive offline: B's user accepts A's payment and the
/// acceptance is refused with the plain reason, before any response leaves. B's proposal waits for
/// its user as it did, A's anchor is untouched, and B holds nothing.
/// MUTATION CONTROL: the receiver's challenge drawn from the phone instead of its board (the
/// receive before 2026-11-07) lets B accept and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_phone_with_no_board_of_its_own_cannot_receive_offline() {
    let pair = Pair::boot(100, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let payer = HostAppliance::birth(&pair.a, [0xC4; 32], 16);
    let _boards = HostAppliance::install_each(vec![(pair.a.device_id, payer.clone())]);
    a.device.enter();
    let loaded = offline_cash(&a, "wallet.loadOffline", "20.00").await;
    assert!(loaded.success, "the load: {:?}", loaded.error_message);
    pair.b.sync().await;
    let before = board(&payer);

    a.device.enter();
    let (prepare, commitment) = a
        .propose(&b, bearer_transfer(&b, 7))
        .await
        .expect("A proposes the payment");
    b.device.enter();
    b.handler
        .handle_prepare_request(&prepare, None)
        .await
        .expect("B takes the proposal");
    let refused = b
        .handler
        .create_prepare_accept_envelope(commitment)
        .await
        .expect_err("B, with no board, accepts an offline payment");
    assert!(
        refused
            .to_string()
            .contains(crate::sdk::core_sdk::OFFLINE_RECEIVE_NO_BOARD_MSG),
        "{refused}"
    );
    assert_eq!(
        stored_phase(&commitment),
        "pending_user_action",
        "the proposal waits for B's user as it did"
    );
    assert_eq!(pending_era(), 0, "B holds nothing");
    assert_eq!(board(&payer), before, "A's anchor is untouched");
}

/// A power cut on B's board as its prepared receive is written: the receive does not commit, and B
/// has recorded it as receiving, its receipt signed before the board moved. At boot the board resets
/// the prepared receive and keeps its challenge open. A's confirm delivered again drives the same
/// receive again: B receives once, and A files B's board's acknowledgement.
/// MUTATION CONTROL: the failed receive left in memory as accepted (its record not taken back) signs
/// a second receipt on the confirm delivered again, which its record refuses: red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receive_cut_while_prepared_on_the_receivers_board_is_driven_again_and_received_once() {
    let (_pair, a, b, appliance, payment) = bearer_pair().await;
    let before = board(&appliance.receiver);
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;
    let challenge = board(&appliance.receiver)
        .open_challenge
        .expect("B's board holds the challenge its acceptance drew");

    b.device.enter();
    // B's board's record writes from here: 1 the prepared receive, 2 the committed candidate, 3 the
    // counter moved, 4 the advanced frontier. Its recovery writes nothing where nothing changes.
    appliance.receiver.cut(Cut::AfterWrite(1));
    b.handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("the receive cannot commit without power");
    assert_eq!(appliance.receiver.power(), Power::Off);
    assert_eq!(
        stored_phase(&commitment),
        "receiving",
        "B recorded the receive before its board moved"
    );
    assert_eq!(pending_era(), 0, "nothing is received");

    appliance.receiver.reboot();
    let rebooted = board(&appliance.receiver);
    assert_eq!(
        rebooted.anchor_counter, before.anchor_counter,
        "the counter never moved"
    );
    assert_eq!(
        rebooted.open_challenge,
        Some(challenge),
        "the prepared receive is reset at boot and its challenge stays open"
    );
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the confirm delivered again drives the receive again");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files B's board's acknowledgement");
    assert_committed_on_both(&a, &b, &commitment);
    received(&b, &appliance.receiver, &before, 7, 1);
}

/// A power cut on B's board after its committed candidate is written and before its counter moves.
/// At boot the board completes the commit from its record: the counter moves once. B restarts; its
/// step is receiving, and A's confirm delivered again takes up the receive the board completed —
/// emitted again, never a second one — and B's phone commits it.
/// MUTATION CONTROL: the receiving step driven again rather than settled by the board's report would
/// stage a second receive the board refuses (no challenge is open after the completed commit): red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receive_cut_after_its_candidate_is_completed_at_boot_and_the_restarted_receiver_commits_it(
) {
    let (_pair, a, b, appliance, payment) = bearer_pair().await;
    let before = board(&appliance.receiver);
    let h_before = appliance.receiver.chip_counter();
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;

    b.device.enter();
    appliance.receiver.cut(Cut::AfterWrite(2));
    b.handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("the commit cannot finish without power");
    assert_eq!(appliance.receiver.power(), Power::Off);
    assert_eq!(
        appliance.receiver.chip_counter(),
        h_before,
        "the counter has not moved"
    );

    appliance.receiver.reboot();
    assert_eq!(
        appliance.receiver.chip_counter(),
        h_before - 1,
        "boot recovery completed the receive's commit: the counter moved once"
    );
    let b = b.restarted().await;
    b.device.enter();
    assert_eq!(stored_phase(&commitment), "receiving");
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the restarted B commits the receive its board completed");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files B's board's acknowledgement");
    assert_committed_on_both(&a, &b, &commitment);
    assert_eq!(
        appliance.receiver.chip_counter(),
        h_before - 1,
        "the counter moved once in all"
    );
    received(&b, &appliance.receiver, &before, 7, 1);
}

/// A power cut on B's board as its counter-committed record is written, after the counter moved. At
/// boot the board marks the commit from its candidate without moving the counter again, and the
/// confirm delivered again commits the receive on B's phone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receive_cut_after_its_counter_moved_is_marked_at_boot_without_moving_it_again() {
    let (_pair, a, b, appliance, payment) = bearer_pair().await;
    let before = board(&appliance.receiver);
    let h_before = appliance.receiver.chip_counter();
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;

    b.device.enter();
    appliance.receiver.cut(Cut::AtWrite(3));
    b.handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("the counter-committed record did not land");
    assert_eq!(appliance.receiver.power(), Power::Off);
    assert_eq!(
        appliance.receiver.chip_counter(),
        h_before - 1,
        "the counter moved before the power went"
    );

    appliance.receiver.reboot();
    assert_eq!(
        appliance.receiver.chip_counter(),
        h_before - 1,
        "boot recovery marks the commit without moving the counter again"
    );
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("the confirm delivered again commits the receive");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files B's board's acknowledgement");
    assert_committed_on_both(&a, &b, &commitment);
    received(&b, &appliance.receiver, &before, 7, 1);
}

/// B's phone commits the receive and the power goes off as its board writes its advanced frontier.
/// The payment is received and its acknowledgement kept: A's confirm delivered again is answered
/// from B's committed step, and A files it. The board's frontier waits for its next use, which
/// finishes it first: B's next receive, of A's second payment, lands beside the first.
/// MUTATION CONTROL: the committed receive not finished at the board's next use
/// (`finalize_committed_receive` answering nothing) leaves the board holding it, and B's next
/// acceptance is refused: red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receive_whose_board_did_not_advance_is_answered_and_finished_at_the_boards_next_use() {
    let (_pair, a, b, appliance, payment) = bearer_pair().await;
    let before = board(&appliance.receiver);
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;

    b.device.enter();
    appliance.receiver.cut(Cut::AtWrite(4));
    let refused = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("the board's frontier did not advance");
    assert!(
        refused
            .to_string()
            .contains("the payment is received and its acknowledgement kept"),
        "{refused}"
    );
    assert!(history_row_exists(&commitment), "B's step committed");
    assert_eq!(pending_era(), 7, "B holds the payment");
    appliance.receiver.reboot();

    a.device.enter();
    let owed = a.handler.frames_owed_to(&b.device.device_id).await;
    assert_eq!(
        owed.len(),
        1,
        "A, holding no acknowledgement, owes its confirm"
    );
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&owed[0].bytes)
        .await
        .expect("B answers its committed step with the acknowledgement it kept");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files B's board's acknowledgement");
    assert_committed_on_both(&a, &b, &commitment);
    let held = board(&appliance.receiver);
    assert_eq!(held.anchor_counter, before.anchor_counter + 1);
    assert_eq!(
        held.root, before.root,
        "the board's frontier waits for its next use"
    );

    let second = bearer_payment_over_ble(&a, &b, &bearer_transfer(&b, 3)).await;
    assert_committed_on_both(&a, &b, &second);
    received(&b, &appliance.receiver, &before, 10, 2);
}

/// `ack` with the board's receive commit it carries replaced by `acknowledgement`. The envelope
/// carries no signature of its own: the acknowledgement's are its board's.
fn with_acknowledgement(ack: &[u8], acknowledgement: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    let mut envelope = crate::envelope::from_canonical_bytes(ack).expect("the ack decodes");
    let Some(crate::generated::envelope::Payload::BilateralCommitResponse(response)) =
        envelope.payload.as_mut()
    else {
        panic!("the ack is a commit response");
    };
    response.receive_acknowledgement = acknowledgement;
    envelope.encode_to_vec()
}

/// The receive commit `ack` carries.
fn acknowledgement_in(ack: &[u8]) -> Vec<u8> {
    match crate::envelope::from_canonical_bytes(ack)
        .expect("the ack decodes")
        .payload
    {
        Some(crate::generated::envelope::Payload::BilateralCommitResponse(response)) => {
            response.receive_acknowledgement
        }
        other => panic!("the ack is a commit response, not {other:?}"),
    }
}

/// The release the confirm `confirm` carries: A's own.
fn release_in(confirm: &[u8]) -> Vec<u8> {
    use prost::Message;
    let envelope = crate::envelope::from_canonical_bytes(confirm).expect("the confirm decodes");
    let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload else {
        panic!("a confirm is a universal transaction");
    };
    let Some(crate::generated::universal_op::Kind::Invoke(invoke)) = &tx.ops[0].kind else {
        panic!("a confirm invokes bilateral.confirm");
    };
    let args = invoke.args.as_ref().expect("the confirm's arguments");
    crate::generated::BilateralConfirmRequest::decode(args.body.as_slice())
        .expect("the confirm request")
        .offline_release
}

/// `acknowledgement` with one byte of its certificate's `signature` turned.
fn with_signature_turned(acknowledgement: &[u8], signature: &str) -> Vec<u8> {
    use prost::Message;
    let mut release = anchor_core::proto::pb::OfflineRelease::decode(acknowledgement)
        .expect("the acknowledgement decodes");
    let cert = release
        .cert
        .as_mut()
        .expect("the acknowledgement's certificate");
    let turned = match signature {
        "sigma_chip" => &mut cert.sigma_chip,
        "sigma_host" => &mut cert.sigma_host,
        other => panic!("a certificate signs with sigma_chip and sigma_host, not {other}"),
    };
    turned[0] ^= 0x01;
    release.encode_to_vec()
}

/// A takes B's acknowledgement only as B's board's receive commit of A's own release, under the
/// board A pinned from B's response: none at all, A's own release in its place, and a receive commit
/// whose chip or host signature does not verify are each refused, A's step stays confirm-pending
/// and keeps no acknowledgement. The honest one is filed.
/// MUTATION CONTROL: the payer not checking the acknowledgement (`decide_commit_ack` taking the
/// receipt alone) files the first forgery: red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_acknowledgement_that_is_not_the_receivers_board_commit_is_refused_and_the_payer_waits()
{
    let (_pair, a, b, _appliance, payment) = bearer_pair().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, payment).await;
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("B commits and acknowledges");
    let honest = acknowledgement_in(&ack);
    let forgeries = [
        (
            "no acknowledgement",
            Vec::new(),
            "carries no receive commit of the receiver's board",
        ),
        (
            "A's own release",
            release_in(&confirm),
            "is not the receiver's board's receive of this release",
        ),
        (
            "a chip signature that does not verify",
            with_signature_turned(&honest, "sigma_chip"),
            "is not the receiver's board's receive of this release",
        ),
        (
            "a host signature that does not verify",
            with_signature_turned(&honest, "sigma_host"),
            "is not the receiver's board's receive of this release",
        ),
    ];
    a.device.enter();
    for (what, forged, why) in forgeries {
        let refused = a
            .handler
            .handle_commit_response(&with_acknowledgement(&ack, forged))
            .await
            .expect_err(what);
        assert!(refused.to_string().contains(why), "{what}: {refused}");
        assert_eq!(
            stored_phase(&commitment),
            "confirm_pending",
            "{what}: A waits"
        );
        assert_eq!(
            crate::storage::client_db::offline_spends::acknowledgement(&commitment)
                .expect("the acknowledgements"),
            None,
            "{what}: A keeps nothing"
        );
    }
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files the honest acknowledgement");
    assert_committed_on_both(&a, &b, &commitment);
}

/// A phone that received offline goes on paying offline (owner, 2026-11-13: "That is not a rule";
/// "That's why both ... sign"): B, its own allocation loaded, receives A's payment and pays A back
/// at once, with no boundary online between. A takes B's payment from B's account as B's steps since
/// leave it, B's board's signed receive among them. What B received stays where it was received
/// until its unload, and no spend draws from it: B's payment came out of its allocation, to the
/// unit.
/// MUTATION CONTROL: a receiver that takes a payer's steps as spends alone
/// (`verify_spend_chain` over them in `spend_starts_at_the_record`) refuses B's payment: red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_phone_that_received_offline_goes_on_paying_offline_from_what_it_loaded() {
    let (pair, a, b, appliance, payment) = loaded_pair(100, 100).await;
    b.device.enter();
    let loaded = offline_cash(&b, "wallet.loadOffline", "20.00").await;
    assert!(loaded.success, "B's load: {:?}", loaded.error_message);
    pair.a.sync().await;
    let first = bearer_payment_over_ble(&a, &b, &payment).await;
    assert_committed_on_both(&a, &b, &first);

    b.device.enter();
    let era = crate::policy::resolve_policy_commit_strict(b"ERA").expect("ERA");
    let loaded = account_of(&b, &appliance.receiver)
        .allocation(&era)
        .expect("B's allocation before its payment");
    let paid = bearer_payment_over_ble(&b, &a, &bearer_transfer(&a, 3)).await;
    assert_committed_on_both(&b, &a, &paid);
    b.device.enter();
    let account = account_of(&b, &appliance.receiver);
    assert_eq!(
        account.received(&era),
        Some(7),
        "what B received waits for its unload"
    );
    assert_eq!(
        account.allocation(&era),
        Some(loaded - 3),
        "B's payment came out of what it loaded"
    );
}

/// B's board holds one challenge open at a time: while B's acceptance of A's payment waits for A's
/// confirm, B's acceptance of C's is refused and A's challenge stays open. A's payment arrives; then
/// B accepts C's, and both land in what B holds received.
/// MUTATION CONTROL: a second acceptance allowed beside the first draws a second challenge over A's,
/// and A's release no longer checks on B's board: red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_second_offline_receive_waits_until_the_first_has_arrived() {
    let (pair, a, b, appliance, payment) = bearer_pair().await;
    let before = board(&appliance.receiver);
    let mut c_device = TestDevice::create("C", 0x0C);
    c_device.boot(&pair.fleet).await;
    c_device.fund_admitted(100).await;
    c_device.add_and_establish(&pair.b).await;
    pair.b.add_and_establish(&c_device).await;
    let _boards = HostAppliance::install_each(vec![
        (pair.a.device_id, appliance.payer.clone()),
        (pair.b.device_id, appliance.receiver.clone()),
        (
            c_device.device_id,
            HostAppliance::birth(&c_device, [0xCC; 32], 16),
        ),
    ]);
    let c = OfflineDevice::new(&c_device);
    c.device.enter();
    let loaded = offline_cash(&c, "wallet.loadOffline", "20.00").await;
    assert!(loaded.success, "C's load: {:?}", loaded.error_message);
    pair.b.sync().await;

    a.device.enter();
    let (a_prepare, a_commitment) = a.propose(&b, payment).await.expect("A proposes");
    b.device.enter();
    b.handler
        .handle_prepare_request(&a_prepare, None)
        .await
        .expect("B takes A's proposal");
    let a_response = b
        .handler
        .create_prepare_accept_envelope(a_commitment)
        .await
        .expect("B accepts A's payment");
    let challenge = board(&appliance.receiver).open_challenge;

    c.device.enter();
    let (c_prepare, c_commitment) = c
        .propose(&b, bearer_transfer(&b, whole_era(5)))
        .await
        .expect("C proposes");
    b.device.enter();
    b.handler
        .handle_prepare_request(&c_prepare, None)
        .await
        .expect("B takes C's proposal");
    let refused = b
        .handler
        .create_prepare_accept_envelope(c_commitment)
        .await
        .expect_err("B accepts a second receive while the first waits");
    assert!(
        refused
            .to_string()
            .contains("already receiving an offline payment"),
        "{refused}"
    );
    assert_eq!(
        board(&appliance.receiver).open_challenge,
        challenge,
        "A's challenge stays open"
    );

    a.device.enter();
    let (confirm, _meta) = a
        .handler
        .handle_prepare_response(&a_response)
        .await
        .expect("A confirms");
    b.device.enter();
    let ack = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect("B receives A's payment");
    a.device.enter();
    a.handler
        .handle_commit_response(&ack)
        .await
        .expect("A files B's acknowledgement");

    b.device.enter();
    let c_response = b
        .handler
        .create_prepare_accept_envelope(c_commitment)
        .await
        .expect("B accepts C's payment once A's has arrived");
    c.device.enter();
    let (c_confirm, _meta) = c
        .handler
        .handle_prepare_response(&c_response)
        .await
        .expect("C confirms");
    b.device.enter();
    let c_ack = b
        .handler
        .handle_confirm_request(&c_confirm)
        .await
        .expect("B receives C's payment");
    c.device.enter();
    c.handler
        .handle_commit_response(&c_ack)
        .await
        .expect("C files B's acknowledgement");
    received(&b, &appliance.receiver, &before, 7 + whole_era(5), 2);
}
