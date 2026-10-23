// SPDX-License-Identifier: Apache-2.0

//! The count on the app icon and the b0x button (owner, 2026-10-23): the
//! transfers a device received and verified that the user has not opened the
//! b0x inbox on yet. Two devices on the network's pinned set of storage nodes;
//! every transfer is a real online send, received by the recipient's own sync.

use prost::Message;
use serial_test::serial;

use crate::bridge::{AppQuery, AppRouter};
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::types::proto as generated;

fn waiting_from(answer: crate::bridge::AppResult, route: &str) -> generated::MoneyWaitingResponse {
    assert!(answer.success, "{route}: {:?}", answer.error_message);
    let env = crate::handlers::response_helpers::decode_local_envelope(&answer.data)
        .expect("the route answers an envelope");
    match env.payload {
        Some(generated::envelope::Payload::MoneyWaitingResponse(resp)) => resp,
        other => panic!("{route} answered {other:?}"),
    }
}

/// `inbox.moneyWaiting` on `device`, as the page reads it.
async fn money_waiting(device: &TestDevice) -> generated::MoneyWaitingResponse {
    device.enter();
    let answer = device
        .router()
        .query(AppQuery {
            path: "inbox.moneyWaiting".to_string(),
            params: generated::ArgPack {
                codec: generated::Codec::Proto as i32,
                body: Vec::new(),
                schema_hash: None,
            }
            .encode_to_vec(),
        })
        .await;
    waiting_from(answer, "inbox.moneyWaiting")
}

/// `inbox.moneySeen` on `device`: the user opened the b0x inbox and was shown
/// everything up to `through`.
async fn money_seen(device: &TestDevice, through: u64) -> crate::bridge::AppResult {
    device
        .invoke("inbox.moneySeen", &generated::MoneySeenRequest { through })
        .await
}

fn amounts(waiting: &generated::MoneyWaitingResponse) -> Vec<i64> {
    waiting.received.iter().map(|t| t.amount_signed).collect()
}

/// A transfer counts once B's own sync verified and applied it, and stops
/// counting only once B is shown it. One that lands after B was shown the
/// list still counts; the sender's count never moves; a look never goes back
/// and never past a notice that has been written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_received_transfer_counts_until_the_inbox_shows_it() {
    let p = Pair::boot(100, 0).await;
    let before = money_waiting(&p.b).await;
    assert!(before.received.is_empty(), "nothing received yet");

    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let waiting = money_waiting(&p.b).await;
    assert!(
        waiting.received.is_empty(),
        "a transfer still on the nodes is not counted: B has not verified it"
    );

    let synced = p.b.sync().await;
    assert!(synced.success, "{:?}", synced.errors);
    assert_eq!(p.b.era_balance(), 10, "credited once");
    let first = money_waiting(&p.b).await;
    assert_eq!(amounts(&first), vec![10], "the one transfer B received");
    assert_eq!(first.received[0].from_device_id, p.a.device_id.to_vec());
    assert!(first.through > before.through);

    // The transfer settles as each inbox poller would settle it: A takes B's
    // acceptance and finalizes, B takes the finality. Neither moves money in.
    let finalized = p.a.sync().await;
    assert!(finalized.success, "{:?}", finalized.errors);
    let certified = p.b.sync().await;
    assert!(certified.success, "{:?}", certified.errors);
    assert_eq!(
        amounts(&money_waiting(&p.b).await),
        vec![10],
        "the transfer's finality is not a second transfer"
    );

    let sent = p.a.send(&p.b, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let synced = p.b.sync().await;
    assert!(synced.success, "{:?}", synced.errors);
    let both = money_waiting(&p.b).await;
    assert_eq!(amounts(&both), vec![5, 10], "newest first");
    assert!(both.through > first.through);

    let again = p.b.sync().await;
    assert!(again.success, "{:?}", again.errors);
    assert_eq!(
        amounts(&money_waiting(&p.b).await),
        vec![5, 10],
        "a sync that takes nothing new counts nothing new"
    );

    // B was shown the list when it held only the first transfer.
    let after_first_look = waiting_from(money_seen(&p.b, first.through).await, "inbox.moneySeen");
    assert_eq!(
        amounts(&after_first_look),
        vec![5],
        "the transfer that landed after the look still counts"
    );

    let past = money_seen(&p.b, both.through + 1).await;
    assert!(!past.success, "a look past the newest notice is refused");
    assert_eq!(amounts(&money_waiting(&p.b).await), vec![5]);

    let cleared = waiting_from(money_seen(&p.b, both.through).await, "inbox.moneySeen");
    assert!(cleared.received.is_empty(), "everything shown");
    assert_eq!(cleared.through, both.through);

    let back = waiting_from(money_seen(&p.b, first.through).await, "inbox.moneySeen");
    assert!(
        back.received.is_empty(),
        "an older look does not bring a transfer back"
    );
    assert_eq!(back.through, both.through);

    assert!(
        money_waiting(&p.a).await.received.is_empty(),
        "sending is not receiving"
    );
}

/// A transfer is noticed once however many times its row is written: storing
/// B's verified row again leaves one transfer waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_received_transfer_written_again_is_counted_once() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 7).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let synced = p.b.sync().await;
    assert!(synced.success, "{:?}", synced.errors);

    let waiting =
        crate::storage::client_db::money_received::money_waiting().expect("B's notices read");
    assert_eq!(waiting.received.len(), 1);
    let row = waiting.received.into_iter().next().expect("the one row");
    crate::storage::client_db::money_received::store_received_transfer(&row)
        .expect("the row stored again");

    let again = money_waiting(&p.b).await;
    assert_eq!(amounts(&again), vec![7], "one transfer, one notice");
    assert_eq!(again.through, waiting.through);
}
