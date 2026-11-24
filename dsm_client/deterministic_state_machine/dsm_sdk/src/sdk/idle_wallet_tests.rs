// SPDX-License-Identifier: MIT OR Apache-2.0
//! What an open wallet with nothing to do asks of the storage nodes, and of
//! its own database.
//!
//! The wallet is the recipient of a booted pair, started as the app starts it
//! (`inbox.startPoller`: the inbox poller, its waiter and the backup loop),
//! on screen, on the storage node's own code over Postgres. Once it has
//! settled, every request each node is asked is counted over a window in
//! which nothing is sent to it and nothing is owed.

use std::collections::BTreeMap;
use std::time::Duration;

use prost::Message;

use crate::sdk::{inbox_poller, inbox_waiter, wallet_backup_flow};
use crate::test_support::two_device::Pair;
use dsm::types::proto as generated;

/// How long the wallet is left to settle after its waits cover the fleet: its
/// first backup is taken once its last transaction has landed
/// (`wallet_backup_flow::SETTLE`), and a sync that took something hurries the
/// next few.
const SETTLE: Duration = Duration::from_secs(45);

/// The window in which the idle wallet is watched.
const WINDOW: Duration = Duration::from_secs(45);

/// Where the app is, as Kotlin reports it.
enum Screen {
    Shown,
    Hidden,
}

fn put_app(screen: Screen) {
    let facts = generated::SessionHardwareFactsProto {
        app_foreground: matches!(screen, Screen::Shown),
        ..Default::default()
    };
    crate::sdk::session_manager::update_hardware_and_snapshot(&facts.encode_to_vec())
        .expect("the hardware facts are taken");
}

/// How long a wake may take to start a sync and see it through.
const WAKE_LIMIT: Duration = Duration::from_secs(20);

/// An open wallet with nothing to do asks the nodes only to hold its waits:
/// one wait per member, renewed when the member's bound runs out. No poll, no
/// sync, no read of its routes, and no scan of its own tables.
///
/// The poller it keeps has no timer then, and is woken instead. A delivery
/// answers a held wait (`inbox_waiter::tests::
/// a_wait_held_at_a_member_is_answered_when_a_delivery_lands`), and the
/// waiter wakes the poller as this test does: the sync runs at once. And when
/// the waits stop covering the fleet — here three of five members go down —
/// the waiter wakes the poller itself, which syncs and polls again.
/// MUTATION CONTROL: a covered on-screen poller with a timer turns the count
/// red; `record_coverage` without its wake turns the outage red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn an_open_wallet_with_nothing_to_do_only_holds_its_waits() {
    let stopping_before = inbox_poller::poller_stopping();
    let mut p = Pair::boot(0, 0).await;
    p.b.enter();
    put_app(Screen::Shown);
    p.release_background_poller();
    let started = p.b.invoke("inbox.startPoller", &()).await;
    assert!(started.success, "{:?}", started.error_message);

    let mut covered_after = Duration::ZERO;
    while !inbox_waiter::covers_fleet() {
        assert!(
            covered_after < Duration::from_secs(120),
            "the waits never covered the fleet"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        covered_after += Duration::from_millis(250);
    }
    tokio::time::sleep(SETTLE).await;

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let cycles_before = inbox_poller::cycles_completed();
    let marks_before = wallet_backup_flow::marks_read();
    tokio::time::sleep(WINDOW).await;
    let cycles = inbox_poller::cycles_completed() - cycles_before;
    let marks = wallet_backup_flow::marks_read() - marks_before;
    let mut asked: BTreeMap<String, usize> = BTreeMap::new();
    for node in &p.nodes.nodes {
        for request in node.requests() {
            *asked.entry(request).or_default() += 1;
        }
    }
    let members = p.nodes.nodes.len();

    // A wait answered: the waiter wakes the poller (`Round::Ready`).
    let before_wake = inbox_poller::cycles_completed();
    inbox_poller::resume_poller();
    inbox_poller::cycle_after(before_wake, WAKE_LIMIT).await;
    let woken_syncs = inbox_poller::cycles_completed() - before_wake;

    // The waits stop covering the fleet.
    let before_outage = inbox_poller::cycles_completed();
    p.nodes
        .take_down(&crate::economic_fixtures::members_to_break_quorum())
        .await;
    inbox_poller::cycle_after(before_outage, WAKE_LIMIT).await;
    let outage_syncs = inbox_poller::cycles_completed() - before_outage;
    let covered_in_outage = inbox_waiter::covers_fleet();

    inbox_poller::stop_poller_and_wait().expect("the poller stops");
    inbox_poller::put_back_the_stop(stopping_before);
    wallet_backup_flow::stop_for_test();
    put_app(Screen::Hidden);

    let total: usize = asked.values().sum();
    println!(
        "idle wallet over {WINDOW:?} on {members} members: {total} requests \
         ({:.1}/min), poller syncs {cycles}, activity-mark scans {marks}: {asked:?}",
        total as f64 * 60.0 / WINDOW.as_secs_f64()
    );
    assert!(
        woken_syncs > 0,
        "a wake started no sync within {WAKE_LIMIT:?}"
    );
    assert!(
        outage_syncs > 0 && !covered_in_outage,
        "the waits stopped covering the fleet and no sync followed within {WAKE_LIMIT:?}"
    );
    assert_eq!(cycles, 0, "the idle wallet synced: {asked:?}");
    assert_eq!(marks, 0, "the idle wallet scanned its tables {marks} times");
    let Some(waits) = asked.remove("POST /api/v2/b0x/wait") else {
        panic!("the idle wallet held no wait: {asked:?}");
    };
    assert!(
        asked.is_empty(),
        "the idle wallet asked the nodes more than to hold its waits: {asked:?}"
    );
    // One wait per member at a time, each held to the node's bound.
    let rounds = (WINDOW.as_secs() / dsm_storage_node::api::transport::b0x::MAX_WAIT.as_secs()) + 1;
    assert!(
        waits <= members * rounds as usize,
        "{waits} waits in {WINDOW:?} on {members} members"
    );
}

/// Whether the backup loop is woken within a moment.
async fn backup_loop_woken() -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(300), wallet_backup_flow::moved()).await,
        Ok(())
    )
}

/// The database says when the wallet moved: a row changed in a table the
/// activity mark reads wakes the backup loop, and a write anywhere else does
/// not. A wallet that does not move wakes it never, so it reads no table on a
/// timer.
/// MUTATION CONTROL: `row_changed` waking on every table, or no update hook
/// on the connection, turns this red.
#[tokio::test]
#[serial_test::serial]
async fn only_a_change_the_activity_mark_reads_wakes_the_backup_loop() {
    // A backup loop another test of this binary started waits on the same
    // wake and would take it: no loop runs, and none starts, while this test
    // listens.
    let _hold = inbox_poller::hold_off_for_two_device_harness().await;
    wallet_backup_flow::stop_for_test();
    crate::economic_fixtures::use_test_storage_dir();
    crate::storage::client_db::reset_database_for_tests();
    crate::storage::client_db::init_database().expect("the device database");
    while backup_loop_woken().await {}

    crate::storage::client_db::set_setting("idle-wallet-test", "a setting")
        .expect("a setting is written");
    assert!(
        !backup_loop_woken().await,
        "a write to a table the mark does not read woke the backup loop"
    );

    {
        let binding = crate::storage::client_db::get_connection().expect("the connection");
        let conn = binding.lock().expect("the connection's lock");
        conn.execute(
            "INSERT INTO own_offline_hop(bundle, seq, hop) VALUES (?1, 1, ?2)",
            rusqlite::params![[0x0Au8; 32].as_slice(), [0x0Bu8; 8].as_slice()],
        )
        .expect("an offline step is recorded");
    }
    assert!(
        backup_loop_woken().await,
        "a step recorded in a table the mark reads did not wake the backup loop"
    );
}
