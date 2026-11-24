// SPDX-License-Identifier: MIT OR Apache-2.0
//! A wallet off screen is rung by the storage nodes instead of holding its
//! waits, on the storage node's own code over Postgres, each node pushing
//! through its own outbound client to Google's push endpoints served by the
//! test (`test_support::google_push`).
//!
//! The wallet is the recipient of a booted pair, started as the app starts
//! it (`inbox.startPoller`), with the push token Firebase would hand it.

use std::collections::BTreeSet;
use std::time::Duration;

use prost::Message;

use crate::sdk::{inbox_doorbell, inbox_poller};
use crate::test_support::two_device::Pair;
use dsm::types::proto as generated;

/// The push token the recipient's app holds.
const PHONE_B: &str = "phone-b";

/// How long the wallet is watched off screen: past the node's bound on a
/// held wait, so a wallet still holding waits would ask again within it.
const OFF_SCREEN_WINDOW: Duration =
    Duration::from_secs(dsm_storage_node::api::transport::b0x::MAX_WAIT.as_secs() + 5);

/// How long anything asked of the wallet or the nodes may take.
const LIMIT: Duration = Duration::from_secs(120);

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

/// The routes the waiter plans on for the entered device.
fn planned_routes() -> Vec<String> {
    let device: [u8; 32] = crate::sdk::app_state::AppState::get_device_id()
        .expect("a device id")
        .as_slice()
        .try_into()
        .expect("32 bytes");
    let genesis: [u8; 32] = crate::sdk::app_state::AppState::get_genesis_hash()
        .expect("a genesis")
        .as_slice()
        .try_into()
        .expect("32 bytes");
    let contacts = crate::storage::client_db::get_all_contacts().expect("contacts");
    crate::handlers::app_router_impl::collect_tagged_inbox_addresses(genesis, device, &contacts)
        .expect("the routes")
        .into_iter()
        .map(|tagged| tagged.address)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Wait until `done`, at most [`LIMIT`].
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let mut waited = Duration::ZERO;
    while !done() {
        assert!(waited < LIMIT, "{what} did not happen within {LIMIT:?}");
        tokio::time::sleep(Duration::from_millis(250)).await;
        waited += Duration::from_millis(250);
    }
}

/// Whether every node holds the entered device's doorbell, under the key it
/// derives for that node, with `PHONE_B` and exactly `routes`.
fn doorbells_stand_for(p: &Pair, routes: &[String]) -> bool {
    p.nodes.nodes.iter().all(|node| {
        let key = inbox_doorbell::doorbell_key(&node.endpoint).expect("a doorbell key");
        node.doorbell(&key) == Some((PHONE_B.to_string(), routes.to_vec()))
    })
}

/// On screen, the wallet puts its doorbell up at every member, under the key
/// it derives for that member, for exactly the routes its waiter plans on.
/// Off screen, the app may let its foreground service go
/// (`Backgrounded::Ringing`) and the wallet holds no wait. A transfer to it
/// then rings its phone: each node that took an entry for it pushes its token
/// at least once, at most once per entry, and the push carries nothing of
/// the transfer. The push runs the sync that takes the transfer, and the
/// doorbells move with the routes it moved.
/// MUTATION CONTROL: a waiter that holds its waits off screen, or a
/// lifecycle stop that keeps the foreground service while the doorbells
/// cover the fleet, turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_wallet_off_screen_is_rung_by_the_nodes_instead_of_holding_waits() {
    let stopping_before = inbox_poller::poller_stopping();
    let mut p = Pair::boot(1_000, 0).await;
    p.b.enter();
    put_app(Screen::Shown);
    inbox_doorbell::set_push_token(PHONE_B.to_string());
    p.release_background_poller();
    let started = p.b.invoke("inbox.startPoller", &()).await;
    assert!(started.success, "{:?}", started.error_message);

    // On screen: the doorbells stand for the routes the waiter plans on.
    let routes = planned_routes();
    assert!(!routes.is_empty(), "a device with a contact reads routes");
    until(
        "the doorbells covering the fleet",
        inbox_doorbell::covers_fleet,
    )
    .await;
    until("every node holding the doorbell", || {
        doorbells_stand_for(&p, &routes)
    })
    .await;

    // Off screen: no foreground service needed, and no wait held.
    put_app(Screen::Hidden);
    let backgrounded = inbox_poller::stop_poller_for_lifecycle().expect("the lifecycle stop");
    assert_eq!(backgrounded, inbox_poller::Backgrounded::Ringing);
    tokio::time::sleep(Duration::from_secs(2)).await;
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    // Longer than a node holds a wait: a wait held before the window would
    // be asked again inside it.
    tokio::time::sleep(OFF_SCREEN_WINDOW).await;
    for node in &p.nodes.nodes {
        let waits = node
            .requests()
            .into_iter()
            .filter(|request| request == "POST /api/v2/b0x/wait")
            .count();
        assert_eq!(
            waits, 0,
            "{} was asked to hold a wait off screen",
            node.member_id
        );
    }
    assert!(
        inbox_doorbell::covers_fleet(),
        "the doorbells stopped covering the fleet off screen"
    );

    // A transfer lands: the nodes ring the phone.
    inbox_poller::stop_poller_and_wait().expect("the poller stops");
    assert!(
        p.nodes.google.pushes().is_empty(),
        "a push before any delivery"
    );
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let mut arrivals = 0;
    let mut nodes_taking = 0;
    for node in &p.nodes.nodes {
        let entries = node
            .spool()
            .await
            .into_iter()
            .filter(|spooled| routes.contains(&spooled.address))
            .count();
        arrivals += entries;
        nodes_taking += usize::from(entries > 0);
    }
    assert!(nodes_taking > 0, "the transfer reached no node");
    let pushes = p
        .nodes
        .google
        .until_pushes(nodes_taking, Duration::from_secs(30))
        .await;
    assert!(
        pushes.len() >= nodes_taking && pushes.len() <= arrivals,
        "{} pushes for {arrivals} entries on {nodes_taking} nodes",
        pushes.len()
    );
    for push in &pushes {
        assert_eq!(push.push_token, PHONE_B);
        assert_eq!(push.message["data"]["dsm"], "inbox");
        assert_eq!(
            push.message["data"].as_object().map(|data| data.len()),
            Some(1)
        );
        let sent = push.message.to_string();
        assert!(
            routes.iter().all(|route| !sent.contains(route.as_str())),
            "a push names a route: {sent}"
        );
    }

    // The push wakes the sync, which takes the transfer. The send woke the
    // poller on its own; it is stopped again, so only the push starts it.
    inbox_poller::stop_poller_and_wait().expect("the poller stops");
    assert!(!inbox_poller::poller_running(), "the poller still runs");
    p.b.enter();
    put_app(Screen::Hidden);
    let before = inbox_poller::cycles_completed();
    inbox_doorbell::on_push_wake();
    inbox_poller::cycle_after(before, Duration::from_secs(60)).await;
    assert!(
        inbox_poller::cycles_completed() > before,
        "the push started no sync"
    );
    p.b.enter();
    assert_eq!(
        p.b.era_balance(),
        10,
        "the sync the push woke did not take the transfer"
    );

    // The routes moved with the transfer; the doorbells follow them.
    p.b.enter();
    let moved = planned_routes();
    until("the doorbells following the routes", || {
        doorbells_stand_for(&p, &moved)
    })
    .await;

    inbox_poller::stop_poller_and_wait().expect("the poller stops");
    inbox_poller::put_back_the_stop(stopping_before);
    inbox_doorbell::push_unavailable("the test is over");
}
