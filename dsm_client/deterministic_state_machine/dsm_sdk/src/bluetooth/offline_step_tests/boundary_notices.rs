// SPDX-License-Identifier: MIT OR Apache-2.0

//! How a payer's offline boundaries reach its contacts (DSM Amendment A30): each
//! test here holds only what production holds. A loads through the wallet route,
//! which tells its contacts; a contact's `storage.sync` takes the notice and
//! validates the step it names. Nothing here aims a check at a load by hand.

use super::*;
use crate::economic_fixtures::whole_era;
use crate::sdk::b0x_sdk::{B0xSDK, OFFLINE_BOUNDARY_NOTICE_METHOD};
use crate::sdk::economic_registers::asked_cells;
use crate::storage::client_db::economic_lineage::{
    get_admitted_coordinate, latest_offline_account, offline_account_below,
};
use crate::storage::client_db::offline_boundary_notices::owed_to;
use crate::test_support::appliance::{HostAppliance, InstalledAppliance};
use dsm::economic::peer_lineage::PeerOfflineAccount;
use dsm::economic::register::economic_root_register_key;
use dsm::types::device_state::DeviceState;
use dsm::types::offline_account::OfflineAccount;

/// A funded and loaded through the wallet route. B has run no sync since.
async fn loaded_with_no_sync_since() -> (Pair, OfflineDevice, OfflineDevice, InstalledAppliance) {
    let pair = Pair::boot(100, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let appliance = HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    a.device.enter();
    let loaded = offline_cash(&a, "wallet.loadOffline", "20.00").await;
    assert!(loaded.success, "the load: {:?}", loaded.error_message);
    (pair, a, b, appliance)
}

/// What `reader`'s store records of `payer`'s offline account under `appliance`.
fn recorded_by(
    reader: &TestDevice,
    payer: &TestDevice,
    appliance: &InstalledAppliance,
) -> Option<PeerOfflineAccount> {
    let bundle = appliance.pin().bundle;
    reader.enter();
    latest_offline_account(&payer.genesis, &payer.device_id, &bundle).expect("the store reads")
}

/// A's sync-free load reaches B by B's own sync, and A's first offline payment,
/// from that production state alone, is taken, held pending and settled. This is
/// the state `spend_starts_at_the_record` refused every time before the notice:
/// production created no record. MUTATION CONTROL: B's sync not taking the notice
/// leaves B with no record, and this is red at "B's sync recorded the load".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_load_reaches_a_contact_by_its_sync_and_the_first_offline_payment_is_taken() {
    let (pair, a, b, appliance) = loaded_with_no_sync_since().await;
    assert!(
        recorded_by(&pair.b, &pair.a, &appliance).is_none(),
        "B has validated nothing of A's offline account"
    );

    let synced = pair.b.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "B's sync");
    let recorded = recorded_by(&pair.b, &pair.a, &appliance).expect("B's sync recorded the load");
    a.device.enter();
    let head = a.device.router().core_sdk.device_head().expect("A's head");
    let held = head
        .offline_account(&appliance.pin().bundle)
        .expect("A's offline account");
    assert_eq!(
        recorded.account_root(),
        &held.root(),
        "the account the load left"
    );

    let commitment = offline_step(&a, &b, bearer_transfer(&b, whole_era(7))).await;
    assert_committed_on_both(&a, &b, &commitment);
    b.device.enter();
    assert_eq!(pending_era(), whole_era(7), "B holds the payment pending");

    a.device.enter();
    let unloaded = offline_cash(&a, "wallet.unloadOffline", "10.00").await;
    assert!(unloaded.success, "the unload: {:?}", unloaded.error_message);
    let synced = pair.b.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "B's second sync");
    b.device.enter();
    assert_eq!(pending_era(), 0, "B settled the payment");
    assert_eq!(pair.b.era_balance(), whole_era(7), "B's online balance");
}

/// The owner's receive rule stands: a receiver that has not synced since the load
/// has validated nothing of it, and takes nothing from it, however genuine the
/// payment is. MUTATION CONTROL: dropping the refusal of a missing record in
/// `spend_starts_at_the_record` takes the payment and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_that_has_not_synced_since_the_load_refuses_the_first_payment() {
    let (pair, a, b, appliance) = loaded_with_no_sync_since().await;
    let (commitment, confirm) = to_the_confirm(&a, &b, bearer_transfer(&b, whole_era(7))).await;
    b.device.enter();
    let refused = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("a payment from an account B has validated nothing of");
    assert!(
        refused
            .to_string()
            .contains("has validated none of the sender's offline account online"),
        "{refused}"
    );
    assert_eq!(pending_era(), 0, "B holds nothing of it");
    assert!(!history_row_exists(&commitment), "B kept the step");
    assert!(recorded_by(&pair.b, &pair.a, &appliance).is_none());
}

/// A's load, an online payment of A's on the same relationship, then B's sync:
/// the notice came on the route of the tip it was sent at, and the payment moves
/// that tip. B takes both, and A's first offline payment after them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_load_followed_by_an_online_payment_still_reaches_the_contact() {
    let (pair, a, b, appliance) = loaded_with_no_sync_since().await;
    let sent = pair.a.send(&pair.b, whole_era(5)).await;
    assert!(sent.success, "A's online send: {:?}", sent.error_message);
    let synced = pair.b.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "B's sync");
    assert_eq!(
        pair.b.era_balance(),
        whole_era(5),
        "B took the online payment"
    );
    assert!(
        recorded_by(&pair.b, &pair.a, &appliance).is_some(),
        "B's sync recorded the load"
    );
    pair.a.sync().await;

    let commitment = offline_step(&a, &b, bearer_transfer(&b, whole_era(7))).await;
    assert_committed_on_both(&a, &b, &commitment);
    b.device.enter();
    assert_eq!(pending_era(), whole_era(7), "B holds the payment pending");
}

/// A contact checks a load one hop (DSM Amendment A14): from that step's own
/// parent, reading nothing behind it. A pays B three times online before it loads,
/// so the load sits past a history. B's sync, told of the load, asks for A's
/// register key at the load's position and at no earlier one, and records the
/// account the load left. MUTATION CONTROL: a check that reads behind the step asks
/// for one of A's earlier positions and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_contact_checks_a_load_one_hop_and_reads_nothing_behind_it() {
    let pair = Pair::boot(100, 0).await;
    let a = OfflineDevice::new(&pair.a);
    for round in 1..=3u64 {
        let sent = pair.a.send(&pair.b, whole_era(5)).await;
        assert!(
            sent.success,
            "A's online send {round}: {:?}",
            sent.error_message
        );
        let synced = pair.b.sync().await;
        assert_eq!(synced.errors, Vec::<String>::new(), "B's sync {round}");
    }
    let appliance = HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    a.device.enter();
    let loaded = offline_cash(&a, "wallet.loadOffline", "20.00").await;
    assert!(loaded.success, "the load: {:?}", loaded.error_message);
    a.device.enter();
    let (load_at, _) = get_admitted_coordinate()
        .expect("A's admitted coordinate reads")
        .expect("A admitted its load");

    asked_cells::take();
    let synced = pair.b.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "B's sync");
    let asked = asked_cells::take();

    let read: Vec<u64> = (1..=load_at)
        .filter(|position| {
            asked.contains_key(&economic_root_register_key(
                &pair.a.genesis,
                &pair.a.device_id,
                *position,
            ))
        })
        .collect();
    assert_eq!(
        read,
        vec![load_at],
        "B read A only at the load, at position {load_at}"
    );

    let recorded = recorded_by(&pair.b, &pair.a, &appliance).expect("B's sync recorded the load");
    a.device.enter();
    let head = a.device.router().core_sdk.device_head().expect("A's head");
    let held = head
        .offline_account(&appliance.pin().bundle)
        .expect("A's offline account");
    assert_eq!(
        recorded.account_root(),
        &held.root(),
        "the account the load left"
    );
}

/// Every boundary since a contact was last told reaches it in order, each
/// continuing the account the one before it left. A contact added after them is
/// told at the payer's next sync of the latest alone, which validates with nothing
/// behind it recorded. Once told, a contact is owed nothing more. MUTATION CONTROL:
/// a sync that does not tell contacts leaves C with no record and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn each_contact_is_told_what_it_is_owed_of_a_payers_boundaries() {
    let (pair, a, _b, appliance) = loaded_with_no_sync_since().await;
    a.device.enter();
    let loaded_at = crate::economic_fixtures::admitted_position().expect("A is activated");
    let unloaded = offline_cash(&a, "wallet.unloadOffline", "5.00").await;
    assert!(unloaded.success, "the unload: {:?}", unloaded.error_message);
    let unloaded_at = crate::economic_fixtures::admitted_position().expect("A is activated");
    assert_eq!(unloaded_at, loaded_at + 1);
    let bundle = appliance.pin().bundle;

    // B was told of both as each was admitted, and takes them in order.
    let synced = pair.b.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "B's sync");
    let recorded = recorded_by(&pair.b, &pair.a, &appliance).expect("B recorded the boundaries");
    assert_eq!(recorded.economic_position(), unloaded_at);
    pair.b.enter();
    let before = offline_account_below(&pair.a.genesis, &pair.a.device_id, &bundle, unloaded_at)
        .expect("the store reads")
        .expect("B recorded the load before the unload");
    assert_eq!(before.economic_position(), loaded_at);

    // C arrives after both.
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&pair.fleet).await;
    c.add_contact(&pair.a).await;
    pair.a.add_contact(&c).await;
    assert!(recorded_by(&c, &pair.a, &appliance).is_none());
    pair.a.enter();
    assert_eq!(owed_to(&c.device_id, unloaded_at).unwrap(), [unloaded_at]);
    let told = pair.a.sync().await;
    assert_eq!(told.errors, Vec::<String>::new(), "A's sync");
    pair.a.enter();
    assert_eq!(
        owed_to(&c.device_id, unloaded_at).unwrap(),
        Vec::<u64>::new(),
        "C is told once"
    );
    assert_eq!(
        owed_to(&pair.b.device_id, unloaded_at).unwrap(),
        Vec::<u64>::new(),
        "B was told as each boundary was admitted"
    );

    let synced = c.sync().await;
    assert_eq!(synced.errors, Vec::<String>::new(), "C's sync");
    let recorded = recorded_by(&c, &pair.a, &appliance).expect("C recorded the unload");
    assert_eq!(recorded.economic_position(), unloaded_at);
    c.enter();
    assert!(
        offline_account_below(&pair.a.genesis, &pair.a.device_id, &bundle, unloaded_at)
            .expect("the store reads")
            .is_none(),
        "C was told of the latest alone"
    );
}

/// A notice is discovery and no authority. From a contact holding no boundary at
/// all: a notice naming the activation root and one whose bytes are no position
/// are refused and passed over; one naming a step that is no boundary records
/// nothing; one naming a position past the contact's head is left and read again,
/// a fact not established and never read as its negation. No notice of any kind
/// creates a record. MUTATION CONTROL: recording from the notice instead of from
/// the step it names turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_notice_is_believed_in_nothing_and_no_notice_creates_a_record() {
    let pair = Pair::boot(100, 0).await;
    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    let appliance = HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    let tip = a.tip_with(&b);
    let funded_at = crate::economic_fixtures::admitted_position().expect("A is activated");
    let mut b0x = B0xSDK::new(
        crate::util::text_id::encode_base32_crockford(&pair.a.device_id),
        pair.a.router().core_sdk.clone(),
        crate::sdk::storage_set::pinned_endpoints().expect("the pinned set"),
    )
    .expect("A's inbox client");
    for position in [0, funded_at] {
        b0x.submit_offline_boundary_notice(position, &pair.b.genesis, &pair.b.device_id, &tip)
            .await
            .expect("the notice is delivered");
    }
    b0x.submit_control_message(
        OFFLINE_BOUNDARY_NOTICE_METHOD,
        vec![0x5A; 3],
        &pair.b.genesis,
        &pair.b.device_id,
        &tip,
    )
    .await
    .expect("the notice is delivered");

    let synced = pair.b.sync().await;
    assert!(
        synced
            .errors
            .iter()
            .any(|e| e.contains("activation root") && e.contains("passed over")),
        "{:?}",
        synced.errors
    );
    assert!(
        synced
            .errors
            .iter()
            .any(|e| e.contains("its body is no position") && e.contains("passed over")),
        "{:?}",
        synced.errors
    );
    assert_eq!(synced.errors.len(), 2, "{:?}", synced.errors);
    assert!(recorded_by(&pair.b, &pair.a, &appliance).is_none());

    let synced = pair.b.sync().await;
    assert_eq!(
        synced.errors,
        Vec::<String>::new(),
        "a notice passed over is not read again"
    );

    a.device.enter();
    b0x.submit_offline_boundary_notice(
        funded_at + 1_000_000,
        &pair.b.genesis,
        &pair.b.device_id,
        &tip,
    )
    .await
    .expect("the notice is delivered");
    for _sync in 0..2 {
        let synced = pair.b.sync().await;
        assert!(
            synced
                .errors
                .iter()
                .any(|e| e.contains("is not established")),
            "left on its route and read again: {:?}",
            synced.errors
        );
        assert!(recorded_by(&pair.b, &pair.a, &appliance).is_none());
    }
}

/// Why the record is the check it is, settled by a run on 2026-11-04. A's host
/// runs other code: it rewrites its own stored head, whose root is its own to
/// state, to hold 1,000,000 ERA in an account loaded with 20, and restarts. Its
/// real chip moves its counter and signs a spend of 500,000 from it, since the
/// chip signs the roots the host gives it and never sees a balance; the receipt's
/// allocation folds to the host's own root. B, holding the record of the real
/// load, refuses. MUTATION CONTROL: dropping `spend_starts_at_the_record` makes B
/// take it, 500,000 pending, and turns this red (run 2026-11-04).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_balance_the_payers_host_invented_is_refused_under_its_real_chip() {
    let (pair, a, b, appliance, _) = bearer_pair().await;
    let asset = dsm::core::token::token_state_manager::era_policy_commit();
    let bundle = appliance.pin().bundle;
    let invented = whole_era(1_000_000);

    a.device.enter();
    let head = a.device.router().core_sdk.device_head().expect("A's head");
    let real = head.offline_account(&bundle).expect("A's account").clone();
    assert_eq!(
        real.allocation(&asset),
        Some(whole_era(20)),
        "the real load"
    );
    let mut allocations = real.allocations().clone();
    allocations.insert(asset, invented);
    let mut accounts = head.offline_accounts().clone();
    accounts.insert(
        bundle,
        OfflineAccount::restore(
            allocations,
            real.counter(),
            real.frontier(),
            real.funding_chain(),
        ),
    );
    let tips: Vec<_> = head
        .relationship_keys()
        .into_iter()
        .map(|key| (key, head.rel_chain_tip(&key).expect("a tip").clone()))
        .collect();
    let extra = head.extra_leaves_snapshot().clone();
    let root = DeviceState::root_over(head.devid(), &tips, &extra, &accounts);
    let invented_head = DeviceState::restore(
        head.genesis(),
        head.devid(),
        head.public_key().to_vec(),
        head.legacy_anchor(),
        head.balances_snapshot().clone(),
        tips,
        extra,
        accounts,
        head.pending_economic_admission().cloned(),
        root,
    )
    .expect("the head restores: its root is the host's own");
    crate::storage::client_db::update_bcr_device_head(&invented_head)
        .expect("the host writes its own store");
    let mut restarted = pair.a.clone();
    restarted.start(&pair.fleet);
    let a = OfflineDevice::new(&restarted);
    assert_eq!(
        restarted
            .router()
            .core_sdk
            .device_head()
            .expect("A's head")
            .offline_allocation(&bundle, &asset),
        Some(invented),
        "A's device holds what its host invented"
    );

    let counter = appliance.chip_counter();
    let (commitment, confirm) =
        to_the_confirm(&a, &b, bearer_transfer(&b, whole_era(500_000))).await;
    assert_ne!(
        appliance.chip_counter(),
        counter,
        "A's real chip signed the spend and moved its counter"
    );

    b.device.enter();
    let refused = b
        .handler
        .handle_confirm_request(&confirm)
        .await
        .expect_err("a balance no online step ever debited");
    assert!(
        refused
            .to_string()
            .contains("does not start from the offline account"),
        "{refused}"
    );
    assert_eq!(pending_era(), 0, "B holds nothing of it");
    assert!(!history_row_exists(&commitment), "B kept the step");
}
