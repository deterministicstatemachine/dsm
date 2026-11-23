// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline steps final at their origin cells (DSM Amendment A39 draft,
//! prototype), on the five storage nodes: real wallets paying offline through
//! their boards, and the payer's steps written to and read from the nodes'
//! cells. The receiver writes the step its payer carried it — the bytes the
//! payer's confirm carried, taken here from the payer's own record of its
//! steps, because a receiver does not keep them yet — and settles its payment
//! from the cells alone.

use super::*;
use crate::economic_fixtures::{whole_era, NETWORK};
use crate::sdk::origin_cell_flow::{self, payment_from_cells, walk, write_of};
use crate::sdk::route_seats::AtLeader;
use crate::test_support::appliance::HostAppliance;
use dsm::types::offline_chain::{AccountHop, SpendHop};

fn set() -> crate::sdk::storage_set::StorageSet {
    crate::sdk::storage_set::canonical_set(NETWORK).expect("the pinned set")
}

/// The steps the entered device's board signed since its last boundary.
fn own_steps(bundle: &[u8; 32]) -> Vec<AccountHop> {
    crate::storage::client_db::offline_spends::own_offline_hops(bundle)
        .expect("the device's own offline steps")
        .iter()
        .map(|bytes| AccountHop::from_bytes(bytes).expect("a step"))
        .collect()
}

/// The entered device's online key.
fn own_key() -> Vec<u8> {
    crate::sdk::signing_authority::current_public_key().expect("the device's online key")
}

/// A spend with its amount changed: the board's roots fold only the amount
/// it signed.
fn inflated(step: &AccountHop, amount: u64) -> AccountHop {
    let AccountHop::Spend(spend) = step else {
        panic!("a spend")
    };
    let mut wire = spend.to_proto();
    wire.amount = amount;
    AccountHop::Spend(SpendHop::from_proto(wire).expect("decodes"))
}

/// `bytes` at the origin cell of `root` of `bundle`, as a hostile leader holds
/// them: an honest leader refuses anything but a step its board signed for the
/// cell (DSM Amendment A41; owner, 2026-11-21: "sure protect them"), which is
/// seen first; then they are put straight in the leader's store, past its
/// check.
async fn planted_at_a_hostile_leader(
    pair: &Pair,
    set: &crate::sdk::storage_set::StorageSet,
    bundle: &[u8; 32],
    root: &[u8; 32],
    bytes: &[u8],
) {
    let honest = origin_cell_flow::put(set, bundle, root, bytes)
        .await
        .expect("the write runs to its end");
    assert_eq!(
        honest,
        AtLeader::Unanswered,
        "an honest leader keeps nothing but a board-signed step at an origin cell"
    );
    let cell = dsm::offline_origin::OriginCell::new(
        bundle,
        root,
        &crate::sdk::storage_set::as_ccb_members(set).expect("the set's members"),
        &set.id(),
    )
    .expect("the origin cell");
    let routed = cell.routed();
    let leader = String::from_utf8(routed.route().leader().to_vec()).expect("member ids are UTF-8");
    let entry = dsm::route_chain::RouteEntry::at_leader(
        routed.namespace().to_vec(),
        *routed.key(),
        bytes.to_vec(),
        routed.route(),
    );
    pair.nodes
        .plant_cell(&leader, routed.namespace(), routed.key(), &entry.encode())
        .await;
}

/// Invalid competing steps never displace a payment, on the nodes. A pays B
/// offline and is never heard from again. Ahead of the real step at its cell's
/// leader go noise, the step re-encoded around its signatures, the step with
/// an inflated amount, and the step as another device's — each refused by an
/// honest leader and held by a hostile one; then B writes the step
/// A carried it. The cell holds the real step, passing over each of the others
/// with its reason, and B proves its payment from the nodes alone. Writing the
/// step again changes nothing, and no other device can claim the payment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn invalid_steps_never_displace_a_payment_on_the_nodes() {
    let (pair, a, b, appliance, payment) = bearer_pair().await;
    offline_step(&a, &b, payment).await;

    a.device.enter();
    let pin = appliance.payer.pin();
    let steps = own_steps(&pin.bundle);
    assert_eq!(steps.len(), 1, "A's one step since its load");
    let step = steps[0].clone();
    let start = step.starts_from();
    let message = step.board_message().expect("the board signed it");
    let real = write_of(&pin, &own_key(), a.device.device_id, &step);

    let mut reencoded = real.clone();
    reencoded.step.extend_from_slice(&[0x78, 0x01]);
    let overpaid = write_of(
        &pin,
        &real.owner_key,
        a.device.device_id,
        &inflated(&step, 9),
    );
    let mut stranger = real.clone();
    stranger.device_id = b.device.device_id;
    let set = set();
    for (bytes, what) in [
        (b"noise".to_vec(), "noise"),
        (reencoded.encode().expect("bytes"), "a re-encoded copy"),
        (overpaid.encode().expect("bytes"), "an inflated amount"),
        (stranger.encode().expect("bytes"), "another device's"),
    ] {
        planted_at_a_hostile_leader(&pair, &set, &pin.bundle, &start, &bytes).await;
        log::info!("{what}: refused by an honest leader, held by a hostile one");
    }

    // A is gone. With only those at the leader, nothing holds the cell: a
    // reader keeps none of them.
    b.device.enter();
    let core = &b.device.router().core_sdk;
    let open = origin_cell_flow::read(core, &set, &pin.bundle, &start).expect("the cell reads");
    assert_eq!(
        open.fact(),
        dsm::route_chain::CellFact::Open,
        "no invalid write holds the cell"
    );
    assert_eq!(open.occupant(), None);

    // B writes the step A carried it, and reads the cell.
    let written = origin_cell_flow::write(&set, &real)
        .await
        .expect("B writes A's step");
    assert!(
        matches!(written, AtLeader::Link),
        "the real step is first recognized"
    );
    let read = origin_cell_flow::read(core, &set, &pin.bundle, &start).expect("the cell reads");
    let held = read.settled().expect("the real step is final");
    assert_eq!(held.message, message);
    let paid = payment_from_cells(
        core,
        &set,
        &pin.bundle,
        &start,
        &start,
        &message,
        &b.device.device_id,
    )
    .expect("B settles from the cells without A");
    assert_eq!(paid.recipient, b.device.device_id);
    assert_eq!(paid.amount, 7);

    // Replay: the same step written again, by A and by B, is the same step.
    for who in [&a, &b] {
        who.device.enter();
        origin_cell_flow::write(&set, &real)
            .await
            .expect("written again");
    }
    b.device.enter();
    let again = payment_from_cells(
        core,
        &set,
        &pin.bundle,
        &start,
        &start,
        &message,
        &b.device.device_id,
    )
    .expect("still B's one payment");
    assert_eq!(again, paid);
    // No other device can claim it.
    let claimed = payment_from_cells(
        core,
        &set,
        &pin.bundle,
        &start,
        &start,
        &message,
        &a.device.device_id,
    )
    .expect_err("A is not the payment's recipient");
    assert!(
        claimed.to_string().contains("not to this device"),
        "{claimed}"
    );
}

/// Valid conflicting steps settle once, on the nodes. A loads 20 ERA. A copy of
/// A's wallet taken after the load runs on a clone of A's board — the same
/// keys, its counter where A's stood — which signs a second step from the root
/// A's first step left: a board that signs twice at one counter. A pays B 15
/// ERA; the copy pays C 15 ERA. Each receiver took its payment offline, 30 from
/// an account of 20. Each writes the step it was carried to the one cell both
/// start from, C first: the cell holds C's, C settles from the cells, and B's
/// payment is off the history the cells hold and never settles. 15 settles of
/// the 20 loaded; nothing is created and nothing settles twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_cloned_board_paying_two_receivers_settles_once_on_the_nodes() {
    let pair = Pair::boot(100, 0).await;
    let mut c_device = TestDevice::create("C", 0x0C);
    c_device.boot(&pair.fleet).await;
    pair.a.add_and_establish(&c_device).await;
    c_device.add_and_establish(&pair.a).await;

    let board_a = HostAppliance::birth(&pair.a, [0xC4; 32], 16);
    let board_b = HostAppliance::birth(&pair.b, [0xB4; 32], 16);
    let board_c = HostAppliance::birth(&c_device, [0xCC; 32], 16);
    let boards = |a: HostAppliance| {
        HostAppliance::install_each(vec![
            (pair.a.device_id, a),
            (pair.b.device_id, board_b.clone()),
            (c_device.device_id, board_c.clone()),
        ])
    };
    let installed = boards(board_a.clone());

    pair.a.enter();
    pair.a
        .offline_boundary("wallet.loadOffline", "20.00")
        .await
        .expect("the load");
    pair.b.sync().await;
    c_device.sync().await;
    let mut copy = pair.a.backed_up_into("A-copy");
    // A's board, cloned as it stands after the load: the copy's board.
    let clone = board_a.cloned();

    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    offline_step(&a, &b, bearer_transfer(&b, whole_era(15))).await;
    a.device.enter();
    let pin = board_a.pin();
    let a_key = own_key();
    let to_b = own_steps(&pin.bundle).remove(0);

    // The copy, on a clone of A's board.
    drop(installed);
    assert_eq!(clone.pin().bundle, pin.bundle, "the clone holds A's keys");
    let _installed = boards(clone);
    copy.boot(&pair.fleet).await;
    let twin = OfflineDevice::new(&copy);
    let c = OfflineDevice::new(&c_device);
    offline_step(&twin, &c, bearer_transfer(&c, whole_era(15))).await;
    twin.device.enter();
    let to_c = own_steps(&pin.bundle).remove(0);

    let root = to_b.starts_from();
    assert_eq!(
        to_c.starts_from(),
        root,
        "both start from the root the load left"
    );
    let m_b = to_b.board_message().expect("signed");
    let m_c = to_c.board_message().expect("signed");
    assert_ne!(m_b, m_c);

    let set = set();
    c.device.enter();
    let c_write = write_of(&pin, &a_key, pair.a.device_id, &to_c);
    let first = origin_cell_flow::write(&set, &c_write)
        .await
        .expect("C writes");
    assert!(matches!(first, AtLeader::Link));
    b.device.enter();
    let b_write = write_of(&pin, &a_key, pair.a.device_id, &to_b);
    let second = origin_cell_flow::write(&set, &b_write)
        .await
        .expect("B writes");
    assert!(
        matches!(second, AtLeader::Taken),
        "the cell is C's step's: {second:?}"
    );

    let core_b = &b.device.router().core_sdk;
    let refused = payment_from_cells(
        core_b,
        &set,
        &pin.bundle,
        &root,
        &root,
        &m_b,
        &b.device.device_id,
    )
    .expect_err("B's payment is off the history the cells hold");
    assert!(refused.to_string().contains("another history"), "{refused}");
    c.device.enter();
    let core_c = &c.device.router().core_sdk;
    let paid = payment_from_cells(
        core_c,
        &set,
        &pin.bundle,
        &root,
        &root,
        &m_c,
        &c.device.device_id,
    )
    .expect("C settles from the cells");
    assert_eq!(paid.amount, whole_era(15));
    assert!(
        paid.amount <= whole_era(20),
        "never more than the account held"
    );
}

/// A flooded cell still settles its payment. Before B writes the step A carried
/// it, a hostile leader holds 30 values of 300 KiB that are no write (an honest
/// one refuses them) — about
/// 9 MiB, more than a reader's budget at one cell. A reader keeps only the
/// leader's first recognized value, so the flood never reaches it: B's step
/// holds the cell and B settles, and nothing settles in its place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_flooded_cell_still_settles_its_payment() {
    let (pair, a, b, appliance, payment) = bearer_pair().await;
    offline_step(&a, &b, payment).await;
    a.device.enter();
    let pin = appliance.payer.pin();
    let step = own_steps(&pin.bundle).remove(0);
    let start = step.starts_from();
    let message = step.board_message().expect("signed");
    let real = write_of(&pin, &own_key(), a.device.device_id, &step);

    let set = set();
    for n in 0..30u64 {
        // Each value distinct: a writer finds a value the leader already
        // holds and puts nothing.
        let mut junk = vec![0x4A_u8; 300 * 1024];
        junk[..8].copy_from_slice(&n.to_be_bytes());
        planted_at_a_hostile_leader(&pair, &set, &pin.bundle, &start, &junk).await;
    }
    b.device.enter();
    origin_cell_flow::write(&set, &real)
        .await
        .expect("B writes");
    let core = &b.device.router().core_sdk;
    let paid = payment_from_cells(
        core,
        &set,
        &pin.bundle,
        &start,
        &start,
        &message,
        &b.device.device_id,
    )
    .expect("the flood does not keep B from settling");
    assert_eq!((paid.recipient, paid.amount), (b.device.device_id, 7));
}

/// A wallet restored from a backup taken before its offline step stands where
/// the network says its account stands once the step's receiver has written it:
/// walking the cells from the account the load left reaches the root A's step
/// left, the one A's board stands at. Before anyone writes the step, the walk
/// stops at the load's root: the restored wallet stands behind its board, and
/// its board signs nothing from there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_restored_wallet_finds_its_account_from_the_nodes() {
    let (pair, a, b, appliance, payment) = bearer_pair().await;
    let mut restored = a.device.backed_up_into("A-restored");
    offline_step(&a, &b, payment).await;
    a.device.enter();
    let pin = appliance.payer.pin();
    let step = own_steps(&pin.bundle).remove(0);
    let start = step.starts_from();
    let real = write_of(&pin, &own_key(), a.device.device_id, &step);
    let set = set();

    restored.boot(&pair.fleet).await;
    restored.enter();
    let core = &restored.router().core_sdk;
    let (before, at) = walk(core, &set, &pin.bundle, &start).expect("the cells read");
    assert!(before.is_empty());
    assert_eq!(
        at, start,
        "nothing written: the walk stands at the load's root"
    );

    b.device.enter();
    origin_cell_flow::write(&set, &real)
        .await
        .expect("B writes");
    restored.enter();
    let (steps, at) = walk(core, &set, &pin.bundle, &start).expect("the cells read");
    assert_eq!(steps.len(), 1);
    assert_eq!(Some(steps[0].message), step.board_message());
    a.device.enter();
    let account = crate::storage::client_db::offline_spends::own_offline_hops(&pin.bundle)
        .expect("A's steps");
    assert_eq!(account.len(), 1);
    assert_eq!(
        at, steps[0].after,
        "the restored wallet stands where A's step left the account"
    );
    assert_ne!(at, start);
}

/// A payer cannot unload what it already paid offline, even before its receiver has published
/// anything (DSM Amendment A39 draft, option B; owner, 2026-11-19: "Don't allow any chance of
/// robbing a receiver"). A loads 20 ERA — its board signs the load — and pays B 15 offline. B
/// writes nothing. A's wallet is then restored from a backup taken before the payment, still on
/// A's genuine board, and asks to unload all 20: the board, which signed the payment from that
/// root and left it, refuses, so no unload is admitted and A's online balance does not move. B
/// then settles its 15 from A's cells. 15 of the 20 settles to B; nothing is taken back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payer_cannot_unload_what_it_paid_offline_before_its_receiver_publishes() {
    let (pair, a, b, _appliance, _) = bearer_pair().await;
    let mut before_payment = a.device.backed_up_into("A-before-payment");
    offline_step(&a, &b, bearer_transfer(&b, whole_era(15))).await;
    a.device.enter();
    let online_before = pair.a.era_balance();

    // A's wallet as it stood before the payment, on A's own board.
    before_payment.boot(&pair.fleet).await;
    before_payment.enter();
    let unload = before_payment
        .invoke(
            "wallet.unloadOffline",
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: "20.00".to_string(),
            },
        )
        .await;
    assert!(
        !unload.success,
        "the board signed an unload of money it already paid"
    );
    assert_eq!(
        before_payment.era_balance(),
        online_before,
        "nothing came back online"
    );

    // B was never needed for that: it settles its payment from A's cells afterwards.
    b.device.enter();
    let moved = unload_received(&b).await;
    assert_eq!((moved.moved, moved.waiting), (1, 0), "{}", moved.message);
    assert_eq!(
        pair.b.era_balance(),
        whole_era(15),
        "B holds what it was paid"
    );
}

/// A wallet's offline account comes back on a restore, from the network (DSM
/// Amendment A40). A has contacts B and C; A loads 20 ERA onto its board and its
/// wallet backs up; then A pays B 15 ERA offline, after the backup, and the
/// wallet puts that step at its origin cell. A's phone is lost before its next
/// backup. Restored from its words on a new device, with the same board, A's
/// account is the backup's advanced through the step its cell holds: the
/// board's counter exactly, 5 ERA, and A pays C 3 ERA offline from there. (Its
/// chain with B moved after the backup, so B refuses a step from the backup's
/// older tip: a step after the last backup is lost to that contact.)
///
/// MUTATION CONTROL: without the account advanced through its cells
/// (`advance_offline_from_cells`), the restored account is the backup's, at
/// counter 1, a step behind its board: red (run 2026-11-19).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_restored_wallet_carries_on_offline_from_its_cells() {
    let pair = Pair::boot(100, 0).await;
    let mut c_device = TestDevice::create("C", 0x0C);
    c_device.boot(&pair.fleet).await;
    pair.a.add_and_establish(&c_device).await;
    c_device.add_and_establish(&pair.a).await;
    let board_a = HostAppliance::birth(&pair.a, [0xA7; 32], 16);
    let board_b = HostAppliance::birth(&pair.b, [0xB7; 32], 16);
    let board_c = HostAppliance::birth(&c_device, [0xC7; 32], 16);
    let _installed = HostAppliance::install_each(vec![
        (pair.a.device_id, board_a.clone()),
        (pair.b.device_id, board_b.clone()),
        (c_device.device_id, board_c.clone()),
    ]);
    pair.a.enter();
    pair.a
        .offline_boundary("wallet.loadOffline", "20.00")
        .await
        .expect("the load");
    pair.b.sync().await;
    c_device.sync().await;
    pair.a.enter();
    let mark = crate::sdk::wallet_backup_flow::activity_mark().expect("the mark");
    let backed = crate::sdk::wallet_backup_flow::back_up_now(&set(), mark)
        .await
        .expect("the backup");
    assert_eq!(backed, crate::sdk::wallet_backup_flow::Attempt::Written(1));

    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    offline_step(&a, &b, bearer_transfer(&b, whole_era(15))).await;
    a.device.enter();
    let put = crate::sdk::wallet_backup_flow::publish_own_steps(&set())
        .await
        .expect("the own steps put");
    assert_eq!(put, 1, "the payment's step, at its cell");
    let bundle = board_a.pin().bundle;
    let board_counter = board_a.chip_counter();

    let mut restored = pair.a.on_a_new_device("A-restored");
    let request = dsm::types::proto::WalletCreateGenesisV2Request {
        mnemonic: crate::economic_fixtures::test_mnemonic(pair.a.seed),
    };
    let args = dsm::types::proto::ArgPack {
        codec: dsm::types::proto::Codec::Proto as i32,
        body: prost::Message::encode_to_vec(&request),
        ..Default::default()
    };
    let answer = crate::handlers::system_routes::handle_restore_from_phrase(
        &prost::Message::encode_to_vec(&args),
    )
    .await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&pair.fleet);
    restored.enter();
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let account = restored
        .router()
        .core_sdk
        .device_head()
        .and_then(|head| head.offline_account(&bundle).cloned())
        .expect("the restored offline account");
    assert_eq!(account.counter(), 2, "the load and the payment");
    assert_eq!(
        account.allocation(&era),
        Some(whole_era(5)),
        "20 loaded, 15 paid"
    );
    assert_eq!(
        board_a.chip_counter(),
        board_counter,
        "the board was not moved by the restore"
    );

    let again = OfflineDevice::new(&restored);
    let c = OfflineDevice::new(&c_device);
    offline_step(&again, &c, bearer_transfer(&c, whole_era(3))).await;
    restored.enter();
    let after = restored
        .router()
        .core_sdk
        .device_head()
        .and_then(|head| head.offline_account(&bundle).cloned())
        .expect("the account");
    assert_eq!(
        after.allocation(&era),
        Some(whole_era(2)),
        "the restored A paid C offline"
    );
}

/// Losing the board and restoring the wallet spends nothing a second time (DSM Amendments A39
/// and A40). A holds 100 ERA and loads 40 onto its board, which leaves 60 online, and its
/// wallet backs up, holding the account at 40. A pays B 30 offline; B writes nothing. A's board
/// is then destroyed and its phone lost, before either reaches the network again. Restored
/// from its words on a new device, A holds 60 ERA online, from its register: the 40 left its
/// online balance when the load was admitted, and a restore does not bring them back. The
/// restored wallet records the account as its backup held it, at 40, and asks for it back:
/// - with no board, nothing signs an unload, and none is admitted;
/// - on a new board born for the same wallet, the account is not that board's: it signs
///   nothing, and none is admitted;
/// - online, it sends 60 and no more.
///
/// B, who was needed for none of that, settles its 30 from A's cells. A holds 60 and B 30; the
/// 10 left on the destroyed board are gone with it, and nothing is counted twice.
///
/// MUTATION CONTROL: with a load that leaves the online balance whole (the debit dropped from
/// `DeviceState`'s boundary), A still reads 100 ERA after loading 40, and this goes red at its
/// first balance (run 2026-11-22). The refusals an unload meets below it each have their own
/// control in Core (`offline_boundary`'s tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_lost_board_and_a_restore_spend_nothing_a_second_time() {
    let pair = Pair::boot(100, 0).await;
    let board_a = HostAppliance::birth(&pair.a, [0xA9; 32], 16);
    let board_b = HostAppliance::birth(&pair.b, [0xB9; 32], 16);
    let both = HostAppliance::install_each(vec![
        (pair.a.device_id, board_a.clone()),
        (pair.b.device_id, board_b.clone()),
    ]);
    pair.a.enter();
    pair.a
        .offline_boundary("wallet.loadOffline", "40.00")
        .await
        .expect("the load");
    assert_eq!(
        pair.a.era_balance(),
        whole_era(60),
        "the load left A's online balance"
    );
    pair.b.sync().await;
    pair.a.enter();
    let mark = crate::sdk::wallet_backup_flow::activity_mark().expect("the mark");
    let backed = crate::sdk::wallet_backup_flow::back_up_now(&set(), mark)
        .await
        .expect("the backup");
    assert_eq!(backed, crate::sdk::wallet_backup_flow::Attempt::Written(1));

    let a = OfflineDevice::new(&pair.a);
    let b = OfflineDevice::new(&pair.b);
    offline_step(&a, &b, bearer_transfer(&b, whole_era(30))).await;
    let bundle = board_a.pin().bundle;

    // A's board is destroyed: only B's is left to attach.
    drop(both);
    let only_b = HostAppliance::install_each(vec![(pair.b.device_id, board_b.clone())]);

    // A's phone is lost too: its wallet comes back from its words on a new device.
    let mut restored = pair.a.on_a_new_device("A-restored");
    let request = dsm::types::proto::WalletCreateGenesisV2Request {
        mnemonic: crate::economic_fixtures::test_mnemonic(pair.a.seed),
    };
    let args = dsm::types::proto::ArgPack {
        codec: dsm::types::proto::Codec::Proto as i32,
        body: prost::Message::encode_to_vec(&request),
        ..Default::default()
    };
    let answer = crate::handlers::system_routes::handle_restore_from_phrase(
        &prost::Message::encode_to_vec(&args),
    )
    .await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&pair.fleet);
    assert_eq!(
        restored.era_balance(),
        whole_era(60),
        "the last online balance: a restore does not undo the load"
    );
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let recorded = restored
        .router()
        .core_sdk
        .device_head()
        .and_then(|head| head.offline_account(&bundle).cloned())
        .expect("the restored wallet's record of its offline account");
    assert_eq!(
        recorded.allocation(&era),
        Some(whole_era(40)),
        "the backup's account, from before the payment"
    );

    // With no board, nothing signs an unload.
    restored.enter();
    let boardless = restored
        .offline_boundary("wallet.unloadOffline", "40.00")
        .await
        .expect_err("an unload was admitted with no board to sign it");
    assert!(
        boardless.contains("connect your anchor device to manage offline cash"),
        "{boardless}"
    );
    assert_eq!(restored.era_balance(), whole_era(60), "nothing came back");

    // On a new board born for the same wallet, the account is not that board's.
    drop(only_b);
    let board_new = HostAppliance::birth(&restored, [0xAA; 32], 16);
    let unsigned = board_new.chip_counter();
    let _installed = HostAppliance::install_each(vec![
        (restored.device_id, board_new.clone()),
        (pair.b.device_id, board_b.clone()),
    ]);
    restored.enter();
    let another_board = restored
        .offline_boundary("wallet.unloadOffline", "40.00")
        .await
        .expect_err("a new board unloaded the lost board's account");
    assert!(
        another_board.contains("an unload names an asset the account does not hold"),
        "{another_board}"
    );
    assert_eq!(
        board_new.chip_counter(),
        unsigned,
        "the new board signed nothing"
    );
    assert_eq!(restored.era_balance(), whole_era(60), "nothing came back");

    // Online, the restored wallet has its 60 and no more.
    let too_much = restored.send(&pair.b, whole_era(61)).await;
    assert!(
        !too_much.success,
        "the restored wallet sent more than its online balance"
    );
    assert!(
        too_much
            .error_message
            .as_deref()
            .is_some_and(|m| m.contains("insufficient funds")),
        "{:?}",
        too_much.error_message
    );
    assert_eq!(restored.era_balance(), whole_era(60), "nothing was sent");

    // B was needed for none of that: it settles its payment from A's cells.
    b.device.enter();
    let moved = unload_received(&b).await;
    assert_eq!((moved.moved, moved.waiting), (1, 0), "{}", moved.message);
    assert_eq!(
        pair.b.era_balance(),
        whole_era(30),
        "B holds what it was paid"
    );
    assert_eq!(
        restored.era_balance(),
        whole_era(60),
        "B's settlement took nothing more from A"
    );
}
