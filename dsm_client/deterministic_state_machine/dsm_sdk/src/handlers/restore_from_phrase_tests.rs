// SPDX-License-Identifier: MIT OR Apache-2.0

//! `system.restoreFromPhrase` on storage nodes: a wallet restored on a new
//! device from its 24 words comes back as the SAME identity at its last online
//! balance, read from the network (owner, 2026-11-19), and words of no wallet
//! on the network restore nothing.

use crate::economic_fixtures;
use crate::sdk::app_state::AppState;
use crate::test_support::two_device::Pair;
use dsm::types::proto as generated;
use prost::Message;

/// `system.restoreFromPhrase` with `words`, as the frontend sends it.
pub(super) async fn restore(words: &str) -> crate::bridge::AppResult {
    super::system_routes::handle_restore_from_phrase(
        &generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: generated::WalletCreateGenesisV2Request {
                mnemonic: words.to_string(),
            }
            .encode_to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .await
}

/// ERA in base units.
fn era(whole: u64) -> u64 {
    whole
        * 10u64.pow(
            dsm::core::token::era_policy::era_policy()
                .expect("ERA's policy")
                .decimals,
        )
}

/// The position this device's register holds as admitted.
fn admitted_position() -> u64 {
    crate::storage::client_db::economic_lineage::get_admitted()
        .expect("the admitted position")
        .expect("an admitted position")
        .economic_position()
}

/// A takes two faucet payouts (200 ERA) and pays B 50 ERA online: three steps
/// of its register. Then A's phone is lost. On a new device, words of a wallet
/// the network does not hold restore nothing and install no identity; A's own
/// words bring back A's identity — the same device id and genesis — at the
/// position and balance A's register holds, 150 ERA, re-verified from the
/// nodes. The restored wallet then admits its next step: a third payout lands
/// on top of the restored head, not on a position the lost phone already took.
///
/// MUTATION CONTROL: without the balances `restored_from_register` installs
/// from the folded leaves, the restored wallet reads 0 ERA, and this goes red
/// (run 2026-11-19).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_wallet_restored_from_its_words_is_the_same_identity_at_its_last_online_balance() {
    let pair = Pair::boot(200, 0).await;
    let paid = pair.a.send(&pair.b, era(50)).await;
    assert!(paid.success, "A pays B: {:?}", paid.error_message);
    pair.b.sync().await;
    pair.a.sync().await;
    let lost_balance = pair.a.era_balance();
    assert_eq!(lost_balance, era(150), "A holds what it kept");
    pair.a.enter();
    let lost_position = admitted_position();

    let mut restored = pair.a.on_a_new_device("A-restored");
    let stranger = restore(&economic_fixtures::test_mnemonic(0x5E)).await;
    assert!(!stranger.success, "words of no wallet on the network");
    assert!(
        stranger
            .error_message
            .as_deref()
            .is_some_and(|m| m.contains("no wallet made from these words is on the network")),
        "{:?}",
        stranger.error_message
    );
    assert!(
        !AppState::get_has_identity(),
        "a refused restore installs no identity"
    );

    let answer = restore(&economic_fixtures::test_mnemonic(pair.a.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    assert_eq!(
        AppState::get_device_id(),
        Some(pair.a.device_id.to_vec()),
        "the same device id"
    );
    assert_eq!(
        AppState::get_genesis_hash(),
        Some(pair.a.genesis.to_vec()),
        "the same genesis"
    );
    assert_eq!(admitted_position(), lost_position, "the register's head");

    restored.start(&pair.fleet);
    assert_eq!(
        restored.era_balance(),
        lost_balance,
        "the last online balance, from the network"
    );
    restored.fund_admitted(100).await;
    assert_eq!(restored.era_balance(), lost_balance + era(100));
    restored.enter();
    assert_eq!(
        admitted_position(),
        lost_position + 1,
        "the next step lands on the head"
    );
}

/// A's wallet, as its backup loop takes it once still: backup `n` written.
pub(super) async fn back_up(device: &crate::test_support::two_device::TestDevice, n: u64) {
    device.enter();
    let set = crate::sdk::storage_set::canonical_set(economic_fixtures::NETWORK).expect("the set");
    let mark = crate::sdk::wallet_backup_flow::activity_mark().expect("the activity mark");
    let attempt = crate::sdk::wallet_backup_flow::back_up_now(&set, mark)
        .await
        .expect("the backup");
    assert_eq!(attempt, crate::sdk::wallet_backup_flow::Attempt::Written(n));
}

/// A and B are contacts and A pays B 50 ERA; A's wallet then backs itself up,
/// and A's phone is lost. Restored from its words on a new device, A comes back
/// with B as an established contact at the chain state it had, and pays B 20
/// ERA from there: B takes the payment from the state it kept of A, so nothing
/// in what B accepts changed. The backup opens only under A's words.
///
/// MUTATION CONTROL: without the backup's tables installed
/// (`restore_from_backup`), the restored A comes back with no head or contact of
/// its own and reads 0 ERA, and this goes red (run 2026-11-19).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_restored_wallet_carries_on_with_its_contacts_from_its_backup() {
    let pair = Pair::boot(200, 0).await;
    let paid = pair.a.send(&pair.b, era(50)).await;
    assert!(paid.success, "A pays B: {:?}", paid.error_message);
    pair.b.sync().await;
    pair.a.sync().await;
    back_up(&pair.a, 1).await;
    let b_before = pair.b.era_balance();

    let mut restored = pair.a.on_a_new_device("A-restored");
    let answer = restore(&economic_fixtures::test_mnemonic(pair.a.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&pair.fleet);
    assert_eq!(restored.era_balance(), era(150));
    assert_eq!(
        restored.relationship_state(&pair.b),
        crate::storage::client_db::RelationshipState::Established,
        "B is A's contact again"
    );

    let again = restored.send(&pair.b, era(20)).await;
    assert!(
        again.success,
        "the restored A pays B: {:?}",
        again.error_message
    );
    pair.b.sync().await;
    restored.sync().await;
    pair.b.sync().await;
    assert_eq!(pair.b.era_balance(), b_before + era(20), "B took it");
    assert_eq!(restored.era_balance(), era(130));
}

/// A backs up, then pays B again before it is still: its latest backup is from
/// before the register's head. Restored, A comes back at its register's head and
/// balance, and the out-of-date contact state is never installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_backup_behind_the_register_is_never_installed() {
    let pair = Pair::boot(200, 0).await;
    back_up(&pair.a, 1).await;
    let paid = pair.a.send(&pair.b, era(50)).await;
    assert!(paid.success, "A pays B: {:?}", paid.error_message);
    pair.b.sync().await;
    pair.a.sync().await;

    let mut restored = pair.a.on_a_new_device("A-restored");
    let answer = restore(&economic_fixtures::test_mnemonic(pair.a.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&pair.fleet);
    assert_eq!(restored.era_balance(), era(150), "the register's balance");
    restored.enter();
    assert_eq!(
        crate::storage::client_db::get_contact_by_device_id(&pair.b.device_id)
            .expect("the contacts")
            .map(|contact| contact.device_id),
        None,
        "no out-of-date contact state"
    );
    assert_eq!(
        crate::sdk::wallet_backup_flow::latest_written().expect("the setting"),
        1,
        "the next backup goes after the one the cells hold"
    );
}

/// An attempt at a backup cut short leaves no gap. After backup 1, an attempt
/// at backup 2 stops after a later part, before part 0. The next attempt still
/// writes backup 2, under an attempt of its own, and the latest the cells hold
/// is backup 2, with exactly the body that attempt wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn an_attempt_cut_short_leaves_no_gap() {
    let pair = Pair::boot(100, 0).await;
    back_up(&pair.a, 1).await;
    pair.a.enter();
    let set = crate::sdk::storage_set::canonical_set(economic_fixtures::NETWORK).expect("the set");
    let keys = crate::sdk::wallet_backup_flow::keys().expect("the keys");
    let cut_short = dsm::wallet_backup::new_attempt();
    let place = dsm::wallet_backup::Place::of(1, cut_short);
    let cell = dsm::wallet_backup::BackupCell::new(
        &keys,
        2,
        place,
        &crate::sdk::storage_set::as_ccb_members(&set).expect("the members"),
        &set.id(),
    )
    .expect("the cell");
    let stray = keys
        .seal(2, 1, 2, &cut_short, b"a later part of an attempt cut short")
        .expect("sealed");
    let left = crate::sdk::route_seats::write_recorded(&set, cell.routed(), &cell.keeps(), &stray)
        .await
        .expect("the stray part");
    assert!(matches!(
        left.leader(),
        crate::sdk::route_seats::AtLeader::Link
    ));

    back_up(&pair.a, 2).await;
    pair.a.enter();
    let own = (pair.a.genesis, pair.a.device_id);
    let latest = tokio::task::spawn_blocking(move || {
        crate::sdk::wallet_backup_flow::latest(&set, own, &keys)
    })
    .await
    .expect("the read finished")
    .expect("the backups")
    .expect("a backup");
    let taken = crate::sdk::wallet_backup_flow::snapshot()
        .expect("the snapshot")
        .expect("still");
    assert_eq!(latest.0, 2, "the latest is backup 2");
    assert_eq!(latest.1, taken, "with the body its own attempt wrote");
}

/// The rows of `table` this device holds, and the rows of it a backup taken
/// now carries.
fn held_and_carried(table: &str) -> (usize, usize) {
    let held: i64 = {
        let binding = crate::storage::client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store's lock");
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .expect("the count")
    };
    let body = crate::sdk::wallet_backup_flow::snapshot()
        .expect("the snapshot")
        .expect("still");
    let carried = body
        .tables
        .iter()
        .find(|t| t.name == table)
        .map(|t| t.rows.len())
        .expect("the table is carried");
    (usize::try_from(held).expect("a count"), carried)
}

/// The parts of this wallet's backups it still keeps a write record of.
fn recorded_backup_parts() -> i64 {
    let binding = crate::storage::client_db::get_connection().expect("the store");
    let conn = binding.lock().expect("the store's lock");
    conn.query_row(
        "SELECT COUNT(*) FROM route_chain_write WHERE namespace = ?1",
        [dsm::common::domain_tags::TAG_DSM_WALLET_BACKUP_CELL.source_bytes()],
        |r| r.get(0),
    )
    .expect("the count")
}

/// A and B pay each other three times each, so each wallet keeps a record of
/// six payments, besides the step that made them contacts. A's backup carries only each contact's latest step and the
/// steps in flight, not the earlier payments, and once every seat holds its
/// parts A forgets its own record of writing them. A's phone is lost;
/// restored from its words, A takes a payment from B and pays B from there,
/// so the trimmed backup is everything A needs to carry on with B both ways.
///
/// MUTATION CONTROL: with `kept_rows` answering `SELECT * FROM {table}` for
/// every table, the backup carries all three of A's sends and goes red on the
/// first carried count; with `forget_writes_held_everywhere` forgetting
/// nothing, the parts stay recorded and it goes red there (run 2026-11-23).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_backup_carries_each_contacts_latest_step_not_every_payment() {
    let pair = Pair::boot(200, 0).await;
    for round in 0..3u64 {
        let paid = pair.a.send(&pair.b, era(20)).await;
        assert!(
            paid.success,
            "A pays B, round {round}: {:?}",
            paid.error_message
        );
        pair.b.sync().await;
        pair.a.sync().await;
        let back = pair.b.send(&pair.a, era(5)).await;
        assert!(
            back.success,
            "B pays A, round {round}: {:?}",
            back.error_message
        );
        pair.a.sync().await;
        pair.b.sync().await;
    }
    pair.a.sync().await;
    pair.a.enter();
    let (sends_held, sends_carried) = held_and_carried("sender_outbox");
    let (taken_held, taken_carried) = held_and_carried("acceptance_fold_journal");
    let (_, replies_carried) = held_and_carried("recipient_outbound_reply");
    assert_eq!(sends_held, 3, "A holds a record of each of its three sends");
    assert_eq!(sends_carried, 1, "the backup carries A's latest send to B");
    assert_eq!(
        taken_held, 4,
        "A holds a record of each payment it took and of the step that made B its contact"
    );
    assert_eq!(
        taken_carried, 1,
        "the backup carries the latest payment A took"
    );
    assert!(replies_carried <= 1, "and at most that payment's reply");

    back_up(&pair.a, 1).await;
    pair.a.enter();
    assert!(recorded_backup_parts() > 0, "A recorded writing its backup");
    crate::sdk::wallet_backup_flow::forget_parts_held_everywhere().expect("forgotten");
    assert_eq!(
        recorded_backup_parts(),
        0,
        "every seat holds every part, so A keeps no record of writing them"
    );
    let a_before = pair.a.era_balance();
    let b_before = pair.b.era_balance();

    let mut restored = pair.a.on_a_new_device("A-restored");
    let answer = restore(&economic_fixtures::test_mnemonic(pair.a.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&pair.fleet);
    assert_eq!(restored.era_balance(), a_before);

    let taken = pair.b.send(&restored, era(4)).await;
    assert!(
        taken.success,
        "B pays the restored A: {:?}",
        taken.error_message
    );
    restored.sync().await;
    pair.b.sync().await;
    assert_eq!(
        restored.era_balance(),
        a_before + era(4),
        "the restored A took it"
    );

    let again = restored.send(&pair.b, era(7)).await;
    assert!(
        again.success,
        "the restored A pays B: {:?}",
        again.error_message
    );
    pair.b.sync().await;
    restored.sync().await;
    pair.b.sync().await;
    assert_eq!(
        pair.b.era_balance(),
        b_before - era(4) + era(7),
        "B took it"
    );
    assert_eq!(restored.era_balance(), a_before + era(4) - era(7));
}
