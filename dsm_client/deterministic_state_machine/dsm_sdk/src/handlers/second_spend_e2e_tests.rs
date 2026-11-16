// SPDX-License-Identifier: MIT OR Apache-2.0

//! One faucet payout offered to two receivers (DSM Amendment A14), on storage
//! nodes.
//!
//! Every device here is created, funded, made a contact and paid through the
//! production routes, and every receiver takes what it is sent through its
//! own `storage.sync`. The payer departs from its wallet in one place, on its
//! own device: it keeps a copy of its wallet's database before it pays, pays
//! one receiver from the original, restores the copy, and changes one number
//! in the copy's database, the position its wallet last admitted, from 1 to
//! 2. The copy then pays a second receiver through the same production send.
//! A copy restored with nothing changed is run first: its wallet builds
//! position 2 again and is stopped where the first payment holds the cell.
//! The step that send builds is the payer's position 3, and it stands on the
//! root the payout left at position 1, where the payer still held all of it.

use serial_test::serial;

use crate::economic_fixtures::whole_era;
use crate::storage::client_db;
use crate::test_support::two_device::{Pair, TestDevice};

/// The position and root `d`'s wallet last admitted, as its own store holds
/// them.
fn admitted(d: &TestDevice) -> (u64, [u8; 32]) {
    d.enter();
    client_db::economic_lineage::get_admitted_coordinate()
        .expect("the admitted store reads")
        .expect("the device admitted a position")
}

/// `payer`'s step at `position` as the entered device's own acceptance
/// validates it (DSM Amendment A14): the root it was validated from and the
/// root it installed, or why it is not validated.
async fn validated_from(payer: &TestDevice, position: u64) -> Result<([u8; 32], [u8; 32]), String> {
    let (genesis, devid) = (payer.genesis, payer.device_id);
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: crate::economic_fixtures::NETWORK.to_vec(),
        }
        .validated_peer_transition(&genesis, &devid, position)
        .map(|step| {
            (
                step.witness().pre_economic_root,
                step.validated_root().economic_root(),
            )
        })
        .map_err(|refused| format!("{refused:?}"))
    })
    .await
    .expect("the check ran")
}

/// How many releases the network's reserve has made, as the entered device's
/// walk of it establishes: the generation of its head.
fn releases_made() -> u64 {
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let runtime = tokio::runtime::Handle::current();
    let stop = tokio::task::block_in_place(|| {
        crate::sdk::native_reserve::walk_reserve(&set, crate::economic_fixtures::NETWORK, &runtime)
    })
    .expect("the reserve walks");
    match stop {
        dsm::economic::native_reserve::WalkStop::Head(head) => head.state().generation(),
        other => panic!("the walk stopped short of the reserve's head: {other:?}"),
    }
}

/// Sync `receiver`, then `payer`, twice over: the receiver takes what it was
/// sent and answers, the payer takes the answer. Every error either sync
/// reported.
async fn settled(receiver: &TestDevice, payer: &TestDevice) -> Vec<String> {
    let mut said = Vec::new();
    for _ in 0..2 {
        for d in [receiver, payer] {
            said.extend(
                d.sync()
                    .await
                    .errors
                    .into_iter()
                    .map(|e| format!("{}: {e}", d.slot)),
            );
        }
    }
    said
}

/// A payout a payer has spent funds no second receiver.
///
/// A claims one faucet payout, 100.00 ERA, and is a contact of B and of C; C
/// is a contact of D. A keeps a copy of its wallet as it stands, then pays B
/// the whole payout, and B is credited it. A restores the copy, moves the
/// position its own store names from 1 to 2, and pays C the whole payout
/// from it. C syncs, then pays D what it holds, and D syncs. The three
/// receivers together must hold no more than the one payout the faucet
/// released: B's 100.00 ERA, and nothing at C or D.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payout_a_payer_has_spent_funds_no_second_receiver() {
    let payout = whole_era(100);
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    let mut d = TestDevice::create("D", 0x0D);
    d.boot(&p.fleet).await;
    c.add_and_establish(&p.a).await;
    p.a.add_and_establish(&c).await;
    d.add_and_establish(&c).await;
    c.add_and_establish(&d).await;
    assert_eq!(p.a.era_balance(), payout, "the faucet paid A once");
    assert_eq!(
        (p.b.era_balance(), c.era_balance(), d.era_balance()),
        (0, 0, 0),
        "no receiver holds anything before A pays"
    );
    let (claimed_at, after_the_claim) = admitted(&p.a);
    assert_eq!(claimed_at, 1, "A's faucet claim is its position 1");

    // A's own copies of its wallet, before it pays anyone: one it will
    // restore as it is, and one it will change.
    let mut unchanged = p.a.backed_up_into("A_UNCHANGED");
    let mut copy = p.a.backed_up_into("A_COPY");

    // A pays B the whole payout.
    let first = p.a.send(&p.b, payout).await;
    assert!(first.success, "A pays B: {:?}", first.error_message);
    let said = settled(&p.b, &p.a).await;
    assert_eq!(
        (p.a.era_balance(), p.b.era_balance()),
        (0, payout),
        "B is credited the payout and A holds nothing: {said:?}"
    );
    assert_eq!(admitted(&p.a).0, 2, "A's payment to B is its position 2");

    // A restores a copy as it is and pays C from it: its wallet builds its
    // position 2 again, where its payment to B already holds the cell.
    unchanged.boot(&p.fleet).await;
    let as_it_is = unchanged.send(&c, payout).await;
    for _ in 0..2 {
        c.sync().await;
    }
    assert!(
        !as_it_is.success,
        "a copy restored as it is pays nobody a second time: {:?}",
        as_it_is.error_message
    );
    assert_eq!(
        c.era_balance(),
        0,
        "C is credited nothing by the unchanged copy"
    );
    assert!(
        as_it_is
            .error_message
            .as_deref()
            .is_some_and(|why| why.contains("held by another root claim")),
        "the unchanged copy is stopped at the position A's payment holds: {:?}",
        as_it_is.error_message
    );

    // A restores its other copy and moves the position its own store names
    // on by one. Nothing else in the copy is touched.
    copy.boot(&p.fleet).await;
    assert_eq!(admitted(&copy), (1, after_the_claim));
    name_position_two(&copy);
    assert_eq!(admitted(&copy), (2, after_the_claim));

    // The copy pays C the same payout, through the production send.
    let second = copy.send(&c, payout).await;
    let second_said = settled(&c, &copy).await;
    let c_credited = c.era_balance();

    // C pays D what it holds.
    let onward = c.send(&d, c_credited).await;
    let onward_said = settled(&d, &c).await;

    // What a device holding nothing of A reads of A's two payments, and of
    // the reserve.
    d.enter();
    let to_b = validated_from(&p.a, 2).await;
    let to_c = validated_from(&p.a, 3).await;
    let released = releases_made();
    let root = |r: &[u8; 32]| crate::util::text_id::encode_base32_crockford(&r[..5]);
    let read = |step: &Result<([u8; 32], [u8; 32]), String>| match step {
        Ok((from, installed)) => format!(
            "validated from root {} (A's root after its claim is {}), installing {}",
            root(from),
            root(&after_the_claim),
            root(installed)
        ),
        Err(refused) => format!("not validated: {refused}"),
    };

    assert_eq!(
        (p.b.era_balance(), c_credited, d.era_balance()),
        (payout, 0, 0),
        "the reserve made {released} release of {payout} base units, and the receivers hold \
         more than it. D's own check of A's position 2: {}. D's own check of A's position 3: \
         {}. B was paid {payout} from A's position 2. The copy's send to C answered success={} ({:?}), at \
         the copy's position {}; C's and the copy's syncs said {second_said:?}; C was credited \
         {c_credited}. C's send to D answered success={} ({:?}); D's and C's syncs said \
         {onward_said:?}; C now holds {} and D {}",
        read(&to_b),
        read(&to_c),
        second.success,
        second.error_message,
        admitted(&copy).0,
        onward.success,
        onward.error_message,
        c.era_balance(),
        d.era_balance()
    );
}

/// Move the position the entered device's own store names from 1 to 2: the
/// one change the payer makes to its restored copy.
fn name_position_two(copy: &TestDevice) {
    copy.enter();
    let binding = client_db::get_connection().expect("the copy's own database");
    let store = binding
        .lock()
        .expect("no other thread holds the copy's database");
    let rows = store
        .execute(
            "UPDATE economic_admitted_v2 SET economic_position = 2 WHERE id = 1",
            [],
        )
        .expect("the copy's owner writes to its own database");
    assert_eq!(rows, 1);
}

/// A payout a payer has spent funds no receiver, whatever step of its own
/// the payer takes in between.
///
/// As above, A pays B its whole payout (position 2) and restores a copy from
/// before, naming position 2. This time the copy first takes a step no
/// receiver takes: it creates a token, through the production route, as its
/// position 3, standing on the root its claim left. Then it pays C what it
/// holds, as position 4, standing on the root its own position 3 installed.
/// C must be credited nothing: A paid that ERA to B.
///
/// What a device holding nothing of A reads is reported with the result:
/// whether the root position 4 stands on is the root registered one position
/// back, and whether the root position 3 stands on is the root position 2
/// installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_spent_payout_funds_no_receiver_behind_the_payers_own_step() {
    use super::node_e2e_tests::create_token;
    let payout = whole_era(100);
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    let mut d = TestDevice::create("D", 0x0D);
    d.boot(&p.fleet).await;
    c.add_and_establish(&p.a).await;
    p.a.add_and_establish(&c).await;
    let (claimed_at, after_the_claim) = admitted(&p.a);
    assert_eq!(claimed_at, 1, "A's faucet claim is its position 1");
    let mut copy = p.a.backed_up_into("A_COPY");

    let first = p.a.send(&p.b, payout).await;
    assert!(first.success, "A pays B: {:?}", first.error_message);
    let said = settled(&p.b, &p.a).await;
    assert_eq!(
        (p.a.era_balance(), p.b.era_balance()),
        (0, payout),
        "B is credited the payout and A holds nothing: {said:?}"
    );
    let (paid_at, after_paying_b) = admitted(&p.a);
    assert_eq!(paid_at, 2, "A's payment to B is its position 2");

    copy.boot(&p.fleet).await;
    assert_eq!(admitted(&copy), (1, after_the_claim));
    name_position_two(&copy);

    // The copy's own step: a token, created through the production route.
    create_token(&copy, "AGAIN", 1_000).await;
    let (own_step_at, after_the_own_step) = admitted(&copy);
    assert_eq!(own_step_at, 3, "the copy's token is A's position 3");
    let held = copy.era_balance();

    // The copy pays C what it holds.
    let second = copy.send(&c, held).await;
    let second_said = settled(&c, &copy).await;

    d.enter();
    let own_step = validated_from(&p.a, 3).await;
    let to_c = validated_from(&p.a, 4).await;
    let released = releases_made();
    let root = |r: &[u8; 32]| crate::util::text_id::encode_base32_crockford(&r[..5]);
    let read = |step: &Result<([u8; 32], [u8; 32]), String>| match step {
        Ok((from, installed)) => format!(
            "validated, standing on root {} and installing {}",
            root(from),
            root(installed)
        ),
        Err(refused) => format!("not validated: {refused}"),
    };
    // Position 4's parent beside the root registered one position back, and
    // position 3's parent beside the root position 2 installed.
    let one_back = match (&to_c, &own_step) {
        (Ok((stands_on, _)), Ok((_, installed))) if stands_on == installed => "the same root",
        (Ok(_), Ok(_)) => "another root",
        (Err(_refused), _) | (_, Err(_refused)) => "not read",
    };
    let two_back = match &own_step {
        Ok((stands_on, _)) if *stands_on == after_paying_b => "the same root",
        Ok(_) => "another root",
        Err(_refused) => "not read",
    };

    assert_eq!(
        (p.b.era_balance(), c.era_balance()),
        (payout, 0),
        "the reserve made {released} release of {payout} base units; B holds {payout} of it, and \
         C was credited {} more. The copy's send answered success={} ({:?}); the syncs said \
         {second_said:?}. Roots: after A's claim {}; after A's payment to B (position 2) {}; \
         after the copy's own step (position 3) {}. A device holding nothing of A reads \
         position 3 as {}, and position 4 as {}. The root position 4 stands on, beside the root registered \
         one position back: {}. The root position 3 stands on, beside the root position 2 \
         installed: {}",
        c.era_balance(),
        second.success,
        second.error_message,
        root(&after_the_claim),
        root(&after_paying_b),
        root(&after_the_own_step),
        read(&own_step),
        read(&to_c),
        one_back,
        two_back,
    );
}

/// What a payer with tooling of its own does to its restored copy: it adds
/// one leaf to its own economic tree, a unit of a token nobody created, and
/// names the root that tree has, at position two. The root is the tree's own
/// root; no step of the payer's, registered anywhere, installed it. The root.
fn name_a_root_no_step_installed(copy: &TestDevice) -> [u8; 32] {
    use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
    copy.enter();
    let mut tree = dsm::economic::tree::EconomicSmt::new();
    for (key, value, _state) in
        client_db::economic_lineage::load_leaf_cache().expect("the copy's own leaves")
    {
        tree.insert(key, value);
    }
    let added = EconomicLeafState::Balance(
        EconomicBalanceState::new(
            dsm::sofi::escrow::external_commitment(b"a token nobody created"),
            1,
        )
        .expect("a balance leaf"),
    );
    let key = added.leaf_key(&copy.genesis, &copy.device_id);
    let value = added.leaf_value().expect("the leaf's value");
    let state = added.encode().expect("the leaf's bytes");
    tree.insert(key, value);
    let root = tree.root();
    let binding = client_db::get_connection().expect("the copy's own database");
    let store = binding
        .lock()
        .expect("no other thread holds the copy's database");
    store
        .execute(
            "INSERT INTO economic_leaf_cache (leaf_key, leaf_value, state_ccb) VALUES (?1, ?2, ?3)",
            rusqlite::params![key.as_slice(), value.as_slice(), state],
        )
        .expect("the copy's owner writes to its own database");
    let rows = store
        .execute(
            "UPDATE economic_admitted_v2 SET economic_position = 2, economic_root = ?1 \
             WHERE id = 1",
            rusqlite::params![root.as_slice()],
        )
        .expect("the copy's owner writes to its own database");
    assert_eq!(rows, 1);
    root
}

/// A payout a payer has spent funds no receiver from a root no step of the
/// payer's installed.
///
/// As above, A pays B its whole payout (position 2) and restores a copy from
/// before. This time the copy changes its own tree: one leaf more than the
/// tree its claim left, and the root of that tree named at position 2. A
/// counter kept as a leaf of the root would be changed the same way. The copy
/// then pays C the payout through the production send, as its position 3,
/// standing on that root. C must be credited nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_spent_payout_funds_no_receiver_from_a_root_no_step_installed() {
    let payout = whole_era(100);
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    let mut d = TestDevice::create("D", 0x0D);
    d.boot(&p.fleet).await;
    c.add_and_establish(&p.a).await;
    p.a.add_and_establish(&c).await;
    let (claimed_at, after_the_claim) = admitted(&p.a);
    assert_eq!(claimed_at, 1, "A's faucet claim is its position 1");
    let mut copy = p.a.backed_up_into("A_COPY");

    let first = p.a.send(&p.b, payout).await;
    assert!(first.success, "A pays B: {:?}", first.error_message);
    let said = settled(&p.b, &p.a).await;
    assert_eq!(
        (p.a.era_balance(), p.b.era_balance()),
        (0, payout),
        "B is credited the payout and A holds nothing: {said:?}"
    );
    let (paid_at, after_paying_b) = admitted(&p.a);
    assert_eq!(paid_at, 2, "A's payment to B is its position 2");

    copy.boot(&p.fleet).await;
    assert_eq!(admitted(&copy), (1, after_the_claim));
    let named = name_a_root_no_step_installed(&copy);
    assert_eq!(admitted(&copy), (2, named));
    assert!(
        named != after_the_claim && named != after_paying_b,
        "the named root is neither root a step of A's installed"
    );

    let second = copy.send(&c, payout).await;
    let second_said = settled(&c, &copy).await;

    d.enter();
    let to_c = validated_from(&p.a, 3).await;
    let released = releases_made();
    let root = |r: &[u8; 32]| crate::util::text_id::encode_base32_crockford(&r[..5]);
    let read = match &to_c {
        Ok((from, installed)) => format!(
            "validated, standing on root {} and installing {}",
            root(from),
            root(installed)
        ),
        Err(refused) => format!("not validated: {refused}"),
    };
    assert_eq!(
        (p.b.era_balance(), c.era_balance()),
        (payout, 0),
        "the reserve made {released} release of {payout} base units; B holds {payout} of it, and \
         C was credited {} more. The copy's send answered success={} ({:?}); the syncs said \
         {second_said:?}. The roots A's registered steps installed: {} (its claim) and {} (its \
         payment to B). The root the copy named, which no registered step installed: {}. A \
         device holding nothing of A reads position 3 as {read}",
        c.era_balance(),
        second.success,
        second.error_message,
        root(&after_the_claim),
        root(&after_paying_b),
        root(&named),
    );
}

/// What a payer with tooling of its own does to its own stopped wallet: it
/// rewrites the one ERA balance leaf of its economic tree to hold `amount`,
/// names the root that tree has where its store named the root its claim
/// left, and writes the same amount into its stored head. No step of the
/// payer's, registered anywhere, credited that amount or installed that
/// root. The position its store names is left as it was. The root.
fn name_a_balance_no_step_credited(wallet: &TestDevice, held: u64, amount: u64) -> [u8; 32] {
    use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
    wallet.enter();
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy");
    let made_up =
        EconomicLeafState::Balance(EconomicBalanceState::new(era, amount).expect("a balance leaf"));
    let key = made_up.leaf_key(&wallet.genesis, &wallet.device_id);
    let value = made_up.leaf_value().expect("the leaf's value");
    let state = made_up.encode().expect("the leaf's bytes");
    let mut tree = dsm::economic::tree::EconomicSmt::new();
    let mut era_leaves = 0;
    for (leaf_key, leaf_value, _state) in
        client_db::economic_lineage::load_leaf_cache().expect("the wallet's own leaves")
    {
        if leaf_key == key {
            era_leaves += 1;
            tree.insert(key, value);
        } else {
            tree.insert(leaf_key, leaf_value);
        }
    }
    assert_eq!(era_leaves, 1, "the wallet holds one ERA balance leaf");
    let root = tree.root();

    let binding = client_db::get_connection().expect("the wallet's own database");
    let store = binding
        .lock()
        .expect("no other thread holds the wallet's database");
    let rows = store
        .execute(
            "UPDATE economic_leaf_cache SET leaf_value = ?1, state_ccb = ?2 WHERE leaf_key = ?3",
            rusqlite::params![value.as_slice(), state, key.as_slice()],
        )
        .expect("the wallet's owner writes to its own database");
    assert_eq!(rows, 1);
    let rows = store
        .execute(
            "UPDATE economic_admitted_v2 SET economic_root = ?1 WHERE id = 1",
            rusqlite::params![root.as_slice()],
        )
        .expect("the wallet's owner writes to its own database");
    assert_eq!(rows, 1);

    // The stored head: the ERA balance is the policy commit followed by the
    // amount, eight bytes, least significant first.
    let mut head: Vec<u8> = store
        .query_row(
            "SELECT head_bytes FROM bcr_device_heads WHERE device_id = ?1",
            rusqlite::params![wallet.device_id.as_slice()],
            |row| row.get(0),
        )
        .expect("the wallet's stored head");
    let mut was = era.to_vec();
    was.extend_from_slice(&held.to_le_bytes());
    let places: Vec<usize> = head
        .windows(was.len())
        .enumerate()
        .filter(|(_, window)| *window == was.as_slice())
        .map(|(at, _)| at)
        .collect();
    assert_eq!(places.len(), 1, "the head names the ERA balance once");
    let at = places[0] + era.len();
    head[at..at + 8].copy_from_slice(&amount.to_le_bytes());
    let rows = store
        .execute(
            "UPDATE bcr_device_heads SET head_bytes = ?1 WHERE device_id = ?2",
            rusqlite::params![head, wallet.device_id.as_slice()],
        )
        .expect("the wallet's owner writes to its own database");
    assert_eq!(rows, 1);
    root
}

/// A balance no step credited pays no receiver.
///
/// A claims one faucet payout, 100.00 ERA, and pays nobody. It stops its
/// wallet and rewrites its own store to hold 1,000.00 ERA: the balance leaf,
/// the root of the tree with that leaf, and the balance in its stored head.
/// It starts its wallet again and pays C the 1,000.00 through the production
/// send, as its position 2, standing on that root. C syncs, then pays D what
/// it holds, and D syncs. The reserve released 100.00 ERA; C and D must be
/// credited nothing by a payment of ERA no step ever credited to A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_balance_no_step_credited_pays_no_receiver() {
    let payout = whole_era(100);
    let made_up = whole_era(1_000);
    let mut p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    let mut d = TestDevice::create("D", 0x0D);
    d.boot(&p.fleet).await;
    c.add_and_establish(&p.a).await;
    p.a.add_and_establish(&c).await;
    d.add_and_establish(&c).await;
    c.add_and_establish(&d).await;
    assert_eq!(p.a.era_balance(), payout, "the faucet paid A once");
    let (claimed_at, after_the_claim) = admitted(&p.a);
    assert_eq!(claimed_at, 1, "A's faucet claim is its position 1");

    // A rewrites its own stopped wallet and starts it again.
    let named = name_a_balance_no_step_credited(&p.a, payout, made_up);
    p.a.start(&p.fleet);
    assert_eq!(admitted(&p.a), (1, named));
    assert_eq!(
        p.a.era_balance(),
        made_up,
        "A's wallet now shows the balance A wrote into it"
    );

    // A pays C the made-up balance, through the production send.
    let paid = p.a.send(&c, made_up).await;
    let paid_said = settled(&c, &p.a).await;
    let c_credited = c.era_balance();

    // C pays D what it holds.
    let onward = c.send(&d, c_credited).await;
    let onward_said = settled(&d, &c).await;

    // What a device holding nothing of A reads of A's payment, and of the
    // reserve.
    d.enter();
    let to_c = validated_from(&p.a, 2).await;
    let released = releases_made();
    let root = |r: &[u8; 32]| crate::util::text_id::encode_base32_crockford(&r[..5]);
    let read = match &to_c {
        Ok((from, installed)) => format!(
            "validated, standing on root {} and installing {}",
            root(from),
            root(installed)
        ),
        Err(refused) => format!("not validated: {refused}"),
    };
    assert_eq!(
        (c_credited, d.era_balance()),
        (0, 0),
        "the reserve made {released} release of {payout} base units, the only ERA any step ever \
         credited to A. A wrote {made_up} into its own store and paid it to C: the send answered \
         success={} ({:?}), at A's position {}; C's and A's syncs said {paid_said:?}; C was \
         credited {c_credited}. C's send to D answered success={} ({:?}); D's and C's syncs said \
         {onward_said:?}; C now holds {} and D {}. The root A's claim installed: {}. The root A \
         named, which no registered step installed: {}. A device holding nothing of A reads A's \
         position 2 as {read}",
        paid.success,
        paid.error_message,
        admitted(&p.a).0,
        onward.success,
        onward.error_message,
        c.era_balance(),
        d.era_balance(),
        root(&after_the_claim),
        root(&named),
    );
}
