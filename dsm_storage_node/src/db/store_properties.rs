// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable-object and device-tree properties of the node's store, on the
//! Postgres database `DSM_TEST_DATABASE_URL` names ([`super::test_store`]).
//! Every test addresses rows of its own.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use super::test_store::{fresh_pool, unique_name};
use crate::db::{self, DeviceTreeUpsertOutcome, ImmutablePutOutcome};

/// Idempotence on the tuple. Two puts of the identical `(namespace, payload)`
/// leave one row; a differing PAYLOAD at the same address is a conflict; and a
/// differing NAMESPACE with the identical payload is ALSO a conflict — the case
/// a bytes-only comparison would pass over, which is why the comparison is on
/// the tuple.
#[tokio::test]
async fn immutable_put_is_write_once_on_the_tuple() {
    let pool = fresh_pool().await;
    let addr = unique_name(0x51);
    let ns = b"DSM/vault-state".to_vec();
    let payload = b"canonical bytes".to_vec();

    let first = db::insert_immutable_object_if_absent(&pool, &addr, &ns, &payload, 1)
        .await
        .expect("insert");
    assert_eq!(first, ImmutablePutOutcome::Inserted);

    let replay = db::insert_immutable_object_if_absent(&pool, &addr, &ns, &payload, 2)
        .await
        .expect("replay");
    assert_eq!(replay, ImmutablePutOutcome::AlreadyExistsIdentical);

    let other_payload = db::insert_immutable_object_if_absent(&pool, &addr, &ns, b"different", 3)
        .await
        .expect("query");
    assert_eq!(other_payload, ImmutablePutOutcome::Conflict);

    let other_ns =
        db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/genesis/v3", &payload, 4)
            .await
            .expect("query");
    assert_eq!(
        other_ns,
        ImmutablePutOutcome::Conflict,
        "a mutated namespace with identical payload must NOT re-ack"
    );

    let (got_ns, got_payload) = db::get_immutable_object(&pool, &addr)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(got_ns, ns);
    assert_eq!(got_payload, payload);
}

/// No overwrite path exists — behaviourally, the losing write leaves the
/// first tuple untouched.
#[tokio::test]
async fn a_conflicting_put_leaves_the_first_write_untouched() {
    let pool = fresh_pool().await;
    let addr = unique_name(0x52);
    db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/vault-state", b"first", 1)
        .await
        .expect("insert");
    let second =
        db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/vault-state", b"second", 2)
            .await
            .expect("query");
    assert_eq!(second, ImmutablePutOutcome::Conflict);
    let (ns, payload) = db::get_immutable_object(&pool, &addr)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(ns, b"DSM/vault-state".to_vec());
    assert_eq!(payload, b"first".to_vec());
}

#[tokio::test]
async fn devtree_first_insert_returns_inserted() {
    let pool = fresh_pool().await;
    let genesis = unique_name(0x53);
    let outcome = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        1,
        1,
        &[0x11u8; 32],
        b"payload1",
        42,
    )
    .await
    .expect("insert");
    assert_eq!(outcome, DeviceTreeUpsertOutcome::Inserted);
    assert_eq!(
        db::get_device_tree_state_version(&pool, &genesis)
            .await
            .expect("read"),
        Some(1u64)
    );
    assert_eq!(
        db::get_device_tree_state_payload(&pool, &genesis)
            .await
            .expect("read payload")
            .as_deref(),
        Some(b"payload1".as_ref())
    );
}

#[tokio::test]
async fn devtree_strictly_greater_version_is_accepted() {
    let pool = fresh_pool().await;
    let genesis = unique_name(0x54);
    db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        1,
        1,
        &[0x11u8; 32],
        b"payload1",
        10,
    )
    .await
    .expect("v1");
    let outcome = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        2,
        2,
        &[0x22u8; 32],
        b"payload2",
        11,
    )
    .await
    .expect("v2");
    assert_eq!(
        outcome,
        DeviceTreeUpsertOutcome::Updated { prior_version: 1 }
    );
    assert_eq!(
        db::get_device_tree_state_version(&pool, &genesis)
            .await
            .expect("read"),
        Some(2u64)
    );
    assert_eq!(
        db::get_device_tree_state_payload(&pool, &genesis)
            .await
            .expect("read payload")
            .as_deref(),
        Some(b"payload2".as_ref())
    );
}

#[tokio::test]
async fn devtree_equal_version_is_rejected_as_stale() {
    let pool = fresh_pool().await;
    let genesis = unique_name(0x55);
    db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        5,
        1,
        &[0x11u8; 32],
        b"payload-v5",
        10,
    )
    .await
    .expect("v5");
    let outcome = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        5,
        1,
        &[0x99u8; 32],
        b"payload-replay",
        11,
    )
    .await
    .expect("replay");
    assert_eq!(
        outcome,
        DeviceTreeUpsertOutcome::RejectedStale { prior_version: 5 }
    );
    assert_eq!(
        db::get_device_tree_state_payload(&pool, &genesis)
            .await
            .expect("read")
            .as_deref(),
        Some(b"payload-v5".as_ref())
    );
}

#[tokio::test]
async fn devtree_lesser_version_is_rejected_as_stale() {
    let pool = fresh_pool().await;
    let genesis = unique_name(0x56);
    db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        10,
        1,
        &[0x11u8; 32],
        b"payload-v10",
        10,
    )
    .await
    .expect("v10");
    let outcome = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis,
        3,
        1,
        &[0x33u8; 32],
        b"payload-v3",
        11,
    )
    .await
    .expect("attempt v3");
    assert_eq!(
        outcome,
        DeviceTreeUpsertOutcome::RejectedStale { prior_version: 10 }
    );
    assert_eq!(
        db::get_device_tree_state_payload(&pool, &genesis)
            .await
            .expect("read")
            .as_deref(),
        Some(b"payload-v10".as_ref())
    );
}

#[tokio::test]
async fn devtree_different_genesis_keys_are_isolated() {
    let pool = fresh_pool().await;
    let genesis_a = unique_name(0x57);
    let genesis_b = unique_name(0x58);
    let a = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis_a,
        1,
        1,
        &[0x11u8; 32],
        b"a-v1",
        10,
    )
    .await
    .expect("a v1");
    let b = db::upsert_device_tree_state_if_monotonic(
        &pool,
        &genesis_b,
        1,
        1,
        &[0x22u8; 32],
        b"b-v1",
        10,
    )
    .await
    .expect("b v1");
    assert_eq!(a, DeviceTreeUpsertOutcome::Inserted);
    assert_eq!(b, DeviceTreeUpsertOutcome::Inserted);
    assert_eq!(
        db::get_device_tree_state_version(&pool, &genesis_a)
            .await
            .expect("read a"),
        Some(1u64)
    );
    assert_eq!(
        db::get_device_tree_state_version(&pool, &genesis_b)
            .await
            .expect("read b"),
        Some(1u64)
    );
}

#[tokio::test]
async fn devtree_get_returns_none_when_absent() {
    let pool = fresh_pool().await;
    let genesis = unique_name(0x59);
    assert_eq!(
        db::get_device_tree_state_version(&pool, &genesis)
            .await
            .expect("read"),
        None
    );
    assert!(db::get_device_tree_state_payload(&pool, &genesis)
        .await
        .expect("read payload")
        .is_none());
}
