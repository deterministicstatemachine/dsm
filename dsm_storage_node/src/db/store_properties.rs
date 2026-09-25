// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable-object properties of the node's store, on the
//! Postgres database `DSM_TEST_DATABASE_URL` names ([`super::test_store`]).
//! Every test addresses rows of its own.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use super::test_store::{fresh_pool, unique_name};
use crate::db::{self, ImmutablePutOutcome};

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

    let first = db::insert_immutable_object_if_absent(&pool, &addr, &ns, &payload)
        .await
        .expect("insert");
    assert_eq!(first, ImmutablePutOutcome::Inserted);

    let replay = db::insert_immutable_object_if_absent(&pool, &addr, &ns, &payload)
        .await
        .expect("replay");
    assert_eq!(replay, ImmutablePutOutcome::AlreadyExistsIdentical);

    let other_payload = db::insert_immutable_object_if_absent(&pool, &addr, &ns, b"different")
        .await
        .expect("query");
    assert_eq!(other_payload, ImmutablePutOutcome::Conflict);

    let other_ns = db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/genesis/v3", &payload)
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
    db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/vault-state", b"first")
        .await
        .expect("insert");
    let second = db::insert_immutable_object_if_absent(&pool, &addr, b"DSM/vault-state", b"second")
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
