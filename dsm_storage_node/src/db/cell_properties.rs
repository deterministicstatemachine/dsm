// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed-cell and index properties of the node's store (Postgres).
//!
//! A member keeps what it is given. Every argument the client builds on a
//! cell read assumes the same things of the store beneath it:
//!
//! 1. every value put at a key is held, in arrival order — nothing is
//!    refused, replaced or compared, and an identical value put twice is
//!    held twice;
//! 2. a key nothing was put under reads as an empty list, not an error;
//! 3. the namespace scopes the key: one key under two namespaces is two cells;
//! 4. an index is append-only and pages in append order from the last `seq`;
//! 5. N concurrent writers on one key lose nothing — the cell holds all N;
//! 6. a value or index entry this node acknowledged is still held after the
//!    store is re-opened;
//! 7. every entry carries its arrival record (storage spec §14): indexes run
//!    1, 2, 3 … per key with no gap or repeat, even under concurrent writers,
//!    and each running hash is exactly what a verifier replays from the
//!    values it reads.
//!
//! They run on the Postgres database `DSM_TEST_DATABASE_URL` names
//! ([`super::test_store`]).

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use super::test_store::{fresh_pool, test_pool, unique_key};
use crate::db;

const NS: &[u8] = b"DSM/cell-properties";

#[tokio::test]
async fn every_value_put_at_a_key_is_held_in_arrival_order() {
    let pool = fresh_pool().await;
    let key = unique_key(0x30);
    for v in [b"one".as_slice(), b"two", b"one"] {
        db::put_cell(&pool, NS, &key, v)
            .await
            .expect("put never refuses");
    }
    assert_eq!(
        db::get_cell_values(&pool, NS, &key).await.expect("read"),
        vec![b"one".to_vec(), b"two".to_vec(), b"one".to_vec()],
        "a second value is kept after the first, and an identical value is held twice"
    );
}

/// PositionPairAtomic at the member: a batch is one transaction. Both keys
/// hold their value after it, or — when an entry names no cell — neither
/// does. Mutation: two separate inserts instead of one transaction, and the
/// first key keeps its value while the batch reports failure.
#[tokio::test]
async fn a_batch_put_lands_every_key_or_none() {
    let pool = fresh_pool().await;
    let (k1, k2) = (unique_key(0x35), unique_key(0x36));
    db::put_cell(&pool, NS, &k1, b"already here")
        .await
        .expect("put");
    db::put_cells(
        &pool,
        &[
            (NS.to_vec(), k1.to_vec(), b"half one".to_vec()),
            (NS.to_vec(), k2.to_vec(), b"half two".to_vec()),
        ],
    )
    .await
    .expect("a batch is a put");
    assert_eq!(
        db::get_cell_values(&pool, NS, &k1).await.expect("read"),
        vec![b"already here".to_vec(), b"half one".to_vec()],
        "after anything already there"
    );
    assert_eq!(
        db::get_cell_values(&pool, NS, &k2).await.expect("read"),
        vec![b"half two".to_vec()]
    );

    let (k3, k4) = (unique_key(0x37), unique_key(0x38));
    let refused = db::put_cells(
        &pool,
        &[
            (NS.to_vec(), k3.to_vec(), b"would be held".to_vec()),
            (Vec::new(), k4.to_vec(), b"names no cell".to_vec()),
        ],
    )
    .await;
    assert!(
        refused.is_err(),
        "an entry that names no cell fails the batch"
    );
    assert!(
        db::get_cell_values(&pool, NS, &k3)
            .await
            .expect("read")
            .is_empty(),
        "the first entry was rolled back with the second: none, not one"
    );
}

#[tokio::test]
async fn a_key_nothing_was_put_under_reads_as_an_empty_list() {
    let pool = fresh_pool().await;
    let key = unique_key(0x31);
    assert!(db::get_cell_values(&pool, NS, &key)
        .await
        .expect("read")
        .is_empty());
}

#[tokio::test]
async fn a_namespace_scopes_the_key() {
    let pool = fresh_pool().await;
    let key = unique_key(0x32);
    db::put_cell(&pool, b"DSM/ns-a", &key, b"in-a")
        .await
        .expect("put");
    db::put_cell(&pool, b"DSM/ns-b", &key, b"in-b")
        .await
        .expect("put");
    assert_eq!(
        db::get_cell_values(&pool, b"DSM/ns-a", &key)
            .await
            .expect("read"),
        vec![b"in-a".to_vec()]
    );
    assert_eq!(
        db::get_cell_values(&pool, b"DSM/ns-b", &key)
            .await
            .expect("read"),
        vec![b"in-b".to_vec()]
    );
    assert!(db::get_cell_values(&pool, NS, &key)
        .await
        .expect("read")
        .is_empty());
}

#[tokio::test]
async fn an_index_pages_in_append_order_from_the_last_seq() {
    let pool = fresh_pool().await;
    let locator = unique_key(0x33);
    for a in [[0xA1u8; 32], [0xA2; 32], [0xA3; 32]] {
        db::append_index(&pool, &locator, &a).await.expect("append");
    }
    let first = db::read_index(&pool, &locator, 0, 2).await.expect("page");
    assert_eq!(first.len(), 2, "at most `limit` entries per page");
    assert!(first[0].0 < first[1].0, "seq grows in append order");
    assert_eq!(first[0].1, vec![0xA1u8; 32]);
    assert_eq!(first[1].1, vec![0xA2u8; 32]);
    let rest = db::read_index(&pool, &locator, first[1].0, 10)
        .await
        .expect("page");
    assert_eq!(
        rest.len(),
        1,
        "paging from the last seq returns only what came after it"
    );
    assert_eq!(rest[0].1, vec![0xA3u8; 32]);
    assert!(db::read_index(&pool, &locator, rest[0].0, 10)
        .await
        .expect("page")
        .is_empty());
    assert!(
        db::read_index(&pool, &unique_key(0x34), 0, 10)
            .await
            .expect("page")
            .is_empty(),
        "an unknown locator is an empty page, not an error"
    );
}

/// Concurrency: the cell is a list, not a slot, so there is no race to win —
/// every writer's value must be held. A store that lost one under contention
/// would let a member silently drop the leader-first copy a client relies on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_on_one_key_lose_nothing() {
    let pool = fresh_pool().await;
    let key = unique_key(0x35);
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            db::put_cell(&pool, NS, &key, &[i; 40])
                .await
                .expect("put never refuses");
        }));
    }
    for h in handles {
        h.await.expect("writer");
    }
    let mut held = db::get_cell_values(&pool, NS, &key).await.expect("read");
    held.sort();
    let expected: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i; 40]).collect();
    assert_eq!(
        held, expected,
        "all sixteen values are held, none twice, none lost"
    );
}

/// Restart persistence: after the store is re-opened — a fresh pool on the
/// same database — the cell and the index still hold what this node
/// acknowledged.
#[tokio::test]
async fn held_values_and_index_entries_survive_reopening_the_store() {
    let key = unique_key(0x36);
    let locator = unique_key(0x37);
    {
        let pool = test_pool();
        db::init_db(&pool).await.expect("init");
        db::put_cell(&pool, NS, &key, b"kept").await.expect("put");
        db::append_index(&pool, &locator, &[0xB1; 32])
            .await
            .expect("append");
    }
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    assert_eq!(
        db::get_cell_values(&pool, NS, &key).await.expect("read"),
        vec![b"kept".to_vec()]
    );
    let page = db::read_index(&pool, &locator, 0, 10).await.expect("page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].1, vec![0xB1u8; 32]);
}

/// Arrival records: what a put returns is what a get reports, and both are
/// exactly the verifier's replay of the values (storage spec §14).
#[tokio::test]
async fn arrival_records_match_the_verifiers_replay() {
    let pool = fresh_pool().await;
    let key = unique_key(0x38);
    let mut returned = Vec::new();
    for v in [b"one".as_slice(), b"two", b"two"] {
        returned.push(db::put_cell(&pool, NS, &key, v).await.expect("put"));
    }
    let entries = db::get_cell_entries(&pool, NS, &key).await.expect("read");
    let values: Vec<Vec<u8>> = entries.iter().map(|(v, _, _)| v.clone()).collect();
    let reported: Vec<(u64, [u8; 32])> = entries.iter().map(|(_, i, h)| (*i, *h)).collect();
    let replayed = dsm::storage_cell::replay(NS, &key, &values);
    assert_eq!(returned, replayed, "put returns the replayed record");
    assert_eq!(reported, replayed, "get reports the replayed record");
    assert_eq!(
        replayed.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

/// A batch put returns one record per entry, each continuing its own key.
#[tokio::test]
async fn a_batch_put_returns_each_entrys_record() {
    let pool = fresh_pool().await;
    let (k1, k2) = (unique_key(0x39), unique_key(0x3A));
    db::put_cell(&pool, NS, &k1, b"before").await.expect("put");
    let records = db::put_cells(
        &pool,
        &[
            (NS.to_vec(), k1.to_vec(), b"a".to_vec()),
            (NS.to_vec(), k2.to_vec(), b"b".to_vec()),
        ],
    )
    .await
    .expect("batch");
    assert_eq!(
        records[0],
        dsm::storage_cell::replay(NS, &k1, &[b"before".to_vec(), b"a".to_vec()])[1]
    );
    assert_eq!(
        records[1],
        dsm::storage_cell::replay(NS, &k2, &[b"b".to_vec()])[0]
    );
}

/// Under contention every writer still gets a distinct index, the indexes
/// are exactly 1..=N, and the records replay: no two entries share a slot in
/// the arrival order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_get_consecutive_arrival_indexes() {
    let pool = fresh_pool().await;
    let key = unique_key(0x3B);
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            db::put_cell(&pool, NS, &key, &[i; 40]).await.expect("put")
        }));
    }
    let mut indexes = Vec::new();
    for h in handles {
        indexes.push(h.await.expect("writer").0);
    }
    indexes.sort();
    assert_eq!(indexes, (1..=16).collect::<Vec<u64>>());
    let entries = db::get_cell_entries(&pool, NS, &key).await.expect("read");
    let values: Vec<Vec<u8>> = entries.iter().map(|(v, _, _)| v.clone()).collect();
    let reported: Vec<(u64, [u8; 32])> = entries.iter().map(|(_, i, h)| (*i, *h)).collect();
    assert_eq!(reported, dsm::storage_cell::replay(NS, &key, &values));
}

/// ByteCommits on the compiled backend (storage spec §14): cycles close only
/// over new entries, link to their parent, and prove exactly the entries
/// they committed; the mirror keeps every distinct ByteCommit it is given.
#[tokio::test]
async fn bytecommits_close_link_and_prove_on_this_backend() {
    let pool = fresh_pool().await;
    let member = b"dsm-node-props";
    let key = unique_key(0x3C);
    // Other tests share this store: first flush whatever they left pending.
    let base = db::close_cycle(&pool, member).await.expect("flush");

    let r1 = db::put_cell(&pool, NS, &key, b"one").await.expect("put");
    let c1 = db::close_cycle(&pool, member)
        .await
        .expect("close")
        .expect("a cycle");
    if let Some(b) = &base {
        assert!(c1.follows(b), "the new cycle links to the one before");
    }
    let values = db::get_cell_values(&pool, NS, &key).await.expect("read");
    let p1 = db::cell_commit_proof(&pool, NS, &key, c1.cycle_index)
        .await
        .expect("proof")
        .expect("committed");
    let rec = dsm::storage_cell::ArrivalRecord {
        member_id: member.to_vec(),
        namespace: NS.to_vec(),
        key,
        index: r1.0,
        running_hash: r1.1,
    };
    assert!(dsm::storage_cell::record_is_committed(
        &rec, &values, &c1, &p1
    ));
    assert_eq!(
        db::get_own_bytecommit(&pool, Some(c1.cycle_index))
            .await
            .expect("read"),
        Some(c1.clone())
    );

    assert!(db::mirror_put(&pool, &c1).await.expect("mirror"), "new");
    assert!(
        !db::mirror_put(&pool, &c1).await.expect("again"),
        "identical bytes are held once"
    );
    let mut forked = c1.clone();
    forked.smt_root = [0xEE; 32];
    assert!(
        db::mirror_put(&pool, &forked).await.expect("fork"),
        "a different one is new"
    );
    let mirrored = db::mirror_get(&pool, member, c1.cycle_index)
        .await
        .expect("read");
    assert_eq!(
        mirrored.len(),
        2,
        "identical bytes once, an equivocation kept beside it"
    );
    assert!(db::mirror_last_cycle(&pool, member).await.expect("last") >= c1.cycle_index);
}

/// Batches over the same keys in opposite orders all complete: a member
/// takes a write's cell locks in one global order, so two batches queue
/// rather than deadlock (on Postgres a deadlock aborts one of them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opposite_order_batches_over_the_same_keys_all_complete() {
    let pool = fresh_pool().await;
    let (k1, k2) = (unique_key(0x3D), unique_key(0x3E));
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let pool = pool.clone();
        let (a, b) = if i % 2 == 0 { (k1, k2) } else { (k2, k1) };
        handles.push(tokio::spawn(async move {
            db::put_cells(
                &pool,
                &[
                    (NS.to_vec(), a.to_vec(), vec![i; 8]),
                    (NS.to_vec(), b.to_vec(), vec![i; 8]),
                ],
            )
            .await
        }));
    }
    for h in handles {
        h.await.expect("writer").expect("every batch completes");
    }
    for k in [k1, k2] {
        let entries = db::get_cell_entries(&pool, NS, &k).await.expect("read");
        assert_eq!(entries.len(), 16);
    }
}

/// Rows a binary from before arrival records wrote, before and after one
/// the current binary recorded, all get exactly the record their arrival
/// order defines when the store is initialised (storage spec §14), with no
/// collision on the arrival index; a cycle then closes over them and proves
/// the latest.
#[tokio::test]
async fn unrecorded_rows_get_the_records_their_arrival_order_defines() {
    let pool = fresh_pool().await;
    let key = unique_key(0x3F);
    db::insert_cell_without_record(&pool, NS, &key, b"old-1")
        .await
        .expect("old row");
    db::put_cell(&pool, NS, &key, b"new-2").await.expect("put");
    db::insert_cell_without_record(&pool, NS, &key, b"old-3")
        .await
        .expect("old row");
    db::init_db(&pool).await.expect("init records every row");

    let entries = db::get_cell_entries(&pool, NS, &key).await.expect("read");
    let values: Vec<Vec<u8>> = entries.iter().map(|(v, _, _)| v.clone()).collect();
    assert_eq!(
        values,
        vec![b"old-1".to_vec(), b"new-2".to_vec(), b"old-3".to_vec()]
    );
    let reported: Vec<(u64, [u8; 32])> = entries.iter().map(|(_, i, h)| (*i, *h)).collect();
    assert_eq!(reported, dsm::storage_cell::replay(NS, &key, &values));

    let member = b"dsm-node-props";
    let c = db::close_cycle(&pool, member)
        .await
        .expect("close")
        .expect("a cycle");
    let p = db::cell_commit_proof(&pool, NS, &key, c.cycle_index)
        .await
        .expect("proof")
        .expect("committed");
    assert_eq!((p.index, p.running_hash), reported[2]);
    assert!(p.verifies(&c, NS, &key));
}
