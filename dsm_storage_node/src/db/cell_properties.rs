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
    let closing = db::CommittedCells::default();
    let base = db::close_cycle(&pool, &closing, member)
        .await
        .expect("flush");

    let r1 = db::put_cell(&pool, NS, &key, b"one").await.expect("put");
    let c1 = db::close_cycle(&pool, &closing, member)
        .await
        .expect("close")
        .expect("a cycle");
    if let Some(b) = &base {
        assert!(c1.follows(b), "the new cycle links to the one before");
    }
    let values = db::get_cell_values(&pool, NS, &key).await.expect("read");
    let p1 = db::cell_commit_proof(&pool, &closing, NS, &key, c1.cycle_index)
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

// ── what a node keeps of its closed cycles ─────────────────────────────────
//
// A close applies only the entries it stamps to the leaf set it kept, and a
// proof reads a kept tree. Each is checked against the computation it
// replaced: every cell's latest committed entry read whole from the store,
// the tree built from all of them, and the bytes summed over every row.

/// The root and bytes a close computed before it kept anything: the tree
/// over every cell's latest entry stamped at or before `cycle`, and every
/// byte the store holds.
async fn rebuilt_root_and_bytes(pool: &db::DBPool, cycle: u64) -> ([u8; 32], u64) {
    let client = pool.get().await.expect("connection");
    let rows = client
        .query(
            "SELECT DISTINCT ON (namespace, cell_key)
                    namespace, cell_key, arrival_index, running_hash
             FROM cells WHERE committed_cycle <= $1
             ORDER BY namespace, cell_key, arrival_index DESC",
            &[&i64::try_from(cycle).expect("cycle")],
        )
        .await
        .expect("leaves");
    let leaves: Vec<super::committed::CellLeaf> = rows
        .iter()
        .map(|r| {
            let key: Vec<u8> = r.get(1);
            let hash: Vec<u8> = r.get(3);
            (
                r.get(0),
                key.try_into().expect("32-byte key"),
                u64::try_from(r.get::<_, i64>(2)).expect("index"),
                hash.try_into().expect("32-byte hash"),
            )
        })
        .collect();
    let root =
        *dsm::storage_cell::cell_tree(leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)))
            .root();
    let bytes: i64 = client
        .query_one(
            "SELECT COALESCE((SELECT SUM(LENGTH(value)) FROM cells), 0)::BIGINT
                  + COALESCE((SELECT SUM(LENGTH(payload)) FROM immutable_objects), 0)::BIGINT",
            &[],
        )
        .await
        .expect("bytes")
        .get(0);
    (root, u64::try_from(bytes).expect("bytes"))
}

/// A proof's wire bytes, as the proof route answers them.
async fn proof_bytes(
    pool: &db::DBPool,
    node: &db::CommittedCells,
    namespace: &[u8],
    key: &[u8; 32],
    cycle: u64,
) -> Option<Vec<u8>> {
    use prost::Message;
    db::cell_commit_proof(pool, node, namespace, key, cycle)
        .await
        .expect("proof")
        .map(|p| p.to_proto().encode_to_vec())
}

/// Close with `node` and check the ByteCommit against the full rebuild.
async fn close_and_check(
    pool: &db::DBPool,
    node: &db::CommittedCells,
    member: &[u8],
) -> dsm::storage_cell::ByteCommit {
    let commit = db::close_cycle(pool, node, member)
        .await
        .expect("close")
        .expect("a cycle");
    let (root, bytes) = rebuilt_root_and_bytes(pool, commit.cycle_index).await;
    assert_eq!(
        commit.smt_root, root,
        "cycle {}: the root is the full rebuild's",
        commit.cycle_index
    );
    assert_eq!(
        commit.bytes_used, bytes,
        "cycle {}: the bytes are every row's",
        commit.cycle_index
    );
    commit
}

/// Over cycles that add cells, overwrite them (one twice within a cycle),
/// use a second namespace and add immutable objects, every ByteCommit a
/// node closes from the leaf set it kept has the root and bytes the full
/// rebuild computes, from the first cycle on, and every proof it answers
/// from a kept tree, for every cycle closed so far, is byte for byte the
/// proof built from the store.
#[tokio::test]
async fn a_kept_leaf_set_closes_and_proves_exactly_what_a_full_rebuild_does() {
    let (pool, admin, schema) = super::schema_properties::isolated_schema(0x3F).await;
    db::init_db(&pool).await.expect("init");
    const OTHER: &[u8] = b"DSM/cell-properties-other";
    let node = db::CommittedCells::default();
    let keys: Vec<[u8; 32]> = (0..24).map(|_| unique_key(0x3F)).collect();
    let never_put = unique_key(0x3F);
    let mut closed = Vec::new();
    for round in 0..6usize {
        if round == 0 {
            for (i, k) in keys.iter().enumerate() {
                db::put_cell(&pool, NS, k, &vec![i as u8; 10 + i])
                    .await
                    .expect("put");
            }
        } else {
            for (i, k) in keys.iter().enumerate().filter(|(i, _)| i % 5 == round % 5) {
                db::put_cell(&pool, NS, k, &vec![round as u8; round * 7 + i])
                    .await
                    .expect("overwrite");
            }
            for v in [b"first of two".as_slice(), b"second of two"] {
                db::put_cell(&pool, NS, &keys[round], v)
                    .await
                    .expect("twice");
            }
            db::put_cell(&pool, OTHER, &keys[round], b"other namespace")
                .await
                .expect("put");
            db::insert_immutable_object_if_absent(
                &pool,
                &super::test_store::unique_name(0x3F),
                NS,
                &vec![round as u8; 100 * round],
            )
            .await
            .expect("immutable");
        }
        let commit = close_and_check(&pool, &node, b"dsm-node-kept").await;
        assert_eq!(commit.cycle_index, round as u64 + 1);
        assert!(
            node.kept_cycles().contains(&commit.cycle_index),
            "the node keeps the tree it closed"
        );
        closed.push(commit.cycle_index);
        for cycle in &closed {
            for k in keys[..7].iter().chain([&never_put]) {
                for ns in [NS, OTHER] {
                    let kept = proof_bytes(&pool, &node, ns, k, *cycle).await;
                    let rebuilt =
                        proof_bytes(&pool, &db::CommittedCells::default(), ns, k, *cycle).await;
                    assert_eq!(kept, rebuilt, "cycle {cycle}: the kept tree's proof");
                }
            }
        }
    }
    assert_eq!(
        proof_bytes(&pool, &node, NS, &keys[0], 7).await,
        None,
        "a cycle that never closed has no proof"
    );
    super::schema_properties::drop_schema(&admin, &schema).await;
}

/// Two processes closing on one database: a node whose kept leaf set is as
/// of a ByteCommit that is no longer the latest reads the store again, so
/// each close — the second process's first (a restart's) included — has the
/// root and bytes of the full rebuild.
#[tokio::test]
async fn a_closer_reads_the_store_again_when_another_closed_since() {
    let (pool, admin, schema) = super::schema_properties::isolated_schema(0x40).await;
    db::init_db(&pool).await.expect("init");
    let (a, b) = (db::CommittedCells::default(), db::CommittedCells::default());
    let keys: Vec<[u8; 32]> = (0..8).map(|_| unique_key(0x40)).collect();
    // a, a, b, a, b, b, a: each closer both continues its own leaf set and
    // finds the other's cycles.
    for (round, node) in [&a, &a, &b, &a, &b, &b, &a].into_iter().enumerate() {
        for k in keys.iter().skip(round % 3).step_by(2) {
            db::put_cell(&pool, NS, k, format!("round {round}").as_bytes())
                .await
                .expect("put");
        }
        let commit = close_and_check(&pool, node, b"dsm-node-shared").await;
        assert_eq!(commit.cycle_index, round as u64 + 1);
    }
    super::schema_properties::drop_schema(&admin, &schema).await;
}

/// A kept tree answers only for the ByteCommit it was kept for: when the
/// store's ByteCommit at that cycle is another (the database was
/// reprovisioned under a running process), the proof is built from the
/// store, as it was before anything was kept.
#[tokio::test]
async fn a_kept_tree_answers_only_for_the_byte_commit_it_was_kept_for() {
    let (pool, admin, schema) = super::schema_properties::isolated_schema(0x41).await;
    db::init_db(&pool).await.expect("init");
    let key = unique_key(0x41);
    let a = db::CommittedCells::default();
    db::put_cell(&pool, NS, &key, b"before").await.expect("put");
    let first = close_and_check(&pool, &a, b"dsm-node-reset").await;
    assert!(proof_bytes(&pool, &a, NS, &key, 1).await.is_some());

    pool.get()
        .await
        .expect("connection")
        .batch_execute("DELETE FROM own_bytecommits; DELETE FROM cells;")
        .await
        .expect("reprovision");
    db::put_cell(&pool, NS, &key, b"after").await.expect("put");
    let b = db::CommittedCells::default();
    let second = close_and_check(&pool, &b, b"dsm-node-reset").await;
    assert_eq!(second.cycle_index, first.cycle_index);
    assert_ne!(second, first);

    assert_eq!(
        proof_bytes(&pool, &a, NS, &key, 1).await,
        proof_bytes(&pool, &db::CommittedCells::default(), NS, &key, 1).await,
        "the tree kept for the first cycle 1 does not answer for the second"
    );
    db::put_cell(&pool, NS, &key, b"later").await.expect("put");
    close_and_check(&pool, &a, b"dsm-node-reset").await;
    super::schema_properties::drop_schema(&admin, &schema).await;
}

/// A node keeps the newest cycles' trees within both bounds, and always the
/// newest, however large.
#[test]
fn kept_trees_are_the_newest_within_the_bounds() {
    use std::sync::Arc;
    let tree = |leaves: u8| {
        Arc::new(
            dsm::merkle::sparse_merkle_tree::SparseMerkleTree::from_leaves(
                (0..leaves).map(|i| ([i; 32], [i; 32])),
            ),
        )
    };
    let by_cycles = db::CommittedCells::bounded(4, 100);
    let by_leaves = db::CommittedCells::bounded(4, 10);
    for cycle in 1..=6u64 {
        by_cycles.keep(cycle, [cycle as u8; 32], tree(3));
        by_leaves.keep(cycle, [cycle as u8; 32], tree(3));
    }
    assert_eq!(by_cycles.kept_cycles(), vec![3, 4, 5, 6]);
    assert_eq!(by_leaves.kept_cycles(), vec![4, 5, 6], "9 leaves, not 12");
    by_leaves.keep(7, [7; 32], tree(20));
    assert_eq!(by_leaves.kept_cycles(), vec![7], "the newest stays");
    assert!(by_leaves.tree_at(7, &[7; 32]).is_some());
    assert!(
        by_leaves.tree_at(7, &[8; 32]).is_none(),
        "kept for another ByteCommit"
    );
}
