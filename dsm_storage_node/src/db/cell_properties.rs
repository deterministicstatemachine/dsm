// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed-cell and index properties, ON WHICHEVER BACKEND IS COMPILED.
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
//!    store is re-opened.
//!
//! The pool comes from `DSM_TEST_DATABASE_URL`, so CI runs this file against
//! a real Postgres server as well as the in-memory default; a property of the
//! shipped store is not proven on a backend that never executed it.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use crate::db;

/// The backend under test.
///
/// SQLite has an in-process default (`:memory:`), so a plain `cargo test`
/// behaves as before. Postgres has none: a Postgres build with no server is
/// not a backend, and a suite that quietly passed without one would report a
/// green board that never executed the shipped store. So the Postgres build
/// REFUSES rather than skips.
pub(crate) fn test_pool() -> db::DBPool {
    db::create_pool(&test_database_url(), true).expect("pool")
}

#[cfg(feature = "local-dev")]
fn test_database_url() -> String {
    std::env::var("DSM_TEST_DATABASE_URL").unwrap_or_else(|_| ":memory:".to_string())
}

#[cfg(not(feature = "local-dev"))]
fn test_database_url() -> String {
    std::env::var("DSM_TEST_DATABASE_URL").expect(
        "DSM_TEST_DATABASE_URL must name a Postgres database: these are the cell and index \
         properties for the SHIPPED backend, and skipping them would report a green board \
         that never executed it",
    )
}

/// A pool that can be closed and re-opened over the SAME durable store — a
/// temp file on SQLite, the configured server on Postgres. The restart
/// property needs both opens to see one store; on Postgres the path is
/// ignored because the server IS the store.
#[cfg(feature = "local-dev")]
pub(crate) fn reopenable_pool(path: &str) -> db::DBPool {
    db::create_pool(path, true).expect("pool")
}

#[cfg(not(feature = "local-dev"))]
pub(crate) fn reopenable_pool(_path: &str) -> db::DBPool {
    test_pool()
}

/// A cell key unique to this test process and call site. Postgres keeps ONE
/// database for the whole run, so a fixed key would make two tests contend
/// for one cell and pass or fail by ordering.
pub(crate) fn unique_key(tag: u8) -> [u8; 32] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut id = [0u8; 32];
    id[0] = tag;
    id[1..5].copy_from_slice(&std::process::id().to_le_bytes()[..4]);
    id[5..13].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    id
}

const NS: &[u8] = b"DSM/cell-properties";

async fn fresh_pool() -> db::DBPool {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    pool
}

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

/// Restart persistence: after the store is re-opened — a fresh SQLite
/// connection on the same file, a fresh pool on the same Postgres database —
/// the cell and the index still hold what this node acknowledged.
#[tokio::test]
async fn held_values_and_index_entries_survive_reopening_the_store() {
    let key = unique_key(0x36);
    let locator = unique_key(0x37);
    let path = std::env::temp_dir()
        .join("dsm-cell-properties-reopen")
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);
    {
        let pool = reopenable_pool(&path);
        db::init_db(&pool).await.expect("init");
        db::put_cell(&pool, NS, &key, b"kept").await.expect("put");
        db::append_index(&pool, &locator, &[0xB1; 32])
            .await
            .expect("append");
    }
    let pool = reopenable_pool(&path);
    db::init_db(&pool).await.expect("init");
    assert_eq!(
        db::get_cell_values(&pool, NS, &key).await.expect("read"),
        vec![b"kept".to_vec()]
    );
    let page = db::read_index(&pool, &locator, 0, 10).await.expect("page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].1, vec![0xB1u8; 32]);
    let _ = std::fs::remove_file(&path);
}
