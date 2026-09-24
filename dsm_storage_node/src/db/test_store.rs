// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Postgres database the node's unit tests run on, named by
//! `DSM_TEST_DATABASE_URL`. With no server named a test REFUSES rather than
//! skips: a suite that passed without one would report a green board that
//! never executed the store.
//!
//! The database outlives the run — CI keeps one for the job, a developer's
//! server keeps its rows between runs — so every test addresses rows of its
//! own ([`unique_key`], [`unique_name`]).

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use crate::db;

/// A pool on the database under test, schema not yet initialized.
pub(crate) fn test_pool() -> db::DBPool {
    let url = std::env::var("DSM_TEST_DATABASE_URL").expect(
        "DSM_TEST_DATABASE_URL must name a Postgres database: the node's store is Postgres, \
         and skipping these tests would report a green board that never executed it",
    );
    db::create_pool(&url).expect("pool")
}

/// A pool on the database under test, schema initialized.
pub(crate) async fn fresh_pool() -> db::DBPool {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    pool
}

/// A key no other call has used: `tag`, a per-process counter and random
/// bytes, so neither another test nor an earlier run's rows can collide.
pub(crate) fn unique_key(tag: u8) -> [u8; 32] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut id = [0u8; 32];
    id[0] = tag;
    id[1..9].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    id[9..].copy_from_slice(&rand::random::<[u8; 23]>());
    id
}

/// [`unique_key`] as Base32, for tables keyed by text.
pub(crate) fn unique_name(tag: u8) -> String {
    dsm_sdk::util::text_id::encode_base32_crockford(&unique_key(tag))
}
