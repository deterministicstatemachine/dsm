// SPDX-License-Identifier: MIT OR Apache-2.0

//! Write-once register properties, ON WHICHEVER BACKEND IS COMPILED.
//!
//! This node serves three one-shot registers — the settlement slot, the
//! faucet ticket, and the economic root — and every economic argument built
//! on them assumes the same four things of each cell:
//!
//! 1. the first bytes accepted are the bytes the cell holds;
//! 2. re-submitting those exact bytes re-acks rather than refusing;
//! 3. different bytes are refused, and the refusal names the HELD digest;
//! 4. N concurrent racers on one cell produce exactly one acceptance, and
//!    every loser is refused with the one winner's digest.
//!
//! Plus a fifth that is about the store rather than the transaction: a claim
//! this node acknowledged is still held after the database is re-opened.
//!
//! These properties used to be asserted only under `feature = "local-dev"`,
//! which meant they only ever executed against SQLite while production runs
//! Postgres — a safety property is not proven on a backend that never ran it.
//! The pool now comes from `DSM_TEST_DATABASE_URL`, and CI runs this file
//! against a real Postgres server as well as the in-memory default.

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
        "DSM_TEST_DATABASE_URL must name a Postgres database: these are the write-once \
         register properties for the SHIPPED backend, and skipping them would report a \
         green board that never executed it",
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
/// for one write-once cell and pass or fail by ordering.
pub(crate) fn unique_key(tag: u8) -> [u8; 32] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut id = [0u8; 32];
    id[0] = tag;
    id[1..5].copy_from_slice(&std::process::id().to_le_bytes()[..4]);
    id[5..13].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    id
}

/// The one outcome vocabulary these properties are stated in. The settlement
/// register keeps its own historical enum and the other two share
/// `OneShotOutcome`; both collapse to the same three answers, and stating the
/// properties once over this enum is what keeps the three registers honest
/// against each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Accepted,
    Reack,
    Refused(Vec<u8>),
}

impl From<db::SlotClaimOutcome> for Outcome {
    fn from(o: db::SlotClaimOutcome) -> Self {
        match o {
            db::SlotClaimOutcome::Accepted => Outcome::Accepted,
            db::SlotClaimOutcome::AlreadyHeldIdentical => Outcome::Reack,
            db::SlotClaimOutcome::Refused { held_digest } => Outcome::Refused(held_digest),
        }
    }
}

impl From<db::OneShotOutcome> for Outcome {
    fn from(o: db::OneShotOutcome) -> Self {
        match o {
            db::OneShotOutcome::Accepted => Outcome::Accepted,
            db::OneShotOutcome::AlreadyHeldIdentical => Outcome::Reack,
            db::OneShotOutcome::Refused { held_digest } => Outcome::Refused(held_digest),
        }
    }
}

/// State the five properties once, for a register described by a `claim` and
/// a `held` accessor over a 32-byte cell key.
///
/// `$tag` distinguishes the register's keys in a shared Postgres database;
/// `$claim` and `$held` are expressions over `pool`, `key`, `bytes`, `digest`.
macro_rules! write_once_register {
    (
        $module:ident,
        tag = $tag:expr,
        claim = |$pool:ident, $key:ident, $bytes:ident, $digest:ident| $claim:expr,
        held = |$hpool:ident, $hkey:ident| $held:expr,
    ) => {
        mod $module {
            use super::*;

            /// One write-once attempt on the cell named by `key`.
            async fn claim(
                $pool: &db::DBPool,
                $key: &[u8],
                $bytes: &[u8],
                $digest: &[u8],
            ) -> Outcome {
                Outcome::from($claim.await.expect("claim"))
            }

            /// The `(bytes, digest)` the cell holds, if any.
            async fn held($hpool: &db::DBPool, $hkey: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                $held.await.expect("read")
            }

            #[tokio::test]
            async fn first_bytes_win_identical_reacks_different_refused() {
                let key = unique_key($tag);
                let pool = test_pool();
                db::init_db(&pool).await.expect("init");
                let a = b"claim-A".to_vec();
                let b = b"claim-B".to_vec();
                let da = *blake3::hash(&a).as_bytes();
                let db_ = *blake3::hash(&b).as_bytes();

                assert_eq!(claim(&pool, &key, &a, &da).await, Outcome::Accepted);
                assert_eq!(
                    claim(&pool, &key, &a, &da).await,
                    Outcome::Reack,
                    "the exact held bytes re-ack rather than refuse"
                );
                assert_eq!(
                    claim(&pool, &key, &b, &db_).await,
                    Outcome::Refused(da.to_vec()),
                    "different bytes are refused, and the refusal names the HELD digest"
                );

                // A different cell is independent of this one.
                let other = unique_key($tag);
                assert_eq!(claim(&pool, &other, &b, &db_).await, Outcome::Accepted);

                let (bytes, digest) = held(&pool, &key).await.expect("held");
                assert_eq!(bytes, a, "the cell holds the first accepted bytes");
                assert_eq!(digest, da.to_vec());
            }

            /// N racers with different bytes for one cell: exactly one
            /// accepted, every other refused with the winner's digest. The
            /// write is one atomic transaction over the unique key — never
            /// check-then-insert.
            #[tokio::test]
            async fn concurrent_racers_on_one_cell_yield_exactly_one_acceptance() {
                let key = unique_key($tag);
                let pool = test_pool();
                db::init_db(&pool).await.expect("init");
                let mut handles = Vec::new();
                for i in 0..16u8 {
                    let pool = pool.clone();
                    handles.push(tokio::spawn(async move {
                        let bytes = vec![i; 40];
                        let d = *blake3::hash(&bytes).as_bytes();
                        claim(&pool, &key, &bytes, &d).await
                    }));
                }
                let mut accepted = 0;
                let mut refused_digests = std::collections::BTreeSet::new();
                for h in handles {
                    match h.await.expect("racer") {
                        Outcome::Accepted => accepted += 1,
                        Outcome::Refused(held_digest) => {
                            refused_digests.insert(held_digest);
                        }
                        Outcome::Reack => panic!("distinct bytes cannot be identical"),
                    }
                }
                assert_eq!(accepted, 1, "exactly one racer wins the cell");
                assert_eq!(
                    refused_digests.len(),
                    1,
                    "every loser is refused with THE winner's digest"
                );
                let (_, digest) = held(&pool, &key).await.expect("held");
                assert_eq!(refused_digests.into_iter().next().unwrap(), digest);
            }

            /// Restart persistence: after the store is re-opened — a fresh
            /// SQLite connection on the same file, a fresh pool on the same
            /// Postgres database — A still holds and B is still refused. An
            /// acknowledgement this node gave is a promise it keeps across a
            /// restart, which is what `synchronous_commit = on` /
            /// `PRAGMA synchronous=FULL` buys at claim time.
            #[tokio::test]
            async fn a_held_claim_survives_reopening_the_store() {
                let key = unique_key($tag);
                let path = std::env::temp_dir()
                    .join(format!("dsm-write-once-{}", stringify!($module)))
                    .to_string_lossy()
                    .to_string();
                let _ = std::fs::remove_file(&path);
                let a = b"claim-A".to_vec();
                let da = *blake3::hash(&a).as_bytes();
                {
                    let pool = reopenable_pool(&path);
                    db::init_db(&pool).await.expect("init");
                    assert_eq!(claim(&pool, &key, &a, &da).await, Outcome::Accepted);
                }
                let pool = reopenable_pool(&path);
                db::init_db(&pool).await.expect("init");
                let b = b"claim-B".to_vec();
                let db_ = *blake3::hash(&b).as_bytes();
                assert_eq!(
                    claim(&pool, &key, &b, &db_).await,
                    Outcome::Refused(da.to_vec()),
                    "B is still refused after the store is re-opened"
                );
                assert_eq!(
                    claim(&pool, &key, &a, &da).await,
                    Outcome::Reack,
                    "A still re-acks after the store is re-opened"
                );
                let _ = std::fs::remove_file(&path);
            }
        }
    };
}

write_once_register!(
    settlement_slot,
    tag = 0x11,
    claim = |pool, key, bytes, digest| db::claim_settlement_slot(
        pool,
        key,
        7,
        bytes,
        digest,
        b"pk",
        &[0x6B; 32]
    ),
    held = |pool, key| db::get_settlement_slot_claim(pool, key, 7),
);

write_once_register!(
    faucet_ticket,
    tag = 0x22,
    claim = |pool, key, bytes, digest| db::claim_faucet_ticket(
        pool,
        key,
        3,
        bytes,
        digest,
        b"pk",
        &[0x6B; 32]
    ),
    held = |pool, key| db::get_faucet_ticket_claim(pool, key, 3),
);

write_once_register!(
    economic_root,
    tag = 0x33,
    claim = |pool, key, bytes, digest| db::claim_economic_root(
        pool,
        key,
        bytes,
        digest,
        b"pk",
        &[0x6B; 32]
    ),
    held = |pool, key| db::get_economic_root_claim(pool, key),
);
