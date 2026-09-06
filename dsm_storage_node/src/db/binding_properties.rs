// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic conditional-binding properties, ON WHICHEVER BACKEND IS
//! COMPILED (SoFi Rev 15 Req 15.6, 15.9, 15.11): all-or-none over a key set,
//! exactly one winner among concurrent exchanges from the same expectation,
//! rounds that only move forward, overlapping key sets that serialise, and
//! a record set that survives re-opening the store. CI executes this file
//! against a real Postgres as well as the in-memory default; the Postgres
//! build refuses to run without `DSM_TEST_DATABASE_URL` rather than skipping.

#![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests

use crate::db;
use crate::db::write_once_properties::{reopenable_pool, test_pool, unique_key};
use dsm::storage::binding_record::{
    empty_set_digest, keyset_digest, BindingRecord, Round, BINDING_RECORD_SCHEMA_V1,
};

fn keys(tag: u8, n: usize) -> Vec<[u8; 32]> {
    let mut k: Vec<[u8; 32]> = (0..n).map(|_| unique_key(tag)).collect();
    k.sort();
    k
}

fn record(keys: &[[u8; 32]], counter: u64, proposer: u8, value: u8) -> (Vec<u8>, [u8; 32], Round) {
    let r = BindingRecord {
        schema: BINDING_RECORD_SCHEMA_V1,
        round: Round {
            counter,
            proposer_id: [proposer; 32],
        },
        tx_id: [0xAA; 32],
        keyset_digest: keyset_digest(keys),
        value_digest: [value; 32],
        value_addr: [value; 32],
        status: 1,
    };
    (r.encode(), r.digest(), r.round)
}

async fn cas(
    pool: &db::DBPool,
    keys: &[[u8; 32]],
    expected: [u8; 32],
    rec: &(Vec<u8>, [u8; 32], Round),
) -> db::CasOutcome {
    db::compare_exchange_many(pool, keys, &expected, &rec.0, &rec.1, rec.2)
        .await
        .expect("cas")
}

/// All-or-none: a set whose expectation is wrong on ONE key applies to NONE,
/// and the keys already held keep their record.
#[tokio::test]
async fn an_exchange_applies_to_every_key_or_to_none() {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    let ks = keys(0x61, 3);
    // Seed only the middle key so the set is partially held.
    let seed = record(&ks[1..2], 1, 1, 0x11);
    assert!(matches!(
        cas(&pool, &ks[1..2], empty_set_digest(&ks[1..2]), &seed).await,
        db::CasOutcome::Applied { .. }
    ));
    // A caller who expects the whole set empty is refused; nothing changes.
    let a = record(&ks, 2, 2, 0xA1);
    let out = cas(&pool, &ks, empty_set_digest(&ks), &a).await;
    assert!(matches!(out, db::CasOutcome::ExpectationMismatch { .. }));
    let held = db::read_bindings(&pool, &ks).await.expect("read");
    assert!(
        held[0].is_none() && held[2].is_none(),
        "unheld keys stay unheld"
    );
    assert_eq!(
        held[1].as_ref().unwrap().record_bytes,
        seed.0,
        "the held key keeps its record"
    );
    // With the true expectation (the read's digest) and a higher round, ALL
    // three keys change together.
    let db::CasOutcome::ExpectationMismatch { current_digest } = out else {
        unreachable!()
    };
    assert!(matches!(
        cas(&pool, &ks, current_digest, &a).await,
        db::CasOutcome::Applied { .. }
    ));
    let held = db::read_bindings(&pool, &ks).await.expect("read");
    assert!(held
        .iter()
        .all(|h| h.as_ref().map(|b| b.record_bytes == a.0).unwrap_or(false)));
}

/// N racers exchanging from the same (empty) expectation with distinct
/// values: exactly one is APPLIED; every other is refused with the winner's
/// resulting digest, and a read agrees.
#[tokio::test]
async fn concurrent_exchanges_from_one_expectation_yield_exactly_one_application() {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    let ks = keys(0x62, 2);
    let empty = empty_set_digest(&ks);
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let pool = pool.clone();
        let ks = ks.clone();
        handles.push(tokio::spawn(async move {
            let rec = record(&ks, 1, i + 1, 0x70 + i);
            cas(&pool, &ks, empty, &rec).await
        }));
    }
    let mut applied = 0;
    let mut reported = std::collections::BTreeSet::new();
    for h in handles {
        match h.await.expect("racer") {
            db::CasOutcome::Applied { resulting_digest } => {
                applied += 1;
                reported.insert(resulting_digest);
            }
            db::CasOutcome::ExpectationMismatch { current_digest } => {
                reported.insert(current_digest);
            }
        }
    }
    assert_eq!(applied, 1, "exactly one racer applies");
    assert_eq!(reported.len(), 1, "every loser is told THE winner's digest");
    let held = db::read_bindings(&pool, &ks).await.expect("read");
    assert!(held.iter().all(|h| h.is_some()));
}

/// Rounds only move forward: after a higher round is held, a lower or equal
/// round is refused even when the caller's expectation is exact.
#[tokio::test]
async fn a_round_never_moves_backwards() {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    let ks = keys(0x63, 1);
    let hi = record(&ks, 7, 3, 0xA1);
    let db::CasOutcome::Applied { resulting_digest } =
        cas(&pool, &ks, empty_set_digest(&ks), &hi).await
    else {
        panic!("first exchange applies")
    };
    let lower = record(&ks, 6, 0xFF, 0xB2);
    assert!(matches!(
        cas(&pool, &ks, resulting_digest, &lower).await,
        db::CasOutcome::ExpectationMismatch { .. }
    ));
    let same_round_other_value = record(&ks, 7, 3, 0xC3);
    assert!(matches!(
        cas(&pool, &ks, resulting_digest, &same_round_other_value).await,
        db::CasOutcome::ExpectationMismatch { .. }
    ));
    let held = db::read_bindings(&pool, &ks).await.expect("read");
    assert_eq!(
        held[0].as_ref().unwrap().record_bytes,
        hi.0,
        "the higher round is still held"
    );
}

/// Overlapping key sets {A,B} and {B,C} exchanged from their own empty
/// expectations: at most one can apply, because B can hold only one record.
#[tokio::test]
async fn overlapping_key_sets_serialise_on_the_shared_key() {
    let pool = test_pool();
    db::init_db(&pool).await.expect("init");
    let mut abc = keys(0x64, 3);
    abc.sort();
    let (a, b, c) = (abc[0], abc[1], abc[2]);
    let ab = vec![a, b];
    let bc = vec![b, c];
    let t1 = record(&ab, 1, 1, 0xA1);
    let t2 = record(&bc, 1, 2, 0xB2);
    let (p1, p2) = (pool.clone(), pool.clone());
    let (ab1, bc1) = (ab.clone(), bc.clone());
    let h1 = tokio::spawn(async move { cas(&p1, &ab1, empty_set_digest(&ab1), &t1).await });
    let h2 = tokio::spawn(async move { cas(&p2, &bc1, empty_set_digest(&bc1), &t2).await });
    let (o1, o2) = (h1.await.unwrap(), h2.await.unwrap());
    let applied = [&o1, &o2]
        .iter()
        .filter(|o| matches!(o, db::CasOutcome::Applied { .. }))
        .count();
    assert_eq!(applied, 1, "B cannot belong to two transactions");
    // Whichever lost sees the truth on B when it reads its own key set.
    let held_b = db::read_bindings(&pool, &[b]).await.expect("read")[0].clone();
    assert!(held_b.is_some(), "B is held by the winner");
}

/// A record set survives re-opening the store: the digest a caller was told
/// is the digest it reads back, and a stale expectation is still refused.
#[tokio::test]
async fn a_record_set_survives_reopening_the_store() {
    let path = std::env::temp_dir()
        .join("dsm-binding-reopen")
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);
    let ks = keys(0x65, 2);
    let a = record(&ks, 1, 1, 0xA1);
    let told = {
        let pool = reopenable_pool(&path);
        db::init_db(&pool).await.expect("init");
        let db::CasOutcome::Applied { resulting_digest } =
            cas(&pool, &ks, empty_set_digest(&ks), &a).await
        else {
            panic!("applies")
        };
        resulting_digest
    };
    let pool = reopenable_pool(&path);
    db::init_db(&pool).await.expect("init");
    let held = db::read_bindings(&pool, &ks).await.expect("read");
    assert!(held
        .iter()
        .all(|h| h.as_ref().map(|b| b.record_bytes == a.0).unwrap_or(false)));
    let b = record(&ks, 2, 2, 0xB2);
    assert!(matches!(
        cas(&pool, &ks, empty_set_digest(&ks), &b).await,
        db::CasOutcome::ExpectationMismatch { current_digest } if current_digest == told
    ));
    let _ = std::fs::remove_file(&path);
}
