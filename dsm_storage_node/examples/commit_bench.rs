// SPDX-License-Identifier: MIT OR Apache-2.0

//! Times what a client's route read costs a seat: closing a cycle over a
//! store of `CELLS` cells, and the proofs a reader asks for the new cycle.
//!
//! Run against an empty database of its own:
//! `DSM_BENCH_DATABASE_URL=postgres://... cargo run --release -p dsm_storage_node --example commit_bench`

use std::fmt::Debug;
use std::time::{Duration, Instant};

use dsm_storage_node::db;

const NS: &[u8] = b"DSM/commit-bench";
const CELLS: usize = 5_000;
const IMMUTABLES: usize = 1_000;
const ROUNDS: usize = 10;
const PROOFS_PER_READ: usize = 5;

fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(e) => panic!("{what}: {e:?}"),
    }
}

fn some<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{what}"),
    }
}

fn key(i: usize) -> [u8; 32] {
    dsm::storage_cell::entry_digest(&(i as u64).to_be_bytes())
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    ok(tokio::runtime::Runtime::new(), "runtime").block_on(run());
}

async fn run() {
    let url = ok(
        std::env::var("DSM_BENCH_DATABASE_URL"),
        "DSM_BENCH_DATABASE_URL names an empty database",
    );
    let pool = ok(db::create_pool(&url, db::POOL_MAX_SIZE), "pool");
    ok(db::init_db(&pool).await, "init");

    for chunk in (0..CELLS).collect::<Vec<_>>().chunks(500) {
        let entries: Vec<_> = chunk
            .iter()
            .map(|i| (NS.to_vec(), key(*i).to_vec(), vec![(*i % 251) as u8; 200]))
            .collect();
        ok(db::put_cells(&pool, &entries).await, "seed cells");
    }
    for i in 0..IMMUTABLES {
        let payload = vec![(i % 251) as u8; 300 + i];
        let addr = dsm::utils::text_id::encode_base32_crockford(&key(i + CELLS));
        ok(
            db::insert_immutable_object_if_absent(&pool, &addr, NS, &payload).await,
            "seed immutable",
        );
    }

    let node = db::CommittedCells::default();
    let started = Instant::now();
    let first = some(
        ok(db::close_cycle(&pool, &node, b"bench-node").await, "close"),
        "a cycle",
    );
    println!(
        "first close over {CELLS} cells: {:?} (cycle {})",
        started.elapsed(),
        first.cycle_index
    );

    let (mut closes, mut proofs) = (Vec::new(), Vec::new());
    for round in 0..ROUNDS {
        // A read overwrites a few cells, then closes and asks its proofs.
        for j in 0..3 {
            let k = key((round * 7 + j * 1_013) % CELLS);
            ok(
                db::put_cell(&pool, NS, &k, format!("round {round} write {j}").as_bytes()).await,
                "put",
            );
        }
        let started = Instant::now();
        let commit = some(
            ok(db::close_cycle(&pool, &node, b"bench-node").await, "close"),
            "a cycle",
        );
        closes.push(started.elapsed());
        for p in 0..PROOFS_PER_READ {
            let k = key((round * 11 + p * 997) % CELLS);
            let started = Instant::now();
            some(
                ok(
                    db::cell_commit_proof(&pool, &node, NS, &k, commit.cycle_index).await,
                    "proof",
                ),
                "committed",
            );
            proofs.push(started.elapsed());
        }
    }
    println!(
        "close after a read's writes: median {:?}, max {:?}",
        median(closes.clone()),
        some(closes.iter().max(), "rounds")
    );
    println!(
        "proof at the new cycle: median {:?}, max {:?}",
        median(proofs.clone()),
        some(proofs.iter().max(), "proofs")
    );
}
