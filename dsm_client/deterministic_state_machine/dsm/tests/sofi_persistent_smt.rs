// SPDX-License-Identifier: Apache-2.0

//! The persistent DLV tree under concurrent readers, and its tracked costs.
//!
//! Benchmarks are `#[ignore]`: run them with
//! `cargo test --release -p dsm --test sofi_persistent_smt -- --ignored --nocapture`.
//! They print measurements and assert only structure, never time.

#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

use std::sync::{Arc, RwLock};

use dsm::economic::tree::empty_economic_root;
use dsm::sofi::smt::{
    apply, collect_garbage, commit_shadow, get, prove, reachable, verify, MemoryNodeStore,
    Mutation, Node, NodeStore,
};

fn key(i: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    let mut x = i.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for chunk in k.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_be_bytes());
    }
    k
}

fn value(i: u64) -> [u8; 32] {
    let mut v = [0xC3u8; 32];
    v[..8].copy_from_slice(&i.to_be_bytes());
    v
}

fn inserts(range: std::ops::Range<u64>) -> Vec<Mutation> {
    range
        .map(|i| Mutation {
            key: key(i),
            value: Some(value(i)),
        })
        .collect()
}

/// Readers holding a pin keep reading and proving their root while a writer
/// keeps committing shadows, unpinning them and collecting garbage.
#[test]
fn pinned_readers_survive_concurrent_shadows_and_collection() {
    let store = Arc::new(RwLock::new(MemoryNodeStore::new()));
    let base = {
        let mut s = store.write().unwrap();
        let shadow = apply(&*s, &empty_economic_root(), &inserts(0..400)).unwrap();
        commit_shadow(&mut *s, &shadow).unwrap();
        shadow.root
    };

    std::thread::scope(|scope| {
        for reader in 0..4u64 {
            let store = Arc::clone(&store);
            scope.spawn(move || {
                store.write().unwrap().pin(&base).unwrap();
                for round in 0..200u64 {
                    let i = (reader * 97 + round * 13) % 400;
                    let s = store.read().unwrap();
                    assert_eq!(get(&*s, &base, &key(i)).unwrap(), Some(value(i)));
                    let proof = prove(&*s, &base, &key(i)).unwrap();
                    assert!(verify(&base, &key(i), Some(&value(i)), &proof.siblings));
                }
                store.write().unwrap().unpin(&base).unwrap();
            });
        }
        let store = Arc::clone(&store);
        scope.spawn(move || {
            for round in 0..60u64 {
                let mut s = store.write().unwrap();
                let shadow = apply(
                    &*s,
                    &base,
                    &[
                        Mutation {
                            key: key(round % 400),
                            value: Some([round as u8; 32]),
                        },
                        Mutation {
                            key: key(1_000 + round),
                            value: Some(value(round)),
                        },
                    ],
                )
                .unwrap();
                commit_shadow(&mut *s, &shadow).unwrap();
                s.unpin(&shadow.root).unwrap();
                collect_garbage(&mut *s).unwrap();
            }
        });
    });

    let s = store.read().unwrap();
    // The base's own pin remains; every shadow was collected.
    assert_eq!(s.pinned_roots().unwrap(), vec![base]);
    assert_eq!(s.node_count(), reachable(&*s, &[base]).unwrap().len());
}

#[test]
#[ignore = "benchmark: run with --release --ignored --nocapture"]
fn benchmark_hundred_thousand_leaves_and_shadow_forks() {
    use std::time::Instant;

    const LEAVES: u64 = 100_000;
    let mut store = MemoryNodeStore::new();

    let t = Instant::now();
    let tree = apply(&store, &empty_economic_root(), &inserts(0..LEAVES)).unwrap();
    let build = t.elapsed();
    let t = Instant::now();
    commit_shadow(&mut store, &tree).unwrap();
    let commit = t.elapsed();
    let nodes = store.node_count();
    let mut singles = 0u64;
    let mut internals = 0u64;
    for address in reachable(&store, &[tree.root]).unwrap() {
        match store.get_node(&address).unwrap() {
            Some(Node::Single { .. }) => singles += 1,
            Some(Node::Internal { .. }) => internals += 1,
            None => panic!("a reachable node is stored"),
        }
    }
    assert_eq!(singles, LEAVES, "exactly one Single per leaf");
    assert!(internals >= LEAVES - 1, "at least one Internal per split");

    let t = Instant::now();
    for i in (0..LEAVES).step_by(100) {
        assert_eq!(get(&store, &tree.root, &key(i)).unwrap(), Some(value(i)));
    }
    let reads = t.elapsed();

    let t = Instant::now();
    for i in (0..LEAVES).step_by(100) {
        let proof = prove(&store, &tree.root, &key(i)).unwrap();
        assert!(verify(
            &tree.root,
            &key(i),
            Some(&value(i)),
            &proof.siblings
        ));
    }
    let proofs = t.elapsed();

    let mut fork_lines = Vec::new();
    for width in [1u64, 4, 16] {
        let muts: Vec<Mutation> = (0..width)
            .map(|j| Mutation {
                key: key(j * 7_919),
                value: Some([0xAB; 32]),
            })
            .collect();
        let t = Instant::now();
        let shadow = apply(&store, &tree.root, &muts).unwrap();
        let fork = t.elapsed();
        fork_lines.push(format!(
            "  shadow fork, {width:>2} mutations: {fork:>10.2?}, {} new nodes",
            shadow.new_nodes.len()
        ));
    }

    println!("persistent DLV tree, {LEAVES} leaves (memory store)");
    println!("  build:  {build:>10.2?}");
    println!("  commit: {commit:>10.2?}");
    println!("  nodes:  {nodes} ({singles} single-leaf, {internals} internal)");
    println!("  1000 reads:  {reads:>10.2?}");
    println!("  1000 proofs (prove + verify): {proofs:>10.2?}");
    for line in fork_lines {
        println!("{line}");
    }
}
