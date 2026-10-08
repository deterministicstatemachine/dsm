// SPDX-License-Identifier: Apache-2.0

//! SoFi Amendment S26: a vault's history proves every root it ever had from
//! one authenticated head, by a path its nodes are read for by hash.

use std::collections::HashMap;

use super::*;
use crate::sofi::wire::VaultHistoryHeadV1;

const VAULT: D32 = [7u8; 32];

fn root_of(generation: u64) -> D32 {
    h(
        TAG_DSM_SOFI_VAULT_HISTORY_LEAF,
        &[b"a test root", &generation.to_be_bytes()],
    )
}

/// A history of `generations + 1` roots, with every node it published by
/// each head, keyed by hash.
struct Published {
    heads: Vec<VaultHistoryHeadV1>,
    nodes_by: Vec<HashMap<D32, Vec<u8>>>,
}

fn publish(generations: u64) -> Published {
    let mut builder = HistoryBuilder::new(VAULT);
    let mut nodes: HashMap<D32, Vec<u8>> = HashMap::new();
    let mut heads = Vec::new();
    let mut nodes_by = Vec::new();
    for g in 0..=generations {
        let appended = builder.append(&root_of(g));
        assert_eq!(appended.leaf, leaf_bytes(&VAULT, g, &root_of(g)));
        for (hash, bytes) in appended.nodes {
            assert_eq!(
                decode_node(&bytes).map(|(l, r)| node_hash(&l, &r)),
                Some(hash)
            );
            nodes.insert(hash, bytes);
        }
        heads.push(builder.head().expect("a head once a root is appended"));
        nodes_by.push(nodes.clone());
    }
    Published { heads, nodes_by }
}

fn read<'a>(
    nodes: &'a HashMap<D32, Vec<u8>>,
) -> impl FnMut(&D32) -> Result<Option<Vec<u8>>, ()> + 'a {
    move |hash| Ok(nodes.get(hash).cloned())
}

#[test]
fn every_root_is_proven_under_every_later_head() {
    let published = publish(40);
    for (n, head) in published.heads.iter().enumerate() {
        assert_eq!(head.generation, n as u64);
        assert_eq!(
            Some(head.peaks.len()),
            VaultHistoryHeadV1::peak_count(head.generation)
        );
        for g in 0..=head.generation {
            let proven = match prove(head, &VAULT, g, &root_of(g), read(&published.nodes_by[n]))
                .expect("reads")
            {
                Ok(proven) => proven,
                Err(why) => panic!("R_{g} under the head at {n}: {why:?}"),
            };
            assert_eq!(
                (proven.vault_id(), proven.generation(), proven.root()),
                (&VAULT, g, &root_of(g))
            );
        }
    }
}

/// Completed subtrees never change: what was published by an older head is
/// all a reader at that head needs, however far the vault has moved since.
#[test]
fn an_older_head_proves_from_the_nodes_published_by_then() {
    let published = publish(40);
    let head = &published.heads[23];
    for g in 0..=23 {
        prove(head, &VAULT, g, &root_of(g), read(&published.nodes_by[23]))
            .expect("reads")
            .expect("proven from the nodes published by generation 23");
    }
}

#[test]
fn another_root_at_a_generation_is_contradicted() {
    let published = publish(40);
    let head = &published.heads[40];
    assert_eq!(
        prove(
            head,
            &VAULT,
            17,
            &root_of(18),
            read(&published.nodes_by[40])
        )
        .expect("reads"),
        Err(NotProven::Contradicted)
    );
}

#[test]
fn a_node_not_in_hand_or_not_its_hash_proves_nothing() {
    let published = publish(40);
    let head = &published.heads[40];
    let empty = HashMap::new();
    assert!(matches!(
        prove(head, &VAULT, 3, &root_of(3), read(&empty)).expect("reads"),
        Err(NotProven::NodeUnavailable(..))
    ));
    // Every node answered with another node's bytes.
    let other = published.nodes_by[40]
        .values()
        .next()
        .expect("a node")
        .clone();
    let liar = |_: &D32| -> Result<Option<Vec<u8>>, ()> { Ok(Some(other.clone())) };
    assert!(matches!(
        prove(head, &VAULT, 3, &root_of(3), liar).expect("reads"),
        Err(NotProven::NodeUnavailable(..))
    ));
}

#[test]
fn nothing_outside_the_head_is_proven() {
    let published = publish(40);
    let head = &published.heads[12];
    assert_eq!(
        prove(
            head,
            &VAULT,
            13,
            &root_of(13),
            read(&published.nodes_by[40])
        )
        .expect("reads"),
        Err(NotProven::OutsideTheHead)
    );
    assert_eq!(
        prove(
            head,
            &[8u8; 32],
            3,
            &root_of(3),
            read(&published.nodes_by[40])
        )
        .expect("reads"),
        Err(NotProven::OutsideTheHead)
    );
}

/// A proof reads one node per level of the peak covering the generation:
/// logarithmic in the vault's age, never its length.
#[test]
fn a_proof_reads_a_logarithmic_path() {
    let published = publish(1023);
    let head = &published.heads[1023];
    let mut reads = 0;
    prove(
        head,
        &VAULT,
        5,
        &root_of(5),
        |hash: &D32| -> Result<_, ()> {
            reads += 1;
            Ok(published.nodes_by[1023].get(hash).cloned())
        },
    )
    .expect("reads")
    .expect("proven");
    assert_eq!(reads, 10, "a 1024-leaf peak is ten levels");
}

#[test]
fn the_history_root_moves_with_every_generation_and_decodes_strictly() {
    let published = publish(8);
    let roots: Vec<D32> = published
        .heads
        .iter()
        .map(|head| history_root(head).expect("a head encodes"))
        .collect();
    let mut distinct = roots.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), roots.len());

    let head = &published.heads[5];
    let bytes = head.encode().expect("encodes");
    assert_eq!(VaultHistoryHeadV1::decode(&bytes).expect("decodes"), *head);
    let mut short = head.clone();
    short.peaks.pop();
    short
        .encode()
        .expect_err("a head with a peak missing does not encode");
    VaultHistoryHeadV1::decode(&bytes[..bytes.len() - 32])
        .expect_err("bytes with a peak missing do not decode");
    let mut long = bytes.clone();
    long.extend_from_slice(&root_of(99));
    VaultHistoryHeadV1::decode(&long).expect_err("trailing bytes do not decode");
}

#[test]
fn a_leaf_reads_back_as_written() {
    let bytes = leaf_bytes(&VAULT, 9, &root_of(9));
    assert_eq!(decode_leaf(&bytes), Some((VAULT, 9, root_of(9))));
    assert_eq!(decode_leaf(&bytes[1..]), None);
    assert_ne!(
        history_locator(&VAULT, &root_of(9)),
        history_locator(&VAULT, &root_of(8))
    );
}
