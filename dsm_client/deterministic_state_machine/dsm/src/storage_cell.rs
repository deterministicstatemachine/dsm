// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed-cell arrival records — storage spec §14, "keyed-cell commitment
//! formats" (settled 2026-09-23).
//!
//! Written with the registry's pinned `H_dom(d, x) = BLAKE3(d ‖ 0x00 ‖ x)`,
//! for namespace bytes `N`, a 32-byte key `K`, and the values `v_1, v_2, …` a
//! member holds at `(N, K)` in arrival order:
//!
//! ```text
//! d_i = H_dom(DSM/storage/cell-entry/v1, v_i)
//! h_0 = H_dom(DSM/storage/cell-run-init/v1, N ‖ K)
//! h_i = H_dom(DSM/storage/cell-run/v1, h_(i-1) ‖ d_i)          i ≥ 1
//! leaf key   = H_dom(DSM/storage/cell-leaf-key/v1, N ‖ K)
//! leaf value = H_dom(DSM/storage/cell-leaf/v1, i ‖ h_i)          i as u64 BE
//! ```
//!
//! `N` is variable-length but always followed by the fixed 32-byte `K`, so
//! `N ‖ K` is unambiguous without a length prefix — the same argument as
//! [`crate::storage_object`].
//!
//! The node computes these to return an arrival record and to commit its
//! latest `(i, h_i)` per key in its ByteCommit. A verifier recomputes them
//! from the values it read: nothing here is a verdict, and the node never
//! checks a chain (§9). This module is the one implementation both sides use,
//! so the two cannot drift apart.

use crate::common::domain_tags::{
    TAG_DSM_STORAGE_BYTECOMMIT_V1, TAG_DSM_STORAGE_CELL_ENTRY_V1, TAG_DSM_STORAGE_CELL_LEAF_KEY_V1,
    TAG_DSM_STORAGE_CELL_LEAF_V1, TAG_DSM_STORAGE_CELL_RUN_INIT_V1, TAG_DSM_STORAGE_CELL_RUN_V1,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// `d_i = H_dom(DSM/storage/cell-entry/v1, v_i)`.
pub fn entry_digest(value: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_CELL_ENTRY_V1);
    h.update(value);
    *h.finalize().as_bytes()
}

/// `h_0 = H_dom(DSM/storage/cell-run-init/v1, N ‖ K)`: the running hash of a
/// key that holds nothing yet.
pub fn running_hash_init(namespace: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_CELL_RUN_INIT_V1);
    h.update(namespace);
    h.update(key);
    *h.finalize().as_bytes()
}

/// `h_i = H_dom(DSM/storage/cell-run/v1, h_(i-1) ‖ d_i)`.
pub fn running_hash_next(previous: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_CELL_RUN_V1);
    h.update(previous);
    h.update(digest);
    *h.finalize().as_bytes()
}

/// The `(i, h_i)` of every value at `(N, K)`, in arrival order, starting at 1.
pub fn replay(namespace: &[u8], key: &[u8; 32], values: &[Vec<u8>]) -> Vec<(u64, [u8; 32])> {
    let mut h = running_hash_init(namespace, key);
    let mut out = Vec::with_capacity(values.len());
    for (n, v) in values.iter().enumerate() {
        h = running_hash_next(&h, &entry_digest(v));
        out.push((n as u64 + 1, h));
    }
    out
}

/// SMT key of the committed leaf for `(N, K)`.
pub fn leaf_key(namespace: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_CELL_LEAF_KEY_V1);
    h.update(namespace);
    h.update(key);
    *h.finalize().as_bytes()
}

/// SMT value of the committed leaf for the latest entry `(i, h_i)`.
pub fn leaf_value(index: u64, running_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_CELL_LEAF_V1);
    h.update(&index.to_be_bytes());
    h.update(running_hash);
    *h.finalize().as_bytes()
}

/// One entry's arrival record: which member, which cell, which position in
/// that cell's arrival order, and the member's running hash after it. Bytes,
/// not a signature — checkable once the member's ByteCommit covering it
/// closes (§6, §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrivalRecord {
    /// The seat's member id, byte for byte as the storage set commits it
    /// (`StorageSetEntry::member_id`), so a verifier names the seat directly.
    pub member_id: Vec<u8>,
    pub namespace: Vec<u8>,
    pub key: [u8; 32],
    pub index: u64,
    pub running_hash: [u8; 32],
}

impl ArrivalRecord {
    pub fn to_proto(&self) -> crate::types::proto::ArrivalRecordV1 {
        crate::types::proto::ArrivalRecordV1 {
            member_id: self.member_id.clone(),
            namespace: self.namespace.clone(),
            key: self.key.to_vec(),
            index: self.index,
            running_hash: self.running_hash.to_vec(),
        }
    }

    /// `None` if the member id is empty, a fixed-length field has the wrong
    /// length, or the index is zero (indexes start at 1).
    pub fn from_proto(p: &crate::types::proto::ArrivalRecordV1) -> Option<Self> {
        if p.index == 0 || p.member_id.is_empty() {
            return None;
        }
        Some(Self {
            member_id: p.member_id.clone(),
            namespace: p.namespace.clone(),
            key: p.key.as_slice().try_into().ok()?,
            index: p.index,
            running_hash: p.running_hash.as_slice().try_into().ok()?,
        })
    }

    /// Whether this record agrees with the values read from that member at
    /// its cell: the `index`-th value exists and replaying up to it yields
    /// `running_hash`. Agreement with the member's own reads is not the same
    /// as the record being committed; that needs the ByteCommit (§14).
    pub fn agrees_with(&self, values: &[Vec<u8>]) -> bool {
        let Ok(i) = usize::try_from(self.index) else {
            return false;
        };
        if i == 0 || i > values.len() {
            return false;
        }
        replay(&self.namespace, &self.key, &values[..i])
            .last()
            .is_some_and(|(_, h)| *h == self.running_hash)
    }
}

// ── ByteCommits (storage spec §14, ByteCommit format) ──────────────────────

/// Longest member id a ByteCommit may name: the wire bound on
/// `ByteCommitV4.member_id`. Well inside the digest's u16 length prefix, so
/// the prefix is exact for every ByteCommit that is decoded or built by a
/// node.
pub const MAX_MEMBER_ID_LEN: usize = 128;

/// A member's ByteCommit for cycle `t`: which member, which cycle, the SMT
/// root over its cells' latest committed entries, the bytes it holds, and the
/// digest of its previous ByteCommit. Unsigned: a verifier checks the chain
/// link and the root itself, and never counts mirrors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteCommit {
    /// The member id exactly as the storage set commits it.
    pub member_id: Vec<u8>,
    /// From 1. A counter, never time.
    pub cycle_index: u64,
    pub smt_root: [u8; 32],
    pub bytes_used: u64,
    /// The previous ByteCommit's digest; zeros at cycle 1.
    pub parent_digest: [u8; 32],
}

impl ByteCommit {
    /// `d_t = H_dom(DSM/storage/bytecommit/v1, len(M) ‖ M ‖ t ‖ root ‖ bytes ‖ parent)`,
    /// with `len(M)` as a u16 and the integers as u64, big-endian. The digest
    /// is over these fields, never over a transport encoding, so no encoder
    /// choice can change it.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_STORAGE_BYTECOMMIT_V1);
        h.update(&(self.member_id.len() as u16).to_be_bytes());
        h.update(&self.member_id);
        h.update(&self.cycle_index.to_be_bytes());
        h.update(&self.smt_root);
        h.update(&self.bytes_used.to_be_bytes());
        h.update(&self.parent_digest);
        *h.finalize().as_bytes()
    }

    /// Whether `self` is the direct successor of `parent` in one member's
    /// chain: same member, next cycle, parent digest linked.
    pub fn follows(&self, parent: &ByteCommit) -> bool {
        self.member_id == parent.member_id
            && parent.cycle_index.checked_add(1) == Some(self.cycle_index)
            && self.parent_digest == parent.digest()
    }

    /// Storage spec §15: a DrainProof is two consecutive ByteCommits of one
    /// member, the second linked to the first, both with bytes used equal to
    /// zero. The verifier takes both from a mirror (§14), never from the
    /// member alone.
    pub fn is_drain_proof(first: &ByteCommit, second: &ByteCommit) -> bool {
        first.bytes_used == 0 && second.bytes_used == 0 && second.follows(first)
    }

    pub fn to_proto(&self) -> crate::types::proto::ByteCommitV4 {
        crate::types::proto::ByteCommitV4 {
            member_id: self.member_id.clone(),
            cycle_index: self.cycle_index,
            smt_root: self.smt_root.to_vec(),
            bytes_used: self.bytes_used,
            parent_digest: self.parent_digest.to_vec(),
        }
    }

    /// `None` on an empty member id or one longer than
    /// [`MAX_MEMBER_ID_LEN`], a zero cycle, a cycle-1 ByteCommit whose parent
    /// is not all zeros, or a malformed fixed-length field.
    pub fn from_proto(p: &crate::types::proto::ByteCommitV4) -> Option<Self> {
        if p.member_id.is_empty() || p.member_id.len() > MAX_MEMBER_ID_LEN || p.cycle_index == 0 {
            return None;
        }
        let parent_digest: [u8; 32] = p.parent_digest.as_slice().try_into().ok()?;
        if p.cycle_index == 1 && parent_digest != [0u8; 32] {
            return None;
        }
        Some(Self {
            member_id: p.member_id.clone(),
            cycle_index: p.cycle_index,
            smt_root: p.smt_root.as_slice().try_into().ok()?,
            bytes_used: p.bytes_used,
            parent_digest,
        })
    }
}

/// The SMT a ByteCommit's root covers, built from each cell's latest entry
/// as of the cycle: `(N, K, i, h_i)`. The node builds it to compute the root
/// and to answer proofs; a verifier never needs the whole tree.
pub fn cell_tree<'a>(
    leaves: impl IntoIterator<Item = (&'a [u8], &'a [u8; 32], u64, &'a [u8; 32])>,
) -> SparseMerkleTree {
    SparseMerkleTree::from_leaves(leaves.into_iter().map(
        |(namespace, key, index, running_hash)| {
            (leaf_key(namespace, key), leaf_value(index, running_hash))
        },
    ))
}

/// A member's proof that its ByteCommit commits a cell's latest entry as of
/// that cycle.
#[derive(Debug, Clone)]
pub struct CellCommitProof {
    pub index: u64,
    pub running_hash: [u8; 32],
    pub smt_proof: SmtInclusionProof,
}

impl CellCommitProof {
    /// Build the proof for `(N, K)` from the node's tree at the cycle.
    pub fn from_tree(
        tree: &SparseMerkleTree,
        namespace: &[u8],
        key: &[u8; 32],
        index: u64,
        running_hash: [u8; 32],
    ) -> Option<Self> {
        let smt_proof = tree
            .get_inclusion_proof(&leaf_key(namespace, key), 256)
            .ok()?;
        Some(Self {
            index,
            running_hash,
            smt_proof,
        })
    }

    pub fn to_proto(&self) -> crate::types::proto::CellCommitProofV1 {
        crate::types::proto::CellCommitProofV1 {
            index: self.index,
            running_hash: self.running_hash.to_vec(),
            smt_proof: self.smt_proof.to_bytes(),
        }
    }

    pub fn from_proto(p: &crate::types::proto::CellCommitProofV1) -> Option<Self> {
        Some(Self {
            index: p.index,
            running_hash: p.running_hash.as_slice().try_into().ok()?,
            smt_proof: SmtInclusionProof::from_bytes(&p.smt_proof)?,
        })
    }

    /// Whether this proof shows `commit` committing `(N, K)` at `(index,
    /// running_hash)`: the proof is for the cell's leaf key, carries exactly
    /// that leaf value, has the full 256-sibling path, and folds to the root.
    pub fn verifies(&self, commit: &ByteCommit, namespace: &[u8], key: &[u8; 32]) -> bool {
        self.index >= 1
            && self.smt_proof.key == leaf_key(namespace, key)
            && self.smt_proof.value == Some(leaf_value(self.index, &self.running_hash))
            && self.smt_proof.siblings.len() == 256
            && SparseMerkleTree::verify_proof_against_root(&self.smt_proof, &commit.smt_root)
    }
}

/// Whether an arrival record is committed by a member's ByteCommit: the
/// ByteCommit is that member's, its proof verifies for the record's cell, the
/// committed entry is at or after the record's, and the values read from the
/// member replay to both running hashes. Agreement with the reads alone is
/// not enough; the commitment is what makes a link checkable (§6, §14).
pub fn record_is_committed(
    record: &ArrivalRecord,
    values: &[Vec<u8>],
    commit: &ByteCommit,
    proof: &CellCommitProof,
) -> bool {
    if commit.member_id != record.member_id
        || proof.index < record.index
        || !proof.verifies(commit, &record.namespace, &record.key)
    {
        return false;
    }
    let Ok(upto) = usize::try_from(proof.index) else {
        return false;
    };
    if upto > values.len() {
        return false;
    }
    let replayed = replay(&record.namespace, &record.key, &values[..upto]);
    // Index 0 names no entry: refused, never an underflow.
    let at = |i: u64| {
        usize::try_from(i)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| replayed.get(i))
            .map(|(_, h)| *h)
    };
    at(record.index) == Some(record.running_hash) && at(proof.index) == Some(proof.running_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent recomputation typed from the spec text, not from the
    /// constants, so a mistyped tag cannot pass by agreeing with itself.
    fn spec_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut pre = tag.to_vec();
        pre.push(0x00);
        for p in parts {
            pre.extend_from_slice(p);
        }
        *blake3::hash(&pre).as_bytes()
    }

    #[test]
    fn the_running_hash_matches_the_spec_construction() {
        let ns = b"DSM/example-ns";
        let key = [7u8; 32];
        let values = vec![b"first".to_vec(), b"second".to_vec()];

        let h0 = spec_hash(b"DSM/storage/cell-run-init/v1", &[ns, &key]);
        let d1 = spec_hash(b"DSM/storage/cell-entry/v1", &[b"first"]);
        let h1 = spec_hash(b"DSM/storage/cell-run/v1", &[&h0, &d1]);
        let d2 = spec_hash(b"DSM/storage/cell-entry/v1", &[b"second"]);
        let h2 = spec_hash(b"DSM/storage/cell-run/v1", &[&h1, &d2]);

        assert_eq!(replay(ns, &key, &values), vec![(1, h1), (2, h2)]);
    }

    #[test]
    fn the_leaf_matches_the_spec_construction() {
        let ns = b"DSM/example-ns";
        let key = [9u8; 32];
        let h = [3u8; 32];
        assert_eq!(
            leaf_key(ns, &key),
            spec_hash(b"DSM/storage/cell-leaf-key/v1", &[ns, &key])
        );
        assert_eq!(
            leaf_value(5, &h),
            spec_hash(b"DSM/storage/cell-leaf/v1", &[&5u64.to_be_bytes(), &h])
        );
    }

    /// Reordering, dropping or altering an earlier entry changes every later
    /// running hash: that is what makes arrival order committable.
    #[test]
    fn any_change_to_earlier_entries_breaks_later_records() {
        let ns = b"DSM/example-ns";
        let key = [1u8; 32];
        let a = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];
        let reordered = vec![b"y".to_vec(), b"x".to_vec(), b"z".to_vec()];
        let dropped = vec![b"x".to_vec(), b"z".to_vec()];
        let last = replay(ns, &key, &a)[2].1;
        assert_ne!(replay(ns, &key, &reordered)[2].1, last);
        assert_ne!(replay(ns, &key, &dropped)[1].1, last);
    }

    #[test]
    fn a_record_agrees_only_with_the_values_it_was_issued_for() {
        let ns = b"DSM/example-ns".to_vec();
        let key = [2u8; 32];
        let values = vec![b"x".to_vec(), b"y".to_vec()];
        let (index, running_hash) = replay(&ns, &key, &values)[1];
        let rec = ArrivalRecord {
            member_id: b"dsm-node-4".to_vec(),
            namespace: ns.clone(),
            key,
            index,
            running_hash,
        };
        assert!(rec.agrees_with(&values));
        // Later arrivals do not disturb an earlier record.
        let mut more = values.clone();
        more.push(b"z".to_vec());
        assert!(rec.agrees_with(&more));
        // A different history does not agree.
        assert!(!rec.agrees_with(&[b"x".to_vec(), b"w".to_vec()]));
        assert!(!rec.agrees_with(&values[..1]));
        // Another cell does not agree.
        let other = ArrivalRecord {
            key: [5u8; 32],
            ..rec.clone()
        };
        assert!(!other.agrees_with(&values));
    }

    #[test]
    fn the_proto_round_trips_and_rejects_bad_lengths_and_index_zero() {
        let rec = ArrivalRecord {
            member_id: b"dsm-node-1".to_vec(),
            namespace: b"DSM/n".to_vec(),
            key: [2u8; 32],
            index: 3,
            running_hash: [4u8; 32],
        };
        assert_eq!(
            ArrivalRecord::from_proto(&rec.to_proto()),
            Some(rec.clone())
        );
        let mut short = rec.to_proto();
        short.key.pop();
        assert_eq!(ArrivalRecord::from_proto(&short), None);
        let mut zero = rec.to_proto();
        zero.index = 0;
        assert_eq!(ArrivalRecord::from_proto(&zero), None);
    }

    fn commit(member: &[u8], cycle: u64, root: [u8; 32], parent: [u8; 32]) -> ByteCommit {
        ByteCommit {
            member_id: member.to_vec(),
            cycle_index: cycle,
            smt_root: root,
            bytes_used: 10,
            parent_digest: parent,
        }
    }

    #[test]
    fn the_bytecommit_digest_matches_the_spec_construction() {
        let c = commit(b"dsm-node-1", 3, [5u8; 32], [6u8; 32]);
        let expected = spec_hash(
            b"DSM/storage/bytecommit/v1",
            &[
                &10u16.to_be_bytes(),
                b"dsm-node-1",
                &3u64.to_be_bytes(),
                &[5u8; 32],
                &10u64.to_be_bytes(),
                &[6u8; 32],
            ],
        );
        assert_eq!(c.digest(), expected);
        assert_eq!(ByteCommit::from_proto(&c.to_proto()), Some(c));
    }

    #[test]
    fn a_chain_link_needs_same_member_next_cycle_and_the_parent_digest() {
        let c1 = commit(b"m", 1, [1u8; 32], [0u8; 32]);
        let c2 = commit(b"m", 2, [2u8; 32], c1.digest());
        assert!(c2.follows(&c1));
        assert!(!commit(b"m", 3, [2u8; 32], c1.digest()).follows(&c1));
        assert!(!commit(b"x", 2, [2u8; 32], c1.digest()).follows(&c1));
        assert!(!commit(b"m", 2, [2u8; 32], [9u8; 32]).follows(&c1));
    }

    /// §15: only two linked, consecutive, empty ByteCommits of one member
    /// prove a drain.
    #[test]
    fn a_drain_proof_is_two_linked_empty_bytecommits() {
        let empty = |c: ByteCommit| ByteCommit { bytes_used: 0, ..c };
        let c1 = empty(commit(b"m", 1, [1u8; 32], [0u8; 32]));
        let c2 = empty(commit(b"m", 2, [2u8; 32], c1.digest()));
        assert!(ByteCommit::is_drain_proof(&c1, &c2));
        // Either one holding bytes is not drained.
        let full = commit(b"m", 2, [2u8; 32], c1.digest());
        assert!(!ByteCommit::is_drain_proof(&c1, &full));
        let full_first = commit(b"m", 1, [1u8; 32], [0u8; 32]);
        let after_full = empty(commit(b"m", 2, [2u8; 32], full_first.digest()));
        assert!(!ByteCommit::is_drain_proof(&full_first, &after_full));
        // Not linked, not consecutive, or another member's: not a proof.
        assert!(!ByteCommit::is_drain_proof(
            &c1,
            &empty(commit(b"m", 2, [2u8; 32], [9u8; 32]))
        ));
        assert!(!ByteCommit::is_drain_proof(
            &c1,
            &empty(commit(b"m", 3, [2u8; 32], c1.digest()))
        ));
        assert!(!ByteCommit::is_drain_proof(
            &c1,
            &empty(commit(b"x", 2, [2u8; 32], c1.digest()))
        ));
    }

    /// End to end: a node builds its tree, commits the root, answers a proof;
    /// a verifier holding the member's values and the ByteCommit accepts
    /// exactly the records that commit covers.
    #[test]
    fn a_committed_record_verifies_and_an_uncommitted_one_does_not() {
        let ns = b"DSM/example-ns".to_vec();
        let key = [8u8; 32];
        let other_key = [9u8; 32];
        let values = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let run = replay(&ns, &key, &values);
        let other_run = replay(&ns, &other_key, &[b"z".to_vec()]);

        // The ByteCommit closed after the second entry at `key`.
        let tree = cell_tree([
            (ns.as_slice(), &key, run[1].0, &run[1].1),
            (ns.as_slice(), &other_key, other_run[0].0, &other_run[0].1),
        ]);
        let c = commit(b"dsm-node-1", 1, *tree.root(), [0u8; 32]);
        let proof =
            CellCommitProof::from_tree(&tree, &ns, &key, run[1].0, run[1].1).expect("proof");
        let proof = CellCommitProof::from_proto(&proof.to_proto()).expect("round trip");

        let rec = |i: usize| ArrivalRecord {
            member_id: b"dsm-node-1".to_vec(),
            namespace: ns.clone(),
            key,
            index: run[i].0,
            running_hash: run[i].1,
        };
        assert!(
            record_is_committed(&rec(0), &values, &c, &proof),
            "entry 1 is covered"
        );
        assert!(
            record_is_committed(&rec(1), &values, &c, &proof),
            "entry 2 is covered"
        );
        assert!(
            !record_is_committed(&rec(2), &values, &c, &proof),
            "entry 3 came after the commit"
        );

        // Another member's ByteCommit does not cover this member's record.
        let foreign = commit(b"dsm-node-2", 1, *tree.root(), [0u8; 32]);
        assert!(!record_is_committed(&rec(0), &values, &foreign, &proof));
        // A different history at the member does not replay to the proof.
        let rewritten = vec![b"a".to_vec(), b"X".to_vec(), b"c".to_vec()];
        assert!(!record_is_committed(&rec(0), &rewritten, &c, &proof));
        // A proof claiming a later index than the tree committed fails the root.
        let mut lying = proof.clone();
        lying.index = run[2].0;
        lying.running_hash = run[2].1;
        assert!(!record_is_committed(&rec(2), &values, &c, &lying));
        // A proof for another cell does not transfer.
        assert!(!proof.verifies(&c, &ns, &other_key));

        // A proof that is internally consistent but comes from a different
        // tree (another root) does not verify against this ByteCommit: the
        // root is what binds a proof to what the member committed.
        let later_tree = cell_tree([(ns.as_slice(), &key, run[2].0, &run[2].1)]);
        let later_proof =
            CellCommitProof::from_tree(&later_tree, &ns, &key, run[2].0, run[2].1).expect("proof");
        let later_commit = commit(b"dsm-node-1", 2, *later_tree.root(), c.digest());
        assert!(
            later_proof.verifies(&later_commit, &ns, &key),
            "valid for its own root"
        );
        assert!(!later_proof.verifies(&c, &ns, &key), "not for another root");
        assert!(!record_is_committed(&rec(2), &values, &c, &later_proof));

        // A forged record against an honest history and an honest proof: the
        // record's own running hash is checked, not just the proof's.
        let mut forged = rec(0);
        forged.running_hash = [0xAB; 32];
        assert!(!record_is_committed(&forged, &values, &c, &proof));

        // Index 0 names no entry: refused, not a panic.
        let mut zero = rec(0);
        zero.index = 0;
        assert!(!record_is_committed(&zero, &values, &c, &proof));
    }

    /// The one-pass build commits the same root as inserting leaf by leaf.
    #[test]
    fn the_cell_tree_root_matches_incremental_insertion() {
        let ns = b"DSM/example-ns".to_vec();
        let keys: Vec<[u8; 32]> = (0u8..40).map(|i| [i; 32]).collect();
        let hashes: Vec<[u8; 32]> = (0u8..40).map(|i| [i ^ 0x5A; 32]).collect();
        let tree = cell_tree(
            keys.iter()
                .zip(&hashes)
                .map(|(k, h)| (ns.as_slice(), k, 3, h)),
        );
        let mut incremental = SparseMerkleTree::new(usize::MAX);
        for (k, h) in keys.iter().zip(&hashes) {
            incremental
                .update_leaf(&leaf_key(&ns, k), &leaf_value(3, h))
                .expect("insert");
        }
        assert_eq!(tree.root(), incremental.root());
        let proof =
            CellCommitProof::from_tree(&tree, &ns, &keys[17], 3, hashes[17]).expect("proof");
        let c = commit(b"m", 1, *tree.root(), [0u8; 32]);
        assert!(proof.verifies(&c, &ns, &keys[17]));
    }

    #[test]
    fn an_empty_member_id_or_cycle_zero_is_refused() {
        let mut p = commit(b"m", 1, [0u8; 32], [0u8; 32]).to_proto();
        p.cycle_index = 0;
        assert_eq!(ByteCommit::from_proto(&p), None);
        let mut p = commit(b"m", 1, [0u8; 32], [0u8; 32]).to_proto();
        p.member_id.clear();
        assert_eq!(ByteCommit::from_proto(&p), None);
        // Cycle 1 starts the chain: its parent is all zeros or it is refused.
        let p = commit(b"m", 1, [0u8; 32], [1u8; 32]).to_proto();
        assert_eq!(ByteCommit::from_proto(&p), None);
        // The member id is bounded by the wire limit, not by the u16 prefix.
        let p = commit(&[b'm'; MAX_MEMBER_ID_LEN + 1], 2, [0u8; 32], [1u8; 32]).to_proto();
        assert_eq!(ByteCommit::from_proto(&p), None);
        let p = commit(&[b'm'; MAX_MEMBER_ID_LEN], 2, [0u8; 32], [1u8; 32]).to_proto();
        assert!(ByteCommit::from_proto(&p).is_some());
        let mut r = ArrivalRecord {
            member_id: b"m".to_vec(),
            namespace: b"DSM/n".to_vec(),
            key: [0u8; 32],
            index: 1,
            running_hash: [0u8; 32],
        }
        .to_proto();
        r.member_id.clear();
        assert_eq!(ArrivalRecord::from_proto(&r), None);
    }
}
