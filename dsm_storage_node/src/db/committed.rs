// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this node's closed cycles commit, kept in process (storage spec §14).
//!
//! A cycle's ByteCommit commits every cell's latest entry stamped at or
//! before that cycle. An entry's stamp never changes once its cycle closes —
//! the one statement that writes `committed_cycle` sets it only where it is
//! still unset, and nothing deletes a cell entry — so the leaf set of cycle
//! `t + 1` is the leaf set of `t` with the entries stamped in `t + 1`
//! applied, and its tree is the tree of `t` with those leaves written. The
//! closer keeps the leaf set and tree of the last cycle it saw close and
//! applies only what it stamps; a proof reads the tree of a recent cycle
//! instead of building it again from every cell.
//!
//! What is kept is a copy of what the store commits, never an authority
//! beside it. The closer uses its leaf set only when the latest ByteCommit
//! in the store is the very one that leaf set is as of; another process
//! closing on the same database, a close that failed, or a restart each make
//! it read the store again. A proof uses a kept tree only for a cycle whose
//! ByteCommit in the store has the digest the tree was kept under.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;
use dsm::storage_cell::{leaf_key, leaf_value, ByteCommit};

/// A node keeps the trees of at most this many closed cycles.
pub const KEPT_CYCLES: usize = 64;

/// Proofs that hold or wait for the node's one tree build at once
/// ([`CommittedCells::hold_tree_build`]). A proof's cycle may be any the node
/// ever closed, and a tree that is not kept is built over every cell the
/// store committed by then, so anyone can make the node build one after
/// another; a proof waiting its turn holds a slot under the node's
/// concurrency limit. Past these, a proof that needs a build is answered at
/// once that the node is busy, as an unavailable node answers, and the
/// node's other requests keep their slots.
pub const TREE_BUILDS_QUEUED: usize = 4;

/// A proof needed a tree build while [`TREE_BUILDS_QUEUED`] proofs already
/// held or waited for one.
#[derive(Debug)]
pub struct TreeBuildsFull;

impl std::fmt::Display for TreeBuildsFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{TREE_BUILDS_QUEUED} proofs already hold or wait for the node's tree build"
        )
    }
}

impl std::error::Error for TreeBuildsFull {}

/// A proof's turn at the node's one tree build: its place among
/// [`TREE_BUILDS_QUEUED`] and the build itself, both given back when it ends.
pub struct TreeBuild<'a> {
    _queued: tokio::sync::SemaphorePermit<'a>,
    _build: tokio::sync::MutexGuard<'a, ()>,
}

/// A node's kept trees hold at most this many leaves between them; the
/// newest cycle's tree is kept whatever its size. At about 250 bytes a leaf
/// this bounds them to a few hundred megabytes on the largest store.
pub const KEPT_LEAVES: usize = 1 << 20;

/// A cell's latest entry as a ByteCommit commits it: namespace, key, arrival
/// index, running hash.
pub(crate) type CellLeaf = (Vec<u8>, [u8; 32], u64, [u8; 32]);

type KeptTrees = BTreeMap<u64, ([u8; 32], Arc<SparseMerkleTree>)>;

/// The trees of a node's recent cycles, and the closer's lock with the leaf
/// set of the last cycle it closed. One per node process.
pub struct CommittedCells {
    /// Held while a cycle closes. A closer waits here before it takes a
    /// database connection, so closers queued behind one another hold no
    /// connection and cannot starve every other request of the pool. It
    /// guards the leaf set as of the last cycle this process saw close, when
    /// it holds one.
    pub(crate) closer: tokio::sync::Mutex<Option<Arc<CommittedLeaves>>>,
    /// Held while a proof builds the tree of a cycle that is not kept
    /// ([`CommittedCells::hold_tree_build`]).
    tree_build: tokio::sync::Mutex<()>,
    /// The proofs holding or waiting for `tree_build`, at most
    /// [`TREE_BUILDS_QUEUED`].
    tree_builds_queued: tokio::sync::Semaphore,
    /// Recently closed cycles' trees, by cycle, each with the digest of the
    /// ByteCommit whose root it is.
    trees: Mutex<KeptTrees>,
    /// At most this many cycles' trees are kept, ...
    kept_cycles: usize,
    /// ... holding at most this many leaves between them.
    kept_leaves: usize,
}

impl Default for CommittedCells {
    /// What a node keeps: [`KEPT_CYCLES`] cycles, [`KEPT_LEAVES`] leaves.
    fn default() -> Self {
        Self::bounded(KEPT_CYCLES, KEPT_LEAVES)
    }
}

impl CommittedCells {
    /// Keeping the trees of at most `kept_cycles` cycles, holding at most
    /// `kept_leaves` leaves between them; the newest is kept whatever its
    /// size.
    pub fn bounded(kept_cycles: usize, kept_leaves: usize) -> Self {
        Self {
            closer: tokio::sync::Mutex::new(None),
            tree_build: tokio::sync::Mutex::new(()),
            tree_builds_queued: tokio::sync::Semaphore::new(TREE_BUILDS_QUEUED),
            trees: Mutex::new(BTreeMap::new()),
            kept_cycles,
            kept_leaves,
        }
    }

    /// The tree of `cycle`, if it is kept and was kept for the ByteCommit
    /// with `digest`.
    pub(crate) fn tree_at(&self, cycle: u64, digest: &[u8; 32]) -> Option<Arc<SparseMerkleTree>> {
        self.kept()
            .get(&cycle)
            .filter(|(kept_for, _)| kept_for == digest)
            .map(|(_, tree)| tree.clone())
    }

    /// Keep `tree` as the tree of `cycle`, whose ByteCommit has `digest`,
    /// and let go of the oldest trees beyond the bounds.
    pub(crate) fn keep(&self, cycle: u64, digest: [u8; 32], tree: Arc<SparseMerkleTree>) {
        let mut trees = self.kept();
        trees.insert(cycle, (digest, tree));
        while trees.len() > 1
            && (trees.len() > self.kept_cycles
                || trees.values().map(|(_, t)| t.leaf_count()).sum::<usize>() > self.kept_leaves)
        {
            trees.pop_first();
        }
    }

    /// Hold the node's one tree build: a proof whose cycle's tree is not kept
    /// builds it while it holds this, so one tree over the store's every cell
    /// is built at a time, however many proofs ask. A proof waits here holding
    /// no database connection, and finds the tree kept when the build it
    /// waited behind was for its cycle. With [`TREE_BUILDS_QUEUED`] proofs
    /// already holding or waiting for it, [`TreeBuildsFull`] at once.
    pub async fn hold_tree_build(&self) -> Result<TreeBuild<'_>, TreeBuildsFull> {
        let queued = self.tree_builds_queued.try_acquire().map_err(|full| {
            log::info!("tree build: {full}");
            TreeBuildsFull
        })?;
        Ok(TreeBuild {
            _queued: queued,
            _build: self.tree_build.lock().await,
        })
    }

    /// The cycles whose trees are kept, oldest first.
    pub fn kept_cycles(&self) -> Vec<u64> {
        self.kept().keys().copied().collect()
    }

    fn kept(&self) -> MutexGuard<'_, KeptTrees> {
        // A panic while the map was held leaves whole entries only — insert
        // and remove do not tear one — and every entry is checked against the
        // store's digest before it is used, so the map is read as it stands.
        match self.trees.lock() {
            Ok(trees) => trees,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Every cell's latest entry committed at or before one ByteCommit's cycle,
/// the tree over them, and the bytes of every entry those cycles stamped.
pub(crate) struct CommittedLeaves {
    /// The ByteCommit these leaves are as of; `None` before the first cycle.
    pub(crate) commit: Option<ByteCommit>,
    /// Each cell's latest committed `(arrival index, running hash)`, by the
    /// cell's leaf key.
    latest: HashMap<[u8; 32], (u64, [u8; 32])>,
    pub(crate) tree: Arc<SparseMerkleTree>,
    /// The bytes of every cell entry stamped at or before `commit`'s cycle.
    pub(crate) cell_bytes: u64,
}

impl CommittedLeaves {
    /// The leaf set as the store holds it, read whole: the tree is built
    /// from the rows exactly as a proof built from the store builds it.
    pub(crate) fn read(commit: Option<ByteCommit>, leaves: &[CellLeaf], cell_bytes: u64) -> Self {
        let tree = dsm::storage_cell::cell_tree(
            leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)),
        );
        Self {
            commit,
            latest: leaves
                .iter()
                .map(|(n, k, i, h)| (leaf_key(n, k), (*i, *h)))
                .collect(),
            tree: Arc::new(tree),
            cell_bytes,
        }
    }

    /// The leaf set once the entries `stamped` in the next cycle, each with
    /// its value's length, are committed too: each cell's leaf is its entry
    /// with the highest arrival index among those held and those stamped,
    /// as the store's "latest entry at or before the cycle" reads it. The
    /// tree is this one with the leaves that changed written. It is still as
    /// of the previous ByteCommit until the caller stores the new one and
    /// sets it. This leaf set is left as it is, so a close that does not
    /// commit still holds the leaf set the store is as of.
    pub(crate) fn advance(&self, stamped: &[(CellLeaf, u64)]) -> Result<Self> {
        let mut latest = self.latest.clone();
        let mut written = BTreeSet::new();
        let mut cell_bytes = self.cell_bytes;
        for ((namespace, key, index, running_hash), length) in stamped {
            cell_bytes = cell_bytes
                .checked_add(*length)
                .ok_or_else(|| anyhow!("the bytes this node holds overflow a u64"))?;
            let leaf = leaf_key(namespace, key);
            if latest.get(&leaf).is_some_and(|(held, _)| held >= index) {
                continue;
            }
            latest.insert(leaf, (*index, *running_hash));
            written.insert(leaf);
        }
        // Writing a leaf rehashes its whole path, building hashes each node
        // once: past a quarter of the leaves changed, building is cheaper.
        // The root and every proof are a function of the leaves alone.
        let tree = if written.len() * 4 > latest.len() {
            SparseMerkleTree::from_leaves(
                latest
                    .iter()
                    .map(|(leaf, (index, running_hash))| (*leaf, leaf_value(*index, running_hash))),
            )
        } else {
            let mut tree = SparseMerkleTree::clone(&self.tree);
            for leaf in &written {
                let (index, running_hash) = latest[leaf];
                tree.update_leaf(leaf, &leaf_value(index, &running_hash));
            }
            tree
        };
        Ok(Self {
            commit: self.commit.clone(),
            latest,
            tree: Arc::new(tree),
            cell_bytes,
        })
    }
}
