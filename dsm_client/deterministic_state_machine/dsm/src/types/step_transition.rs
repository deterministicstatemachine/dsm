// SPDX-License-Identifier: MIT OR Apache-2.0

//! What one step wrote to its device tree.
//!
//! A step moves the device root from `R_i` to `R_{i+1}` over every leaf it
//! writes — the relationship leaf, and for an offline-bearer spend the
//! anchor-state leaf and the offline allocation leaf as well (§9: the counter
//! and the value source are inside the root). A receipt that proves the step
//! has to prove all of them against the one pre-root, or it proves a different
//! move. [`StepTransition`] is that move as its producer holds it: each written
//! leaf with the value it held, the value written and its path against the
//! pre-root, and both roots.

use crate::merkle::batch_fold::{batch_fold, FoldEntry};
use crate::merkle::smt_path;
use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};
use crate::types::error::DsmError;
use crate::types::receipt_types::{ReceiptLeaf, ReceiptWrite};

/// The offline allocation a bearer spend drew from, as it stood BEFORE the
/// step. Its leaf is an opaque hash of `(amount, sequence)`, so a verifier
/// cannot derive the debit from the leaf alone: this preimage is the minimum
/// witness a receipt carries for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationBefore {
    pub key: [u8; 32],
    pub amount: u64,
    pub sequence: u64,
}

/// Every leaf one step wrote, with its path against the step's pre-root, and
/// both roots. Built only by [`StepTransition::apply`], which refuses to
/// return a set of writes that does not fold from the pre-root to the root the
/// tree actually reached.
#[derive(Clone, Debug)]
pub struct StepTransition {
    pre_root: [u8; 32],
    post_root: [u8; 32],
    writes: Vec<FoldEntry>,
    allocation_before: Option<AllocationBefore>,
}

impl StepTransition {
    /// Apply `writes` to `tree` as one move and record it. The recorded
    /// writes are checked to fold from the tree's root before the move to the
    /// root after it: a transition that does not prove its own move is never
    /// returned.
    pub(crate) fn apply(
        tree: &mut SparseMerkleTree,
        writes: &[([u8; 32], [u8; 32])],
        allocation_before: Option<AllocationBefore>,
    ) -> Result<Self, DsmError> {
        let pre_root = *tree.root();
        let entries = tree.apply_writes(writes)?;
        let post_root = *tree.root();
        let folded = batch_fold::<DeviceSmtHashes>(&entries)
            .map_err(|e| DsmError::invalid_operation(format!("a step's writes: {e}")))?;
        if folded.pre_root != pre_root || folded.post_root != post_root {
            return Err(DsmError::invalid_operation(
                "a step's writes do not fold from the tree's root before the step to its root after",
            ));
        }
        if let Some(before) = &allocation_before {
            if !entries.iter().any(|e| e.key == before.key) {
                return Err(DsmError::invalid_operation(
                    "a step names the allocation it drew from but does not write it",
                ));
            }
        }
        Ok(Self {
            pre_root,
            post_root,
            writes: entries,
            allocation_before,
        })
    }

    /// The device root before the step (`R_i`).
    pub fn pre_root(&self) -> [u8; 32] {
        self.pre_root
    }

    /// The device root after the step (`R_{i+1}`).
    pub fn post_root(&self) -> [u8; 32] {
        self.post_root
    }

    /// Every leaf the step wrote, sorted by key, each with its path against
    /// [`Self::pre_root`].
    pub fn writes(&self) -> &[FoldEntry] {
        &self.writes
    }

    /// The write at `key`, if the step wrote it.
    pub fn write_at(&self, key: &[u8; 32]) -> Option<&FoldEntry> {
        self.writes.iter().find(|e| &e.key == key)
    }

    /// The allocation a bearer spend drew from, as it stood before the step.
    pub fn allocation_before(&self) -> Option<AllocationBefore> {
        self.allocation_before
    }

    /// The step's writes as its receipt carries them: each leaf named by what
    /// it is, with its path in the one canonical encoding, in key order.
    /// `relationship_key` is the relationship leaf the step advanced;
    /// `anchor_key` is the anchor-state leaf a bearer step moved. A step that
    /// writes any other leaf (a token adoption, a reserve or vault leaf) has no
    /// receipt that names it, and is refused rather than proven in part.
    pub fn receipt_writes(
        &self,
        relationship_key: &[u8; 32],
        anchor_key: Option<&[u8; 32]>,
    ) -> Result<Vec<ReceiptWrite>, DsmError> {
        self.writes
            .iter()
            .map(|entry| {
                let leaf = if &entry.key == relationship_key {
                    ReceiptLeaf::Relationship
                } else if Some(&entry.key) == anchor_key {
                    ReceiptLeaf::AnchorState
                } else if let Some(before) = self
                    .allocation_before
                    .filter(|before| before.key == entry.key)
                {
                    ReceiptLeaf::OfflineAllocation {
                        pre_amount: before.amount,
                        pre_sequence: before.sequence,
                    }
                } else {
                    return Err(DsmError::invalid_operation(
                        "the step writes a leaf no receipt names; it has no receipt",
                    ));
                };
                Ok(ReceiptWrite {
                    leaf,
                    path: smt_path::encode::<DeviceSmtHashes>(&entry.path),
                })
            })
            .collect()
    }
}
