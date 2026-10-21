// SPDX-License-Identifier: MIT OR Apache-2.0

//! What one step wrote to its device tree.
//!
//! A step moves the device root from `R_i` to `R_{i+1}` over every leaf it
//! writes — the relationship leaf, and for an offline-bearer spend the leaf of
//! the offline account it spends from as well, whose root carries the
//! allocation debit, the counter step and the frontier's advance (§9: the
//! counter and the value source are inside the root). A receipt that proves the step
//! has to prove all of them against the one pre-root, or it proves a different
//! move. [`StepTransition`] is that move as its producer holds it: each written
//! leaf with the value it held, the value written and its path against the
//! pre-root, and both roots.

use crate::merkle::batch_fold::{batch_fold, FoldEntry};
use crate::merkle::smt_path;
use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};
use crate::types::error::DsmError;
use crate::types::offline_account::SpendWitness;
use crate::types::receipt_types::{ReceiptLeaf, ReceiptWrite};

/// Every leaf one step wrote, with its path against the step's pre-root, and
/// both roots. Built only by [`StepTransition::apply`], which refuses to
/// return a set of writes that does not fold from the pre-root to the root the
/// tree actually reached.
#[derive(Clone, Debug)]
pub struct StepTransition {
    pre_root: [u8; 32],
    post_root: [u8; 32],
    writes: Vec<FoldEntry>,
    offline_account: Option<([u8; 32], SpendWitness)>,
}

impl StepTransition {
    /// Apply `writes` to `tree` as one move and record it. The recorded
    /// writes are checked to fold from the tree's root before the move to the
    /// root after it: a transition that does not prove its own move is never
    /// returned.
    pub(crate) fn apply(
        tree: &mut SparseMerkleTree,
        writes: &[([u8; 32], [u8; 32])],
        offline_account: Option<([u8; 32], SpendWitness)>,
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
        if let Some((key, witness)) = &offline_account {
            if !entries
                .iter()
                .any(|e| &e.key == key && e.pre == Some(witness.pre_account_root))
            {
                return Err(DsmError::invalid_operation(
                    "a step names the offline account it spent from but does not write it",
                ));
            }
        }
        Ok(Self {
            pre_root,
            post_root,
            writes: entries,
            offline_account,
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

    /// The offline account a bearer spend drew from: its device-SMT key and
    /// the spend's witness.
    pub fn offline_account(&self) -> Option<&([u8; 32], SpendWitness)> {
        self.offline_account.as_ref()
    }

    /// The step's writes as its receipt carries them: each leaf named by what
    /// it is, with its path in the one canonical encoding, in key order.
    /// `relationship_key` is the relationship leaf the step advanced; an
    /// offline-bearer spend's account leaf is named by the witness the step
    /// recorded. A step that writes any other leaf (a token adoption) has no
    /// receipt that names it, and is refused rather than proven in part.
    pub fn receipt_writes(
        &self,
        relationship_key: &[u8; 32],
    ) -> Result<Vec<ReceiptWrite>, DsmError> {
        self.writes
            .iter()
            .map(|entry| {
                let leaf = if &entry.key == relationship_key {
                    ReceiptLeaf::Relationship
                } else if let Some((_, witness)) = self
                    .offline_account
                    .as_ref()
                    .filter(|(key, _)| key == &entry.key)
                {
                    ReceiptLeaf::OfflineAccount(Box::new(witness.clone()))
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::core::bilateral_transaction_manager::compute_smt_key;
    use crate::merkle::batch_fold::verify_batch;
    use crate::types::step_fixture::{transfer_step, Party};

    /// A real step's transition folds from its pre-root to its post-root,
    /// names the relationship leaf it moved, and its receipt carries exactly
    /// that write; a relationship key the step did not write names nothing,
    /// so no receipt proves the step in part.
    #[test]
    fn a_transition_proves_its_own_move_and_nothing_less() {
        let sender = Party::from_seed(b"step transition sender wallet seed");
        let receiver = Party::from_seed(b"step transition receiver wallet seed");
        let step = transfer_step(&sender, &receiver, 7);
        let transition = &step.outcome.transition;
        assert_eq!(
            verify_batch::<DeviceSmtHashes>(&transition.pre_root(), transition.writes())
                .expect("the writes fold from the pre-root"),
            transition.post_root()
        );
        let rel_key = compute_smt_key(&sender.device_id(), &receiver.device_id());
        let write = transition
            .write_at(&rel_key)
            .expect("the step moved its leaf");
        assert_eq!(write.post, Some(step.receipt.child_tip));
        assert_eq!(
            transition.receipt_writes(&rel_key).expect("receipt writes"),
            step.receipt.step_writes
        );
        let self_loop = compute_smt_key(&sender.device_id(), &sender.device_id());
        let refused = transition
            .receipt_writes(&self_loop)
            .expect_err("a written leaf no receipt names refuses the receipt");
        assert!(refused.to_string().contains("no receipt names"));
    }

    /// A step that names an offline account it does not write is refused:
    /// the witness would describe a leaf the root never moved.
    #[test]
    fn an_offline_account_the_step_does_not_write_is_refused() {
        let sender = Party::from_seed(b"step transition sender wallet seed");
        let receiver = Party::from_seed(b"step transition receiver wallet seed");
        let step = transfer_step(&sender, &receiver, 7);
        let rel_key = compute_smt_key(&sender.device_id(), &receiver.device_id());
        let written = [(rel_key, step.receipt.child_tip)];
        let account = crate::types::offline_account::OfflineAccount::open([0x01; 32], 0);
        let witness = SpendWitness {
            pre_account_root: account.root(),
            pre_allocation: 5,
            pre_counter: 0,
            pre_frontier: [0x01; 32],
            next_frontier: [0x02; 32],
            account_paths: Vec::new(),
        };
        let unwritten = crate::types::offline_account::offline_account_leaf_key(&[0x0B; 32]);
        let mut tree = SparseMerkleTree::new();
        let refused = StepTransition::apply(&mut tree, &written, Some((unwritten, witness)))
            .expect_err("an account the step does not write");
        assert!(refused.to_string().contains("does not write it"));
        let mut tree = SparseMerkleTree::new();
        StepTransition::apply(&mut tree, &written, None).expect("the same writes, no account");
    }
}
