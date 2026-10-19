// SPDX-License-Identifier: MIT OR Apache-2.0

//! The offline account: a smaller SMT that hangs off the device SMT.
//!
//! Value spent offline is not the online balance. It is moved first, by a
//! canonical load, into a separate account the device holds for its enrolled
//! anchor bundle `B`, and it comes back by a canonical unload. That account is
//! its own sparse Merkle tree, and its root `R_off` is one leaf of the device
//! SMT, at `offline_account_leaf_key(B)`:
//!
//! ```text
//! R_A ─ … ─ offline_account_leaf_key(B) → R_off
//!                                          │
//!            allocation(asset) → H(amount) ┤
//!            counter           → H(u)      ┤   the software counter (DSM §68)
//!            frontier          → h         ┤   the offline frontier
//!            origin            → op id     ┘   the boundary that last funded it
//! ```
//!
//! The counter leaf is the authority for offline progression (DSM §68, §69):
//! `u_{i+1} = u_i + 1` is committed into authenticated state, and the anchor's
//! hardware counter is its mirror, never the other way round.
//!
//! Each transition is ONE write set over the account tree, returned as fold
//! entries against the account's pre-root. A verifier recomputes the leaves a
//! transition must touch from the transition and the stated pre-values, folds
//! them with the carried paths, and gets the post-root only if the pre-root
//! matches. A leaf the transition does not name is not in the write set, so
//! the fold proves it unchanged.
//!
//! All hashing is domain-separated BLAKE3. No JSON, no hex, no wall-clock.

use std::collections::BTreeMap;

use crate::common::domain_tags::{
    TAG_OFFLINE_ACCOUNT_ALLOCATION_KEY, TAG_OFFLINE_ACCOUNT_ALLOCATION_VALUE,
    TAG_OFFLINE_ACCOUNT_COUNTER_KEY, TAG_OFFLINE_ACCOUNT_COUNTER_VALUE,
    TAG_OFFLINE_ACCOUNT_FRONTIER_KEY, TAG_OFFLINE_ACCOUNT_LEAF, TAG_OFFLINE_ACCOUNT_ORIGIN_KEY,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::batch_fold::{verify_batch, FoldEntry, FOLD_HEIGHT};
use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};
use crate::types::error::DsmError;

/// Device-SMT key of the offline account for anchor bundle `B`:
/// `H("DSM/offline-account/v1" ‖ B)`. Its value is the account root `R_off`.
pub fn offline_account_leaf_key(bundle: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_LEAF);
    h.update(bundle);
    *h.finalize().as_bytes()
}

/// Account-tree key of the allocation of `asset`.
pub fn allocation_key(asset: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_ALLOCATION_KEY);
    h.update(asset);
    *h.finalize().as_bytes()
}

/// Account-tree value of an allocation holding `amount`.
pub fn allocation_value(amount: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_ALLOCATION_VALUE);
    h.update(&amount.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Account-tree key of the software counter.
pub fn counter_key() -> [u8; 32] {
    *dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_COUNTER_KEY)
        .finalize()
        .as_bytes()
}

/// Account-tree value of the software counter at `u`.
pub fn counter_value(u: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_COUNTER_VALUE);
    h.update(&u.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Account-tree key of the offline frontier. Its value is the frontier itself.
pub fn frontier_key() -> [u8; 32] {
    *dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_FRONTIER_KEY)
        .finalize()
        .as_bytes()
}

/// Account-tree key of the funding origin. Its value is the economic operation
/// id of the boundary (load or unload) that last moved value across.
pub fn origin_key() -> [u8; 32] {
    *dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_ORIGIN_KEY)
        .finalize()
        .as_bytes()
}

/// One transition of an offline account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineAccountStep {
    /// A canonical load: `amount` of `asset` enters the account. `origin` is
    /// the economic operation id of the load.
    Load {
        asset: [u8; 32],
        amount: u64,
        origin: [u8; 32],
    },
    /// A canonical unload: `amount` of `asset` leaves the account for the
    /// online balance. `origin` is the economic operation id of the unload.
    Unload {
        asset: [u8; 32],
        amount: u64,
        origin: [u8; 32],
    },
    /// An offline-bearer spend: `amount` of `asset` leaves the account, and
    /// the counter and the frontier advance with it in the same write set.
    Spend {
        asset: [u8; 32],
        amount: u64,
        next_frontier: [u8; 32],
    },
}

/// The values a step's touched leaves held before it, as the prover states
/// them. A verifier never takes them on trust: they are hashed into the
/// fold's pre-leaves, and a misstated one folds to a different pre-root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepBefore {
    /// Before a load or an unload: the allocation of the step's asset, if the
    /// account holds one, and the origin, if a boundary has funded it.
    Boundary {
        allocation: Option<u64>,
        origin: Option<[u8; 32]>,
    },
    /// Before a spend: the allocation of the step's asset, the counter and
    /// the frontier.
    Spend {
        allocation: u64,
        counter: u64,
        frontier: [u8; 32],
    },
}

/// One leaf a step writes: its key and its value before and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountWrite {
    pub key: [u8; 32],
    pub pre: Option<[u8; 32]>,
    pub post: [u8; 32],
}

/// The leaves `step` writes, from the values `before` states, sorted by key.
///
/// The one function the prover and the verifier share: the write set is a
/// function of the step and its pre-values, never of anything else the
/// prover chooses.
pub fn step_writes(
    step: &OfflineAccountStep,
    before: &StepBefore,
) -> Result<Vec<AccountWrite>, DsmError> {
    let mut writes = match (step, before) {
        (
            OfflineAccountStep::Load {
                asset,
                amount,
                origin,
            },
            StepBefore::Boundary {
                allocation,
                origin: prior_origin,
            },
        ) => {
            positive(*amount, "a load")?;
            // An asset the account has never held starts its allocation here.
            let next = match allocation {
                Some(held) => held.checked_add(*amount).ok_or_else(|| {
                    DsmError::invalid_operation("a load overflows the offline allocation")
                })?,
                None => *amount,
            };
            boundary_writes(asset, *allocation, next, *prior_origin, *origin)?
        }
        (
            OfflineAccountStep::Unload {
                asset,
                amount,
                origin,
            },
            StepBefore::Boundary {
                allocation,
                origin: prior_origin,
            },
        ) => {
            positive(*amount, "an unload")?;
            let held = allocation.ok_or_else(|| {
                DsmError::invalid_operation("an unload names an asset the account does not hold")
            })?;
            let next = held.checked_sub(*amount).ok_or_else(|| {
                DsmError::invalid_operation(
                    "an unload takes more than the offline allocation holds",
                )
            })?;
            boundary_writes(asset, *allocation, next, *prior_origin, *origin)?
        }
        (
            OfflineAccountStep::Spend {
                asset,
                amount,
                next_frontier,
            },
            StepBefore::Spend {
                allocation,
                counter,
                frontier,
            },
        ) => {
            positive(*amount, "a spend")?;
            let next = allocation.checked_sub(*amount).ok_or_else(|| {
                DsmError::invalid_operation("a spend takes more than the offline allocation holds")
            })?;
            let next_counter = counter
                .checked_add(1)
                .ok_or_else(|| DsmError::invalid_operation("the offline counter is exhausted"))?;
            if next_frontier == frontier {
                return Err(DsmError::invalid_operation(
                    "a spend moves the offline frontier",
                ));
            }
            vec![
                AccountWrite {
                    key: allocation_key(asset),
                    pre: Some(allocation_value(*allocation)),
                    post: allocation_value(next),
                },
                AccountWrite {
                    key: counter_key(),
                    pre: Some(counter_value(*counter)),
                    post: counter_value(next_counter),
                },
                AccountWrite {
                    key: frontier_key(),
                    pre: Some(*frontier),
                    post: *next_frontier,
                },
            ]
        }
        _ => {
            return Err(DsmError::invalid_operation(
                "the stated pre-values are not those of this kind of step",
            ))
        }
    };
    writes.sort_by_key(|w| w.key);
    Ok(writes)
}

fn positive(amount: u64, what: &str) -> Result<(), DsmError> {
    match amount {
        0 => Err(DsmError::invalid_operation(format!(
            "{what} moves a positive amount"
        ))),
        _ => Ok(()),
    }
}

fn boundary_writes(
    asset: &[u8; 32],
    allocation: Option<u64>,
    next: u64,
    prior_origin: Option<[u8; 32]>,
    origin: [u8; 32],
) -> Result<Vec<AccountWrite>, DsmError> {
    if prior_origin == Some(origin) {
        return Err(DsmError::invalid_operation(
            "a boundary names the operation that already funded the account",
        ));
    }
    Ok(vec![
        AccountWrite {
            key: allocation_key(asset),
            pre: allocation.map(allocation_value),
            post: allocation_value(next),
        },
        AccountWrite {
            key: origin_key(),
            pre: prior_origin,
            post: origin,
        },
    ])
}

/// Verify one step of an offline account: fold the step's writes, recomputed
/// from `step` and `before`, with the carried `paths` (one per write, in key
/// order) against `pre_root`. Returns the post-root.
///
/// The fold is the multiproof: every path is against the same pre-root, and
/// the post-root accounts for exactly the writes the step makes, so every
/// other leaf of the account is the same on both sides.
pub fn verify_step(
    pre_root: &[u8; 32],
    step: &OfflineAccountStep,
    before: &StepBefore,
    paths: &[Box<[[u8; 32]; FOLD_HEIGHT]>],
) -> Result<[u8; 32], DsmError> {
    let writes = step_writes(step, before)?;
    if writes.len() != paths.len() {
        return Err(DsmError::invalid_operation(format!(
            "the step writes {} account leaves; {} paths are carried",
            writes.len(),
            paths.len()
        )));
    }
    let entries: Vec<FoldEntry> = writes
        .iter()
        .zip(paths)
        .map(|(w, path)| FoldEntry {
            key: w.key,
            pre: w.pre,
            post: Some(w.post),
            path: path.clone(),
        })
        .collect();
    verify_batch::<DeviceSmtHashes>(pre_root, &entries)
        .map_err(|e| DsmError::invalid_operation(format!("the offline account step: {e}")))
}

/// The offline account of one enrolled anchor bundle.
///
/// The tree is the canonical source of truth; the fields beside it are the
/// enumerable record of the same leaves, kept so the account can be persisted
/// and rebuilt, and so a step can state its pre-values.
#[derive(Clone)]
pub struct OfflineAccount {
    tree: SparseMerkleTree,
    allocations: BTreeMap<[u8; 32], u64>,
    counter: u64,
    frontier: [u8; 32],
    origin: Option<[u8; 32]>,
}

impl core::fmt::Debug for OfflineAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OfflineAccount")
            .field("root", &self.tree.root())
            .field("allocations", &self.allocations)
            .field("counter", &self.counter)
            .field("frontier", &self.frontier)
            .field("origin", &self.origin)
            .finish()
    }
}

/// An offline account after one step, with the step's writes as fold entries
/// against the account's pre-root.
#[derive(Debug, Clone)]
pub struct OfflineAccountMove {
    pub account: OfflineAccount,
    pub before: StepBefore,
    pub entries: Vec<FoldEntry>,
}

impl OfflineAccount {
    /// Open the account of a newly enrolled anchor at its frontier and
    /// counter. It holds no allocation and no boundary has funded it.
    pub fn open(frontier: [u8; 32], counter: u64) -> Self {
        Self::restore(BTreeMap::new(), counter, frontier, None)
    }

    /// Rebuild an account from its persisted record.
    pub fn restore(
        allocations: BTreeMap<[u8; 32], u64>,
        counter: u64,
        frontier: [u8; 32],
        origin: Option<[u8; 32]>,
    ) -> Self {
        let leaves = allocations
            .iter()
            .map(|(asset, amount)| (allocation_key(asset), allocation_value(*amount)))
            .chain([
                (counter_key(), counter_value(counter)),
                (frontier_key(), frontier),
            ])
            .chain(origin.map(|o| (origin_key(), o)));
        Self {
            tree: SparseMerkleTree::from_leaves(leaves),
            allocations,
            counter,
            frontier,
            origin,
        }
    }

    /// The account root `R_off`, the device-SMT leaf value.
    pub fn root(&self) -> [u8; 32] {
        *self.tree.root()
    }

    /// The allocation of `asset`, if the account holds one.
    pub fn allocation(&self, asset: &[u8; 32]) -> Option<u64> {
        self.allocations.get(asset).copied()
    }

    /// Every allocation, for persistence.
    pub fn allocations(&self) -> &BTreeMap<[u8; 32], u64> {
        &self.allocations
    }

    /// The software counter `u`.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The offline frontier `h`.
    pub fn frontier(&self) -> [u8; 32] {
        self.frontier
    }

    /// The economic operation id of the boundary that last funded the account.
    pub fn origin(&self) -> Option<[u8; 32]> {
        self.origin
    }

    /// The values `step`'s touched leaves hold in this account.
    pub fn before(&self, step: &OfflineAccountStep) -> Result<StepBefore, DsmError> {
        match step {
            OfflineAccountStep::Load { asset, .. } | OfflineAccountStep::Unload { asset, .. } => {
                Ok(StepBefore::Boundary {
                    allocation: self.allocation(asset),
                    origin: self.origin,
                })
            }
            OfflineAccountStep::Spend { asset, .. } => Ok(StepBefore::Spend {
                allocation: self.allocation(asset).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "a spend names an asset the offline account does not hold",
                    )
                })?,
                counter: self.counter,
                frontier: self.frontier,
            }),
        }
    }

    /// Take `step` as one write set. Fails, leaving `self` untouched, on any
    /// step the account cannot take.
    pub fn step(&self, step: &OfflineAccountStep) -> Result<OfflineAccountMove, DsmError> {
        let before = self.before(step)?;
        let writes = step_writes(step, &before)?;
        let mut tree = self.tree.clone();
        let pairs: Vec<([u8; 32], [u8; 32])> = writes.iter().map(|w| (w.key, w.post)).collect();
        let entries = tree.apply_writes(&pairs)?;
        let mut account = Self {
            tree,
            allocations: self.allocations.clone(),
            counter: self.counter,
            frontier: self.frontier,
            origin: self.origin,
        };
        match step {
            OfflineAccountStep::Load {
                asset,
                amount,
                origin,
            } => {
                let held = account.allocations.entry(*asset).or_insert(0);
                *held += amount;
                account.origin = Some(*origin);
            }
            OfflineAccountStep::Unload {
                asset,
                amount,
                origin,
            } => {
                let held = account.allocations.entry(*asset).or_insert(0);
                *held -= amount;
                account.origin = Some(*origin);
            }
            OfflineAccountStep::Spend {
                asset,
                amount,
                next_frontier,
            } => {
                let held = account.allocations.entry(*asset).or_insert(0);
                *held -= amount;
                account.counter += 1;
                account.frontier = *next_frontier;
            }
        }
        Ok(OfflineAccountMove {
            account,
            before,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSET: [u8; 32] = [0xA1; 32];
    const OTHER: [u8; 32] = [0xB2; 32];

    fn refused<T: core::fmt::Debug>(result: Result<T, DsmError>, reason: &str) {
        let error = result.expect_err("the step is refused");
        assert!(
            error.to_string().contains(reason),
            "refused for another reason: {error}"
        );
    }

    fn paths(m: &OfflineAccountMove) -> Vec<Box<[[u8; 32]; FOLD_HEIGHT]>> {
        m.entries.iter().map(|e| e.path.clone()).collect()
    }

    fn load(asset: [u8; 32], amount: u64, origin: u8) -> OfflineAccountStep {
        OfflineAccountStep::Load {
            asset,
            amount,
            origin: [origin; 32],
        }
    }

    fn spend(amount: u64, next_frontier: u8) -> OfflineAccountStep {
        OfflineAccountStep::Spend {
            asset: ASSET,
            amount,
            next_frontier: [next_frontier; 32],
        }
    }

    #[test]
    fn each_step_folds_from_its_pre_root_to_the_account_it_leaves() {
        let opened = OfflineAccount::open([0x01; 32], 0);
        let steps = [
            load(ASSET, 30, 0x10),
            load(OTHER, 7, 0x11),
            spend(10, 0x02),
            OfflineAccountStep::Unload {
                asset: ASSET,
                amount: 5,
                origin: [0x12; 32],
            },
        ];
        let mut account = opened;
        for step in &steps {
            let m = account.step(step).expect("the account takes the step");
            let post = verify_step(&account.root(), step, &m.before, &paths(&m))
                .expect("the step verifies");
            assert_eq!(post, m.account.root());
            account = m.account;
        }
        assert_eq!(account.allocation(&ASSET), Some(15));
        assert_eq!(account.allocation(&OTHER), Some(7));
        assert_eq!(account.counter(), 1);
        assert_eq!(account.frontier(), [0x02; 32]);
        assert_eq!(account.origin(), Some([0x12; 32]));
        let rebuilt = OfflineAccount::restore(
            account.allocations().clone(),
            account.counter(),
            account.frontier(),
            account.origin(),
        );
        assert_eq!(rebuilt.root(), account.root());
    }

    #[test]
    fn a_spend_from_an_allocation_the_account_never_held_does_not_fold() {
        let funded = OfflineAccount::open([0x01; 32], 0)
            .step(&load(ASSET, 10, 0x10))
            .expect("load")
            .account;
        let step = spend(50, 0x02);
        let honest = funded.step(&spend(10, 0x02)).expect("spend");
        // The prover states an allocation of 50 the account never held.
        let inflated = StepBefore::Spend {
            allocation: 50,
            counter: 0,
            frontier: [0x01; 32],
        };
        refused(
            verify_step(&funded.root(), &step, &inflated, &paths(&honest)),
            "the offline account step:",
        );
        refused(funded.step(&step), "more than the offline allocation holds");
    }

    #[test]
    fn a_spend_moves_the_allocation_counter_and_frontier_and_nothing_else() {
        let account = OfflineAccount::open([0x01; 32], 4)
            .step(&load(ASSET, 10, 0x10))
            .expect("load")
            .account
            .step(&load(OTHER, 9, 0x11))
            .expect("load")
            .account;
        let step = spend(3, 0x02);
        let m = account.step(&step).expect("spend");
        let keys: Vec<[u8; 32]> = m.entries.iter().map(|e| e.key).collect();
        let mut expected = vec![allocation_key(&ASSET), counter_key(), frontier_key()];
        expected.sort();
        assert_eq!(keys, expected);
        assert_eq!(m.account.allocation(&OTHER), Some(9));
        assert_eq!(m.account.counter(), 5);
        // One path more than the step writes is not this step's multiproof.
        let mut extra = paths(&m);
        extra.push(extra[0].clone());
        refused(
            verify_step(&account.root(), &step, &m.before, &extra),
            "4 paths are carried",
        );
    }

    #[test]
    fn steps_the_account_cannot_take_leave_it_untouched() {
        let opened = OfflineAccount::open([0x01; 32], 0);
        let root = opened.root();
        refused(opened.step(&spend(1, 0x02)), "does not hold");
        refused(
            opened.step(&OfflineAccountStep::Unload {
                asset: ASSET,
                amount: 1,
                origin: [0x10; 32],
            }),
            "does not hold",
        );
        refused(opened.step(&load(ASSET, 0, 0x10)), "positive amount");
        let funded = opened.step(&load(ASSET, 5, 0x10)).expect("load").account;
        refused(funded.step(&load(ASSET, 1, 0x10)), "already funded");
        refused(funded.step(&spend(1, 0x01)), "moves the offline frontier");
        let exhausted = OfflineAccount::open([0x01; 32], u64::MAX)
            .step(&load(ASSET, 5, 0x10))
            .expect("load")
            .account;
        refused(exhausted.step(&spend(1, 0x02)), "counter is exhausted");
        assert_eq!(opened.root(), root);
    }

    #[test]
    fn the_device_leaf_is_one_key_per_bundle() {
        assert_eq!(
            offline_account_leaf_key(&[0x0B; 32]),
            offline_account_leaf_key(&[0x0B; 32])
        );
        assert_ne!(
            offline_account_leaf_key(&[0x0B; 32]),
            offline_account_leaf_key(&[0x0C; 32])
        );
        let keys = [
            allocation_key(&ASSET),
            counter_key(),
            frontier_key(),
            origin_key(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
