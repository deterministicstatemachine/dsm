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
//!            funding chain     → op id     ┤   the last boundary, which chains every one before it
//!            received(asset)   → H(amount) ┘   value received offline, waiting for its unload
//! ```
//!
//! Value received offline (owner, 2026-11-07: an offline payment needs a board on both sides, and
//! the money received lands in the receiver's own offline balance) sits in its own leaf, apart from
//! the loaded allocation: no spend draws from it, and it leaves only by its unload, which a contact
//! takes once the payer's own online history shows the spend.
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
    TAG_OFFLINE_ACCOUNT_FRONTIER_KEY, TAG_OFFLINE_ACCOUNT_FUNDING_CHAIN_KEY,
    TAG_OFFLINE_ACCOUNT_LEAF, TAG_OFFLINE_ACCOUNT_RECEIVED_KEY, TAG_OFFLINE_ACCOUNT_RECEIVED_VALUE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::batch_fold::{fold_path, verify_batch, FoldEntry, FOLD_HEIGHT};
use crate::merkle::smt_path::{self, EncodedPath};
use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};
use crate::types::error::DsmError;
use crate::types::proto::SmtPath as SmtPathProto;

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

/// Account-tree key of the amount of `asset` received offline.
pub fn received_key(asset: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_RECEIVED_KEY);
    h.update(asset);
    *h.finalize().as_bytes()
}

/// Account-tree value of a received amount of `amount`.
pub fn received_value(amount: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_RECEIVED_VALUE);
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

/// Account-tree key of the funding chain. Its value is the economic operation
/// id of the boundary (load or unload) that last moved value across — and that
/// id is a hash over the account root the boundary started from, which holds
/// this leaf's previous value. So the leaf commits every boundary since the
/// account opened, as a hash chain: a later load extends the chain, it never
/// replaces the provenance of value an earlier load brought in. A verifier
/// holding the boundaries' bodies walks the chain back from any account root.
pub fn funding_chain_key() -> [u8; 32] {
    *dsm_domain_hasher(TAG_OFFLINE_ACCOUNT_FUNDING_CHAIN_KEY)
        .finalize()
        .as_bytes()
}

/// One transition of an offline account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineAccountStep {
    /// A canonical load: `amount` of `asset` enters the account. `boundary_id` is
    /// the economic operation id of the load.
    Load {
        asset: [u8; 32],
        amount: u64,
        boundary_id: [u8; 32],
    },
    /// A canonical unload: `amount` of `asset` leaves the account for the
    /// online balance. `boundary_id` is the economic operation id of the unload.
    Unload {
        asset: [u8; 32],
        amount: u64,
        boundary_id: [u8; 32],
    },
    /// An offline-bearer spend: `amount` of `asset` leaves the account, and
    /// the counter and the frontier advance with it in the same write set.
    Spend {
        asset: [u8; 32],
        amount: u64,
        next_frontier: [u8; 32],
    },
    /// An offline-bearer receive, the receiver's board's receive commit: `amount` of `asset` is
    /// added to what the account holds received (never to its loaded allocation), and the counter
    /// and the frontier advance with it in the same write set.
    Receive {
        asset: [u8; 32],
        amount: u64,
        next_frontier: [u8; 32],
    },
    /// The unload of a payment received offline: `amount` of `asset` leaves what the account holds
    /// received, for the online balance.
    Settle { asset: [u8; 32], amount: u64 },
}

/// The values a step's touched leaves held before it, as the prover states
/// them. A verifier never takes them on trust: they are hashed into the
/// fold's pre-leaves, and a misstated one folds to a different pre-root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepBefore {
    /// Before a load or an unload: the allocation of the step's asset, if the
    /// account holds one, and the funding chain, if a boundary has funded it.
    Boundary {
        allocation: Option<u64>,
        funding_chain: Option<[u8; 32]>,
    },
    /// Before a spend: the allocation of the step's asset, the counter and
    /// the frontier.
    Spend {
        allocation: u64,
        counter: u64,
        frontier: [u8; 32],
    },
    /// Before a receive: what the account holds received of the step's asset, if it ever received
    /// any, the counter and the frontier.
    Receive {
        received: Option<u64>,
        counter: u64,
        frontier: [u8; 32],
    },
    /// Before the unload of a received payment: what the account holds received of its asset.
    Settle { received: u64 },
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
                boundary_id,
            },
            StepBefore::Boundary {
                allocation,
                funding_chain: prior_chain,
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
            boundary_writes(asset, *allocation, next, *prior_chain, *boundary_id)?
        }
        (
            OfflineAccountStep::Unload {
                asset,
                amount,
                boundary_id,
            },
            StepBefore::Boundary {
                allocation,
                funding_chain: prior_chain,
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
            boundary_writes(asset, *allocation, next, *prior_chain, *boundary_id)?
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
        (
            OfflineAccountStep::Receive {
                asset,
                amount,
                next_frontier,
            },
            StepBefore::Receive {
                received,
                counter,
                frontier,
            },
        ) => {
            positive(*amount, "a receive")?;
            let next = match received {
                Some(held) => held.checked_add(*amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "a receive overflows what the account holds received",
                    )
                })?,
                None => *amount,
            };
            let next_counter = counter
                .checked_add(1)
                .ok_or_else(|| DsmError::invalid_operation("the offline counter is exhausted"))?;
            if next_frontier == frontier {
                return Err(DsmError::invalid_operation(
                    "a receive moves the offline frontier",
                ));
            }
            vec![
                AccountWrite {
                    key: received_key(asset),
                    pre: received.map(received_value),
                    post: received_value(next),
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
        (OfflineAccountStep::Settle { asset, amount }, StepBefore::Settle { received }) => {
            positive(*amount, "an unload of a received payment")?;
            let next = received.checked_sub(*amount).ok_or_else(|| {
                DsmError::invalid_operation(
                    "an unload of a received payment takes more than the account holds received",
                )
            })?;
            vec![AccountWrite {
                key: received_key(asset),
                pre: Some(received_value(*received)),
                post: received_value(next),
            }]
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
    prior_chain: Option<[u8; 32]>,
    boundary_id: [u8; 32],
) -> Result<Vec<AccountWrite>, DsmError> {
    if prior_chain == Some(boundary_id) {
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
            key: funding_chain_key(),
            pre: prior_chain,
            post: boundary_id,
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
    received: BTreeMap<[u8; 32], u64>,
    counter: u64,
    frontier: [u8; 32],
    funding_chain: Option<[u8; 32]>,
}

impl core::fmt::Debug for OfflineAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OfflineAccount")
            .field("root", &self.tree.root())
            .field("allocations", &self.allocations)
            .field("received", &self.received)
            .field("counter", &self.counter)
            .field("frontier", &self.frontier)
            .field("funding_chain", &self.funding_chain)
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
        Self::restore(BTreeMap::new(), BTreeMap::new(), counter, frontier, None)
    }

    /// Rebuild an account from its persisted record.
    pub fn restore(
        allocations: BTreeMap<[u8; 32], u64>,
        received: BTreeMap<[u8; 32], u64>,
        counter: u64,
        frontier: [u8; 32],
        funding_chain: Option<[u8; 32]>,
    ) -> Self {
        let leaves = allocations
            .iter()
            .map(|(asset, amount)| (allocation_key(asset), allocation_value(*amount)))
            .chain(
                received
                    .iter()
                    .map(|(asset, amount)| (received_key(asset), received_value(*amount))),
            )
            .chain([
                (counter_key(), counter_value(counter)),
                (frontier_key(), frontier),
            ])
            .chain(funding_chain.map(|o| (funding_chain_key(), o)));
        Self {
            tree: SparseMerkleTree::from_leaves(leaves),
            allocations,
            received,
            counter,
            frontier,
            funding_chain,
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

    /// Everything the account holds, per asset: what was loaded for paying and what it received
    /// offline, which waits there for its unload (owner, 2026-11-07). What a closed account takes
    /// with it.
    pub fn held(&self) -> Result<BTreeMap<[u8; 32], u64>, DsmError> {
        let mut held = self.allocations.clone();
        for (asset, amount) in &self.received {
            let total = held.entry(*asset).or_insert(0);
            *total = total.checked_add(*amount).ok_or_else(|| {
                DsmError::invalid_operation(
                    "an offline account holds more of an asset than a u64 counts",
                )
            })?;
        }
        Ok(held)
    }

    /// What the account holds received of `asset`, if it ever received any.
    pub fn received(&self, asset: &[u8; 32]) -> Option<u64> {
        self.received.get(asset).copied()
    }

    /// Everything the account holds received, by asset, for persistence.
    pub fn received_amounts(&self) -> &BTreeMap<[u8; 32], u64> {
        &self.received
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
    pub fn funding_chain(&self) -> Option<[u8; 32]> {
        self.funding_chain
    }

    /// The values `step`'s touched leaves hold in this account.
    pub fn before(&self, step: &OfflineAccountStep) -> Result<StepBefore, DsmError> {
        match step {
            OfflineAccountStep::Load { asset, .. } | OfflineAccountStep::Unload { asset, .. } => {
                Ok(StepBefore::Boundary {
                    allocation: self.allocation(asset),
                    funding_chain: self.funding_chain,
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
            OfflineAccountStep::Receive { asset, .. } => Ok(StepBefore::Receive {
                received: self.received(asset),
                counter: self.counter,
                frontier: self.frontier,
            }),
            OfflineAccountStep::Settle { asset, .. } => Ok(StepBefore::Settle {
                received: self.received(asset).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "an unload of a received payment names an asset the account never received",
                    )
                })?,
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
            received: self.received.clone(),
            counter: self.counter,
            frontier: self.frontier,
            funding_chain: self.funding_chain,
        };
        match step {
            OfflineAccountStep::Load {
                asset,
                amount,
                boundary_id,
            } => {
                let held = account.allocations.entry(*asset).or_insert(0);
                *held += amount;
                account.funding_chain = Some(*boundary_id);
            }
            OfflineAccountStep::Unload {
                asset,
                amount,
                boundary_id,
            } => {
                let held = account.allocations.entry(*asset).or_insert(0);
                *held -= amount;
                account.funding_chain = Some(*boundary_id);
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
            OfflineAccountStep::Receive {
                asset,
                amount,
                next_frontier,
            } => {
                let held = account.received.entry(*asset).or_insert(0);
                *held += amount;
                account.counter += 1;
                account.frontier = *next_frontier;
            }
            OfflineAccountStep::Settle { asset, amount } => {
                let held = account.received.entry(*asset).or_insert(0);
                *held -= amount;
            }
        }
        Ok(OfflineAccountMove {
            account,
            before,
            entries,
        })
    }
}

/// What a receipt carries for the offline account an offline-bearer spend
/// writes: the account as it stood before the step, the frontier the spend
/// advances to, and the account paths of the leaves the spend writes, in key
/// order. The account after the step is derived from these and the operation,
/// never carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendWitness {
    pub pre_account_root: [u8; 32],
    pub pre_allocation: u64,
    pub pre_counter: u64,
    pub pre_frontier: [u8; 32],
    pub next_frontier: [u8; 32],
    pub account_paths: Vec<EncodedPath>,
}

impl SpendWitness {
    /// The witness of `spend` taken by `before` (the account the spend
    /// started from), with the paths of the spend's writes.
    pub fn of(before: &OfflineAccount, spend: &OfflineAccountMove) -> Result<Self, DsmError> {
        let StepBefore::Spend {
            allocation,
            counter,
            frontier,
        } = spend.before
        else {
            return Err(DsmError::invalid_operation(
                "a spend witness is taken of a spend",
            ));
        };
        Ok(Self {
            pre_account_root: before.root(),
            pre_allocation: allocation,
            pre_counter: counter,
            pre_frontier: frontier,
            next_frontier: spend.account.frontier(),
            account_paths: spend
                .entries
                .iter()
                .map(|e| smt_path::encode::<DeviceSmtHashes>(&e.path))
                .collect(),
        })
    }

    /// The account root after spending `amount` of `asset`: the spend's
    /// writes, recomputed from this witness, folded from its pre-root.
    pub fn post_account_root(&self, asset: &[u8; 32], amount: u64) -> Result<[u8; 32], DsmError> {
        let paths = self
            .account_paths
            .iter()
            .map(|p| {
                smt_path::decode::<DeviceSmtHashes>(&p.explicit_heights, &p.siblings).map_err(|e| {
                    DsmError::invalid_operation(format!("an offline account path: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        verify_step(
            &self.pre_account_root,
            &OfflineAccountStep::Spend {
                asset: *asset,
                amount,
                next_frontier: self.next_frontier,
            },
            &StepBefore::Spend {
                allocation: self.pre_allocation,
                counter: self.pre_counter,
                frontier: self.pre_frontier,
            },
            &paths,
        )
    }
}

impl SpendWitness {
    /// The witness's wire form.
    pub fn to_proto(&self) -> crate::types::proto::StepWriteOfflineAccount {
        crate::types::proto::StepWriteOfflineAccount {
            pre_account_root: self.pre_account_root.to_vec(),
            pre_allocation: self.pre_allocation,
            pre_counter: self.pre_counter,
            pre_frontier: self.pre_frontier.to_vec(),
            next_frontier: self.next_frontier.to_vec(),
            account_paths: self
                .account_paths
                .iter()
                .map(|p| SmtPathProto {
                    heights: p.explicit_heights.to_vec(),
                    siblings: p.siblings.clone(),
                })
                .collect(),
        }
    }

    /// The witness a wire form states, its paths each in the one canonical
    /// encoding of a path.
    pub fn from_proto(a: crate::types::proto::StepWriteOfflineAccount) -> Result<Self, DsmError> {
        let fixed = |bytes: &[u8], what: &str| -> Result<[u8; 32], DsmError> {
            bytes.try_into().map_err(|e| {
                DsmError::invalid_operation(format!("an offline account witness's {what}: {e}"))
            })
        };
        let account_paths = a
            .account_paths
            .into_iter()
            .map(|p| {
                smt_path::decode::<DeviceSmtHashes>(&p.heights, &p.siblings).map_err(|e| {
                    DsmError::invalid_operation(format!("an offline account witness's path: {e}"))
                })?;
                Ok(EncodedPath {
                    explicit_heights: fixed(&p.heights, "path height set")?,
                    siblings: p.siblings,
                })
            })
            .collect::<Result<Vec<_>, DsmError>>()?;
        Ok(Self {
            pre_account_root: fixed(&a.pre_account_root, "pre-root")?,
            pre_allocation: a.pre_allocation,
            pre_counter: a.pre_counter,
            pre_frontier: fixed(&a.pre_frontier, "pre-frontier")?,
            next_frontier: fixed(&a.next_frontier, "next frontier")?,
            account_paths,
        })
    }
}

/// The paths of a witness, each in the one canonical encoding.
fn decoded_paths(paths: &[EncodedPath]) -> Result<Vec<Box<[[u8; 32]; FOLD_HEIGHT]>>, DsmError> {
    paths
        .iter()
        .map(|p| {
            smt_path::decode::<DeviceSmtHashes>(&p.explicit_heights, &p.siblings)
                .map_err(|e| DsmError::invalid_operation(format!("an offline account path: {e}")))
        })
        .collect()
}

/// The paths a wire form states, each checked to be in the one canonical encoding of a path.
fn paths_from_proto(paths: Vec<SmtPathProto>, what: &str) -> Result<Vec<EncodedPath>, DsmError> {
    paths
        .into_iter()
        .map(|p| {
            smt_path::decode::<DeviceSmtHashes>(&p.heights, &p.siblings)
                .map_err(|e| DsmError::invalid_operation(format!("{what}'s path: {e}")))?;
            Ok(EncodedPath {
                explicit_heights: fixed32(&p.heights, what, "path height set")?,
                siblings: p.siblings,
            })
        })
        .collect()
}

fn paths_to_proto(paths: &[EncodedPath]) -> Vec<SmtPathProto> {
    paths
        .iter()
        .map(|p| SmtPathProto {
            heights: p.explicit_heights.to_vec(),
            siblings: p.siblings.clone(),
        })
        .collect()
}

fn fixed32(bytes: &[u8], what: &str, field: &str) -> Result<[u8; 32], DsmError> {
    bytes
        .try_into()
        .map_err(|e| DsmError::invalid_operation(format!("{what}'s {field}: {e}")))
}

/// What a receipt carries for the offline account an offline-bearer receive writes, the receiver's
/// own under its bundle (owner, 2026-11-07): the account as it stood before the receive, the
/// frontier the receiver's board advanced to, and the account paths of the leaves the receive
/// writes, in key order. After is derived from these and the operation, never carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveWitness {
    pub pre_account_root: [u8; 32],
    /// What the account held received of the asset, or `None` when it never received it.
    pub pre_received: Option<u64>,
    pub pre_counter: u64,
    pub pre_frontier: [u8; 32],
    pub next_frontier: [u8; 32],
    pub account_paths: Vec<EncodedPath>,
}

impl ReceiveWitness {
    /// The witness of `receive` taken by `before` (the account the receive started from).
    pub fn of(before: &OfflineAccount, receive: &OfflineAccountMove) -> Result<Self, DsmError> {
        let StepBefore::Receive {
            received,
            counter,
            frontier,
        } = receive.before
        else {
            return Err(DsmError::invalid_operation(
                "a receive witness is taken of a receive",
            ));
        };
        Ok(Self {
            pre_account_root: before.root(),
            pre_received: received,
            pre_counter: counter,
            pre_frontier: frontier,
            next_frontier: receive.account.frontier(),
            account_paths: receive
                .entries
                .iter()
                .map(|e| smt_path::encode::<DeviceSmtHashes>(&e.path))
                .collect(),
        })
    }

    /// The account root after receiving `amount` of `asset`: the receive's writes, recomputed from
    /// this witness, folded from its pre-root.
    pub fn post_account_root(&self, asset: &[u8; 32], amount: u64) -> Result<[u8; 32], DsmError> {
        verify_step(
            &self.pre_account_root,
            &OfflineAccountStep::Receive {
                asset: *asset,
                amount,
                next_frontier: self.next_frontier,
            },
            &StepBefore::Receive {
                received: self.pre_received,
                counter: self.pre_counter,
                frontier: self.pre_frontier,
            },
            &decoded_paths(&self.account_paths)?,
        )
    }

    /// The witness's wire form.
    pub fn to_proto(&self) -> crate::types::proto::StepWriteOfflineReceive {
        crate::types::proto::StepWriteOfflineReceive {
            pre_account_root: self.pre_account_root.to_vec(),
            pre_received: self.pre_received,
            pre_counter: self.pre_counter,
            pre_frontier: self.pre_frontier.to_vec(),
            next_frontier: self.next_frontier.to_vec(),
            account_paths: paths_to_proto(&self.account_paths),
        }
    }

    /// The witness a wire form states.
    pub fn from_proto(a: crate::types::proto::StepWriteOfflineReceive) -> Result<Self, DsmError> {
        const WHAT: &str = "an offline receive witness";
        Ok(Self {
            pre_account_root: fixed32(&a.pre_account_root, WHAT, "pre-root")?,
            pre_received: a.pre_received,
            pre_counter: a.pre_counter,
            pre_frontier: fixed32(&a.pre_frontier, WHAT, "pre-frontier")?,
            next_frontier: fixed32(&a.next_frontier, WHAT, "next frontier")?,
            account_paths: paths_from_proto(a.account_paths, WHAT)?,
        })
    }
}

/// The witness of the one offline-account move a bearer step makes: the sender's spend, or the
/// receiver's receive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountWitness {
    Spend(SpendWitness),
    Receive(ReceiveWitness),
}

impl AccountWitness {
    /// The account root the move started from.
    pub fn pre_account_root(&self) -> [u8; 32] {
        match self {
            Self::Spend(w) => w.pre_account_root,
            Self::Receive(w) => w.pre_account_root,
        }
    }

    /// The receipt leaf that names the move.
    pub fn receipt_leaf(&self) -> crate::types::receipt_types::ReceiptLeaf {
        use crate::types::receipt_types::ReceiptLeaf;
        match self {
            Self::Spend(w) => ReceiptLeaf::OfflineAccount(Box::new(w.clone())),
            Self::Receive(w) => ReceiptLeaf::OfflineReceive(Box::new(w.clone())),
        }
    }
}

/// The unload of a payment received offline, as a step of the account: the account before it,
/// what it held received of the payment's asset, and the path of that leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettleWitness {
    pub pre_account_root: [u8; 32],
    pub pre_received: u64,
    pub account_path: EncodedPath,
}

impl SettleWitness {
    /// The witness of `settle` taken by `before`.
    pub fn of(before: &OfflineAccount, settle: &OfflineAccountMove) -> Result<Self, DsmError> {
        let (StepBefore::Settle { received }, [entry]) = (settle.before, settle.entries.as_slice())
        else {
            return Err(DsmError::invalid_operation(
                "a settle witness is taken of the one write of an unload of a received payment",
            ));
        };
        Ok(Self {
            pre_account_root: before.root(),
            pre_received: received,
            account_path: smt_path::encode::<DeviceSmtHashes>(&entry.path),
        })
    }

    /// The account root after the unload of `amount` of `asset`.
    pub fn post_account_root(&self, asset: &[u8; 32], amount: u64) -> Result<[u8; 32], DsmError> {
        verify_step(
            &self.pre_account_root,
            &OfflineAccountStep::Settle {
                asset: *asset,
                amount,
            },
            &StepBefore::Settle {
                received: self.pre_received,
            },
            &decoded_paths(core::slice::from_ref(&self.account_path))?,
        )
    }

    pub fn to_proto(&self) -> crate::types::proto::StepWriteOfflineSettle {
        crate::types::proto::StepWriteOfflineSettle {
            pre_account_root: self.pre_account_root.to_vec(),
            pre_received: self.pre_received,
            account_path: paths_to_proto(core::slice::from_ref(&self.account_path))
                .into_iter()
                .next(),
        }
    }

    pub fn from_proto(a: crate::types::proto::StepWriteOfflineSettle) -> Result<Self, DsmError> {
        const WHAT: &str = "an offline settle witness";
        let path = a
            .account_path
            .ok_or_else(|| DsmError::invalid_operation(format!("{WHAT} carries no path")))?;
        let mut paths = paths_from_proto(vec![path], WHAT)?;
        Ok(Self {
            pre_account_root: fixed32(&a.pre_account_root, WHAT, "pre-root")?,
            pre_received: a.pre_received,
            account_path: paths.remove(0),
        })
    }
}

fn decode_path(path: &SmtPathProto) -> Result<Box<[[u8; 32]; FOLD_HEIGHT]>, DsmError> {
    smt_path::decode::<DeviceSmtHashes>(&path.heights, &path.siblings)
        .map_err(|e| DsmError::invalid_operation(format!("an offline state proof's path: {e}")))
}

fn path_proto(path: &[[u8; 32]; FOLD_HEIGHT]) -> SmtPathProto {
    let encoded = smt_path::encode::<DeviceSmtHashes>(path);
    SmtPathProto {
        heights: encoded.explicit_heights.to_vec(),
        siblings: encoded.siblings,
    }
}

/// Encode the proof that `device_tree` commits `account` at the leaf of
/// `bundle`, with the account's counter and frontier: what an offline release
/// carries beside each of its device roots.
pub fn offline_state_proof(
    device_tree: &SparseMerkleTree,
    bundle: &[u8; 32],
    account: &OfflineAccount,
) -> Result<Vec<u8>, DsmError> {
    use prost::Message;
    let path = |tree: &SparseMerkleTree, key: &[u8; 32]| -> Result<SmtPathProto, DsmError> {
        let proof = tree
            .get_inclusion_proof(key, FOLD_HEIGHT)
            .map_err(|e| DsmError::merkle(format!("offline state proof: {e}")))?;
        let siblings: Box<[[u8; 32]; FOLD_HEIGHT]> = proof
            .siblings
            .into_boxed_slice()
            .try_into()
            .map_err(|path: Box<[[u8; 32]]>| {
            DsmError::merkle(format!(
                "offline state proof: a path of {} siblings, not 256",
                path.len()
            ))
        })?;
        Ok(path_proto(&siblings))
    };
    Ok(crate::types::proto::OfflineStateProof {
        account_root: account.root().to_vec(),
        account_leaf: Some(path(device_tree, &offline_account_leaf_key(bundle))?),
        counter: Some(path(&account.tree, &counter_key())?),
        frontier: Some(path(&account.tree, &frontier_key())?),
    }
    .encode_to_vec())
}

/// Verify that `device_root` commits the offline account of `bundle` with its
/// software counter at `counter` and its frontier at `frontier`, by the
/// encoded `proof`: the account's leaf in the device SMT, and the counter and
/// frontier leaves in the account's own SMT, all folding to the roots named.
pub fn verify_offline_state(
    device_root: &[u8; 32],
    bundle: &[u8; 32],
    frontier: &[u8; 32],
    counter: u64,
    proof: &[u8],
) -> Result<(), DsmError> {
    verify_offline_state_at(device_root, bundle, frontier, counter, proof).map(|_| ())
}

/// [`verify_offline_state`], answering with the account root the proof proved:
/// the account `device_root` commits under `bundle`, which holds `counter` and
/// `frontier`.
pub fn verify_offline_state_at(
    device_root: &[u8; 32],
    bundle: &[u8; 32],
    frontier: &[u8; 32],
    counter: u64,
    proof: &[u8],
) -> Result<[u8; 32], DsmError> {
    use prost::Message;
    let proof = crate::types::proto::OfflineStateProof::decode(proof)
        .map_err(|e| DsmError::invalid_operation(format!("an offline state proof: {e}")))?;
    let account_root: [u8; 32] = proof.account_root.as_slice().try_into().map_err(|e| {
        DsmError::invalid_operation(format!("an offline state proof's account root: {e}"))
    })?;
    let missing = || DsmError::invalid_operation("an offline state proof is missing a path");
    let account_leaf = decode_path(proof.account_leaf.as_ref().ok_or_else(missing)?)?;
    let counter_path = decode_path(proof.counter.as_ref().ok_or_else(missing)?)?;
    let frontier_path = decode_path(proof.frontier.as_ref().ok_or_else(missing)?)?;
    if fold_path::<DeviceSmtHashes>(&counter_key(), Some(&counter_value(counter)), &counter_path)
        != account_root
    {
        return Err(DsmError::invalid_operation(
            "the offline account does not hold the counter named",
        ));
    }
    if fold_path::<DeviceSmtHashes>(&frontier_key(), Some(frontier), &frontier_path) != account_root
    {
        return Err(DsmError::invalid_operation(
            "the offline account does not hold the frontier named",
        ));
    }
    if fold_path::<DeviceSmtHashes>(
        &offline_account_leaf_key(bundle),
        Some(&account_root),
        &account_leaf,
    ) != *device_root
    {
        return Err(DsmError::invalid_operation(
            "the device root does not commit this offline account",
        ));
    }
    Ok(account_root)
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

    fn load(asset: [u8; 32], amount: u64, boundary: u8) -> OfflineAccountStep {
        OfflineAccountStep::Load {
            asset,
            amount,
            boundary_id: [boundary; 32],
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
                boundary_id: [0x12; 32],
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
        assert_eq!(account.funding_chain(), Some([0x12; 32]));
        let rebuilt = OfflineAccount::restore(
            account.allocations().clone(),
            account.received_amounts().clone(),
            account.counter(),
            account.frontier(),
            account.funding_chain(),
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
                boundary_id: [0x10; 32],
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
            funding_chain_key(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    fn receive(amount: u64, next_frontier: u8) -> OfflineAccountStep {
        OfflineAccountStep::Receive {
            asset: ASSET,
            amount,
            next_frontier: [next_frontier; 32],
        }
    }

    /// A receive (owner, 2026-11-07: the money received offline lands in the receiver's own offline
    /// balance, apart from what it loaded) adds to what the account holds received, never to its
    /// loaded allocation, and moves the counter and the frontier with the receiver's board. Its
    /// unload takes only from what was received. Both fold from their pre-roots, and the account
    /// they leave rebuilds from its persisted record.
    #[test]
    fn a_receive_lands_beside_the_loaded_allocation_and_leaves_only_by_its_unload() {
        let mut account = OfflineAccount::open([0x01; 32], 0)
            .step(&load(ASSET, 10, 0x10))
            .expect("load")
            .account;
        for step in [
            receive(4, 0x02),
            receive(3, 0x03),
            OfflineAccountStep::Settle {
                asset: ASSET,
                amount: 5,
            },
        ] {
            let m = account.step(&step).expect("the account takes the step");
            let post = verify_step(&account.root(), &step, &m.before, &paths(&m))
                .expect("the step verifies");
            assert_eq!(post, m.account.root());
            account = m.account;
        }
        assert_eq!(
            account.allocation(&ASSET),
            Some(10),
            "the loaded allocation is untouched"
        );
        assert_eq!(account.received(&ASSET), Some(2), "received 7, unloaded 5");
        assert_eq!(
            account.held().expect("what the account holds"),
            BTreeMap::from([(ASSET, 12)]),
            "it holds what was loaded and what was received: a closed account takes both"
        );
        assert_eq!(account.counter(), 2, "each receive moves the counter once");
        assert_eq!(account.frontier(), [0x03; 32]);
        let rebuilt = OfflineAccount::restore(
            account.allocations().clone(),
            account.received_amounts().clone(),
            account.counter(),
            account.frontier(),
            account.funding_chain(),
        );
        assert_eq!(rebuilt.root(), account.root());

        // Money received is spent by no one: a spend takes the loaded allocation only.
        refused(
            account.step(&spend(11, 0x04)),
            "takes more than the offline allocation holds",
        );
        // An unload of a received payment takes only from what was received.
        refused(
            account.step(&OfflineAccountStep::Settle {
                asset: ASSET,
                amount: 3,
            }),
            "takes more than the account holds received",
        );
        refused(
            account.step(&OfflineAccountStep::Settle {
                asset: OTHER,
                amount: 1,
            }),
            "never received",
        );
        refused(
            account.step(&receive(1, 0x03)),
            "moves the offline frontier",
        );
        refused(account.step(&receive(0, 0x05)), "positive amount");
    }

    /// The witnesses a receipt and an account's ancestry carry fold exactly the step they were
    /// taken of: a receive into an asset never received proves the received leaf absent, and a
    /// misstated pre-value folds to another root.
    #[test]
    fn a_receive_and_its_unload_are_proven_by_their_witnesses() {
        let opened = OfflineAccount::open([0x01; 32], 0);
        let received = opened.step(&receive(6, 0x02)).expect("a first receive");
        let witness = ReceiveWitness::of(&opened, &received).expect("its witness");
        assert_eq!(witness.pre_received, None, "never received before");
        assert_eq!(
            witness.post_account_root(&ASSET, 6).expect("folds"),
            received.account.root()
        );
        assert_ne!(
            witness.post_account_root(&ASSET, 7).expect("folds"),
            received.account.root(),
            "another amount folds to another account"
        );
        let mut misstated = witness.clone();
        misstated.pre_received = Some(0);
        refused(
            misstated.post_account_root(&ASSET, 6),
            "the offline account step",
        );
        let wire = ReceiveWitness::from_proto(witness.to_proto()).expect("the wire form");
        assert_eq!(wire, witness);

        let settled = received
            .account
            .step(&OfflineAccountStep::Settle {
                asset: ASSET,
                amount: 6,
            })
            .expect("its unload");
        let witness = SettleWitness::of(&received.account, &settled).expect("its witness");
        assert_eq!(
            witness.post_account_root(&ASSET, 6).expect("folds"),
            settled.account.root()
        );
        assert_eq!(
            SettleWitness::from_proto(witness.to_proto()).expect("the wire form"),
            witness
        );
    }
}
