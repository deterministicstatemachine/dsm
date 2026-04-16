//! Device state: the canonical per-device head per whitepaper §2.2, §4, §8.
//!
//! This module defines [`DeviceState`] — the authoritative representation of a
//! DSM device's state. It consists of:
//!
//! - Per-Device SMT whose root `r_A` is the device's head pointer (§2.2)
//! - Device-level fungible token balances keyed by CPTA `policy_commit` (§9)
//! - Per-relationship chain tips + minimal acceptance material (§4.2)
//!
//! Advances take the device from `r_A → r'_A` via a single SMT leaf replace
//! (§4.2). The design follows first-commit-wins semantics: each advance is an
//! atomic head update. Concurrency is structurally impossible at the head
//! level — two attempted advances from the same `r_A` will each see the same
//! parent root, build valid successors, and race at the caller's CAS step;
//! the loser's receipt references a stale `r_A` and is rejected.
//!
//! Per §4.3, this module contains **no counters, no timestamps, no heights**
//! in any acceptance predicate or canonical hash. Ordering is by hash
//! adjacency (§2.1): each [`RelationshipChainState`] embeds its predecessor
//! tip `h_{i-1}`. Per-transition entropy (§11) makes state identity unique
//! even when balance values round-trip.

use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::{SmtReplaceResult, SparseMerkleTree};
use crate::types::error::DsmError;
use crate::types::operations::Operation;

/// The canonical per-device head per §2.2.
///
/// `DeviceState` stores **current truth only** — tip-per-relationship plus
/// device-level fungible balances. Full per-relationship history lives in
/// BCR archives, not here.
#[derive(Clone)]
pub struct DeviceState {
    /// Genesis digest `G_A` (§2.4–§2.5). Immutable 32 bytes.
    genesis: [u8; 32],

    /// Device identifier `DevID_A = BLAKE3("DSM/devid\0" ‖ pk ‖ att)` (§2.4).
    devid: [u8; 32],

    /// Device's SPHINCS+ public key for receipt signatures.
    public_key: Vec<u8>,

    /// Per-Device SMT (§2.2). Leaves: `rel_key → chain_tip`. Root is `r_A`.
    smt: SparseMerkleTree,

    /// Device-level fungible token balances.
    ///
    /// Keyed by the **32-byte CPTA `policy_commit`** per §9 — not by a
    /// token_id string. This eliminates any runtime policy-resolution
    /// dependency in canonical hashing: a verifier reproducing a
    /// [`RelationshipChainState`] hash only needs the 32-byte keys from
    /// the state itself, never a CPTA lookup.
    ///
    /// `BTreeMap` for deterministic iteration order during canonical hashing.
    balances: BTreeMap<[u8; 32], u64>,

    /// Per-relationship current tip cache. Mirrors the SMT leaf values plus
    /// the minimum acceptance material needed to build the next advance
    /// (embedded parent, balance witness, counterparty binding).
    ///
    /// Canonical source of truth is [`SparseMerkleTree`]; this map is a
    /// fast-path for building successors without archive fetches.
    tips: BTreeMap<[u8; 32], RelChainTip>,
}

impl fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceState")
            .field("genesis", &hex_short(&self.genesis))
            .field("devid", &hex_short(&self.devid))
            .field("root", &hex_short(&self.root()))
            .field("balances", &self.balances.len())
            .field("tips", &self.tips.len())
            .finish()
    }
}

fn hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Cached per-relationship tip metadata.
///
/// Contains the current chain tip digest (mirror of the SMT leaf) plus the
/// full [`RelationshipChainState`] that produced it, so the next advance on
/// this relationship can read `embedded_parent` and prior `balance_witness`
/// without an archive fetch.
#[derive(Clone, Debug)]
pub struct RelChainTip {
    /// Current chain tip `h_n = H(canonical_bytes(state))`.
    /// Mirrors the SMT leaf value.
    pub chain_tip: [u8; 32],

    /// Counterparty device identifier for this relationship.
    pub counterparty_devid: [u8; 32],

    /// Full state at the tip, if available. `None` when the tip was restored
    /// from a recovery capsule that only carried the digest.
    pub state: Option<RelationshipChainState>,
}

/// One accepted state in a per-relationship straight hash chain (§2.1).
///
/// Replaces the old monolithic `State` for per-chain semantics. Carries
/// adjacency material, the operation, entropy, a device-level balance
/// witness, and signatures. **No `state_number`, no `sparse_index`** —
/// both are forbidden in acceptance predicates by §4.3.
#[derive(Clone, Debug)]
pub struct RelationshipChainState {
    /// 32-byte relationship key `k_{A↔B}` per §2.2 canonical derivation.
    pub rel_key: [u8; 32],

    /// Embedded parent hash `h_{i-1}` from the **same** relationship chain
    /// (§2.1 eq. 1). For first-ever advances on a relationship this is the
    /// spec-canonical initial tip derived from genesis + counterparty.
    pub embedded_parent: [u8; 32],

    /// Counterparty device identifier.
    pub counterparty_devid: [u8; 32],

    /// Operation performed in this transition.
    pub operation: Operation,

    /// Fresh per-transition entropy (§11 eq. 14). Makes state identity
    /// unique even when field values round-trip.
    pub entropy: Vec<u8>,

    /// Optional ML-KEM-768 ciphertext binding this transition to the
    /// counterparty (§11 eq. 12).
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Device-level `B^T` witness at the moment of this transition (§8).
    ///
    /// Keyed by 32-byte CPTA `policy_commit` (not token_id string) so the
    /// canonical hash has no runtime policy-resolution dependency. Values
    /// are raw `u64` balances. `BTreeMap` for deterministic order.
    pub balance_witness: BTreeMap<[u8; 32], u64>,

    /// Entity (advancing party) SPHINCS+ signature.
    pub entity_sig: Option<Vec<u8>>,

    /// Counterparty SPHINCS+ signature (bilateral mode).
    pub counterparty_sig: Option<Vec<u8>>,

    /// Optional DBRW health summary commitment (§12). Advisory only —
    /// included in the hash iff present on the advancing device.
    pub dbrw_summary_hash: Option<[u8; 32]>,
}

impl RelationshipChainState {
    /// Compute `h_n = H(canonical_bytes(self))` with the
    /// `DSM/state-hash` domain tag.
    ///
    /// The canonical byte layout EXCLUDES `state_number`, `sparse_index`,
    /// and any counter-like metadata per §4.3. Ordering of fields is:
    ///
    /// `rel_key ‖ embedded_parent ‖ counterparty_devid ‖ op ‖ entropy
    /// ‖ encap_flag ‖ encap? ‖ dbrw_flag ‖ dbrw? ‖ witness_len
    /// ‖ (policy_commit ‖ value)* sorted_by_policy_commit`
    ///
    /// Signatures are NOT hashed — they sign this digest, not the other
    /// way around.
    pub fn compute_chain_tip(&self) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/state-hash");

        hasher.update(&self.rel_key);
        hasher.update(&self.embedded_parent);
        hasher.update(&self.counterparty_devid);

        let op_bytes = self.operation.to_bytes();
        hasher.update(&(op_bytes.len() as u32).to_le_bytes());
        hasher.update(&op_bytes);

        hasher.update(&(self.entropy.len() as u32).to_le_bytes());
        hasher.update(&self.entropy);

        match &self.encapsulated_entropy {
            Some(enc) => {
                hasher.update(&[1u8]);
                hasher.update(&(enc.len() as u32).to_le_bytes());
                hasher.update(enc);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }

        match &self.dbrw_summary_hash {
            Some(dbrw) => {
                hasher.update(&[1u8]);
                hasher.update(dbrw);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }

        // Balance witness: already sorted by 32B policy_commit (BTreeMap).
        hasher.update(&(self.balance_witness.len() as u32).to_le_bytes());
        for (policy_commit, value) in &self.balance_witness {
            hasher.update(policy_commit);
            hasher.update(&value.to_le_bytes());
        }

        *hasher.finalize().as_bytes()
    }
}

/// A balance mutation to apply during [`DeviceState::advance`].
#[derive(Clone, Debug)]
pub struct BalanceDelta {
    /// CPTA `policy_commit` (32B) identifying the token.
    pub policy_commit: [u8; 32],

    /// Direction and magnitude of the change.
    pub direction: BalanceDirection,

    /// Magnitude.
    pub amount: u64,
}

/// Direction of a [`BalanceDelta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceDirection {
    /// Increase the balance (`B^T ← B^T + amount`).
    Credit,
    /// Decrease the balance (`B^T ← B^T - amount`), failing on underflow
    /// per §8 eq. 10.
    Debit,
}

/// Result of a successful [`DeviceState::advance`] build.
///
/// The caller must CAS-swap the device head from `parent_r_a` to
/// `child_r_a`. If the CAS fails, another advance landed first and this
/// outcome is stale; discard and rebuild from the new head.
#[derive(Clone, Debug)]
pub struct AdvanceOutcome {
    /// The new [`DeviceState`] to install on CAS success.
    pub new_device_state: DeviceState,

    /// The new chain state for the advanced relationship. Signatures are
    /// `None` in this outcome — the caller attaches them via the stitched
    /// receipt flow (§4.2) before CAS.
    pub new_chain_state: RelationshipChainState,

    /// SMT replace proofs for the stitched receipt: parent inclusion
    /// (`h_n ∈ r_A`) and child inclusion (`h_{n+1} ∈ r'_A`), plus the
    /// pre/post root pair (§4.2).
    pub smt_proofs: SmtReplaceResult,

    /// Parent device root `r_A` at the time the outcome was built. Used
    /// by the caller to CAS-check the current head.
    pub parent_r_a: [u8; 32],

    /// Child device root `r'_A` produced by the leaf replace.
    pub child_r_a: [u8; 32],
}

impl DeviceState {
    /// Construct a fresh, empty device state at genesis.
    ///
    /// The SMT starts empty (root = empty-leaf default), balances are
    /// zero, and no relationship tips exist. `max_relationships` bounds
    /// the SMT's leaf cache (FIFO eviction).
    pub fn new(
        genesis: [u8; 32],
        devid: [u8; 32],
        public_key: Vec<u8>,
        max_relationships: usize,
    ) -> Self {
        Self {
            genesis,
            devid,
            public_key,
            smt: SparseMerkleTree::new(max_relationships),
            balances: BTreeMap::new(),
            tips: BTreeMap::new(),
        }
    }

    /// Current device head `r_A` — the Per-Device SMT root (§2.2).
    pub fn root(&self) -> [u8; 32] {
        *self.smt.root()
    }

    /// Device genesis digest.
    pub fn genesis_digest(&self) -> [u8; 32] {
        self.genesis
    }

    /// Device identifier.
    pub fn devid(&self) -> [u8; 32] {
        self.devid
    }

    /// Device SPHINCS+ public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Current device-level fungible balance for a token, keyed by its
    /// 32-byte CPTA `policy_commit`.
    pub fn balance(&self, policy_commit: &[u8; 32]) -> u64 {
        self.balances.get(policy_commit).copied().unwrap_or(0)
    }

    /// Snapshot of all device-level balances (read-only view).
    pub fn balances_snapshot(&self) -> &BTreeMap<[u8; 32], u64> {
        &self.balances
    }

    /// Current chain tip for a relationship, if one exists. Returns
    /// `None` for first-ever transactions on an unseen relationship —
    /// the caller must supply a spec-canonical initial tip.
    pub fn chain_tip(&self, rel_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.tips.get(rel_key).map(|t| t.chain_tip)
    }

    /// Retrieve the cached full state at a relationship's current tip,
    /// if present.
    pub fn tip_state(&self, rel_key: &[u8; 32]) -> Option<&RelationshipChainState> {
        self.tips.get(rel_key).and_then(|t| t.state.as_ref())
    }

    /// Attempt to build an advance by one transition on `rel_key`.
    ///
    /// Takes the current state by reference and returns an
    /// [`AdvanceOutcome`] containing the new device state by value. The
    /// caller commits the advance by CAS-swapping their device head from
    /// `outcome.parent_r_a` to `outcome.child_r_a`. On CAS failure the
    /// outcome is stale and must be discarded.
    ///
    /// # Parameters
    ///
    /// - `rel_key` — 32-byte relationship key `k_{A↔B}`
    /// - `counterparty_devid` — the other party's `DevID`
    /// - `operation` — the op being performed
    /// - `entropy` — fresh per-transition entropy (§11 eq. 14)
    /// - `encapsulated_entropy` — optional ML-KEM ciphertext (§11 eq. 12)
    /// - `deltas` — balance mutations to apply to device-level `B^T`
    /// - `initial_chain_tip` — spec-canonical initial tip, used ONLY if
    ///   `rel_key` has no prior entry in the SMT (first-ever tx)
    /// - `dbrw_summary_hash` — optional DBRW health commitment (§12)
    ///
    /// # Errors
    ///
    /// - Balance underflow or overflow (§8 eq. 10)
    /// - First-ever tx without `initial_chain_tip`
    /// - SMT replace failure
    ///
    /// # Concurrency
    ///
    /// This method is pure: it does not mutate `self`. Two concurrent
    /// callers on the same device observe identical `parent_r_a`
    /// snapshots and build valid candidates; the caller's CAS layer
    /// enforces first-commit-wins.
    #[allow(clippy::too_many_arguments)]
    pub fn advance(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: Operation,
        entropy: Vec<u8>,
        encapsulated_entropy: Option<Vec<u8>>,
        deltas: &[BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        dbrw_summary_hash: Option<[u8; 32]>,
    ) -> Result<AdvanceOutcome, DsmError> {
        let parent_r_a = self.root();

        // Resolve embedded_parent: prior SMT leaf, or the initial tip for
        // first-ever advances on this relationship.
        let embedded_parent = match self.chain_tip(&rel_key) {
            Some(tip) => tip,
            None => initial_chain_tip.ok_or_else(|| {
                DsmError::invalid_operation(
                    "advance: first-ever transaction requires initial_chain_tip",
                )
            })?,
        };

        // Apply deltas to a working copy. Failures leave self untouched.
        let mut new_balances = self.balances.clone();
        for d in deltas {
            let cur = new_balances.get(&d.policy_commit).copied().unwrap_or(0);
            let next = match d.direction {
                BalanceDirection::Credit => cur.checked_add(d.amount).ok_or_else(|| {
                    DsmError::invalid_operation("advance: balance overflow on credit")
                })?,
                BalanceDirection::Debit => cur.checked_sub(d.amount).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: balance underflow on debit (insufficient funds)",
                    )
                })?,
            };
            if next == 0 {
                new_balances.remove(&d.policy_commit);
            } else {
                new_balances.insert(d.policy_commit, next);
            }
        }

        // Build the successor chain state with the updated witness.
        let new_chain_state = RelationshipChainState {
            rel_key,
            embedded_parent,
            counterparty_devid,
            operation,
            entropy,
            encapsulated_entropy,
            balance_witness: new_balances.clone(),
            entity_sig: None,
            counterparty_sig: None,
            dbrw_summary_hash,
        };

        // Derive h_{n+1} = H(canonical_bytes(new_chain_state)).
        let child_chain_tip = new_chain_state.compute_chain_tip();

        // Atomic SMT-replace on a working copy of the SMT.
        let mut new_smt = self.smt.clone();
        let smt_proofs = new_smt
            .smt_replace(&rel_key, &child_chain_tip)
            .map_err(|e| DsmError::invalid_operation(format!("SMT replace failed: {e}")))?;

        let child_r_a = smt_proofs.post_root;

        // Update the tip cache with the new state.
        let mut new_tips = self.tips.clone();
        new_tips.insert(
            rel_key,
            RelChainTip {
                chain_tip: child_chain_tip,
                counterparty_devid,
                state: Some(new_chain_state.clone()),
            },
        );

        let new_device_state = Self {
            genesis: self.genesis,
            devid: self.devid,
            public_key: self.public_key.clone(),
            smt: new_smt,
            balances: new_balances,
            tips: new_tips,
        };

        Ok(AdvanceOutcome {
            new_device_state,
            new_chain_state,
            smt_proofs,
            parent_r_a,
            child_r_a,
        })
    }
}
