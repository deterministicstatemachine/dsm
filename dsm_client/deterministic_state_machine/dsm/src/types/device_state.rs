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

    /// Legacy compat anchor: if a State was bootstrapped via `set_state`,
    /// its hash is stored here so that `verify_state` and similar legacy
    /// checks have a head_hash to compare against. Strictly compat path —
    /// new code reads `root()` (the SMT root, §2.2 canonical).
    legacy_anchor: Option<[u8; 32]>,
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
            legacy_anchor: None,
        }
    }

    /// Reconstruct a `DeviceState` from previously-encoded fields, replaying
    /// the per-relationship tips into the SMT to recompute the canonical root.
    ///
    /// Phase 4.1 codec roundtrip path. The caller supplies the device-level
    /// fields plus the sorted-by-`rel_key` tip list and this constructor:
    ///
    /// 1. Builds a fresh `DeviceState::new(...)` with empty SMT and balances.
    /// 2. Replays each tip via `smt_replace(&rel_key, &tip.chain_tip)` in
    ///    the supplied order. Determinism is guaranteed because
    ///    `SparseMerkleTree` is purely functional in its leaf-replace path.
    /// 3. Installs `balances`, `tips`, and `legacy_anchor` directly.
    ///
    /// The caller is responsible for verifying that the resulting `root()`
    /// matches the stored sanity-check digest.
    ///
    /// # Errors
    ///
    /// Returns `Err` on any SMT replace failure.
    pub fn restore(
        genesis: [u8; 32],
        devid: [u8; 32],
        public_key: Vec<u8>,
        legacy_anchor: Option<[u8; 32]>,
        balances: BTreeMap<[u8; 32], u64>,
        tips_in_order: Vec<([u8; 32], RelChainTip)>,
        max_relationships: usize,
    ) -> Result<Self, DsmError> {
        let mut state = Self::new(genesis, devid, public_key, max_relationships);
        state.legacy_anchor = legacy_anchor;
        state.balances = balances;

        for (rel_key, tip) in tips_in_order.into_iter() {
            state
                .smt
                .smt_replace(&rel_key, &tip.chain_tip)
                .map_err(|e| {
                    DsmError::invalid_operation(format!(
                        "DeviceState::restore: SMT replace failed for rel_key: {e}"
                    ))
                })?;
            state.tips.insert(rel_key, tip);
        }

        Ok(state)
    }

    /// Current device head `r_A` — the Per-Device SMT root (§2.2).
    pub fn root(&self) -> [u8; 32] {
        *self.smt.root()
    }

    /// Stash a legacy `State.hash` as a verification anchor. Callers that
    /// hold a legacy State and want `legacy_anchor()` to return its hash
    /// (for hash-adjacency verification) use this. Strictly compat path —
    /// not part of the §2.2 SMT.
    pub fn bootstrap_legacy_root(&mut self, legacy_root: [u8; 32]) {
        self.legacy_anchor = Some(legacy_root);
    }

    /// Returns the legacy anchor if set (compat path).
    pub fn legacy_anchor(&self) -> Option<[u8; 32]> {
        self.legacy_anchor
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

    /// Retrieve the cached tip metadata for a relationship, if present.
    pub fn rel_chain_tip(&self, rel_key: &[u8; 32]) -> Option<&RelChainTip> {
        self.tips.get(rel_key)
    }

    /// Device ID as a 32-byte array. Convenience for callers migrating from
    /// `State.device_info.device_id`.
    pub fn device_id(&self) -> [u8; 32] {
        self.devid
    }

    /// All relationship keys currently in the SMT.
    pub fn relationship_keys(&self) -> Vec<[u8; 32]> {
        self.tips.keys().copied().collect()
    }

    /// Number of active relationships in the SMT.
    pub fn relationship_count(&self) -> usize {
        self.tips.len()
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
        // Resolve embedded_parent: prior SMT leaf, or the initial tip for
        // first-ever advances on this relationship. For first-ever advances
        // we additionally seed the SMT leaf to that initial tip BEFORE the
        // replace so the parent inclusion proof carries a real value
        // (matching the historical behaviour of `initialize_contact_chain_tip`
        // on the retired `SHARED_SMT`). Without the seed, the first-ever
        // parent proof would be a non-inclusion proof with value=None, which
        // §4.3 `verify_receipt_bytes` rejects.
        let (embedded_parent, seed_first_ever) = match self.chain_tip(&rel_key) {
            Some(tip) => (tip, false),
            None => {
                let seed = initial_chain_tip.ok_or_else(|| {
                    DsmError::invalid_operation(
                        "advance: first-ever transaction requires initial_chain_tip",
                    )
                })?;
                (seed, true)
            }
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

        // Atomic SMT-replace on a working copy of the SMT. For first-ever
        // advances, seed the leaf with `embedded_parent` (= initial_chain_tip)
        // before the replace so the parent proof is an inclusion proof.
        let mut new_smt = self.smt.clone();
        if seed_first_ever {
            new_smt
                .update_leaf(&rel_key, &embedded_parent)
                .map_err(|e| {
                    DsmError::invalid_operation(format!(
                        "advance: first-ever seed update_leaf failed: {e}"
                    ))
                })?;
        }
        let parent_r_a = *new_smt.root();
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
            legacy_anchor: self.legacy_anchor,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::{Operation, TransactionMode};

    fn devid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn pubkey() -> Vec<u8> {
        vec![0xAA; 64]
    }
    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn fresh_device(b: u8) -> DeviceState {
        DeviceState::new([0u8; 32], devid(b), pubkey(), 1024)
    }

    fn op() -> Operation {
        Operation::Generic {
            operation_type: b"test".to_vec(),
            data: vec![],
            message: "t".to_string(),
            signature: vec![],
        }
    }

    fn entropy(seed: u8) -> Vec<u8> {
        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/test-entropy");
        h.update(&[seed]);
        h.finalize().as_bytes().to_vec()
    }

    /// Phase 6 test: balance witness reflects device-level total at commit time.
    /// Two relationships, each debiting from the same device-level token balance.
    /// Each chain's `balance_witness` must show the device total at the moment
    /// of that advance (per §8 — "Each state binds B^T_{n+1}").
    #[test]
    fn balance_witness_reflects_device_total_across_relationships() {
        let mut dev = fresh_device(0xAA);
        // Seed the device with 100 of token T.
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let charlie = devid(0xDD);
        let rk_bob = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let rk_chrl =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &charlie);
        let init_bob =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &bob,
            );
        let init_chrl =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &charlie,
            );

        // Advance (A↔Bob): debit 30 → device total now 70
        let out_bob = dev
            .advance(
                rk_bob,
                bob,
                op(),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 30,
                }],
                Some(init_bob),
                None,
            )
            .expect("advance Bob");
        assert_eq!(
            out_bob.new_chain_state.balance_witness.get(&token).copied(),
            Some(70),
            "after debit 30 from 100, witness on (A↔Bob) chain must = 70"
        );

        // Apply outcome to device, then advance (A↔Charlie) from updated device state.
        let dev_after_bob = out_bob.new_device_state;
        let out_chrl = dev_after_bob
            .advance(
                rk_chrl,
                charlie,
                op(),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 50,
                }],
                Some(init_chrl),
                None,
            )
            .expect("advance Charlie");
        assert_eq!(
            out_chrl
                .new_chain_state
                .balance_witness
                .get(&token)
                .copied(),
            Some(20),
            "after debit 50 from 70, witness on (A↔Charlie) chain must = 20"
        );

        // Device-level balance is the canonical source of truth.
        assert_eq!(out_chrl.new_device_state.balance(&token), 20);
    }

    /// Phase 6 test: stale-snapshot CAS detection.
    /// Two advances built from the SAME parent `r_A` produce different child
    /// `r'_A` values (different relationships → different SMT leaves replaced).
    /// In the CAS layer above this, only the first to install wins; the second
    /// sees its `parent_r_a` no longer matches the current head.
    #[test]
    fn concurrent_advances_from_same_root_produce_different_children() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let charlie = devid(0xDD);
        let rk_bob = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let rk_chrl =
            crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &charlie);
        let init_bob =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &bob,
            );
        let init_chrl =
            crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.devid, &charlie,
            );

        let parent_root = dev.root();

        // Two advances from the same parent root, on different relationships.
        let a = dev
            .advance(
                rk_bob,
                bob,
                op(),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 10,
                }],
                Some(init_bob),
                None,
            )
            .expect("advance A");
        let b = dev
            .advance(
                rk_chrl,
                charlie,
                op(),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 20,
                }],
                Some(init_chrl),
                None,
            )
            .expect("advance B");

        // Both built from the same parent.
        assert_eq!(a.parent_r_a, parent_root);
        assert_eq!(b.parent_r_a, parent_root);

        // But produce different children — first-commit-wins at the CAS layer
        // means the second outcome is stale.
        assert_ne!(
            a.child_r_a, b.child_r_a,
            "different SMT leaf replacements must yield different child roots"
        );

        // Balances on the two outcomes also diverge.
        assert_eq!(a.new_device_state.balance(&token), 90);
        assert_eq!(b.new_device_state.balance(&token), 80);
    }

    /// Phase 6 test: same-relationship double advance from same SMT root.
    /// This is the per-relationship Tripwire scenario (§6.1, Theorem 2):
    /// two attempts to consume the same chain tip `h_n` on the same relationship.
    /// Both advances individually succeed (DeviceState::advance is pure), but
    /// they produce DIFFERENT `h_{n+1}` because entropy/op differ — yet both
    /// embed the same `embedded_parent`. Verifiers seeing both must reject one.
    #[test]
    fn tripwire_same_relationship_same_parent_different_children() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 100);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let a = dev
            .advance(
                rk,
                bob,
                op(),
                entropy(1),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 10,
                }],
                Some(init),
                None,
            )
            .expect("advance A");
        let b = dev
            .advance(
                rk,
                bob,
                op(),
                entropy(2),
                None,
                &[BalanceDelta {
                    policy_commit: token,
                    direction: BalanceDirection::Debit,
                    amount: 20,
                }],
                Some(init),
                None,
            )
            .expect("advance B");

        // Both consume the SAME embedded_parent (the initial tip).
        assert_eq!(a.new_chain_state.embedded_parent, init);
        assert_eq!(b.new_chain_state.embedded_parent, init);

        // But produce DIFFERENT successor chain tips (different entropy/op).
        let h_a = a.new_chain_state.compute_chain_tip();
        let h_b = b.new_chain_state.compute_chain_tip();
        assert_ne!(
            h_a, h_b,
            "Tripwire: two children of same h_n must be cryptographically distinguishable"
        );

        // A verifier seeing both signed receipts would detect the fork:
        // both claim to extend the same h_n, only one can be accepted.
    }

    /// Phase 6 test: balance underflow rejected.
    #[test]
    fn advance_rejects_balance_underflow() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 5);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let r = dev.advance(
            rk,
            bob,
            op(),
            entropy(1),
            None,
            &[BalanceDelta {
                policy_commit: token,
                direction: BalanceDirection::Debit,
                amount: 10,
            }],
            Some(init),
            None,
        );
        assert!(
            r.is_err(),
            "debit > balance must fail with insufficient funds"
        );
    }

    /// Phase 6 test: balance overflow rejected.
    #[test]
    fn advance_rejects_balance_overflow() {
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, u64::MAX);

        let bob = devid(0xBB);
        let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, &bob);
        let init = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev.devid, &bob,
        );

        let r = dev.advance(
            rk,
            bob,
            op(),
            entropy(1),
            None,
            &[BalanceDelta {
                policy_commit: token,
                direction: BalanceDirection::Credit,
                amount: 1,
            }],
            Some(init),
            None,
        );
        assert!(r.is_err(), "u64::MAX + 1 must overflow");
    }

    /// Phase 6 test: balance conservation across cross-relationship sequence.
    /// Property: sum of all deltas across a sequence of valid advances equals
    /// the net change in the device-level balance scalar.
    #[test]
    fn balance_conservation_across_sequence() {
        let _ = TransactionMode::Bilateral; // import keep-alive
        let mut dev = fresh_device(0xAA);
        let token = pc(0xCC);
        dev.balances.insert(token, 1000);

        let parties: Vec<[u8; 32]> = (0u8..5).map(|i| devid(0xB0 + i)).collect();
        let mut net_delta: i64 = 0;
        for (i, party) in parties.iter().enumerate() {
            let amt = (i + 1) as u64 * 7;
            let dir = if i % 2 == 0 {
                BalanceDirection::Debit
            } else {
                BalanceDirection::Credit
            };
            let signed = if matches!(dir, BalanceDirection::Debit) {
                -(amt as i64)
            } else {
                amt as i64
            };
            net_delta += signed;

            let rk = crate::core::bilateral_transaction_manager::compute_smt_key(&dev.devid, party);
            let init =
                crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                    &dev.devid, party,
                );
            let out = dev
                .advance(
                    rk,
                    *party,
                    op(),
                    entropy(i as u8),
                    None,
                    &[BalanceDelta {
                        policy_commit: token,
                        direction: dir,
                        amount: amt,
                    }],
                    Some(init),
                    None,
                )
                .expect("advance");
            dev = out.new_device_state;
        }

        let expected = (1000_i64 + net_delta) as u64;
        assert_eq!(
            dev.balance(&token),
            expected,
            "net balance change must equal sum of signed deltas"
        );
    }
}
