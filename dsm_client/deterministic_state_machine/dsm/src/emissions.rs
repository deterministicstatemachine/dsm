//! DJTE: Deterministic Join-Triggered Emissions
//!
//! Core logic for:
//! - Join Activation Proof (JAP) commitment
//! - Deterministic exact-uniform winner selection (bounded reseed; no BigInt)
//! - Emission receipt verification
//! - State transition validation (activation + spent + supply + tip binding)
//!
//! Properties:
//! - Fully deterministic (no wall-clock, no OS randomness)
//! - Exact-uniform sampling over [0, N) using Lemire-style rejection on u64
//! - Winner selection returns the selected activation leaf hash:
//!   leaf = H("DJTE.ACTIVE", winner_id)

use crate::crypto::blake3::{dsm_domain_hasher, domain_hash_bytes};
use crate::merkle::sparse_merkle_tree::SparseMerkleTreeImpl;
use crate::types::error::DsmError;
use std::collections::HashMap;

const DJTE_MAX_RESEEDS: usize = 128;

/// Join Activation Proof (JAP)
///
/// Produced when a device unlocks the spend-gate.
#[derive(Clone, Debug)]
pub struct JoinActivationProof {
    pub id: [u8; 32],
    pub gate_proof: Vec<u8>, // Kept as-is; verification lives outside this module today.
    pub nonce: [u8; 32],
}

impl JoinActivationProof {
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + self.gate_proof.len() + 32);
        buf.extend_from_slice(&self.id);
        buf.extend_from_slice(&self.gate_proof);
        buf.extend_from_slice(&self.nonce);
        domain_hash_bytes("DJTE.JAP", &buf)
    }
}

/// Emission Receipt
///
/// Produced by an emission event.
#[derive(Clone, Debug)]
pub struct EmissionReceipt {
    pub emission_index: u64,
    pub winner_id: [u8; 32],
    pub amount: u64,
    pub jap_hash: [u8; 32],
}

impl EmissionReceipt {
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32);
        buf.extend_from_slice(&self.emission_index.to_le_bytes());
        buf.extend_from_slice(&self.winner_id);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.jap_hash);
        domain_hash_bytes("DJTE.RCPT", &buf)
    }
}

/// Shard Count SMT
///
/// Maps prefix (as heap index) to count.
/// Heap index: 1 is root. 2 is left child, 3 is right child, etc.
/// Leaves for shards live at depth `shard_depth`: heap = 2^b + shard_idx.
#[derive(Clone, Debug)]
pub struct ShardCountSmt {
    pub tree: SparseMerkleTreeImpl,
    pub shard_depth: u8,
    pub counts: HashMap<u64, u64>, // heap_index -> count
}

impl ShardCountSmt {
    pub fn new(shard_depth: u8) -> Self {
        Self {
            tree: SparseMerkleTreeImpl::new((shard_depth + 2) as u32),
            shard_depth,
            counts: HashMap::new(),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        let h = self.tree.root();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h.as_bytes());
        arr
    }

    pub fn get_count(&self, heap_index: u64) -> u64 {
        *self.counts.get(&heap_index).unwrap_or(&0)
    }

    pub fn total(&self) -> u64 {
        self.get_count(1)
    }

    pub fn increment(&mut self, shard_index: u64) -> Result<(), DsmError> {
        let mut current_val = shard_index;
        for len in (0..=self.shard_depth).rev() {
            let heap_index = (1u64 << len) + current_val;

            let new_count = self.get_count(heap_index).saturating_add(1);
            self.counts.insert(heap_index, new_count);

            let mut val_bytes = [0u8; 32];
            val_bytes[0..8].copy_from_slice(&new_count.to_le_bytes());

            self.tree.insert(heap_index, &val_bytes)?;
            current_val >>= 1;
        }
        Ok(())
    }
}

/// Shard Activation Accumulator
///
/// Append-only list of activated identities, stored as:
///   leaf = H("DJTE.ACTIVE", id)
#[derive(Clone, Debug)]
pub struct ShardActivationAccumulator {
    pub leaves: Vec<[u8; 32]>,
}

impl ShardActivationAccumulator {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, id: [u8; 32]) {
        let leaf = domain_hash_bytes("DJTE.ACTIVE", &id);
        self.leaves.push(leaf);
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let mut hasher = dsm_domain_hasher("DSM/djte-shard-merkle");
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                let res = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(res.as_bytes());
                next_level.push(h);
            }
            current_level = next_level;
        }
        current_level[0]
    }

    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for ShardActivationAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Spent Proof SMT
///
/// Maps jap_hash -> 1 (represented as a deterministic commitment over sorted keys).
#[derive(Clone, Debug)]
pub struct SpentProofSmt {
    pub spent: HashMap<[u8; 32], bool>,
}

impl SpentProofSmt {
    pub fn new() -> Self {
        Self {
            spent: HashMap::new(),
        }
    }

    pub fn mark_spent(&mut self, jap_hash: [u8; 32]) {
        self.spent.insert(jap_hash, true);
    }

    pub fn is_spent(&self, jap_hash: &[u8; 32]) -> bool {
        self.spent.contains_key(jap_hash)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        let mut keys: Vec<[u8; 32]> = self.spent.keys().cloned().collect();
        keys.sort();

        let mut hasher = dsm_domain_hasher("DSM/djte-spent-proof");
        for k in keys {
            hasher.update(&k);
        }
        let res = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(res.as_bytes());
        h
    }
}

impl Default for SpentProofSmt {
    fn default() -> Self {
        Self::new()
    }
}

/// Source DLV State
#[derive(Clone, Debug)]
pub struct SourceDlvState {
    pub dlv_tip: [u8; 32],
    pub emission_index: u64,
    pub spent_smt: SpentProofSmt,
    pub count_smt: ShardCountSmt,
    pub shard_accumulators: Vec<ShardActivationAccumulator>,
    pub remaining_supply: u64,
}

impl SourceDlvState {
    pub fn new(shard_depth: u8, total_supply: u64) -> Self {
        let num_shards = 1usize << shard_depth;
        let mut accs = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            accs.push(ShardActivationAccumulator::new());
        }

        Self {
            dlv_tip: [0u8; 32],
            emission_index: 0,
            spent_smt: SpentProofSmt::new(),
            count_smt: ShardCountSmt::new(shard_depth),
            shard_accumulators: accs,
            remaining_supply: total_supply,
        }
    }

    /// Applies an activation to this state (append + count update).
    pub fn add_activation(&mut self, jap: &JoinActivationProof) -> Result<u64, DsmError> {
        let shard_hash = domain_hash_bytes("DJTE.SHARD", &jap.id);
        let shard_idx = extract_shard_index(&shard_hash, self.count_smt.shard_depth);

        if shard_idx as usize >= self.shard_accumulators.len() {
            return Err(DsmError::internal(
                "Shard index out of bounds",
                None::<String>,
            ));
        }

        self.shard_accumulators[shard_idx as usize].append(jap.id);
        self.count_smt.increment(shard_idx)?;

        Ok(shard_idx)
    }
}

/// Deterministic exact-uniform sampling over [0, n)
///
/// Lemire-style rejection on u64 derived from `seed`.
pub fn uniform_index(seed: &[u8; 32], n: u64) -> Result<u64, DsmError> {
    if n <= 1 {
        return Ok(0);
    }

    let threshold = n.wrapping_neg() % n;

    let mut s = *seed;
    for _ in 0..DJTE_MAX_RESEEDS {
        let x = u64::from_le_bytes(s[0..8].try_into().map_err(|_| DsmError::Internal {
            context: "Failed to convert 8 bytes to u64 in uniform_index".to_string(),
            source: None,
        })?);
        let m = (x as u128) * (n as u128);
        let low = m as u64;

        if low >= threshold {
            return Ok((m >> 64) as u64);
        }

        s = domain_hash_bytes("DJTE.RESEED", &s);
    }

    let x = u64::from_le_bytes(seed[0..8].try_into().map_err(|_| DsmError::Internal {
        context: "Failed to convert 8 bytes to u64 in uniform_index".to_string(),
        source: None,
    })?);
    let m = (x as u128) * (n as u128);
    Ok((m >> 64) as u64)
}

/// Deterministically select winner leaf for a given event index.
///
/// Selection is over the eligible set represented by `state`.
pub fn select_winner_for_event(
    state: &SourceDlvState,
    emission_index: u64,
    jap_hash: &[u8; 32],
) -> Result<[u8; 32], DsmError> {
    let mut seed_buf = Vec::with_capacity(32 + 8 + 32);
    seed_buf.extend_from_slice(&state.dlv_tip);
    seed_buf.extend_from_slice(&emission_index.to_le_bytes());
    seed_buf.extend_from_slice(jap_hash);
    let r0 = domain_hash_bytes("DJTE.SEED", &seed_buf);

    let n = state.count_smt.total();
    if n == 0 {
        return Err(DsmError::Verification("No eligible identities".into()));
    }

    let mut k = uniform_index(&r0, n)?;

    let b = state.count_smt.shard_depth;
    let mut heap: u64 = 1;
    for _ in 0..b {
        let left = heap * 2;
        let left_count = state.count_smt.get_count(left);

        if k < left_count {
            heap = left;
        } else {
            k = k.saturating_sub(left_count);
            heap = left + 1;
        }
    }

    let shard_base = 1u64 << b;
    if heap < shard_base {
        return Err(DsmError::Verification("Invalid shard descent".into()));
    }
    let shard_idx = heap - shard_base;

    let acc = state
        .shard_accumulators
        .get(shard_idx as usize)
        .ok_or_else(|| DsmError::Verification("Shard accumulator missing".into()))?;

    acc.get_leaf(k as usize)
        .ok_or_else(|| DsmError::Verification("Leaf not found".into()))
}

/// Backwards-compatible wrapper: uses state.emission_index as the event index.
pub fn select_winner(state: &SourceDlvState, jap_hash: &[u8; 32]) -> Result<[u8; 32], DsmError> {
    select_winner_for_event(state, state.emission_index, jap_hash)
}

fn compute_next_tip(
    prev_tip: &[u8; 32],
    receipt_digest: &[u8; 32],
    count_root: &[u8; 32],
    spent_root: &[u8; 32],
    shard_roots_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    buf.extend_from_slice(prev_tip);
    buf.extend_from_slice(receipt_digest);
    buf.extend_from_slice(count_root);
    buf.extend_from_slice(spent_root);
    buf.extend_from_slice(shard_roots_commitment);
    domain_hash_bytes("DJTE.DLV.TIP", &buf)
}

fn shard_roots_commitment(state: &SourceDlvState) -> [u8; 32] {
    let mut buf = Vec::with_capacity(state.shard_accumulators.len() * 32);
    for acc in &state.shard_accumulators {
        buf.extend_from_slice(&acc.root());
    }
    domain_hash_bytes("DJTE.SHARDS.ROOT", &buf)
}

/// Verify an emission transition
///
/// Validates that `next_state` is the deterministic result of applying:
/// - activation(jap)
/// - spent(jap_hash)
/// - supply decrement(amount)
/// - emission_index increment
/// - winner binding (receipt.winner_id)
/// - tip update commitment
pub fn verify_emission(
    prev_state: &SourceDlvState,
    next_state: &SourceDlvState,
    jap: &JoinActivationProof,
    receipt: &EmissionReceipt,
) -> Result<bool, DsmError> {
    if next_state.count_smt.shard_depth != prev_state.count_smt.shard_depth {
        return Err(DsmError::Verification("Shard depth changed".into()));
    }
    if next_state.shard_accumulators.len() != prev_state.shard_accumulators.len() {
        return Err(DsmError::Verification("Shard set changed".into()));
    }

    let expected_index = prev_state
        .emission_index
        .checked_add(1)
        .ok_or_else(|| DsmError::Verification("Emission index overflow".into()))?;

    if receipt.emission_index != expected_index {
        return Err(DsmError::Verification(
            "Receipt emission_index mismatch".into(),
        ));
    }
    if next_state.emission_index != expected_index {
        return Err(DsmError::Verification(
            "Invalid emission index increment".into(),
        ));
    }

    let jap_hash = jap.digest();
    if jap_hash != receipt.jap_hash {
        return Err(DsmError::Verification("JAP digest mismatch".into()));
    }

    let expected_supply = prev_state
        .remaining_supply
        .checked_sub(receipt.amount)
        .ok_or_else(|| DsmError::Verification("Supply underflow".into()))?;

    if next_state.remaining_supply != expected_supply {
        return Err(DsmError::Verification("Invalid supply update".into()));
    }

    if prev_state.spent_smt.is_spent(&receipt.jap_hash) {
        return Err(DsmError::Verification("JAP already spent".into()));
    }
    if !next_state.spent_smt.is_spent(&receipt.jap_hash) {
        return Err(DsmError::Verification(
            "Next state did not mark JAP spent".into(),
        ));
    }
    if next_state.spent_smt.len() != prev_state.spent_smt.len() + 1 {
        return Err(DsmError::Verification("Spent set size mismatch".into()));
    }
    for k in prev_state.spent_smt.spent.keys() {
        if !next_state.spent_smt.is_spent(k) {
            return Err(DsmError::Verification(
                "Spent set lost an existing key".into(),
            ));
        }
    }

    let shard_hash = domain_hash_bytes("DJTE.SHARD", &jap.id);
    let shard_idx = extract_shard_index(&shard_hash, prev_state.count_smt.shard_depth);

    if shard_idx as usize >= prev_state.shard_accumulators.len() {
        return Err(DsmError::Verification("Shard index out of bounds".into()));
    }

    let expected_new_leaf = domain_hash_bytes("DJTE.ACTIVE", &jap.id);

    for (i, (prev_acc, next_acc)) in prev_state
        .shard_accumulators
        .iter()
        .zip(next_state.shard_accumulators.iter())
        .enumerate()
    {
        if i == shard_idx as usize {
            if next_acc.len() != prev_acc.len() + 1 {
                return Err(DsmError::Verification(
                    "Activation shard leaf count mismatch".into(),
                ));
            }
            if !next_acc.leaves.starts_with(&prev_acc.leaves) {
                return Err(DsmError::Verification(
                    "Activation shard history mismatch".into(),
                ));
            }
            if next_acc.leaves.last().cloned() != Some(expected_new_leaf) {
                return Err(DsmError::Verification(
                    "Activation shard appended wrong leaf".into(),
                ));
            }
        } else if next_acc.leaves != prev_acc.leaves {
            return Err(DsmError::Verification(
                "Non-activation shard changed".into(),
            ));
        }
    }

    let mut expected_count = prev_state.count_smt.clone();
    expected_count.increment(shard_idx)?;
    if next_state.count_smt.root() != expected_count.root() {
        return Err(DsmError::Verification("Count SMT root mismatch".into()));
    }
    if next_state.count_smt.total() != prev_state.count_smt.total() + 1 {
        return Err(DsmError::Verification(
            "Total eligible count mismatch".into(),
        ));
    }

    let mut selection_state = prev_state.clone();
    selection_state.add_activation(jap)?;
    let winner_leaf =
        select_winner_for_event(&selection_state, receipt.emission_index, &receipt.jap_hash)?;
    let expected_winner_leaf = domain_hash_bytes("DJTE.ACTIVE", &receipt.winner_id);

    if winner_leaf != expected_winner_leaf {
        return Err(DsmError::Verification(
            "Winner ID does not match selected leaf".into(),
        ));
    }

    let receipt_digest = receipt.digest();
    let expected_spent_root = next_state.spent_smt.root();
    let expected_count_root = next_state.count_smt.root();
    let expected_shard_commit = shard_roots_commitment(next_state);

    let expected_tip = compute_next_tip(
        &prev_state.dlv_tip,
        &receipt_digest,
        &expected_count_root,
        &expected_spent_root,
        &expected_shard_commit,
    );

    if next_state.dlv_tip != expected_tip {
        return Err(DsmError::Verification("DLV tip mismatch".into()));
    }

    Ok(true)
}

fn extract_shard_index(hash: &[u8; 32], depth: u8) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[0..8]);
    let val = u64::from_be_bytes(bytes);

    if depth == 0 {
        return 0;
    }
    if depth < 64 {
        val >> (64 - depth)
    } else {
        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_index_determinism_and_bounds() {
        let seed = [0u8; 32];
        let n = 100u64;

        let idx1 = uniform_index(&seed, n).unwrap();
        let idx2 = uniform_index(&seed, n).unwrap();

        assert!(idx1 < n);
        assert_eq!(idx1, idx2);

        let mut seed2 = [0u8; 32];
        seed2[0] = 1;
        let idx3 = uniform_index(&seed2, n).unwrap();
        assert!(idx3 < n);
    }

    #[test]
    fn test_add_activation_updates_counts_and_leaf() {
        let mut state = SourceDlvState::new(2, 1000);

        let id1 = [1u8; 32];
        let jap2 = JoinActivationProof {
            id: id1,
            gate_proof: vec![],
            nonce: [0u8; 32],
        };

        let shard_idx = state.add_activation(&jap2).unwrap();

        assert_eq!(state.count_smt.total(), 1);

        let acc = &state.shard_accumulators[shard_idx as usize];
        assert_eq!(acc.len(), 1);
        assert_eq!(acc.leaves[0], domain_hash_bytes("DJTE.ACTIVE", &id1));
    }

    #[test]
    fn test_select_winner_after_activation_is_in_range() {
        let mut state = SourceDlvState::new(2, 1000);

        for v in 1u8..=4u8 {
            let jap = JoinActivationProof {
                id: [v; 32],
                gate_proof: vec![],
                nonce: [0u8; 32],
            };
            state.add_activation(&jap).unwrap();
        }

        let jap_hash = [0xAAu8; 32];
        let winner_leaf = select_winner_for_event(&state, 1, &jap_hash).unwrap();

        assert!(state
            .shard_accumulators
            .iter()
            .any(|acc| acc.leaves.contains(&winner_leaf)));
    }

    #[test]
    fn test_verify_emission_happy_path() {
        let prev = SourceDlvState::new(2, 10);

        let jap = JoinActivationProof {
            id: [7u8; 32],
            gate_proof: vec![1, 2, 3],
            nonce: [9u8; 32],
        };

        let receipt_amount = 1u64;
        let jap_hash = jap.digest();

        let mut temp = prev.clone();
        temp.add_activation(&jap).unwrap();

        let emission_index = prev.emission_index + 1;
        let winner_leaf = select_winner_for_event(&temp, emission_index, &jap_hash).unwrap();

        let receipt = EmissionReceipt {
            emission_index,
            winner_id: jap.id,
            amount: receipt_amount,
            jap_hash,
        };

        let mut next = prev.clone();
        next.emission_index = emission_index;
        next.remaining_supply = prev.remaining_supply - receipt_amount;

        next.add_activation(&jap).unwrap();
        next.spent_smt.mark_spent(jap_hash);

        let receipt_digest = receipt.digest();
        let count_root = next.count_smt.root();
        let spent_root = next.spent_smt.root();
        let shard_commit = shard_roots_commitment(&next);
        next.dlv_tip = compute_next_tip(
            &prev.dlv_tip,
            &receipt_digest,
            &count_root,
            &spent_root,
            &shard_commit,
        );

        assert_eq!(
            winner_leaf,
            domain_hash_bytes("DJTE.ACTIVE", &receipt.winner_id)
        );
        assert!(verify_emission(&prev, &next, &jap, &receipt).unwrap());
    }
}
