//! DJTE: Deterministic Join-Triggered Emissions
//!
//! Core logic for:
//! - Join Activation Proof (JAP) commitment
//! - Deterministic exact-uniform winner selection (256-bit rejection sampling)
//! - Emission receipt verification
//! - State transition validation (activation + spent + supply + tip binding)
//!
//! Properties:
//! - Fully deterministic (no wall-clock, no OS randomness)
//! - Exact-uniform sampling over [0, N) using 256-bit rejection sampling
//! - Winner selection returns the selected activation leaf hash:
//!   leaf = H("DJTE.ACTIVE", winner_id)
//!
//! # Module Organization
//!
//! - [`shard_count_smt`] — ShardCountSMT (§3.5): prefix-keyed count tree for O(b) rank descent
//! - [`spent_proof_smt`] — SpentProofSMT (§3.6): tracks consumed JAP hashes
//! - [`shard_activation_accumulator`] — SAA (§3.4): per-shard append-only activated identity list
//!
//! # Storage
//!
//! All emission data structures (ShardCountSMT, SpentProofSMT, SAA) live on storage
//! nodes as part of the Source DLV state. Devices verify proofs against committed roots.

pub mod shard_activation_accumulator;
pub mod shard_count_smt;
pub mod spent_proof_smt;

pub use shard_activation_accumulator::ShardActivationAccumulator;
pub use shard_count_smt::ShardCountSmt;
pub use spent_proof_smt::SpentProofSmt;

use crate::crypto::blake3::domain_hash_bytes;
use crate::types::error::DsmError;

const DEFAULT_HALVING_STEPS: u32 = 64;
const DEFAULT_INITIAL_STEP_EMISSIONS: u64 = 1;
const DEFAULT_INITIAL_STEP_AMOUNT: u64 = 1;

/// Canonical DJTE emission schedule tuple Π = (Stotal, b, E, M0, r0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionSchedule {
    pub total_supply: u64,
    pub shard_depth: u8,
    pub schedule_steps: u32,
    pub initial_step_emissions: u64,
    pub initial_step_amount: u64,
}

impl EmissionSchedule {
    pub fn new(
        total_supply: u64,
        shard_depth: u8,
        schedule_steps: u32,
        initial_step_emissions: u64,
        initial_step_amount: u64,
    ) -> Result<Self, DsmError> {
        if schedule_steps == 0 {
            return Err(DsmError::Validation {
                context: "DJTE schedule_steps must be non-zero".into(),
                source: None,
            });
        }
        if initial_step_emissions == 0 {
            return Err(DsmError::Validation {
                context: "DJTE initial_step_emissions must be non-zero".into(),
                source: None,
            });
        }

        Ok(Self {
            total_supply,
            shard_depth,
            schedule_steps,
            initial_step_emissions,
            initial_step_amount,
        })
    }

    pub fn default_for_source(shard_depth: u8, total_supply: u64) -> Self {
        Self {
            total_supply,
            shard_depth,
            schedule_steps: DEFAULT_HALVING_STEPS,
            initial_step_emissions: DEFAULT_INITIAL_STEP_EMISSIONS,
            initial_step_amount: DEFAULT_INITIAL_STEP_AMOUNT,
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + 1 + 4 + 8 + 8);
        buf.extend_from_slice(&self.total_supply.to_le_bytes());
        buf.push(self.shard_depth);
        buf.extend_from_slice(&self.schedule_steps.to_le_bytes());
        buf.extend_from_slice(&self.initial_step_emissions.to_le_bytes());
        buf.extend_from_slice(&self.initial_step_amount.to_le_bytes());
        domain_hash_bytes("DJTE.POLICY", &buf)
    }

    pub fn amount_for_index(
        &self,
        emission_index: u64,
        remaining_supply: u64,
    ) -> Result<u64, DsmError> {
        if emission_index == 0 {
            return Err(DsmError::Verification("Emission index is one-based".into()));
        }
        let epoch = (emission_index - 1) / self.initial_step_emissions;
        if epoch >= u64::from(self.schedule_steps) {
            return Ok(0);
        }
        let step_amount = if epoch >= 64 {
            0
        } else {
            self.initial_step_amount >> epoch
        };
        Ok(step_amount.min(remaining_supply))
    }
}

/// Root witness supplied with an emission transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionWitness {
    pub policy_digest: [u8; 32],
    pub prev_count_root: [u8; 32],
    pub next_count_root: [u8; 32],
    pub prev_spent_root: [u8; 32],
    pub next_spent_root: [u8; 32],
    pub prev_shard_roots_commitment: [u8; 32],
    pub next_shard_roots_commitment: [u8; 32],
    pub activation_shard: u64,
    pub activated_leaf: [u8; 32],
}

impl EmissionWitness {
    pub fn from_states(
        prev_state: &SourceDlvState,
        next_state: &SourceDlvState,
        jap: &JoinActivationProof,
    ) -> Self {
        let shard_hash = domain_hash_bytes("DJTE.SHARD", &jap.id);
        let activation_shard = extract_shard_index(&shard_hash, prev_state.count_smt.shard_depth);
        Self {
            policy_digest: prev_state.policy.digest(),
            prev_count_root: prev_state.count_smt.root(),
            next_count_root: next_state.count_smt.root(),
            prev_spent_root: prev_state.spent_smt.root(),
            next_spent_root: next_state.spent_smt.root(),
            prev_shard_roots_commitment: shard_roots_commitment(prev_state),
            next_shard_roots_commitment: shard_roots_commitment(next_state),
            activation_shard,
            activated_leaf: domain_hash_bytes("DJTE.ACTIVE", &jap.id),
        }
    }
}

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

/// Source DLV State
#[derive(Clone, Debug)]
pub struct SourceDlvState {
    pub dlv_tip: [u8; 32],
    pub emission_index: u64,
    pub policy: EmissionSchedule,
    pub spent_smt: SpentProofSmt,
    pub count_smt: ShardCountSmt,
    pub shard_accumulators: Vec<ShardActivationAccumulator>,
    pub remaining_supply: u64,
}

impl SourceDlvState {
    pub fn new(shard_depth: u8, total_supply: u64) -> Self {
        Self::new_with_schedule(EmissionSchedule::default_for_source(
            shard_depth,
            total_supply,
        ))
    }

    pub fn new_with_schedule(schedule: EmissionSchedule) -> Self {
        let shard_depth = schedule.shard_depth;
        let total_supply = schedule.total_supply;
        let num_shards = 1usize << shard_depth;
        let mut accs = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            accs.push(ShardActivationAccumulator::new());
        }

        Self {
            dlv_tip: [0u8; 32],
            emission_index: 0,
            policy: schedule,
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

fn two_pow_256_mod(n: u64) -> u64 {
    let modulus = n as u128;
    let mut rem = 1u128 % modulus;
    for _ in 0..256 {
        rem = (rem * 2) % modulus;
    }
    rem as u64
}

fn limit_2_256_minus(rem: u64) -> [u8; 32] {
    if rem == 0 {
        return [0u8; 32];
    }

    let subtract = rem - 1;
    let mut limit = [0xffu8; 32];
    let subtract_bytes = subtract.to_be_bytes();
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let rhs = if i >= 24 {
            u16::from(subtract_bytes[i - 24])
        } else {
            0
        } + borrow;
        let lhs = u16::from(limit[i]);
        if lhs >= rhs {
            limit[i] = (lhs - rhs) as u8;
            borrow = 0;
        } else {
            limit[i] = (lhs + 256 - rhs) as u8;
            borrow = 1;
        }
    }
    limit
}

fn bytes_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a >= b
}

fn rem_u64_be(bytes: &[u8; 32], n: u64) -> u64 {
    let modulus = n as u128;
    let mut rem = 0u128;
    for byte in bytes {
        rem = ((rem << 8) + u128::from(*byte)) % modulus;
    }
    rem as u64
}

fn reseed(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 8);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&counter.to_le_bytes());
    domain_hash_bytes("DJTE.RESEED", &buf)
}

/// Deterministic exact-uniform sampling over [0, n).
///
/// Consumes a full 256-bit candidate. Values in the incomplete top range are
/// rejected and deterministically reseeded until the sample is unbiased.
pub fn uniform_index(seed: &[u8; 32], n: u64) -> Result<u64, DsmError> {
    if n <= 1 {
        return Ok(0);
    }

    let top_remainder = two_pow_256_mod(n);
    let limit = limit_2_256_minus(top_remainder);
    let mut candidate = *seed;
    let mut counter = 0u64;

    loop {
        if top_remainder == 0 || !bytes_ge(&candidate, &limit) {
            return Ok(rem_u64_be(&candidate, n));
        }

        counter = counter.checked_add(1).ok_or_else(|| {
            DsmError::Verification("DJTE uniform_index reseed counter overflow".into())
        })?;
        candidate = reseed(seed, counter);
    }
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
    witness: &EmissionWitness,
) -> Result<bool, DsmError> {
    if next_state.count_smt.shard_depth != prev_state.count_smt.shard_depth {
        return Err(DsmError::Verification("Shard depth changed".into()));
    }
    if prev_state.policy != next_state.policy {
        return Err(DsmError::Verification(
            "Source DLV emission policy changed".into(),
        ));
    }
    if prev_state.policy.shard_depth != prev_state.count_smt.shard_depth {
        return Err(DsmError::Verification(
            "Emission policy shard depth mismatch".into(),
        ));
    }
    if witness.policy_digest != prev_state.policy.digest() {
        return Err(DsmError::Verification(
            "Emission witness policy digest mismatch".into(),
        ));
    }
    if witness.prev_count_root != prev_state.count_smt.root()
        || witness.next_count_root != next_state.count_smt.root()
    {
        return Err(DsmError::Verification(
            "Emission witness count root mismatch".into(),
        ));
    }
    if witness.prev_spent_root != prev_state.spent_smt.root()
        || witness.next_spent_root != next_state.spent_smt.root()
    {
        return Err(DsmError::Verification(
            "Emission witness spent root mismatch".into(),
        ));
    }
    if witness.prev_shard_roots_commitment != shard_roots_commitment(prev_state)
        || witness.next_shard_roots_commitment != shard_roots_commitment(next_state)
    {
        return Err(DsmError::Verification(
            "Emission witness shard roots mismatch".into(),
        ));
    }
    if next_state.shard_accumulators.len() != prev_state.shard_accumulators.len() {
        return Err(DsmError::Verification("Shard set changed".into()));
    }
    if prev_state.remaining_supply > prev_state.policy.total_supply
        || next_state.remaining_supply > next_state.policy.total_supply
    {
        return Err(DsmError::Verification(
            "Remaining supply exceeds source DLV policy supply".into(),
        ));
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

    let expected_amount = prev_state
        .policy
        .amount_for_index(expected_index, prev_state.remaining_supply)?;
    if receipt.amount != expected_amount {
        return Err(DsmError::Verification(format!(
            "Emission amount mismatch: expected {expected_amount}, got {}",
            receipt.amount
        )));
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
    if witness.activation_shard != shard_idx {
        return Err(DsmError::Verification(
            "Emission witness activation shard mismatch".into(),
        ));
    }

    if shard_idx as usize >= prev_state.shard_accumulators.len() {
        return Err(DsmError::Verification("Shard index out of bounds".into()));
    }

    let expected_new_leaf = domain_hash_bytes("DJTE.ACTIVE", &jap.id);
    if witness.activated_leaf != expected_new_leaf {
        return Err(DsmError::Verification(
            "Emission witness activated leaf mismatch".into(),
        ));
    }

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
        let _winner_leaf = select_winner_for_event(&temp, emission_index, &jap_hash).unwrap();

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
        let witness = EmissionWitness::from_states(&prev, &next, &jap);

        assert_eq!(
            _winner_leaf,
            domain_hash_bytes("DJTE.ACTIVE", &receipt.winner_id)
        );
        assert!(verify_emission(&prev, &next, &jap, &receipt, &witness).unwrap());
    }

    #[test]
    fn test_verify_emission_rejects_arbitrary_amount() {
        let prev = SourceDlvState::new(2, 10);
        let jap = JoinActivationProof {
            id: [7u8; 32],
            gate_proof: vec![1, 2, 3],
            nonce: [9u8; 32],
        };
        let jap_hash = jap.digest();
        let emission_index = prev.emission_index + 1;

        let mut next = prev.clone();
        next.emission_index = emission_index;
        next.remaining_supply = prev.remaining_supply - 2;
        next.add_activation(&jap).unwrap();
        next.spent_smt.mark_spent(jap_hash);

        let receipt = EmissionReceipt {
            emission_index,
            winner_id: jap.id,
            amount: 2,
            jap_hash,
        };
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
        let witness = EmissionWitness::from_states(&prev, &next, &jap);

        let err = verify_emission(&prev, &next, &jap, &receipt, &witness)
            .expect_err("arbitrary amount must be rejected");
        assert!(err.to_string().contains("Emission amount mismatch"));
    }

    #[test]
    fn test_uniform_index_uses_full_256_bit_candidate() {
        let mut seed = [0u8; 32];
        seed[31] = 42;
        assert_eq!(uniform_index(&seed, 100).unwrap(), 42);

        let mut high = [0u8; 32];
        high[0] = 1;
        assert_ne!(
            uniform_index(&high, 257).unwrap(),
            uniform_index(&[0u8; 32], 257).unwrap()
        );
    }
}
