//! Hash chain evolution engine for the DSM state machine.
//!
//! Implements the forward-only hash chain described in whitepaper §2.1.
//! Each state commits to its predecessor via
//! `H_n = BLAKE3("DSM/state-hash\0" ‖ S_n)`, forming an append-only,
//! tamper-evident chain. Per §4.3 there is no counter — states are indexed
//! by their 32-byte hash and the chain is walked via `prev_state_hash`.

use crate::types::error::DsmError;
use crate::types::state_types::State;
use constant_time_eq;
use std::collections::HashMap;

/// HashChain maintains a sequence of states that cryptographically reference
/// each other via `prev_state_hash` embedding (§2.1 eq. 1).
pub struct HashChain {
    /// Map of state hashes (32B) to states. Stable, counter-free index.
    states: HashMap<[u8; 32], State>,

    /// Current (most recent) state.
    current_state: Option<State>,
}

#[allow(dead_code)]
impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

impl HashChain {
    /// Create a new, empty hash chain.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            current_state: None,
        }
    }

    /// Add a state to the hash chain, validating its cryptographic integrity.
    ///
    /// Per §2.1 eq. 1: `S_{n+1}` must embed `h_n = H(S_n)` in its
    /// `prev_state_hash`. There is no counter check (§4.3).
    pub fn add_state(&mut self, state: State) -> Result<(), DsmError> {
        // Compute the state's self-hash; this is its canonical identity.
        let digest = state.hash()?;

        // Reject duplicates (same hash already present).
        if self.states.contains_key(&digest) {
            return Err(DsmError::generic(
                "State with this hash already exists in the chain",
                None::<std::convert::Infallible>,
            ));
        }

        // For non-genesis states, the parent must already be in the chain
        // and must match this state's prev_state_hash.
        let is_genesis = state.prev_state_hash == [0u8; 32];
        if !is_genesis && !self.states.contains_key(&state.prev_state_hash) {
            return Err(DsmError::invalid_operation(
                "Parent state not found in chain for non-genesis state",
            ));
        }

        // Store the state.
        let mut state_with_hash = state;
        state_with_hash.hash = digest;
        self.states.insert(digest, state_with_hash.clone());

        // Update current state if this is the newest (has no known child).
        // The newest state is the unique one whose hash is not referenced
        // as a `prev_state_hash` by any other state in the chain.
        self.current_state = Some(self.find_tip()?);

        Ok(())
    }

    /// Find the tip state — the one whose hash is not referenced by any
    /// other state's `prev_state_hash`.
    fn find_tip(&self) -> Result<State, DsmError> {
        let referenced: std::collections::HashSet<[u8; 32]> = self
            .states
            .values()
            .map(|s| s.prev_state_hash)
            .collect();

        let mut tips: Vec<&State> = self
            .states
            .values()
            .filter(|s| !referenced.contains(&s.hash))
            .collect();

        if tips.len() == 1 {
            return Ok(tips.remove(0).clone());
        }
        if tips.is_empty() {
            return Err(DsmError::internal(
                "HashChain has no tip (all states referenced)",
                None::<std::convert::Infallible>,
            ));
        }
        Err(DsmError::internal(
            format!("HashChain has {} tips; expected exactly one", tips.len()),
            None::<std::convert::Infallible>,
        ))
    }

    /// Get a state by its canonical 32-byte hash.
    pub fn get_state(&self, hash: &[u8; 32]) -> Option<&State> {
        self.states.get(hash)
    }

    /// Get the current (most recent) state.
    pub fn get_latest_state(&self) -> Result<&State, DsmError> {
        self.current_state
            .as_ref()
            .ok_or_else(|| DsmError::not_found("State", Some("Chain is empty")))
    }

    /// Get a state by its hash (alias of [`get_state`] returning a `Result`).
    pub fn get_state_by_hash(&self, hash: &[u8; 32]) -> Result<&State, DsmError> {
        self.states
            .get(hash)
            .ok_or_else(|| DsmError::not_found("State", Some("State with given hash not found")))
    }

    /// Check if the chain has a state with the given hash.
    pub fn has_state_with_hash(&self, hash: &[u8; 32]) -> Result<bool, DsmError> {
        Ok(self.states.contains_key(hash))
    }

    /// Verify the integrity of the entire chain by walking from tip to genesis.
    pub fn verify_chain(&self) -> Result<bool, DsmError> {
        if self.states.is_empty() {
            return Ok(true);
        }

        let tip = self.find_tip()?;
        let mut current = &tip;

        loop {
            // Verify this state's self-hash.
            if !Self::verify_state_hash(current)? {
                return Err(DsmError::invalid_operation("State has invalid self-hash"));
            }

            // Genesis — done.
            if current.prev_state_hash == [0u8; 32] {
                return Ok(true);
            }

            // Walk to parent.
            let parent = self.states.get(&current.prev_state_hash).ok_or_else(|| {
                DsmError::invalid_operation("Parent state missing during chain walk")
            })?;

            // Check the child embedded the parent's actual hash.
            let parent_hash = parent.hash()?;
            if current.prev_state_hash != parent_hash {
                return Err(DsmError::invalid_operation(
                    "Hash chain broken: child does not embed parent's hash",
                ));
            }

            current = parent;
        }
    }

    /// Extract a subsequence of states by walking back from `tip_hash` for
    /// `depth` steps (inclusive of `tip_hash`). Returned in order from
    /// oldest to newest.
    pub fn extract_subsequence_from_tip(
        &self,
        tip_hash: &[u8; 32],
        depth: usize,
    ) -> Result<Vec<State>, DsmError> {
        let mut collected = Vec::with_capacity(depth);
        let mut cursor = self.states.get(tip_hash).ok_or_else(|| {
            DsmError::not_found("State", Some("Tip hash not found in chain"))
        })?;

        for _ in 0..depth {
            collected.push(cursor.clone());
            if cursor.prev_state_hash == [0u8; 32] {
                break;
            }
            cursor = match self.states.get(&cursor.prev_state_hash) {
                Some(parent) => parent,
                None => break,
            };
        }

        collected.reverse();
        Ok(collected)
    }

    /// Verify a state's hash integrity and its chain linkage.
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        // First verify the state's own hash integrity.
        if !Self::verify_state_hash(state)? {
            return Ok(false);
        }

        // Genesis has no parent to verify against.
        if state.prev_state_hash == [0u8; 32] {
            return Ok(true);
        }

        // The referenced parent must exist and its hash must match.
        let parent = self.states.get(&state.prev_state_hash).ok_or_else(|| {
            DsmError::verification("Cannot verify state - parent state not found".to_string())
        })?;
        let actual_parent_hash = parent.hash()?;

        Ok(constant_time_eq::constant_time_eq(
            &state.prev_state_hash,
            &actual_parent_hash,
        ))
    }

    /// Verify the cryptographic integrity of a state's hash.
    pub fn verify_state_hash(state: &State) -> Result<bool, DsmError> {
        let expected_hash = state.compute_hash()?;
        Ok(constant_time_eq::constant_time_eq(
            &expected_hash,
            &state.hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::{DeviceInfo, StateParams};
    use crate::types::operations::Operation;

    fn genesis_state() -> State {
        let device_info = DeviceInfo {
            device_id: [0x11; 32],
            public_key: vec![0x22; 64],
            metadata: Vec::new(),
        };
        let mut s = State::new_genesis([0xAA; 32], device_info);
        s.hash = s.compute_hash().expect("hash");
        s
    }

    fn child_of(parent: &State, tag: u8) -> State {
        let device_info = DeviceInfo {
            device_id: parent.device_info.device_id,
            public_key: parent.device_info.public_key.clone(),
            metadata: Vec::new(),
        };
        let params = StateParams::new(vec![tag; 32], Operation::Noop, device_info)
            .with_prev_state_hash(parent.hash);
        let mut s = State::new(params);
        s.hash = s.compute_hash().expect("hash");
        s
    }

    #[test]
    fn add_genesis_and_walk() {
        let mut chain = HashChain::new();
        let g = genesis_state();
        let g_hash = g.hash;
        chain.add_state(g).expect("add genesis");
        assert_eq!(chain.get_latest_state().expect("latest").hash, g_hash);
    }

    #[test]
    fn add_child_chain_walks_to_genesis() {
        let mut chain = HashChain::new();
        let g = genesis_state();
        let g_hash = g.hash;
        let c1 = child_of(&g, 0x01);
        let c1_hash = c1.hash;
        let c2 = child_of(&c1, 0x02);
        chain.add_state(g).expect("add g");
        chain.add_state(c1).expect("add c1");
        chain.add_state(c2).expect("add c2");

        assert_eq!(chain.get_latest_state().expect("latest").prev_state_hash, c1_hash);
        assert!(chain.verify_chain().expect("verify"));
        assert!(chain.has_state_with_hash(&g_hash).expect("has genesis"));
    }

    #[test]
    fn duplicate_hash_rejected() {
        let mut chain = HashChain::new();
        let g1 = genesis_state();
        let g2 = g1.clone();
        chain.add_state(g1).expect("first add");
        let err = chain.add_state(g2).unwrap_err();
        assert!(format!("{err:?}").contains("already"));
    }
}
