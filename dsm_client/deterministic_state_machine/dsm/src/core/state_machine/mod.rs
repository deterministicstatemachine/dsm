// SPDX-License-Identifier: MIT OR Apache-2.0

//! The device's state machine: the canonical Per-Device SMT head (§2.2) and
//! the one transition path onto it, `DeviceState::advance`.

pub mod random_walk;
pub mod utils;

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;

pub use random_walk::algorithms::{
    generate_positions, generate_random_walk_coordinates, generate_seed, verify_positions,
    verify_random_walk_coordinates, Position, RandomWalkConfig,
};

pub use utils::constant_time_eq;

/// Core state machine — Per-Device SMT head (§2.2).
///
/// All transitions route through `advance_relationship`, which uses
/// `DeviceState::advance()`; `device_state` IS the canonical head.
#[derive(Clone, Debug)]
pub struct StateMachine {
    /// Canonical device state per §2.2: SMT root + device-level balances +
    /// per-relationship chain tips. This IS the device head.
    device_state: Option<crate::types::device_state::DeviceState>,
}

impl StateMachine {
    /// Create a new state machine instance
    pub fn new() -> Self {
        StateMachine { device_state: None }
    }

    /// Get the canonical device state (§2.2 SMT head).
    pub fn device_head(&self) -> Option<&crate::types::device_state::DeviceState> {
        self.device_state.as_ref()
    }

    /// Install a canonical DeviceState head directly.
    pub fn set_device_head(&mut self, head: crate::types::device_state::DeviceState) {
        self.device_state = Some(head);
    }

    /// Get a compatibility State view from DeviceState. Used by legacy
    /// callers during migration; prefer `device_head()` for new code.
    pub fn current_state(&self) -> Option<State> {
        // The canonical DeviceState head is the SOLE source of truth. There is no
        // override: the removed `legacy_state` field once let a pinned `State` win
        // over the head, which is exactly how a stale snapshot came to shadow a
        // correct canonical balance. The compat `State` is now always SYNTHESIZED
        // from the head, so it can never diverge from it.
        let ds = self.device_state.as_ref()?;
        let device_info =
            crate::types::state_types::DeviceInfo::new(ds.devid(), ds.public_key().to_vec());
        let hash = if ds.relationship_count() == 0 && ds.balances_snapshot().is_empty() {
            ds.legacy_anchor().unwrap_or_else(|| ds.root())
        } else {
            ds.root()
        };
        let mut token_balances = std::collections::HashMap::new();
        // Project DeviceState.balances (keyed by 32-byte policy_commit) into the
        // legacy `State.token_balances` format (keyed by the canonical
        // `{prefix}|{token_id}` string) so `balance.list` and other legacy
        // readers can find balances by their ticker suffix.
        //
        // A balance whose token cannot be named is OMITTED. It previously fell
        // back to a `{prefix}|?` placeholder, which surfaced every created
        // token in the wallet as "?" — a row that is present but wrong. Absent
        // is the honest failure mode; the canonical balance is unaffected
        // either way, since `policy_commit` remains its real key.
        let public_key = ds.public_key();
        for (pc, val) in ds.balances_snapshot() {
            let Some(key) = crate::core::token::canonical_balance_key_for_commit(pc, public_key)
            else {
                continue;
            };
            token_balances.insert(
                key,
                crate::types::token_types::Balance::from_state(*val, hash),
            );
        }
        Some(State {
            device_info,
            hash,
            token_balances,
            ..State::default()
        })
    }

    /// Initialize with a genesis state. Bootstraps DeviceState from
    /// the State's device info, seeding the SMT root from the State's hash
    /// so legacy callers' verify_state checks have a head_hash to compare.
    pub fn set_state(&mut self, state: State) {
        let state_hash = state.hash().unwrap_or(state.hash);
        // Re-seed an EXISTING head only. This function does not know the
        // genesis authority root `G`, so it must not manufacture a head that
        // claims one.
        //
        // It used to build `DeviceState::new([0u8; 32], ...)` whenever no head
        // existed. That zero is not "unset" to any reader — `genesis_digest()`
        // returns it as a genesis root like any other. Because genesis install
        // calls this BEFORE `write_genesis_device_head`, the fabricated
        // zero-root head is the one that got persisted, and the ERA faucet's
        // authority evidence — which re-derives the real seed-rooted `v3.g` —
        // fail-closed against zeros on every freshly created wallet. The check
        // was right; the state was fabricated.
        //
        // Every production caller either holds `G` and writes the head itself
        // immediately after (`install_v2_genesis`,
        // `initialize_with_genesis_state`, `create_genesis_with_passive_contributors`
        // all call `write_genesis_device_head`), or already has a head
        // (`migrate_token_balance_keys`). None needs a pre-genesis head, so
        // nothing legitimate is lost by refusing to invent one.
        if let Some(ds) = self.device_state.as_mut() {
            ds.bootstrap_legacy_root(state_hash);
        }
    }

    /// Compute the next AdvanceOutcome for a relationship without installing it.
    ///
    /// Pure prepare phase of the spec-canonical transition path (§2.2, §4.2):
    /// builds the entropy from hash-adjacency inputs, extends the chain by
    /// one state, computes the SMT-replace witness, and produces the outcome.
    /// The in-memory device head is NOT mutated. Caller must subsequently
    /// `commit_advance(&outcome)` to install it as the head.
    ///
    /// This split exists so callers can persist the outcome (e.g. BCR dual
    /// write) BEFORE installing it, enabling true fail-closed atomicity:
    /// if persistence fails, the in-memory head stays on the prior state
    /// and the failure is surfaced to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_advance_relationship(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: Operation,
        deltas: &[crate::types::device_state::BalanceDelta],
        anchor_leaf: Option<crate::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<crate::types::device_state::OfflineSpend>,
    ) -> Result<crate::types::device_state::AdvanceOutcome, DsmError> {
        let ds = self.device_state.as_ref().ok_or_else(|| {
            DsmError::state_machine(
                "DeviceState not initialized — call set_state with genesis first",
            )
        })?;

        // Core derives the transition's one entropy inside `advance`, from
        // the relationship tip (Part VII step 3). Nothing is passed in.
        ds.advance(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            anchor_leaf,
            offline_spend,
        )
    }

    /// Install a previously prepared AdvanceOutcome as the new device head.
    ///
    /// Pairs with `prepare_advance_relationship`. After this returns the
    /// in-memory head reflects the outcome.
    /// Attach or clear the pending economic admission on the CURRENT head, so
    /// the next `advance` sees it. The faucet-claim accepting gate REQUIRES a
    /// matching `Prepared` admission on the head — this is the one sanctioned
    /// way the orchestration layer puts it there. The commit seam's
    /// head-carries check then keeps the durable head and the durable pending
    /// row in agreement.
    pub fn attach_pending_economic_admission(
        &mut self,
        pending: Option<crate::economic::admission::PendingEconomicAdmission>,
    ) {
        if let Some(head) = self.device_state.take() {
            self.device_state = Some(head.with_pending_economic_admission(pending));
        }
    }

    pub fn commit_advance(&mut self, outcome: &crate::types::device_state::AdvanceOutcome) {
        self.device_state = Some(outcome.new_device_state.clone());
    }

    /// Advance a specific relationship chain on the device.
    ///
    /// Convenience wrapper that runs `prepare_advance_relationship` followed
    /// by `commit_advance` with no persistence step in between. Callers that
    /// need fail-closed persistence should use the prepare/commit primitives
    /// directly so they can persist between the two phases.
    pub fn advance_relationship(
        &mut self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: Operation,
        deltas: &[crate::types::device_state::BalanceDelta],
    ) -> Result<crate::types::device_state::AdvanceOutcome, DsmError> {
        let outcome = self.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            None, // anchor_leaf — this convenience path is for ordinary transitions
            None, // offline_spend — ordinary (online) transition, no allocation draw
        )?;
        self.commit_advance(&outcome);
        Ok(outcome)
    }

    /// Initialize the state machine with a genesis state
    ///
    /// This method sets up the state machine with a genesis state,
    /// ensuring the system starts from a valid initial state.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DsmError)` - If initialization failed
    pub fn initialize_with_genesis(&mut self) -> Result<(), DsmError> {
        if self.device_state.is_some() {
            Ok(())
        } else {
            Err(DsmError::state_machine(
                "No DeviceState — call set_state with genesis first",
            ))
        }
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;

    /// REGRESSION — the 8XK incident. A pinned legacy `State` must never be able
    /// to shadow the canonical DeviceState head. The override field is gone, so
    /// `current_state()` can only ever reflect the head. If this file ever
    /// reintroduces a way to pin a `State` that wins over the head, this fails to
    /// compile or fails here — and a stale snapshot could again show the wrong
    /// balance over a correct canonical head.
    #[test]
    fn current_state_always_reflects_the_canonical_head_never_an_override() {
        let devid = [0x42u8; 32];
        // The head holds ERA through the ONLY path that produces ERA in the real
        // system: admitted faucet claims on the device's self-loop, the protocol
        // payout each. The subject here is that `current_state` reflects the
        // canonical head rather than an override — but how the head came to hold
        // a balance is not incidental: a restored, invented balance would make
        // this test pass against a head no device could ever have.
        let head = crate::types::device_state::DeviceState::new(devid, devid, vec![0xAAu8; 32])
            .admitted_faucet_claim(0)
            .expect("faucet claim")
            .admitted_faucet_claim(1)
            .expect("faucet claim")
            .admitted_faucet_claim(2)
            .expect("faucet claim");

        let mut sm = StateMachine::new();
        sm.set_device_head(head.clone());

        let cs = sm.current_state().expect("state from head");
        let era = cs
            .token_balances
            .values()
            .map(|b| b.value())
            .max()
            .unwrap_or(0);
        assert_eq!(
            era, 300,
            "current_state must reflect the canonical head's balance"
        );
        assert_eq!(cs.hash, head.root(), "hash is the canonical SMT root");
    }
    /// A device head over a real SPHINCS+ key, at a genesis root derived from
    /// the key — what `DeviceState::advance` runs on in production.
    fn test_head() -> crate::types::device_state::DeviceState {
        let (pk, _sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let device_id = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DEVICE_ID,
            &pk,
        );
        let genesis = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DEVICE_ID,
            &device_id,
        );
        crate::types::device_state::DeviceState::new(genesis, device_id, pk)
    }

    #[test]
    fn test_first_post_genesis_transition_is_allowed() -> Result<(), DsmError> {
        let head = test_head();
        let device_id = head.devid();
        // SMT-advance mechanics test: a non-balance op carries no deltas. The
        // conservation guard requires Transfer/Mint/Burn deltas to match the op;
        // balance-bearing advances are covered by the device_state guard tests.
        let op = Operation::Generic {
            operation_type: b"test.post-genesis".to_vec(),
            data: vec![],
            message: "first post-genesis transition".to_string(),
            signature: vec![],
        };

        let mut state_machine = StateMachine::new();
        state_machine.set_device_head(head);

        let dev_id = device_id;
        let rel_key = crate::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let outcome = state_machine.advance_relationship(rel_key, dev_id, op, &[])?;
        assert_ne!(outcome.child_r_a, [0u8; 32]);

        Ok(())
    }

    #[test]
    fn test_state_machine_advance_relationship() -> Result<(), DsmError> {
        let mut machine = StateMachine::new();
        let head = test_head();
        let dev_id = head.devid();
        machine.set_device_head(head);

        // SMT-advance mechanics test: non-balance op, no deltas (see conservation guard).
        let op = Operation::Generic {
            operation_type: b"test.advance".to_vec(),
            data: vec![],
            message: "Test transfer".to_string(),
            signature: vec![],
        };

        let rel_key = crate::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let outcome = machine.advance_relationship(rel_key, dev_id, op, &[])?;

        // Verify the SMT root advanced
        assert_ne!(outcome.parent_r_a, outcome.child_r_a);
        // Verify the device state was updated
        assert_eq!(
            machine.device_head().map(|d| d.root()),
            Some(outcome.child_r_a)
        );

        Ok(())
    }
}
