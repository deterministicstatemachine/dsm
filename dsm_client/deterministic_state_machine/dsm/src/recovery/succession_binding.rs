// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-counterparty recovery evidence — in-place endpoint migration (spec §0.5).
//!
//! Recovery authority is the counterparty's OWN online-posted,
//! genesis-authenticated state. This module verifies the structural core of that
//! evidence for one relationship: that counterparty C's posted per-device SMT
//! root commits a relationship state whose endpoint has migrated **in place** from
//! `A_old` to `A_new`, reached by a valid **hash forward-ancestry** chain from the
//! capsule floor (parent consumption / hash adjacency — never numeric heights).
//!
//! Authentication chain (how this is trustworthy):
//! - `counterparty_root` is C's posted per-device SMT root, **genesis-authenticated
//!   by the caller** (e.g. `DevTreeProof::verify` + signature on the posted root) —
//!   storage only supplies bytes; verification is client-side.
//! - the inclusion proof ties the migrated relationship tip into `counterparty_root`;
//! - the forward chain ties that tip back to the capsule floor `h^cap` by
//!   `embedded_parent` adjacency, each link recomputed via `compute_chain_tip`.
//! Because the migrated tip lives in C's genesis-authenticated posted root, it is C
//! that performed the migration — A_new cannot fabricate it.
//!
//! Scope (not yet enforced here): the op-level check that the migration transition
//! references the specific mnemonic-authorized tombstone for `A_old`. The migration
//! state is C-authored and only produced after C's sync verifies that tombstone;
//! binding the exact tombstone digest into the op check is a refinement pending the
//! succession-bind operation encoding (§6).

use crate::types::device_state::RelationshipChainState;
use crate::types::error::DsmError;

/// The owner's own sealed floor for one relationship, taken from A_new's capsule.
#[derive(Clone, Copy, Debug)]
pub struct RelationshipFloor {
    /// Canonical relationship key `k_{A↔C}`.
    pub rel_key: [u8; 32],
    /// `h^cap` — the last relationship tip A sealed for this relationship.
    pub floor_tip: [u8; 32],
    /// The relationship's endpoint at the floor (`A_old`).
    pub old_endpoint: [u8; 32],
}

/// Verify the forward-ancestry + in-place endpoint migration of C's relationship
/// chain, from the capsule floor up to C's current tip. Returns the verified
/// current tip on success.
///
/// `chain` is C's sequence of relationship states from just-after the floor to the
/// current tip: `chain[0].embedded_parent == floor.floor_tip`, and each subsequent
/// state's `embedded_parent` equals the prior state's recomputed tip. The final
/// state's `counterparty_devid` must be `new_endpoint` (`A_new`) — that is the
/// in-place endpoint migration.
///
/// Acceptance is by **hash adjacency / parent consumption only** — there is no
/// height, counter, or timestamp anywhere in this check (spec §0.5 mandate).
pub fn verify_endpoint_migration_chain(
    floor: &RelationshipFloor,
    new_endpoint: &[u8; 32],
    chain: &[RelationshipChainState],
) -> Result<[u8; 32], DsmError> {
    if floor.old_endpoint == *new_endpoint {
        return Err(DsmError::verification(
            "succession binding: old and new endpoints are identical (not a migration)",
        ));
    }
    if chain.is_empty() {
        return Err(DsmError::verification(
            "succession binding: empty migration chain",
        ));
    }

    // Forward-ancestry walk from the floor.
    let mut parent = floor.floor_tip;
    let mut last_tip = floor.floor_tip;
    for state in chain {
        if state.rel_key != floor.rel_key {
            return Err(DsmError::verification(
                "succession binding: rel_key mismatch within the migration chain",
            ));
        }
        if state.embedded_parent != parent {
            return Err(DsmError::verification(
                "succession binding: broken parent adjacency (not a forward descendant of the floor)",
            ));
        }
        last_tip = state.compute_chain_tip();
        parent = last_tip;
    }

    // In-place endpoint migration: the latest state must bind the successor.
    let final_state = &chain[chain.len() - 1];
    if &final_state.counterparty_devid != new_endpoint {
        return Err(DsmError::verification(
            "succession binding: final relationship state does not bind the successor A_new",
        ));
    }

    Ok(last_tip)
}

/// Full per-counterparty evidence check (spec §0.5): the migrated tip is a forward
/// descendant of the capsule floor and is included in C's posted (and, by the
/// caller's precondition, genesis-authenticated) per-device SMT root.
///
/// `counterparty_root` MUST already be verified to belong to C (genesis /
/// device-tree authenticated) before calling this — storage delivers bytes,
/// verification is client-side.
pub fn verify_succession_binding(
    floor: &RelationshipFloor,
    new_endpoint: &[u8; 32],
    counterparty_root: &[u8; 32],
    inclusion_proof: &[u8],
    chain: &[RelationshipChainState],
) -> Result<[u8; 32], DsmError> {
    let final_tip = verify_endpoint_migration_chain(floor, new_endpoint, chain)?;

    let included = crate::verification::proof_primitives::verify_smt_inclusion_proof_bytes(
        counterparty_root,
        &floor.rel_key,
        &final_tip,
        inclusion_proof,
    )?;
    if !included {
        return Err(DsmError::verification(
            "succession binding: inclusion proof failed against the counterparty's posted root",
        ));
    }
    Ok(final_tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use std::collections::BTreeMap;

    const OLD: [u8; 32] = [0xA0; 32];
    const NEW: [u8; 32] = [0xA1; 32];
    const REL: [u8; 32] = [0x5A; 32];

    fn state(rel_key: [u8; 32], parent: [u8; 32], endpoint: [u8; 32], entropy: u8) -> RelationshipChainState {
        RelationshipChainState {
            rel_key,
            embedded_parent: parent,
            counterparty_devid: endpoint,
            operation: Operation::Noop,
            entropy: vec![entropy],
            encapsulated_entropy: None,
            balance_witness: BTreeMap::new(),
            entity_sig: None,
            counterparty_sig: None,
            dbrw_summary_hash: None,
        }
    }

    fn floor() -> RelationshipFloor {
        // floor_tip is the recomputed tip of the last A_old state A sealed.
        let last_old = state(REL, [0x11; 32], OLD, 0);
        RelationshipFloor {
            rel_key: REL,
            floor_tip: last_old.compute_chain_tip(),
            old_endpoint: OLD,
        }
    }

    #[test]
    fn single_step_migration_passes() {
        let f = floor();
        // One forward state: parent == floor, endpoint flips to A_new.
        let migration = state(REL, f.floor_tip, NEW, 1);
        let tip = verify_endpoint_migration_chain(&f, &NEW, std::slice::from_ref(&migration))
            .expect("valid migration");
        assert_eq!(tip, migration.compute_chain_tip());
    }

    #[test]
    fn multi_step_chain_passes() {
        let f = floor();
        let s1 = state(REL, f.floor_tip, OLD, 1); // still old endpoint
        let s2 = state(REL, s1.compute_chain_tip(), NEW, 2); // migrates to A_new
        let chain = vec![s1, s2.clone()];
        let tip = verify_endpoint_migration_chain(&f, &NEW, &chain).expect("valid");
        assert_eq!(tip, s2.compute_chain_tip());
    }

    #[test]
    fn broken_parent_adjacency_fails() {
        let f = floor();
        let migration = state(REL, [0xDE; 32], NEW, 1); // wrong parent
        assert!(verify_endpoint_migration_chain(&f, &NEW, std::slice::from_ref(&migration)).is_err());
    }

    #[test]
    fn final_endpoint_not_successor_fails() {
        let f = floor();
        let migration = state(REL, f.floor_tip, OLD, 1); // never migrates
        assert!(verify_endpoint_migration_chain(&f, &NEW, std::slice::from_ref(&migration)).is_err());
    }

    #[test]
    fn second_step_breaks_adjacency_fails() {
        let f = floor();
        let s1 = state(REL, f.floor_tip, OLD, 1);
        let s2 = state(REL, [0xBE; 32], NEW, 2); // parent not s1's tip
        assert!(verify_endpoint_migration_chain(&f, &NEW, &[s1, s2]).is_err());
    }

    #[test]
    fn rel_key_mismatch_fails() {
        let f = floor();
        let migration = state([0x99; 32], f.floor_tip, NEW, 1);
        assert!(verify_endpoint_migration_chain(&f, &NEW, std::slice::from_ref(&migration)).is_err());
    }

    #[test]
    fn empty_chain_fails() {
        let f = floor();
        assert!(verify_endpoint_migration_chain(&f, &NEW, &[]).is_err());
    }

    #[test]
    fn old_equals_new_fails() {
        let mut f = floor();
        f.old_endpoint = NEW;
        let migration = state(REL, f.floor_tip, NEW, 1);
        assert!(verify_endpoint_migration_chain(&f, &NEW, std::slice::from_ref(&migration)).is_err());
    }
}
