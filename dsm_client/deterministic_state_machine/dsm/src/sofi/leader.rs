// SPDX-License-Identifier: Apache-2.0

//! The leader of a cell — Part II §7 — rebuild step R3.
//!
//! For every cell at a key `K`, the writer and Core compute one leader from a
//! seed over the COMMITTED set `S`:
//!
//! ```text
//! L = FisherYates(s, S)[0]
//! ```
//!
//! A storage node never does: it does not know which cells it leads, and it
//! never compares its value with anyone else's. Availability, the caller's
//! identity and node ids never enter a seed, and an offline member stays in
//! `S`, so the leader of a cell never depends on who is online.
//!
//! The two SoFi seeds (§7.2) both consume a state root, so a writer cannot
//! choose its leader:
//!
//! | cells                                        | seed                                  |
//! |----------------------------------------------|---------------------------------------|
//! | DLV successor cells of vault `v` at `R_n`    | `s_v = storage_seed(v, R_n)` — here   |
//! | the trader's position `q`                    | `s(q)` — `economic::register::position_leader` |
//!
//! `S` is the set the vault state names (`VaultStateLeaf.storage_set_id`,
//! which every precommit must match); the caller resolves that id to the
//! committed members and passes them in. A caller that passed the members it
//! could reach would be computing a different function, and the test
//! `a_reachable_subset_can_name_another_leader` shows it.
//!
//! Formal statement: `tla/DSM_SofiSuccessorCells.tla`, `LeaderFromCommittedSet`
//! with the `_AvailabilityLeader` faults (a leader chosen by reachability
//! violates it). The ordering is frozen by the vectors in
//! `dsm/tests/sofi_v8_independent.rs`.

use super::derive::storage_seed;
use super::fisher_yates::{first_member, FisherYatesError};
use crate::ccb::StorageSetMembers;

type D32 = [u8; 32];

/// The member that leads every successor cell of vault `vault_id` at parent
/// root `parent_root`: `FisherYates(storage_seed(v, R_n), S)[0]` over the
/// committed set's member ids.
pub fn successor_cell_leader(
    vault_id: &D32,
    parent_root: &D32,
    members: &StorageSetMembers,
) -> Result<Vec<u8>, FisherYatesError> {
    let ids: Vec<Vec<u8>> = members
        .entries()
        .iter()
        .map(|e| e.member_id().to_vec())
        .collect();
    first_member(&storage_seed(vault_id, parent_root), &ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(ids: &[&[u8]]) -> StorageSetMembers {
        let pairs: Vec<(&[u8], D32)> = ids.iter().map(|id| (*id, [0x11; 32])).collect();
        StorageSetMembers::new(&pairs).expect("distinct members")
    }

    const FIVE: [&[u8]; 5] = [b"m1", b"m2", b"m3", b"m4", b"m5"];

    /// The leader is exactly the frozen algorithm's first member under the
    /// vault's storage seed — nothing else enters.
    #[test]
    fn the_leader_is_the_first_member_of_the_seeded_shuffle_over_s() {
        let (v, r) = ([0xA1; 32], [0xB2; 32]);
        let expected = first_member(
            &storage_seed(&v, &r),
            &FIVE.iter().map(|m| m.to_vec()).collect::<Vec<_>>(),
        )
        .expect("shuffle");
        assert_eq!(
            successor_cell_leader(&v, &r, &members(&FIVE)).expect("leader"),
            expected
        );
    }

    /// The seed consumes the vault and the parent root, so a writer cannot
    /// choose its leader: change either and the leader moves for some root.
    #[test]
    fn the_seed_binds_the_vault_and_the_parent_root() {
        let m = members(&FIVE);
        let base = successor_cell_leader(&[0xA1; 32], &[0xB2; 32], &m).expect("leader");
        let moved_by_root = (0u8..32)
            .map(|b| successor_cell_leader(&[0xA1; 32], &[b; 32], &m).expect("leader"))
            .any(|l| l != base);
        let moved_by_vault = (0u8..32)
            .map(|b| successor_cell_leader(&[b; 32], &[0xB2; 32], &m).expect("leader"))
            .any(|l| l != base);
        assert!(moved_by_root && moved_by_vault);
    }

    /// The witness for the R3 mutation: computing over the members a caller
    /// could reach is a DIFFERENT function of the world. For some root, the
    /// leader over `S` is a member absent from the reachable subset, so the
    /// subset names someone else; a client that used its view would send its
    /// first write to a member that is not the leader.
    #[test]
    fn a_reachable_subset_can_name_another_leader() {
        let all = members(&FIVE);
        let reachable = members(&[b"m1", b"m2", b"m3", b"m4"]);
        let v = [0xA1; 32];
        let differs = (0u8..64).any(|b| {
            let r = [b; 32];
            successor_cell_leader(&v, &r, &all).expect("leader")
                != successor_cell_leader(&v, &r, &reachable).expect("leader")
        });
        assert!(
            differs,
            "availability would change the leader if it entered"
        );
    }
}
