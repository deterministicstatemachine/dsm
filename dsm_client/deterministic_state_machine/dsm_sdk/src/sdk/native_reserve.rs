// SPDX-License-Identifier: Apache-2.0

//! The client side of the native ERA reserve (Part IX §51; rebuild step R4):
//! the walk to the reserve's head, the leader-first write of a release, the
//! final release at a generation for a verifier, and the background carry of
//! every final successor to every member.
//!
//! Everything semantic is Core's ([`dsm::economic::native_reserve`]): which
//! bytes at a cell are a release of the parent, what the successor state is,
//! and what a read established. This module only moves bytes and memoises
//! what Core concluded.
//!
//! ## Two properties, kept apart (owner ruling, 2026-09-20)
//!
//! Finality is leader first: the deterministic leader plus two other members
//! holding the same recognized object, and nothing more — a release final on
//! three members is exposed to its recipient at once. Replication of the
//! reserve lineage is all-member: every successor that is final is carried
//! to every remaining member in the background ([`carry_pending_releases`])
//! until all of them hold it. An unavailable non-leader member delays the
//! carry, never the claim.
//!
//! ## The memo is a cache, never authority
//!
//! Finality is permanent (Part II §8), so a state a walk reached through
//! final releases is a sound start for the next walk. The memo records
//! exactly that — each final release with the state it succeeded — and a
//! walk resumes from the latest memoised generation. Nothing in the memo is
//! ever read as a fact about a cell the walk has not read.

use dsm::economic::native_reserve::{
    resolve_successor, reserve_cell_namespace, walk_lineage, NativeReserveState, SuccessorRead,
    WalkStop,
};
use dsm::economic::provenance::ReserveReleaseWin;
use dsm::types::error::DsmError;

use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::native_reserve as memo;

/// Successor cells one walk may read before it is `BudgetExhausted` — never
/// a verdict about the lineage, only about this walk.
pub const RESERVE_WALK_BUDGET: usize = 4096;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// `R_0` for `network_id`, committing the set the claimant resolved.
pub fn genesis_state(set: &StorageSet, network_id: &[u8]) -> NativeReserveState {
    NativeReserveState::genesis(network_id, set.id())
}

/// The set a reserve state commits, and no other, names the leader and the
/// members of its successor cell: `S_commit(R_n)` decides `R_n → R_{n+1}`,
/// whatever the live membership is when the cell is read or written. Live
/// membership is only ever the carry's target.
fn committed_set_only(set: &StorageSet, parent: &NativeReserveState) -> Result<(), DsmError> {
    if set.id() != parent.storage_set_id {
        return Err(DsmError::storage(
            "the reserve state commits a different storage set than the one offered — the \
             leader and finality of a release are decided over the committed set, never over \
             the live membership"
                .to_string(),
            None::<std::io::Error>,
        ));
    }
    Ok(())
}

/// Read the successor cell of `parent` from every member of the set the
/// state commits and let Core resolve it: the leader from the reserve seed
/// over that committed set, recognition and the leader-first rule from the
/// raw reads.
pub async fn read_successor(
    set: &StorageSet,
    parent: &NativeReserveState,
) -> Result<SuccessorRead, DsmError> {
    committed_set_only(set, parent)?;
    let leader = crate::sdk::storage_io::leader_index(set, &parent.successor_seed())?;
    let reads = crate::sdk::storage_io::read_cell_raw(
        set,
        reserve_cell_namespace(),
        &parent.successor_cell(),
    )
    .await?;
    resolve_successor(parent, &reads, leader).map_err(|e| storage_err("reserve cell read", e))
}

/// Walk the reserve lineage from the latest memoised state (or `R_0`) to
/// wherever it stops, memoising every final release on the way. Bridges to
/// the async reads through `runtime`; call from a worker thread.
pub fn walk_reserve(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
) -> Result<WalkStop, DsmError> {
    let genesis = genesis_state(set, network_id);
    let start = memo::latest_state(&genesis).map_err(|e| storage_err("reserve memo", e))?;
    let mut read_err: Option<DsmError> = None;
    let mut memo_err: Option<DsmError> = None;
    let stop = walk_lineage(
        start,
        RESERVE_WALK_BUDGET,
        |parent| match tokio::task::block_in_place(|| runtime.block_on(read_successor(set, parent)))
        {
            Ok(read) => read,
            Err(e) => {
                read_err = Some(e);
                SuccessorRead::Unavailable
            }
        },
        |parent, release, child| {
            if let Err(e) = memo::record_final_release(parent, release, child) {
                memo_err = Some(storage_err("reserve memo write", e));
            }
        },
    );
    if let Some(e) = memo_err {
        return Err(e);
    }
    if let (WalkStop::Unavailable(_), Some(e)) = (&stop, read_err) {
        return Err(e);
    }
    Ok(stop)
}

/// The final release at `generation` of the reserve, for a verifier: from
/// the memo when the walk already passed it, else by walking. `None` while
/// the lineage has not reached that generation with a final release.
pub fn release_at(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
    reserve_id: &[u8; 32],
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let genesis = genesis_state(set, network_id);
    if *reserve_id != genesis.reserve_id || generation == 0 {
        return Ok(None);
    }
    if let Some(win) =
        memo::release_at(&genesis, generation).map_err(|e| storage_err("reserve memo", e))?
    {
        return Ok(Some(win));
    }
    walk_reserve(set, network_id, runtime)?;
    memo::release_at(&genesis, generation).map_err(|e| storage_err("reserve memo", e))
}

/// Part II §8: write the exact release bytes at the parent's successor cell,
/// the leader first and the other members after, and queue the bytes for
/// the background carry to every member. Nothing here decides who won —
/// Core reads that back ([`read_successor`]).
pub async fn write_release(
    set: &StorageSet,
    parent: &NativeReserveState,
    envelope: &[u8],
) -> Result<crate::sdk::storage_io::CellWrite, DsmError> {
    committed_set_only(set, parent)?;
    let key = parent.successor_cell();
    let write = crate::sdk::storage_io::write_cell_leader_first(
        set,
        reserve_cell_namespace(),
        &key,
        &parent.successor_seed(),
        envelope,
    )
    .await?;
    memo::record_carry(&key, reserve_cell_namespace(), envelope)
        .map_err(|e| storage_err("reserve carry queue", e))?;
    Ok(write)
}

/// The background carry: every queued release goes to every member of the
/// canonical set that has not yet taken it, until all of them hold it. A
/// member that is down is retried next pass; nothing about finality waits
/// on it. Returns how many releases reached every member on this pass.
pub async fn carry_pending_releases(set: &StorageSet) -> Result<u32, DsmError> {
    let pending = memo::pending_carries(64).map_err(|e| storage_err("reserve carry queue", e))?;
    let mut completed = 0u32;
    for carry in pending {
        for (i, member) in set.members().iter().enumerate() {
            if carry.carried.contains(&member.member_id) {
                continue;
            }
            if crate::sdk::storage_io::put_cell_to_member(
                set,
                i,
                &carry.namespace,
                &carry.cell_key,
                &carry.value,
            )
            .await
            .is_ok()
            {
                memo::record_carried(&carry.cell_key, &member.member_id)
                    .map_err(|e| storage_err("reserve carry queue", e))?;
            }
        }
        let carried = memo::carried_members(&carry.cell_key)
            .map_err(|e| storage_err("reserve carry queue", e))?;
        if set.members().iter().all(|m| carried.contains(&m.member_id)) {
            memo::clear_carry(&carry.cell_key)
                .map_err(|e| storage_err("reserve carry queue", e))?;
            completed += 1;
        }
    }
    Ok(completed)
}

#[cfg(test)]
mod tests {
    //! The SDK twins of the Core reserve properties, over the fake fleet:
    //! finality is leader first and needs three holders, an unavailable
    //! non-leader never blocks a claim, and the carry reaches every member
    //! afterwards.

    use super::*;
    use dsm::economic::native_reserve::{
        release_constructible, sign_release, NativeReserveReleaseBody, ReleaseSource,
        ERA_FAUCET_PAYOUT,
    };
    use serial_test::serial;

    const NETWORK: &[u8] = b"dsm-testnet";

    fn setup() -> (StorageSet, crate::handlers::faucet_flow_tests::FleetGuard) {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        let guard = crate::handlers::faucet_flow_tests::install_canonical_fleet();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        crate::sdk::storage_io::fake_registers::reset();
        let set = crate::sdk::economic_admission_flow::canonical_set(NETWORK).expect("set");
        (set, guard)
    }

    fn release_for(parent: &NativeReserveState, tag: u8) -> Vec<u8> {
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        sign_release(
            &NativeReserveReleaseBody {
                reserve_id: parent.reserve_id,
                parent_root: parent.root(),
                generation: parent.generation + 1,
                amount: ERA_FAUCET_PAYOUT,
                recipient_genesis: [tag; 32],
                recipient_devid: [tag; 32],
                recipient_economic_position: 1,
                recipient_operation_digest: [tag; 32],
                storage_set_id: parent.storage_set_id,
                source: ReleaseSource::FaucetClaimant {
                    claimant_public_key: pk,
                },
            },
            &sk,
        )
        .expect("signable")
    }

    fn leader_of(set: &StorageSet, parent: &NativeReserveState) -> String {
        let i = crate::sdk::storage_io::leader_index(set, &parent.successor_seed()).unwrap();
        set.members()[i].member_id.clone()
    }

    /// `finality without the deterministic leader is impossible`, over the
    /// fake fleet: with the leader down, a release on the four other members
    /// resolves to nothing; with the leader up and two copies, it is final.
    /// The R4 mutation control: count holders without the leader and this
    /// goes red.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn finality_without_the_deterministic_leader_is_impossible() {
        let (set, _guard) = setup();
        let r0 = genesis_state(&set, NETWORK);
        let leader = leader_of(&set, &r0);
        let x = release_for(&r0, 0xA1);
        crate::sdk::storage_io::fake_registers::fail_member(&leader, true);
        let write = write_release(&set, &r0, &x).await.expect("write");
        assert!(!write.leader_reached, "the leader is down");
        assert_eq!(write.copies, 4, "every other member took the bytes");
        assert_eq!(
            read_successor(&set, &r0).await.expect("read"),
            SuccessorRead::Unavailable,
            "four holders and no leader: nothing is final, and no member stands in"
        );
        crate::sdk::storage_io::fake_registers::fail_member(&leader, false);
        let write = write_release(&set, &r0, &x).await.expect("write");
        assert!(write.leader_reached);
        match read_successor(&set, &r0).await.expect("read") {
            SuccessorRead::Final { release, child } => {
                assert_eq!(release.envelope_bytes, x);
                assert_eq!(child.generation, 1);
                assert_eq!(
                    child.remaining_supply,
                    r0.remaining_supply - ERA_FAUCET_PAYOUT
                );
            }
            other => panic!("expected Final, got {other:?}"),
        }
    }

    /// An unavailable non-leader member does not block finality: the leader
    /// plus two copies is final, whoever else is down. Then the carry reaches
    /// the member that was down once it is back.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn an_unavailable_non_leader_never_blocks_finality_and_the_carry_reaches_it_later() {
        let (set, _guard) = setup();
        let r0 = genesis_state(&set, NETWORK);
        let leader = leader_of(&set, &r0);
        let down: Vec<String> = set
            .members()
            .iter()
            .map(|m| m.member_id.clone())
            .filter(|m| *m != leader)
            .take(2)
            .collect();
        for m in &down {
            crate::sdk::storage_io::fake_registers::fail_member(m, true);
        }
        let x = release_for(&r0, 0xB2);
        let write = write_release(&set, &r0, &x).await.expect("write");
        assert!(write.leader_reached);
        assert_eq!(
            write.copies, 2,
            "the leader and two others: exactly finality"
        );
        assert!(matches!(
            read_successor(&set, &r0).await.expect("read"),
            SuccessorRead::Final { .. }
        ));
        // The carry cannot reach the members that are down; the release is
        // final regardless.
        let completed = carry_pending_releases(&set).await.expect("carry");
        assert_eq!(completed, 0, "two members still do not hold it");
        for m in &down {
            crate::sdk::storage_io::fake_registers::fail_member(m, false);
        }
        let completed = carry_pending_releases(&set).await.expect("carry");
        assert_eq!(completed, 1);
        let holders = crate::sdk::storage_io::fake_registers::holders(
            &set,
            reserve_cell_namespace(),
            &r0.successor_cell(),
            &x,
        );
        assert_eq!(
            holders.len(),
            set.len(),
            "eventually every member holds the successor"
        );
    }

    /// `S_commit(R_n)` decides the leader and finality of `R_n → R_{n+1}`; a
    /// set that is not the one the reserve commits — a live membership with a
    /// member joined or gone — names no leader and takes no write. The R4
    /// mutation control for the authority boundary: drop `committed_set_only`
    /// and this goes red.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn a_set_other_than_the_one_the_reserve_commits_never_names_a_leader() {
        let (set, _guard) = setup();
        let r0 = genesis_state(&set, NETWORK);
        // The live membership moved: one member gone, one joined.
        let mut live: Vec<crate::sdk::storage_set::StorageMember> = set.members().to_vec();
        live.pop();
        live.push(crate::sdk::storage_set::StorageMember {
            member_id: "dsm-node-joined".into(),
            register_incarnation_id: [0xEE; 32],
            endpoint: "http://127.0.0.1:9999".into(),
        });
        let live = StorageSet::new(live).expect("a well-formed set");
        assert_ne!(live.id(), r0.storage_set_id);
        let x = release_for(&r0, 0xD1);
        assert!(
            write_release(&live, &r0, &x).await.is_err(),
            "a write over the live membership is refused before any member is touched"
        );
        assert!(
            read_successor(&live, &r0).await.is_err(),
            "a read over the live membership names no leader"
        );
        // Over the committed set, the same release is written and read.
        write_release(&set, &r0, &x).await.expect("committed set");
        assert!(matches!(
            read_successor(&set, &r0).await.expect("read"),
            SuccessorRead::Final { .. }
        ));
    }

    /// The walk advances through final releases, memoises them, and answers
    /// a verifier's `release_at` from the memo; a second walk resumes from
    /// the memoised head.
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn the_walk_memoises_final_releases_and_resumes_from_them() {
        let (set, _guard) = setup();
        let r0 = genesis_state(&set, NETWORK);
        let x1 = release_for(&r0, 0xC1);
        write_release(&set, &r0, &x1).await.expect("write");
        let r1 = match read_successor(&set, &r0).await.expect("read") {
            SuccessorRead::Final { release, child } => {
                assert_eq!(release_constructible(&r0, &release).unwrap(), child);
                child
            }
            other => panic!("{other:?}"),
        };
        let x2 = release_for(&r1, 0xC2);
        write_release(&set, &r1, &x2).await.expect("write");
        let handle = tokio::runtime::Handle::current();
        let stop = tokio::task::spawn_blocking({
            let set = set.clone();
            let handle = handle.clone();
            move || walk_reserve(&set, NETWORK, &handle)
        })
        .await
        .unwrap()
        .expect("walk");
        match stop {
            WalkStop::Head(head) => {
                assert_eq!(head.generation, 2);
                assert_eq!(
                    head.remaining_supply,
                    r0.remaining_supply - 2 * ERA_FAUCET_PAYOUT
                );
            }
            other => panic!("{other:?}"),
        }
        let win = tokio::task::spawn_blocking({
            let set = set.clone();
            move || release_at(&set, NETWORK, &handle, &r0.reserve_id, 2)
        })
        .await
        .unwrap()
        .expect("memo")
        .expect("generation 2 is final");
        assert_eq!(win.envelope_bytes, x2);
        assert_eq!(win.parent, r1);
        let start = memo::latest_state(&r0).expect("memo");
        assert_eq!(
            start.generation, 2,
            "the next walk resumes from the memoised head"
        );
    }
}
