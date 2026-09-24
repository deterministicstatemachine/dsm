// SPDX-License-Identifier: Apache-2.0

//! The client side of the native ERA reserve (SoFi Part IX §51): the walk to
//! the reserve's head, the write of a release along its successor cell's
//! route, the final release at a generation for a verifier, and the
//! completion proof of this device's own release.
//!
//! Everything semantic is Core's ([`dsm::economic::native_reserve`]): which
//! cell succeeds a state and its route, which bytes at a cell are a release
//! of the parent, what the successor state is, and what a read established.
//! This module moves bytes and memoises what Core concluded.
//!
//! ## The memo is a cache, never authority
//!
//! Finality is permanent, so a state a walk reached through final releases
//! is a sound start for the next walk. The memo records exactly that — each
//! final release with the state it succeeded — and a walk resumes from the
//! latest memoised generation. Nothing in the memo is ever read as a fact
//! about a cell the walk has not read.

use dsm::economic::native_reserve::{
    resolve_successor, successor_completion, walk_lineage, NativeReserveState, SuccessorCell,
    SuccessorRead, WalkStop,
};
use dsm::economic::provenance::ReserveReleaseWin;
use dsm::types::error::DsmError;

use crate::sdk::route_seats::{keep_completion, read_cell, write_recorded, NodeSeats, WriteReport};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::native_reserve as memo;

/// Successor cells one walk may read before it is `BudgetExhausted` — never
/// a verdict about the lineage, only about this walk.
pub const RESERVE_WALK_BUDGET: usize = 4096;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// `R_0` for `network_id`: the whole genesis supply, committing the
/// network's pinned register set.
pub fn genesis_state(network_id: &[u8]) -> Result<NativeReserveState, DsmError> {
    let profile = dsm::economic::register::resolve_root_register_profile(network_id)
        .map_err(|e| storage_err("root register profile", e))?;
    Ok(NativeReserveState::genesis(
        network_id,
        profile.storage_set_id,
    ))
}

/// `parent`'s successor cell over the members of `set`, which must be the
/// set `parent` commits.
fn successor_cell(
    set: &StorageSet,
    parent: &NativeReserveState,
) -> Result<SuccessorCell, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    SuccessorCell::of(parent, &members)
        .map_err(|e| storage_err("reserve successor cell", format!("{e:?}")))
}

/// Read `parent`'s successor cell from its seats and let Core resolve it.
pub async fn read_successor(
    set: &StorageSet,
    parent: &NativeReserveState,
) -> Result<SuccessorRead, DsmError> {
    let cell = successor_cell(set, parent)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    Ok(resolve_successor(&cell, &evidence))
}

/// Walk the reserve lineage from the latest memoised state (or `R_0`) to
/// wherever it stops, memoising every final release on the way. Bridges to
/// the async reads through `runtime`; call from a worker thread.
pub fn walk_reserve(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
) -> Result<WalkStop, DsmError> {
    let genesis = genesis_state(network_id)?;
    let start = memo::latest_state(&genesis).map_err(|e| storage_err("reserve memo", e))?;
    walk_lineage(
        start,
        RESERVE_WALK_BUDGET,
        |parent| tokio::task::block_in_place(|| runtime.block_on(read_successor(set, parent))),
        |parent, release, child| {
            memo::record_final_release(parent, release, child)
                .map_err(|e| storage_err("reserve memo write", e))
        },
    )
}

/// The final release at `generation` of the reserve `reserve_id`, for a
/// verifier: from the memo when a walk already passed it, else by walking.
/// `None` while the lineage has not reached that generation with a final
/// release.
pub fn release_at(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
    reserve_id: &[u8; 32],
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let genesis = genesis_state(network_id)?;
    if *reserve_id != genesis.reserve_id {
        return Err(DsmError::invalid_operation(
            "the named reserve is not this network's native reserve",
        ));
    }
    if generation == 0 {
        return Err(DsmError::invalid_operation(
            "generation 0 is the reserve's genesis state, never a release",
        ));
    }
    if let Some(win) =
        memo::release_at(&genesis, generation).map_err(|e| storage_err("reserve memo", e))?
    {
        return Ok(Some(win));
    }
    walk_reserve(set, network_id, runtime)?;
    memo::release_at(&genesis, generation).map_err(|e| storage_err("reserve memo", e))
}

/// Write the exact release bytes at `parent`'s successor cell along its
/// route (storage spec §9), continuing an earlier write of the same bytes.
/// Nothing here decides which release holds the cell — Core reads that back
/// ([`read_successor`]).
pub async fn write_release(
    set: &StorageSet,
    parent: &NativeReserveState,
    envelope: &[u8],
) -> Result<WriteReport, DsmError> {
    let cell = successor_cell(set, parent)?;
    write_recorded(set, cell.routed(), envelope).await
}

/// Keep the completion proof of this device's release at `parent`'s
/// successor cell (storage spec §9 rule 11). `Ok(true)` once `envelope` is the
/// release final there and its proof is kept; `Ok(false)` while it is not
/// final, or another release holds the cell.
pub async fn keep_release_completion(
    set: &StorageSet,
    parent: &NativeReserveState,
    envelope: &[u8],
) -> Result<bool, DsmError> {
    let cell = successor_cell(set, parent)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cell.routed()).await;
    let Some((release, child, proof)) = successor_completion(&cell, &evidence)
        .map_err(|missing| storage_err("reserve completion", format!("{missing:?}")))?
    else {
        return Ok(false);
    };
    if release.envelope_bytes != envelope {
        log::info!(
            "reserve completion: another release holds generation {}",
            child.generation
        );
        return Ok(false);
    }
    keep_completion(cell.routed(), &proof)?;
    Ok(true)
}
