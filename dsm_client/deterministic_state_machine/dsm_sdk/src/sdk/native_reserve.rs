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

use std::collections::{BTreeMap, HashMap};

use dsm::economic::native_reserve::{
    release_evidence_addr, reserve_cell_key, reserve_cell_namespace, reserve_seed,
    resolve_successor, successor_completion, walk_lineage, NativeReserveState, SuccessorCell,
    SuccessorRead, WalkStop,
};
use dsm::route_chain::{CellEvidence, RoutedCell};
use dsm::shared_lineage::{
    BundleStep, GenerationChain, LineageKind, SharedGenesisV1, TransitionBundleV1,
    EPOCH_GENERATIONS,
};
use dsm::economic::provenance::ReserveReleaseWin;
use dsm::types::error::DsmError;

use crate::sdk::lineage_discovery::{self, Candidates};
use crate::sdk::route_seats::{
    keep_completion, read_cell, read_cell_kept, write_recorded, NodeSeats, RouteSeats, WriteReport,
};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::native_reserve as memo;

/// Successor cells one walk may read before it is `BudgetExhausted` — never
/// a verdict about the lineage, only about this walk.
pub const RESERVE_WALK_BUDGET: usize = 4096;

/// Successor cells a walk locates ahead of the state it stands on, and
/// reads together.
pub const RESERVE_LOOKAHEAD: usize = 16;

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
    let evidence = read_successor_cell(&seats, &cell).await;
    Ok(resolve_successor(&cell, &evidence))
}

/// The reads of a successor cell: kept by the process once Core resolves a
/// final release there, which holds the cell for good (storage spec §9,
/// finality 2), and read from the seats otherwise.
async fn read_successor_cell(
    seats: &NodeSeats,
    cell: &SuccessorCell,
) -> dsm::route_chain::CellEvidence {
    read_cell_kept(seats, cell.routed(), |evidence| {
        matches!(
            resolve_successor(cell, evidence),
            SuccessorRead::Final { .. }
        )
    })
    .await
}

/// The successor cells after `from`, up to `count` of them, located by the
/// release the leader holds first at each — the copy every chain of a cell
/// begins with — that verifies and succeeds the state before it. Where to
/// look, never what holds a cell: Core decides that from each cell's full
/// reads ([`resolve_successor`]). One leader read per cell, one after the
/// other, since each cell is routed from the state the release before it
/// builds — none for a cell kept final, whose release Core resolves from
/// what was kept. It stops before a cell whose leader holds no such release:
/// the walk reads that one itself.
async fn locate_ahead(
    set: &StorageSet,
    seats: &NodeSeats,
    from: &NativeReserveState,
    count: usize,
) -> Result<Vec<SuccessorCell>, DsmError> {
    let mut cells = Vec::with_capacity(count);
    let mut state = *from;
    while cells.len() < count {
        let cell = successor_cell(set, &state)?;
        let routed = cell.routed();
        // A cell this process already read final is stepped over from what
        // it kept, with nothing asked of any member.
        if let Some(kept) = crate::sdk::final_reads::final_cell(routed) {
            if let SuccessorRead::Final { child, .. } = resolve_successor(&cell, &kept) {
                cells.push(cell);
                state = child;
                continue;
            }
        }
        let Some(held) = seats
            .read_values(routed.route().leader(), routed.namespace(), routed.key())
            .await
        else {
            break;
        };
        let Some(child) = held
            .iter()
            .find_map(|bytes| next_state(&state, routed, bytes))
        else {
            break;
        };
        cells.push(cell);
        state = child;
    }
    Ok(cells)
}

/// The state the release in the leader's copy `bytes` builds on `state`,
/// when the copy is a leader entry of this cell holding a release that
/// verifies and succeeds `state`.
fn next_state(
    state: &NativeReserveState,
    cell: &dsm::route_chain::RoutedCell,
    bytes: &[u8],
) -> Option<NativeReserveState> {
    let entry = dsm::route_chain::RouteEntry::decode(bytes)?;
    if entry.position != 0 || entry.namespace != cell.namespace() || entry.key != *cell.key() {
        return None;
    }
    match dsm::economic::native_reserve::decode_and_verify_release(&entry.value) {
        Ok(release) => {
            match dsm::economic::native_reserve::release_constructible(state, &release) {
                Ok(child) => Some(child),
                Err(refusal) => {
                    log::info!(
                        "[reserve] a release at generation {} does not succeed it: {refusal:?}",
                        state.generation + 1
                    );
                    None
                }
            }
        }
        Err(refusal) => {
            log::info!(
                "[reserve] bytes at generation {} are no release: {refusal:?}",
                state.generation + 1
            );
            None
        }
    }
}

/// Read the cells `locate_ahead` found, all at once. Each final one is kept
/// by the process (`read_successor_cell`), so the walk that follows reads it
/// from what was kept; one that is not final is read again when the walk
/// reaches it.
pub(crate) async fn read_ahead(
    set: &StorageSet,
    from: &NativeReserveState,
    count: usize,
) -> Result<(), DsmError> {
    let seats = NodeSeats::new(set)?;
    let cells = locate_ahead(set, &seats, from, count).await?;
    futures::future::join_all(cells.iter().map(|cell| read_successor_cell(&seats, cell))).await;
    log::info!(
        "[reserve] read {} successor cells ahead of generation {}",
        cells.len(),
        from.generation
    );
    Ok(())
}

/// The reserve as a shared lineage of kind 2 (SoFi Amendment S23): its
/// `R_0`, and the policy commit its genesis supply is fixed in.
fn shared_genesis(genesis: &NativeReserveState) -> SharedGenesisV1 {
    SharedGenesisV1::new(
        LineageKind::Reserve,
        genesis.reserve_id,
        genesis.root(),
        genesis.policy_commit,
    )
}

/// The successor cell of a root the epoch index names: where a release of
/// that state would be decided. Where to look, never what the state is.
fn cell_of_named_root(
    set: &StorageSet,
    reserve_id: &[u8; 32],
    root: &[u8; 32],
    storage_set_id: &[u8; 32],
) -> Result<RoutedCell, DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    RoutedCell::new(
        reserve_cell_namespace(),
        reserve_cell_key(reserve_id, root),
        &reserve_seed(reserve_id, root),
        &members,
        storage_set_id,
    )
    .map_err(|e| storage_err("reserve successor cell", format!("{e:?}")))
}

/// Cells read ahead of the walk, by cell key: reads nothing has judged yet.
/// The walk takes each out when it reaches that cell, and Core resolves it
/// there; a read Core does not resolve final is read again.
#[derive(Default)]
struct ReadAhead {
    cells: HashMap<[u8; 32], CellEvidence>,
}

/// Reads made at once, at most this many at a time.
const CELLS_AT_ONCE: usize = 16;

/// The successor cells of every root the epoch index names from `start`'s
/// generation on, read at once.
async fn read_named(
    set: &StorageSet,
    start: &NativeReserveState,
    candidates: &Candidates,
) -> Result<ReadAhead, DsmError> {
    let mut cells = Vec::new();
    for generation in candidates.generations().filter(|g| *g >= start.generation) {
        for root in candidates.roots_at(generation) {
            let cell = cell_of_named_root(set, &start.reserve_id, root, &start.storage_set_id)?;
            // A cell this process already read final is read from what it
            // kept, and is not asked for again.
            if crate::sdk::final_reads::final_cell(&cell).is_none() {
                cells.push(cell);
            }
        }
    }
    let seats = NodeSeats::new(set)?;
    let mut ahead = ReadAhead::default();
    for chunk in cells.chunks(CELLS_AT_ONCE) {
        let reads =
            futures::future::join_all(chunk.iter().map(|cell| read_cell(&seats, cell))).await;
        for (cell, evidence) in chunk.iter().zip(reads) {
            ahead.cells.insert(*cell.key(), evidence);
        }
    }
    log::info!(
        "[reserve] read {} named successor cells from generation {}",
        ahead.cells.len(),
        start.generation
    );
    Ok(ahead)
}

/// Walk the reserve lineage from the latest memoised state (or `R_0`) to
/// wherever it stops, memoising every final release on the way.
///
/// Before the walk, the epoch index is read for the hints and checkpoints
/// others published (SoFi Amendment S23), and the cells of every root they
/// name are read at once. The walk then establishes each generation exactly
/// as before — Core resolves each cell from its own reads — taking a cell
/// read ahead when it reaches it, and reading it again when Core does not
/// resolve that read final. Past what the index named, once a cell reads
/// final the next [`RESERVE_LOOKAHEAD`] cells are located and read together
/// ([`read_ahead`]). Afterwards, the hints and checkpoints nobody published
/// for what the walk established are owed, and the sweep publishes them.
///
/// Bridges to the async reads through `runtime`; call from a worker thread.
pub fn walk_reserve(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
) -> Result<WalkStop, DsmError> {
    let genesis = genesis_state(network_id)?;
    let start = memo::latest_state(&genesis).map_err(|e| storage_err("reserve memo", e))?;
    let (mut ahead, candidates) = tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let candidates = lineage_discovery::discover(
                set,
                LineageKind::Reserve,
                &start.reserve_id,
                start.generation,
            )
            .await;
            let ahead = read_named(set, &start, &candidates).await?;
            Ok::<_, DsmError>((ahead, candidates))
        })
    })?;
    let mut read_through = match candidates.generations().last() {
        Some(named) => named.max(start.generation),
        None => start.generation,
    };
    let stop = walk_lineage(
        start,
        RESERVE_WALK_BUDGET,
        |parent| {
            tokio::task::block_in_place(|| {
                runtime.block_on(async {
                    let cell = successor_cell(set, parent)?;
                    if let Some(evidence) = ahead.cells.remove(cell.routed().key()) {
                        let read = resolve_successor(&cell, &evidence);
                        if let SuccessorRead::Final { .. } = &read {
                            crate::sdk::final_reads::keep_final_cell(cell.routed(), &evidence);
                            return Ok(read);
                        }
                    }
                    let read = read_successor(set, parent).await?;
                    // A final release means the walk is behind the head: the
                    // cells after it are located and read together.
                    if let SuccessorRead::Final { child, .. } = &read {
                        if child.generation > read_through {
                            read_ahead(set, child, RESERVE_LOOKAHEAD).await?;
                            read_through = child.generation + RESERVE_LOOKAHEAD as u64;
                        }
                    }
                    Ok(read)
                })
            })
        },
        |parent, release, child| {
            memo::record_final_release(parent, release, child)
                .map_err(|e| storage_err("reserve memo write", e))
        },
    )?;
    owe_after_walk(set, &genesis, start.generation, &candidates)?;
    Ok(stop)
}

/// The generation chain of what this device's walks established, and each
/// generation's step digest (its release's evidence address).
fn established_chain(
    genesis: &NativeReserveState,
) -> Result<(GenerationChain, BTreeMap<u64, [u8; 32]>), DsmError> {
    let mut chain = GenerationChain::from_genesis(&shared_genesis(genesis));
    let mut steps = BTreeMap::new();
    for (state, envelope) in
        memo::memoised_lineage(genesis).map_err(|e| storage_err("reserve memo", e))?
    {
        if state.generation != chain.head().generation() + 1 {
            break;
        }
        let step = release_evidence_addr(&envelope);
        chain
            .push(state.root(), step)
            .map_err(|e| storage_err("reserve generation chain", e))?;
        steps.insert(state.generation, step);
    }
    Ok((chain, steps))
}

/// Owe the epoch index a hint for every generation the walk established
/// from `from` that the index named no hint for, and a checkpoint for every
/// complete segment it named no checkpoint for; then start the sweep that
/// publishes what is owed. Never on the claim's path: what is owed and never
/// reaches the set costs a later reader speed and nothing else.
fn owe_after_walk(
    set: &StorageSet,
    genesis: &NativeReserveState,
    from: u64,
    candidates: &Candidates,
) -> Result<usize, DsmError> {
    let (chain, steps) = established_chain(genesis)?;
    let set_id = set.id();
    let mut owed = lineage_discovery::owe_missing_hints(&set_id, &chain, &steps, candidates, from)?;
    let head = chain.head().generation();
    let mut start = from - from % EPOCH_GENERATIONS;
    while start + EPOCH_GENERATIONS <= head {
        let bundle = segment_bundle(&chain, &steps, start)?;
        owed += lineage_discovery::owe_checkpoint(&set_id, &chain, &bundle, start, candidates)?;
        start += EPOCH_GENERATIONS;
    }
    if owed > 0 {
        crate::handlers::artifact_republish::spawn_frozen_artifact_republish("shared lineage");
    }
    Ok(owed)
}

/// The bundle of the segment of `chain` starting at `start`: each
/// generation's release evidence address.
fn segment_bundle(
    chain: &GenerationChain,
    steps: &BTreeMap<u64, [u8; 32]>,
    start: u64,
) -> Result<TransitionBundleV1, DsmError> {
    let mut bundle_steps = Vec::with_capacity(EPOCH_GENERATIONS as usize);
    for g in start + 1..=start + EPOCH_GENERATIONS {
        bundle_steps.push(BundleStep::Reserve {
            release_evidence_addr: *steps.get(&g).ok_or_else(|| {
                storage_err(
                    "reserve segment",
                    format!("generation {g} is not established"),
                )
            })?,
        });
    }
    TransitionBundleV1::new(
        LineageKind::Reserve,
        *chain.head().lineage_id(),
        start,
        bundle_steps,
    )
    .map_err(|e| storage_err("reserve bundle", e))
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
    let evidence = read_successor_cell(&seats, &cell).await;
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
