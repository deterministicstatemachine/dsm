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
    release_evidence_addr, reserve_cell_key, reserve_cell_namespace, reserve_lineage_genesis,
    reserve_seed, resolve_successor, successor_completion, walk_lineage, EstablishedReserve,
    NativeReserveState, SuccessorCell, SuccessorRead, WalkStop,
};
use dsm::route_chain::{CellEvidence, RoutedCell};
use dsm::shared_lineage::{
    BundleStep, GenerationChain, LineageKind, TransitionBundleV1, EPOCH_GENERATIONS,
};
use dsm::economic::provenance::ReserveReleaseWin;
use dsm::types::error::DsmError;

use crate::sdk::lineage_discovery::{self, Candidates};
use crate::sdk::route_seats::{
    keep_completion, read_cell_kept, read_cell_kept_within, read_cell_within, write_recorded,
    NodeSeats, ReadWindow, WriteReport,
};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::native_reserve as memo;

/// Successor cells one walk may read before it is `BudgetExhausted` — never
/// a verdict about the lineage, only about this walk.
pub const RESERVE_WALK_BUDGET: usize = 4096;

/// Successor cells a walk locates ahead of the state it stands on, and
/// reads together.
pub const RESERVE_LOOKAHEAD: usize = 16;

/// What the cells one walk reads together may keep between them, read ahead
/// of the walk: the most the process keeps of cells it found final
/// (`final_reads`), which is where what the walk finds final goes. Anyone
/// may write a release that verifies at a cell, so a cell's copies are the
/// writers' to choose; past this a seat is not read ahead, and the walk
/// reads its cell when it reaches it (SA-76).
const READ_AHEAD_BYTES: usize = 24 * 1024 * 1024;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// `R_0` for `network_id`: the whole genesis supply, committing the
/// network's pinned register set.
pub fn genesis_state(network_id: &[u8]) -> Result<NativeReserveState, DsmError> {
    let profile = dsm::economic::register::resolve_root_register_profile(network_id)
        .map_err(|e| storage_err("root register profile", e))?;
    NativeReserveState::genesis(network_id, profile.storage_set_id)
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
    read_cell_kept(seats, cell.routed(), &cell.keeps(), |evidence| {
        matches!(
            resolve_successor(cell, evidence),
            SuccessorRead::Final { .. }
        )
    })
    .await
}

/// [`read_successor_cell`], as one of the reads a walk makes ahead together
/// within `window`.
async fn read_successor_cell_within(
    seats: &NodeSeats,
    cell: &SuccessorCell,
    window: &ReadWindow,
) -> dsm::route_chain::CellEvidence {
    read_cell_kept_within(seats, cell.routed(), &cell.keeps(), window, |evidence| {
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
        // Only a leader copy holding a release that succeeds the state is
        // kept from the leader's log; anything else there costs the read.
        let succeeds = |bytes: &[u8]| next_state(&state, routed, bytes).is_some();
        let Some(held) = crate::sdk::route_seats::kept_values(
            seats,
            routed.route().leader(),
            routed.namespace(),
            routed.key(),
            &succeeds,
        )
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
                        state.generation() + 1
                    );
                    None
                }
            }
        }
        Err(refusal) => {
            log::info!(
                "[reserve] bytes at generation {} are no release: {refusal:?}",
                state.generation() + 1
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
    let window = &ReadWindow::new(READ_AHEAD_BYTES);
    futures::future::join_all(
        cells
            .iter()
            .map(|cell| read_successor_cell_within(&seats, cell, window)),
    )
    .await;
    log::info!(
        "[reserve] read {} successor cells ahead of generation {}",
        cells.len(),
        from.generation()
    );
    Ok(())
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
    /// The last generation whose named roots' cells were read ahead.
    through: u64,
}

/// Reads made at once, at most this many at a time.
const CELLS_AT_ONCE: usize = 16;

/// The successor cells of the roots the epoch index names from `start`'s
/// generation on, as many as one walk reads ahead
/// ([`lineage_discovery::NAMED_READS_PER_WALK`]), read at once.
async fn read_named(
    set: &StorageSet,
    start: &NativeReserveState,
    candidates: &Candidates,
) -> Result<ReadAhead, DsmError> {
    let mut cells = Vec::new();
    for (generation, root) in candidates.named_from(start.generation()) {
        let cell = cell_of_named_root(set, start.reserve_id(), &root, start.storage_set_id())?;
        // A cell this process already read final is read from what it
        // kept, and is not asked for again.
        if crate::sdk::final_reads::final_cell(&cell).is_none() {
            cells.push((cell, root, generation));
        }
    }
    let seats = &NodeSeats::new(set)?;
    let window = &ReadWindow::new(READ_AHEAD_BYTES);
    let mut ahead = ReadAhead {
        cells: HashMap::new(),
        through: start.generation(),
    };
    for chunk in cells.chunks(CELLS_AT_ONCE) {
        // Once a seat went unread for want of the window, a further read
        // within it reads for nothing: the walk reads the rest itself.
        if window.spent() {
            break;
        }
        let reads = futures::future::join_all(chunk.iter().map(|(cell, root, _)| async move {
            let keep = dsm::economic::native_reserve::named_successor_keeps(
                cell,
                start.reserve_id(),
                root,
            );
            read_cell_within(seats, cell, &keep, window).await
        }))
        .await;
        for ((cell, _, generation), evidence) in chunk.iter().zip(reads) {
            ahead.cells.insert(*cell.key(), evidence);
            ahead.through = ahead.through.max(*generation);
        }
    }
    log::info!(
        "[reserve] read {} named successor cells from generation {}",
        ahead.cells.len(),
        start.generation()
    );
    Ok(ahead)
}

/// Walk the reserve lineage from the head this device's walks established
/// (or `R_0`) to wherever it stops, memoising every final release on the
/// way. The walk starts from that head and stops at one (DSM Amendment A15).
///
/// Before the walk, the epoch index is read for the hints and checkpoints
/// others published (SoFi Amendment S23), and the cells of the roots they
/// name — the hints', and a checkpoint's only when it starts at the head this
/// device's walks established — are read at once, up to
/// [`lineage_discovery::NAMED_READS_PER_WALK`]. The walk then establishes each generation exactly
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
    let (established, _, _) = established_chain(&genesis, None)?;
    let start = EstablishedReserve::of(&genesis, &established.head())
        .map_err(|e| storage_err("reserve head", e))?;
    let from = *start.state();
    let (mut ahead, mut candidates) = tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let mut candidates = lineage_discovery::discover(
                set,
                LineageKind::Reserve,
                from.reserve_id(),
                from.generation(),
            )
            .await;
            // A checkpoint names cells to read only for the segment that
            // starts where this device's own walks stand (SA-69).
            candidates.admit_checkpoints(start.head());
            let ahead = read_named(set, &from, &candidates).await?;
            Ok::<_, DsmError>((ahead, candidates))
        })
    })?;
    let mut read_through = ahead.through;
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
                        if child.generation() > read_through {
                            read_ahead(set, child, RESERVE_LOOKAHEAD).await?;
                            read_through = child.generation() + RESERVE_LOOKAHEAD as u64;
                        }
                    }
                    Ok(read)
                })
            })
        },
        |parent, release, child| {
            memo::record_final_release(parent.state(), release, child.state())
                .map_err(|e| storage_err("reserve memo write", e))
        },
    )?;
    // A checkpoint whose end the walk did not reproduce is discarded before
    // anything is owed (SoFi Amendment S23, step 4).
    let (walked, _, _) = established_chain(&genesis, None)?;
    let settled = candidates.settle_checkpoints(&walked);
    log::info!(
        "[reserve] checkpoints after the walk: {} borne out, {} discarded",
        settled.borne_out,
        settled.discarded
    );
    owe_after_walk(set, &genesis, from.generation(), &candidates)?;
    Ok(stop)
}

/// The generation chain of what this device's walks established, each
/// generation's step digest (its release's evidence address), and the
/// envelope of the release at generation `keep`, when the chain reaches it.
/// A memoised release past the first generation the memo skips is not one
/// this device's walks established, and is not in the chain.
fn established_chain(
    genesis: &NativeReserveState,
    keep: Option<u64>,
) -> Result<(GenerationChain, BTreeMap<u64, [u8; 32]>, Option<Vec<u8>>), DsmError> {
    let lineage =
        reserve_lineage_genesis(genesis).map_err(|e| storage_err("reserve genesis", e))?;
    let mut chain = GenerationChain::from_genesis(&lineage);
    let mut steps = BTreeMap::new();
    let mut kept = None;
    // One memoised release at a time: its step digest is taken and the
    // release let go before the next is read (SA-75), except the one asked
    // to be kept.
    memo::fold_memoised_lineage(genesis, |state, envelope| {
        if state.generation() != chain.head().generation() + 1 {
            return Ok(std::ops::ControlFlow::Break(()));
        }
        let step = release_evidence_addr(envelope);
        chain
            .push(state.root(), step)
            .map_err(|e| anyhow::anyhow!("reserve generation chain: {e}"))?;
        steps.insert(state.generation(), step);
        if keep == Some(state.generation()) {
            kept = Some(envelope.to_vec());
        }
        Ok(std::ops::ControlFlow::Continue(()))
    })
    .map_err(|e| storage_err("reserve memo", e))?;
    Ok((chain, steps, kept))
}

/// The release this device's walks established at `generation`, with the
/// established heads before and after it; `None` while the chain does not
/// reach it. Reads only what was memoised: nothing is walked here.
pub(crate) fn established_release_at(
    genesis: &NativeReserveState,
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let Some(before) = generation.checked_sub(1) else {
        return Err(DsmError::invalid_operation(
            "generation 0 is the reserve's genesis state, never a release",
        ));
    };
    let (chain, _, kept) = established_chain(genesis, Some(generation))?;
    let (Some(parent), Some(child), Some(envelope_bytes)) =
        (chain.head_at(before), chain.head_at(generation), kept)
    else {
        return Ok(None);
    };
    Ok(Some(ReserveReleaseWin {
        envelope_bytes,
        parent,
        child,
    }))
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
    let (chain, steps, _) = established_chain(genesis, None)?;
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
/// verifier, with the established heads around it: from what this device's
/// walks established when they already passed it, else by walking. `None`
/// while the lineage has not reached that generation with a final release.
pub fn release_at(
    set: &StorageSet,
    network_id: &[u8],
    runtime: &tokio::runtime::Handle,
    reserve_id: &[u8; 32],
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let genesis = genesis_state(network_id)?;
    if reserve_id != genesis.reserve_id() {
        return Err(DsmError::invalid_operation(
            "the named reserve is not this network's native reserve",
        ));
    }
    if let Some(win) = established_release_at(&genesis, generation)? {
        return Ok(Some(win));
    }
    walk_reserve(set, network_id, runtime)?;
    established_release_at(&genesis, generation)
}

/// Write the exact release bytes at `parent`'s successor cell along its
/// route (storage spec §9), continuing an earlier write of the same bytes.
/// Another release first at the cell's leader takes the write there. Nothing
/// here decides which release holds the cell — Core reads that back
/// ([`read_successor`]).
pub async fn write_release(
    set: &StorageSet,
    parent: &NativeReserveState,
    envelope: &[u8],
) -> Result<WriteReport, DsmError> {
    let cell = successor_cell(set, parent)?;
    let report = write_recorded(set, cell.routed(), &cell.keeps(), envelope).await?;
    Ok(report)
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
            child.generation()
        );
        return Ok(false);
    }
    keep_completion(cell.routed(), &proof)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A memoised final release at `child`, with `envelope` as its bytes.
    fn memo_row(genesis: &NativeReserveState, child: &NativeReserveState, envelope: &[u8]) {
        let binding = crate::storage::client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store is not poisoned");
        conn.execute(
            "INSERT INTO native_reserve_lineage_memo
               (reserve_id, generation, parent_remaining, remaining, recipient_genesis,
                recipient_devid, recipient_position, envelope)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            rusqlite::params![
                genesis.reserve_id().as_slice(),
                child.generation() as i64,
                (child.remaining_supply() + dsm::economic::native_reserve::ERA_FAUCET_PAYOUT)
                    as i64,
                child.remaining_supply() as i64,
                [0x61u8; 32].as_slice(),
                [0x62u8; 32].as_slice(),
                envelope,
            ],
        )
        .expect("a memo row");
    }

    /// The generation chain a walk owes hints and checkpoints from is each
    /// memoised release's evidence address, generation by generation from
    /// the genesis, and stops at the first generation the memo skips: a
    /// generation after a gap is not one this device's walks established.
    #[test]
    #[serial_test::serial]
    fn the_generation_chain_is_the_memoised_releases_up_to_the_first_gap() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let genesis = NativeReserveState::genesis(b"chain-test", [0x5E; 32]).expect("R_0");
        let mut expected =
            GenerationChain::from_genesis(&reserve_lineage_genesis(&genesis).expect("R_0"));
        for g in [1u64, 2, 3, 5] {
            let state = genesis
                .at_generation(g)
                .expect("a generation of the lineage");
            let envelope = [0xC0 | g as u8; 40];
            memo_row(&genesis, &state, &envelope);
            if g <= 3 {
                expected
                    .push(state.root(), release_evidence_addr(&envelope))
                    .expect("the next generation");
            }
        }
        let (chain, steps, _) = established_chain(&genesis, None).expect("the chain");
        assert_eq!(chain.head(), expected.head());
        assert_eq!(steps.len(), 3, "generation 5 follows a gap");
    }

    /// DSM Amendment A15, MR-DSM-0315: a verifier is answered from the head
    /// this device's walks established. A memoised release on that chain
    /// comes with the chain's heads before and after it; a memoised release
    /// past a gap is not established, and is not answered as a release, so
    /// the verifier walks for it instead.
    #[test]
    #[serial_test::serial]
    fn a_memoised_release_past_a_gap_is_not_an_established_release() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let genesis = NativeReserveState::genesis(b"chain-test", [0x5E; 32]).expect("R_0");
        let mut expected =
            GenerationChain::from_genesis(&reserve_lineage_genesis(&genesis).expect("R_0"));
        for g in [1u64, 2, 3, 5] {
            let state = genesis.at_generation(g).expect("a generation");
            let envelope = [0xC0 | g as u8; 40];
            memo_row(&genesis, &state, &envelope);
            if g <= 3 {
                expected
                    .push(state.root(), release_evidence_addr(&envelope))
                    .expect("the next generation");
            }
        }
        let win = established_release_at(&genesis, 3)
            .expect("read")
            .expect("generation 3 is on the chain");
        assert_eq!(win.envelope_bytes, vec![0xC3; 40]);
        assert_eq!(Some(win.parent), expected.head_at(2));
        assert_eq!(Some(win.child), expected.head_at(3));
        assert_eq!(
            established_release_at(&genesis, 5).expect("read"),
            None,
            "a release memoised past a gap is not established"
        );
        assert_eq!(established_release_at(&genesis, 4).expect("read"), None);
    }
}
