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

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use dsm::economic::native_reserve::{
    release_evidence_addr, reserve_cell_key, reserve_cell_namespace, reserve_seed,
    resolve_successor, successor_completion, walk_lineage, NativeReserveState, ReserveLineage,
    SuccessorCell, SuccessorRead, WalkStop,
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
    let (mut lineage, _) = established_lineage(set, &genesis, None)?;
    let start = *lineage.head();
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
    // The reads of each cell the walk read final, kept until the release
    // there is memoised with them.
    let finals: RefCell<HashMap<[u8; 32], CellEvidence>> = RefCell::new(HashMap::new());
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
                            finals.borrow_mut().insert(*cell.routed().key(), evidence);
                            return Ok(read);
                        }
                    }
                    let seats = NodeSeats::new(set)?;
                    let evidence = read_successor_cell(&seats, &cell).await;
                    let read = resolve_successor(&cell, &evidence);
                    // A final release means the walk is behind the head: the
                    // cells after it are located and read together.
                    if let SuccessorRead::Final { child, .. } = &read {
                        finals.borrow_mut().insert(*cell.routed().key(), evidence);
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
            let cell = successor_cell(set, parent.state())?;
            let reads = finals
                .borrow_mut()
                .remove(cell.routed().key())
                .ok_or_else(|| {
                    storage_err(
                        "reserve walk",
                        format!(
                            "no reads are held of the cell final at generation {}",
                            child.state().generation()
                        ),
                    )
                })?;
            // The release is memoised with the reads that showed it final,
            // its completion proof kept, and taken into the lineage by Core
            // from them, like every kept release.
            let proof = memoise_final(&cell, &reads, release, child.state())?;
            lineage
                .establish_final(&cell, &reads, &proof)
                .map_err(|e| storage_err("reserve lineage", e))?;
            Ok::<(), DsmError>(())
        },
    )?;
    if lineage.head().head().generation() > from.generation() {
        keep_checkpoint(&genesis, &lineage)?;
    }
    // A checkpoint whose end the walk did not reproduce is discarded before
    // anything is owed (SoFi Amendment S23, step 4).
    let settled = candidates.settle_checkpoints(lineage.chain());
    log::info!(
        "[reserve] checkpoints after the walk: {} borne out, {} discarded",
        settled.borne_out,
        settled.discarded
    );
    owe_after_walk(set, from.generation(), &lineage, &candidates)?;
    Ok(stop)
}

/// Memoise `release`, final at `cell` by `reads`, with those reads, and keep
/// its completion proof: what [`established_lineage`] proves final again on
/// load. The proof is built from the reads, and must prove `release`.
fn memoise_final(
    cell: &SuccessorCell,
    reads: &CellEvidence,
    release: &dsm::economic::native_reserve::VerifiedRelease,
    child: &NativeReserveState,
) -> Result<dsm::route_chain::CompletionProof, DsmError> {
    let (proven, _, proof) = successor_completion(cell, reads)
        .map_err(|missing| storage_err("reserve completion", format!("{missing:?}")))?
        .ok_or_else(|| storage_err("reserve completion", "the reads show no release final"))?;
    if proven.envelope_bytes != release.envelope_bytes {
        return Err(storage_err(
            "reserve completion",
            "the reads show another release final than the one memoised",
        ));
    }
    keep_completion(cell.routed(), &proof)?;
    memo::record_final_release(cell.parent(), release, child, &reads.encode_kept())
        .map_err(|e| storage_err("reserve memo write", e))?;
    Ok(proof)
}

/// The lineage this device's walks established, and the envelope of the
/// release at generation `keep`, when the lineage reaches it and a row is
/// kept for it.
///
/// It starts from this device's sealed checkpoint when Core resumes it
/// (SA-75): every root and digest is recomputed from the steps, and the seal
/// is this device's own. A checkpoint that does not resume, or none, starts
/// the lineage at the genesis. After the start, each memoised release is
/// proven final again from the reads kept with it and its kept completion
/// proof, and checked as the successor of the head before it
/// (`ReserveLineage::establish_final`), before its generation is taken: a
/// row Core does not establish is corrupt storage, and an error, never a
/// generation. A memoised release past the first generation the memo skips
/// is not one this device's walks established, and is not in the lineage.
/// A release at or below the start is the one whose step the sealed
/// lineage holds there, or an error. When the lineage reaches past its
/// start, the checkpoint is kept again at its head.
fn established_lineage(
    set: &StorageSet,
    genesis: &NativeReserveState,
    keep: Option<u64>,
) -> Result<(ReserveLineage, Option<Vec<u8>>), DsmError> {
    let members = crate::sdk::storage_set::as_ccb_members(set)?;
    let mut lineage = match resumed(genesis)? {
        Start::Checkpoint(lineage) => *lineage,
        Start::Genesis(why) => {
            log::info!("[reserve] the lineage is established from its genesis: {why}");
            ReserveLineage::from_genesis(genesis).map_err(|e| storage_err("reserve genesis", e))?
        }
    };
    let start = *lineage.head().state();
    let mut kept = match keep {
        Some(generation) if (1..=start.generation()).contains(&generation) => {
            sealed_release(genesis, &lineage, generation)?
        }
        _ => None,
    };
    // One memoised release at a time: it is established and let go before
    // the next is read (SA-75), except the one asked to be kept.
    memo::fold_memoised_lineage(genesis, &start, |conn, state, envelope, cell_reads| {
        let generation = state.generation();
        if generation != lineage.head().head().generation() + 1 {
            return Ok(std::ops::ControlFlow::Break(()));
        }
        let refused = |why: String| {
            anyhow::anyhow!("native_reserve_lineage_memo: generation {generation}: {why}")
        };
        let cell = SuccessorCell::of(lineage.head().state(), &members)
            .map_err(|e| refused(format!("its cell: {e:?}")))?;
        let reads = CellEvidence::decode_kept(cell.routed(), cell_reads, &cell.keeps())
            .map_err(|e| refused(format!("the reads kept with the release: {e:?}")))?;
        let proof = crate::storage::client_db::completion_proofs::get_with_conn(
            conn,
            cell.routed(),
            envelope,
        )
        .map_err(|e| refused(format!("its completion proof: {e}")))?
        .ok_or_else(|| refused("no completion proof is kept for the release".to_string()))?;
        lineage
            .establish_final(&cell, &reads, &proof.proof)
            .map_err(|e| anyhow::anyhow!("native_reserve_lineage_memo: {e}"))?;
        if keep == Some(generation) {
            kept = Some(envelope.to_vec());
        }
        Ok(std::ops::ControlFlow::Continue(()))
    })
    .map_err(|e| storage_err("reserve memo", e))?;
    if lineage.head().head().generation() > start.generation() {
        keep_checkpoint(genesis, &lineage)?;
    }
    Ok((lineage, kept))
}

/// Where a load of the reserve lineage starts (SA-75).
enum Start {
    /// This device's checkpoint, resumed by Core.
    Checkpoint(Box<ReserveLineage>),
    /// The genesis, and why not a checkpoint: none is kept, or Core refused
    /// the one kept. Every release is then established from the memo again.
    Genesis(String),
}

/// The start of a load: the checkpoint kept for the reserve, when Core
/// resumes it under this device's key. Fails closed while the wallet is
/// locked, since no seal can be checked.
fn resumed(genesis: &NativeReserveState) -> Result<Start, DsmError> {
    let Some(checkpoint) = memo::get_checkpoint(genesis.reserve_id())
        .map_err(|e| storage_err("reserve checkpoint", e))?
    else {
        return Ok(Start::Genesis("no checkpoint is kept".into()));
    };
    let key = checkpoint_key()?;
    Ok(match ReserveLineage::resume(genesis, &checkpoint, &key) {
        Ok(lineage) => Start::Checkpoint(Box::new(lineage)),
        Err(refused) => Start::Genesis(format!(
            "the checkpoint at generation {} is refused: {refused}",
            checkpoint.generation()
        )),
    })
}

/// The key this device seals its reserve checkpoints under (SA-75), derived
/// under its at-rest key: a checkpoint written into the store by anything
/// that does not hold the wallet seed does not resume. Fails closed while
/// the wallet is locked.
pub(crate) fn checkpoint_key() -> Result<[u8; 32], DsmError> {
    let at_rest = crate::init::current_chain_head_at_rest_key()?;
    let mut h =
        dsm::crypto::blake3::Hasher::new_derive_key("DSM/native-reserve-checkpoint-key/v1\0");
    h.update(&at_rest);
    Ok(*h.finalize().as_bytes())
}

/// Keep `lineage`'s checkpoint, sealed under this device's key, and let go
/// of the memoised releases it covers that are not this device's own
/// (SA-75). Fails closed while the wallet is locked.
fn keep_checkpoint(genesis: &NativeReserveState, lineage: &ReserveLineage) -> Result<(), DsmError> {
    let key = checkpoint_key()?;
    let checkpoint = lineage.checkpoint(&key);
    memo::put_checkpoint(genesis.reserve_id(), &checkpoint)
        .map_err(|e| storage_err("reserve checkpoint write", e))?;
    let (own_genesis, own_devid) = own_identity()?;
    let let_go = memo::let_go_through(
        genesis.reserve_id(),
        checkpoint.generation(),
        &own_genesis,
        &own_devid,
    )
    .map_err(|e| storage_err("reserve memo", e))?;
    log::info!(
        "[reserve] checkpoint kept at generation {}; {let_go} memoised releases it covers let go",
        checkpoint.generation()
    );
    Ok(())
}

/// This device's genesis and device id, as the store keeps them.
fn own_identity() -> Result<([u8; 32], [u8; 32]), DsmError> {
    let field = |value: Option<Vec<u8>>, what: &str| match value {
        Some(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| {
            DsmError::invalid_operation(format!("this device's {what} is not 32 bytes: {e}"))
        }),
        None => Err(DsmError::invalid_operation(format!(
            "this device's {what} is not set"
        ))),
    };
    Ok((
        field(
            crate::sdk::app_state::AppState::get_genesis_hash(),
            "genesis",
        )?,
        field(
            crate::sdk::app_state::AppState::get_device_id(),
            "device id",
        )?,
    ))
}

/// The envelope memoised at `generation`, at or below the start of
/// `lineage`, when a row is kept for it: the release whose step the sealed
/// lineage holds there. A row holding another release is corrupt storage,
/// and an error.
fn sealed_release(
    genesis: &NativeReserveState,
    lineage: &ReserveLineage,
    generation: u64,
) -> Result<Option<Vec<u8>>, DsmError> {
    let step = lineage.steps().get(&generation).ok_or_else(|| {
        storage_err(
            "reserve checkpoint",
            format!("the resumed lineage holds no step for generation {generation}"),
        )
    })?;
    let Some(envelope) = memo::memoised_envelope(genesis.reserve_id(), generation)
        .map_err(|e| storage_err("reserve memo", e))?
    else {
        return Ok(None);
    };
    if release_evidence_addr(&envelope) != *step {
        return Err(storage_err(
            "reserve memo",
            format!(
                "generation {generation} holds another release than the one this device's \
                 walks established"
            ),
        ));
    }
    Ok(Some(envelope))
}

/// The release this device's walks established at `generation`, with the
/// established heads before and after it; `None` while the chain does not
/// reach it. Reads only what was memoised: nothing is walked here.
pub(crate) fn established_release_at(
    set: &StorageSet,
    genesis: &NativeReserveState,
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let Some(before) = generation.checked_sub(1) else {
        return Err(DsmError::invalid_operation(
            "generation 0 is the reserve's genesis state, never a release",
        ));
    };
    let (lineage, kept) = established_lineage(set, genesis, Some(generation))?;
    let chain = lineage.chain();
    let (Some(parent), Some(child), Some(envelope_bytes)) =
        (chain.head_at(before), chain.head_at(generation), kept)
    else {
        return Ok(None);
    };
    // The parent state names the release that installed it, or the genesis
    // step at generation 0 (SA-63).
    let parent_step = match before {
        0 => *genesis.predecessor(),
        _ => *lineage.steps().get(&before).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "the established lineage holds no step for generation {before}"
            ))
        })?,
    };
    Ok(Some(ReserveReleaseWin {
        envelope_bytes,
        parent,
        parent_step,
        child,
    }))
}

/// Owe the epoch index the hint of every generation `lineage` established
/// from `from` whose own hint it did not find, and a checkpoint for every
/// complete segment whose own checkpoint it did not find; then start the
/// sweep that publishes what is owed. Never on the claim's path: what is
/// owed and never reaches the set costs a later reader speed and nothing
/// else.
fn owe_after_walk(
    set: &StorageSet,
    from: u64,
    lineage: &ReserveLineage,
    candidates: &Candidates,
) -> Result<usize, DsmError> {
    let (chain, steps) = (lineage.chain(), lineage.steps());
    let set_id = set.id();
    let mut owed = lineage_discovery::owe_missing_hints(&set_id, chain, steps, candidates, from)?;
    let head = chain.head().generation();
    let mut start = from - from % EPOCH_GENERATIONS;
    while start + EPOCH_GENERATIONS <= head {
        let bundle = segment_bundle(chain, steps, start)?;
        owed += lineage_discovery::owe_checkpoint(&set_id, chain, &bundle, start, candidates)?;
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
/// walks established when they already passed it, else by walking. A
/// generation the lineage has already passed is read back from its cell with
/// no walk, since a walk adds nothing behind the head: every check of a
/// peer's ancestry that reaches a faucet claim asks for one (DSM Amendment
/// A31). `None` while the lineage has not reached that generation with a
/// final release.
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
    if let Some(win) = established_release_at(set, &genesis, generation)? {
        return Ok(Some(win));
    }
    let (lineage, _) = established_lineage(set, &genesis, None)?;
    if lineage.head().head().generation() < generation {
        walk_reserve(set, network_id, runtime)?;
        if let Some(win) = established_release_at(set, &genesis, generation)? {
            return Ok(Some(win));
        }
    }
    read_back_release(set, &genesis, runtime, generation)
}

/// A release this device's walks established whose memo row its checkpoint
/// let go (SA-75), read back from its cell: Core resolves the cell from
/// fresh reads, and the release final there must be the one whose step the
/// lineage holds at `generation`. `None` when the lineage does not reach
/// `generation`. A cell not final when read back is an error, never a
/// verdict.
fn read_back_release(
    set: &StorageSet,
    genesis: &NativeReserveState,
    runtime: &tokio::runtime::Handle,
    generation: u64,
) -> Result<Option<ReserveReleaseWin>, DsmError> {
    let Some(before) = generation.checked_sub(1) else {
        return Err(DsmError::invalid_operation(
            "generation 0 is the reserve's genesis state, never a release",
        ));
    };
    let (lineage, _) = established_lineage(set, genesis, None)?;
    let chain = lineage.chain();
    let (Some(parent), Some(child), Some(step)) = (
        chain.head_at(before),
        chain.head_at(generation),
        lineage.steps().get(&generation),
    ) else {
        return Ok(None);
    };
    let parent_step = match before {
        0 => *genesis.predecessor(),
        _ => *lineage.steps().get(&before).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "the established lineage holds no step for generation {before}"
            ))
        })?,
    };
    let parent_state = genesis
        .at_generation(before, parent_step)
        .map_err(|e| storage_err("reserve read-back", e))?;
    let read =
        tokio::task::block_in_place(|| runtime.block_on(read_successor(set, &parent_state)))?;
    match read {
        SuccessorRead::Final { release, .. } => {
            if release_evidence_addr(&release.envelope_bytes) != *step {
                return Err(storage_err(
                    "reserve read-back",
                    format!(
                        "the release final at generation {generation} is not the one this \
                         device's walks established"
                    ),
                ));
            }
            Ok(Some(ReserveReleaseWin {
                envelope_bytes: release.envelope_bytes,
                parent,
                parent_step,
                child,
            }))
        }
        not_final => Err(storage_err(
            "reserve read-back",
            format!("generation {generation}'s cell is not final when read back: {not_final:?}"),
        )),
    }
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

/// Memoise this device's release at `parent`'s successor cell with the
/// reads that show it final, and keep its completion proof (storage spec §9
/// rule 11). The answer is whether `envelope` is the release final there,
/// now memoised with its reads: it is not while the cell is not final, or
/// while another release holds it.
pub async fn memoise_release_completion(
    set: &StorageSet,
    parent: &NativeReserveState,
    envelope: &[u8],
) -> Result<bool, DsmError> {
    let cell = successor_cell(set, parent)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_successor_cell(&seats, &cell).await;
    let Some((release, child, _)) = successor_completion(&cell, &evidence)
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
    memoise_final(&cell, &evidence, &release, &child)?;
    Ok(true)
}
