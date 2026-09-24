// SPDX-License-Identifier: MIT OR Apache-2.0

//! Route chains over the members of a committed storage set (storage spec
//! §9, §14).
//!
//! A writer puts a value at a cell's seats in route order, leader first, and
//! carries the chain built so far to each later seat. A verifier reads every
//! seat's entries, each seat's committed state as the other members' mirrors
//! hold it, and each later seat's own mirror of the leader, and hands that
//! evidence to Core (`dsm::route_chain::evaluate`).
//!
//! Nothing here evaluates a chain, counts links, or decides which value holds
//! a cell. That is Core's, over the evidence these calls gather.

use dsm::route_chain::{
    CellEvidence, ChainSlot, CommittedAt, Route, RouteEntry, RoutedCell, SeatEvidence,
};
use dsm::sofi::registration::PositionCells;
use dsm::storage_cell::{ArrivalRecord, ByteCommit, CellCommitProof};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::{MemberClient, SetClient};
use crate::sdk::storage_set::StorageSet;

/// One value for one cell: `(namespace, key, bytes)`.
pub type CellPut = (Vec<u8>, [u8; 32], Vec<u8>);

/// The storage operations route chains use, addressed by the member ids a
/// committed set names.
pub trait RouteSeats: Send + Sync {
    /// Every member of the set, by member id.
    fn members(&self) -> Vec<Vec<u8>>;

    /// Put entries at `member` in one local transaction there, all of them
    /// or none (storage spec §6). `Ok` carries one arrival record per entry,
    /// in order, each naming `member` and its entry's cell.
    fn put_entries(
        &self,
        member: &[u8],
        entries: &[CellPut],
    ) -> impl core::future::Future<Output = Result<Vec<ArrivalRecord>, String>> + Send;

    /// Everything `member` holds at the cell, in arrival order. `None` when
    /// the member did not answer; an empty list is an answer.
    fn read_values(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> impl core::future::Future<Output = Option<Vec<Vec<u8>>>> + Send;

    /// Ask `member` to close a ByteCommit cycle over what arrived since its
    /// last one, and return the cycle of its latest ByteCommit. Only the
    /// cycle number is taken from the member; the ByteCommit a verifier uses
    /// comes from a mirror (§14). `None` when it has none or did not answer.
    fn close(&self, member: &[u8]) -> impl core::future::Future<Output = Option<u64>> + Send;

    /// Ask `member` to fetch its set-mates' new ByteCommits into its mirror.
    fn sync_mirror(&self, member: &[u8]) -> impl core::future::Future<Output = ()> + Send;

    /// Every distinct ByteCommit `mirror` holds for `member` at `cycle`.
    /// `None` when `mirror` did not answer.
    fn mirrored(
        &self,
        mirror: &[u8],
        member: &[u8],
        cycle: u64,
    ) -> impl core::future::Future<Output = Option<Vec<ByteCommit>>> + Send;

    /// `member`'s proof that its ByteCommit at `cycle` commits the cell's
    /// latest entry as of that cycle.
    fn proof(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
        cycle: u64,
    ) -> impl core::future::Future<Output = Option<CellCommitProof>> + Send;
}

/// What one cell's write produced at each route position, in route order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReport {
    pub slots: Vec<ChainSlot>,
}

impl WriteReport {
    /// Whether the leader answered with a link. Only the leader's copy can
    /// hold the cell; whether this value holds it is Core's reading of the
    /// cell afterwards, never this report.
    pub fn reached_leader(&self) -> bool {
        matches!(self.slots.first(), Some(ChainSlot::Link(..)))
    }

    /// Whether every position of `route` is recorded — as a link or an empty
    /// — with fewer links than finality needs. Every position of such a chain
    /// is closed (§9 rule 5), so it can never become final; a new chain of
    /// the same value, from its leader link, can.
    fn closed_short(&self, route: &Route) -> bool {
        self.slots.len() >= route.seats().len()
            && self
                .slots
                .iter()
                .filter(|slot| matches!(slot, ChainSlot::Link(..)))
                .count()
                < dsm::route_chain::FINAL_LINKS
    }
}

/// Records a write's progress after the leader and after every later seat,
/// so a write that stops part-way continues from where it stopped.
type Recorder<'r, const N: usize> =
    dyn FnMut(&[WriteReport; N]) -> Result<(), DsmError> + Send + 'r;

/// What the leader holds for one value, read from its arrival log.
enum LeaderHolds {
    /// The record of the value's first copy: its leader link.
    Record(ArrivalRecord),
    /// The leader answered and holds no copy of the value.
    Nothing,
    /// The leader did not answer.
    Unread,
}

async fn leader_holds<S: RouteSeats>(seats: &S, cell: &RoutedCell, value: &[u8]) -> LeaderHolds {
    match seats
        .read_values(cell.route().leader(), cell.namespace(), cell.key())
        .await
    {
        Some(log) => match dsm::route_chain::leader_copy_record(cell, value, &log) {
            Some(record) => LeaderHolds::Record(record),
            None => LeaderHolds::Nothing,
        },
        None => LeaderHolds::Unread,
    }
}

/// The report of a write the leader did not answer: nothing went further.
fn leader_unanswered<const N: usize>() -> [WriteReport; N] {
    [(); N].map(|()| WriteReport {
        slots: vec![ChainSlot::NoResponse],
    })
}

fn entry_at_leader(cell: &RoutedCell, value: &[u8]) -> RouteEntry {
    RouteEntry::at_leader(
        cell.namespace().to_vec(),
        *cell.key(),
        value.to_vec(),
        cell.route(),
    )
}

/// Write `N` values that share `route`, the leader first (§9 route chains,
/// rule 1). Position 0 is always the leader and everything waits for it: the
/// leader's record for each value is the first link, and every later copy
/// carries it. So the leader's log is read first, and a value the leader
/// already holds keeps the record of its FIRST copy — writing it again would
/// add a copy whose record no chain begins with. Only the values it does not
/// hold are put there, together in one transaction, each record returned to
/// the value it names. When the leader does not answer, the write stops: a
/// later copy would have no leader record to carry.
async fn from_leader<S: RouteSeats, const N: usize>(
    seats: &S,
    route: &Route,
    cells: [(&RoutedCell, &[u8]); N],
    record: &mut Recorder<'_, N>,
) -> Result<[WriteReport; N], DsmError> {
    let mut links: [Option<ArrivalRecord>; N] = [(); N].map(|()| None);
    for (link, (cell, value)) in links.iter_mut().zip(&cells) {
        match leader_holds(seats, cell, value).await {
            LeaderHolds::Record(found) => *link = Some(found),
            LeaderHolds::Nothing => {}
            LeaderHolds::Unread => {
                log::warn!("route write: the leader did not answer; the write waits for it");
                return Ok(leader_unanswered());
            }
        }
    }
    let missing: Vec<usize> = (0..N).filter(|&i| links[i].is_none()).collect();
    if !missing.is_empty() {
        let batch: Vec<CellPut> = missing
            .iter()
            .map(|&i| {
                let (cell, value) = cells[i];
                let entry = entry_at_leader(cell, value);
                (entry.namespace.clone(), entry.key, entry.encode())
            })
            .collect();
        match seats.put_entries(route.leader(), &batch).await {
            Ok(records) => {
                for (&i, put) in missing.iter().zip(records) {
                    links[i] = Some(put);
                }
            }
            Err(e) => {
                log::warn!("route write: the leader did not answer: {e}; the write waits for it");
                return Ok(leader_unanswered());
            }
        }
    }
    let mut entries = cells.map(|(cell, value)| entry_at_leader(cell, value));
    let mut reports = [(); N].map(|()| WriteReport { slots: Vec::new() });
    for ((entry, report), link) in entries.iter_mut().zip(&mut reports).zip(links) {
        let Some(leader_record) = link else {
            log::warn!("route write: the leader returned no record for a value");
            return Ok(leader_unanswered());
        };
        report.slots.push(ChainSlot::Link(leader_record.clone()));
        if let Some(next) = entry.next(ChainSlot::Link(leader_record), route) {
            *entry = next;
        }
    }
    record(&reports)?;
    write_along(seats, route, entries, reports, record).await
}

/// Carry `N` entries that share `route` from the position they are at to the
/// end of the route. At each seat every entry's copy goes in one
/// transaction, carrying that entry's chain so far — the leader's record
/// first — and the link the seat returns goes into the next copy at once,
/// without waiting for a ByteCommit. A seat after the leader that does not
/// answer is recorded as no response and the write goes on (§9 rule 5); once
/// a later position is recorded, that seat is closed for this chain.
async fn write_along<S: RouteSeats, const N: usize>(
    seats: &S,
    route: &Route,
    mut entries: [RouteEntry; N],
    mut reports: [WriteReport; N],
    record: &mut Recorder<'_, N>,
) -> Result<[WriteReport; N], DsmError> {
    let Some(start) = entries.first().map(|entry| entry.position) else {
        return Ok(reports);
    };
    for (position, seat) in route.seats().iter().enumerate().skip(start) {
        let batch: Vec<CellPut> = entries
            .iter()
            .map(|e| (e.namespace.clone(), e.key, e.encode()))
            .collect();
        let slots: Vec<ChainSlot> = match seats.put_entries(seat, &batch).await {
            Ok(records) => records.into_iter().map(ChainSlot::Link).collect(),
            Err(e) => {
                log::warn!("route write: the seat at position {position} did not answer: {e}");
                vec![ChainSlot::NoResponse; N]
            }
        };
        for ((entry, report), slot) in entries.iter_mut().zip(&mut reports).zip(slots) {
            report.slots.push(slot.clone());
            if let Some(next) = entry.next(slot, route) {
                *entry = next;
            }
        }
        record(&reports)?;
    }
    Ok(reports)
}

/// Continue a write that holds its leader link from the position after the
/// last one it reached (§9 route chains, rule 8: any party may continue a
/// chain along the REMAINING route). The chain moves strictly in route order:
/// a position already recorded, as a link or as no response, is closed for
/// this chain and is never written again. A write without its leader link is
/// returned as it is: only the flow that made it can take it to the leader.
async fn continue_write<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    value: &[u8],
    report: WriteReport,
    record: &mut Recorder<'_, 1>,
) -> Result<WriteReport, DsmError> {
    let route = cell.route();
    let position = report.slots.len();
    let Some(seat) = route.seat(position) else {
        return Ok(report);
    };
    if !report.reached_leader() {
        return Ok(report);
    }
    let entry = RouteEntry {
        namespace: cell.namespace().to_vec(),
        key: *cell.key(),
        value: value.to_vec(),
        seat: seat.to_vec(),
        position,
        chain: report.slots.clone(),
    };
    let [continued] = write_along(seats, route, [entry], [report], record).await?;
    Ok(continued)
}

fn recorded(
    cell: &RoutedCell,
    value: &[u8],
) -> Result<Option<crate::storage::client_db::route_writes::RecordedWrite>, DsmError> {
    let found =
        crate::storage::client_db::route_writes::get_write(cell.namespace(), cell.key(), value)
            .map_err(|e| {
                DsmError::storage(format!("route write record: {e}"), None::<std::io::Error>)
            })?;
    match found {
        Some(write)
            if write.seed != *cell.seed() || write.storage_set_id != *cell.committed_set_id() =>
        {
            Err(DsmError::storage(
                "a recorded write at this cell names another route".to_string(),
                None::<std::io::Error>,
            ))
        }
        Some(write) => Ok(Some(write)),
        None => Ok(None),
    }
}

/// The value a Core reading of `evidence` names by `id`: the exact bytes a
/// seat's copy carries, whose entry digest is `id`. A seat's log holds the
/// cell's route entries; the value is the one an entry carries, never the
/// entry's own bytes.
pub(crate) fn value_of(evidence: &CellEvidence, id: &[u8; 32]) -> Option<Vec<u8>> {
    carried_values(evidence).find(|value| dsm::storage_cell::entry_digest(value) == *id)
}

/// Every value the cell's copies carry, seat by seat in route order and in
/// each seat's arrival order: the bytes a recognizer is shown. What does not
/// decode as a route entry carries nothing.
pub(crate) fn carried_values(evidence: &CellEvidence) -> impl Iterator<Item = Vec<u8>> + '_ {
    evidence
        .seats
        .iter()
        .filter_map(|seat| seat.values.as_ref())
        .flatten()
        .filter_map(|bytes| dsm::route_chain::RouteEntry::decode(bytes))
        .map(|entry| entry.value)
}

/// Keep the completion proof of the value final at `cell` (storage spec §9
/// rule 11), keyed by the cell and the value it proves.
pub(crate) fn keep_completion(
    cell: &RoutedCell,
    proof: &dsm::route_chain::CompletionProof,
) -> Result<(), DsmError> {
    let storage = |what: &str, e: &dyn core::fmt::Display| {
        DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
    };
    let digest = dsm::route_chain::completion_digest(cell, proof)
        .map_err(|e| storage("completion digest", &format!("{e:?}")))?;
    crate::storage::client_db::completion_proofs::keep(cell.namespace(), cell.key(), &digest, proof)
        .map_err(|e| storage("keep completion proof", &e))
}

fn record(cell: &RoutedCell, value: &[u8], report: &WriteReport) -> Result<(), DsmError> {
    crate::storage::client_db::route_writes::record_write(
        cell.namespace(),
        cell.key(),
        value,
        cell.seed(),
        cell.committed_set_id(),
        &report.slots,
    )
    .map_err(|e| DsmError::storage(format!("route write record: {e}"), None::<std::io::Error>))
}

/// Write `value` at `cell` over the members of `set`, recording its progress
/// after every seat. A recorded write that has its leader link continues
/// from the position after the last one it reached. A write with no leader
/// link yet, or whose recorded chain closed every position short of three
/// links, starts at the leader: the leader's record of the value's first
/// copy begins a new chain, and one chain of the value with three links is
/// final (§9: any party can complete it).
pub async fn write_recorded(
    set: &StorageSet,
    cell: &RoutedCell,
    value: &[u8],
) -> Result<WriteReport, DsmError> {
    let seats = NodeSeats::new(set)?;
    let mut recorder = |reports: &[WriteReport; 1]| {
        let [report] = reports;
        record(cell, value, report)
    };
    if let Some(write) = recorded(cell, value)? {
        let report = WriteReport { slots: write.slots };
        if report.reached_leader() && !report.closed_short(cell.route()) {
            return continue_write(&seats, cell, value, report, &mut recorder).await;
        }
        log::info!(
            "route write: the recorded chain ({} slot) cannot finish; a new chain from the \
             leader",
            report.slots.len()
        );
    }
    let [report] = from_leader(&seats, cell.route(), [(cell, value)], &mut recorder).await?;
    Ok(report)
}

/// Write a trader's position pair, `F` at `K_ful(q)` and `C_q` at
/// `K_root(q)`, each along its own chain on the one route both share (SoFi
/// §17.4). At the leader both go in one transaction; a recorded pair that
/// has both leader links and open positions continues, each cell from the
/// position after the last one it reached; otherwise both start at the
/// leader, as new chains from the leader's records.
pub async fn write_recorded_position(
    set: &StorageSet,
    cells: &PositionCells,
    fulfillment: &[u8],
    claim: &[u8],
) -> Result<[WriteReport; 2], DsmError> {
    let seats = NodeSeats::new(set)?;
    let (ful_cell, root_cell) = (cells.fulfillment(), cells.root().routed());
    let ful = recorded(ful_cell, fulfillment)?;
    let root = recorded(root_cell, claim)?;
    let continuable = |slots: &[ChainSlot]| {
        let report = WriteReport {
            slots: slots.to_vec(),
        };
        report.reached_leader() && !report.closed_short(ful_cell.route())
    };
    match (ful, root) {
        (Some(ful), Some(root)) if continuable(&ful.slots) && continuable(&root.slots) => {
            let mut ful_recorder = |reports: &[WriteReport; 1]| {
                let [report] = reports;
                record(ful_cell, fulfillment, report)
            };
            let mut root_recorder = |reports: &[WriteReport; 1]| {
                let [report] = reports;
                record(root_cell, claim, report)
            };
            Ok([
                continue_write(
                    &seats,
                    ful_cell,
                    fulfillment,
                    WriteReport { slots: ful.slots },
                    &mut ful_recorder,
                )
                .await?,
                continue_write(
                    &seats,
                    root_cell,
                    claim,
                    WriteReport { slots: root.slots },
                    &mut root_recorder,
                )
                .await?,
            ])
        }
        (ful, root) => {
            log::debug!(
                "position write: recorded fulfillment {}, recorded claim {}; starting at the leader",
                ful.is_some(),
                root.is_some()
            );
            let mut recorder = |reports: &[WriteReport; 2]| {
                let [ful_report, root_report] = reports;
                record(ful_cell, fulfillment, ful_report)?;
                record(root_cell, claim, root_report)
            };
            from_leader(
                &seats,
                ful_cell.route(),
                [(ful_cell, fulfillment), (root_cell, claim)],
                &mut recorder,
            )
            .await
        }
    }
}

/// Continue every recorded write that has its leader link and has not
/// reached the end of its route, from the position after the last one it
/// reached, over the set the write names. Returns how many writes now reach
/// the end of their route. Writes without their leader link, and chains that
/// closed short, are left to the flows that made them: only a flow reads the
/// cell back through Core, and so knows whether its value holds the leader.
pub async fn continue_recorded_writes(
    catalog: &crate::sdk::storage_set::StorageSetCatalog,
) -> Result<u32, DsmError> {
    let open =
        crate::storage::client_db::route_writes::open_writes(dsm::route_chain::ROUTE_LEN, 64)
            .map_err(|e| {
                DsmError::storage(format!("route write record: {e}"), None::<std::io::Error>)
            })?;
    let mut completed = 0u32;
    for write in open {
        let report = WriteReport { slots: write.slots };
        if !report.reached_leader() {
            continue;
        }
        let Some(set) = catalog.resolve(&write.storage_set_id) else {
            log::warn!("route continue: the set a recorded write names is not in the catalog");
            continue;
        };
        let members = crate::sdk::storage_set::as_ccb_members(set)?;
        let cell = RoutedCell::new(
            &write.namespace,
            write.cell_key,
            &write.seed,
            &members,
            &write.storage_set_id,
        )
        .map_err(|e| DsmError::storage(format!("route continue: {e:?}"), None::<std::io::Error>))?;
        let seats = NodeSeats::new(set)?;
        let value = write.value;
        let mut recorder = |reports: &[WriteReport; 1]| {
            let [report] = reports;
            record(&cell, &value, report)
        };
        let report = continue_write(&seats, &cell, &value, report, &mut recorder).await?;
        if report.slots.len() == cell.route().seats().len() {
            completed += 1;
        }
    }
    Ok(completed)
}

/// The one ByteCommit of `member` at `cycle` that the given mirrors hold.
/// Every mirror keeps each distinct ByteCommit it fetched for a member and
/// cycle (§14 mirror sync), so a mirror holding two, or two mirrors holding
/// different ones, show the member equivocating; none is used then.
///
/// One mirror holding it is enough, by the spec, not by default: nodes crash
/// and omit but never alter what they hold (§3), a member's mirror is held to
/// that same model (§14 mirror provenance, rule 3), and a ByteCommit "is not
/// accepted by counting how many mirrors hold it" (§14 rule 3). What makes it
/// evidence is its chain link and its root, which Core checks
/// ([`CommittedAt::chain_link_holds`], `record_is_committed`).
fn agreed(member: &[u8], cycle: u64, held: &[Vec<ByteCommit>]) -> Option<ByteCommit> {
    let mut found: Option<&ByteCommit> = None;
    for commit in held.iter().flatten() {
        if commit.member_id != member || commit.cycle_index != cycle {
            return None;
        }
        if let Some(seen) = found {
            if seen != commit {
                return None;
            }
        } else {
            found = Some(commit);
        }
    }
    found.cloned()
}

/// `member`'s ByteCommit at `cycle` as the mirrors at `mirrors` hold it,
/// with `member`'s proof for the cell against it.
async fn committed_at<S: RouteSeats>(
    seats: &S,
    mirrors: &[Vec<u8>],
    member: &[u8],
    cycle: u64,
    namespace: &[u8],
    key: &[u8; 32],
) -> Option<CommittedAt> {
    let mut held = Vec::with_capacity(mirrors.len());
    for mirror in mirrors {
        if let Some(commits) = seats.mirrored(mirror, member, cycle).await {
            held.push(commits);
        }
    }
    let commit = agreed(member, cycle, &held)?;
    // The member's previous ByteCommit, from the same mirrors, for the
    // chain link (§14 rule 3). Cycle 1 has none: its parent is zero.
    let parent = match cycle.checked_sub(1).filter(|previous| *previous >= 1) {
        None => None,
        Some(previous) => {
            let mut held = Vec::with_capacity(mirrors.len());
            for mirror in mirrors {
                if let Some(commits) = seats.mirrored(mirror, member, previous).await {
                    held.push(commits);
                }
            }
            Some(agreed(member, previous, &held)?)
        }
    };
    let proof = seats.proof(member, namespace, key, cycle).await?;
    Some(CommittedAt {
        commit,
        parent,
        proof,
    })
}

/// Everything a verifier gathers about a cell for Core to evaluate.
///
/// Every seat is read. Each seat that holds anything is asked to close a
/// cycle; then every member of the set syncs its mirror once. A seat's
/// committed state is its ByteCommit at its latest cycle as every other
/// member's mirror holds it, with the seat's proof against that root. A later
/// seat's view of the leader is the leader's ByteCommit at the leader's
/// latest cycle as that seat's own mirror holds it, with the leader's proof
/// (§9 route chains, rule 4).
pub async fn read_cell<S: RouteSeats>(seats: &S, cell: &RoutedCell) -> CellEvidence {
    let (route, namespace, key) = (cell.route(), cell.namespace(), cell.key());
    let mut values = Vec::with_capacity(route.seats().len());
    for seat in route.seats() {
        values.push(seats.read_values(seat, namespace, key).await);
    }
    let mut cycles = Vec::with_capacity(values.len());
    for (seat, held) in route.seats().iter().zip(&values) {
        let holds_any = held.as_ref().is_some_and(|v| !v.is_empty());
        cycles.push(if holds_any {
            seats.close(seat).await
        } else {
            None
        });
    }
    let members = seats.members();
    if cycles.iter().any(Option::is_some) {
        for member in &members {
            seats.sync_mirror(member).await;
        }
    }
    let leader = route.leader();
    let leader_cycle = cycles.first().copied().flatten();
    let mut evidence = Vec::with_capacity(values.len());
    for (position, (seat, (held, cycle))) in route
        .seats()
        .iter()
        .zip(values.into_iter().zip(cycles))
        .enumerate()
    {
        let others: Vec<Vec<u8>> = members
            .iter()
            .filter(|m| m.as_slice() != seat.as_slice())
            .cloned()
            .collect();
        let committed = match cycle {
            Some(t) => committed_at(seats, &others, seat, t, namespace, key).await,
            None => None,
        };
        let leader_view = (position > 0 && cycle.is_some())
            .then_some(leader_cycle)
            .flatten();
        let leader_seen = match leader_view {
            Some(t) => {
                committed_at(
                    seats,
                    core::slice::from_ref(seat),
                    leader,
                    t,
                    namespace,
                    key,
                )
                .await
            }
            None => None,
        };
        evidence.push(SeatEvidence {
            values: held,
            committed,
            leader_seen,
        });
    }
    CellEvidence { seats: evidence }
}

/// The members of a committed set, reached at the endpoints the set names.
pub struct NodeSeats {
    set: SetClient,
}

impl NodeSeats {
    pub fn new(set: &StorageSet) -> Result<Self, DsmError> {
        Ok(Self {
            set: SetClient::new(set)?,
        })
    }

    fn member(&self, member: &[u8]) -> Result<&MemberClient, String> {
        self.set.member(member).ok_or_else(|| {
            format!(
                "{} is not a member of the set",
                String::from_utf8_lossy(member)
            )
        })
    }
}

impl RouteSeats for NodeSeats {
    fn members(&self) -> Vec<Vec<u8>> {
        self.set
            .members()
            .iter()
            .map(|m| m.member_id().as_bytes().to_vec())
            .collect()
    }

    async fn put_entries(
        &self,
        member: &[u8],
        entries: &[CellPut],
    ) -> Result<Vec<ArrivalRecord>, String> {
        self.member(member)?.put_cells(entries).await
    }

    async fn read_values(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> Option<Vec<Vec<u8>>> {
        self.member(member).ok()?.get_cell(namespace, key).await
    }

    async fn close(&self, member: &[u8]) -> Option<u64> {
        self.member(member).ok()?.close_cycle().await
    }

    async fn sync_mirror(&self, member: &[u8]) {
        let outcome = match self.member(member) {
            Ok(client) => client.sync_mirror().await,
            Err(e) => Err(e),
        };
        if let Err(e) = outcome {
            log::warn!("mirror sync at {}: {e}", String::from_utf8_lossy(member));
        }
    }

    async fn mirrored(&self, mirror: &[u8], member: &[u8], cycle: u64) -> Option<Vec<ByteCommit>> {
        self.member(mirror).ok()?.mirrored(member, cycle).await
    }

    async fn proof(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
        cycle: u64,
    ) -> Option<CellCommitProof> {
        self.member(member).ok()?.proof(namespace, key, cycle).await
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    fn commit(member: &[u8], cycle: u64, root: u8) -> ByteCommit {
        ByteCommit {
            member_id: member.to_vec(),
            cycle_index: cycle,
            smt_root: [root; 32],
            bytes_used: 1,
            parent_digest: [7u8; 32],
        }
    }

    #[test]
    fn mirrors_that_agree_give_the_byte_commit() {
        let m = b"dsm-node-1";
        let held = [vec![commit(m, 3, 1)], vec![commit(m, 3, 1)], Vec::new()];
        assert_eq!(agreed(m, 3, &held), Some(commit(m, 3, 1)));
    }

    #[test]
    fn two_mirrors_holding_different_byte_commits_give_none() {
        let m = b"dsm-node-1";
        let held = [vec![commit(m, 3, 1)], vec![commit(m, 3, 2)]];
        assert_eq!(agreed(m, 3, &held), None);
    }

    #[test]
    fn one_mirror_holding_two_byte_commits_gives_none() {
        let m = b"dsm-node-1";
        let held = [vec![commit(m, 3, 1), commit(m, 3, 2)]];
        assert_eq!(agreed(m, 3, &held), None);
    }

    #[test]
    fn a_byte_commit_of_another_member_or_cycle_gives_none() {
        let m = b"dsm-node-1";
        assert_eq!(agreed(m, 3, &[vec![commit(b"dsm-node-2", 3, 1)]]), None);
        assert_eq!(agreed(m, 3, &[vec![commit(m, 4, 1)]]), None);
    }

    /// A value the leader already holds keeps its first copy: writing it again
    /// beside a value the leader lacks puts only the new one there, and the
    /// held value's leader record is the one it already had. On the storage
    /// node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_value_the_leader_already_holds_is_not_written_there_again() {
        let _fleet = crate::test_support::one_device::Fleet::start();
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let members = crate::sdk::storage_set::as_ccb_members(&set).expect("members");
        let seed = [0x5A; 32];
        let cell = |key: u8| {
            RoutedCell::new(
                b"DSM/test/leader-copy",
                [key; 32],
                &seed,
                &members,
                &set.id(),
            )
            .expect("a routed cell")
        };
        let (a, b) = (cell(0x01), cell(0x02));
        assert_eq!(a.route(), b.route(), "one seed, one route");
        let seats = NodeSeats::new(&set).expect("seats");
        let leader = a.route().leader().to_vec();

        let mut quiet_one = |_: &[WriteReport; 1]| Ok(());
        let [first] = from_leader(&seats, a.route(), [(&a, b"A".as_slice())], &mut quiet_one)
            .await
            .expect("write A");
        let mut quiet_two = |_: &[WriteReport; 2]| Ok(());
        let [again, fresh] = from_leader(
            &seats,
            a.route(),
            [(&a, b"A".as_slice()), (&b, b"B".as_slice())],
            &mut quiet_two,
        )
        .await
        .expect("write A and B");

        let at_leader = |cell: &RoutedCell| {
            let seats = &seats;
            let leader = leader.clone();
            let (namespace, key) = (cell.namespace().to_vec(), *cell.key());
            async move {
                seats
                    .read_values(&leader, &namespace, &key)
                    .await
                    .expect("the leader answers")
            }
        };
        assert_eq!(at_leader(&a).await.len(), 1, "A has one copy at the leader");
        assert_eq!(at_leader(&b).await.len(), 1, "B has one copy at the leader");
        assert_eq!(
            again.slots.first(),
            first.slots.first(),
            "A's leader link is the record of its first copy"
        );
        assert!(matches!(fresh.slots.first(), Some(ChainSlot::Link(_))));
    }

    #[test]
    fn nothing_mirrored_gives_none() {
        let m = b"dsm-node-1";
        assert_eq!(agreed(m, 3, &[Vec::new(), Vec::new()]), None);
        assert_eq!(agreed(m, 3, &[]), None);
    }
}
