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
    CellEvidence, ChainSlot, CommittedAt, HeldLog, Route, RouteEntry, RoutedCell, SeatEvidence,
};
use dsm::sofi::registration::PositionCells;
use dsm::storage_cell::{ArrivalRecord, ByteCommit, CellCommitProof};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::{CellFold, MemberClient, SetClient};
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

    /// Read what `member` holds at the cell from arrival index `from`, and
    /// hand each value to `take` in arrival order as it is read. The arrival
    /// index of the last value the member holds as far as it was read
    /// (`from - 1` when none); `None` when the member did not answer every
    /// page, or `take` stopped the read.
    fn fold_values(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
        from: u64,
        take: &mut CellFold<'_>,
    ) -> impl core::future::Future<Output = Option<u64>> + Send;

    /// Ask `member` to close a ByteCommit cycle over what arrived since its
    /// last one, and return the cycle of its latest ByteCommit. Only the
    /// cycle number is taken from the member; the ByteCommit a verifier uses
    /// comes from a mirror (§14). `None` when it has none or did not answer.
    fn close(&self, member: &[u8]) -> impl core::future::Future<Output = Option<u64>> + Send;

    /// The cycle of `member`'s latest ByteCommit as it states it, closing
    /// none. Only the cycle number is taken from the member, as with
    /// [`Self::close`]. `None` when it has none or did not answer.
    fn latest_cycle(&self, member: &[u8])
        -> impl core::future::Future<Output = Option<u64>> + Send;

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

/// What a write got at its cell's leader, position 0 of the route (storage
/// spec §9). Whether the value holds the cell is Core's reading of the cell
/// afterwards, never this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtLeader {
    /// The leader holds the value and no other value was first there: the
    /// record of the value's first copy is its leader link, and the write
    /// carries it to the later seats.
    Link,
    /// Another value is first at the leader, shown by the record the leader
    /// gave that value's copy. The cell is decided for that value: the write
    /// stopped at the leader and put nothing of its own there.
    Taken,
    /// Nothing of this write is at the leader: the leader did not answer, or,
    /// for a position pair, the other cell was taken and the two go there
    /// both or neither ([`pair_at_leader`]). The write waits for the leader.
    Unanswered,
}

/// What one cell's write produced at each route position, in route order.
/// Empty when nothing was written: a position pair whose other cell was
/// taken at the leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReport {
    pub slots: Vec<ChainSlot>,
}

impl WriteReport {
    /// What the write got at the leader. Only the leader's copy can hold the
    /// cell, and a taken leader decides it for another value (§9 route
    /// chains, rules 3 and 5).
    pub fn leader(&self) -> AtLeader {
        match self.slots.first() {
            Some(ChainSlot::Link(..)) => AtLeader::Link,
            Some(ChainSlot::Taken(..)) => AtLeader::Taken,
            Some(ChainSlot::NoResponse) | None => AtLeader::Unanswered,
        }
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

/// What a position pair's write got at the leader of `s(q)` (SoFi §17.4):
/// taken when either cell is first at the leader for another value, so the
/// position went to that value and the pair goes no further; a link when the
/// leader holds both; unanswered otherwise.
pub fn pair_at_leader(reports: &[WriteReport; 2]) -> AtLeader {
    let at = reports.each_ref().map(WriteReport::leader);
    if at.contains(&AtLeader::Taken) {
        AtLeader::Taken
    } else if at.iter().all(|leader| *leader == AtLeader::Link) {
        AtLeader::Link
    } else {
        AtLeader::Unanswered
    }
}

/// A cell's rule for what can count there: the copies the reader of that
/// cell kind keeps ([`dsm::route_chain::recognized_copies`]). The writer
/// reads which of them is first at the leader by Core's own rule
/// ([`dsm::route_chain::first_recognized_at_leader`]).
pub type Recognized<'r> = &'r (dyn Fn(&RouteEntry) -> bool + Sync);

/// Records a write's progress after the leader and after every later seat,
/// so a write that stops part-way continues from where it stopped.
type Recorder<'r, const N: usize> =
    dyn FnMut(&[WriteReport; N]) -> Result<(), DsmError> + Send + 'r;

/// What the leader's arrival log shows for one value.
enum LeaderLog {
    /// The slot the value's write gets at the leader: its leader link, or a
    /// taken empty carrying the record of the value first there instead.
    Decided(ChainSlot),
    /// The leader answered, and holds neither the value nor any other value
    /// first.
    Open,
    /// The leader did not answer.
    Unread,
}

/// Read what the leader holds for `value` at `cell`, keeping the cell's
/// recognized copies and the value's own. Another value first there, by
/// Core's rule ([`dsm::route_chain::first_recognized_at_leader`]), is a
/// taken empty carrying its record (§9 route chains, rule 5). The value
/// itself first, or its own copy where no recognized value is first, gets
/// the record of its first copy, its leader link (§9, the leader first,
/// rule 2): writing it there again would add a copy no chain begins with.
async fn read_leader<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    recognized: Recognized<'_>,
    value: &[u8],
) -> LeaderLog {
    let copy = dsm::route_chain::leader_copy(cell, value);
    let own = dsm::route_chain::copies_of(&copy);
    let keep = |entry: &RouteEntry| recognized(entry) || own(entry);
    let log = HeldLog::new(cell.namespace(), cell.key());
    let Some(log) = fold_seat(seats, cell.route().leader(), log, &keep, None).await else {
        return LeaderLog::Unread;
    };
    match dsm::route_chain::first_recognized_at_leader(cell, &log, recognized) {
        Some((first, record)) if first == value => LeaderLog::Decided(ChainSlot::Link(record)),
        Some((_, record)) => LeaderLog::Decided(ChainSlot::Taken(record)),
        None => match dsm::route_chain::leader_copy_record(cell, value, &log) {
            Some(record) => LeaderLog::Decided(ChainSlot::Link(record)),
            None => LeaderLog::Open,
        },
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

/// One value for one cell, with the cell's rule for what can count there.
type LeaderWrite<'w> = (&'w RoutedCell, Recognized<'w>, &'w [u8]);

/// Read what the leader holds for each of `cells`, asked at once and taken
/// in the cells' order. `None` when the leader did not answer for one.
async fn read_leaders<S: RouteSeats>(
    seats: &S,
    cells: &[LeaderWrite<'_>],
) -> Option<Vec<Option<ChainSlot>>> {
    // The leader's log of each cell is its own read, and none waits on
    // another.
    let held = futures::future::join_all(
        cells
            .iter()
            .map(|&(cell, recognized, value)| read_leader(seats, cell, recognized, value)),
    )
    .await;
    held.into_iter()
        .map(|held| match held {
            LeaderLog::Decided(slot) => Some(Some(slot)),
            LeaderLog::Open => Some(None),
            LeaderLog::Unread => None,
        })
        .collect()
}

/// Write `N` values that share `route`, the leader first (§9 route chains,
/// rule 1). Position 0 is always the leader and everything waits for it: the
/// leader's record for each value is the first link, and every later copy
/// carries it. So the leader's log is read first, by each cell's rule for
/// what can count there:
///
/// - another value first at a cell's leader decides that cell for it. The
///   write records a taken empty with that value's record and stops (§9
///   rule 5), and the values written together go to the leader both or
///   neither (SoFi §17.4), so nothing is put;
/// - a value the leader already holds keeps the record of its FIRST copy —
///   writing it again would add a copy whose record no chain begins with;
/// - the values it does not hold are put there together, in one
///   transaction, and each is decided again from the leader's log, not from
///   the record the put returned: another value may have got there first
///   between the read and the put.
///
/// When the leader does not answer, the write stops: a later copy would have
/// no leader record to carry.
async fn from_leader<S: RouteSeats, const N: usize>(
    seats: &S,
    route: &Route,
    cells: [LeaderWrite<'_>; N],
    record: &mut Recorder<'_, N>,
) -> Result<[WriteReport; N], DsmError> {
    let Some(mut slots) = read_leaders(seats, &cells).await else {
        log::warn!("route write: the leader did not answer; the write waits for it");
        return Ok(leader_unanswered());
    };
    let missing: Vec<usize> = (0..N).filter(|&i| slots[i].is_none()).collect();
    let taken = slots
        .iter()
        .any(|slot| matches!(slot, Some(ChainSlot::Taken(..))));
    if !taken && !missing.is_empty() {
        let put: Vec<LeaderWrite<'_>> = missing.iter().map(|&i| cells[i]).collect();
        let batch: Vec<CellPut> = put
            .iter()
            .map(|&(cell, _, value)| {
                let entry = entry_at_leader(cell, value);
                (entry.namespace.clone(), entry.key, entry.encode())
            })
            .collect();
        let returned = match seats.put_entries(route.leader(), &batch).await {
            Ok(records) => records,
            Err(e) => {
                log::warn!("route write: the leader did not answer: {e}; the write waits for it");
                return Ok(leader_unanswered());
            }
        };
        log::info!("route write: the leader took {} values", returned.len());
        let Some(after) = read_leaders(seats, &put).await else {
            log::warn!(
                "route write: the leader's log was not read after the put; the write waits for it"
            );
            return Ok(leader_unanswered());
        };
        for (n, (&i, decided)) in missing.iter().zip(after).enumerate() {
            let Some(decided) = decided else {
                log::warn!("route write: the leader's log does not hold the value it took");
                return Ok(leader_unanswered());
            };
            if let ChainSlot::Link(link) = &decided {
                if returned.get(n) != Some(link) {
                    log::warn!(
                        "route write: the leader returned a record its log does not give; the \
                         log's record is the leader link"
                    );
                }
            }
            slots[i] = Some(decided);
        }
    }
    let mut entries = cells.map(|(cell, _, value)| entry_at_leader(cell, value));
    let mut reports = [(); N].map(|()| WriteReport { slots: Vec::new() });
    for ((entry, report), slot) in entries.iter_mut().zip(&mut reports).zip(slots) {
        let Some(slot) = slot else {
            continue;
        };
        report.slots.push(slot.clone());
        if let Some(next) = entry.next(slot, route) {
            *entry = next;
        }
    }
    // A cell decided for another value stops the write, and is not recorded:
    // nothing continues it, and a value written beside it goes no further.
    if reports
        .iter()
        .any(|report| report.leader() != AtLeader::Link)
    {
        log::info!("route write: another value is first at the leader; the write stops there");
        return Ok(reports);
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
///
/// No seat after the leader is ever recorded taken. A taken empty there would
/// show another value's valid chain at that seat, and a valid chain begins
/// with the cell's leader link, which one value at most holds (§9 finality
/// 2). A write gets here only with its leader link: its value was first
/// recognized at the leader, so no other value's chain is valid anywhere on
/// the route; or its value is nothing the cell recognizes, and no slot of its
/// chain is ever read. And a later seat holding another value's copies never
/// keeps this value's copy from being a link there (§9 rule 4 asks no seat
/// but the leader which value came first).
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
            Ok(records) => {
                log::info!("route write: the seat at position {position} took the chain");
                borne_out(seats, seat, &batch, records).await
            }
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

/// The slots a seat's answer to `batch` earns: each record it returned that
/// its own arrival log bears out, as a link; any other as an empty. A record
/// is carried into every later copy, and Core counts a later link only when
/// every link its copy carries is valid, so one seat returning a record its
/// log does not give made every later link of the chain invalid, and the
/// value never final (SA-98). An empty proves nothing and invalidates
/// nothing (§9 rule 5).
async fn borne_out<S: RouteSeats>(
    seats: &S,
    seat: &[u8],
    batch: &[CellPut],
    records: Vec<ArrivalRecord>,
) -> Vec<ChainSlot> {
    // Each copy is the writer's own encoding of an entry, which decodes to
    // it; the seat's log is read keeping that copy and nothing else.
    let copies: Vec<Option<RouteEntry>> = batch
        .iter()
        .map(|(_, _, copy)| RouteEntry::decode(copy))
        .collect();
    let logs = futures::future::join_all(batch.iter().zip(&copies).map(
        |((namespace, key, _), copy)| async move {
            let copy = copy.as_ref()?;
            let keep = dsm::route_chain::copies_of(copy);
            fold_seat(seats, seat, HeldLog::new(namespace, key), &keep, None).await
        },
    ))
    .await;
    batch
        .iter()
        .zip(copies.iter().zip(logs))
        .zip(
            records
                .into_iter()
                .map(Some)
                .chain(std::iter::repeat_with(|| None)),
        )
        .map(|((_, (copy, log)), record)| {
            let given = copy
                .as_ref()
                .zip(log)
                .and_then(|(copy, log)| dsm::route_chain::copy_record(seat, copy, &log));
            match (record, given) {
                (Some(record), Some(given)) if record == given => ChainSlot::Link(record),
                (record, given) => {
                    log::warn!(
                        "route write: the seat's record is not the one its log gives \
                         (returned {}, borne out {}); recorded empty",
                        record.is_some(),
                        given.is_some()
                    );
                    ChainSlot::NoResponse
                }
            }
        })
        .collect()
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
    if report.leader() != AtLeader::Link {
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

/// Keep the completion proof of the value final at `cell` (storage spec §9
/// rule 11), keyed by the cell and the value it proves. A proof already kept
/// for the value stands: later reads may build another proof of it, and the
/// kept one is never replaced.
pub(crate) fn keep_completion(
    cell: &RoutedCell,
    proof: &dsm::route_chain::CompletionProof,
) -> Result<(), DsmError> {
    let storage = |what: &str, e: &dyn core::fmt::Display| {
        DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
    };
    if crate::storage::client_db::completion_proofs::get(cell, &proof.value)
        .map_err(|e| storage("kept completion proof", &e))?
        .is_some()
    {
        return Ok(());
    }
    let digest = dsm::route_chain::completion_digest(cell, proof)
        .map_err(|e| storage("completion digest", &format!("{e:?}")))?;
    crate::storage::client_db::completion_proofs::keep(cell, &digest, proof)
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
/// final (§9: any party can complete it). At the leader, `recognized` — the
/// cell's rule for what can count there — decides whether another value is
/// first, and the write is then taken there ([`AtLeader::Taken`]).
pub async fn write_recorded(
    set: &StorageSet,
    cell: &RoutedCell,
    recognized: Recognized<'_>,
    value: &[u8],
) -> Result<WriteReport, DsmError> {
    let seats = NodeSeats::new(set)?;
    let mut recorder = |reports: &[WriteReport; 1]| {
        let [report] = reports;
        record(cell, value, report)
    };
    if let Some(write) = recorded(cell, value)? {
        let report = WriteReport { slots: write.slots };
        if report.leader() == AtLeader::Link && !report.closed_short(cell.route()) {
            return continue_write(&seats, cell, value, report, &mut recorder).await;
        }
        log::info!(
            "route write: the recorded chain ({} slot) cannot finish; a new chain from the \
             leader",
            report.slots.len()
        );
    }
    let [report] = from_leader(
        &seats,
        cell.route(),
        [(cell, recognized, value)],
        &mut recorder,
    )
    .await?;
    Ok(report)
}

/// Write a trader's position pair, `F` at `K_ful(q)` and `C_q` at
/// `K_root(q)`, each along its own chain on the one route both share (SoFi
/// §17.4). At the leader both go in one transaction, both or neither, each
/// cell read by its own rule for what can count there; a recorded pair that
/// has both leader links and open positions continues, each cell from the
/// position after the last one it reached; otherwise both start at the
/// leader, as new chains from the leader's records. Another value first at
/// either cell's leader takes the position ([`pair_at_leader`]).
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
        report.leader() == AtLeader::Link && !report.closed_short(ful_cell.route())
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
            // Two cells, each continued seat by seat along its own chain;
            // neither chain carries anything of the other, so they move at
            // once, and both run to their end before either's error is
            // returned.
            let (ful, root) = futures::future::join(
                continue_write(
                    &seats,
                    ful_cell,
                    fulfillment,
                    WriteReport { slots: ful.slots },
                    &mut ful_recorder,
                ),
                continue_write(
                    &seats,
                    root_cell,
                    claim,
                    WriteReport { slots: root.slots },
                    &mut root_recorder,
                ),
            )
            .await;
            Ok([ful?, root?])
        }
        (ful, root) => {
            log::info!(
                "position write: recorded fulfillment {}, recorded claim {}; starting at the leader",
                ful.is_some(),
                root.is_some()
            );
            let mut recorder = |reports: &[WriteReport; 2]| {
                let [ful_report, root_report] = reports;
                record(ful_cell, fulfillment, ful_report)?;
                record(root_cell, claim, root_report)
            };
            let (ful_rule, root_rule) = (cells.keeps_fulfillment(), cells.root().keeps());
            from_leader(
                &seats,
                ful_cell.route(),
                [
                    (ful_cell, &ful_rule, fulfillment),
                    (root_cell, &root_rule, claim),
                ],
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
        if report.leader() != AtLeader::Link {
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

/// `member`'s ByteCommit at `cycle` as every mirror at `mirrors` that
/// answers holds it, asked all at once.
async fn agreed_at<S: RouteSeats>(
    seats: &S,
    mirrors: &[Vec<u8>],
    member: &[u8],
    cycle: u64,
) -> Option<ByteCommit> {
    let held: Vec<Vec<ByteCommit>> = futures::future::join_all(
        mirrors
            .iter()
            .map(|mirror| seats.mirrored(mirror, member, cycle)),
    )
    .await
    .into_iter()
    .flatten()
    .collect();
    agreed(member, cycle, &held)
}

/// `member`'s ByteCommit at `cycle` as the mirrors at `mirrors` hold it,
/// with `member`'s proof for the cell against it. The ByteCommit, its parent
/// and the proof are asked for at once: each is a round trip to a node, and
/// none depends on another's answer.
async fn committed_at<S: RouteSeats>(
    seats: &S,
    mirrors: &[Vec<u8>],
    member: &[u8],
    cycle: u64,
    namespace: &[u8],
    key: &[u8; 32],
) -> Option<CommittedAt> {
    // The member's previous ByteCommit, from the same mirrors, for the
    // chain link (§14 rule 3). Cycle 1 has none: its parent is zero.
    let previous = cycle.checked_sub(1).filter(|previous| *previous >= 1);
    let (commit, parent, proof) = futures::future::join3(
        agreed_at(seats, mirrors, member, cycle),
        async {
            match previous {
                None => Some(None),
                Some(previous) => agreed_at(seats, mirrors, member, previous).await.map(Some),
            }
        },
        seats.proof(member, namespace, key, cycle),
    )
    .await;
    Some(CommittedAt {
        commit: commit?,
        parent: parent?,
        proof: proof?,
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
/// [`read_cell`] for a cell whose final value, once there, holds it for good
/// (storage spec §9, finality 2): the reads this process kept when Core
/// evaluated them as final at the cell, or else the seats' reads, kept when
/// `is_final` — Core's evaluation of them at this cell — says they show a
/// final value. An open or undecided cell is read from the seats every time.
pub(crate) async fn read_cell_kept<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    is_final: impl FnOnce(&CellEvidence) -> bool,
) -> CellEvidence {
    read_cell_kept_in(seats, cell, keep, None, is_final).await
}

/// [`read_cell_kept`], as one of reads made together within `window`.
pub(crate) async fn read_cell_kept_within<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    window: &ReadWindow,
    is_final: impl FnOnce(&CellEvidence) -> bool,
) -> CellEvidence {
    read_cell_kept_in(seats, cell, keep, Some(window), is_final).await
}

async fn read_cell_kept_in<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    window: Option<&ReadWindow>,
    is_final: impl FnOnce(&CellEvidence) -> bool,
) -> CellEvidence {
    if let Some(kept) = crate::sdk::final_reads::final_cell(cell) {
        return kept;
    }
    let evidence = read_cell_in(seats, cell, keep, window).await;
    if is_final(&evidence) {
        crate::sdk::final_reads::keep_final_cell(cell, &evidence);
    }
    evidence
}

/// Whether Core reads a final claim at the root cell `cell` from `evidence`.
pub(crate) fn root_claim_final(
    cell: &dsm::economic::register::RootCell,
    evidence: &CellEvidence,
) -> bool {
    matches!(
        dsm::economic::register::read_root_cell(cell, evidence),
        Ok(dsm::route_chain::CellReading::Held {
            state: dsm::route_chain::ChainState::Final,
            ..
        })
    )
}

/// What this device holds of one seat's log at a cell at most: the copies a
/// reader keeps of it ([`HeldLog::kept_bytes`]). Bytes that are no kept
/// copy never count toward it. A resource limit, not a protocol rule: a
/// read past it is that seat not read, never a verdict.
const HELD_LOG_BUDGET: usize = 8 * 1024 * 1024;

/// What reads made together may keep between them: a read-ahead window
/// (SA-76). Each seat's fold takes from it what its kept copies add, and a
/// seat whose copies would take it past its total is not read, as a seat
/// past [`HELD_LOG_BUDGET`] is not: a resource limit, never a verdict. A
/// cell left unread here is read again by the walk that reaches it.
pub(crate) struct ReadWindow {
    left: std::sync::atomic::AtomicUsize,
    refused: std::sync::atomic::AtomicUsize,
}

impl ReadWindow {
    pub(crate) fn new(bytes: usize) -> Self {
        Self {
            left: std::sync::atomic::AtomicUsize::new(bytes),
            refused: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Take `bytes` from what is left, or nothing, when fewer are left, and
    /// say how many were.
    fn take(&self, bytes: usize) -> Result<(), usize> {
        use std::sync::atomic::Ordering::SeqCst;
        self.left
            .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(bytes))
            .map(drop)
            .inspect_err(|_| {
                self.refused.fetch_add(1, SeqCst);
            })
    }

    /// Give back what a log that was dropped took.
    fn give_back(&self, bytes: usize) {
        self.left
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether a seat was left unread for want of the window: a further read
    /// within it would read for nothing.
    pub(crate) fn spent(&self) -> bool {
        self.refused.load(std::sync::atomic::Ordering::SeqCst) > 0
    }
}

/// Fold `seat`'s log into `log` from the entry after the last one it holds,
/// keeping what `keep` keeps. `None` when the seat did not answer every
/// page, or what was kept passed [`HELD_LOG_BUDGET`] or what is left of
/// `window`: the log is then not a read of the seat.
async fn fold_seat<S: RouteSeats>(
    seats: &S,
    seat: &[u8],
    mut log: HeldLog,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    window: Option<&ReadWindow>,
) -> Option<HeldLog> {
    let (namespace, key) = (log.namespace().to_vec(), *log.key());
    let from = log.count().saturating_add(1);
    // What the log already holds was taken from `window` by the fold before
    // this one; what this fold keeps is taken as it is kept.
    let mut taken = log.kept_bytes();
    let held = {
        let mut take = |value: Vec<u8>| {
            let before = log.kept_bytes();
            log.fold(&value, keep);
            if log.kept_bytes() > HELD_LOG_BUDGET {
                return Err(format!(
                    "the seat's copies of the cell hold {} bytes, past this device's \
                     {HELD_LOG_BUDGET}-byte budget for one seat's log",
                    log.kept_bytes()
                ));
            }
            if let Some(window) = window {
                let added = log.kept_bytes().saturating_sub(before);
                window.take(added).map_err(|left| {
                    format!(
                        "the seat's copies of the cell pass the {left} bytes left of the \
                         reads made with it"
                    )
                })?;
                taken = taken.saturating_add(added);
            }
            Ok(())
        };
        seats
            .fold_values(seat, &namespace, &key, from, &mut take)
            .await
    };
    match held {
        Some(held) if held == log.count() => Some(log),
        Some(..) | None => {
            // The log is not a read of the seat and is dropped: what it took
            // from the window is free again.
            if let Some(window) = window {
                window.give_back(taken);
            }
            None
        }
    }
}

/// The distinct values `member` holds at `(namespace, key)` that `keep`
/// keeps, in the order they first arrived: a read of a key that is no
/// routed cell, every member's entries a candidate list for Core to check.
/// What is not kept costs the read and nothing it holds. `None` when the
/// member did not answer every page, or what was kept passed
/// [`HELD_LOG_BUDGET`].
pub(crate) async fn kept_values<S: RouteSeats>(
    seats: &S,
    member: &[u8],
    namespace: &[u8],
    key: &[u8; 32],
    keep: &(dyn Fn(&[u8]) -> bool + Sync),
) -> Option<Vec<Vec<u8>>> {
    let mut kept: Vec<Vec<u8>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut bytes = 0usize;
    {
        let mut take = |value: Vec<u8>| {
            if keep(&value) && seen.insert(dsm::storage_cell::entry_digest(&value)) {
                bytes = bytes.saturating_add(value.len());
                if bytes > HELD_LOG_BUDGET {
                    return Err(format!(
                        "the values kept hold {bytes} bytes, past this device's \
                         {HELD_LOG_BUDGET}-byte budget for one member's read"
                    ));
                }
                kept.push(value);
            }
            Ok(())
        };
        seats
            .fold_values(member, namespace, key, 1, &mut take)
            .await
    }?;
    Some(kept)
}

/// What a verifier reads at a cell for Core to evaluate: every seat's log,
/// folded keeping what `keep` keeps — Core's rule for what can count there
/// ([`dsm::route_chain::recognized_copies`]) — with each seat's committed
/// state.
pub async fn read_cell<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
) -> CellEvidence {
    read_cell_in(seats, cell, keep, None).await
}

/// [`read_cell`], as one of reads made together within `window`.
pub(crate) async fn read_cell_within<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    window: &ReadWindow,
) -> CellEvidence {
    read_cell_in(seats, cell, keep, Some(window)).await
}

async fn read_cell_in<S: RouteSeats>(
    seats: &S,
    cell: &RoutedCell,
    keep: &(dyn Fn(&RouteEntry) -> bool + Sync),
    window: Option<&ReadWindow>,
) -> CellEvidence {
    let (route, namespace, key) = (cell.route(), cell.namespace(), cell.key());
    // Each phase logs where it ends; the log's own timestamps time it. The
    // cell is named by its key's first five bytes (eight characters).
    let short = crate::util::text_id::encode_base32_crockford(&key[..5]);
    // Every seat is asked at once, and the answers stay in route order: a
    // seat that does not answer costs one timeout, not one per seat. The
    // cycle each seat last closed is asked for in the same round.
    let (logs, latest): (Vec<Option<HeldLog>>, Vec<Option<u64>>) = futures::future::join(
        futures::future::join_all(
            route
                .seats()
                .iter()
                .map(|seat| fold_seat(seats, seat, HeldLog::new(namespace, key), keep, window)),
        ),
        futures::future::join_all(route.seats().iter().map(|seat| seats.latest_cycle(seat))),
    )
    .await;
    log::info!(
        "route read {short}: values from {} of {} seats",
        logs.iter().filter(|v| v.is_some()).count(),
        logs.len()
    );
    let members = seats.members();
    let holds = |log: &Option<HeldLog>| log.as_ref().is_some_and(|log| log.count() > 0);

    // A settled cell: every seat that holds anything already closed a cycle
    // committing everything it holds there. Closing another cycle would
    // commit the same entries at the same running hashes, so the committed
    // state at the cycles already closed is the read.
    let held_cycles: Vec<Option<u64>> = logs
        .iter()
        .zip(&latest)
        .map(|(log, cycle)| if holds(log) { *cycle } else { None })
        .collect();
    let every_holder_closed = logs
        .iter()
        .zip(&held_cycles)
        .all(|(log, cycle)| !holds(log) || cycle.is_some());
    if every_holder_closed {
        let committed = committed_state(seats, route, &members, &held_cycles, namespace, key).await;
        let evidence = seat_evidence(logs.clone(), committed);
        if commits_everything_held(&evidence) {
            log::info!(
                "route read {short}: settled, committed state from {} seats",
                evidence.iter().filter(|e| e.committed.is_some()).count()
            );
            return CellEvidence { seats: evidence };
        }
    }

    let cycles: Vec<Option<u64>> = futures::future::join_all(route.seats().iter().zip(&logs).map(
        |(seat, log)| async move {
            if holds(log) {
                seats.close(seat).await
            } else {
                None
            }
        },
    ))
    .await;
    log::info!(
        "route read {short}: cycles closed at {} seats",
        cycles.iter().filter(|c| c.is_some()).count()
    );
    if cycles.iter().any(Option::is_some) {
        futures::future::join_all(members.iter().map(|member| seats.sync_mirror(member))).await;
        log::info!(
            "route read {short}: mirrors synced at {} members",
            members.len()
        );
    }
    let committed = committed_state(seats, route, &members, &cycles, namespace, key).await;
    // Each log was read before its seat's cycle closed, and the cycle
    // commits every entry that arrived by then, after the read too. Each log
    // is read on to the entry its seat's committed state names, and the
    // leader's to the entry each later seat's view of it names, keeping the
    // running hash there: checked against what was read before the close, a
    // trickle of writes kept every commitment past the read, and the cell
    // undecided (SA-99).
    let logs = futures::future::join_all(route.seats().iter().zip(logs).enumerate().map(
        |(position, (seat, log))| {
            let committed = &committed;
            async move {
                let mut log = log?;
                let named = committed
                    .get(position)
                    .into_iter()
                    .flat_map(|(own, ..)| own);
                let seen = (position == 0)
                    .then_some(
                        committed
                            .iter()
                            .skip(1)
                            .filter_map(|(.., seen)| seen.as_ref()),
                    )
                    .into_iter()
                    .flatten();
                let wanted: Vec<u64> = named.chain(seen).map(|c| c.proof.index).collect();
                for index in &wanted {
                    log.want(*index);
                }
                if wanted.iter().any(|index| *index > log.count()) {
                    fold_seat(seats, seat, log, keep, window).await
                } else {
                    Some(log)
                }
            }
        },
    ))
    .await;
    let evidence = seat_evidence(logs, committed);
    log::info!(
        "route read {short}: committed state from {} seats",
        evidence.iter().filter(|e| e.committed.is_some()).count()
    );
    CellEvidence { seats: evidence }
}

/// Whether the committed state gathered commits every entry each seat
/// holds: each holding seat's proof is at its last entry, and each later
/// holding seat's view of the leader is at the leader's last entry.
fn commits_everything_held(evidence: &[SeatEvidence]) -> bool {
    let held = |seat: &SeatEvidence| seat.values.as_ref().map_or(0, HeldLog::count);
    let at_last = |committed: &Option<CommittedAt>, count: u64| {
        committed.as_ref().is_some_and(|c| c.proof.index == count)
    };
    let leader_count = evidence.first().map_or(0, held);
    evidence.iter().enumerate().all(|(position, seat)| {
        let count = held(seat);
        count == 0
            || (at_last(&seat.committed, count)
                && (position == 0 || at_last(&seat.leader_seen, leader_count)))
    })
}

/// Each seat's log with its committed state, in route order.
fn seat_evidence(
    logs: Vec<Option<HeldLog>>,
    committed: Vec<(Option<CommittedAt>, Option<CommittedAt>)>,
) -> Vec<SeatEvidence> {
    logs.into_iter()
        .zip(committed)
        .map(|(values, (committed, leader_seen))| SeatEvidence {
            values,
            committed,
            leader_seen,
        })
        .collect()
}

/// Every seat's committed state at the cycle given for it, and each later
/// seat's view of the leader at the leader's cycle, gathered at once, in
/// route order.
async fn committed_state<S: RouteSeats>(
    seats: &S,
    route: &Route,
    members: &[Vec<u8>],
    cycles: &[Option<u64>],
    namespace: &[u8],
    key: &[u8; 32],
) -> Vec<(Option<CommittedAt>, Option<CommittedAt>)> {
    let leader = route.leader();
    let leader_cycle = cycles.first().copied().flatten();
    futures::future::join_all(
        route
            .seats()
            .iter()
            .zip(cycles.iter().copied())
            .enumerate()
            .map(|(position, (seat, cycle))| async move {
                let others: Vec<Vec<u8>> = members
                    .iter()
                    .filter(|m| m.as_slice() != seat.as_slice())
                    .cloned()
                    .collect();
                let leader_view = (position > 0 && cycle.is_some())
                    .then_some(leader_cycle)
                    .flatten();
                futures::future::join(
                    async {
                        match cycle {
                            Some(t) => committed_at(seats, &others, seat, t, namespace, key).await,
                            None => None,
                        }
                    },
                    async {
                        match leader_view {
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
                        }
                    },
                )
                .await
            }),
    )
    .await
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

    async fn fold_values(
        &self,
        member: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
        from: u64,
        take: &mut CellFold<'_>,
    ) -> Option<u64> {
        // A seat outside the set is asked nothing: it gives no answer.
        let client = self.set.member(member)?;
        client.fold_cell(namespace, key, from, take).await
    }

    async fn close(&self, member: &[u8]) -> Option<u64> {
        self.member(member).ok()?.close_cycle().await
    }

    async fn latest_cycle(&self, member: &[u8]) -> Option<u64> {
        use crate::sdk::storage_node_sdk::LatestByteCommit;
        let client = match self.member(member) {
            Ok(client) => client,
            Err(e) => {
                log::warn!("latest cycle: {e}");
                return None;
            }
        };
        match client.latest_bytecommit().await.answer {
            LatestByteCommit::Stated(commit) => Some(commit.cycle_index),
            LatestByteCommit::NoCycle => None,
            LatestByteCommit::Unanswered(why) => {
                log::info!("latest cycle at {}: {why}", String::from_utf8_lossy(member));
                None
            }
        }
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

        let (keeps_a, keeps_b) = (
            dsm::route_chain::recognized_copies(&a, |bytes: &[u8]| bytes == b"A"),
            dsm::route_chain::recognized_copies(&b, |bytes: &[u8]| bytes == b"B"),
        );
        let mut quiet_one = |_: &[WriteReport; 1]| Ok(());
        let [first] = from_leader(
            &seats,
            a.route(),
            [(&a, &keeps_a, b"A".as_slice())],
            &mut quiet_one,
        )
        .await
        .expect("write A");
        let mut quiet_two = |_: &[WriteReport; 2]| Ok(());
        let [again, fresh] = from_leader(
            &seats,
            a.route(),
            [
                (&a, &keeps_a, b"A".as_slice()),
                (&b, &keeps_b, b"B".as_slice()),
            ],
            &mut quiet_two,
        )
        .await
        .expect("write A and B");

        let at_leader = |cell: &RoutedCell| {
            let seats = &seats;
            let leader = leader.clone();
            let (namespace, key) = (cell.namespace().to_vec(), *cell.key());
            async move { values_at(seats, &leader, &namespace, &key).await }
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

    /// SoFi §17.4, MR-SOFI-0092: a trader's two position cells, `K_ful(q)`
    /// and `K_root(q)`, are written together at their leader. They share one
    /// route, and each seat — the leader first — is asked for both in one
    /// put, which the node applies all or none.
    ///
    /// MUTATION CONTROL: writing the pair as two writes, one per cell, turns
    /// this red: the leader is asked twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_positions_two_cells_go_to_each_seat_in_one_put() {
        let (nodes, _config, set, _cell) = pinned(0x92).await;
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let cells = crate::sdk::sofi_register::position_cells(
            &set,
            &[0x91; 32],
            &[0x92; 32],
            7,
            &[0x93; 32],
        )
        .expect("the pair's cells");
        assert_eq!(
            cells.fulfillment().route(),
            cells.root().routed().route(),
            "one route serves both cells"
        );
        for node in &nodes.nodes {
            node.forget_requests();
        }
        let reports = write_recorded_position(&set, &cells, b"F", b"C_q")
            .await
            .expect("the pair is written");
        assert_eq!(pair_at_leader(&reports), AtLeader::Link);
        let puts = |member: &str| {
            let Some(node) = nodes.nodes.iter().find(|n| n.member_id == member) else {
                panic!("no node {member}");
            };
            node.requests()
                .iter()
                .filter(|request| request.as_str() == "POST /api/v2/cells")
                .count()
        };
        for (position, seat) in cells.fulfillment().route().seats().iter().enumerate() {
            assert_eq!(
                puts(&member_id(seat)),
                1,
                "the seat at position {position} is asked once, for both cells"
            );
        }
    }

    /// The network's pinned nodes on Postgres, the SDK pointed at them, the
    /// set they serve, and a test cell routed over it with key `key`.
    async fn pinned(
        key: u8,
    ) -> (
        crate::test_support::nodes::NodeSet,
        crate::economic_fixtures::FleetGuard,
        StorageSet,
        RoutedCell,
    ) {
        let nodes = crate::test_support::nodes::NodeSet::start().await;
        let config = crate::economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let members = crate::sdk::storage_set::as_ccb_members(&set).expect("members");
        let cell = RoutedCell::new(
            b"DSM/test/route-order",
            [key; 32],
            &[0x61; 32],
            &members,
            &set.id(),
        )
        .expect("a routed cell");
        (nodes, config, set, cell)
    }

    fn member_id(seat: &[u8]) -> String {
        String::from_utf8(seat.to_vec()).expect("member ids are UTF-8")
    }

    /// Everything the seat holds at `cell`, in arrival order.
    async fn held(seats: &NodeSeats, seat: &[u8], cell: &RoutedCell) -> Vec<Vec<u8>> {
        values_at(seats, seat, cell.namespace(), cell.key()).await
    }

    /// Every value the seat holds at `(namespace, key)`, in arrival order, as
    /// its pages return them.
    async fn values_at(
        seats: &NodeSeats,
        seat: &[u8],
        namespace: &[u8],
        key: &[u8; 32],
    ) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let held = {
            let mut take = |value: Vec<u8>| {
                values.push(value);
                Ok(())
            };
            seats.fold_values(seat, namespace, key, 1, &mut take).await
        };
        assert_eq!(
            held.expect("the seat answers"),
            values.len() as u64,
            "the read names the index of the last value it handed over"
        );
        values
    }

    /// What a verifier keeps of a seat's log at `cell` when `V` is the only
    /// recognized value.
    fn keeps_v(cell: &RoutedCell) -> impl Fn(&RouteEntry) -> bool + Sync + '_ {
        dsm::route_chain::recognized_copies(cell, |bytes: &[u8]| bytes == b"V")
    }

    /// Storage spec §9, the leader first (MR-STOR-0148): nothing is written
    /// to a later seat until the leader has returned its arrival record for
    /// the value. With the leader down the write stops at the leader, and no
    /// later seat holds anything at the cell. Once the leader is back the
    /// write goes through, and every later copy carries the leader's record
    /// as its first link. On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn nothing_reaches_a_later_seat_before_the_leader_answers() {
        let (mut nodes, _config, set, cell) = pinned(0x31).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let route = cell.route();
        let leader = member_id(route.leader());
        nodes.take_down(std::slice::from_ref(&leader)).await;

        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let [stopped] = from_leader(
            &seats,
            route,
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        assert_eq!(
            stopped.slots,
            vec![ChainSlot::NoResponse],
            "the write stops at the leader"
        );
        for (position, seat) in route.seats().iter().enumerate().skip(1) {
            assert_eq!(
                held(&seats, seat, &cell).await,
                Vec::<Vec<u8>>::new(),
                "the seat at position {position} holds the value before the leader answered"
            );
        }

        nodes.bring_up(&[leader]).await;
        let [written] = from_leader(
            &seats,
            route,
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        let Some(ChainSlot::Link(leader_link)) = written.slots.first() else {
            panic!("the leader answers with a link: {:?}", written.slots);
        };
        assert_eq!(written.slots.len(), route.seats().len());
        for (position, seat) in route.seats().iter().enumerate().skip(1) {
            let copies = held(&seats, seat, &cell).await;
            assert_eq!(copies.len(), 1, "one copy at position {position}");
            let entry = RouteEntry::decode(&copies[0]).expect("a route entry");
            assert_eq!(entry.position, position);
            assert_eq!(
                entry.chain.first(),
                Some(&ChainSlot::Link(leader_link.clone())),
                "the copy at position {position} does not carry the leader's record first"
            );
        }
    }

    /// Whether any seat of `cell` holds a copy of `value`.
    async fn copies_of_anywhere(seats: &NodeSeats, cell: &RoutedCell, value: &[u8]) -> Vec<usize> {
        let mut at = Vec::new();
        for (position, seat) in cell.route().seats().iter().enumerate() {
            let carries = held(seats, seat, cell)
                .await
                .iter()
                .filter_map(|bytes| RouteEntry::decode(bytes))
                .any(|entry| entry.value == value);
            if carries {
                at.push(position);
            }
        }
        at
    }

    /// Storage spec §9 route chains, rule 5 (MR-STOR-0134): where another
    /// value is first at the leader, the writer records a taken empty
    /// carrying the record the leader gave that value's copy, and stops.
    /// Nothing of its own value is put at the leader or carried to a later
    /// seat, and the write is not recorded for anything to continue. Junk
    /// ahead of both blocks nothing. On the storage node's own code, on
    /// Postgres.
    /// MUTATION CONTROL: reading another value first at the leader as an open
    /// cell puts V at the leader and carries it along the route; this turns
    /// red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_value_another_holds_first_at_the_leader_is_recorded_taken() {
        let (_nodes, _config, set, cell) = pinned(0x3A).await;
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let seats = NodeSeats::new(&set).expect("seats");
        let rule = dsm::route_chain::recognized_copies(&cell, |bytes: &[u8]| {
            bytes == b"V" || bytes == b"W"
        });
        seats
            .put_entries(
                cell.route().leader(),
                &[(cell.namespace().to_vec(), *cell.key(), b"junk".to_vec())],
            )
            .await
            .expect("the leader keeps the junk");
        let first = write_recorded(&set, &cell, &rule, b"W")
            .await
            .expect("W is written");
        let Some(ChainSlot::Link(w_link)) = first.slots.first().cloned() else {
            panic!("W is first at the leader: {:?}", first.slots);
        };

        let taken = write_recorded(&set, &cell, &rule, b"V")
            .await
            .expect("V's write is reported");
        assert_eq!(taken.leader(), AtLeader::Taken);
        assert_eq!(
            taken.slots,
            vec![ChainSlot::Taken(w_link)],
            "V's write records the cell taken, with W's leader record"
        );
        assert_eq!(
            copies_of_anywhere(&seats, &cell, b"V").await,
            Vec::<usize>::new(),
            "no seat holds a copy of V"
        );
        assert_eq!(
            crate::storage::client_db::route_writes::get_write(cell.namespace(), cell.key(), b"V")
                .expect("read the record"),
            None,
            "a taken write is not recorded"
        );
    }

    /// A seat set whose leader takes another value's copy just before the
    /// first put it is asked for: that value got to the leader between the
    /// writer's read of the leader and its put.
    struct Racing<'a> {
        seats: &'a NodeSeats,
        leader: Vec<u8>,
        rival: CellPut,
        raced: std::sync::Mutex<Option<ArrivalRecord>>,
    }

    impl RouteSeats for Racing<'_> {
        fn members(&self) -> Vec<Vec<u8>> {
            self.seats.members()
        }

        async fn put_entries(
            &self,
            member: &[u8],
            entries: &[CellPut],
        ) -> Result<Vec<ArrivalRecord>, String> {
            let first_put = member == self.leader.as_slice()
                && self
                    .raced
                    .lock()
                    .map_err(|e| format!("the race record: {e}"))?
                    .is_none();
            if first_put {
                let [record] = <[ArrivalRecord; 1]>::try_from(
                    self.seats
                        .put_entries(member, core::slice::from_ref(&self.rival))
                        .await?,
                )
                .map_err(|records| format!("{} records for one rival copy", records.len()))?;
                *self
                    .raced
                    .lock()
                    .map_err(|e| format!("the race record: {e}"))? = Some(record);
            }
            self.seats.put_entries(member, entries).await
        }

        async fn fold_values(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            from: u64,
            take: &mut CellFold<'_>,
        ) -> Option<u64> {
            self.seats
                .fold_values(member, namespace, key, from, take)
                .await
        }

        async fn close(&self, member: &[u8]) -> Option<u64> {
            self.seats.close(member).await
        }

        async fn latest_cycle(&self, member: &[u8]) -> Option<u64> {
            self.seats.latest_cycle(member).await
        }

        async fn sync_mirror(&self, member: &[u8]) {
            self.seats.sync_mirror(member).await
        }

        async fn mirrored(
            &self,
            mirror: &[u8],
            member: &[u8],
            cycle: u64,
        ) -> Option<Vec<ByteCommit>> {
            self.seats.mirrored(mirror, member, cycle).await
        }

        async fn proof(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            cycle: u64,
        ) -> Option<CellCommitProof> {
            self.seats.proof(member, namespace, key, cycle).await
        }
    }

    /// MR-STOR-0134: the writer decides the leader from the leader's log after
    /// its put, not from the record the put returned. W lands at the leader
    /// between the writer's read, which found the cell open, and its put of
    /// V; the leader returns V's own record, and its log shows W first. The
    /// write is recorded taken with W's record and goes no further than the
    /// leader. On the storage node's own code, on Postgres.
    /// MUTATION CONTROL: taking the record the put returned as V's leader
    /// link records a link and carries V along the route; this turns red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_value_that_gets_first_between_the_read_and_the_put_takes_the_write() {
        let (_nodes, _config, set, cell) = pinned(0x3B).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let rival = dsm::route_chain::leader_copy(&cell, b"W");
        let racing = Racing {
            seats: &seats,
            leader: cell.route().leader().to_vec(),
            rival: (rival.namespace.clone(), rival.key, rival.encode()),
            raced: std::sync::Mutex::new(None),
        };
        let rule = dsm::route_chain::recognized_copies(&cell, |bytes: &[u8]| {
            bytes == b"V" || bytes == b"W"
        });
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let [report] = from_leader(
            &racing,
            cell.route(),
            [(&cell, &rule, b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        let w_record = racing
            .raced
            .lock()
            .expect("the race record")
            .clone()
            .expect("W got to the leader first");
        assert_eq!(report.slots, vec![ChainSlot::Taken(w_record)]);
        assert_eq!(
            copies_of_anywhere(&seats, &cell, b"V").await,
            vec![0],
            "V is at the leader, put after W, and at no later seat"
        );
    }

    /// SoFi §17.4 with storage spec §9 rule 5 (MR-STOR-0134): values written
    /// together at one leader go there both or neither. With another value
    /// first at the leader of `a`, the pair's write records `a` taken and
    /// puts nothing: `b`'s value is not put at the leader either, and the
    /// pair reads taken. On the storage node's own code, on Postgres.
    /// MUTATION CONTROL: putting the open cell's value beside the taken one
    /// puts B at the leader; this turns red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_pair_whose_other_cell_is_taken_puts_neither_at_the_leader() {
        let (_nodes, _config, set, _cell) = pinned(0x3C).await;
        let members = crate::sdk::storage_set::as_ccb_members(&set).expect("members");
        let cell = |key: u8| {
            RoutedCell::new(
                b"DSM/test/pair-taken",
                [key; 32],
                &[0x3C; 32],
                &members,
                &set.id(),
            )
            .expect("a routed cell")
        };
        let (a, b) = (cell(0x01), cell(0x02));
        let seats = NodeSeats::new(&set).expect("seats");
        let keeps_a =
            dsm::route_chain::recognized_copies(&a, |bytes: &[u8]| bytes == b"A" || bytes == b"X");
        let keeps_b = dsm::route_chain::recognized_copies(&b, |bytes: &[u8]| bytes == b"B");
        let mut quiet_one = |_: &[WriteReport; 1]| Ok(());
        let [x] = from_leader(
            &seats,
            a.route(),
            [(&a, &keeps_a, b"X".as_slice())],
            &mut quiet_one,
        )
        .await
        .expect("X is written");
        let Some(ChainSlot::Link(x_link)) = x.slots.first().cloned() else {
            panic!("X is first at a's leader: {:?}", x.slots);
        };

        let mut quiet_two = |_: &[WriteReport; 2]| Ok(());
        let reports = from_leader(
            &seats,
            a.route(),
            [
                (&a, &keeps_a, b"A".as_slice()),
                (&b, &keeps_b, b"B".as_slice()),
            ],
            &mut quiet_two,
        )
        .await
        .expect("the pair's report");
        assert_eq!(pair_at_leader(&reports), AtLeader::Taken);
        assert_eq!(reports[0].slots, vec![ChainSlot::Taken(x_link)]);
        assert_eq!(
            reports[1].slots,
            Vec::<ChainSlot>::new(),
            "b is not written"
        );
        assert_eq!(
            held(&seats, b.route().leader(), &b).await,
            Vec::<Vec<u8>>::new(),
            "B is not at the leader"
        );
        assert_eq!(
            copies_of_anywhere(&seats, &a, b"A").await,
            Vec::<usize>::new()
        );
    }

    /// Storage spec §9, one chain in route order (MR-STOR-0151): links and
    /// empties are appended strictly in route order, and at a seat that does
    /// not answer the writer records an empty and goes on. With the seat at
    /// position 2 down, the write records links at 0 and 1, an empty at 2 and
    /// links at 3 and 4, and the copies at 3 and 4 carry exactly the slots
    /// before them, the empty in its place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_seat_that_does_not_answer_is_recorded_empty_in_its_place() {
        let (mut nodes, _config, set, cell) = pinned(0x32).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let route = cell.route();
        nodes.take_down(&[member_id(&route.seats()[2])]).await;

        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let [report] = from_leader(
            &seats,
            route,
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        assert_eq!(report.slots.len(), route.seats().len());
        assert_eq!(
            report.slots[2],
            ChainSlot::NoResponse,
            "position 2 is recorded empty"
        );
        for position in [0, 1, 3, 4] {
            assert!(
                matches!(report.slots[position], ChainSlot::Link(..)),
                "position {position}: {:?}",
                report.slots[position]
            );
        }
        for position in [3, 4] {
            let copies = held(&seats, &route.seats()[position], &cell).await;
            assert_eq!(copies.len(), 1, "one copy at position {position}");
            let entry = RouteEntry::decode(&copies[0]).expect("a route entry");
            assert_eq!(
                entry.chain,
                report.slots[..position].to_vec(),
                "the copy at position {position} does not carry the chain before it"
            );
        }
    }

    /// Storage spec §9, closed positions (MR-STOR-0152): once a later
    /// position is recorded, every earlier position is closed for that chain
    /// and is never written again. A write records an empty at position 2 and
    /// stops there, as a writer whose progress record fails. The seat comes
    /// back, and the write continues from the record it kept: positions 3 and
    /// 4 are written, and the seat at position 2 never is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_recorded_position_is_never_written_again() {
        let (mut nodes, _config, set, cell) = pinned(0x33).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let route = cell.route();
        let closed = member_id(&route.seats()[2]);
        nodes.take_down(std::slice::from_ref(&closed)).await;

        let mut kept: Option<WriteReport> = None;
        let mut stop_after_position_two = |reports: &[WriteReport; 1]| {
            let [report] = reports;
            kept = Some(report.clone());
            match report.slots.len() {
                3 => Err(DsmError::storage(
                    "the progress record failed after position 2".to_string(),
                    None::<std::io::Error>,
                )),
                _ => Ok(()),
            }
        };
        let stopped = from_leader(
            &seats,
            route,
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut stop_after_position_two,
        )
        .await;
        match stopped {
            Err(e) => assert!(
                e.to_string()
                    .contains("the progress record failed after position 2"),
                "the write stopped for another reason: {e}"
            ),
            Ok(reports) => panic!("the write went on past its failed record: {reports:?}"),
        }
        let report = kept.expect("the write recorded its progress");
        assert_eq!(report.slots.len(), 3);
        assert_eq!(report.slots[2], ChainSlot::NoResponse);

        nodes.bring_up(&[closed]).await;
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let continued = continue_write(&seats, &cell, b"V", report, &mut quiet)
            .await
            .expect("the write continues");
        assert_eq!(continued.slots.len(), route.seats().len());
        assert_eq!(
            continued.slots[2],
            ChainSlot::NoResponse,
            "position 2 stays empty"
        );
        assert_eq!(
            held(&seats, &route.seats()[2], &cell).await,
            Vec::<Vec<u8>>::new(),
            "the closed position 2 was written"
        );
        for position in [3, 4] {
            assert!(
                matches!(continued.slots[position], ChainSlot::Link(..)),
                "position {position}: {:?}",
                continued.slots[position]
            );
        }
    }

    /// The real seats, with the committed-state requests a read makes (every
    /// mirrored ByteCommit and every proof) counted while they are in flight.
    struct Watched<'a> {
        seats: &'a NodeSeats,
        in_flight: std::sync::atomic::AtomicUsize,
        most_at_once: std::sync::atomic::AtomicUsize,
        asked: std::sync::atomic::AtomicUsize,
        /// Cycles the read asked a seat to close.
        closed: std::sync::atomic::AtomicUsize,
    }

    impl Watched<'_> {
        async fn watch<T>(&self, call: impl core::future::Future<Output = T>) -> T {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.most_at_once.fetch_max(now, SeqCst);
            self.asked.fetch_add(1, SeqCst);
            // Hand control back once before the request goes out, so every
            // request the read has already started is counted in flight.
            tokio::task::yield_now().await;
            let answer = call.await;
            self.in_flight.fetch_sub(1, SeqCst);
            answer
        }
    }

    impl RouteSeats for Watched<'_> {
        fn members(&self) -> Vec<Vec<u8>> {
            self.seats.members()
        }

        async fn put_entries(
            &self,
            member: &[u8],
            entries: &[CellPut],
        ) -> Result<Vec<ArrivalRecord>, String> {
            self.seats.put_entries(member, entries).await
        }

        async fn fold_values(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            from: u64,
            take: &mut CellFold<'_>,
        ) -> Option<u64> {
            self.seats
                .fold_values(member, namespace, key, from, take)
                .await
        }

        async fn close(&self, member: &[u8]) -> Option<u64> {
            self.closed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.seats.close(member).await
        }

        async fn latest_cycle(&self, member: &[u8]) -> Option<u64> {
            self.seats.latest_cycle(member).await
        }

        async fn sync_mirror(&self, member: &[u8]) {
            self.seats.sync_mirror(member).await
        }

        async fn mirrored(
            &self,
            mirror: &[u8],
            member: &[u8],
            cycle: u64,
        ) -> Option<Vec<ByteCommit>> {
            self.watch(self.seats.mirrored(mirror, member, cycle)).await
        }

        async fn proof(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            cycle: u64,
        ) -> Option<CellCommitProof> {
            self.watch(self.seats.proof(member, namespace, key, cycle))
                .await
        }
    }

    /// A seat that takes a copy and answers with a record its own log does
    /// not give.
    struct Lying<'a> {
        seats: &'a NodeSeats,
        liar: Vec<u8>,
    }

    impl RouteSeats for Lying<'_> {
        fn members(&self) -> Vec<Vec<u8>> {
            self.seats.members()
        }

        async fn put_entries(
            &self,
            member: &[u8],
            entries: &[CellPut],
        ) -> Result<Vec<ArrivalRecord>, String> {
            let records = self.seats.put_entries(member, entries).await?;
            if member != self.liar.as_slice() {
                return Ok(records);
            }
            Ok(records
                .into_iter()
                .map(|record| ArrivalRecord {
                    running_hash: dsm::crypto::blake3::domain_hash_bytes(
                        dsm::common::domain_tags::TAG_DSM_TEST_TIP,
                        &record.running_hash,
                    ),
                    ..record
                })
                .collect())
        }

        async fn fold_values(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            from: u64,
            take: &mut CellFold<'_>,
        ) -> Option<u64> {
            self.seats
                .fold_values(member, namespace, key, from, take)
                .await
        }

        async fn close(&self, member: &[u8]) -> Option<u64> {
            self.seats.close(member).await
        }

        async fn latest_cycle(&self, member: &[u8]) -> Option<u64> {
            self.seats.latest_cycle(member).await
        }

        async fn sync_mirror(&self, member: &[u8]) {
            self.seats.sync_mirror(member).await
        }

        async fn mirrored(
            &self,
            mirror: &[u8],
            member: &[u8],
            cycle: u64,
        ) -> Option<Vec<ByteCommit>> {
            self.seats.mirrored(mirror, member, cycle).await
        }

        async fn proof(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            cycle: u64,
        ) -> Option<CellCommitProof> {
            self.seats.proof(member, namespace, key, cycle).await
        }
    }

    /// SA-98. A seat that takes the chain and returns a record its own log
    /// does not give is recorded empty in its place, and the chain goes on:
    /// with the seat at position 1 lying, the value written still reads
    /// Final. Carried as a link, the lie made every later link invalid.
    /// MUTATION CONTROL: carrying every record a seat returns as a link, as
    /// the writer did, leaves the value short of final and turns this red.
    /// On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_seat_lying_about_its_record_is_recorded_empty_and_the_value_is_final() {
        use dsm::route_chain::{CellReading, ChainState};
        let (_nodes, _config, set, cell) = pinned(0x36).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let lying = Lying {
            seats: &seats,
            liar: cell.route().seats()[1].to_vec(),
        };
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let [written] = from_leader(
            &lying,
            cell.route(),
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        assert_eq!(
            written.slots[1],
            ChainSlot::NoResponse,
            "{:?}",
            written.slots
        );

        let evidence = read_cell(&seats, &cell, &keeps_v(&cell)).await;
        let reading = dsm::route_chain::evaluate(&cell, &evidence, |bytes: &[u8]| {
            (bytes == b"V").then(|| (dsm::storage_cell::entry_digest(bytes), ()))
        });
        assert!(
            matches!(
                reading,
                Ok(CellReading::Held {
                    state: ChainState::Final,
                    ..
                })
            ),
            "the value reads Final past the lying seat: {reading:?}"
        );
    }

    /// A cell read asks for every seat's committed state at once (each
    /// mirrored ByteCommit, each parent, each proof, and each later seat's
    /// view of the leader) instead of one round trip after another, so a
    /// phone pays one network latency for that stage, not one per request.
    /// The evidence gathered that way still reads the written value Final.
    /// On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_cell_read_asks_for_every_seats_committed_state_at_once() {
        use dsm::route_chain::{CellReading, ChainState};
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        let (_nodes, _config, set, cell) = pinned(0x34).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        let [written] = from_leader(
            &seats,
            cell.route(),
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        assert!(
            written
                .slots
                .iter()
                .all(|slot| matches!(slot, ChainSlot::Link(..))),
            "the write reaches every seat: {:?}",
            written.slots
        );

        let watched = Watched {
            seats: &seats,
            in_flight: AtomicUsize::new(0),
            most_at_once: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
        };
        let evidence = read_cell(&watched, &cell, &keeps_v(&cell)).await;
        let asked = watched.asked.load(SeqCst);
        assert!(
            asked >= 2 * cell.route().seats().len(),
            "every seat's committed state is asked for: {asked} requests"
        );
        assert_eq!(
            watched.most_at_once.load(SeqCst),
            asked,
            "of {asked} committed-state requests, fewer were in flight together"
        );

        let reading = dsm::route_chain::evaluate(&cell, &evidence, |bytes: &[u8]| {
            (bytes == b"V").then(|| (dsm::storage_cell::entry_digest(bytes), ()))
        });
        assert!(
            matches!(
                reading,
                Ok(CellReading::Held {
                    state: ChainState::Final,
                    ..
                })
            ),
            "the value written to every seat reads Final: {reading:?}"
        );
    }

    /// A cell every seat already committed in full is read at the cycles
    /// already closed: closing another would commit the same entries. The
    /// read closes no cycle and still reads the value Final. Once a seat
    /// holds an entry no cycle of its commits, the read closes cycles again.
    /// On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_settled_cell_is_read_without_closing_a_cycle() {
        use dsm::route_chain::{CellReading, ChainState};
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        let (_nodes, _config, set, cell) = pinned(0x35).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        from_leader(
            &seats,
            cell.route(),
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        let watched = || Watched {
            seats: &seats,
            in_flight: AtomicUsize::new(0),
            most_at_once: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
        };
        let reads_final = |evidence: &CellEvidence| {
            matches!(
                dsm::route_chain::evaluate(&cell, evidence, |bytes: &[u8]| {
                    (bytes == b"V").then(|| (dsm::storage_cell::entry_digest(bytes), ()))
                }),
                Ok(CellReading::Held {
                    state: ChainState::Final,
                    ..
                })
            )
        };

        let first = watched();
        let evidence = read_cell(&first, &cell, &keeps_v(&cell)).await;
        assert!(
            first.closed.load(SeqCst) > 0,
            "nothing was committed yet: the first read closes cycles"
        );
        assert!(reads_final(&evidence), "the first read reads V Final");

        let settled = watched();
        let evidence = read_cell(&settled, &cell, &keeps_v(&cell)).await;
        assert_eq!(
            settled.closed.load(SeqCst),
            0,
            "every seat's last cycle commits all it holds: no cycle is closed"
        );
        assert!(reads_final(&evidence), "the settled read reads V Final");

        let leader = cell.route().leader().to_vec();
        seats
            .put_entries(
                &leader,
                &[(cell.namespace().to_vec(), *cell.key(), b"W".to_vec())],
            )
            .await
            .expect("the leader takes a later entry");
        let moved = watched();
        let evidence = read_cell(&moved, &cell, &keeps_v(&cell)).await;
        assert!(
            moved.closed.load(SeqCst) > 0,
            "the leader holds an entry no cycle commits: the read closes cycles"
        );
        assert!(
            reads_final(&evidence),
            "V's chain is still Final once the later entry is committed"
        );
    }

    /// A set whose seats each take one more write just before they are asked
    /// to close a cycle: a write arriving between a reader's read of a seat
    /// and the close that commits it.
    struct Trickling<'a> {
        seats: &'a NodeSeats,
        cell: &'a RoutedCell,
    }

    impl RouteSeats for Trickling<'_> {
        fn members(&self) -> Vec<Vec<u8>> {
            self.seats.members()
        }

        async fn put_entries(
            &self,
            member: &[u8],
            entries: &[CellPut],
        ) -> Result<Vec<ArrivalRecord>, String> {
            self.seats.put_entries(member, entries).await
        }

        async fn fold_values(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            from: u64,
            take: &mut CellFold<'_>,
        ) -> Option<u64> {
            self.seats
                .fold_values(member, namespace, key, from, take)
                .await
        }

        async fn close(&self, member: &[u8]) -> Option<u64> {
            let write = (
                self.cell.namespace().to_vec(),
                *self.cell.key(),
                b"a write after the read".to_vec(),
            );
            self.seats
                .put_entries(member, &[write])
                .await
                .expect("the seat takes the write");
            self.seats.close(member).await
        }

        async fn latest_cycle(&self, member: &[u8]) -> Option<u64> {
            self.seats.latest_cycle(member).await
        }

        async fn sync_mirror(&self, member: &[u8]) {
            self.seats.sync_mirror(member).await
        }

        async fn mirrored(
            &self,
            mirror: &[u8],
            member: &[u8],
            cycle: u64,
        ) -> Option<Vec<ByteCommit>> {
            self.seats.mirrored(mirror, member, cycle).await
        }

        async fn proof(
            &self,
            member: &[u8],
            namespace: &[u8],
            key: &[u8; 32],
            cycle: u64,
        ) -> Option<CellCommitProof> {
            self.seats.proof(member, namespace, key, cycle).await
        }
    }

    /// Whether `evidence` shows `V` Final at `cell`.
    fn v_is_final(cell: &RoutedCell, evidence: &CellEvidence) -> bool {
        matches!(
            dsm::route_chain::evaluate(cell, evidence, |bytes: &[u8]| {
                (bytes == b"V").then(|| (dsm::storage_cell::entry_digest(bytes), ()))
            }),
            Ok(dsm::route_chain::CellReading::Held {
                state: dsm::route_chain::ChainState::Final,
                ..
            })
        )
    }

    /// SA-99. A seat's cycle closes over every write that arrived by then,
    /// those after the reader read the seat too, so each log is read on to
    /// the entry the close committed: with a write arriving at every seat
    /// between its read and its close, the value still reads Final. Checked
    /// against the read before the close, each commitment named an entry the
    /// read never held, and a trickle of writes kept the cell undecided
    /// however often it was read.
    /// MUTATION CONTROL: not reading a log on past its seat's close in
    /// `read_cell` turns this red. On the storage node's own code, on
    /// Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_write_between_the_read_and_the_close_leaves_the_value_final() {
        let (_nodes, _config, set, cell) = pinned(0x37).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        from_leader(
            &seats,
            cell.route(),
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        let trickling = Trickling {
            seats: &seats,
            cell: &cell,
        };
        let evidence = read_cell(&trickling, &cell, &keeps_v(&cell)).await;
        for seat in cell.route().seats() {
            assert_eq!(
                held(&seats, seat, &cell).await.len(),
                2,
                "the seat took a write between the read and the close"
            );
        }
        assert!(
            v_is_final(&cell, &evidence),
            "V reads Final over the writes that arrived before the close"
        );
    }

    /// SA-67. Bytes at a seat that are no copy of the cell's value never
    /// count, so junk at the leader blocks nothing however much of it there
    /// is: thirty of the largest entries ahead of the value, past the 8 MiB a
    /// whole-cell read refused the leader's log at, and the value still
    /// reads Final.
    /// MUTATION CONTROL: holding a seat's log to this device's budget for a
    /// seat by every byte read, as the whole-cell read did, turns this red.
    /// On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn junk_past_any_budget_at_the_leader_blocks_no_read() {
        const JUNK: usize = 30;
        let (_nodes, _config, set, cell) = pinned(0x38).await;
        let seats = NodeSeats::new(&set).expect("seats");
        let leader = cell.route().leader().to_vec();
        let junk = vec![0x76u8; dsm::route_chain::MAX_ENTRY_BYTES];
        assert!(JUNK * junk.len() > HELD_LOG_BUDGET);
        for _ in 0..JUNK {
            seats
                .put_entries(
                    &leader,
                    &[(cell.namespace().to_vec(), *cell.key(), junk.clone())],
                )
                .await
                .expect("the leader takes the junk");
        }
        let mut quiet = |_: &[WriteReport; 1]| Ok(());
        from_leader(
            &seats,
            cell.route(),
            [(&cell, &keeps_v(&cell), b"V".as_slice())],
            &mut quiet,
        )
        .await
        .expect("a report");
        let evidence = read_cell(&seats, &cell, &keeps_v(&cell)).await;
        assert_eq!(
            evidence.seats[0].values.as_ref().map(HeldLog::count),
            Some(JUNK as u64 + 1),
            "the leader's whole log was read"
        );
        assert!(
            v_is_final(&cell, &evidence),
            "V reads Final behind the junk"
        );
    }

    /// SA-76. Reads made together keep between them no more than their
    /// window. Every seat of a cell holds six distinct values the reader
    /// keeps; read within a window of two seats' copies, the seats past it
    /// are not read, never read with copies left out, and what is read fits
    /// the window. Within a window that holds them all, and on their own,
    /// every seat is read whole.
    /// MUTATION CONTROL: a fold that takes nothing from the window turns
    /// this red.
    /// On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn reads_made_together_keep_no_more_than_their_window() {
        const VALUES: usize = 6;
        const VALUE_BYTES: usize = 64 * 1024;
        let (_nodes, _config, set, cell) = pinned(0x39).await;
        let seats = NodeSeats::new(&set).expect("seats");
        // Each value is written under a rule that recognizes it alone, so
        // none is taken at the leader and each reaches every seat; the
        // reader's rule below keeps all six.
        for n in 0..VALUES {
            let mut value = vec![0x57u8; VALUE_BYTES];
            value[1] = n as u8;
            let alone = dsm::route_chain::recognized_copies(&cell, |bytes: &[u8]| bytes == value);
            let mut quiet = |_: &[WriteReport; 1]| Ok(());
            from_leader(
                &seats,
                cell.route(),
                [(&cell, &alone, value.as_slice())],
                &mut quiet,
            )
            .await
            .expect("a report");
        }
        let keep =
            dsm::route_chain::recognized_copies(&cell, |bytes: &[u8]| bytes.first() == Some(&0x57));
        let kept = |evidence: &CellEvidence| -> Vec<Option<usize>> {
            evidence
                .seats
                .iter()
                .map(|seat| seat.values.as_ref().map(HeldLog::kept_bytes))
                .collect()
        };

        let alone = kept(&read_cell(&seats, &cell, &keep).await);
        let whole: Vec<usize> = alone.iter().flatten().copied().collect();
        assert_eq!(whole.len(), alone.len(), "read alone, every seat is read");
        assert!(
            whole.iter().all(|bytes| *bytes >= VALUES * VALUE_BYTES),
            "each seat keeps every value"
        );
        let ample = ReadWindow::new(whole.iter().sum());
        let within_ample = read_cell_within(&seats, &cell, &keep, &ample).await;
        assert_eq!(kept(&within_ample), alone, "a window that holds every copy");
        assert!(!ample.spent());

        let budget = 2 * whole.iter().copied().max().expect("the cell has seats");
        let window = ReadWindow::new(budget);
        let within = kept(&read_cell_within(&seats, &cell, &keep, &window).await);
        let read: Vec<(usize, usize)> = within
            .iter()
            .enumerate()
            .filter_map(|(position, bytes)| bytes.map(|bytes| (position, bytes)))
            .collect();
        assert!(
            read.len() < within.len(),
            "a seat past the window is not read"
        );
        assert!(
            read.iter().map(|(_, bytes)| bytes).sum::<usize>() <= budget,
            "what is read fits the window"
        );
        for (position, bytes) in &read {
            assert_eq!(
                Some(*bytes),
                alone[*position],
                "a seat that is read is read whole"
            );
        }
        assert!(window.spent());
    }

    #[test]
    fn nothing_mirrored_gives_none() {
        let m = b"dsm-node-1";
        assert_eq!(agreed(m, 3, &[Vec::new(), Vec::new()]), None);
        assert_eq!(agreed(m, 3, &[]), None);
    }
}
