// SPDX-License-Identifier: MIT OR Apache-2.0

//! Route chains — storage spec §9, DSM Amendment A6, SoFi Amendment S4.
//!
//! A cell's route is `R(K) = FisherYates(s, S) = [r0, r1, r2, r3, r4]` over the
//! committed set; `r0` is the leader. A writer writes a value to the seats in
//! route order, leader first, and every copy after the leader carries the
//! chain built so far. A link is the arrival record a seat returned for the
//! value; each entry's bytes carry the earlier links, so each link commits the
//! ones before it.
//!
//! ```text
//! LeaderHeld(K, x) ⇔ x has a valid leader link at K
//! Preserved(K, x)  ⇔ x's chain has a valid leader link and ≥ 1 further valid link
//! Final(K, x)      ⇔ x's chain has a valid leader link and ≥ 2 further valid links
//! ```
//!
//! Only Core evaluates chains. A node stores the bytes it is given and returns
//! their arrival record; it never reads a route entry. A receiver relies only
//! on `Final`; `Preserved` matters only for loss (§12.6) and is never
//! spendable.
//!
//! This module holds the route, the entry every seat stores, the chain slots,
//! the chain states, and the evidence a verifier gathers to evaluate them.

use crate::ccb::StorageSetMembers;
use crate::sofi::fisher_yates::{permute, FisherYatesError};
use crate::storage_cell::{ArrivalRecord, ByteCommit, CellCommitProof};
use crate::types::proto;

/// Every route has one position per member of the five-member set.
pub const ROUTE_LEN: usize = 5;

/// The number of links, the leader's included, at which a value is final.
pub const FINAL_LINKS: usize = 3;

/// Longest namespace a route entry may name (the proto bound).
pub const MAX_NAMESPACE_LEN: usize = 128;

/// Longest member id a route entry may name (the proto bound).
pub const MAX_MEMBER_ID_LEN: usize = 128;

/// Largest value a route entry may carry (the proto bound): the largest
/// object a cell holds, such as a SoFi exercise (`MAX_EXERCISE_BYTES`).
pub const MAX_VALUE_LEN: usize = 262_144;

/// A bound on everything an entry adds around its value: the cell, the seat,
/// the position, and up to four chain slots, each an arrival record with
/// bounded fields, with their protobuf framing. The largest possible entry is
/// tested to fit (`the_largest_entry_fits_the_bound`).
pub const MAX_ENTRY_OVERHEAD: usize = 4096;

/// The largest route entry, and so the largest value a node's cell must take
/// (the node's cell limit is this constant).
pub const MAX_ENTRY_BYTES: usize = MAX_VALUE_LEN + MAX_ENTRY_OVERHEAD;

/// A cell's route: the committed set's member ids in the order the seed's
/// Fisher–Yates shuffle puts them. Position 0 is the leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    seats: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// The committed set does not have exactly five members.
    NotFiveMembers {
        members: usize,
    },
    Shuffle(FisherYatesError),
}

impl Route {
    /// `FisherYates(s, S)` over the set committed in the state that seeds the
    /// cell. The seed comes from committed state only; availability, the
    /// caller and node ids never enter it (§9 rules 1–3). Offline members keep
    /// their positions.
    pub fn of(seed: &[u8; 32], members: &StorageSetMembers) -> Result<Self, RouteError> {
        let ids: Vec<Vec<u8>> = members
            .entries()
            .iter()
            .map(|e| e.member_id().to_vec())
            .collect();
        if ids.len() != ROUTE_LEN {
            return Err(RouteError::NotFiveMembers { members: ids.len() });
        }
        let seats = permute(seed, &ids).map_err(RouteError::Shuffle)?;
        Ok(Self { seats })
    }

    /// The seat at route position `position`, if the position exists.
    pub fn seat(&self, position: usize) -> Option<&[u8]> {
        self.seats.get(position).map(Vec::as_slice)
    }

    /// The leader, `r0`.
    pub fn leader(&self) -> &[u8] {
        &self.seats[0]
    }

    /// The seats in route order.
    pub fn seats(&self) -> &[Vec<u8>] {
        &self.seats
    }
}

/// One earlier position of a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSlot {
    /// The seat's arrival record for this value.
    Link(ArrivalRecord),
    /// Another value's valid chain is already first at that seat, shown by
    /// the seat's arrival record for that other value's entry.
    Taken(ArrivalRecord),
    /// The seat did not answer. Recorded so the route never shortens or
    /// reorders; it proves nothing.
    NoResponse,
}

impl ChainSlot {
    pub fn to_proto(&self) -> proto::ChainSlotV1 {
        use proto::chain_slot_v1::Kind;
        let kind = match self {
            ChainSlot::Link(r) => Kind::Link(r.to_proto()),
            ChainSlot::Taken(r) => Kind::Taken(r.to_proto()),
            ChainSlot::NoResponse => Kind::NoResponse(proto::NoResponseV1 {}),
        };
        proto::ChainSlotV1 { kind: Some(kind) }
    }

    pub fn from_proto(p: &proto::ChainSlotV1) -> Option<Self> {
        use proto::chain_slot_v1::Kind;
        match p.kind.as_ref()? {
            Kind::Link(r) => Some(ChainSlot::Link(ArrivalRecord::from_proto(r)?)),
            Kind::Taken(r) => Some(ChainSlot::Taken(ArrivalRecord::from_proto(r)?)),
            Kind::NoResponse(_) => Some(ChainSlot::NoResponse),
        }
    }

    /// The arrival record the slot carries, if any.
    pub fn record(&self) -> Option<&ArrivalRecord> {
        match self {
            ChainSlot::Link(r) | ChainSlot::Taken(r) => Some(r),
            ChainSlot::NoResponse => None,
        }
    }
}

/// What a writer puts at one seat: the cell, the value, which seat and route
/// position this copy is for, and the chain collected at the earlier
/// positions, one slot per position in route order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub namespace: Vec<u8>,
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub seat: Vec<u8>,
    pub position: usize,
    pub chain: Vec<ChainSlot>,
}

impl RouteEntry {
    /// The entry for the leader: position 0, empty chain.
    pub fn at_leader(namespace: Vec<u8>, key: [u8; 32], value: Vec<u8>, route: &Route) -> Self {
        Self {
            namespace,
            key,
            value,
            seat: route.leader().to_vec(),
            position: 0,
            chain: Vec::new(),
        }
    }

    /// The entry for the next position, carrying this entry's chain plus the
    /// slot this position produced. `None` past the last position.
    pub fn next(&self, slot: ChainSlot, route: &Route) -> Option<Self> {
        let position = self.position + 1;
        let seat = route.seat(position)?.to_vec();
        let mut chain = self.chain.clone();
        chain.push(slot);
        Some(Self {
            namespace: self.namespace.clone(),
            key: self.key,
            value: self.value.clone(),
            seat,
            position,
            chain,
        })
    }

    pub fn to_proto(&self) -> proto::RouteEntryV1 {
        proto::RouteEntryV1 {
            namespace: self.namespace.clone(),
            key: self.key.to_vec(),
            value: self.value.clone(),
            seat_member_id: self.seat.clone(),
            position: self.position as u32,
            chain: self.chain.iter().map(ChainSlot::to_proto).collect(),
        }
    }

    /// The exact bytes written to the seat. The seat's arrival record digests
    /// these bytes, so the link it returns commits the whole chain before it.
    pub fn encode(&self) -> Vec<u8> {
        use prost::Message;
        self.to_proto().encode_to_vec()
    }

    /// Decode bytes read from a seat. `None` unless the bytes are the one
    /// canonical encoding of a well-formed entry: bounded fields, a position
    /// on the route, exactly one slot per earlier position, and every carried
    /// record naming this cell. Canonical means re-encoding reproduces the
    /// bytes exactly, so no reordered, duplicated or unknown field decodes,
    /// and one entry has one byte string. Whether the entry fits a particular
    /// route is [`RouteEntry::fits`].
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        use prost::Message;
        let p = proto::RouteEntryV1::decode(bytes).ok()?;
        if p.encode_to_vec() != bytes {
            return None;
        }
        if p.namespace.is_empty()
            || p.namespace.len() > MAX_NAMESPACE_LEN
            || p.seat_member_id.is_empty()
            || p.seat_member_id.len() > MAX_MEMBER_ID_LEN
            || p.value.len() > MAX_VALUE_LEN
        {
            return None;
        }
        let position = usize::try_from(p.position).ok()?;
        if position >= ROUTE_LEN || p.chain.len() != position {
            return None;
        }
        let key: [u8; 32] = p.key.as_slice().try_into().ok()?;
        let chain = p
            .chain
            .iter()
            .map(ChainSlot::from_proto)
            .collect::<Option<Vec<_>>>()?;
        if chain
            .iter()
            .filter_map(ChainSlot::record)
            .any(|r| r.namespace != p.namespace || r.key != key)
        {
            return None;
        }
        Some(Self {
            namespace: p.namespace,
            key,
            value: p.value,
            seat: p.seat_member_id,
            position,
            chain,
        })
    }

    /// Whether the entry names the seat the route puts at its position, and
    /// every carried record comes from the seat at that record's position.
    pub fn fits(&self, route: &Route) -> bool {
        route.seat(self.position) == Some(self.seat.as_slice())
            && self
                .chain
                .iter()
                .enumerate()
                .all(|(i, slot)| match slot.record() {
                    Some(r) => route.seat(i) == Some(r.member_id.as_slice()),
                    None => true,
                })
    }
}

/// Where a value stands at a cell. Absent means the value has no valid leader
/// link there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainState {
    /// A valid leader link: the value has won the race at the cell.
    LeaderHeld,
    /// A valid leader link and one further valid link. Not final, never
    /// spendable; it matters only for loss (§12.6).
    Preserved,
    /// A valid leader link and two further valid links. The only state a
    /// receiver relies on.
    Final,
}

impl ChainState {
    /// The state of a value with a valid leader link and `further` further
    /// valid links.
    pub fn with_further_links(further: usize) -> Self {
        match further {
            0 => ChainState::LeaderHeld,
            1 => ChainState::Preserved,
            2.. => ChainState::Final,
        }
    }

    /// The state a count of valid links, the leader's included, amounts to.
    /// No state without a leader link.
    pub fn of_links(valid_links: usize) -> Option<Self> {
        valid_links.checked_sub(1).map(Self::with_further_links)
    }
}

/// The storage fact at one cell, as Core evaluated its route chains: either
/// no value has a valid leader link yet, or one has, identified the way the
/// caller's recognizer identifies values at that cell, with how far its chain
/// has gone. A storage fact, not a predicate: it says who holds the cell, not
/// whether what it holds is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellFact {
    /// No value has a valid leader link at the cell. The cell is open.
    Open,
    /// `id` names the value with the valid leader link; `state` is how far
    /// its chain has gone. Only `ChainState::Final` is relied on.
    Held { id: [u8; 32], state: ChainState },
}

/// A seat's committed state for the cell: a ByteCommit obtained from a
/// mirror, and the seat's own proof that it commits the cell's latest entry
/// as of that cycle (§14). A link counts only once such evidence verifies.
#[derive(Debug, Clone)]
pub struct CommittedAt {
    pub commit: ByteCommit,
    pub proof: CellCommitProof,
}

/// Everything a verifier holds about one seat of a cell's route.
#[derive(Debug, Clone)]
pub struct SeatEvidence {
    /// Everything the seat holds at the cell, in arrival order. `None` when
    /// the seat has not been read.
    pub values: Option<Vec<Vec<u8>>>,
    /// The seat's committed state for the cell, if a ByteCommit covering it
    /// has closed and been obtained.
    pub committed: Option<CommittedAt>,
    /// This seat's own mirror of the leader's ByteCommits, with the leader's
    /// proof against the mirrored root: what rule 4 of §9 requires before a
    /// later link at this seat counts.
    pub leader_seen: Option<CommittedAt>,
}

/// Everything a verifier holds about one cell: which cell, its route, and
/// one [`SeatEvidence`] per route position.
#[derive(Debug, Clone)]
pub struct CellEvidence {
    pub namespace: Vec<u8>,
    pub key: [u8; 32],
    pub route: Route,
    pub seats: Vec<SeatEvidence>,
}

/// What Core reads at a cell once it has evaluated the route chains: the cell
/// is open, or one recognized object holds it with a chain that has gone as
/// far as `state`. `object` is what the caller's recognizer made of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellReading<T> {
    Open,
    Held {
        object: T,
        id: [u8; 32],
        state: ChainState,
    },
}

impl<T> CellReading<T> {
    /// The storage fact, without the object.
    pub fn fact(&self) -> CellFact {
        match self {
            CellReading::Open => CellFact::Open,
            CellReading::Held { id, state, .. } => CellFact::Held {
                id: *id,
                state: *state,
            },
        }
    }
}

/// What the evidence in hand does not yet show. Never a verdict: the
/// acquisition layer fetches it and evaluates again, and a network that never
/// delivers it is a network failure, not an answer (SoFi Amendment S7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// The leader has not been read. No other seat stands in (§9 finality 4).
    LeaderUnread,
    /// The leader holds a recognized value first, but no closed ByteCommit of
    /// the leader's covering its arrival record is in hand yet (§9 rule 7).
    LeaderLinkUncommitted,
}

/// The arrival record a seat returned for the last value of `log`, where
/// `log` is the seat's arrival order up to and including that value: its
/// per-key index and the seat's running hash after it (§6, §14).
fn record_of(seat: &[u8], namespace: &[u8], key: &[u8; 32], log: &[Vec<u8>]) -> ArrivalRecord {
    let running_hash = log.iter().fold(
        crate::storage_cell::running_hash_init(namespace, key),
        |previous, value| {
            crate::storage_cell::running_hash_next(
                &previous,
                &crate::storage_cell::entry_digest(value),
            )
        },
    );
    ArrivalRecord {
        member_id: seat.to_vec(),
        namespace: namespace.to_vec(),
        key: *key,
        index: log.len() as u64,
        running_hash,
    }
}

/// Whether `commit` is a ByteCommit of `record`'s seat that commits the
/// record against the values read from that seat (§14).
fn committed_by(record: &ArrivalRecord, log: &[Vec<u8>], commit: Option<&CommittedAt>) -> bool {
    commit
        .is_some_and(|c| crate::storage_cell::record_is_committed(record, log, &c.commit, &c.proof))
}

/// Whether a route entry is this cell's copy for route position `position`:
/// same namespace and key, that position, the seat the route puts there, and
/// every carried record from the seat at its own position.
fn is_cell_copy_at(entry: &RouteEntry, ev: &CellEvidence, position: usize) -> bool {
    entry.namespace == ev.namespace
        && entry.key == ev.key
        && entry.position == position
        && entry.fits(&ev.route)
}

/// Evaluate a cell's route chains (storage spec §9). `recognize` returns the
/// id of a value that is a recognized object naming the cell, with what it
/// recognized, and `None` for anything else; unrecognized bytes never count,
/// wherever they arrived.
///
/// 1. The leader link is valid for the first recognized value in the
///    leader's arrival log, stored as the cell's position-0 copy at the
///    leader, and only once the leader's ByteCommit commits its record.
/// 2. A later link at position `i` is an arrival record seat `r_i` returned
///    for the same value's position-`i` copy, whose carried chain begins with
///    the leader link and carries no link that is not itself valid; the
///    record is committed by that seat's ByteCommit; and the seat's own
///    mirror of the leader's ByteCommits covers the leader link (§9 rule 4).
///    The position is the route's, so it is higher than every carried link's.
/// 3. The value's state is its count of positions with a valid link.
pub fn evaluate<T, F>(ev: &CellEvidence, recognize: F) -> Result<CellReading<T>, Missing>
where
    F: Fn(&[u8]) -> Option<([u8; 32], T)>,
{
    let leader = ev.seats.first().ok_or(Missing::LeaderUnread)?;
    let leader_log = leader.values.as_ref().ok_or(Missing::LeaderUnread)?;

    let mut first = None;
    for (n, bytes) in leader_log.iter().enumerate() {
        let Some(entry) = RouteEntry::decode(bytes) else {
            continue;
        };
        if !is_cell_copy_at(&entry, ev, 0) {
            continue;
        }
        if let Some((id, object)) = recognize(&entry.value) {
            first = Some((n, entry.value, id, object));
            break;
        }
    }
    let Some((n, value, id, object)) = first else {
        return Ok(CellReading::Open);
    };
    let leader_link = record_of(ev.route.leader(), &ev.namespace, &ev.key, &leader_log[..=n]);
    if !committed_by(&leader_link, leader_log, leader.committed.as_ref()) {
        return Err(Missing::LeaderLinkUncommitted);
    }

    // `links[i]` holds every valid link of this value at route position `i`.
    let mut links: Vec<Vec<ArrivalRecord>> = vec![Vec::new(); ev.route.seats().len()];
    links[0].push(leader_link.clone());
    let leader_slot = ChainSlot::Link(leader_link.clone());
    for (position, seat_id) in ev.route.seats().iter().enumerate().skip(1) {
        let Some(seat) = ev.seats.get(position) else {
            continue;
        };
        let Some(log) = seat.values.as_ref() else {
            continue;
        };
        let leader_seen = seat.leader_seen.as_ref().is_some_and(|c| {
            c.commit.member_id.as_slice() == ev.route.leader()
                && crate::storage_cell::record_is_committed(
                    &leader_link,
                    leader_log,
                    &c.commit,
                    &c.proof,
                )
        });
        if !leader_seen {
            continue;
        }
        for (m, bytes) in log.iter().enumerate() {
            let Some(entry) = RouteEntry::decode(bytes) else {
                continue;
            };
            if !is_cell_copy_at(&entry, ev, position)
                || entry.value != value
                || entry.chain.first() != Some(&leader_slot)
            {
                continue;
            }
            // An empty is never a link (§9 rule 5): it neither counts nor
            // invalidates. Every carried link must be a valid one.
            let carries_only_valid_links =
                entry
                    .chain
                    .iter()
                    .enumerate()
                    .all(|(earlier, slot)| match slot {
                        ChainSlot::Link(record) => links[earlier].contains(record),
                        ChainSlot::Taken(..) | ChainSlot::NoResponse => true,
                    });
            if !carries_only_valid_links {
                continue;
            }
            let link = record_of(seat_id, &ev.namespace, &ev.key, &log[..=m]);
            if committed_by(&link, log, seat.committed.as_ref()) {
                links[position].push(link);
            }
        }
    }

    let further = links.iter().skip(1).filter(|at| !at.is_empty()).count();
    Ok(CellReading::Held {
        object,
        id,
        state: ChainState::with_further_links(further),
    })
}

/// A cell written the way storage spec §9 describes, for tests across Core:
/// real arrival logs at each seat, the arrival records a node returns, and
/// each seat's ByteCommit over the cell with its inclusion proof.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// The five-member committed set every fixture route is drawn over.
    pub(crate) fn committed_set() -> StorageSetMembers {
        let ids = [
            "dsm-node-1",
            "dsm-node-2",
            "dsm-node-3",
            "dsm-node-4",
            "dsm-node-5",
        ];
        let entries: Vec<(&[u8], [u8; 32])> =
            ids.iter().map(|m| (m.as_bytes(), [7u8; 32])).collect();
        StorageSetMembers::new(&entries).expect("five members")
    }

    /// One cell across its five seats.
    pub(crate) struct Cell {
        pub(crate) namespace: Vec<u8>,
        pub(crate) key: [u8; 32],
        pub(crate) route: Route,
        /// Each seat's arrival log at the cell, by route position.
        pub(crate) logs: Vec<Vec<Vec<u8>>>,
    }

    impl Cell {
        pub(crate) fn new(namespace: &[u8], key: [u8; 32], seed: [u8; 32]) -> Self {
            Self {
                namespace: namespace.to_vec(),
                key,
                route: Route::of(&seed, &committed_set()).expect("route"),
                logs: vec![Vec::new(); ROUTE_LEN],
            }
        }

        /// Store `bytes` at the seat at `position`, as a node does, and
        /// return the arrival record the node gives for them.
        pub(crate) fn put(&mut self, position: usize, bytes: Vec<u8>) -> ArrivalRecord {
            self.logs[position].push(bytes);
            record_of(
                &self.route.seats()[position],
                &self.namespace,
                &self.key,
                &self.logs[position],
            )
        }

        /// Write `value` along the route through position `last`, leader
        /// first, each copy carrying the chain built so far. A position in
        /// `silent` does not answer: nothing is stored there and the chain
        /// records no response.
        pub(crate) fn write(&mut self, value: &[u8], last: usize, silent: &[usize]) {
            let mut entry = RouteEntry::at_leader(
                self.namespace.clone(),
                self.key,
                value.to_vec(),
                &self.route,
            );
            for position in 0..=last {
                let slot = if silent.contains(&position) {
                    ChainSlot::NoResponse
                } else {
                    ChainSlot::Link(self.put(position, entry.encode()))
                };
                if position < last {
                    entry = entry.next(slot, &self.route).expect("a route position");
                }
            }
        }

        /// The arrival record the seat at `position` gave its `index`-th
        /// value (1-based).
        pub(crate) fn record_at(&self, position: usize, index: usize) -> ArrivalRecord {
            record_of(
                &self.route.seats()[position],
                &self.namespace,
                &self.key,
                &self.logs[position][..index],
            )
        }

        /// Carry the chain of `value`, whose leader copy is the leader's
        /// `leader_index`-th value, through position `last`: any party may
        /// continue a chain along the rest of its route (§9 rule 8).
        pub(crate) fn continue_chain(&mut self, value: &[u8], leader_index: usize, last: usize) {
            let leader_link = ChainSlot::Link(self.record_at(0, leader_index));
            let mut entry = RouteEntry::at_leader(
                self.namespace.clone(),
                self.key,
                value.to_vec(),
                &self.route,
            )
            .next(leader_link, &self.route)
            .expect("position 1");
            for position in 1..=last {
                let slot = ChainSlot::Link(self.put(position, entry.encode()));
                if position < last {
                    entry = entry.next(slot, &self.route).expect("a route position");
                }
            }
        }

        /// The ByteCommit the seat at `position` closes now, committing the
        /// cell's latest entry, with its proof. `None` while the seat holds
        /// nothing at the cell.
        pub(crate) fn commit(&self, position: usize) -> Option<CommittedAt> {
            let log = &self.logs[position];
            if log.is_empty() {
                return None;
            }
            let seat = &self.route.seats()[position];
            let latest = record_of(seat, &self.namespace, &self.key, log);
            let tree = crate::storage_cell::cell_tree([(
                self.namespace.as_slice(),
                &self.key,
                latest.index,
                &latest.running_hash,
            )]);
            let proof = CellCommitProof::from_tree(
                &tree,
                &self.namespace,
                &self.key,
                latest.index,
                latest.running_hash,
            )
            .expect("an inclusion proof for a leaf the tree holds");
            Some(CommittedAt {
                commit: ByteCommit {
                    member_id: seat.clone(),
                    cycle_index: 1,
                    smt_root: *tree.root(),
                    bytes_used: log.iter().map(|v| v.len() as u64).sum(),
                    parent_digest: [0u8; 32],
                },
                proof,
            })
        }

        /// What a verifier holds once it has read every seat and obtained
        /// every seat's ByteCommit, each seat having mirrored the leader's
        /// latest one.
        pub(crate) fn evidence(&self) -> CellEvidence {
            let leader = self.commit(0);
            CellEvidence {
                namespace: self.namespace.clone(),
                key: self.key,
                route: self.route.clone(),
                seats: (0..ROUTE_LEN)
                    .map(|position| SeatEvidence {
                        values: Some(self.logs[position].clone()),
                        committed: self.commit(position),
                        leader_seen: leader.clone(),
                    })
                    .collect(),
            }
        }
    }

    /// A test recognizer: a value is a recognized object when it begins with
    /// `ok`; its id is its entry digest and the object is its bytes.
    pub(crate) fn recognize_ok(bytes: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
        bytes
            .starts_with(b"ok")
            .then(|| (crate::storage_cell::entry_digest(bytes), bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> StorageSetMembers {
        let entries: Vec<(&[u8], [u8; 32])> =
            ids.iter().map(|m| (m.as_bytes(), [7u8; 32])).collect();
        StorageSetMembers::new(&entries).expect("set")
    }

    fn five() -> StorageSetMembers {
        set(&[
            "dsm-node-1",
            "dsm-node-2",
            "dsm-node-3",
            "dsm-node-4",
            "dsm-node-5",
        ])
    }

    fn record(member: &[u8], ns: &[u8], key: [u8; 32], index: u64) -> ArrivalRecord {
        ArrivalRecord {
            member_id: member.to_vec(),
            namespace: ns.to_vec(),
            key,
            index,
            running_hash: [index as u8; 32],
        }
    }

    #[test]
    fn a_route_is_the_fisher_yates_permutation_of_the_committed_set() {
        let seed = [3u8; 32];
        let route = Route::of(&seed, &five()).expect("route");
        let ids: Vec<Vec<u8>> = five()
            .entries()
            .iter()
            .map(|e| e.member_id().to_vec())
            .collect();
        assert_eq!(
            route.seats(),
            permute(&seed, &ids).expect("permute").as_slice()
        );
        assert_eq!(route.leader(), route.seats()[0].as_slice());
        assert_ne!(
            Route::of(&[4u8; 32], &five()).expect("route"),
            route,
            "the seed decides"
        );
    }

    #[test]
    fn a_route_needs_exactly_five_members() {
        let four = set(&["a", "b", "c", "d"]);
        assert_eq!(
            Route::of(&[0u8; 32], &four),
            Err(RouteError::NotFiveMembers { members: 4 })
        );
    }

    #[test]
    fn an_entry_carries_one_slot_per_earlier_position_and_round_trips() {
        let route = Route::of(&[9u8; 32], &five()).expect("route");
        let ns = b"DSM/example".to_vec();
        let key = [1u8; 32];
        let e0 = RouteEntry::at_leader(ns.clone(), key, b"x".to_vec(), &route);
        let e1 = e0
            .next(ChainSlot::Link(record(route.leader(), &ns, key, 1)), &route)
            .expect("position 1");
        let e2 = e1.next(ChainSlot::NoResponse, &route).expect("position 2");
        for e in [&e0, &e1, &e2] {
            assert_eq!(RouteEntry::decode(&e.encode()).as_ref(), Some(e));
            assert!(e.fits(&route));
        }
        assert_eq!(e2.chain.len(), 2);
        let mut last = e2.clone();
        for _ in 2..ROUTE_LEN - 1 {
            last = last.next(ChainSlot::NoResponse, &route).expect("next");
        }
        assert_eq!(last.position, ROUTE_LEN - 1);
        assert!(
            last.next(ChainSlot::NoResponse, &route).is_none(),
            "no position past the route"
        );
    }

    #[test]
    fn malformed_entries_do_not_decode() {
        let route = Route::of(&[9u8; 32], &five()).expect("route");
        let ns = b"DSM/example".to_vec();
        let key = [1u8; 32];
        let good = RouteEntry::at_leader(ns.clone(), key, b"x".to_vec(), &route)
            .next(ChainSlot::Link(record(route.leader(), &ns, key, 1)), &route)
            .expect("position 1");

        let mut p = good.to_proto();
        p.chain.clear();
        assert_eq!(
            RouteEntry::decode(&prost::Message::encode_to_vec(&p)),
            None,
            "a slot missing"
        );

        let mut p = good.to_proto();
        p.position = ROUTE_LEN as u32;
        assert_eq!(
            RouteEntry::decode(&prost::Message::encode_to_vec(&p)),
            None,
            "off the route"
        );

        let mut other = record(route.leader(), &ns, key, 1);
        other.key = [2u8; 32];
        let mut p = good.to_proto();
        p.chain = vec![ChainSlot::Link(other).to_proto()];
        assert_eq!(
            RouteEntry::decode(&prost::Message::encode_to_vec(&p)),
            None,
            "another cell's record"
        );

        let mut p = good.to_proto();
        p.chain = vec![proto::ChainSlotV1 { kind: None }];
        assert_eq!(
            RouteEntry::decode(&prost::Message::encode_to_vec(&p)),
            None,
            "an empty slot"
        );

        // The same entry under another byte string: a field repeated at the
        // end (protobuf keeps the last scalar) decodes to an equal message,
        // and must still be refused.
        let mut noncanonical = good.encode();
        noncanonical.extend_from_slice(&prost::Message::encode_to_vec(&proto::RouteEntryV1 {
            position: 1,
            ..Default::default()
        }));
        assert_eq!(
            RouteEntry::decode(&noncanonical),
            None,
            "a non-canonical encoding"
        );
    }

    #[test]
    fn an_entry_fits_only_its_own_route() {
        let route = Route::of(&[9u8; 32], &five()).expect("route");
        let ns = b"DSM/example".to_vec();
        let key = [1u8; 32];
        let e1 = RouteEntry::at_leader(ns.clone(), key, b"x".to_vec(), &route)
            .next(ChainSlot::Link(record(route.leader(), &ns, key, 1)), &route)
            .expect("position 1");
        let mut wrong_seat = e1.clone();
        wrong_seat.seat = route.seats()[2].clone();
        assert!(!wrong_seat.fits(&route));
        let mut wrong_link = e1.clone();
        wrong_link.chain = vec![ChainSlot::Link(record(&route.seats()[3], &ns, key, 1))];
        assert!(!wrong_link.fits(&route));
    }

    #[test]
    fn the_largest_entry_fits_the_bound() {
        let ns = vec![b'n'; MAX_NAMESPACE_LEN];
        let key = [0xFF; 32];
        let member = |i: u8| vec![i; MAX_MEMBER_ID_LEN];
        let biggest_record = |i: u8| ArrivalRecord {
            member_id: member(i),
            namespace: ns.clone(),
            key,
            index: u64::MAX,
            running_hash: [0xFF; 32],
        };
        let entry = RouteEntry {
            namespace: ns.clone(),
            key,
            value: vec![0xFF; MAX_VALUE_LEN],
            seat: member(4),
            position: ROUTE_LEN - 1,
            chain: (0..(ROUTE_LEN - 1) as u8)
                .map(|i| ChainSlot::Taken(biggest_record(i)))
                .collect(),
        };
        let bytes = entry.encode();
        assert!(
            bytes.len() <= MAX_ENTRY_BYTES,
            "{} bytes exceed MAX_ENTRY_BYTES {}",
            bytes.len(),
            MAX_ENTRY_BYTES
        );
        assert_eq!(RouteEntry::decode(&bytes).as_ref(), Some(&entry));
    }

    #[test]
    fn three_links_are_final_two_preserved_one_leader_held() {
        assert_eq!(ChainState::of_links(0), None);
        assert_eq!(ChainState::of_links(1), Some(ChainState::LeaderHeld));
        assert_eq!(ChainState::of_links(2), Some(ChainState::Preserved));
        assert_eq!(ChainState::of_links(FINAL_LINKS), Some(ChainState::Final));
        assert_eq!(ChainState::of_links(ROUTE_LEN), Some(ChainState::Final));
    }

    // ── evaluate: storage spec §9 ──────────────────────────────────────────

    use super::fixtures::{recognize_ok, Cell};

    const NS: &[u8] = b"DSM/test-cell";

    fn cell() -> Cell {
        Cell::new(NS, [0x5A; 32], [0x3C; 32])
    }

    fn held(state: ChainState, object: &[u8]) -> Result<CellReading<Vec<u8>>, Missing> {
        Ok(CellReading::Held {
            object: object.to_vec(),
            id: crate::storage_cell::entry_digest(object),
            state,
        })
    }

    /// Finality 4: an unread leader leaves the cell waiting, however many
    /// later seats hold the value.
    #[test]
    fn an_unread_leader_is_missing_and_no_other_seat_stands_in() {
        let mut c = cell();
        c.write(b"ok-x", ROUTE_LEN - 1, &[]);
        let mut ev = c.evidence();
        ev.seats[0].values = None;
        assert_eq!(evaluate(&ev, recognize_ok), Err(Missing::LeaderUnread));
        ev.seats.clear();
        assert_eq!(evaluate(&ev, recognize_ok), Err(Missing::LeaderUnread));
    }

    #[test]
    fn a_leader_holding_no_recognized_value_leaves_the_cell_open() {
        let mut c = cell();
        c.write(b"junk", ROUTE_LEN - 1, &[]);
        c.put(0, b"not a route entry".to_vec());
        assert_eq!(evaluate(&c.evidence(), recognize_ok), Ok(CellReading::Open));
    }

    /// Rule 3: bytes that are not a recognized object naming the cell never
    /// count, so junk written to the leader first blocks nothing.
    #[test]
    fn junk_first_at_the_leader_blocks_nothing() {
        let mut c = cell();
        c.put(0, b"not a route entry".to_vec());
        c.write(b"junk", 0, &[]);
        c.write(b"ok-x", ROUTE_LEN - 1, &[]);
        assert_eq!(
            evaluate(&c.evidence(), recognize_ok),
            held(ChainState::Final, b"ok-x")
        );
    }

    /// Rule 3 and finality 2: the first recognized value at the leader holds
    /// the cell. A later value's copies carry its own leader record, which
    /// is not the leader link, so its chain never counts.
    #[test]
    fn the_first_recognized_value_at_the_leader_holds_the_cell() {
        let mut c = cell();
        c.write(b"ok-a", 0, &[]);
        c.write(b"ok-b", ROUTE_LEN - 1, &[]);
        assert_eq!(
            evaluate(&c.evidence(), recognize_ok),
            held(ChainState::LeaderHeld, b"ok-a")
        );
    }

    /// Rule 7: the leader link is checkable only once a ByteCommit of the
    /// leader's commits its record.
    #[test]
    fn a_leader_link_counts_only_once_a_byte_commit_commits_it() {
        let mut c = cell();
        c.put(0, b"not a route entry".to_vec());
        let before = c.commit(0);
        c.write(b"ok-x", ROUTE_LEN - 1, &[]);
        let mut ev = c.evidence();
        ev.seats[0].committed = None;
        assert_eq!(
            evaluate(&ev, recognize_ok),
            Err(Missing::LeaderLinkUncommitted)
        );
        ev.seats[0].committed = before;
        assert_eq!(
            evaluate(&ev, recognize_ok),
            Err(Missing::LeaderLinkUncommitted),
            "a ByteCommit closed before the value arrived commits nothing of it"
        );
    }

    /// Finality: the state is the count of positions with a valid link.
    #[test]
    fn the_state_is_the_count_of_valid_links() {
        for (last, state) in [
            (0, ChainState::LeaderHeld),
            (1, ChainState::Preserved),
            (2, ChainState::Final),
            (ROUTE_LEN - 1, ChainState::Final),
        ] {
            let mut c = cell();
            c.write(b"ok-x", last, &[]);
            assert_eq!(
                evaluate(&c.evidence(), recognize_ok),
                held(state, b"ok-x"),
                "written through position {last}"
            );
        }
    }

    /// Rule 4: a later link counts only when its seat's own mirror of the
    /// leader's ByteCommits covers the leader link.
    #[test]
    fn a_later_link_needs_its_seats_mirror_of_the_leader_link() {
        let mut c = cell();
        c.put(0, b"not a route entry".to_vec());
        let stale = c.commit(0);
        c.write(b"ok-x", ROUTE_LEN - 1, &[]);
        let mut ev = c.evidence();
        for seat in ev.seats.iter_mut().skip(1) {
            seat.leader_seen = None;
        }
        assert_eq!(
            evaluate(&ev, recognize_ok),
            held(ChainState::LeaderHeld, b"ok-x")
        );
        for seat in ev.seats.iter_mut().skip(1) {
            seat.leader_seen = stale.clone();
        }
        assert_eq!(
            evaluate(&ev, recognize_ok),
            held(ChainState::LeaderHeld, b"ok-x"),
            "a mirror older than the leader link does not cover it"
        );
    }

    /// Rules 4 and 7: a later link needs its own seat's ByteCommit, and a
    /// copy that carries a link which is not valid is not a link either.
    #[test]
    fn a_later_link_needs_its_own_byte_commit_and_valid_carried_links() {
        let mut c = cell();
        c.write(b"ok-x", ROUTE_LEN - 1, &[]);
        let mut ev = c.evidence();
        ev.seats[1].committed = None;
        assert_eq!(
            evaluate(&ev, recognize_ok),
            held(ChainState::LeaderHeld, b"ok-x"),
            "every later copy carries the uncommitted link at position 1"
        );
    }

    /// Rule 5: an empty is never a link, and a copy that carries one still
    /// counts.
    #[test]
    fn an_empty_neither_counts_nor_invalidates() {
        for (silent, state) in [
            (vec![1], ChainState::Final),
            (vec![1, 2], ChainState::Final),
            (vec![1, 2, 3], ChainState::Preserved),
        ] {
            let mut c = cell();
            c.write(b"ok-x", ROUTE_LEN - 1, &silent);
            assert_eq!(
                evaluate(&c.evidence(), recognize_ok),
                held(state, b"ok-x"),
                "silent at {silent:?}"
            );
        }
    }

    /// Rule 4: a later link's chain begins with the leader link. Copies whose
    /// chain begins with an empty never count, even when the leader holds the
    /// same value.
    #[test]
    fn a_copy_whose_chain_does_not_begin_with_the_leader_link_does_not_count() {
        let mut c = cell();
        c.write(b"ok-x", 0, &[]);
        c.write(b"ok-x", 2, &[0]);
        assert_eq!(
            evaluate(&c.evidence(), recognize_ok),
            held(ChainState::LeaderHeld, b"ok-x")
        );
    }

    /// A copy counts only at its own route position and seat, and only for
    /// the value the leader link records.
    #[test]
    fn a_copy_at_another_position_or_of_another_value_does_not_count() {
        let mut c = cell();
        c.write(b"ok-x", 0, &[]);
        let leader_link = ChainSlot::Link(record_of(c.route.leader(), NS, &c.key, &c.logs[0]));
        let at_one = RouteEntry::at_leader(NS.to_vec(), c.key, b"ok-x".to_vec(), &c.route)
            .next(leader_link.clone(), &c.route)
            .expect("position 1");
        c.put(2, at_one.encode());
        let other_value = RouteEntry::at_leader(NS.to_vec(), c.key, b"ok-y".to_vec(), &c.route)
            .next(leader_link, &c.route)
            .expect("position 1");
        c.put(1, other_value.encode());
        assert_eq!(
            evaluate(&c.evidence(), recognize_ok),
            held(ChainState::LeaderHeld, b"ok-x")
        );
    }
}
