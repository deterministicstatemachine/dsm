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
    NotFiveMembers { members: usize },
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
    /// The state a count of valid links, the leader's included, amounts to.
    pub fn of_links(valid_links: usize) -> Option<Self> {
        match valid_links {
            0 => None,
            1 => Some(ChainState::LeaderHeld),
            2 => Some(ChainState::Preserved),
            _ => Some(ChainState::Final),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> StorageSetMembers {
        let entries: Vec<(&[u8], [u8; 32])> =
            ids.iter().map(|m| (m.as_bytes(), [7u8; 32])).collect();
        StorageSetMembers::new(&entries).expect("set")
    }

    fn five() -> StorageSetMembers {
        set(&["dsm-node-1", "dsm-node-2", "dsm-node-3", "dsm-node-4", "dsm-node-5"])
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
        let ids: Vec<Vec<u8>> = five().entries().iter().map(|e| e.member_id().to_vec()).collect();
        assert_eq!(route.seats(), permute(&seed, &ids).expect("permute").as_slice());
        assert_eq!(route.leader(), route.seats()[0].as_slice());
        assert_ne!(Route::of(&[4u8; 32], &five()).expect("route"), route, "the seed decides");
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
        assert!(last.next(ChainSlot::NoResponse, &route).is_none(), "no position past the route");
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
        assert_eq!(RouteEntry::decode(&prost::Message::encode_to_vec(&p)), None, "a slot missing");

        let mut p = good.to_proto();
        p.position = ROUTE_LEN as u32;
        assert_eq!(RouteEntry::decode(&prost::Message::encode_to_vec(&p)), None, "off the route");

        let mut other = record(route.leader(), &ns, key, 1);
        other.key = [2u8; 32];
        let mut p = good.to_proto();
        p.chain = vec![ChainSlot::Link(other).to_proto()];
        assert_eq!(RouteEntry::decode(&prost::Message::encode_to_vec(&p)), None, "another cell's record");

        let mut p = good.to_proto();
        p.chain = vec![proto::ChainSlotV1 { kind: None }];
        assert_eq!(RouteEntry::decode(&prost::Message::encode_to_vec(&p)), None, "an empty slot");

        // The same entry under another byte string: a field repeated at the
        // end (protobuf keeps the last scalar) decodes to an equal message,
        // and must still be refused.
        let mut noncanonical = good.encode();
        noncanonical.extend_from_slice(&prost::Message::encode_to_vec(&proto::RouteEntryV1 {
            position: 1,
            ..Default::default()
        }));
        assert_eq!(RouteEntry::decode(&noncanonical), None, "a non-canonical encoding");
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
}
