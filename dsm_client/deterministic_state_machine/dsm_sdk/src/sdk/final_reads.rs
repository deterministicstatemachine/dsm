// SPDX-License-Identifier: Apache-2.0

//! Reads whose answer never changes, kept for the life of the process.
//!
//! - An immutable object is its bytes: kept only once they re-hash to the
//!   address they were asked for, so what is kept is the object.
//! - A cell whose reads Core evaluated as showing a final value holds that
//!   value for good (storage spec §9, finality 2): those reads are kept, and
//!   Core evaluates them again on every use. The SoFi reader already kept
//!   them for one verification; here every walk, and every later
//!   verification, starts from what an earlier one read.
//!
//! Nothing else is kept. An open or undecided cell, or an object no member
//! served, is read again each time: it may have been written since. What is
//! kept is evidence, never a verdict. Each store is bounded by bytes; past
//! the bound the earliest kept goes first, and is read again when asked for.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;

use dsm::crypto::domain::TaggedHashDomain;
use dsm::route_chain::{CellEvidence, RoutedCell};

/// Bytes of immutable objects kept.
const OBJECT_BUDGET: usize = 16 * 1024 * 1024;

/// Bytes of final cells' reads kept.
const CELL_BUDGET: usize = 24 * 1024 * 1024;

/// What one seat's commitments and proofs are counted as, beside the values
/// it holds: two ByteCommits and an inclusion proof each, at most.
const SEAT_PROOF_BYTES: usize = 20 * 1024;

/// A cell as its reading depends on it: the namespace and key it is read at,
/// and the seed and committed set its route is derived from.
pub(crate) type CellKey = (Vec<u8>, [u8; 32], [u8; 32], [u8; 32]);

pub(crate) fn cell_key(cell: &RoutedCell) -> CellKey {
    (
        cell.namespace().to_vec(),
        *cell.key(),
        *cell.seed(),
        *cell.committed_set_id(),
    )
}

/// Entries kept in the order they were kept, within a byte budget.
struct Bounded<K, V> {
    entries: HashMap<K, (V, usize)>,
    order: VecDeque<K>,
    bytes: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> Bounded<K, V> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        }
    }

    fn get(&self, key: &K) -> Option<V> {
        self.entries.get(key).map(|(value, _)| value.clone())
    }

    /// Keep `value` under `key`, making room by letting the earliest go. A
    /// value larger than the whole budget is not kept.
    fn keep(&mut self, key: K, value: V, size: usize, budget: usize) {
        if size > budget || self.entries.contains_key(&key) {
            return;
        }
        while self.bytes + size > budget {
            let Some(earliest) = self.order.pop_front() else {
                break;
            };
            if let Some((_, gone)) = self.entries.remove(&earliest) {
                self.bytes -= gone;
            }
        }
        self.bytes += size;
        self.order.push_back(key.clone());
        self.entries.insert(key, (value, size));
    }
}

static OBJECTS: once_cell::sync::Lazy<Mutex<Bounded<[u8; 32], Vec<u8>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Bounded::new()));

/// Objects this process read `Stored` (storage spec §5 rule 6), apart from
/// the objects one member served: those are their bytes, but not `Stored`.
static STORED_OBJECTS: once_cell::sync::Lazy<Mutex<Bounded<[u8; 32], Vec<u8>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Bounded::new()));

static FINAL_CELLS: once_cell::sync::Lazy<Mutex<Bounded<CellKey, CellEvidence>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Bounded::new()));

/// A panic elsewhere while a store's lock was held leaves every entry whole:
/// an entry is inserted in one step, so the store is still read.
fn lock<T>(store: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The immutable object at `addr`, when it is kept.
pub(crate) fn object(addr: &[u8; 32]) -> Option<Vec<u8>> {
    lock(&OBJECTS).get(addr)
}

/// Keep `bytes` as the object at `addr` under `namespace`, only when they
/// re-hash to it.
pub(crate) fn keep_object(namespace: TaggedHashDomain<'_>, addr: &[u8; 32], bytes: &[u8]) {
    if dsm::storage_object::immutable_addr(namespace, bytes) != *addr {
        return;
    }
    lock(&OBJECTS).keep(*addr, bytes.to_vec(), bytes.len(), OBJECT_BUDGET);
}

/// The bytes at `addr` this process read `Stored`, when kept.
pub(crate) fn stored_object(addr: &[u8; 32]) -> Option<Vec<u8>> {
    lock(&STORED_OBJECTS).get(addr)
}

/// Keep `bytes`, which Core read `Stored` at `addr`: Core established them
/// as the object there, so nothing here hashes them again.
pub(crate) fn keep_stored_object(addr: &[u8; 32], bytes: &[u8]) {
    lock(&STORED_OBJECTS).keep(*addr, bytes.to_vec(), bytes.len(), OBJECT_BUDGET);
}

/// The reads of `cell` Core evaluated as showing a final value, when kept.
pub(crate) fn final_cell(cell: &RoutedCell) -> Option<CellEvidence> {
    lock(&FINAL_CELLS).get(&cell_key(cell))
}

/// Keep reads of `cell` that Core evaluated as showing a final value there.
/// The caller holds that evaluation; nothing here evaluates.
pub(crate) fn keep_final_cell(cell: &RoutedCell, evidence: &CellEvidence) {
    let size = evidence
        .seats
        .iter()
        .map(|seat| SEAT_PROOF_BYTES + seat.values.iter().flatten().map(Vec::len).sum::<usize>())
        .sum();
    lock(&FINAL_CELLS).keep(cell_key(cell), evidence.clone(), size, CELL_BUDGET);
}

/// Forget everything kept, where a test stands in for a fresh start: a node
/// set that starts is a fresh fleet, in which nothing has been written (tests
/// reuse identities, and so cells, over fleets that start empty), and a
/// device the harness enters is a process of its own, which starts from what
/// it read itself.
#[cfg(test)]
pub(crate) fn forget_everything() {
    *lock(&OBJECTS) = Bounded::new();
    *lock(&STORED_OBJECTS) = Bounded::new();
    *lock(&FINAL_CELLS) = Bounded::new();
    // The walks' judgements stand on cells read final in the same world.
    crate::sdk::sofi_reads::forget_judgements();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The earliest kept goes first once the budget is reached, and a value
    /// larger than the whole budget is never kept.
    #[test]
    fn the_earliest_goes_first_past_the_budget() {
        let mut kept: Bounded<u8, u8> = Bounded::new();
        kept.keep(1, 10, 4, 10);
        kept.keep(2, 20, 4, 10);
        kept.keep(3, 30, 4, 10);
        assert_eq!(kept.get(&1), None);
        assert_eq!(kept.get(&2), Some(20));
        assert_eq!(kept.get(&3), Some(30));
        assert_eq!(kept.bytes, 8);
        kept.keep(4, 40, 11, 10);
        assert_eq!(kept.get(&4), None);
        assert_eq!(kept.bytes, 8);
    }

    /// Bytes that do not re-hash to the address are not the object there,
    /// and are not kept as it.
    #[test]
    fn only_the_object_itself_is_kept() {
        let namespace = dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST;
        let bytes = b"final-reads object".to_vec();
        let addr = dsm::storage_object::immutable_addr(namespace, &bytes);
        let mut other = addr;
        other[0] ^= 1;
        keep_object(namespace, &other, &bytes);
        assert_eq!(object(&other), None);
        keep_object(namespace, &addr, &bytes);
        assert_eq!(object(&addr), Some(bytes));
    }
}
