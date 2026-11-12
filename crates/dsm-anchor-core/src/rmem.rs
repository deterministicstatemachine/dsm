//! The appliance's durable record in TROPIC01 R-memory (§26): an [`ActiveStore`] over slots that
//! are erased and written one at a time.
//!
//! A slot cannot be rewritten in place (a write to a written slot is refused, so a rewrite is an
//! erase and then a write), and a record is larger than a slot. The record is therefore kept in
//! two banks of slots, each named by one of two headers. A write goes to the bank the current
//! record is not in, and only then to the header slot the current record's header is not in. Each
//! header carries a sequence number and the digest of its record; a read takes the highest
//! sequence whose bank still hashes to its digest. A power cut at any erase or write, torn writes
//! included, leaves either the new record or the one before it: a slot the chip will not give back
//! ([`StoreError::Unreadable`]) is a slot holding no record, never a failure of the store, and an
//! erased slot may be answered either way.
//!
//! Every slot is read back before anything depends on it. A worn slot that does not hold what was
//! written fails the write with the record before it still in force.

use alloc::vec::Vec;

use crate::domain;
use crate::durable::{ActiveStore, StoreError};
use crate::hash::h;
use crate::util::{ct_eq_32, u32_le};

/// Slots erased and written one at a time: TROPIC01 R-memory, or a model of it.
pub trait SlotMemory {
    /// Bytes one slot holds.
    fn capacity(&self) -> usize;
    /// Slots the memory has, numbered from 0.
    fn slots(&self) -> u16;
    /// The bytes a slot holds; `None` for an erased slot.
    fn read(&mut self, slot: u16) -> Result<Option<Vec<u8>>, StoreError>;
    /// Erase a slot.
    fn erase(&mut self, slot: u16) -> Result<(), StoreError>;
    /// Write an erased slot.
    fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError>;
}

/// Forward `SlotMemory` through a `Box`, so a firmware can hold its store in a `'static` slot with
/// the (unnameable) chip session erased behind `Box<dyn SlotMemory>`.
impl<M: SlotMemory + ?Sized> SlotMemory for alloc::boxed::Box<M> {
    fn capacity(&self) -> usize {
        (**self).capacity()
    }
    fn slots(&self) -> u16 {
        (**self).slots()
    }
    fn read(&mut self, slot: u16) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).read(slot)
    }
    fn erase(&mut self, slot: u16) -> Result<(), StoreError> {
        (**self).erase(slot)
    }
    fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
        (**self).write(slot, data)
    }
}

/// Slots lent for a while, as a try-run borrows them.
impl<M: SlotMemory + ?Sized> SlotMemory for &mut M {
    fn capacity(&self) -> usize {
        (**self).capacity()
    }
    fn slots(&self) -> u16 {
        (**self).slots()
    }
    fn read(&mut self, slot: u16) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).read(slot)
    }
    fn erase(&mut self, slot: u16) -> Result<(), StoreError> {
        (**self).erase(slot)
    }
    fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
        (**self).write(slot, data)
    }
}

/// The most slots a bank of the trial store takes: 28 KiB, larger than any record.
const TRIAL_BANK_SLOTS: u16 = 64;

/// Why a store could not be laid out over a memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutError {
    /// The memory's slots hold no header.
    SlotTooSmall,
    /// Two headers and two banks for the largest record do not fit from the first slot.
    OutOfSlots,
}

const HEADER_LEN: usize = 8 + 1 + 4 + 32 + 32;

struct Header {
    seq: u64,
    bank: u8,
    len: u32,
    digest: [u8; 32],
}

impl Header {
    fn seal(&self) -> [u8; 32] {
        h(
            domain::RMEM_HEADER_V1,
            &[
                &self.seq.to_le_bytes(),
                &[self.bank],
                &u32_le(self.len),
                &self.digest,
            ],
        )
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.push(self.bank);
        out.extend_from_slice(&u32_le(self.len));
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.seal());
        out
    }

    /// A header written in full; a torn or foreign slot decodes to nothing.
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HEADER_LEN {
            return None;
        }
        let seal: [u8; 32] = core::array::from_fn(|i| bytes[45 + i]);
        let header = Self {
            seq: u64::from_le_bytes(core::array::from_fn(|i| bytes[i])),
            bank: bytes[8],
            len: u32::from_le_bytes(core::array::from_fn(|i| bytes[9 + i])),
            digest: core::array::from_fn(|i| bytes[13 + i]),
        };
        (header.bank < 2 && ct_eq_32(&header.seal(), &seal)).then_some(header)
    }
}

/// The record in two banks of slots named by two headers.
pub struct SlottedStore<M: SlotMemory> {
    memory: M,
    first: u16,
    bank_slots: u16,
}

impl<M: SlotMemory> SlottedStore<M> {
    /// Lay the store out from slot `first`: two header slots, then two banks each large enough
    /// for a record of `record_max` bytes.
    pub fn new(memory: M, first: u16, record_max: usize) -> Result<Self, LayoutError> {
        let capacity = memory.capacity();
        if capacity < HEADER_LEN {
            return Err(LayoutError::SlotTooSmall);
        }
        let bank_slots = record_max.div_ceil(capacity);
        if usize::from(first) + 2 + 2 * bank_slots > usize::from(memory.slots()) {
            return Err(LayoutError::OutOfSlots);
        }
        // At most the memory's slot count, so it is a slot number.
        let bank_slots = bank_slots as u16;
        Ok(Self {
            memory,
            first,
            bank_slots,
        })
    }

    /// The memory under the store.
    pub fn memory(&self) -> &M {
        &self.memory
    }

    fn header_slot(&self, seq: u64) -> u16 {
        self.first + (seq % 2) as u16
    }

    fn bank_slot(&self, bank: u8, index: u16) -> u16 {
        self.first + 2 + u16::from(bank) * self.bank_slots + index
    }

    fn record_of(&mut self, header: &Header) -> Result<Option<Vec<u8>>, StoreError> {
        let capacity = self.memory.capacity();
        let len = header.len as usize;
        if len > usize::from(self.bank_slots) * capacity {
            return Ok(None);
        }
        let mut record = Vec::with_capacity(len);
        let mut index = 0u16;
        while record.len() < len {
            let want = core::cmp::min(capacity, len - record.len());
            match self.memory.read(self.bank_slot(header.bank, index)) {
                Ok(Some(chunk)) if chunk.len() == want => record.extend_from_slice(&chunk),
                Ok(Some(_) | None) | Err(StoreError::Unreadable) => return Ok(None),
                Err(e) => return Err(e),
            }
            index += 1;
        }
        let digest = h(domain::RMEM_RECORD_V1, &[&record]);
        Ok(ct_eq_32(&digest, &header.digest).then_some(record))
    }

    /// The headers written in full, highest sequence first, and how many header slots hold bytes.
    fn headers(&mut self) -> Result<(Vec<Header>, usize), StoreError> {
        let mut found = Vec::new();
        let mut written = 0usize;
        for slot in [self.first, self.first + 1] {
            match self.memory.read(slot) {
                Ok(Some(bytes)) => {
                    written += 1;
                    if let Some(header) = Header::decode(&bytes) {
                        found.push(header);
                    }
                }
                // Tropic Square's firmware answers an erased slot with no bytes and its datasheet says
                // FAIL, which cannot be told from a slot the chip will not give back. Neither is a
                // header. A cut can leave one such slot beside a good header, never two: an anchor
                // that finds none is unprovisioned, and a caged chip refuses that at `ready_for_birth`.
                Ok(None) | Err(StoreError::Unreadable) => {}
                Err(e) => return Err(e),
            }
        }
        // Two at most, and a general sort would cost 4 KiB of stack and its code to order them.
        if let [first, second] = found.as_mut_slice() {
            if first.seq < second.seq {
                core::mem::swap(first, second);
            }
        }
        Ok((found, written))
    }

    /// The current record and its sequence number.
    fn current(&mut self) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        let (headers, written) = self.headers()?;
        let no_header = headers.is_empty();
        for header in headers {
            if let Some(record) = self.record_of(&header)? {
                return Ok(Some((header.seq, record)));
            }
        }
        // No header decodes. Only the first write can leave that state honestly: its header torn
        // in the one slot it was writing, the other never written. Then nothing was born.
        if written <= 1 && no_header {
            return Ok(None);
        }
        Err(StoreError::Corrupt)
    }

    /// `data` in `slot`, read back. Nothing is written over a record the store depends on: a bank
    /// is the one the current record is not in, and a header the one its header is not in.
    fn write_held(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
        self.memory.erase(slot)?;
        self.memory.write(slot, data)?;
        match self.memory.read(slot) {
            Ok(Some(held)) if held == data => Ok(()),
            Ok(Some(_) | None) | Err(StoreError::Unreadable) => Err(StoreError::NotHeld),
            Err(e) => Err(e),
        }
    }

    /// This store's own code over the slots past its banks, where no record is ever read from.
    fn trial(&mut self) -> SlottedStore<&mut M> {
        let first = self.first + 2 + 2 * self.bank_slots;
        let room = self.memory.slots().saturating_sub(first).saturating_sub(2) / 2;
        SlottedStore {
            memory: &mut self.memory,
            first,
            bank_slots: core::cmp::min(room, TRIAL_BANK_SLOTS),
        }
    }
}

impl<M: SlotMemory> ActiveStore for SlottedStore<M> {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        let capacity = self.memory.capacity();
        if record.len() > usize::from(self.bank_slots) * capacity
            || record.len() > u32::MAX as usize
        {
            return Err(StoreError::TooLarge);
        }
        let len = record.len() as u32;
        let seq = match self.current() {
            Ok(Some((seq, _))) => seq + 1,
            Ok(None) => 1,
            Err(e) => return Err(e),
        };
        let bank = (seq % 2) as u8;
        for (index, chunk) in record.chunks(capacity).enumerate() {
            let slot = self.bank_slot(bank, index as u16);
            self.write_held(slot, chunk)?;
        }
        let header = Header {
            seq,
            bank,
            len,
            digest: h(domain::RMEM_RECORD_V1, &[record]),
        };
        let slot = self.header_slot(seq);
        self.write_held(slot, &header.encode())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.current()?.map(|(_, record)| record))
    }

    /// The first slot of each of the record's own banks: erased, written, read back, erased. Only
    /// with no record in the store, whose banks no header names, so a power cut leaves nothing a
    /// read would ever take. The trial store's slots say nothing about the access rules on these.
    fn try_record(&mut self, record: &[u8]) -> Result<(), StoreError> {
        if self.current()?.is_some() {
            return Err(StoreError::Refused);
        }
        let chunk = &record[..core::cmp::min(self.memory.capacity(), record.len())];
        for bank in 0..2u8 {
            let slot = self.bank_slot(bank, 0);
            self.write_held(slot, chunk)?;
            self.memory.erase(slot)?;
        }
        Ok(())
    }

    fn trial_write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.trial().write(record)
    }

    fn trial_read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        self.trial().read()
    }

    fn trial_clear(&mut self) -> Result<(), StoreError> {
        // Erased without asking: a cut write can read as empty and still not be erased.
        let trial = self.trial();
        for slot in trial.first..trial.first + 2 + 2 * trial.bank_slots {
            trial.memory.erase(slot)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tropic::{ChipLink, TropicError};
    use alloc::vec;
    use core::fmt::Debug;

    /// A power cut, as the chip's driver gives it: a chip with no power never reports itself ready.
    const CUT: StoreError = StoreError::Chip(TropicError::Comm(ChipLink::Busy));

    fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(e) => panic!("{what}: {e:?}"),
        }
    }

    /// R-memory as the chip keeps it: slots erased and written one at a time, a write to a written
    /// slot refused. Power fails after `budget` operations: the failing write leaves the first
    /// half of its bytes, and nothing after it happens.
    struct Memory {
        slots: Vec<Option<Vec<u8>>>,
        capacity: usize,
        budget: Option<usize>,
        /// Slots the chip answers but will not give back.
        unreadable: Vec<u16>,
        /// Slots that keep none of what is written to them, as a worn one does.
        worn: Vec<u16>,
        /// Reads answered with this failure of the bus.
        read_fault: Option<StoreError>,
        /// How the chip answers an erased slot.
        erased: Erased,
    }

    /// Tropic Square's firmware answers an erased slot with no bytes. Its datasheet says FAIL.
    #[derive(Clone, Copy, PartialEq)]
    enum Erased {
        NoBytes,
        Fail,
    }

    impl Memory {
        fn new(slots: u16, capacity: usize) -> Self {
            Self {
                slots: vec![None; usize::from(slots)],
                capacity,
                budget: None,
                unreadable: Vec::new(),
                worn: Vec::new(),
                read_fault: None,
                erased: Erased::NoBytes,
            }
        }

        fn spend(&mut self) -> Result<(), StoreError> {
            match self.budget {
                Some(0) => Err(CUT),
                Some(n) => {
                    self.budget = Some(n - 1);
                    Ok(())
                }
                None => Ok(()),
            }
        }
    }

    impl SlotMemory for Memory {
        fn capacity(&self) -> usize {
            self.capacity
        }
        fn slots(&self) -> u16 {
            self.slots.len() as u16
        }
        fn read(&mut self, slot: u16) -> Result<Option<Vec<u8>>, StoreError> {
            if let Some(fault) = self.read_fault {
                return Err(fault);
            }
            let held = self.slots[usize::from(slot)].clone();
            if self.unreadable.contains(&slot) || (self.erased == Erased::Fail && held.is_none()) {
                return Err(StoreError::Unreadable);
            }
            Ok(held)
        }
        fn erase(&mut self, slot: u16) -> Result<(), StoreError> {
            self.spend()?;
            self.slots[usize::from(slot)] = None;
            Ok(())
        }
        fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
            assert!(
                self.slots[usize::from(slot)].is_none(),
                "a written slot is never written"
            );
            if let Err(cut) = self.spend() {
                self.slots[usize::from(slot)] = Some(data[..data.len() / 2].to_vec());
                return Err(cut);
            }
            let keep = if self.worn.contains(&slot) {
                vec![0u8; data.len()]
            } else {
                data.to_vec()
            };
            self.slots[usize::from(slot)] = Some(keep);
            Ok(())
        }
    }

    fn record(len: usize, fill: u8) -> Vec<u8> {
        (0..len).map(|i| fill ^ (i as u8)).collect()
    }

    #[test]
    fn a_record_larger_than_a_slot_reads_back_whole_and_the_latest_wins() {
        let mut store = ok(SlottedStore::new(Memory::new(64, 100), 3, 1250), "laid out");
        assert_eq!(store.read(), Ok(None));
        for fill in 1..6u8 {
            let r = record(250 * usize::from(fill), fill);
            ok(store.write(&r), "written");
            assert_eq!(store.read(), Ok(Some(r)));
        }
    }

    #[test]
    fn a_power_cut_at_any_erase_or_write_leaves_the_new_record_or_the_one_before() {
        let before = record(730, 0x11);
        let after = record(410, 0x5C);
        let mut steps = 0usize;
        loop {
            let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 800), "laid out");
            ok(store.write(&record(500, 0x77)), "written");
            ok(store.write(&before), "written");
            store.memory.budget = Some(steps);
            let cut = store.write(&after);
            store.memory.budget = None;
            let read = ok(store.read(), "read");
            match cut {
                Ok(()) => {
                    assert_eq!(read, Some(after));
                    break;
                }
                Err(e) => assert_eq!(e, CUT),
            }
            assert_eq!(read, Some(before.clone()), "cut after {steps} operations");
            steps += 1;
        }
        assert!(
            steps > 2 * 5,
            "every erase and write of the record and its header was cut"
        );
    }

    #[test]
    fn a_power_cut_during_the_first_write_leaves_nothing_born() {
        let first = record(300, 0x42);
        let mut steps = 0usize;
        loop {
            let mut store = ok(SlottedStore::new(Memory::new(16, 128), 0, 512), "laid out");
            store.memory.budget = Some(steps);
            let cut = store.write(&first);
            store.memory.budget = None;
            let read = ok(store.read(), "read");
            match cut {
                Ok(()) => {
                    assert_eq!(read, Some(first));
                    break;
                }
                Err(e) => assert_eq!(e, CUT),
            }
            assert_eq!(read, None, "cut after {steps} operations");
            steps += 1;
        }
    }

    #[test]
    fn a_bank_changed_under_its_header_is_no_record() {
        let mut store = ok(SlottedStore::new(Memory::new(16, 96), 0, 256), "laid out");
        ok(store.write(&record(200, 0x01)), "written");
        let slot = store.bank_slot(1, 1);
        let mut chunk = match store.memory.slots[usize::from(slot)].clone() {
            Some(chunk) => chunk,
            None => panic!("the bank holds the record"),
        };
        chunk[7] ^= 0x01;
        store.memory.slots[usize::from(slot)] = Some(chunk);
        assert_eq!(store.read(), Err(StoreError::Corrupt));
    }

    #[test]
    fn a_torn_header_the_chip_will_not_give_back_leaves_the_record_before_it() {
        let held = record(200, 0x21);
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        ok(store.write(&record(150, 0x77)), "written");
        ok(store.write(&held), "written");
        // The older header's slot, as a cut in its next rewrite leaves it.
        store.memory.unreadable = vec![store.header_slot(3)];
        assert_eq!(store.read(), Ok(Some(held.clone())));
        // The newer header's: the record before it stands, and the store writes on from there.
        store.memory.unreadable = vec![store.header_slot(2)];
        assert_eq!(store.read(), Ok(Some(record(150, 0x77))));
    }

    #[test]
    fn a_torn_bank_slot_the_chip_will_not_give_back_leaves_the_record_before_it() {
        let before = record(150, 0x77);
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        ok(store.write(&before), "written");
        ok(store.write(&record(200, 0x21)), "written");
        store.memory.unreadable = vec![store.bank_slot(0, 1)];
        assert_eq!(store.read(), Ok(Some(before)));
    }

    #[test]
    fn a_first_header_torn_unreadable_leaves_nothing_born() {
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        store.memory.unreadable = vec![0];
        assert_eq!(store.read(), Ok(None));
    }

    /// The datasheet says a read of an erased slot is answered FAIL, where the firmware's source
    /// answers no bytes. A new chip must come up either way: this is every slot of it.
    #[test]
    fn a_chip_that_answers_an_erased_slot_with_fail_is_a_new_chip_and_keeps_its_records() {
        let mut memory = Memory::new(600, 96);
        memory.erased = Erased::Fail;
        let mut store = ok(SlottedStore::new(memory, 0, 960), "laid out");
        assert_eq!(store.read(), Ok(None), "nothing is born");
        ok(store.try_record(&record(150, 0x31)), "the record's slots");
        assert_eq!(store.read(), Ok(None), "the try left nothing");
        ok(store.trial_write(&record(300, 0x42)), "the trial write");
        assert_eq!(store.trial_read(), Ok(Some(record(300, 0x42))));
        ok(store.trial_clear(), "the trial clear");
        assert_eq!(store.trial_read(), Ok(None));
        ok(store.write(&record(150, 0x51)), "the first record");
        assert_eq!(store.read(), Ok(Some(record(150, 0x51))));
        ok(store.write(&record(700, 0x62)), "the next");
        assert_eq!(store.read(), Ok(Some(record(700, 0x62))));
    }

    /// Two slots the chip will not give back is what an erased chip that answers FAIL looks like. It
    /// reads as no record, and what stops that being a second birth is the cage, not this store:
    /// `chip_model::a_record_wiped_from_a_caged_chip_never_makes_it_installable_again`.
    #[test]
    fn two_header_slots_the_chip_will_not_give_back_are_no_record() {
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        store.memory.unreadable = vec![0, 1];
        assert_eq!(store.read(), Ok(None));
    }

    #[test]
    fn two_written_slots_with_no_header_were_not_left_by_a_first_write() {
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        store.memory.slots[0] = Some(vec![0x11; 40]);
        store.memory.slots[1] = Some(vec![0x22; 40]);
        assert_eq!(store.read(), Err(StoreError::Corrupt));
    }

    #[test]
    fn a_failure_of_the_bus_is_never_read_as_a_torn_slot() {
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        ok(store.write(&record(200, 0x21)), "written");
        store.memory.read_fault = Some(CUT);
        assert_eq!(store.read(), Err(CUT));
    }

    #[test]
    fn a_worn_slot_fails_its_write_and_the_record_before_it_stands() {
        let before = record(150, 0x77);
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        ok(store.write(&before), "written");
        store.memory.worn = vec![store.bank_slot(0, 1)];
        assert_eq!(store.write(&record(200, 0x21)), Err(StoreError::NotHeld));
        assert_eq!(store.read(), Ok(Some(before.clone())));
        store.memory.worn = vec![store.header_slot(2)];
        assert_eq!(store.write(&record(200, 0x21)), Err(StoreError::NotHeld));
        assert_eq!(store.read(), Ok(Some(before)));
    }

    #[test]
    fn the_trial_store_runs_the_same_code_where_no_record_is_read_from() {
        let mut store = ok(SlottedStore::new(Memory::new(64, 96), 0, 256), "laid out");
        let trial = record(250, 0x5A);
        ok(store.trial_clear(), "cleared");
        assert_eq!(store.trial_read(), Ok(None));
        ok(store.trial_write(&record(120, 0x11)), "written");
        ok(store.trial_write(&trial), "written");
        assert_eq!(store.trial_read(), Ok(Some(trial)));
        assert_eq!(store.read(), Ok(None), "the store itself holds no record");
        ok(store.trial_clear(), "cleared");
        assert!(
            store.memory.slots.iter().all(Option::is_none),
            "every slot it wrote is erased"
        );
    }

    #[test]
    fn the_trial_store_clears_a_slot_a_cut_left_unreadable() {
        let mut store = ok(SlottedStore::new(Memory::new(64, 96), 0, 256), "laid out");
        ok(store.trial_write(&record(120, 0x11)), "written");
        let first = store.trial().first;
        store.memory.unreadable = vec![first];
        ok(store.trial_clear(), "cleared");
        assert_eq!(store.memory.slots[usize::from(first)], None);
    }

    #[test]
    fn a_try_of_the_own_slots_leaves_them_erased_and_is_refused_over_a_record() {
        let mut store = ok(SlottedStore::new(Memory::new(32, 96), 0, 256), "laid out");
        ok(store.try_record(&record(250, 0x5A)), "tried");
        assert!(
            store.memory.slots.iter().all(Option::is_none),
            "every slot is erased"
        );
        store.memory.worn = vec![store.bank_slot(1, 0)];
        assert_eq!(
            store.try_record(&record(250, 0x5A)),
            Err(StoreError::NotHeld),
            "a slot that does not hold what it took fails the try"
        );
        store.memory.worn = Vec::new();
        ok(store.write(&record(200, 0x21)), "written");
        assert_eq!(
            store.try_record(&record(250, 0x5A)),
            Err(StoreError::Refused)
        );
    }

    #[test]
    fn a_record_past_its_banks_is_refused_and_a_layout_past_the_memory_is_refused() {
        // Two banks of two 96-byte slots each hold up to 192 bytes.
        let mut store = ok(SlottedStore::new(Memory::new(16, 96), 0, 128), "laid out");
        assert_eq!(store.write(&record(193, 0x09)), Err(StoreError::TooLarge));
        assert_eq!(store.read(), Ok(None));
        assert_eq!(
            SlottedStore::new(Memory::new(16, 96), 11, 128).err(),
            Some(LayoutError::OutOfSlots)
        );
        assert_eq!(
            SlottedStore::new(Memory::new(16, 40), 0, 128).err(),
            Some(LayoutError::SlotTooSmall)
        );
    }
}
