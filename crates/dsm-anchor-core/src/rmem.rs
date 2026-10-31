//! The appliance's durable record in TROPIC01 R-memory (§26): an [`ActiveStore`] over slots that
//! are erased and written one at a time.
//!
//! A slot cannot be rewritten in place (a write to a written slot is refused, so a rewrite is an
//! erase and then a write), and a record is larger than a slot. The record is therefore kept in
//! two banks of slots, each named by one of two headers. A write goes to the bank the current
//! record is not in, and only then to the header slot the current record's header is not in. Each
//! header carries a sequence number and the digest of its record; a read takes the highest
//! sequence whose bank still hashes to its digest. A power cut at any erase or write, torn writes
//! included, leaves either the new record or the one before it.

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
            match self.memory.read(self.bank_slot(header.bank, index))? {
                Some(chunk) if chunk.len() == want => record.extend_from_slice(&chunk),
                Some(_) | None => return Ok(None),
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
            if let Some(bytes) = self.memory.read(slot)? {
                written += 1;
                if let Some(header) = Header::decode(&bytes) {
                    found.push(header);
                }
            }
        }
        found.sort_by_key(|header| core::cmp::Reverse(header.seq));
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
            self.memory.erase(slot)?;
            self.memory.write(slot, chunk)?;
        }
        let header = Header {
            seq,
            bank,
            len,
            digest: h(domain::RMEM_RECORD_V1, &[record]),
        };
        let slot = self.header_slot(seq);
        self.memory.erase(slot)?;
        self.memory.write(slot, &header.encode())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.current()?.map(|(_, record)| record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::fmt::Debug;

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
    }

    impl Memory {
        fn new(slots: u16, capacity: usize) -> Self {
            Self {
                slots: vec![None; usize::from(slots)],
                capacity,
                budget: None,
            }
        }

        fn spend(&mut self) -> Result<(), StoreError> {
            match self.budget {
                Some(0) => Err(StoreError::Unavailable),
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
            Ok(self.slots[usize::from(slot)].clone())
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
            self.slots[usize::from(slot)] = Some(data.to_vec());
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
                Err(e) => assert_eq!(e, StoreError::Unavailable),
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
                Err(e) => assert_eq!(e, StoreError::Unavailable),
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
