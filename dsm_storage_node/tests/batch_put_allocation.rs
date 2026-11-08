// SPDX-License-Identifier: Apache-2.0
//! A batch put is refused by its entry count before its entries are decoded.
//! A body of empty entries is two bytes an entry, and each decoded entry is a
//! struct of three vectors, so decoding a 1 MiB body of them before counting
//! would take tens of megabytes for one request. This binary counts every
//! allocation the process makes, so what the refusal took is measured, not
//! inferred.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use dsm_storage_node::api::cells::decode_batch;
use prost::Message;

/// The system allocator, counting the bytes live and the most ever live.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed on unchanged.
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract for `dealloc` is passed on unchanged.
        unsafe { System.dealloc(block, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The bytes `decode` took at its peak above what was live before it.
fn peak_taken<T>(decode: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let out = decode();
    (out, PEAK.load(Ordering::SeqCst).saturating_sub(before))
}

fn batch(entries: u64) -> Vec<u8> {
    dsm::types::proto::CellPutsV1 {
        entries: (0..entries)
            .map(|i| {
                let mut key = vec![0x4b; 32];
                key[..8].copy_from_slice(&i.to_be_bytes());
                dsm::types::proto::CellPutV1 {
                    namespace: b"DSM/batch-allocation".to_vec(),
                    key,
                    value: b"v".to_vec(),
                }
            })
            .collect(),
    }
    .encode_to_vec()
}

/// One test in this binary, so no other test's allocations land in the count.
#[test]
fn a_body_of_empty_entries_is_refused_before_one_is_decoded() {
    // 524,288 empty entries: the whole 1 MiB body limit.
    let hostile = [0x0au8, 0x00].repeat(524_288);
    let (answer, taken) = peak_taken(|| decode_batch(&hostile));
    match answer {
        Ok(decoded) => panic!("a batch of {} entries was decoded", decoded.entries.len()),
        Err(status) => assert_eq!(status, StatusCode::BAD_REQUEST),
    }
    assert!(
        taken < 64 * 1024,
        "refusing a batch of 524,288 entries took {taken} bytes; counting them takes none"
    );

    // The count refuses only what is over the limit: a batch of 16 entries
    // decodes whole, and one of 17, or of none, is refused.
    match decode_batch(&batch(16)) {
        Ok(decoded) => assert_eq!(decoded.entries.len(), 16),
        Err(status) => panic!("a batch of 16 entries was refused: {status}"),
    }
    match decode_batch(&batch(17)) {
        Ok(decoded) => panic!("a batch of {} entries was decoded", decoded.entries.len()),
        Err(status) => assert_eq!(status, StatusCode::BAD_REQUEST),
    }
    match decode_batch(&[]) {
        Ok(decoded) => panic!("an empty body decoded as {} entries", decoded.entries.len()),
        Err(status) => assert_eq!(status, StatusCode::BAD_REQUEST),
    }
}
