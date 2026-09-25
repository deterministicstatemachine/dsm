// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable objects and indexes over a committed storage set (storage spec
//! §5, §7), and the storage facts Core derives from them.
//!
//! Every function takes the set the caller resolved from committed state,
//! never "the configured nodes". Writes go to every member; what a member
//! answered is never counted toward anything here. Reads return what the
//! members hold, and Core decides what it establishes: `Stored(o)` from
//! three members returning the exact bytes (§5 rule 6), an index's candidate
//! order from every member's appends (§7). Raced cells are written and read
//! along their routes (`sdk::route_seats`).

use dsm::crypto::domain::TaggedHashDomain;
use dsm::sofi::storage::{Discovered, IndexCandidates, Resolved, StoredFact};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;

/// Put an immutable object at every member of `set` (§5). Returns its
/// address and how many members took it; whether it is `Stored` is read back
/// ([`read_stored_bytes`]), never inferred from this count.
pub(crate) async fn put_immutable(
    set: &StorageSet,
    namespace: TaggedHashDomain<'_>,
    payload: &[u8],
) -> Result<([u8; 32], u32), DsmError> {
    let took = SetClient::new(set)?.put_immutable(namespace, payload).await;
    Ok((
        dsm::storage_object::immutable_addr(namespace, payload),
        took,
    ))
}

/// The bytes of the object whose identity is `inner` under `namespace`, from
/// the first member whose bytes re-hash to its address. A member can fail to
/// serve an object, never substitute one. `None` when no member holds it.
pub(crate) async fn fetch_immutable(
    set: &StorageSet,
    namespace: TaggedHashDomain<'_>,
    inner: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    let addr = dsm::storage_object::immutable_addr_from_inner(namespace, inner);
    Ok(SetClient::new(set)?.fetch_verified(&addr).await)
}

/// `Stored(o)` for the object whose identity is `inner` under `namespace`
/// (§5 rule 6), derived by Core from every member's raw answer.
pub async fn read_stored_object(
    set: &StorageSet,
    namespace: TaggedHashDomain<'_>,
    inner: &[u8; 32],
) -> Result<StoredFact, DsmError> {
    let addr = dsm::storage_object::immutable_addr_from_inner(namespace, inner);
    let reads = SetClient::new(set)?.get_immutable(&addr).await;
    Ok(dsm::sofi::storage::stored(&addr, &reads))
}

/// The exact bytes at `addr` once `Stored` holds for them, `None` otherwise.
/// For a caller that holds the address rather than the identity (a vault
/// state commits its policies by address).
pub(crate) async fn read_stored_bytes(
    set: &StorageSet,
    addr: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    let reads = SetClient::new(set)?.get_immutable(addr).await;
    Ok(match dsm::sofi::storage::stored(addr, &reads) {
        StoredFact::Stored(bytes) => Some(bytes),
        StoredFact::Unavailable => None,
    })
}

/// Append `addr` under `locator` at every member of `set` (§7). Returns how
/// many members took it.
pub async fn append_to_index(
    set: &StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    addr: &[u8; 32],
) -> Result<u32, DsmError> {
    Ok(SetClient::new(set)?
        .append_index(namespace, locator, addr)
        .await)
}

/// The candidates under `locator`: every member's appends in append order,
/// members in set order, merged by Core; `Unavailable` when no member
/// answered. Reading stops at `budget` addresses per member, and Core's scan
/// applies the budget again over the merged order.
pub async fn read_index_candidates(
    set: &StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
) -> Result<IndexCandidates, DsmError> {
    let reads = SetClient::new(set)?
        .read_index(namespace, locator, budget)
        .await;
    Ok(dsm::sofi::storage::merge_index_reads(&reads))
}

/// The `Stored` bytes of at most `budget + 1` candidates, in candidate order:
/// the budget bounds the work a flood of appends can cost.
async fn stored_candidates(
    set: &StorageSet,
    candidates: &[[u8; 32]],
    budget: usize,
) -> Result<Vec<Option<Vec<u8>>>, DsmError> {
    let client = SetClient::new(set)?;
    let mut fetched = Vec::with_capacity(candidates.len().min(budget + 1));
    for addr in candidates.iter().take(budget + 1) {
        let reads = client.get_immutable(addr).await;
        fetched.push(match dsm::sofi::storage::stored(addr, &reads) {
            StoredFact::Stored(bytes) => Some(bytes),
            StoredFact::Unavailable => None,
        });
    }
    Ok(fetched)
}

/// The one object under `locator` whose bytes are `Stored` and whose
/// identity, recomputed by Core from the bytes with `recognize`, is
/// `locator`. Every other candidate is nothing; a scan that would examine
/// more than `budget` candidates is `Unavailable`, never `Invalid`.
pub async fn resolve_locator<T>(
    set: &StorageSet,
    index_namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<Resolved<T>, DsmError> {
    let candidates = match read_index_candidates(set, index_namespace, locator, budget).await? {
        IndexCandidates::Unavailable => return Ok(Resolved::Unavailable),
        IndexCandidates::Candidates(c) => c,
    };
    let fetched = stored_candidates(set, &candidates, budget).await?;
    Ok(dsm::sofi::storage::keep_verifying(
        locator, &fetched, budget, recognize,
    ))
}

/// Every candidate under `locator` whose `Stored` bytes recognize to
/// `locator`, in append order, and whether that is all of them. It
/// establishes what is published under the locator and decides nothing about
/// which applies.
pub async fn resolve_locator_all<T>(
    set: &StorageSet,
    index_namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<Discovered<T>, DsmError> {
    let candidates = match read_index_candidates(set, index_namespace, locator, budget).await? {
        IndexCandidates::Unavailable => return Ok(Discovered::Partial(Vec::new())),
        IndexCandidates::Candidates(c) => c,
    };
    let fetched = stored_candidates(set, &candidates, budget).await?;
    Ok(dsm::sofi::storage::keep_all_verifying(
        locator, &fetched, budget, recognize,
    ))
}
