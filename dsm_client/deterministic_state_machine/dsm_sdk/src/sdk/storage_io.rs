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
    // An object is its bytes: once a member served bytes that re-hash to the
    // address, they are kept and never fetched again.
    if let Some(kept) = crate::sdk::final_reads::object(&addr) {
        return Ok(Some(kept));
    }
    let fetched = SetClient::new(set)?.fetch_verified(&addr).await;
    if let Some(bytes) = &fetched {
        crate::sdk::final_reads::keep_object(namespace, &addr, bytes);
    }
    Ok(fetched)
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
/// state commits its policies by address). Always read from the members: a
/// publisher reads its object back with it.
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

/// [`read_stored_bytes`] for a reader: the bytes at `addr` once this process
/// read them `Stored`, which never changes what they are (§5: an address is
/// its bytes, and there is no overwrite path), and read from the members
/// otherwise. Bytes not `Stored` are not kept, and are read again when asked
/// for. A publisher reading its own object back does not use this.
pub(crate) async fn read_stored_bytes_kept(
    set: &StorageSet,
    addr: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    if let Some(kept) = crate::sdk::final_reads::stored_object(addr) {
        return Ok(Some(kept));
    }
    let read = read_stored_bytes(set, addr).await?;
    if let Some(bytes) = &read {
        crate::sdk::final_reads::keep_stored_object(addr, bytes);
    }
    Ok(read)
}

/// Candidates whose bytes are asked for at once.
const CANDIDATE_READS_AT_ONCE: usize = 8;

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
    let client = &SetClient::new(set)?;
    let asked = &candidates[..candidates.len().min(budget + 1)];
    let mut fetched = Vec::with_capacity(asked.len());
    // Each candidate is its own object: a few are asked for at once, and
    // their answers are taken in candidate order.
    for some in asked.chunks(CANDIDATE_READS_AT_ONCE) {
        let reads =
            futures::future::join_all(some.iter().map(|addr| client.get_immutable(addr))).await;
        for (addr, reads) in some.iter().zip(reads) {
            fetched.push(match dsm::sofi::storage::stored(addr, &reads) {
                StoredFact::Stored(bytes) => Some(bytes),
                StoredFact::Unavailable => None,
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic_fixtures::NETWORK;
    use crate::sdk::storage_set::canonical_set;
    use crate::test_support::one_device::Fleet;

    const NAMESPACE: TaggedHashDomain<'static> =
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST;

    /// How many times the members were asked for the object at `addr`
    /// since they last forgot.
    fn asked_for(fleet: &Fleet, addr: &[u8; 32]) -> usize {
        let read = format!(
            "GET /api/v2/immutable/{}",
            crate::util::text_id::encode_base32_crockford(addr)
        );
        fleet
            .nodes()
            .nodes
            .iter()
            .map(|node| node.requests().iter().filter(|r| **r == read).count())
            .sum()
    }

    fn forget_requests(fleet: &Fleet) {
        for node in &fleet.nodes().nodes {
            node.forget_requests();
        }
    }

    /// An object a reader read `Stored` is its bytes for good: asked for
    /// again it asks no member, and answers the same bytes. Bytes that are
    /// not `Stored` are not kept, and a publisher's read-back always asks
    /// the members.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_object_read_stored_is_not_read_again_by_a_reader() {
        let fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let payload = b"an object a reader reads twice".to_vec();
        let (addr, took) = put_immutable(&set, NAMESPACE, &payload)
            .await
            .expect("the put");
        assert!(took >= 3, "the members took the object");

        let absent = dsm::storage_object::immutable_addr(NAMESPACE, b"never put");
        for _ in 0..2 {
            assert_eq!(
                read_stored_bytes_kept(&set, &absent).await.expect("read"),
                None
            );
        }

        forget_requests(&fleet);
        let first = read_stored_bytes_kept(&set, &addr).await.expect("read");
        assert_eq!(first, Some(payload.clone()));
        assert!(
            asked_for(&fleet, &addr) >= 3,
            "the first read asks the members"
        );

        forget_requests(&fleet);
        let again = read_stored_bytes_kept(&set, &addr).await.expect("read");
        assert_eq!(again, first, "the same bytes");
        assert_eq!(asked_for(&fleet, &addr), 0, "a kept object asks no member");

        let read_back = read_stored_bytes(&set, &addr).await.expect("read");
        assert_eq!(read_back, first);
        assert!(
            asked_for(&fleet, &addr) >= 3,
            "a publisher's read-back asks the members"
        );
    }

    /// A locator's candidates are fetched a few at once and kept in the
    /// order they were appended: twenty objects under one locator, more than
    /// are asked for at once, come back in append order, every one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn candidates_fetched_at_once_keep_their_append_order() {
        let _fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let index = b"DSM/test/candidate-order";
        let locator = [0x4C; 32];
        let mut appended = Vec::new();
        for n in 0..20u8 {
            let payload = vec![n; 1 + usize::from(n)];
            let (addr, ..) = put_immutable(&set, NAMESPACE, &payload)
                .await
                .expect("the put");
            append_to_index(&set, index, &locator, &addr)
                .await
                .expect("the append");
            appended.push(payload);
        }
        let found = resolve_locator_all(&set, index, &locator, 64, |bytes| {
            Some((locator, bytes.to_vec()))
        })
        .await
        .expect("the scan");
        match found {
            Discovered::Complete(objects) => assert_eq!(objects, appended),
            Discovered::Partial(objects) => {
                panic!("every candidate is Stored, yet the scan is partial: {objects:?}")
            }
        }
    }
}
