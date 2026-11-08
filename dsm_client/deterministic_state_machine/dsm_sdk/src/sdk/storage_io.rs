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
use dsm::sofi::storage::{Candidate, Discovered, IndexCandidates, Resolved, StoredFact};
use dsm::types::error::DsmError;

use crate::sdk::final_reads::PassedOver;
use crate::sdk::storage_node_sdk::{IndexRead, SetClient};
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

/// One scan's read of a locator: the candidates and what the read covers,
/// with each member's entries as it answered, by member id, and what earlier
/// scans had read past.
struct LocatorRead {
    key: crate::sdk::final_reads::LocatorKey,
    candidates: IndexCandidates,
    members: Vec<(Vec<u8>, Option<IndexRead>)>,
    passed: PassedOver,
}

/// The candidates under `locator` (§7): the addresses earlier scans
/// recognized under it, then every member's appends past what earlier scans
/// read, merged by Core round by round so no member's answer starves
/// another's; with what the read covers, and `Unavailable` when no member
/// answered. Each member is read past the run of its entries this process
/// already decided ([`remember_passed_over`]), and for at most `budget`
/// addresses; Core's scan applies the budget again over the candidates.
async fn read_locator(
    set: &StorageSet,
    namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
) -> Result<LocatorRead, DsmError> {
    let client = SetClient::new(set)?;
    let key = (set.id(), namespace.to_vec(), *locator);
    let passed = match crate::sdk::final_reads::passed_over(&key) {
        Some(passed) => passed,
        None => PassedOver {
            cursors: Vec::new(),
            kept: Vec::new(),
        },
    };
    let reads = client
        .read_index_after(namespace, locator, &passed.cursors, budget)
        .await;
    let merged: Vec<Option<dsm::sofi::storage::MemberIndex>> = reads
        .iter()
        .map(|read| read.as_ref().map(IndexRead::member_index))
        .collect();
    // What earlier scans recognized is examined again first: it was met
    // before anything read now, and passing it over saved no examination.
    let candidates = match dsm::sofi::storage::merge_index_reads(&merged) {
        IndexCandidates::Candidates { addrs, coverage } => {
            let mut all = passed.kept.clone();
            all.extend(addrs.into_iter().filter(|addr| !passed.kept.contains(addr)));
            IndexCandidates::Candidates {
                addrs: all,
                coverage,
            }
        }
        IndexCandidates::Unavailable => IndexCandidates::Unavailable,
    };
    let members = client
        .members()
        .iter()
        .map(|member| member.member_id().as_bytes().to_vec())
        .zip(reads)
        .collect();
    Ok(LocatorRead {
        key,
        candidates,
        members,
        passed,
    })
}

/// What the members' answers establish of at most `budget + 1` candidates,
/// in candidate order ([`dsm::sofi::storage::judge`]): the budget bounds the
/// work a flood of appends can cost.
async fn judged_candidates(
    set: &StorageSet,
    candidates: &[[u8; 32]],
    budget: usize,
) -> Result<Vec<Candidate>, DsmError> {
    let client = &SetClient::new(set)?;
    let asked = &candidates[..candidates.len().min(budget + 1)];
    let mut judged = Vec::with_capacity(asked.len());
    // Each candidate is its own object: a few are asked for at once, and
    // their answers are taken in candidate order.
    for some in asked.chunks(CANDIDATE_READS_AT_ONCE) {
        let reads =
            futures::future::join_all(some.iter().map(|addr| client.get_immutable(addr))).await;
        for (addr, reads) in some.iter().zip(reads) {
            judged.push(dsm::sofi::storage::judge(addr, &reads));
        }
    }
    Ok(judged)
}

/// Move each member's cursor under the locator through the run of its
/// entries, from where its read started, whose bytes this scan read: Stored,
/// or seen at fewer than three members, recognized under the locator or not.
/// The recognized addresses are kept, and every later scan examines them
/// again before anything it reads; the rest were decided nothing, from bytes
/// the address binds. A later
/// scan reads each member on from its cursor, so a flood of appends — junk
/// at a predictable locator, written before or after the objects it hides —
/// costs this process the reads of it once, never every scan (SA-87, SA-89,
/// SA-132). The run stops at the first entry the scan did not decide,
/// examined or not, so nothing undecided is ever skipped; a kept address
/// this scan decided nothing is dropped, and one it did not decide stays.
fn remember_passed_over<T>(
    read: &LocatorRead,
    candidates: &[[u8; 32]],
    judged: &[Candidate],
    locator: &[u8; 32],
    recognize: &impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) {
    let decided: std::collections::HashMap<&[u8; 32], &Candidate> =
        candidates.iter().zip(judged).collect();
    let settled = |addr: &[u8; 32]| {
        decided.get(addr).is_some_and(|candidate| {
            matches!(candidate, Candidate::Stored(..) | Candidate::Seen(..))
        })
    };
    let recognized = |addr: &[u8; 32]| {
        decided.get(addr).is_some_and(|candidate| {
            matches!(
                candidate,
                Candidate::Stored(bytes) | Candidate::Seen(bytes)
                    if recognize(bytes).is_some_and(|(identity, _)| identity == *locator)
            )
        })
    };
    let mut kept: Vec<[u8; 32]> = read
        .passed
        .kept
        .iter()
        .filter(|addr| recognized(addr) || !settled(addr))
        .copied()
        .collect();
    let mut cursors: Vec<(Vec<u8>, i64)> = Vec::new();
    for (member, answer) in &read.members {
        let started = read
            .passed
            .cursors
            .iter()
            .find(|(id, _)| id == member)
            .map(|(_, seq)| *seq);
        let run: Vec<&(i64, [u8; 32])> = match answer.as_ref() {
            Some(answer) => answer
                .entries
                .iter()
                .take_while(|(_, addr)| settled(addr))
                .collect(),
            None => Vec::new(),
        };
        for (_, addr) in &run {
            if recognized(addr) && !kept.contains(addr) {
                kept.push(*addr);
            }
        }
        if let Some(seq) = run.last().map(|(seq, _)| *seq).or(started) {
            cursors.push((member.clone(), seq));
        }
    }
    let passed = PassedOver { cursors, kept };
    if passed != read.passed {
        crate::sdk::final_reads::keep_passed_over(read.key.clone(), passed);
    }
}

/// The one object under `locator` whose bytes are `Stored` and whose
/// identity, recomputed by Core from the bytes with `recognize`, is
/// `locator`. Every other candidate is nothing; a scan that would examine
/// more than `budget` candidates is `Unavailable`, never `Invalid`, and so is
/// one whose read does not cover the locator.
pub async fn resolve_locator<T>(
    set: &StorageSet,
    index_namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<Resolved<T>, DsmError> {
    let read = read_locator(set, index_namespace, locator, budget).await?;
    let IndexCandidates::Candidates { addrs, coverage } = &read.candidates else {
        return Ok(Resolved::Unavailable);
    };
    let judged = judged_candidates(set, addrs, budget).await?;
    let resolved =
        dsm::sofi::storage::keep_verifying(locator, &judged, *coverage, budget, &recognize);
    remember_passed_over(&read, addrs, &judged, locator, &recognize);
    Ok(resolved)
}

/// Every candidate under `locator` whose `Stored` bytes recognize to
/// `locator`, in candidate order, and whether that is all of them. It
/// establishes what is published under the locator and decides nothing about
/// which applies.
pub async fn resolve_locator_all<T>(
    set: &StorageSet,
    index_namespace: &[u8],
    locator: &[u8; 32],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<([u8; 32], T)>,
) -> Result<Discovered<T>, DsmError> {
    let read = read_locator(set, index_namespace, locator, budget).await?;
    let IndexCandidates::Candidates { addrs, coverage } = &read.candidates else {
        return Ok(Discovered::Partial(Vec::new()));
    };
    let judged = judged_candidates(set, addrs, budget).await?;
    let found =
        dsm::sofi::storage::keep_all_verifying(locator, &judged, *coverage, budget, &recognize);
    remember_passed_over(&read, addrs, &judged, locator, &recognize);
    Ok(found)
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

    /// The tests' recognizer of what is under `locator`: bytes that begin
    /// `object:` are an object named by it; anything else is no object.
    fn objects_named(locator: [u8; 32]) -> impl Fn(&[u8]) -> Option<([u8; 32], Vec<u8>)> {
        move |bytes| {
            bytes
                .starts_with(b"object:")
                .then(|| (locator, bytes.to_vec()))
        }
    }

    /// Put `bytes` at the members of `set` numbered `members` alone, and
    /// append their address under `locator` at each: a member takes the
    /// append of what it holds (storage spec §7).
    async fn held_by(
        set: &StorageSet,
        members: &[usize],
        index: &[u8],
        locator: &[u8; 32],
        bytes: &[u8],
    ) {
        let client = SetClient::new(set).expect("the set's members");
        let addr = dsm::storage_object::immutable_addr(NAMESPACE, bytes);
        for n in members {
            let member = &client.members()[*n];
            member
                .put_immutable(NAMESPACE, bytes)
                .await
                .expect("the member keeps what it is given");
            member
                .append_index(index, locator, &addr)
                .await
                .expect("the member appends what it holds");
        }
    }

    /// SA-85. Junk one member holds, appended there, is decided by its bytes:
    /// they re-hash to the address and are no object under the locator, so
    /// the candidate is nothing, and the scan beside it is complete with the
    /// object that was published. Read as undecided, one such append made
    /// every scan of the locator partial for good. An address no member
    /// holds is appended at none (storage spec §7).
    /// MUTATION CONTROL: reading bytes seen at fewer than three members as
    /// not established turns this red. On the storage node's own code, on
    /// Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn junk_one_member_holds_leaves_the_scan_complete() {
        let _fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let index = b"DSM/test/junk-append";
        let locator = [0x4D; 32];
        let nowhere = dsm::storage_object::immutable_addr(NAMESPACE, b"stored nowhere");
        assert_eq!(
            append_to_index(&set, index, &locator, &nowhere)
                .await
                .expect("the append is answered"),
            0,
            "no member appends an address it holds no object at"
        );
        held_by(&set, &[0], index, &locator, b"junk one member holds").await;
        let payload = b"object: under the locator".to_vec();
        let (addr, ..) = put_immutable(&set, NAMESPACE, &payload)
            .await
            .expect("the put");
        append_to_index(&set, index, &locator, &addr)
            .await
            .expect("the append");
        let found = resolve_locator_all(&set, index, &locator, 64, objects_named(locator))
            .await
            .expect("the scan");
        assert_eq!(found, Discovered::Complete(vec![payload]));
    }

    /// SA-85, the other side (storage §4, MR-STOR-0021). An object two
    /// members hold is not `Stored`, so a scan that meets it is never
    /// complete without it, and the one object is not established; held by a
    /// third, it is. A member listing an address that no member holds leaves
    /// the scan partial: an answer that members hold nothing is no verdict.
    /// MUTATION CONTROL: passing over seen bytes that recognize turns this
    /// red. On the storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_object_fewer_than_three_members_hold_is_not_established() {
        let fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let index = b"DSM/test/object-at-two";
        let locator = [0x4A; 32];
        let payload = b"object: held by two".to_vec();
        held_by(&set, &[0, 1], index, &locator, &payload).await;
        assert_eq!(
            resolve_locator_all(&set, index, &locator, 64, objects_named(locator))
                .await
                .expect("the scan"),
            Discovered::Partial(Vec::new())
        );
        assert_eq!(
            resolve_locator(&set, index, &locator, 64, objects_named(locator))
                .await
                .expect("the scan"),
            Resolved::Unavailable
        );
        let client = SetClient::new(&set).expect("the set's members");
        client.members()[2]
            .put_immutable(NAMESPACE, &payload)
            .await
            .expect("a third member keeps it");
        assert_eq!(
            resolve_locator_all(&set, index, &locator, 64, objects_named(locator))
                .await
                .expect("the scan"),
            Discovered::Complete(vec![payload])
        );

        let listed = [0x4B; 32];
        let member = fleet.nodes().nodes[0].member_id.clone();
        fleet
            .nodes()
            .list_unheld(&member, index, &listed, &[0x98; 32])
            .await;
        assert_eq!(
            resolve_locator_all(&set, index, &listed, 64, objects_named(listed))
                .await
                .expect("the scan"),
            Discovered::Partial(Vec::new()),
            "a candidate no member returns bytes for may be the object"
        );
    }

    /// SA-87, SA-89, SA-132. A flood of junk past a scan's budget, written
    /// ahead of the object it hides at a predictable locator, is read once
    /// by a process, never by every scan: the first scan reads the budget's
    /// worth of it and says it may not be all; the next reads on from past
    /// what the first decided nothing, and finds the object, complete. A
    /// fresh process pays for the flood once again.
    /// MUTATION CONTROL: keeping no cursor after a scan leaves every scan
    /// behind the flood and turns this red. On the storage node's own code,
    /// on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_flood_past_the_budget_is_read_past_by_the_next_scan() {
        const BUDGET: usize = 8;
        let _fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let index = b"DSM/test/junk-flood";
        let locator = [0x4E; 32];
        for n in 0..(BUDGET + 4) as u8 {
            let (junk, ..) = put_immutable(&set, NAMESPACE, &[0x6A, n])
                .await
                .expect("a junk put");
            append_to_index(&set, index, &locator, &junk)
                .await
                .expect("a junk append");
        }
        let payload = b"object: behind the flood".to_vec();
        let (addr, ..) = put_immutable(&set, NAMESPACE, &payload)
            .await
            .expect("the put");
        append_to_index(&set, index, &locator, &addr)
            .await
            .expect("the append");
        let scan = || resolve_locator_all(&set, index, &locator, BUDGET, objects_named(locator));
        assert_eq!(
            scan().await.expect("the first scan"),
            Discovered::Partial(Vec::new()),
            "the budget ran out in the flood"
        );
        assert_eq!(
            scan().await.expect("the second scan"),
            Discovered::Complete(vec![payload]),
            "the next scan reads on past the flood"
        );
        crate::sdk::final_reads::forget_everything();
        assert_eq!(
            scan().await.expect("a fresh process's scan"),
            Discovered::Partial(Vec::new())
        );
    }

    /// SA-87, SA-89, SA-132, the flood written after the object. A scan
    /// that must examine every candidate cannot stop at the object: the
    /// first scan finds it and says it may not be all; the next examines it
    /// again, reads on past the flood, and is complete with it. Stopped at
    /// the object it recognized, every scan read the same flood again and
    /// none was ever complete.
    /// MUTATION CONTROL: ending a member's run at an address the scan
    /// recognized, or keeping no recognized address, turns this red. On the
    /// storage node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_flood_after_the_object_is_read_past_by_the_next_scan() {
        const BUDGET: usize = 8;
        let _fleet = Fleet::start();
        crate::sdk::final_reads::forget_everything();
        let set = canonical_set(NETWORK).expect("the pinned set");
        let index = b"DSM/test/junk-flood-after";
        let locator = [0x4F; 32];
        let payload = b"object: ahead of the flood".to_vec();
        let (addr, ..) = put_immutable(&set, NAMESPACE, &payload)
            .await
            .expect("the put");
        append_to_index(&set, index, &locator, &addr)
            .await
            .expect("the append");
        for n in 0..(BUDGET + 4) as u8 {
            let (junk, ..) = put_immutable(&set, NAMESPACE, &[0x6B, n])
                .await
                .expect("a junk put");
            append_to_index(&set, index, &locator, &junk)
                .await
                .expect("a junk append");
        }
        let scan = || resolve_locator_all(&set, index, &locator, BUDGET, objects_named(locator));
        assert_eq!(
            scan().await.expect("the first scan"),
            Discovered::Partial(vec![payload.clone()]),
            "the budget ran out in the flood behind the object"
        );
        assert_eq!(
            scan().await.expect("the second scan"),
            Discovered::Complete(vec![payload.clone()]),
            "the next scan examines the object again and reads on past the flood"
        );
        assert_eq!(
            resolve_locator(&set, index, &locator, BUDGET, objects_named(locator))
                .await
                .expect("the one object"),
            Resolved::Kept(payload)
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
