// SPDX-License-Identifier: Apache-2.0

//! The storage facts for objects and indexes — Part II §10, §11 and §13 —
//! pure, storage-fact only. Rebuild step R1.
//!
//! A member stores bytes under the hash of the bytes and appends content
//! addresses under locators. It interprets nothing. Core turns raw member
//! answers into facts and uses nothing else from storage:
//!
//! ```text
//! Stored(o)      ⟺  three members of S return the exact bytes of o
//! Kept(L, o)     ⟺  o is the first candidate under L whose recomputed
//!                    identity is L — every other candidate is nothing
//! ```
//!
//! What a member answers proves itself: the address is a pure function of
//! `(namespace, payload)` (`storage_object::immutable_addr`), so bytes that
//! do not re-hash to the address a reader asked for are not that object,
//! whoever returned them, and a member that returns them has returned
//! nothing. An index is a list of addresses anyone may have appended; a
//! candidate is an object only once its bytes are `Stored` and its identity,
//! recomputed by Core from the bytes, is the locator. A scan that exceeds
//! its budget is `Unavailable`, never `Invalid`: garbage under a locator can
//! cost work, never a refusal.
//!
//! Formal statement: `lean4/DSMSofiStorage.lean`. Every theorem there has a
//! test here with the same name; the mutation controls are executed against
//! this module (see the Lean header).

use super::wire::STORAGE_FINALITY_COUNT;
use crate::crypto::domain::TaggedHashDomain;
use crate::storage_object::immutable_addr;

type D32 = [u8; 32];

/// What one member answered to a fetch of one content address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectRead {
    /// The member returned a `(namespace, payload)` tuple. Untrusted until it
    /// re-hashes to the address that was asked for.
    Bytes {
        namespace: Vec<u8>,
        payload: Vec<u8>,
    },
    /// The member answered that it holds nothing at the address.
    Absent,
    /// No usable answer: unreachable, timed out, or malformed.
    Unavailable,
}

/// §10: whether `Stored(o)` holds for the address that was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredFact {
    /// Three members returned the exact bytes; these are them.
    Stored(Vec<u8>),
    /// Fewer than three members returned bytes that re-hash to the address.
    /// Not a statement about the object — a statement about this read.
    Unavailable,
}

/// The payload of a read that re-hashes to `addr`, or `None`. This is the
/// only place a member's answer is admitted: the address binds the bytes,
/// so a payload that does not derive it is not the object, and a member
/// that returned it has returned nothing.
fn counts<'r>(addr: &D32, read: &'r ObjectRead) -> Option<&'r [u8]> {
    let ObjectRead::Bytes { namespace, payload } = read else {
        return None;
    };
    let domain = TaggedHashDomain::try_new(namespace).ok()?;
    if immutable_addr(domain, payload) != *addr {
        return None;
    }
    Some(payload.as_slice())
}

/// §10 `Stored(o)`: the bytes at `addr` once at least
/// [`STORAGE_FINALITY_COUNT`] members have returned bytes that re-hash to
/// `addr`. Every counted answer carries the same payload — the address is
/// injective in the payload — so the fact carries the bytes themselves.
pub fn stored(addr: &D32, reads: &[ObjectRead]) -> StoredFact {
    let mut counted: Option<&[u8]> = None;
    let mut members = 0usize;
    for read in reads {
        let Some(payload) = counts(addr, read) else {
            continue;
        };
        // Two counted answers with different bytes would be a collision of
        // the address; the first counted payload is the payload.
        if counted.is_none() {
            counted = Some(payload);
        }
        members += 1;
    }
    match counted {
        Some(payload) if members >= STORAGE_FINALITY_COUNT => StoredFact::Stored(payload.to_vec()),
        _ => StoredFact::Unavailable,
    }
}

/// What the reads of one candidate address establish about its bytes (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// `Stored(o)`: these are its bytes.
    Stored(Vec<u8>),
    /// Fewer than three members returned bytes that re-hash to the address,
    /// and at least one did: `Stored(o)` is not established, but these are
    /// the bytes of whatever is at the address — the address binds them —
    /// so what the candidate is, is decided from them. Bytes that are no
    /// object under the locator are nothing, however few hold them; bytes
    /// that are one are not `Stored`, and may yet be.
    Seen(Vec<u8>),
    /// No member returned bytes that re-hash to the address: nothing about
    /// the candidate is established, and it may be the object. An answer
    /// that a member holds nothing is no verdict (storage §4).
    Unestablished,
}

/// §10: what `reads`, one answer per member of the set, establish about the
/// candidate `addr`: `Stored` when three members return its exact bytes,
/// `Seen` when fewer do and one does, and otherwise nothing. How many
/// members answered that they hold nothing decides nothing.
pub fn judge(addr: &D32, reads: &[ObjectRead]) -> Candidate {
    match stored(addr, reads) {
        StoredFact::Stored(bytes) => Candidate::Stored(bytes),
        StoredFact::Unavailable => match reads.iter().find_map(|read| counts(addr, read)) {
            Some(payload) => Candidate::Seen(payload.to_vec()),
            None => Candidate::Unestablished,
        },
    }
}

/// How many members hold a candidate's bytes, as a scan weighs them.
enum Held {
    /// Three: `Stored(o)`.
    Stored,
    /// Fewer, one at least.
    Seen,
}

/// One member's answer to an index read: the addresses it holds under the
/// locator, in append order, and where the read stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIndex {
    pub addrs: Vec<D32>,
    pub end: IndexEnd,
}

/// Where a read of one member's index stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexEnd {
    /// At the end of the member's index: these are all it holds.
    Ended,
    /// At the read's own bound, with more possibly after.
    Cut,
}

/// Whether an index read can show every address the locator holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Enough members' indexes were read to their end that every address
    /// appended at the members an object is stored at is among the
    /// candidates.
    Whole,
    /// Not so: an address may sit only at members not read whole, so the
    /// candidates are not shown to be all.
    Partial,
}

/// The candidates an index read produced, in the order Core will examine
/// them, and whether they are all there are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexCandidates {
    /// At least one member answered: the addresses, each once, and what the
    /// read covers.
    Candidates { addrs: Vec<D32>, coverage: Coverage },
    /// No member answered the index read.
    Unavailable,
}

/// §11: merge one index read per member of the set, in set order (`None`
/// where a member did not answer), into the candidate order: round by round,
/// each member's next address in its append order, members in set order,
/// each address at its first occurrence. One member's appends take one place
/// in each round, so no member's index — however long, whatever it names —
/// pushes another's past a scan's budget (SA-88).
///
/// The read covers the locator when at least `members − STORAGE_FINALITY_COUNT
/// + 1` members' indexes were read to their end: an object is `Stored` at
/// three members and published under the locator at each, so that many whole
/// reads must include one of them (SA-130). Fewer, and an object published
/// under the locator can be among no candidate: the read is `Partial`.
pub fn merge_index_reads(reads: &[Option<MemberIndex>]) -> IndexCandidates {
    let answered: Vec<&MemberIndex> = reads.iter().flatten().collect();
    if answered.is_empty() {
        return IndexCandidates::Unavailable;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut addrs: Vec<D32> = Vec::new();
    let longest = answered
        .iter()
        .map(|read| read.addrs.len())
        .fold(0, usize::max);
    for rank in 0..longest {
        for read in &answered {
            if let Some(addr) = read.addrs.get(rank) {
                if seen.insert(*addr) {
                    addrs.push(*addr);
                }
            }
        }
    }
    let whole = answered
        .iter()
        .filter(|read| read.end == IndexEnd::Ended)
        .count();
    let needed = reads.len().saturating_sub(STORAGE_FINALITY_COUNT) + 1;
    let coverage = if whole >= needed {
        Coverage::Whole
    } else {
        Coverage::Partial
    };
    IndexCandidates::Candidates { addrs, coverage }
}

/// §11: what a scan of the candidates under a locator established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<T> {
    /// A candidate whose bytes are `Stored` and whose recomputed identity is
    /// the locator. The identity is the locator, so any one that verifies is
    /// the object, whatever else is still unknown.
    Kept(T),
    /// The read covers the locator, every candidate was examined within the
    /// budget, every one was decided, and none verifies.
    None,
    /// Nothing verified and the scan cannot say there is nothing: a
    /// candidate was not decided (storage §4: a fact not established from
    /// the reads in hand is never read as its negation), the read does not
    /// cover the locator, the budget ran out, or no member answered. Never
    /// `Invalid`.
    Unavailable,
}

/// §11: what a discovery scan under an index of references established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovered<T> {
    /// The read covers the locator, every candidate was examined within the
    /// budget and every one was decided: these are all the objects that
    /// verify, possibly none.
    Complete(Vec<T>),
    /// These verify, and others may: a candidate was not decided, the read
    /// does not cover the locator, the budget ran out, or no member answered
    /// the index read. An object missing from the list is not thereby absent.
    Partial(Vec<T>),
}

/// §11: keep the one candidate that verifies.
///
/// `candidates` are what the reads establish of each candidate address, in
/// examination order ([`judge`]), and `coverage` what the index read covers.
/// `recognize` is Core's recognition of an object from its bytes: the object
/// and the identity Core recomputes from the bytes, or nothing. A candidate
/// is kept only when that identity is `locator`. Examining a candidate —
/// verifying or not, fetched or not — spends one unit of `budget`; a scan
/// that would examine more than `budget` candidates is `Unavailable`, and so
/// is a scan that kept nothing while a candidate was not decided — that
/// candidate may be the object — or over a read that does not cover the
/// locator. A `Seen` candidate is decided by its bytes: nothing when they are
/// no object under the locator, and not decided when they are one, for it is
/// not `Stored`.
pub fn keep_verifying<T>(
    locator: &D32,
    candidates: &[Candidate],
    coverage: Coverage,
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Resolved<T> {
    let mut decided = coverage;
    for (examined, candidate) in candidates.iter().enumerate() {
        if examined >= budget {
            return Resolved::Unavailable;
        }
        let (bytes, stored) = match candidate {
            Candidate::Stored(bytes) => (bytes, Held::Stored),
            Candidate::Seen(bytes) => (bytes, Held::Seen),
            Candidate::Unestablished => {
                decided = Coverage::Partial;
                continue;
            }
        };
        let Some((identity, object)) = recognize(bytes) else {
            continue;
        };
        if identity == *locator {
            match stored {
                Held::Stored => return Resolved::Kept(object),
                Held::Seen => decided = Coverage::Partial,
            }
        }
    }
    match decided {
        Coverage::Whole => Resolved::None,
        Coverage::Partial => Resolved::Unavailable,
    }
}

/// §11, discovery: EVERY candidate that verifies, in examination order.
///
/// The counterpart of [`keep_verifying`] for a locator that is an index of
/// references rather than an identity — the relationship index key, under
/// which a trader may have published more than one setup for a vault. The
/// scan establishes which objects are recognized under the locator and
/// nothing about which of them applies: that is Core's, by the identity the
/// operation names (`ρ` in a precommit leg) and the leaf the trader's tree
/// admitted. Order of arrival confers nothing. The budget is spent as in
/// [`keep_verifying`]; running out of it, meeting a candidate that was not
/// decided — an object `Seen` and not `Stored` among them — or a read that
/// does not cover the locator makes the discovery `Partial`.
pub fn keep_all_verifying<T>(
    locator: &D32,
    candidates: &[Candidate],
    coverage: Coverage,
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Discovered<T> {
    let mut kept = Vec::new();
    let mut decided = coverage;
    for (examined, candidate) in candidates.iter().enumerate() {
        if examined >= budget {
            return Discovered::Partial(kept);
        }
        let (bytes, stored) = match candidate {
            Candidate::Stored(bytes) => (bytes, Held::Stored),
            Candidate::Seen(bytes) => (bytes, Held::Seen),
            Candidate::Unestablished => {
                decided = Coverage::Partial;
                continue;
            }
        };
        let Some((identity, object)) = recognize(bytes) else {
            continue;
        };
        if identity == *locator {
            match stored {
                Held::Stored => kept.push(object),
                Held::Seen => decided = Coverage::Partial,
            }
        }
    }
    match decided {
        Coverage::Whole => Discovered::Complete(kept),
        Coverage::Partial => Discovered::Partial(kept),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::domain_tags::TAG_DSM_VAULT_STATE;

    const NS: &[u8] = b"DSM/vault-state";

    fn bytes(payload: &[u8]) -> ObjectRead {
        ObjectRead::Bytes {
            namespace: NS.to_vec(),
            payload: payload.to_vec(),
        }
    }

    fn addr_of(payload: &[u8]) -> D32 {
        immutable_addr(TAG_DSM_VAULT_STATE, payload)
    }

    // ── §10 Stored ────────────────────────────────────────────────────────

    /// `stored_returns_exact_bytes` (Lean): the fact carries bytes that
    /// re-hash to the address that was read — never a member's word.
    #[test]
    fn stored_returns_exact_bytes() {
        let o = b"the object";
        let a = addr_of(o);
        let reads = [
            bytes(o),
            bytes(o),
            bytes(o),
            ObjectRead::Absent,
            ObjectRead::Unavailable,
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Stored(o.to_vec()));
    }

    /// `wrong_bytes_never_count` (Lean): a member returning other bytes at
    /// the address has returned nothing, however many do it.
    #[test]
    fn wrong_bytes_never_count() {
        let o = b"the object";
        let a = addr_of(o);
        let hostile = b"the object!";
        let reads = [
            bytes(hostile),
            bytes(hostile),
            bytes(hostile),
            bytes(hostile),
            bytes(hostile),
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
        // Two honest members and three hostile ones: still not Stored.
        let reads = [
            bytes(o),
            bytes(o),
            bytes(hostile),
            bytes(hostile),
            bytes(hostile),
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
        // Three honest members and two hostile ones: Stored, with the honest bytes.
        let reads = [bytes(hostile), bytes(o), bytes(hostile), bytes(o), bytes(o)];
        assert_eq!(stored(&a, &reads), StoredFact::Stored(o.to_vec()));
    }

    /// `a_wrong_namespace_never_counts` (Lean): the address binds the
    /// namespace as well as the payload.
    #[test]
    fn a_wrong_namespace_never_counts() {
        let o = b"the object";
        let a = addr_of(o);
        let other_ns = ObjectRead::Bytes {
            namespace: b"DSM/genesis-v3".to_vec(),
            payload: o.to_vec(),
        };
        let reads = [
            other_ns.clone(),
            other_ns.clone(),
            other_ns,
            bytes(o),
            bytes(o),
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
    }

    /// A member's namespace answer outside the `DSM/` and `DJTE.` families is
    /// a malformed answer, passed over like any other: it once reached the
    /// hasher and panicked the reader, so one member could stop every read
    /// that asked it. Three honest members beside it are still `Stored`.
    #[test]
    fn a_namespace_outside_the_domain_families_is_passed_over() {
        let o = b"the object";
        let a = addr_of(o);
        let unprefixed = ObjectRead::Bytes {
            namespace: b"x".to_vec(),
            payload: o.to_vec(),
        };
        let reads = [
            unprefixed.clone(),
            bytes(o),
            unprefixed.clone(),
            bytes(o),
            bytes(o),
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Stored(o.to_vec()));
        let reads = [unprefixed.clone(), unprefixed.clone(), unprefixed];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
    }

    /// `two_members_is_not_stored` (Lean): the threshold is three, exactly.
    #[test]
    fn two_members_is_not_stored() {
        let o = b"the object";
        let a = addr_of(o);
        let reads = [
            bytes(o),
            bytes(o),
            ObjectRead::Absent,
            ObjectRead::Absent,
            ObjectRead::Absent,
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
        let reads = [bytes(o), bytes(o), bytes(o)];
        assert_eq!(stored(&a, &reads), StoredFact::Stored(o.to_vec()));
    }

    /// `silence_never_counts` (Lean): an unreachable member and an absent
    /// answer are not bytes.
    #[test]
    fn silence_never_counts() {
        let a = addr_of(b"anything");
        let reads = [
            ObjectRead::Unavailable,
            ObjectRead::Unavailable,
            ObjectRead::Absent,
            ObjectRead::Absent,
            ObjectRead::Absent,
        ];
        assert_eq!(stored(&a, &reads), StoredFact::Unavailable);
    }

    // ── §11 the index ─────────────────────────────────────────────────────

    fn whole(addrs: Vec<D32>) -> Option<MemberIndex> {
        Some(MemberIndex {
            addrs,
            end: IndexEnd::Ended,
        })
    }

    fn cut(addrs: Vec<D32>) -> Option<MemberIndex> {
        Some(MemberIndex {
            addrs,
            end: IndexEnd::Cut,
        })
    }

    #[test]
    fn index_reads_merge_by_rank_then_member_without_duplicates() {
        let (x, y, z) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let reads = [whole(vec![x, y]), None, whole(vec![y, z, x]), whole(vec![])];
        assert_eq!(
            merge_index_reads(&reads),
            IndexCandidates::Candidates {
                addrs: vec![x, y, z],
                coverage: Coverage::Whole,
            }
        );
        assert_eq!(
            merge_index_reads(&[None, None]),
            IndexCandidates::Unavailable
        );
        assert_eq!(
            merge_index_reads(&[None, whole(Vec::new()), None, None, None]),
            IndexCandidates::Candidates {
                addrs: Vec::new(),
                coverage: Coverage::Partial,
            }
        );
    }

    /// SA-88. One member's index, however long and whatever it names, takes
    /// one place in each round of the merge: an honest address a member
    /// holds at the front of its own index is examined within the first
    /// round, however many addresses the member before it in set order
    /// fabricated.
    /// MUTATION CONTROL: joining the members' indexes one after another, as
    /// the merge did, puts the honest address past the hostile member's 300
    /// and turns this red.
    #[test]
    fn index_reads_interleave_by_rank_so_no_member_starves_another() {
        let honest = [0x0A; 32];
        let fabricated: Vec<D32> = (0..300u16)
            .map(|n| {
                let mut a = [0xF0; 32];
                a[..2].copy_from_slice(&n.to_be_bytes());
                a
            })
            .collect();
        let reads = [
            whole(fabricated),
            whole(vec![honest]),
            whole(vec![honest]),
            whole(vec![honest]),
            None,
        ];
        let IndexCandidates::Candidates { addrs, .. } = merge_index_reads(&reads) else {
            panic!("members answered");
        };
        let at = addrs.iter().position(|a| *a == honest);
        assert_eq!(
            at,
            Some(1),
            "the honest address is second, after one fabricated one"
        );
    }

    /// SA-130. "Nothing is published under the locator" needs the indexes of
    /// at least `members − 3 + 1` members read to their end: an object is
    /// stored at three members and published at each, so fewer whole reads
    /// can miss it. One member's index, or reads cut at their bound, never
    /// conclude it is not there.
    /// MUTATION CONTROL: taking any one answering member's read as covering
    /// the locator turns this red.
    #[test]
    fn a_read_too_few_members_ended_is_never_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let partial = [whole(Vec::new()), None, None, None, None];
        let IndexCandidates::Candidates { addrs, coverage } = merge_index_reads(&partial) else {
            panic!("a member answered");
        };
        assert_eq!(coverage, Coverage::Partial);
        assert_eq!(
            keep_verifying(&locator, &judged(&addrs), coverage, 16, recognize),
            Resolved::Unavailable
        );
        let cut_short = [
            cut(Vec::new()),
            cut(Vec::new()),
            cut(Vec::new()),
            whole(Vec::new()),
            None,
        ];
        assert!(matches!(
            merge_index_reads(&cut_short),
            IndexCandidates::Candidates {
                coverage: Coverage::Partial,
                ..
            }
        ));
        let enough = [
            whole(Vec::new()),
            whole(Vec::new()),
            whole(Vec::new()),
            None,
            None,
        ];
        let IndexCandidates::Candidates { coverage, .. } = merge_index_reads(&enough) else {
            panic!("members answered");
        };
        assert_eq!(coverage, Coverage::Whole);
        assert_eq!(
            keep_verifying(&locator, &[], coverage, 16, recognize),
            Resolved::None
        );
    }

    /// Candidates no member answered for: not decided.
    fn judged(addrs: &[D32]) -> Vec<Candidate> {
        addrs.iter().map(|_| Candidate::Unestablished).collect()
    }

    /// SA-85. A candidate whose bytes fewer than three members return is
    /// decided by the bytes, which the address binds: bytes that are no
    /// object under the locator are nothing, so junk put at one member and
    /// appended there no longer leaves every later scan of the locator
    /// undecided. Members answering that they hold nothing decide nothing,
    /// however many: with no bytes returned, the candidate may be the object.
    /// MUTATION CONTROL: reading `Seen` bytes as not established, as the
    /// scan did, turns this red.
    #[test]
    fn bytes_seen_that_are_no_object_under_the_locator_are_nothing() {
        let junk = b"junk at one member";
        let a = addr_of(junk);
        let one = [
            bytes(junk),
            ObjectRead::Absent,
            ObjectRead::Absent,
            ObjectRead::Absent,
            ObjectRead::Absent,
        ];
        assert_eq!(judge(&a, &one), Candidate::Seen(junk.to_vec()));
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [judge(&a, &one), Candidate::Stored(b"ok:Q".to_vec())];
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 16, recognize),
            Resolved::None
        );
        assert_eq!(
            keep_all_verifying(&locator, &candidates, Coverage::Whole, 16, recognize),
            Discovered::<Vec<u8>>::Complete(Vec::new())
        );
        let none_returned = vec![ObjectRead::Absent; 5];
        assert_eq!(
            judge(&addr_of(b"never stored"), &none_returned),
            Candidate::Unestablished
        );
        let o = b"the object";
        let stored_three = [
            bytes(o),
            bytes(o),
            bytes(o),
            ObjectRead::Absent,
            ObjectRead::Absent,
        ];
        assert_eq!(
            judge(&addr_of(o), &stored_three),
            Candidate::Stored(o.to_vec())
        );
    }

    /// SA-85, the other side (storage §4, MR-STOR-0021): an object seen at
    /// fewer than three members is not `Stored`, so it is never kept, and a
    /// scan that meets it is never None — it may yet be published.
    /// MUTATION CONTROL: keeping `Seen` bytes that recognize, or passing over
    /// them, turns this red.
    #[test]
    fn an_object_seen_short_of_stored_is_never_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let seen = [Candidate::Seen(b"ok:P".to_vec())];
        assert_eq!(
            keep_verifying(&locator, &seen, Coverage::Whole, 16, recognize),
            Resolved::Unavailable
        );
        assert_eq!(
            keep_all_verifying(&locator, &seen, Coverage::Whole, 16, recognize),
            Discovered::<Vec<u8>>::Partial(Vec::new())
        );
        let then_stored = [
            Candidate::Seen(b"ok:P".to_vec()),
            Candidate::Stored(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &then_stored, Coverage::Whole, 16, recognize),
            Resolved::Kept(b"P".to_vec())
        );
    }

    /// The recognizer of the tests: an object is its bytes when they start
    /// with `ok:`, and its identity is the hash of the rest.
    fn recognize(b: &[u8]) -> Option<(D32, Vec<u8>)> {
        let rest = b.strip_prefix(b"ok:")?;
        Some((*blake3::hash(rest).as_bytes(), rest.to_vec()))
    }

    /// `kept_verifies` (Lean): what is kept recomputes to the locator, and
    /// it is one of the candidates.
    #[test]
    fn kept_verifies() {
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [
            Candidate::Stored(b"garbage".to_vec()),
            Candidate::Stored(b"ok:Q".to_vec()),
            Candidate::Unestablished,
            Candidate::Stored(b"ok:P".to_vec()),
            Candidate::Stored(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 16, recognize),
            Resolved::Kept(b"P".to_vec())
        );
    }

    /// `garbage_is_never_kept` (Lean): bytes that decode to nothing, and
    /// objects whose identity is another locator, are nothing under this one.
    #[test]
    fn garbage_is_never_kept() {
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [
            Candidate::Stored(b"garbage".to_vec()),
            Candidate::Stored(b"ok:Q".to_vec()),
            Candidate::Stored(b"ok:R".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 16, recognize),
            Resolved::None
        );
    }

    /// `over_budget_is_unavailable_never_none` (Lean): running out of budget
    /// before the verifying candidate is not an absence.
    #[test]
    fn over_budget_is_unavailable_never_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [
            Candidate::Stored(b"garbage".to_vec()),
            Candidate::Stored(b"garbage".to_vec()),
            Candidate::Stored(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 2, recognize),
            Resolved::Unavailable
        );
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 3, recognize),
            Resolved::Kept(b"P".to_vec())
        );
        // Garbage beyond the budget with nothing verifying is Unavailable too.
        let garbage = [
            Candidate::Stored(b"g".to_vec()),
            Candidate::Stored(b"g".to_vec()),
            Candidate::Stored(b"g".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &garbage, Coverage::Whole, 2, recognize),
            Resolved::Unavailable
        );
    }

    /// `within_budget_exhausted_is_none` (Lean): a scan that examined every
    /// candidate within its budget and kept nothing is an absence.
    #[test]
    fn within_budget_exhausted_is_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let garbage = [
            Candidate::Stored(b"g".to_vec()),
            Candidate::Stored(b"ok:Q".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &garbage, Coverage::Whole, 2, recognize),
            Resolved::None
        );
        assert_eq!(
            keep_verifying(&locator, &[], Coverage::Whole, 0, recognize),
            Resolved::None
        );
    }

    /// `an_unestablished_candidate_is_never_none` (Lean): a candidate whose
    /// bytes were not established may be the object, so a scan that kept
    /// nothing past it is Unavailable (storage §4, MR-STOR-0021). One that
    /// verifies elsewhere is still kept: the identity is the locator.
    #[test]
    fn an_unestablished_candidate_is_never_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let unknown = [
            Candidate::Stored(b"g".to_vec()),
            Candidate::Unestablished,
            Candidate::Stored(b"ok:Q".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &unknown, Coverage::Whole, 3, recognize),
            Resolved::Unavailable
        );
        let found = [
            Candidate::Unestablished,
            Candidate::Stored(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &found, Coverage::Whole, 2, recognize),
            Resolved::Kept(b"P".to_vec())
        );
    }

    /// Discovery under an index of references: every recognized candidate is
    /// returned in examination order, a candidate of another identity or
    /// garbage is passed over, and nothing about order confers preference.
    #[test]
    fn discovery_returns_every_recognized_candidate_and_prefers_none() {
        let locator = [0xAB; 32];
        let recognize = |bytes: &[u8]| -> Option<([u8; 32], u8)> {
            match bytes {
                [id, value] => Some(([*id; 32], *value)),
                _ => None,
            }
        };
        let candidates = vec![
            Candidate::Stored(vec![0xAB, 1]),
            Candidate::Stored(vec![0xCD, 9]),
            Candidate::Stored(b"garbage".to_vec()),
            Candidate::Stored(vec![0xAB, 2]),
        ];
        assert_eq!(
            keep_all_verifying(&locator, &candidates, Coverage::Whole, 4, recognize),
            Discovered::Complete(vec![1, 2])
        );
        // The same scan, kept singly, is the first — which is exactly why an
        // index of references must not be read through it.
        assert_eq!(
            keep_verifying(&locator, &candidates, Coverage::Whole, 4, recognize),
            Resolved::Kept(1)
        );
        assert_eq!(
            keep_all_verifying(&locator, &candidates[1..3], Coverage::Whole, 2, recognize),
            Discovered::<u8>::Complete(Vec::new())
        );
    }

    /// `an_unestablished_candidate_makes_discovery_partial` (Lean): a
    /// discovery that met a candidate whose bytes were not established, or
    /// ran out of budget, keeps what verified and says it may not be all
    /// (storage §4, MR-STOR-0021).
    #[test]
    fn an_unestablished_candidate_makes_discovery_partial() {
        let locator = [0xAB; 32];
        let recognize = |bytes: &[u8]| -> Option<([u8; 32], u8)> {
            match bytes {
                [id, value] => Some(([*id; 32], *value)),
                _ => None,
            }
        };
        let candidates = vec![
            Candidate::Stored(vec![0xAB, 1]),
            Candidate::Unestablished,
            Candidate::Stored(vec![0xCD, 9]),
            Candidate::Stored(vec![0xAB, 2]),
        ];
        assert_eq!(
            keep_all_verifying(&locator, &candidates, Coverage::Whole, 4, recognize),
            Discovered::Partial(vec![1, 2])
        );
        assert_eq!(
            keep_all_verifying(&locator, &candidates[1..3], Coverage::Whole, 2, recognize),
            Discovered::<u8>::Partial(Vec::new())
        );
        // Over budget: what was examined, and no claim about the rest.
        assert_eq!(
            keep_all_verifying(&locator, &candidates, Coverage::Whole, 1, recognize),
            Discovered::Partial(vec![1])
        );
    }
}
