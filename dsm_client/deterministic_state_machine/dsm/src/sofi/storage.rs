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

/// The candidates an index read produced, in the order Core will examine
/// them: each member's appends in append order, members in set order,
/// duplicates dropped at their first occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexCandidates {
    /// At least one member answered; these are the addresses.
    Candidates(Vec<D32>),
    /// No member answered the index read.
    Unavailable,
}

/// §11: merge one index read per member (`None` where a member did not
/// answer) into the candidate order.
pub fn merge_index_reads(reads: &[Option<Vec<D32>>]) -> IndexCandidates {
    let mut answered = false;
    let mut out: Vec<D32> = Vec::new();
    for read in reads.iter().flatten() {
        answered = true;
        for addr in read {
            if !out.contains(addr) {
                out.push(*addr);
            }
        }
    }
    if answered {
        IndexCandidates::Candidates(out)
    } else {
        IndexCandidates::Unavailable
    }
}

/// §11: what a scan of the candidates under a locator established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<T> {
    /// The first candidate whose bytes are `Stored` and whose recomputed
    /// identity is the locator.
    Kept(T),
    /// Every candidate was examined within the budget and none verifies.
    None,
    /// The scan ran out of budget before a verifying candidate was found, or
    /// no member answered. Never `Invalid`.
    Unavailable,
}

/// §11: keep the one candidate that verifies.
///
/// `candidates` are the `Stored` bytes of each candidate address in
/// examination order, `None` where the bytes are not `Stored`. `recognize`
/// is Core's recognition of an object from its bytes: the object and the
/// identity Core recomputes from the bytes, or nothing. A candidate is kept
/// only when that identity is `locator`. Examining a candidate — verifying
/// or not, fetched or not — spends one unit of `budget`; a scan that would
/// examine more than `budget` candidates is `Unavailable`.
pub fn keep_verifying<T>(
    locator: &D32,
    candidates: &[Option<Vec<u8>>],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Resolved<T> {
    for (examined, candidate) in candidates.iter().enumerate() {
        if examined >= budget {
            return Resolved::Unavailable;
        }
        let Some(bytes) = candidate else {
            continue;
        };
        let Some((identity, object)) = recognize(bytes) else {
            continue;
        };
        if identity == *locator {
            return Resolved::Kept(object);
        }
    }
    Resolved::None
}

/// §11, discovery: EVERY candidate that verifies, in examination order.
///
/// The counterpart of [`keep_verifying`] for a locator that is an index of
/// references rather than an identity — the relationship index key, under
/// which a trader may have published more than one setup for a vault. The
/// scan establishes which objects are recognized under the locator and
/// nothing about which of them applies: that is Core's, by the identity the
/// operation names (`ρ` in a precommit leg) and the leaf the trader's tree
/// admitted. Order of arrival confers nothing. The budget is spent and
/// answered exactly as in [`keep_verifying`].
pub fn keep_all_verifying<T>(
    locator: &D32,
    candidates: &[Option<Vec<u8>>],
    budget: usize,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Resolved<Vec<T>> {
    let mut kept = Vec::new();
    for (examined, candidate) in candidates.iter().enumerate() {
        if examined >= budget {
            return Resolved::Unavailable;
        }
        let Some(bytes) = candidate else {
            continue;
        };
        let Some((identity, object)) = recognize(bytes) else {
            continue;
        };
        if identity == *locator {
            kept.push(object);
        }
    }
    if kept.is_empty() {
        Resolved::None
    } else {
        Resolved::Kept(kept)
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

    #[test]
    fn index_reads_merge_in_member_then_append_order_without_duplicates() {
        let (x, y, z) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let reads = [Some(vec![x, y]), None, Some(vec![y, z, x])];
        assert_eq!(
            merge_index_reads(&reads),
            IndexCandidates::Candidates(vec![x, y, z])
        );
        assert_eq!(
            merge_index_reads(&[None, None]),
            IndexCandidates::Unavailable
        );
        assert_eq!(
            merge_index_reads(&[None, Some(Vec::new())]),
            IndexCandidates::Candidates(Vec::new())
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
            Some(b"garbage".to_vec()),
            Some(b"ok:Q".to_vec()),
            None,
            Some(b"ok:P".to_vec()),
            Some(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, 16, recognize),
            Resolved::Kept(b"P".to_vec())
        );
    }

    /// `garbage_is_never_kept` (Lean): bytes that decode to nothing, and
    /// objects whose identity is another locator, are nothing under this one.
    #[test]
    fn garbage_is_never_kept() {
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [
            Some(b"garbage".to_vec()),
            Some(b"ok:Q".to_vec()),
            None,
            Some(b"ok:R".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, 16, recognize),
            Resolved::None
        );
    }

    /// `over_budget_is_unavailable_never_none` (Lean): running out of budget
    /// before the verifying candidate is not an absence.
    #[test]
    fn over_budget_is_unavailable_never_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let candidates = [
            Some(b"garbage".to_vec()),
            Some(b"garbage".to_vec()),
            Some(b"ok:P".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &candidates, 2, recognize),
            Resolved::Unavailable
        );
        assert_eq!(
            keep_verifying(&locator, &candidates, 3, recognize),
            Resolved::Kept(b"P".to_vec())
        );
        // Garbage beyond the budget with nothing verifying is Unavailable too.
        let garbage = [
            Some(b"g".to_vec()),
            Some(b"g".to_vec()),
            Some(b"g".to_vec()),
        ];
        assert_eq!(
            keep_verifying(&locator, &garbage, 2, recognize),
            Resolved::Unavailable
        );
    }

    /// `within_budget_exhausted_is_none` (Lean): a scan that examined every
    /// candidate within its budget and kept nothing is an absence.
    #[test]
    fn within_budget_exhausted_is_none() {
        let locator = *blake3::hash(b"P").as_bytes();
        let garbage = [Some(b"g".to_vec()), None];
        assert_eq!(
            keep_verifying(&locator, &garbage, 2, recognize),
            Resolved::None
        );
        assert_eq!(keep_verifying(&locator, &[], 0, recognize), Resolved::None);
    }

    /// Discovery under an index of references: every recognized candidate is
    /// returned in examination order, a candidate of another identity or
    /// garbage is passed over, the budget answers Unavailable exactly as the
    /// single-object scan does, and nothing about order confers preference.
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
            Some(vec![0xAB, 1]),
            Some(vec![0xCD, 9]),
            None,
            Some(b"garbage".to_vec()),
            Some(vec![0xAB, 2]),
        ];
        assert_eq!(
            keep_all_verifying(&locator, &candidates, 5, recognize),
            Resolved::Kept(vec![1, 2])
        );
        // The same scan, kept singly, is the first — which is exactly why an
        // index of references must not be read through it.
        assert_eq!(
            keep_verifying(&locator, &candidates, 5, recognize),
            Resolved::Kept(1)
        );
        assert_eq!(
            keep_all_verifying(&locator, &candidates, 4, recognize),
            Resolved::<Vec<u8>>::Unavailable
        );
        assert_eq!(
            keep_all_verifying(&locator, &candidates[1..4], 3, recognize),
            Resolved::<Vec<u8>>::None
        );
    }
}
