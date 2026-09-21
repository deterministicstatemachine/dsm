// SPDX-License-Identifier: Apache-2.0

//! Successor-cell resolution over one attempt key — pure, storage-fact only.
//!
//! A cell is read from every member of the fixed five-member set. Each member
//! returns EVERYTHING it holds at the key, in the order it arrived; a member
//! holds bytes and decides nothing. The writer computed the cell's leader from
//! the committed set and a state root, and wrote there first, so the race at
//! a key ends at its leader:
//!
//! ```text
//! LeaderHeld(K, x) ⟺ x is the first object naming K in the leader's read
//! Final(K, x)      ⟺ LeaderHeld(K, x) ∧ #{ m ∈ S ∖ {leader} : m holds x } ≥ 2
//! ```
//!
//! No key is ever dead: a key is open until an object naming it reaches its
//! leader, and nothing else can close it. `Unknown` covers an unread member,
//! a timeout, and any response that is not a well-formed list; it is never
//! read as empty and never counted toward finality. This module decides
//! storage facts only; whether a final value is valid, canonical or live is
//! not its business.
//!
//! Which values in a member's list are objects that name the key — and which
//! are noise that counts as nothing — is the caller's question, answered from
//! the bytes. This module is handed the digest of each value already
//! classified as an object naming `K`, in arrival order.

use super::wire::{STORAGE_FINALITY_COUNT, STORAGE_MEMBER_COUNT};

/// What one committed member's cell at one attempt key was observed to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellObservation {
    /// The digests of every object naming the key that this member holds, in
    /// arrival order. Empty means an authenticated read of a cell that holds
    /// no such object.
    Holds(Vec<[u8; 32]>),
    /// Unread, unavailable, timed out, or an unverifiable response.
    Unknown,
}

/// The storage-level resolution of one attempt key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellResolution {
    /// The leader's first object, held by at least two other members.
    Final([u8; 32]),
    /// The leader's first object, not yet held by two others. Settles that
    /// no other value will ever be final here.
    LeaderHeld([u8; 32]),
    /// The leader holds no object naming the key, or has not answered.
    Unresolved,
}

/// Resolve one attempt key from one observation per committed member, with
/// the leader's observation at `leader` (its position in the committed
/// set, which the caller computed from the seed and never from availability).
///
/// Non-leader observations are copies: they contribute only to the count of
/// members holding the leader's first value. A value the leader does not hold
/// first is never final, whatever the other members hold.
pub fn resolve(
    observations: &[CellObservation; STORAGE_MEMBER_COUNT],
    leader: usize,
) -> CellResolution {
    let first = match observations.get(leader) {
        Some(CellObservation::Holds(values)) => match values.first() {
            Some(v) => *v,
            None => return CellResolution::Unresolved,
        },
        _ => return CellResolution::Unresolved,
    };
    let copies = observations
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != leader)
        .filter(|(_, obs)| matches!(obs, CellObservation::Holds(values) if values.contains(&first)))
        .count();
    if copies + 1 >= STORAGE_FINALITY_COUNT {
        CellResolution::Final(first)
    } else {
        CellResolution::LeaderHeld(first)
    }
}

/// A read handed to [`resolve_objects`] did not have one entry per
/// committed member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArityError {
    pub reads: usize,
}

impl core::fmt::Display for ArityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "a cell read carries one entry per committed member ({STORAGE_MEMBER_COUNT}), got {}",
            self.reads
        )
    }
}

impl std::error::Error for ArityError {}

/// What the raw reads of one cell established, over the recognized view
/// (Part II §13) — the Core read adapter of rebuild step R4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectResolution {
    /// The leader's first recognized object, held by two other members.
    Final(Vec<u8>),
    /// The leader's first recognized object, not yet held by two others. No
    /// other object will ever be final at this key.
    LeaderHeld(Vec<u8>),
    /// The leader answered and holds no recognized object: the key is open.
    Open,
    /// The leader did not answer. Never read as empty; no member stands in.
    Unavailable,
}

/// Derive `LeaderHeld` and `Final` from raw member reads: everything each
/// member holds at the key in arrival order, `None` where a member did not
/// answer, with the leader at `leader` — its position in the committed set,
/// which the caller computed from the seed and never from availability.
///
/// `recognized` is Core's recognition of an object naming the key from its
/// bytes. Bytes it refuses count as nothing anywhere: they are neither a
/// rival nor a winner, however early they arrived and however many members
/// hold them. Nothing is counted against a quorum.
pub fn resolve_objects(
    reads: &[Option<Vec<Vec<u8>>>],
    leader: usize,
    recognized: impl Fn(&[u8]) -> bool,
) -> Result<ObjectResolution, ArityError> {
    if reads.len() != STORAGE_MEMBER_COUNT {
        return Err(ArityError { reads: reads.len() });
    }
    let naming: Vec<Option<Vec<&Vec<u8>>>> = reads
        .iter()
        .map(|r| {
            r.as_ref()
                .map(|values| values.iter().filter(|v| recognized(v)).collect())
        })
        .collect();
    let observations: [CellObservation; STORAGE_MEMBER_COUNT] = naming
        .iter()
        .map(|r| match r {
            Some(values) => {
                CellObservation::Holds(values.iter().map(|v| *blake3::hash(v).as_bytes()).collect())
            }
            None => CellObservation::Unknown,
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ArityError { reads: reads.len() })?;
    // The digest `resolve` names is the leader's first recognized object, so
    // it is in the leader's read; a read that somehow lacks it establishes
    // nothing rather than something.
    let first = |digest: [u8; 32]| -> Option<Vec<u8>> {
        naming.get(leader)?.as_ref().and_then(|values| {
            values
                .iter()
                .find(|v| *blake3::hash(v).as_bytes() == digest)
                .map(|v| (*v).clone())
        })
    };
    Ok(match resolve(&observations, leader) {
        CellResolution::Final(d) => match first(d) {
            Some(bytes) => ObjectResolution::Final(bytes),
            None => ObjectResolution::Unavailable,
        },
        CellResolution::LeaderHeld(d) => match first(d) {
            Some(bytes) => ObjectResolution::LeaderHeld(bytes),
            None => ObjectResolution::Unavailable,
        },
        CellResolution::Unresolved => match observations.get(leader) {
            Some(CellObservation::Holds(_)) => ObjectResolution::Open,
            _ => ObjectResolution::Unavailable,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xA; 32];
    const B: [u8; 32] = [0xB; 32];

    fn holds(v: &[[u8; 32]]) -> CellObservation {
        CellObservation::Holds(v.to_vec())
    }
    fn empty() -> CellObservation {
        CellObservation::Holds(Vec::new())
    }

    #[test]
    fn the_leaders_first_value_held_by_two_others_is_final() {
        let obs = [
            holds(&[A]),
            holds(&[A]),
            holds(&[A]),
            empty(),
            CellObservation::Unknown,
        ];
        assert_eq!(resolve(&obs, 0), CellResolution::Final(A));
    }

    #[test]
    fn three_non_leaders_agreeing_is_not_final() {
        // The leader holds nothing: whatever the others hold, the race has not
        // ended, and nothing is final. This is what replaces counting.
        let obs = [empty(), holds(&[A]), holds(&[A]), holds(&[A]), holds(&[A])];
        assert_eq!(resolve(&obs, 0), CellResolution::Unresolved);
    }

    #[test]
    fn a_later_value_at_the_leader_never_becomes_final() {
        // B arrived at the leader after A. Four members hold B; A is the
        // winner because it got to the leader first.
        let obs = [
            holds(&[A, B]),
            holds(&[B]),
            holds(&[B]),
            holds(&[B]),
            holds(&[B]),
        ];
        assert_eq!(resolve(&obs, 0), CellResolution::LeaderHeld(A));
    }

    #[test]
    fn leader_held_settles_the_race_before_finality() {
        let obs = [
            holds(&[A]),
            empty(),
            CellObservation::Unknown,
            empty(),
            empty(),
        ];
        assert_eq!(resolve(&obs, 0), CellResolution::LeaderHeld(A));
    }

    #[test]
    fn copies_count_wherever_the_value_sits_in_a_copys_list() {
        // A copy may hold other values too; it holds A, so it counts.
        let obs = [
            holds(&[A]),
            holds(&[B, A]),
            holds(&[A, B]),
            empty(),
            empty(),
        ];
        assert_eq!(resolve(&obs, 0), CellResolution::Final(A));
    }

    #[test]
    fn an_unreachable_leader_resolves_nothing_and_no_member_stands_in() {
        let obs = [
            CellObservation::Unknown,
            holds(&[A]),
            holds(&[A]),
            holds(&[A]),
            holds(&[A]),
        ];
        assert_eq!(resolve(&obs, 0), CellResolution::Unresolved);
    }

    #[test]
    fn the_leader_position_is_the_callers_and_changes_the_answer() {
        let obs = [holds(&[A]), holds(&[B]), holds(&[B]), holds(&[B]), empty()];
        assert_eq!(resolve(&obs, 0), CellResolution::LeaderHeld(A));
        assert_eq!(resolve(&obs, 1), CellResolution::Final(B));
    }

    // ── The bytes-level adapter (R4) ──────────────────────────────────────

    fn object(tag: u8) -> Vec<u8> {
        vec![b'o', tag]
    }
    fn garbage() -> Vec<u8> {
        b"g".to_vec()
    }
    fn recognized(v: &[u8]) -> bool {
        v.first() == Some(&b'o')
    }

    #[test]
    fn the_adapter_derives_final_from_the_recognized_view() {
        let x = object(1);
        let reads = vec![
            Some(vec![garbage(), x.clone()]),
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
            None,
            Some(vec![]),
        ];
        assert_eq!(
            resolve_objects(&reads, 0, recognized).unwrap(),
            ObjectResolution::Final(x)
        );
    }

    #[test]
    fn the_adapter_tells_open_from_unavailable_at_the_leader() {
        let x = object(1);
        let open = vec![
            Some(vec![garbage()]),
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
        ];
        assert_eq!(
            resolve_objects(&open, 0, recognized).unwrap(),
            ObjectResolution::Open,
            "garbage at the leader and copies everywhere: the key is open"
        );
        let unread = vec![
            None,
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
            Some(vec![x.clone()]),
            Some(vec![x]),
        ];
        assert_eq!(
            resolve_objects(&unread, 0, recognized).unwrap(),
            ObjectResolution::Unavailable
        );
    }

    #[test]
    fn the_adapter_refuses_a_read_of_the_wrong_arity() {
        assert_eq!(
            resolve_objects(&[Some(vec![])], 0, recognized),
            Err(ArityError { reads: 1 })
        );
    }
}
