// SPDX-License-Identifier: Apache-2.0

//! TURNING MEMBER RESPONSES INTO AN AUTHORITATIVE OBSERVATION.
//!
//! A write-once register cell is only as sound as the reader that interprets
//! it. The storage primitive underneath is strong — one writer, insert-if-
//! absent, no update or delete path, durable before the acknowledgement — but
//! none of that survives a reader that treats "I could not ask" as an answer.
//!
//! Given a vault's birth-committed storage set, an observer derives exactly
//! one of four things, and the distinctions are load-bearing:
//!
//! - [`CellObservation::Claimed`] — a quorum of attributed members returned
//!   byte-identical contents.
//! - [`CellObservation::EmptyAtQuorum`] — a quorum of attributed members each
//!   returned an EXPLICIT, successful "no row". This says no quorum claim is
//!   observable NOW. It does not say the generation can never be claimed.
//! - [`CellObservation::Conflict`] — no value reached quorum and members
//!   returned contradictory non-empty claims. Reported, never smoothed into
//!   "nothing here".
//! - [`CellObservation::Unavailable`] — the read establishes nothing. Every
//!   timeout, transport error, 5xx, database failure, malformed body, and
//!   missing or incorrect node identity lands here.
//!
//! **An error is never evidence of emptiness.** That was the defect this
//! module exists to remove: a non-success response classified as "no value"
//! made a quorum of failing members manufacture the one observation the design
//! treats as a fact, and a lineage walker reading that fact would call a
//! claimed generation unconsumed.
//!
//! **The tally completes before anything is selected.** Choosing a winner and
//! only then looking for disagreement lets a divergence go unreported, and
//! makes the choice depend on iteration order.

use std::collections::BTreeMap;

/// One member's answer, already attributed. Anything that is not an explicit
/// success or an explicit absence — including a response this observer could
/// not attribute to the member it asked — is [`MemberCellRead::Unavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberCellRead {
    /// A successful read carrying the cell's exact bytes.
    Value(Vec<u8>),
    /// An explicit, successful "this cell holds nothing".
    Absent,
    /// No usable answer. Never counted toward emptiness.
    Unavailable,
}

/// What a set of member reads establishes about one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellObservation {
    /// A quorum returned byte-identical contents.
    Claimed(Vec<u8>),
    /// A quorum explicitly reported no row. True of the moment it was read.
    EmptyAtQuorum,
    /// Contradictory non-empty claims with no quorum winner.
    Conflict { distinct: usize },
    /// The read establishes nothing and the caller must fail closed.
    Unavailable { attributed: u32, required: u32 },
}

/// The canonical quorum for a set of `members`: a strict majority.
///
/// DERIVED, never chosen. Safety needs `2q > n` so two quorums must intersect;
/// strict majority is the smallest `q` that satisfies it, and fixing `q`
/// exactly removes the discretion that would otherwise let a signed
/// `1-of-3` be honoured forever by every verifier that trusts the committed
/// value.
pub fn canonical_quorum(members: usize) -> u32 {
    if members == 0 {
        return 0;
    }
    (members as u32 / 2) + 1
}

/// A committed `q` that is not the canonical strict majority of its set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncanonicalQuorum {
    pub members: usize,
    pub committed: u32,
    pub canonical: u32,
}

impl core::fmt::Display for NoncanonicalQuorum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the state commits q={} over a {}-member set; the canonical quorum is {}",
            self.committed, self.members, self.canonical
        )
    }
}

impl std::error::Error for NoncanonicalQuorum {}

/// Require a committed `q` to BE the canonical strict majority of its set.
///
/// Exact equality, in both directions. A smaller `q` admits two disjoint
/// quorums and therefore two winners; a larger one is safe but is still a
/// value no honest producer derives, and accepting it would leave the
/// committed field a place where discretion lives.
pub fn require_canonical_quorum(members: usize, committed: u32) -> Result<(), NoncanonicalQuorum> {
    let canonical = canonical_quorum(members);
    if committed == canonical && canonical != 0 {
        Ok(())
    } else {
        Err(NoncanonicalQuorum {
            members,
            committed,
            canonical,
        })
    }
}

/// Observe one cell from every member's attributed answer.
///
/// `quorum` is supplied by the caller because a vault's cells are counted at
/// the quorum its own signed state commits — a local majority-of-catalog rule
/// is the verifier's opinion, not the vault's. Callers must have already
/// required that committed value to be canonical.
pub fn observe_cell(reads: &[MemberCellRead], quorum: u32) -> CellObservation {
    // ── TALLY EVERYTHING FIRST. Nothing is selected in this loop. ────────
    let mut counts: BTreeMap<&[u8], u32> = BTreeMap::new();
    let mut absent = 0u32;
    let mut attributed = 0u32;
    for read in reads {
        match read {
            MemberCellRead::Value(bytes) => {
                attributed += 1;
                *counts.entry(bytes.as_slice()).or_insert(0) += 1;
            }
            MemberCellRead::Absent => {
                attributed += 1;
                absent += 1;
            }
            // Not an observation of anything. Deliberately not counted as
            // attributed: it cannot support a conclusion in either direction.
            MemberCellRead::Unavailable => {}
        }
    }

    // ── Only now is anything chosen. ─────────────────────────────────────
    let mut at_quorum = counts.iter().filter(|(_, c)| **c >= quorum);
    let winner = at_quorum.next();
    let second = at_quorum.next();
    match (winner, second) {
        (Some((bytes, _)), None) => CellObservation::Claimed(bytes.to_vec()),
        // Two values at quorum is impossible while `q` is a strict majority,
        // and is exactly what a noncanonical `q` produces. Refused rather
        // than resolved by iteration order.
        (Some(_), Some(_)) => CellObservation::Conflict {
            distinct: counts.len(),
        },
        (None, _) => {
            if counts.len() > 1 {
                // Contradictory claims and no winner. A minority disagreement
                // BESIDE a quorum winner is not this case: write-once rows
                // mean the loser can never gain a majority, so `A,A,B`
                // resolves to `A` above and never reaches here.
                CellObservation::Conflict {
                    distinct: counts.len(),
                }
            } else if absent >= quorum {
                CellObservation::EmptyAtQuorum
            } else {
                CellObservation::Unavailable {
                    attributed,
                    required: quorum,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: u32 = 2; // the canonical quorum of the three-member set

    fn v(b: u8) -> MemberCellRead {
        MemberCellRead::Value(vec![b; 4])
    }

    /// THE DEFECT THIS MODULE REMOVES. Three members whose reads all fail
    /// establish nothing. If failure could count as emptiness, a quorum of
    /// broken members would manufacture "this generation is unconsumed" for a
    /// generation that is claimed.
    #[test]
    fn three_failing_reads_are_unavailable_never_empty() {
        let reads = vec![
            MemberCellRead::Unavailable,
            MemberCellRead::Unavailable,
            MemberCellRead::Unavailable,
        ];
        assert_eq!(
            observe_cell(&reads, Q),
            CellObservation::Unavailable {
                attributed: 0,
                required: Q
            }
        );
    }

    /// Emptiness needs a quorum of EXPLICIT "no row" answers. Two of them
    /// suffice in a three-member set even when the third member is down,
    /// because the two that answered each asserted a fact.
    #[test]
    fn two_explicit_absences_and_one_outage_are_empty_at_quorum() {
        let reads = vec![
            MemberCellRead::Absent,
            MemberCellRead::Absent,
            MemberCellRead::Unavailable,
        ];
        assert_eq!(observe_cell(&reads, Q), CellObservation::EmptyAtQuorum);
    }

    /// A minority conflicting row does NOT invalidate a unique strict-majority
    /// winner. Rows are write-once, so the minority value can never gain a
    /// majority without a member changing a row it can no longer change.
    #[test]
    fn a_minority_disagreement_beside_a_majority_winner_still_resolves() {
        let reads = vec![v(0xAA), v(0xAA), v(0xBB)];
        assert_eq!(
            observe_cell(&reads, Q),
            CellObservation::Claimed(vec![0xAA; 4])
        );
    }

    /// Contradictory claims with no winner are a CONFLICT, reported as such —
    /// never quietly downgraded to "unavailable" or "empty".
    #[test]
    fn contradictory_claims_without_a_winner_are_a_conflict() {
        let reads = vec![v(0xAA), v(0xBB), MemberCellRead::Unavailable];
        assert_eq!(
            observe_cell(&reads, Q),
            CellObservation::Conflict { distinct: 2 }
        );
    }

    /// One claim, one explicit absence, one outage: nothing reached quorum in
    /// either direction, so the read establishes nothing.
    #[test]
    fn one_claim_one_absence_and_one_outage_are_unavailable() {
        let reads = vec![v(0xAA), MemberCellRead::Absent, MemberCellRead::Unavailable];
        assert_eq!(
            observe_cell(&reads, Q),
            CellObservation::Unavailable {
                attributed: 2,
                required: Q
            }
        );
    }

    /// THE NONCANONICAL QUORUM, which is what makes two winners arithmetically
    /// possible at all. `1-of-3` is refused before any cell is read; and if it
    /// were not, two disjoint claims would each reach it — which this observer
    /// reports as a conflict rather than resolving by iteration order.
    #[test]
    fn a_noncanonical_quorum_is_refused_and_never_silently_picks_a_winner() {
        let err = require_canonical_quorum(3, 1).expect_err("1-of-3 must be refused");
        assert_eq!(err.canonical, 2);
        require_canonical_quorum(3, 2).expect("2-of-3 is canonical");
        require_canonical_quorum(3, 3).expect_err("3-of-3 is not the canonical value either");
        require_canonical_quorum(0, 0).expect_err("an empty set has no quorum");

        // The arithmetic that noncanonical q would have allowed.
        let reads = vec![v(0xAA), v(0xBB), MemberCellRead::Unavailable];
        assert_eq!(
            observe_cell(&reads, 1),
            CellObservation::Conflict { distinct: 2 },
            "two values at a noncanonical quorum must conflict, not pick one"
        );
    }

    /// Strict majority at every constructible size: two quorums always
    /// intersect, so two winners are impossible whenever `q` is canonical.
    #[test]
    fn the_canonical_quorum_makes_disjoint_quorums_impossible() {
        for n in 1..=9usize {
            let q = canonical_quorum(n) as usize;
            assert!(2 * q > n, "n={n} q={q} admits two disjoint quorums");
        }
        assert_eq!(canonical_quorum(1), 1);
        assert_eq!(canonical_quorum(2), 2);
        assert_eq!(canonical_quorum(3), 2);
        assert_eq!(canonical_quorum(5), 3);
    }
}
