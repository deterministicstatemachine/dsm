// SPDX-License-Identifier: Apache-2.0

//! WHAT A SET OF BINDING READS ESTABLISHES ABOUT ONE RESOURCE KEY.
//!
//! [`crate::economic::cell_observation`] answers this question for a WRITE-ONCE
//! cell, and its discipline is reused here verbatim: the tally completes before
//! anything is selected, and an error is never evidence of emptiness. What is
//! NOT reused is the tally itself. A write-once cell holds opaque bytes and
//! "claimed" means a quorum returned byte-identical contents; a binding key
//! holds a [`BindingRecord`] carrying a round and a status, and **chosen** means
//! `q` members hold an ACCEPTED record at exactly the same round (Def 6.21 —
//! one round has one proposer, so one round has one value). Routing records
//! through an opaque-bytes tally would count a PROMISED record as a claim.
//!
//! That is why there are FIVE answers here and four there. A promise in flight,
//! or an accepted record held by fewer than `q` members, is a real state that a
//! write-once cell simply could not express:
//!
//! - [`BindingObservation::BoundFinal`] — binding-final. Says the parent is
//!   OCCUPIED. It does not say the successor was realized; that is a separate
//!   question with a successor-kind-specific answer.
//! - [`BindingObservation::Free`] — `q` attributed members each explicitly hold
//!   NOTHING at this key. No binding is observable NOW; never that the key can
//!   never be bound.
//! - [`BindingObservation::Undetermined`] — at least `q` responses are
//!   attributable, but the evidence establishes NEITHER a chosen value NOR a
//!   quorum of explicit absences.
//! - [`BindingObservation::Conflict`] — two chosen values on one key. Reported,
//!   never resolved by iteration order.
//! - [`BindingObservation::Unavailable`] — fewer than `q` attributed answers.
//!   The read establishes nothing.
//!
//! **`Undetermined` is not emptiness and not a forgery.** Two quorums
//! intersect, but one READ need not see the intersection: a value already
//! chosen behind a down member lands here. A composer that read this as "the
//! parent is free" would compose past a generation whose bind is mid-flight; a
//! verifier that read it as a forgery would make every concurrent settle
//! permanently invalid. It is retryable evidence, and nothing else.
//!
//! **A sub-quorum ACCEPTED record does not defeat `Free`.** `absent >= q` is
//! decisive on its own: if a value were chosen, `q` members hold it, and any
//! `q`-subset intersects them — so a quorum of authenticated explicit absences
//! proves nothing is chosen, whatever a minority also holds. Treating a stray
//! minority record as blocking would let one lagging member freeze a vault
//! forever. The minority record may still win later; that is the same "NOW"
//! semantics `EmptyAtQuorum` documents, and the loser of that race is refused
//! at bind time by the register itself. The observer does not have to serialize
//! what the register already serializes.

use std::collections::BTreeMap;

use crate::dlv::quorum_bind::{MemberRead, BINDING_STATUS_ACCEPTED};
use crate::storage::binding_record::{BindingRecord, Round};

/// Per-member records in key order. `None` at a member means this observer
/// cannot use that member's answer; `None` at a key means the member explicitly
/// holds nothing there. The two are different facts and never collapse.
pub type AttributedRecords = Vec<Option<Vec<Option<BindingRecord>>>>;

/// The FULL identity of a held record — its round plus everything a chosen
/// value is. Never keyed on the round alone: two records sharing a round but
/// naming different values are a divergence, and a round-only key would hide it
/// behind whichever one was seen first.
type RecordIdentity = (Round, [u8; 32], [u8; 32], [u8; 32]);

/// The value chosen at one resource key: `q` attributed members holding this
/// bundle's ACCEPTED record at ONE round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenBinding {
    /// One bundle is one transaction (Req 16.2), so this is the bundle digest.
    pub tx_id: [u8; 32],
    /// `b` — the inner identity of the bundle bytes, and the `GetImmutable` key.
    pub value_digest: [u8; 32],
    /// `addr(B)`. A record whose two identity fields disagree is not usable
    /// evidence; the caller checks that, because only the caller knows the tag.
    pub value_addr: [u8; 32],
    pub round: Round,
    pub holders: u32,
}

/// What a set of attributed `ReadBinding` answers establishes about ONE key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingObservation {
    /// `q` attributed members each explicitly hold nothing here.
    Free,
    /// Binding-final (Def 6.21). Occupancy, not realization.
    BoundFinal(ChosenBinding),
    /// Two distinct chosen values on one key. Arithmetically impossible while
    /// `q` is the canonical strict majority — a member holds exactly one record
    /// per key, so two chosen sets are disjoint and cannot both exceed `n/2` —
    /// which is why reaching this arm means a wrong `q` or a member that broke
    /// its register, and it is quarantined rather than resolved.
    Conflict { distinct: usize },
    /// Attributed, but neither a chosen value nor a quorum of absences.
    Undetermined {
        attributed: u32,
        highest_round: Option<Round>,
    },
    /// Fewer than `q` attributed answers.
    Unavailable { attributed: u32, required: u32 },
}

/// Per-member records in key order, `None` for a member whose answer this
/// observer cannot use, plus how many members answered usably.
///
/// A `MemberRead::Records` whose arity does not match the key set is NOT a
/// usable answer: the member answered a different question.
pub fn attributed_records(
    reads: &[Option<MemberRead>],
    key_count: usize,
) -> (AttributedRecords, u32) {
    let mut per_member: AttributedRecords = vec![None; reads.len()];
    let mut attributed = 0u32;
    for (ix, ans) in reads.iter().enumerate() {
        if let Some(MemberRead::Records(recs)) = ans {
            if recs.len() == key_count {
                attributed += 1;
                per_member[ix] = Some(recs.clone());
            }
        }
    }
    (per_member, attributed)
}

/// The per-key tally. Completes before any winner is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTally {
    /// Members that answered usably (identical for every key of one read).
    pub attributed: u32,
    /// Members that explicitly hold NOTHING at this key.
    pub absent: u32,
    /// The ACCEPTED record at the highest round, if any.
    pub highest_accept: Option<BindingRecord>,
    /// Members holding an ACCEPTED record at exactly that round.
    pub holders_at_highest: u32,
    /// Distinct record identities held by at least `quorum` members.
    pub chosen: Vec<ChosenBinding>,
    /// The highest BALLOT of any record here, accept or promise, so a proposer's
    /// next ballot can clear it.
    pub max_ballot: u64,
}

/// Tally one key of a read. Shared by the proposer ([`crate::dlv::quorum_bind`])
/// and by every observer, so the two cannot drift on what "chosen" means.
pub fn tally_key(per_member: &AttributedRecords, key_ix: usize, quorum: u32) -> KeyTally {
    let mut attributed = 0u32;
    let mut absent = 0u32;
    let mut max_ballot = 0u64;
    let mut highest_accept: Option<BindingRecord> = None;
    // Keyed by the FULL record identity, not by round alone: two records that
    // share a round but name different values are a divergence, and collapsing
    // them under one key would hide it.
    let mut by_identity: BTreeMap<RecordIdentity, u32> = BTreeMap::new();

    for recs in per_member.iter() {
        let Some(recs) = recs else { continue };
        attributed += 1;
        let Some(rec) = recs.get(key_ix).and_then(|r| r.as_ref()) else {
            absent += 1;
            continue;
        };
        max_ballot = max_ballot.max(rec.round.counter / 2);
        if rec.status != BINDING_STATUS_ACCEPTED {
            continue;
        }
        match &highest_accept {
            Some(h) if h.round >= rec.round => {}
            _ => highest_accept = Some(rec.clone()),
        }
        *by_identity
            .entry((rec.round, rec.tx_id, rec.value_digest, rec.value_addr))
            .or_insert(0) += 1;
    }

    let holders_at_highest = match &highest_accept {
        None => 0,
        Some(h) => per_member
            .iter()
            .flatten()
            .filter(|recs| {
                recs.get(key_ix)
                    .and_then(|r| r.as_ref())
                    .is_some_and(|r| r.status == BINDING_STATUS_ACCEPTED && r.round == h.round)
            })
            .count() as u32,
    };

    let chosen = by_identity
        .into_iter()
        .filter(|(_, holders)| *holders >= quorum)
        .map(
            |((round, tx_id, value_digest, value_addr), holders)| ChosenBinding {
                tx_id,
                value_digest,
                value_addr,
                round,
                holders,
            },
        )
        .collect();

    KeyTally {
        attributed,
        absent,
        highest_accept,
        holders_at_highest,
        chosen,
        max_ballot,
    }
}

/// Classify one key of a read at `quorum`.
pub fn observe_key(
    reads: &[Option<MemberRead>],
    key_ix: usize,
    key_count: usize,
    quorum: u32,
) -> BindingObservation {
    let (per_member, attributed) = attributed_records(reads, key_count);
    if attributed < quorum {
        return BindingObservation::Unavailable {
            attributed,
            required: quorum,
        };
    }
    let mut t = tally_key(&per_member, key_ix, quorum);
    match t.chosen.len() {
        0 => {}
        1 => {
            // `pop` cannot fail on a one-element vector, and expressing it this
            // way keeps the arm total without a panicking index.
            if let Some(c) = t.chosen.pop() {
                return BindingObservation::BoundFinal(c);
            }
        }
        distinct => return BindingObservation::Conflict { distinct },
    }
    // Nothing is chosen. A quorum of EXPLICIT absences settles it: any chosen
    // value would be held by `q` members, and every `q`-subset intersects them.
    if t.absent >= quorum {
        return BindingObservation::Free;
    }
    BindingObservation::Undetermined {
        attributed,
        highest_round: t.highest_accept.map(|r| r.round),
    }
}

/// Classify the only key of a single-key read — the frontier walk's shape.
pub fn observe_single_key(reads: &[Option<MemberRead>], quorum: u32) -> BindingObservation {
    observe_key(reads, 0, 1, quorum)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::dlv::quorum_bind::BINDING_STATUS_PROMISED;

    const Q: u32 = 2; // the strict majority of the three-member beta profile

    fn round(counter: u64, proposer: u8) -> Round {
        Round {
            counter,
            proposer_id: [proposer; 32],
        }
    }

    fn rec(status: u32, r: Round, value: u8) -> BindingRecord {
        BindingRecord {
            schema: 1,
            round: r,
            tx_id: [value; 32],
            keyset_digest: [0x5E; 32],
            value_digest: [value; 32],
            value_addr: [value ^ 0xFF; 32],
            status,
        }
    }

    fn holds(rec: BindingRecord) -> Option<MemberRead> {
        Some(MemberRead::Records(vec![Some(rec)]))
    }
    fn absent() -> Option<MemberRead> {
        Some(MemberRead::Records(vec![None]))
    }
    fn down() -> Option<MemberRead> {
        Some(MemberRead::Unavailable)
    }

    // ── THE TWO PINNED CASES ───────────────────────────────────────────────
    //
    // These two differ in ONE member and land on different answers. Getting the
    // boundary wrong in either direction is a real failure: read the first as
    // Undetermined and one lagging member freezes a vault forever; read the
    // second as Free and a composer walks past a bind that is mid-flight.

    /// A quorum of EXPLICIT absences is decisive even beside a stray accept.
    /// Any chosen value is held by `q` members, and every `q`-subset of a
    /// 3-member set intersects any 2 of them — so two members saying "nothing
    /// here" prove nothing is chosen, whatever the third holds.
    #[test]
    fn a_sub_quorum_accept_beside_an_absence_quorum_is_free() {
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, round(3, 1), 0xAA)),
            absent(),
            absent(),
        ];
        assert_eq!(observe_single_key(&reads, Q), BindingObservation::Free);
    }

    /// Swap one absence for an unreachable member and the absence quorum is
    /// gone. Still attributed (2 of 3 answered), still nothing chosen — so the
    /// evidence establishes neither, which is exactly `Undetermined`.
    #[test]
    fn a_sub_quorum_accept_without_an_absence_quorum_is_undetermined() {
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, round(3, 1), 0xAA)),
            absent(),
            down(),
        ];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::Undetermined {
                attributed: 2,
                highest_round: Some(round(3, 1)),
            }
        );
    }

    // ── the rest of the classification ─────────────────────────────────────

    #[test]
    fn a_quorum_holding_one_accepted_record_at_one_round_is_bound_final() {
        let r = round(5, 7);
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, r, 0xAA)),
            holds(rec(BINDING_STATUS_ACCEPTED, r, 0xAA)),
            absent(),
        ];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::BoundFinal(ChosenBinding {
                tx_id: [0xAA; 32],
                value_digest: [0xAA; 32],
                value_addr: [0xAA ^ 0xFF; 32],
                round: r,
                holders: 2,
            })
        );
    }

    #[test]
    fn a_quorum_of_absences_is_free() {
        let reads = [absent(), absent(), absent()];
        assert_eq!(observe_single_key(&reads, Q), BindingObservation::Free);
    }

    /// A PROMISE is not a claim. The whole reason this module cannot reuse the
    /// write-once tally: as opaque bytes these two members agree, and a
    /// byte-identical tally would call the key bound.
    #[test]
    fn a_quorum_of_promises_is_undetermined_not_bound() {
        let r = round(4, 1);
        let reads = [
            holds(rec(BINDING_STATUS_PROMISED, r, 0xAA)),
            holds(rec(BINDING_STATUS_PROMISED, r, 0xAA)),
            absent(),
        ];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::Undetermined {
                attributed: 3,
                highest_round: None, // no ACCEPTED record exists at all
            }
        );
    }

    /// Accepts at two rounds, neither at quorum. Not chosen, and not empty.
    #[test]
    fn accepts_split_across_rounds_are_undetermined() {
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, round(3, 1), 0xAA)),
            holds(rec(BINDING_STATUS_ACCEPTED, round(5, 2), 0xBB)),
            down(),
        ];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::Undetermined {
                attributed: 2,
                highest_round: Some(round(5, 2)),
            }
        );
    }

    #[test]
    fn fewer_than_quorum_attributed_answers_establish_nothing() {
        let reads = [absent(), down(), down()];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::Unavailable {
                attributed: 1,
                required: Q,
            }
        );
    }

    /// A member that answered a DIFFERENT key set answered a different
    /// question, so it is not attributed — and here that is the difference
    /// between `Free` and `Unavailable`.
    #[test]
    fn an_answer_with_the_wrong_arity_is_not_attributed() {
        let reads = [
            absent(),
            Some(MemberRead::Records(vec![None, None])),
            down(),
        ];
        assert_eq!(
            observe_single_key(&reads, Q),
            BindingObservation::Unavailable {
                attributed: 1,
                required: Q,
            }
        );
    }

    /// Two chosen values on one key. Unreachable at a canonical `q` (the two
    /// holder sets are disjoint and cannot both exceed n/2), so it is forced
    /// here with a degenerate `q` to prove the arm reports rather than picks.
    #[test]
    fn two_chosen_values_conflict_and_are_never_resolved_by_order() {
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, round(3, 1), 0xAA)),
            holds(rec(BINDING_STATUS_ACCEPTED, round(5, 2), 0xBB)),
        ];
        assert_eq!(
            observe_single_key(&reads, 1),
            BindingObservation::Conflict { distinct: 2 }
        );
    }

    /// Records sharing a round but naming different values are a divergence,
    /// not one value: the identity tally keys on the whole record, so they do
    /// not collapse into a single chosen entry.
    #[test]
    fn one_round_naming_two_values_does_not_collapse_into_one_chosen_value() {
        let r = round(3, 1);
        let reads = [
            holds(rec(BINDING_STATUS_ACCEPTED, r, 0xAA)),
            holds(rec(BINDING_STATUS_ACCEPTED, r, 0xBB)),
        ];
        assert_eq!(
            observe_single_key(&reads, 1),
            BindingObservation::Conflict { distinct: 2 }
        );
    }

    /// The multi-key shape: each key is classified independently, and a bundle
    /// bound over two vaults is chosen at BOTH its keys.
    #[test]
    fn each_key_of_a_multi_key_read_is_classified_independently() {
        let r = round(5, 7);
        let two = |a: Option<BindingRecord>, b: Option<BindingRecord>| {
            Some(MemberRead::Records(vec![a, b]))
        };
        let reads = [
            two(Some(rec(BINDING_STATUS_ACCEPTED, r, 0xAA)), None),
            two(Some(rec(BINDING_STATUS_ACCEPTED, r, 0xAA)), None),
            two(None, None),
        ];
        assert!(matches!(
            observe_key(&reads, 0, 2, Q),
            BindingObservation::BoundFinal(_)
        ));
        assert_eq!(observe_key(&reads, 1, 2, Q), BindingObservation::Free);
    }

    /// `max_ballot` is the ballot of ANY record, promise included — a proposer
    /// that only cleared accepted rounds would reuse a promised ballot.
    #[test]
    fn max_ballot_counts_promises_too() {
        let per_member = attributed_records(
            &[
                holds(rec(BINDING_STATUS_PROMISED, round(9, 1), 0xAA)),
                holds(rec(BINDING_STATUS_ACCEPTED, round(4, 2), 0xBB)),
                absent(),
            ],
            1,
        )
        .0;
        let t = tally_key(&per_member, 0, Q);
        assert_eq!(t.max_ballot, 4); // 9/2 — the promise, not the accept
        assert_eq!(t.absent, 1);
        assert_eq!(t.holders_at_highest, 1);
        assert_eq!(t.highest_accept.map(|r| r.round), Some(round(4, 2)));
    }
}
