// SPDX-License-Identifier: Apache-2.0

//! `FulfillmentRegistered(F)` — the exercise fact, and the decision that
//! establishes it.
//!
//! **Holding `F` is not the same statement as `F` being registered.** A member
//! that accepted `F` has one row in `sofi_fulfillments` and has installed
//! `C_q`; that is one member's local fact. The exercise boundary is the
//! SYSTEM fact that a quorum of the committed set holds it, and it is written
//! only after an authenticated read of those members says so (F2, and R11-4:
//! "one-member publication is not exercise").
//!
//! ## The answers are observed, never supplied
//!
//! No endpoint here accepts a caller's account of who holds what. A caller
//! that could assert "three members hold this" could manufacture the exercise
//! fact for a fulfillment nobody registered — and the record is monotone, so
//! it could never be taken back. The member does its own reading; this module
//! decides what the readings mean.

use std::collections::BTreeSet;

use dsm_sdk::sdk::storage_node_sdk::{answer_counts_for, MemberEcho};
use dsm_sdk::sdk::storage_set::StorageMember;

/// The quorum of holders the exercise fact requires (3 of 5).
pub const HOLDER_QUORUM: usize = 3;

/// One member's answer to "do you hold this fulfillment?", exactly as it came
/// back — echo included, because an answer without a matching echo is
/// uncountable rather than negative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderAnswer {
    /// The member this read was addressed to, from the committed set.
    pub asked: StorageMember,
    /// What the responder echoed about itself.
    pub echoed: MemberEcho,
    /// The fulfillment id the member reports holding at that position, if any.
    pub holds: Option<[u8; 32]>,
}

/// Whether these answers establish `FulfillmentRegistered(F)`.
///
/// An answer counts only when ALL of:
///
/// - the echo matches the member that was asked, on BOTH axes — node id and
///   register incarnation (`answer_counts_for`). A member that lost and
///   rebuilt its register answers with its own id and can honestly report
///   "nothing here" for a cell the committed incarnation held, so node
///   identity alone cannot tell that apart from the real member;
/// - the member reports holding THIS fulfillment, not merely something at that
///   position. A different `F` at the same `q` is a competitor, not a holder;
/// - the member has not already been counted. Distinctness is by the member
///   asked, so one endpoint answering twice is one holder.
pub fn holders_establish_registration(
    answers: &[HolderAnswer],
    fulfillment_id: &[u8; 32],
    quorum: usize,
) -> bool {
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    for a in answers {
        if !answer_counts_for(&a.echoed, &a.asked) {
            continue;
        }
        if a.holds.as_ref() != Some(fulfillment_id) {
            continue;
        }
        counted.insert(a.asked.member_id.as_str());
    }
    counted.len() >= quorum
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: [u8; 32] = [0xF1; 32];
    const OTHER_F: [u8; 32] = [0xF2; 32];

    fn member(id: &str) -> StorageMember {
        StorageMember {
            member_id: id.to_string(),
            register_incarnation_id: [id.as_bytes()[id.len() - 1]; 32],
            endpoint: format!("http://{id}.local:8080"),
        }
    }

    fn holder(id: &str) -> HolderAnswer {
        let m = member(id);
        HolderAnswer {
            echoed: MemberEcho {
                node_id: Some(m.member_id.clone()),
                register_incarnation: Some(m.register_incarnation_id),
            },
            asked: m,
            holds: Some(F),
        }
    }

    /// A quorum of distinct, correctly-echoing holders establishes it.
    #[test]
    fn three_distinct_holders_establish_the_exercise_fact() {
        let answers = vec![holder("node-1"), holder("node-2"), holder("node-3")];
        assert!(holders_establish_registration(&answers, &F, HOLDER_QUORUM));
    }

    /// TWO IS NOT THREE. This is the property that makes publication to one
    /// or two members not exercise.
    #[test]
    fn fewer_than_a_quorum_establishes_nothing() {
        for n in 0..HOLDER_QUORUM {
            let answers: Vec<_> = ["node-1", "node-2", "node-3"][..n]
                .iter()
                .map(|id| holder(id))
                .collect();
            assert!(
                !holders_establish_registration(&answers, &F, HOLDER_QUORUM),
                "{n} holders must not establish the exercise fact"
            );
        }
    }

    /// ONE MEMBER ANSWERING THREE TIMES IS ONE HOLDER. Distinctness is by the
    /// member asked, so a retried or duplicated read cannot manufacture a
    /// quorum.
    #[test]
    fn one_member_answering_repeatedly_is_one_holder() {
        let answers = vec![holder("node-1"), holder("node-1"), holder("node-1")];
        assert!(!holders_establish_registration(&answers, &F, HOLDER_QUORUM));
    }

    /// AN ANSWER WITHOUT A MATCHING ECHO IS UNCOUNTABLE, not a holder. A
    /// rebuilt member wearing the same node id answers honestly and is still
    /// not the member the set committed.
    #[test]
    fn an_answer_whose_echo_does_not_match_is_uncountable() {
        let mut rebuilt = holder("node-3");
        rebuilt.echoed.register_incarnation = Some([0xEE; 32]);
        let answers = vec![holder("node-1"), holder("node-2"), rebuilt];
        assert!(!holders_establish_registration(&answers, &F, HOLDER_QUORUM));

        let mut no_echo = holder("node-3");
        no_echo.echoed = MemberEcho {
            node_id: None,
            register_incarnation: None,
        };
        let answers = vec![holder("node-1"), holder("node-2"), no_echo];
        assert!(!holders_establish_registration(&answers, &F, HOLDER_QUORUM));
    }

    /// A DIFFERENT `F` AT THE SAME POSITION IS A COMPETITOR, NOT A HOLDER.
    /// Counting "something is there" instead of "this is there" would let two
    /// rival fulfillments each borrow the other's members.
    #[test]
    fn a_member_holding_another_fulfillment_is_not_a_holder() {
        let mut rival = holder("node-3");
        rival.holds = Some(OTHER_F);
        let answers = vec![holder("node-1"), holder("node-2"), rival];
        assert!(!holders_establish_registration(&answers, &F, HOLDER_QUORUM));

        let mut empty = holder("node-3");
        empty.holds = None;
        let answers = vec![holder("node-1"), holder("node-2"), empty];
        assert!(!holders_establish_registration(&answers, &F, HOLDER_QUORUM));
    }
}
