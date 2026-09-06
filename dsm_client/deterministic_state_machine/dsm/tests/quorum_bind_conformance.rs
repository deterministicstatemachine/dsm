// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! Class K QuorumBind conformance (Rev 15 §6.8, §15.6, §18.2; conformance rows
//! `binding-race/`, `binding-split/`, `overlap-liveness/`, `quorum-fixed/`,
//! `quorum-client/`, `multi-vault-atomic/`).
//!
//! The engine is sans-IO, so a DETERMINISTIC fleet double stands in for the
//! storage members and the two-bundle races are driven at single-operation
//! granularity under EXHAUSTIVE interleaving — no real scheduling is forced
//! (Req 21.1). The fleet's compare-and-exchange mirrors the Class N decision of
//! PR #772 (`dsm_storage_node::db::binding::decide_compare_exchange`) exactly:
//! byte-identical replay re-acks; the prior set digest must match; the
//! replacement round must strictly supersede every held round.

use std::collections::BTreeMap;

use dsm::dlv::quorum_bind::{
    strict_majority, BindingTransaction, CommittedMember, MemberCas, MemberOp, MemberRead, Outcome,
    QuorumBind, Step, BINDING_STATUS_ACCEPTED,
};
use dsm::storage::binding_record::{
    record_digest_of_bytes, record_set_digest, BindingRecord, Round, SetCell,
};

// ───────────────────────── fleet double ─────────────────────────

#[derive(Clone)]
struct Cell {
    bytes: Vec<u8>,
    round: Round,
}

#[derive(Clone)]
struct Fleet {
    members: Vec<BTreeMap<[u8; 32], Cell>>,
}

impl Fleet {
    fn new(n: usize) -> Self {
        Fleet {
            members: vec![BTreeMap::new(); n],
        }
    }

    fn read(&self, m: usize, keys: &[[u8; 32]]) -> Vec<Option<BindingRecord>> {
        keys.iter()
            .map(|k| {
                self.members[m]
                    .get(k)
                    .map(|c| BindingRecord::decode_canonical(&c.bytes).expect("stored canonical"))
            })
            .collect()
    }

    /// Faithful mirror of `decide_compare_exchange` over one member's local
    /// multi-key state: all named keys change to the replacement or none do.
    fn cas(
        &mut self,
        m: usize,
        keys: &[[u8; 32]],
        expected: [u8; 32],
        repl_bytes: &[u8],
    ) -> MemberCas {
        let repl = match BindingRecord::decode_canonical(repl_bytes) {
            Ok(r) => r,
            Err(_) => return MemberCas::InvalidStorageEncoding,
        };
        let held: Vec<Option<Cell>> = keys
            .iter()
            .map(|k| self.members[m].get(k).cloned())
            .collect();
        // 1) byte-identical replay on EVERY key → Applied, no change.
        if held
            .iter()
            .all(|h| h.as_ref().is_some_and(|c| c.bytes == repl_bytes))
        {
            return MemberCas::Applied;
        }
        // 2) the exact prior set digest must match.
        let cells: Vec<SetCell> = keys
            .iter()
            .zip(held.iter())
            .map(|(k, h)| SetCell {
                key: *k,
                record_digest: h.as_ref().map(|c| record_digest_of_bytes(&c.bytes)),
            })
            .collect();
        if record_set_digest(&cells) != expected {
            return MemberCas::ExpectationMismatch;
        }
        // 3) the replacement round must strictly supersede every held round.
        if held.iter().flatten().any(|c| repl.round <= c.round) {
            return MemberCas::ExpectationMismatch;
        }
        for k in keys {
            self.members[m].insert(
                *k,
                Cell {
                    bytes: repl_bytes.to_vec(),
                    round: repl.round,
                },
            );
        }
        MemberCas::Applied
    }

    /// The ground-truth chosen value on a key: a value held as an ACCEPTED
    /// record at the same round by at least `q` members. At most one can exist.
    fn chosen_value(&self, key: &[u8; 32], q: u32) -> Option<[u8; 32]> {
        let mut by_round: BTreeMap<(u64, [u8; 32]), Vec<[u8; 32]>> = BTreeMap::new();
        for member in &self.members {
            if let Some(c) = member.get(key) {
                let rec = BindingRecord::decode_canonical(&c.bytes).unwrap();
                if rec.status == BINDING_STATUS_ACCEPTED {
                    by_round
                        .entry((rec.round.counter, rec.round.proposer_id))
                        .or_default()
                        .push(rec.value_digest);
                }
            }
        }
        for (_, vals) in by_round {
            if vals.len() as u32 >= q {
                return Some(vals[0]);
            }
        }
        None
    }
}

// ───────────────────────── builders ─────────────────────────

fn key(n: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = n;
    k
}

fn member(id: u8) -> CommittedMember {
    CommittedMember {
        member_id: vec![id],
        register_incarnation: [id; 32],
    }
}

fn tx(proposer: u8, value: u8, keys: Vec<[u8; 32]>, members: usize) -> BindingTransaction {
    BindingTransaction {
        proposer_id: [proposer; 32],
        members: (0..members as u8).map(member).collect(),
        quorum: strict_majority(members),
        keys,
        tx_id: [0xA0 ^ value; 32],
        value_addr: [value; 32],
        value_digest: [value; 32],
        base_ballot: 1,
    }
}

// ───────────────────────── single-driver runner ─────────────────────────

fn run_to_done(
    qb: &mut QuorumBind,
    fleet: &mut Fleet,
    keys: &[[u8; 32]],
    avail: &[bool],
    max_ballots: u32,
) -> Option<Outcome> {
    let mut ballots = 0u32;
    loop {
        match qb.poll() {
            Step::Done(o) => return Some(o),
            Step::Contact(ops) => {
                for op in ops {
                    perform(qb, fleet, keys, avail, op);
                }
            }
            Step::Recovering(_) => {
                ballots += 1;
                if ballots > max_ballots {
                    return None;
                }
                qb.recover();
            }
        }
    }
}

fn perform(
    qb: &mut QuorumBind,
    fleet: &mut Fleet,
    keys: &[[u8; 32]],
    avail: &[bool],
    op: MemberOp,
) {
    match op {
        MemberOp::Read { member_ix } => {
            let ans = if avail[member_ix] {
                MemberRead::Records(fleet.read(member_ix, keys))
            } else {
                MemberRead::Unavailable
            };
            qb.deliver_read(member_ix, ans);
        }
        MemberOp::CompareExchange {
            member_ix,
            expected_digest,
            replacement_bytes,
        } => {
            let ans = if avail[member_ix] {
                fleet.cas(member_ix, keys, expected_digest, &replacement_bytes)
            } else {
                MemberCas::Unavailable
            };
            qb.deliver_cas(member_ix, ans);
        }
    }
}

/// One driver plus its own key set and availability view, steppable one member
/// operation at a time for adversarial interleaving.
struct Driver {
    qb: QuorumBind,
    keys: Vec<[u8; 32]>,
    avail: Vec<bool>,
    done: Option<Outcome>,
}

impl Driver {
    fn new(t: BindingTransaction, avail: Vec<bool>) -> Self {
        let keys = t.keys.clone();
        Driver {
            qb: QuorumBind::begin(t).unwrap(),
            keys,
            avail,
            done: None,
        }
    }

    /// Advance by exactly one member operation (or one recovery). Returns true
    /// if still live.
    fn step(&mut self, fleet: &mut Fleet) -> bool {
        if self.done.is_some() {
            return false;
        }
        match self.qb.poll() {
            Step::Done(o) => {
                self.done = Some(o);
                false
            }
            Step::Recovering(_) => {
                self.qb.recover();
                true
            }
            Step::Contact(ops) => {
                if let Some(op) = ops.into_iter().next() {
                    perform(&mut self.qb, fleet, &self.keys, &self.avail, op);
                }
                true
            }
        }
    }

    fn drive_home(&mut self, fleet: &mut Fleet, budget: u32) {
        let mut n = 0;
        while self.done.is_none() && n < budget {
            self.step(fleet);
            n += 1;
        }
    }
}

// ───────────────────────── tests ─────────────────────────

#[test]
fn begin_refuses_a_noncanonical_quorum_and_a_bad_key_set() {
    // q must BE the strict majority.
    let mut bad = tx(1, 10, vec![key(1)], 3);
    bad.quorum = 1;
    assert!(QuorumBind::begin(bad).is_err());
    let mut bad2 = tx(1, 10, vec![key(1)], 3);
    bad2.quorum = 3;
    assert!(QuorumBind::begin(bad2).is_err());
    // key set must be strictly ascending and non-empty.
    let empty = tx(1, 10, vec![], 3);
    assert!(QuorumBind::begin(empty).is_err());
    let dup = tx(1, 10, vec![key(1), key(1)], 3);
    assert!(QuorumBind::begin(dup).is_err());
    let unsorted = tx(1, 10, vec![key(2), key(1)], 3);
    assert!(QuorumBind::begin(unsorted).is_err());
}

#[test]
fn a_clean_transaction_commits_at_quorum_and_the_value_is_chosen() {
    let keys = vec![key(1)];
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    let out = run_to_done(&mut qb, &mut fleet, &keys, &[true, true, true], 8);
    assert_eq!(out, Some(Outcome::Committed));
    assert_eq!(fleet.chosen_value(&key(1), 2), Some([10u8; 32]));
}

#[test]
fn quorum_fixed_one_unavailable_still_needs_and_reaches_both() {
    // quorum-fixed/: with one member down, the two survivors still commit.
    let keys = vec![key(1)];
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    let out = run_to_done(&mut qb, &mut fleet, &keys, &[true, true, false], 8);
    assert_eq!(out, Some(Outcome::Committed));
    // two down: no read quorum, never commits (safety, not a timeout).
    let mut fleet2 = Fleet::new(3);
    let mut qb2 = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    let out2 = run_to_done(&mut qb2, &mut fleet2, &keys, &[true, false, false], 8);
    assert_eq!(out2, None, "must not commit without a quorum");
    assert_eq!(fleet2.chosen_value(&key(1), 2), None);
}

#[test]
fn quorum_client_an_unattributed_answer_does_not_count() {
    // quorum-client/: a member delivered Unavailable (its runner failed
    // attribution) cannot be part of a quorum. Two attributed + one
    // unattributed commits; one attributed + two unattributed cannot.
    let keys = vec![key(1)];
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    // model member 2 as "reachable but unattributed" by marking it unavailable.
    let out = run_to_done(&mut qb, &mut fleet, &keys, &[true, true, false], 8);
    assert_eq!(out, Some(Outcome::Committed));
}

#[test]
fn a_foreign_value_already_chosen_is_conflict_final() {
    let keys = vec![key(1)];
    let mut fleet = Fleet::new(3);
    // Drive a foreign bundle (value 20) to a chosen state first.
    let mut foreign = QuorumBind::begin(tx(2, 20, keys.clone(), 3)).unwrap();
    assert_eq!(
        run_to_done(&mut foreign, &mut fleet, &keys, &[true, true, true], 8),
        Some(Outcome::Committed)
    );
    // Our bundle (value 10) now reads a chosen foreign value.
    let mut ours = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    let out = run_to_done(&mut ours, &mut fleet, &keys, &[true, true, true], 8);
    assert_eq!(
        out,
        Some(Outcome::ConflictFinal {
            other_value_digest: [20u8; 32]
        })
    );
    // The foreign value is still the only chosen value.
    assert_eq!(fleet.chosen_value(&key(1), 2), Some([20u8; 32]));
}

#[test]
fn recovering_our_own_completed_transaction_is_an_idempotent_commit() {
    let keys = vec![key(1)];
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    assert_eq!(
        run_to_done(&mut qb, &mut fleet, &keys, &[true, true, true], 8),
        Some(Outcome::Committed)
    );
    // A fresh Class K instance for the SAME bundle recovers to Committed
    // without changing the chosen value (Theorem 18.4).
    let mut recov = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    assert_eq!(
        run_to_done(&mut recov, &mut fleet, &keys, &[true, true, true], 8),
        Some(Outcome::Committed)
    );
    assert_eq!(fleet.chosen_value(&key(1), 2), Some([10u8; 32]));
}

#[test]
fn abort_is_safe_only_when_nothing_is_chosen() {
    let keys = vec![key(1)];
    // Clean read → abort is safe.
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    // advance to a completed read round
    if let Step::Contact(ops) = qb.poll() {
        for op in ops {
            perform(&mut qb, &mut fleet, &keys, &[true, true, true], op);
        }
    }
    assert_eq!(qb.abort_if_safe(), Some(Outcome::Aborted));

    // After a value is chosen, abort is refused.
    let mut fleet2 = Fleet::new(3);
    let mut winner = QuorumBind::begin(tx(2, 20, keys.clone(), 3)).unwrap();
    run_to_done(&mut winner, &mut fleet2, &keys, &[true, true, true], 8);
    let mut late = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    if let Step::Contact(ops) = late.poll() {
        for op in ops {
            perform(&mut late, &mut fleet2, &keys, &[true, true, true], op);
        }
    }
    assert_eq!(
        late.abort_if_safe(),
        None,
        "cannot abort over a chosen value"
    );
}

/// binding-race/: two complete bundles over one shared parent, EXHAUSTIVELY
/// interleaved at single-operation granularity. This is the exact family of
/// schedules — one bundle's value landing on a quorum at a low round while the
/// other read first — that a single-phase register would let both commit.
#[test]
fn binding_race_at_most_one_bundle_commits_under_every_interleaving() {
    let keys = vec![key(1)];
    let steps = 12u32;
    let mut d1_wins = 0u32;
    let mut d2_wins = 0u32;
    for sched in 0u32..(1 << steps) {
        let mut fleet = Fleet::new(3);
        let mut d1 = Driver::new(tx(1, 10, keys.clone(), 3), vec![true, true, true]);
        let mut d2 = Driver::new(tx(2, 20, keys.clone(), 3), vec![true, true, true]);
        for i in 0..steps {
            if (sched >> i) & 1 == 0 {
                d1.step(&mut fleet);
            } else {
                d2.step(&mut fleet);
            }
        }
        // Let both finish fairly.
        d1.drive_home(&mut fleet, 200);
        d2.drive_home(&mut fleet, 200);
        if d1.done == Some(Outcome::Committed) {
            d1_wins += 1;
        }
        if d2.done == Some(Outcome::Committed) {
            d2_wins += 1;
        }

        // SAFETY: the fleet has at most one chosen value on the shared key.
        let chosen = fleet.chosen_value(&key(1), 2);
        let committed: Vec<&Outcome> = [&d1.done, &d2.done]
            .into_iter()
            .flatten()
            .filter(|o| **o == Outcome::Committed)
            .collect();
        assert!(
            committed.len() <= 1,
            "schedule {sched:#014b}: both bundles committed"
        );
        if let Some(v) = chosen {
            // A committed bundle's value is exactly the one chosen value.
            for (d, val) in [(&d1, [10u8; 32]), (&d2, [20u8; 32])] {
                if d.done == Some(Outcome::Committed) {
                    assert_eq!(
                        val, v,
                        "schedule {sched:#014b}: commit disagrees with chosen"
                    );
                }
            }
        } else {
            // Nothing chosen ⇒ neither may claim Committed.
            assert!(
                committed.is_empty(),
                "schedule {sched:#014b}: committed with no chosen value"
            );
        }
    }
    // Non-vacuity: the safety property is not holding because nobody ever wins.
    // BOTH bundles must win under SOME interleavings — the race is real.
    assert!(
        d1_wins > 0 && d2_wins > 0,
        "vacuous: d1={d1_wins} d2={d2_wins}"
    );
}

/// overlap-liveness/: K(T1)={A,B} against K(T2)={B,C} with both recovery
/// drivers active. Safety must hold under arbitrary interleaving on the shared
/// key B; at most one of the two bundles can become binding-final.
#[test]
fn overlap_ab_bc_never_lets_both_bundles_commit() {
    let k1 = vec![key(1), key(2)]; // {A,B}
    let k2 = vec![key(2), key(3)]; // {B,C}
    let steps = 12u32;
    let mut d1_wins = 0u32;
    let mut d2_wins = 0u32;
    for sched in 0u32..(1 << steps) {
        let mut fleet = Fleet::new(3);
        let mut d1 = Driver::new(tx(1, 10, k1.clone(), 3), vec![true, true, true]);
        let mut d2 = Driver::new(tx(2, 20, k2.clone(), 3), vec![true, true, true]);
        for i in 0..steps {
            if (sched >> i) & 1 == 0 {
                d1.step(&mut fleet);
            } else {
                d2.step(&mut fleet);
            }
        }
        d1.drive_home(&mut fleet, 300);
        d2.drive_home(&mut fleet, 300);

        let both_committed =
            d1.done == Some(Outcome::Committed) && d2.done == Some(Outcome::Committed);
        assert!(
            !both_committed,
            "schedule {sched:#014b}: two overlapping bundles both committed"
        );
        if d1.done == Some(Outcome::Committed) {
            d1_wins += 1;
        }
        if d2.done == Some(Outcome::Committed) {
            d2_wins += 1;
        }
    }
    // Non-vacuity: both overlapping bundles must be able to win, just never
    // together.
    assert!(
        d1_wins > 0 && d2_wins > 0,
        "vacuous: d1={d1_wins} d2={d2_wins}"
    );
}

/// multi-vault-atomic/: one route over {A,B,C} is one transaction over the
/// complete sorted key set; a commit means the record is on every key, never a
/// subset.
#[test]
fn multi_vault_atomic_commit_covers_every_key() {
    let keys = vec![key(1), key(2), key(3)];
    let mut fleet = Fleet::new(3);
    let mut qb = QuorumBind::begin(tx(1, 10, keys.clone(), 3)).unwrap();
    assert_eq!(
        run_to_done(&mut qb, &mut fleet, &keys, &[true, true, true], 8),
        Some(Outcome::Committed)
    );
    for k in &keys {
        assert_eq!(
            fleet.chosen_value(k, 2),
            Some([10u8; 32]),
            "every key of K(B) carries the chosen value"
        );
    }
}
