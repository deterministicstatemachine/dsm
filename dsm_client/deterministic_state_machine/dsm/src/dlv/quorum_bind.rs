// SPDX-License-Identifier: Apache-2.0

//! CLASS K QUORUMBIND — the sans-IO decision engine (Rev 15 §6.8 Def 6.21,
//! Req 6.22, Theorem 18.1).
//!
//! This is the client-driven quorum transaction that drives the exact `S`,
//! `q`, and `K(B)` committed by a bundle to one consume-once decision. It is a
//! **pure state machine**: it performs no networking, no sleeping, no retry
//! timers, and no async I/O. It consumes authenticated member observations and
//! emits the next deterministic storage operations; a runner in the SDK
//! performs those operations and feeds the results back with the `deliver_*`
//! methods. All timing, backoff, and concurrency live in that runner; the
//! safety algorithm here stays deterministic, so `binding-race`,
//! `binding-split`, and overlapping `{A,B}` / `{B,C}` schedules can be driven
//! adversarially against a fleet double without forcing real scheduling.
//!
//! ## Two-phase, because the register supersedes
//!
//! The generic compare-and-exchange of Class N (PR #772) is a **max-round CAS
//! register**: it installs a record on every key or none, but a *strictly
//! higher* round with a *different* value may overwrite what a quorum already
//! holds. A single accept phase over such a register is NOT safe — a value on
//! a quorum at a low round can be overwritten by a higher round whose proposer
//! read before that value landed, which is exactly the state Paxos forbids and
//! would let two bundles both become binding-final. Req 6.22 therefore
//! prescribes Paxos-style prepare/accept rounds, and this engine implements
//! them:
//!
//! - **Learn** — `ReadBinding(K(B))` a quorum to discover the safe value (the
//!   value of the highest-round *accepted* record) and any already-chosen
//!   value.
//! - **Promise** — compare-exchange a `PROMISED` record at round `2·ballot`
//!   onto a quorum. The member's monotonic-round rule makes this the promise:
//!   once a member holds a promise at ballot `b`, it refuses every accept below
//!   `b`.
//! - **Accept** — compare-exchange an `ACCEPTED` record at round `2·ballot+1`
//!   (which supersedes this ballot's own promise) onto a quorum.
//!
//! The phase rides in the round counter (`2·ballot` promise, `2·ballot+1`
//! accept) so one monotonic round expresses both, and `status` records which.
//! A bundle either owns *every* key or yields: the engine proposes only when no
//! key's highest accepted value is a foreign bundle's, so at most one bundle
//! accepts on a shared key. `COMMITTED` is `q` distinct authenticated members
//! holding this bundle's accepted record at the same round on every key;
//! `ABORTED` is reachable only when no value is chosen anywhere — never from
//! elapsed time.

use crate::dlv::binding_observation;
use crate::storage::binding_record::{
    keyset_digest, record_set_digest, validate_key_set, BindingEncodingError, BindingRecord, Round,
    SetCell, BINDING_RECORD_SCHEMA_V1,
};

/// A generic binding record that promises a ballot but chooses no value yet.
/// The node never interprets `status` (Req 15.7); it is Class K metadata.
pub const BINDING_STATUS_PROMISED: u32 = 1;
/// A generic binding record that accepts a transaction value at a ballot.
pub const BINDING_STATUS_ACCEPTED: u32 = 2;

/// A member of the exact owner-committed storage set `S`, named by the two
/// facts a quorum counts: its committed id and the committed register
/// incarnation. The runner authenticates a member's answer against BOTH before
/// it reaches this engine (Req 15.8); an answer that fails either is delivered
/// as [`MemberRead::Unavailable`] / [`MemberCas::Unavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedMember {
    pub member_id: Vec<u8>,
    pub register_incarnation: [u8; 32],
}

/// The complete, committed inputs to one quorum transaction. Nothing here is
/// discretionary at run time: `S`, `q`, and `K(B)` come from the bundle, and
/// the value address/digest name the immutable bytes already stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingTransaction {
    /// This Class K instance's proposer id — the low tiebreak of every round.
    pub proposer_id: [u8; 32],
    /// The exact owner-committed set `S`.
    pub members: Vec<CommittedMember>,
    /// The owner-committed `q`, carried, never re-derived (§22 #10).
    pub quorum: u32,
    /// `K(B)`, strictly ascending.
    pub keys: Vec<[u8; 32]>,
    /// The bundle's transaction id.
    pub tx_id: [u8; 32],
    /// The immutable value the record points at.
    pub value_addr: [u8; 32],
    pub value_digest: [u8; 32],
    /// A proposer-local monotonic ballot floor. The first ballot is
    /// `max(base_ballot, highest ballot read) + 1`; PR 3 persists it so a
    /// restarted proposer never reuses a ballot.
    pub base_ballot: u64,
}

/// Why a transaction could not even begin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    /// `K(B)` is empty or not strictly ascending.
    KeySet(BindingEncodingError),
    /// `S` is empty, or `q` is not the strict majority of `|S|`.
    Profile { members: usize, quorum: u32 },
}

impl core::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransactionError::KeySet(e) => write!(f, "invalid key set: {e}"),
            TransactionError::Profile { members, quorum } => write!(
                f,
                "q={quorum} is not the strict majority of a {members}-member set"
            ),
        }
    }
}
impl std::error::Error for TransactionError {}

/// What one member answered to a `ReadBinding` over `K(B)`, already
/// authenticated. `Records` is in the exact key order of `K(B)`: `None` at a
/// key is the member's explicit assertion that it holds nothing there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRead {
    Records(Vec<Option<BindingRecord>>),
    /// No usable answer. Never counted toward a quorum or toward emptiness.
    Unavailable,
}

/// What one member answered to a `CompareExchangeMany`, already authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberCas {
    /// The member now holds the replacement on every key.
    Applied,
    /// The member's state was not what we exchanged from (a higher round
    /// promised or accepted, or the state moved); recover at a higher ballot.
    ExpectationMismatch,
    /// A storage-domain refusal (canonical/keyset). Nothing was written.
    InvalidStorageEncoding,
    /// No usable answer.
    Unavailable,
}

/// One operation the runner must perform against one member this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOp {
    /// `ReadBinding(K(B))` at `member_ix`.
    Read { member_ix: usize },
    /// `CompareExchangeMany` at `member_ix`: exchange from `expected_digest` to
    /// `replacement_bytes` (the canonical bytes of a promise or accept record).
    CompareExchange {
        member_ix: usize,
        expected_digest: [u8; 32],
        replacement_bytes: Vec<u8>,
    },
}

/// What the engine wants next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Perform these operations (the members not yet heard from this round) and
    /// `deliver` each result. Concurrency is the runner's choice; order does
    /// not affect the decision.
    Contact(Vec<MemberOp>),
    /// This round completed without a terminal outcome and cannot progress
    /// without a fresh, higher ballot. The runner applies operational backoff,
    /// then calls [`recover`](QuorumBind::recover) to start the next ballot —
    /// or, if it is giving up a not-yet-chosen attempt, [`abort_if_safe`].
    /// Safety never depends on how long the runner waits.
    Recovering(Recovering),
    /// Terminal. Reroute discipline (Req 9.6) is the caller's.
    Done(Outcome),
}

/// Why a round is stuck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovering {
    /// Fewer than `q` members were reachable for a read; no safe value can be
    /// established yet.
    NoReadQuorum { attributed: u32, required: u32 },
    /// A key's highest accepted value is a foreign bundle's, not yet chosen;
    /// the engine must not overwrite a value that could still be chosen.
    Contended { blocked_key_ix: usize },
    /// A promise round did not reach `q` (another ballot interfered).
    PromiseIncomplete { promised: u32, required: u32 },
    /// An accept round did not reach `q` (another ballot interfered).
    AcceptIncomplete { accepted: u32, required: u32 },
}

/// The protocol-visible terminal outcomes of Def 6.21.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `q` distinct authenticated members hold this bundle's accepted record on
    /// every key of `K(B)`. Binding-final for the named DLV parents; does NOT
    /// itself move any reserve cursor or advance any chain.
    Committed,
    /// Recovery safely decided the bundle will not become binding-final and no
    /// value is chosen anywhere in `K(B)`.
    Aborted,
    /// An overlapping key already belongs to a different binding-final value.
    ConflictFinal { other_value_digest: [u8; 32] },
    /// A storage-domain check failed before any value could be chosen.
    Invalid,
}

/// The sans-IO Class K quorum-binding driver for one bundle.
#[derive(Debug, Clone)]
pub struct QuorumBind {
    tx: BindingTransaction,
    keyset_digest: [u8; 32],
    /// The ballot currently being driven. Only ever increases.
    ballot: u64,
    phase: Phase,
    /// Per-member answer for the current round, indexed like `tx.members`.
    read_answers: Vec<Option<MemberRead>>,
    promise_answers: Vec<Option<MemberCas>>,
    accept_answers: Vec<Option<MemberCas>>,
    /// The digest each member held at the READ that opened this ballot, so the
    /// promise can exchange from it. Indexed like `tx.members`.
    read_digest: Vec<Option<[u8; 32]>>,
    /// True once any promise/accept op has been emitted: from here a lost
    /// answer is INDETERMINATE, not a non-commit, and PR 3 keeps the fence.
    mutated: bool,
    /// The terminal outcome, once reached, so polling after `Done` is
    /// idempotent.
    outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Learn,
    Promise,
    Accept,
    Done,
}

impl QuorumBind {
    /// Begin a transaction. Refuses a non-strict-majority `q` (the committed
    /// value must BE the canonical quorum, in both directions) and an invalid
    /// key set.
    pub fn begin(tx: BindingTransaction) -> Result<Self, TransactionError> {
        validate_key_set(&tx.keys).map_err(TransactionError::KeySet)?;
        let n = tx.members.len();
        if n == 0 || tx.quorum != strict_majority(n) {
            return Err(TransactionError::Profile {
                members: n,
                quorum: tx.quorum,
            });
        }
        let ksd = keyset_digest(&tx.keys);
        let ballot = tx.base_ballot.max(1);
        Ok(Self {
            tx,
            keyset_digest: ksd,
            ballot,
            phase: Phase::Learn,
            read_answers: vec![None; n],
            promise_answers: vec![None; n],
            accept_answers: vec![None; n],
            read_digest: vec![None; n],
            mutated: false,
            outcome: None,
        })
    }

    /// The ballot currently being driven. PR 3 persists it.
    pub fn ballot(&self) -> u64 {
        self.ballot
    }

    /// Whether any mutating operation has been emitted. Once true, a lost
    /// outcome is INDETERMINATE and the trader-parent fence must be kept.
    pub fn mutated(&self) -> bool {
        self.mutated
    }

    /// The next thing to do. Pure and idempotent between `deliver` calls.
    pub fn poll(&mut self) -> Step {
        match self.phase {
            Phase::Done => Step::Done(self.outcome.clone().unwrap_or(Outcome::Invalid)),
            Phase::Learn => self.poll_learn(),
            Phase::Promise => self.poll_promise(),
            Phase::Accept => self.poll_accept(),
        }
    }

    /// Feed a member's authenticated `ReadBinding` answer for the current round.
    pub fn deliver_read(&mut self, member_ix: usize, answer: MemberRead) {
        if self.phase == Phase::Learn {
            if let (Some(slot), Some(dslot)) = (
                self.read_answers.get_mut(member_ix),
                self.read_digest.get_mut(member_ix),
            ) {
                *dslot = match &answer {
                    MemberRead::Records(recs) if recs.len() == self.tx.keys.len() => {
                        Some(set_digest_of(&self.tx.keys, recs))
                    }
                    _ => None,
                };
                *slot = Some(answer);
            }
        }
    }

    /// Feed a member's authenticated promise `CompareExchangeMany` answer.
    pub fn deliver_promise(&mut self, member_ix: usize, answer: MemberCas) {
        if self.phase == Phase::Promise {
            if let Some(slot) = self.promise_answers.get_mut(member_ix) {
                *slot = Some(answer);
            }
        }
    }

    /// Feed a member's authenticated accept `CompareExchangeMany` answer.
    pub fn deliver_accept(&mut self, member_ix: usize, answer: MemberCas) {
        if self.phase == Phase::Accept {
            if let Some(slot) = self.accept_answers.get_mut(member_ix) {
                *slot = Some(answer);
            }
        }
    }

    /// Route a `CompareExchangeMany` answer to the current mutating phase. The
    /// runner uses this so it need not track whether an emitted
    /// [`MemberOp::CompareExchange`] was a promise or an accept: the engine is
    /// in exactly one mutating phase while a batch is outstanding.
    pub fn deliver_cas(&mut self, member_ix: usize, answer: MemberCas) {
        match self.phase {
            Phase::Promise => self.deliver_promise(member_ix, answer),
            Phase::Accept => self.deliver_accept(member_ix, answer),
            Phase::Learn | Phase::Done => {}
        }
    }

    /// Start the next ballot after a [`Step::Recovering`]. Advances the ballot,
    /// clears per-round answers, and re-enters the learn phase. The runner
    /// calls this AFTER its backoff; the engine itself never waits.
    pub fn recover(&mut self) {
        if self.phase == Phase::Done {
            return;
        }
        self.ballot = self.ballot.saturating_add(1);
        self.reset_round();
        self.phase = Phase::Learn;
    }

    /// Safely abort a not-yet-chosen attempt. Returns `Some(Aborted)` and moves
    /// to the terminal state ONLY when the current read evidence shows no value
    /// chosen anywhere in `K(B)`; otherwise `None`. Call only from a completed
    /// learn round.
    pub fn abort_if_safe(&mut self) -> Option<Outcome> {
        if self.phase != Phase::Learn || !all_some(&self.read_answers) {
            return None;
        }
        if self.fold_reads().any_chosen() {
            return None;
        }
        self.phase = Phase::Done;
        self.outcome = Some(Outcome::Aborted);
        Some(Outcome::Aborted)
    }

    // ── phase drivers ────────────────────────────────────────────────────

    fn poll_learn(&mut self) -> Step {
        if !all_some(&self.read_answers) {
            let ops = (0..self.tx.members.len())
                .filter(|ix| self.read_answers[*ix].is_none())
                .map(|member_ix| MemberOp::Read { member_ix })
                .collect();
            return Step::Contact(ops);
        }
        let ev = self.fold_reads();
        if ev.attributed < self.tx.quorum {
            return Step::Recovering(Recovering::NoReadQuorum {
                attributed: ev.attributed,
                required: self.tx.quorum,
            });
        }
        if let Some(other) = ev.foreign_chosen_value() {
            return self.finish(Outcome::ConflictFinal {
                other_value_digest: other,
            });
        }
        if ev.all_keys_chosen_ours() {
            return self.finish(Outcome::Committed);
        }
        if let Some(k) = ev.first_foreign_accepted_key() {
            return Step::Recovering(Recovering::Contended { blocked_key_ix: k });
        }
        // Clean: our bundle may own every key. Raise the ballot above every
        // ballot we read, then promise.
        self.ballot = ev
            .max_ballot()
            .saturating_add(1)
            .max(self.ballot)
            .max(self.tx.base_ballot);
        self.phase = Phase::Promise;
        self.poll_promise()
    }

    fn poll_promise(&mut self) -> Step {
        let record = self.record(BINDING_STATUS_PROMISED, self.promise_round());
        let bytes = record.encode();
        if !all_some(&self.promise_answers) {
            let missing: Vec<Option<MemberCas>> = self.promise_answers.clone();
            let keys = self.tx.keys.clone();
            let digests = self.read_digest.clone();
            self.mutated = true;
            let ops = (0..self.tx.members.len())
                .filter(|ix| missing[*ix].is_none())
                .map(|member_ix| MemberOp::CompareExchange {
                    member_ix,
                    // Exchange from exactly what the read saw; a member absent
                    // from the read exchanges from the empty set and will
                    // simply mismatch if it in fact holds something.
                    expected_digest: digests[member_ix]
                        .unwrap_or_else(|| empty_set_digest_of(&keys)),
                    replacement_bytes: bytes.clone(),
                })
                .collect();
            return Step::Contact(ops);
        }
        let promised = count_applied(&self.promise_answers);
        if promised >= self.tx.quorum {
            self.phase = Phase::Accept;
            return self.poll_accept();
        }
        Step::Recovering(Recovering::PromiseIncomplete {
            promised,
            required: self.tx.quorum,
        })
    }

    fn poll_accept(&mut self) -> Step {
        let promise_record = self.record(BINDING_STATUS_PROMISED, self.promise_round());
        let accept_record = self.record(BINDING_STATUS_ACCEPTED, self.accept_round());
        let bytes = accept_record.encode();
        // After our promise, a promised member holds our promise record on every
        // key: the accept exchanges from that.
        let expected = uniform_set_digest(&self.tx.keys, promise_record.digest());
        if !self.accept_round_complete() {
            let promise_answers = self.promise_answers.clone();
            let accept_answers = self.accept_answers.clone();
            self.mutated = true;
            let ops = (0..self.tx.members.len())
                .filter(|ix| {
                    // Accept only where we hold a promise, and only where we
                    // have not yet heard an accept answer.
                    promise_answers[*ix] == Some(MemberCas::Applied)
                        && accept_answers[*ix].is_none()
                })
                .map(|member_ix| MemberOp::CompareExchange {
                    member_ix,
                    expected_digest: expected,
                    replacement_bytes: bytes.clone(),
                })
                .collect();
            return Step::Contact(ops);
        }
        let accepted = count_applied(&self.accept_answers);
        if accepted >= self.tx.quorum {
            return self.finish(Outcome::Committed);
        }
        let invalid = self
            .accept_answers
            .iter()
            .flatten()
            .any(|a| *a == MemberCas::InvalidStorageEncoding);
        if invalid && accepted == 0 {
            return self.finish(Outcome::Invalid);
        }
        Step::Recovering(Recovering::AcceptIncomplete {
            accepted,
            required: self.tx.quorum,
        })
    }

    /// The accept round is complete when every member we promised has answered
    /// (members we did not promise are not contacted for accept).
    fn accept_round_complete(&self) -> bool {
        (0..self.tx.members.len()).all(|ix| {
            self.promise_answers[ix] != Some(MemberCas::Applied)
                || self.accept_answers[ix].is_some()
        })
    }

    fn finish(&mut self, o: Outcome) -> Step {
        self.phase = Phase::Done;
        self.outcome = Some(o.clone());
        Step::Done(o)
    }

    // ── records & evidence ───────────────────────────────────────────────

    fn promise_round(&self) -> Round {
        Round {
            counter: self.ballot.saturating_mul(2),
            proposer_id: self.tx.proposer_id,
        }
    }
    fn accept_round(&self) -> Round {
        Round {
            counter: self.ballot.saturating_mul(2).saturating_add(1),
            proposer_id: self.tx.proposer_id,
        }
    }

    fn record(&self, status: u32, round: Round) -> BindingRecord {
        BindingRecord {
            schema: BINDING_RECORD_SCHEMA_V1,
            round,
            tx_id: self.tx.tx_id,
            keyset_digest: self.keyset_digest,
            value_digest: self.tx.value_digest,
            value_addr: self.tx.value_addr,
            status,
        }
    }

    fn is_ours(&self, rec: &BindingRecord) -> bool {
        rec.tx_id == self.tx.tx_id
            && rec.value_digest == self.tx.value_digest
            && rec.value_addr == self.tx.value_addr
    }

    fn reset_round(&mut self) {
        self.read_answers.fill(None);
        self.promise_answers.fill(None);
        self.accept_answers.fill(None);
        self.read_digest.fill(None);
    }

    /// Fold this round's read answers into the evidence the decision rule
    /// consumes. The per-key tally itself lives in
    /// [`crate::dlv::binding_observation::tally_key`] and is shared with every
    /// observer, so a proposer and a composer cannot drift on what "chosen"
    /// means. All this adds is `highest_is_ours`, which only a proposer can
    /// answer.
    fn fold_reads(&self) -> ReadEvidence {
        let (per_member, attributed) =
            binding_observation::attributed_records(&self.read_answers, self.tx.keys.len());
        let mut keys = Vec::with_capacity(self.tx.keys.len());
        let mut max_ballot = 0u64;
        for ki in 0..self.tx.keys.len() {
            let t = binding_observation::tally_key(&per_member, ki, self.tx.quorum);
            max_ballot = max_ballot.max(t.max_ballot);
            let highest_is_ours = t.highest_accept.as_ref().is_some_and(|h| self.is_ours(h));
            keys.push(KeyView {
                highest_accept: t.highest_accept,
                holders_at_highest: t.holders_at_highest,
                highest_is_ours,
            });
        }
        ReadEvidence {
            attributed,
            quorum: self.tx.quorum,
            max_ballot,
            keys,
        }
    }
}

/// The strict majority of `n`: the smallest `q` with `2q > n`.
pub fn strict_majority(n: usize) -> u32 {
    (n as u32 / 2) + 1
}

fn all_some<T>(v: &[Option<T>]) -> bool {
    v.iter().all(|a| a.is_some())
}

fn count_applied(answers: &[Option<MemberCas>]) -> u32 {
    answers
        .iter()
        .flatten()
        .filter(|a| **a == MemberCas::Applied)
        .count() as u32
}

fn set_digest_of(keys: &[[u8; 32]], recs: &[Option<BindingRecord>]) -> [u8; 32] {
    let cells: Vec<SetCell> = keys
        .iter()
        .zip(recs.iter())
        .map(|(k, r)| SetCell {
            key: *k,
            record_digest: r.as_ref().map(|rec| rec.digest()),
        })
        .collect();
    record_set_digest(&cells)
}

fn empty_set_digest_of(keys: &[[u8; 32]]) -> [u8; 32] {
    let cells: Vec<SetCell> = keys
        .iter()
        .map(|k| SetCell {
            key: *k,
            record_digest: None,
        })
        .collect();
    record_set_digest(&cells)
}

fn uniform_set_digest(keys: &[[u8; 32]], record_digest: [u8; 32]) -> [u8; 32] {
    let cells: Vec<SetCell> = keys
        .iter()
        .map(|k| SetCell {
            key: *k,
            record_digest: Some(record_digest),
        })
        .collect();
    record_set_digest(&cells)
}

struct KeyView {
    highest_accept: Option<BindingRecord>,
    holders_at_highest: u32,
    highest_is_ours: bool,
}

struct ReadEvidence {
    attributed: u32,
    quorum: u32,
    max_ballot: u64,
    keys: Vec<KeyView>,
}

impl ReadEvidence {
    fn max_ballot(&self) -> u64 {
        self.max_ballot
    }

    fn any_chosen(&self) -> bool {
        self.keys
            .iter()
            .any(|k| k.highest_accept.is_some() && k.holders_at_highest >= self.quorum)
    }

    fn foreign_chosen_value(&self) -> Option<[u8; 32]> {
        self.keys.iter().find_map(|k| match &k.highest_accept {
            Some(h) if !k.highest_is_ours && k.holders_at_highest >= self.quorum => {
                Some(h.value_digest)
            }
            _ => None,
        })
    }

    fn all_keys_chosen_ours(&self) -> bool {
        self.keys
            .iter()
            .all(|k| k.highest_is_ours && k.holders_at_highest >= self.quorum)
    }

    /// The first key whose highest accepted value is a foreign bundle's — we
    /// must not overwrite a value that could still be chosen.
    fn first_foreign_accepted_key(&self) -> Option<usize> {
        self.keys
            .iter()
            .position(|k| k.highest_accept.is_some() && !k.highest_is_ours)
    }
}
