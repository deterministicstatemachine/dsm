// SPDX-License-Identifier: Apache-2.0

//! THE THIN ASYNC CLASS K RUNNER — plumbing around the sans-IO engine.
//!
//! [`dsm::dlv::quorum_bind::QuorumBind`] is a pure decision engine: it emits the
//! member operations to perform and folds authenticated answers. This runner is
//! the only place the timing lives. It:
//!
//! 1. asks the engine what to do ([`QuorumBind::poll`]);
//! 2. performs each emitted operation through a [`BindingTransport`] (the HTTP
//!    client for `/api/v2/storage/binding/{cas,read}` arrives in PR 4);
//! 3. **authenticates every answer against BOTH the committed member id and the
//!    committed register incarnation** (Req 15.8) before it counts — a write
//!    acknowledgement that does not name both is not countable;
//! 4. on `Recovering`, applies randomized operational backoff and asks the
//!    engine to open the next ballot.
//!
//! Safety never depends on the backoff: elapsed time cannot change a protocol
//! decision (Req 15.11, §22 #16). The runner is one recovery worker for one
//! unresolved transaction on one device (§22 #16).

use std::time::Duration;

use async_trait::async_trait;
use dsm::dlv::quorum_bind::{
    CommittedMember, MemberCas, MemberOp, MemberRead, Outcome, QuorumBind, Step,
};
use dsm::storage::binding_record::BindingRecord;

/// A member's `ReadBinding` answer as the transport observed it, before
/// attribution. The runner turns it into a countable [`MemberRead`] only when
/// the echo names the committed member.
pub struct TransportRead {
    /// The `member_id` the node stamped on its answer.
    pub echoed_member_id: Option<Vec<u8>>,
    /// The `x-dsm-register-incarnation` the node echoed.
    pub echoed_incarnation: Option<[u8; 32]>,
    /// The per-key records, in `K(B)` order, or `None` if the transport failed
    /// or the node has no established incarnation (503).
    pub records: Option<Vec<Option<BindingRecord>>>,
}

/// A member's `CompareExchangeMany` answer as the transport observed it.
pub struct TransportCas {
    pub echoed_member_id: Option<Vec<u8>>,
    pub echoed_incarnation: Option<[u8; 32]>,
    /// The storage outcome, or `None` if the transport failed / 503.
    pub outcome: Option<CasOutcome>,
}

/// The three storage outcomes a member can return for a conditional exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    Applied,
    ExpectationMismatch,
    InvalidStorageEncoding,
}

/// One member's two generic storage operations. Implemented by the HTTP client
/// (PR 4) and by test doubles. The engine — not this trait — decides what to
/// send and how to fold the answers; the trait is pure plumbing, which is why
/// it, and not the engine, is the async boundary.
#[async_trait]
pub trait BindingTransport {
    async fn read_binding(&self, member_ix: usize, keys: &[[u8; 32]]) -> TransportRead;
    async fn compare_exchange(
        &self,
        member_ix: usize,
        keys: &[[u8; 32]],
        expected_digest: [u8; 32],
        replacement_bytes: &[u8],
    ) -> TransportCas;
}

/// Randomized operational backoff between recovery ballots. Not a protocol
/// object: it changes only when the runner retries, never which value is valid.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub base: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            base: Duration::from_millis(20),
            max: Duration::from_millis(2000),
        }
    }
}

impl Backoff {
    fn delay(&self, attempt: u32) -> Duration {
        let shift = attempt.min(20);
        let scaled = self.base.saturating_mul(1u32 << shift.min(16));
        let capped = scaled.min(self.max);
        // Full jitter in [0, capped]. Operational only.
        let jitter: f64 = rand::random::<f64>();
        capped.mul_f64(jitter)
    }
}

/// Whether an answer's echo authenticates the exact committed member: BOTH the
/// id and the register incarnation must match (Req 15.8). This is the write-side
/// attribution the settlement-slot path lacked.
fn counts_for(
    member: &CommittedMember,
    echoed_id: Option<&[u8]>,
    echoed_incarnation: Option<[u8; 32]>,
) -> bool {
    echoed_id == Some(member.member_id.as_slice())
        && echoed_incarnation == Some(member.register_incarnation)
}

/// Why the runner stopped without a terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The recovery-ballot budget was exhausted before a terminal outcome. The
    /// transaction is INDETERMINATE if it mutated; the caller keeps the
    /// trader-parent fence and may resume recovery later (PR 3).
    Unresolved { mutated: bool },
}

/// Drive one transaction to a terminal [`Outcome`], authenticating every answer
/// and backing off between ballots. `max_ballots` bounds recovery attempts for
/// this call; exhausting it is not ABORT — the transaction stays recoverable.
pub async fn run<T: BindingTransport + ?Sized>(
    engine: &mut QuorumBind,
    members: &[CommittedMember],
    keys: &[[u8; 32]],
    transport: &T,
    backoff: Backoff,
    max_ballots: u32,
) -> Result<Outcome, RunError> {
    let mut attempt = 0u32;
    loop {
        match engine.poll() {
            Step::Done(o) => return Ok(o),
            Step::Contact(ops) => {
                for op in ops {
                    match op {
                        MemberOp::Read { member_ix } => {
                            let r = transport.read_binding(member_ix, keys).await;
                            let answer = match r.records {
                                Some(recs)
                                    if counts_for(
                                        &members[member_ix],
                                        r.echoed_member_id.as_deref(),
                                        r.echoed_incarnation,
                                    ) =>
                                {
                                    MemberRead::Records(recs)
                                }
                                _ => MemberRead::Unavailable,
                            };
                            engine.deliver_read(member_ix, answer);
                        }
                        MemberOp::CompareExchange {
                            member_ix,
                            expected_digest,
                            replacement_bytes,
                        } => {
                            let r = transport
                                .compare_exchange(
                                    member_ix,
                                    keys,
                                    expected_digest,
                                    &replacement_bytes,
                                )
                                .await;
                            let authed = counts_for(
                                &members[member_ix],
                                r.echoed_member_id.as_deref(),
                                r.echoed_incarnation,
                            );
                            let answer = match (authed, r.outcome) {
                                (true, Some(CasOutcome::Applied)) => MemberCas::Applied,
                                (true, Some(CasOutcome::ExpectationMismatch)) => {
                                    MemberCas::ExpectationMismatch
                                }
                                (true, Some(CasOutcome::InvalidStorageEncoding)) => {
                                    MemberCas::InvalidStorageEncoding
                                }
                                // An unauthenticated or failed write ack is never
                                // counted — not as an application and not as a
                                // refusal.
                                _ => MemberCas::Unavailable,
                            };
                            engine.deliver_cas(member_ix, answer);
                        }
                    }
                }
            }
            Step::Recovering(_) => {
                attempt += 1;
                if attempt > max_ballots {
                    return Err(RunError::Unresolved {
                        mutated: engine.mutated(),
                    });
                }
                let d = backoff.delay(attempt);
                if !d.is_zero() {
                    tokio::time::sleep(d).await;
                }
                engine.recover();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::dlv::quorum_bind::{strict_majority, BindingTransaction};
    use dsm::storage::binding_record::{record_digest_of_bytes, record_set_digest, Round, SetCell};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    fn members(n: u8) -> Vec<CommittedMember> {
        (0..n)
            .map(|i| CommittedMember {
                member_id: vec![i],
                register_incarnation: [i; 32],
            })
            .collect()
    }

    /// An in-memory transport over a faithful per-member CAS, optionally
    /// echoing a WRONG incarnation for one member to exercise attribution.
    struct MockTransport {
        cells: Mutex<Vec<BTreeMap<[u8; 32], (Vec<u8>, Round)>>>,
        members: Vec<CommittedMember>,
        wrong_incarnation_for: Vec<usize>,
    }

    impl MockTransport {
        fn new(n: usize) -> Self {
            MockTransport {
                cells: Mutex::new(vec![BTreeMap::new(); n]),
                members: members(n as u8),
                wrong_incarnation_for: Vec::new(),
            }
        }
        fn echo(&self, ix: usize) -> (Option<Vec<u8>>, Option<[u8; 32]>) {
            let inc = if self.wrong_incarnation_for.contains(&ix) {
                [0xFF; 32]
            } else {
                self.members[ix].register_incarnation
            };
            (Some(self.members[ix].member_id.clone()), Some(inc))
        }
    }

    #[async_trait]
    impl BindingTransport for MockTransport {
        async fn read_binding(&self, ix: usize, keys: &[[u8; 32]]) -> TransportRead {
            let cells = self.cells.lock().unwrap();
            let recs = keys
                .iter()
                .map(|k| {
                    cells[ix]
                        .get(k)
                        .map(|(b, _)| BindingRecord::decode_canonical(b).unwrap())
                })
                .collect();
            let (id, inc) = self.echo(ix);
            TransportRead {
                echoed_member_id: id,
                echoed_incarnation: inc,
                records: Some(recs),
            }
        }
        async fn compare_exchange(
            &self,
            ix: usize,
            keys: &[[u8; 32]],
            expected: [u8; 32],
            repl: &[u8],
        ) -> TransportCas {
            let repl_rec = BindingRecord::decode_canonical(repl).unwrap();
            let mut cells = self.cells.lock().unwrap();
            let held: Vec<Option<(Vec<u8>, Round)>> =
                keys.iter().map(|k| cells[ix].get(k).cloned()).collect();
            let (id, inc) = self.echo(ix);
            let outcome = if held
                .iter()
                .all(|h| h.as_ref().is_some_and(|(b, _)| b == repl))
            {
                CasOutcome::Applied
            } else {
                let cur = record_set_digest(
                    &keys
                        .iter()
                        .zip(held.iter())
                        .map(|(k, h)| SetCell {
                            key: *k,
                            record_digest: h.as_ref().map(|(b, _)| record_digest_of_bytes(b)),
                        })
                        .collect::<Vec<_>>(),
                );
                let round_not_superseding =
                    held.iter().flatten().any(|(_, r)| repl_rec.round <= *r);
                if cur != expected || round_not_superseding {
                    CasOutcome::ExpectationMismatch
                } else {
                    for k in keys {
                        cells[ix].insert(*k, (repl.to_vec(), repl_rec.round));
                    }
                    CasOutcome::Applied
                }
            };
            TransportCas {
                echoed_member_id: id,
                echoed_incarnation: inc,
                outcome: Some(outcome),
            }
        }
    }

    fn tx(n: usize) -> BindingTransaction {
        BindingTransaction {
            proposer_id: [7; 32],
            members: members(n as u8),
            quorum: strict_majority(n),
            keys: vec![key(1)],
            tx_id: [9; 32],
            value_addr: [10; 32],
            value_digest: [10; 32],
            base_ballot: 1,
        }
    }

    #[tokio::test]
    async fn the_runner_drives_a_clean_transaction_to_committed() {
        let t = MockTransport::new(3);
        let mut engine = QuorumBind::begin(tx(3)).unwrap();
        let out = run(
            &mut engine,
            &members(3),
            &[key(1)],
            &t,
            Backoff::default(),
            10,
        )
        .await;
        assert_eq!(out, Ok(Outcome::Committed));
    }

    #[tokio::test]
    async fn an_answer_echoing_the_wrong_incarnation_is_not_counted() {
        // Members 1 and 2 echo the wrong register incarnation, so only member 0
        // is countable — below quorum. The runner reports the transaction
        // unresolved rather than counting the mis-attributed acknowledgements.
        let mut t = MockTransport::new(3);
        t.wrong_incarnation_for = vec![1, 2];
        let mut engine = QuorumBind::begin(tx(3)).unwrap();
        let out = run(
            &mut engine,
            &members(3),
            &[key(1)],
            &t,
            Backoff::default(),
            4,
        )
        .await;
        assert_eq!(out, Err(RunError::Unresolved { mutated: false }));
    }
}
