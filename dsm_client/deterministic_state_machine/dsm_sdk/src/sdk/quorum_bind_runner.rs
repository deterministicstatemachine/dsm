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

/// Turn one transport answer into a countable [`MemberRead`]. An answer that
/// does not name BOTH the committed member id and the committed register
/// incarnation is `Unavailable` — never an empty read, which would be evidence.
fn attribute_read(member: &CommittedMember, r: TransportRead) -> MemberRead {
    match r.records {
        Some(recs) if counts_for(member, r.echoed_member_id.as_deref(), r.echoed_incarnation) => {
            MemberRead::Records(recs)
        }
        _ => MemberRead::Unavailable,
    }
}

/// Read `keys` at EVERY committed member and attribute each answer.
///
/// This is the observer's half of the runner: the same fan-out and the same
/// attribution rule the proposer uses, with no engine and no writes. Sharing
/// [`attribute_read`] is the point — an observer with its own attribution rule
/// could count an answer the proposer would refuse.
///
/// Every member is asked, not just `q` of them: a transaction that committed
/// with exactly `q` holders needs the full fan-out to find them.
pub(crate) async fn read_binding_attributed<T: BindingTransport + ?Sized>(
    members: &[CommittedMember],
    keys: &[[u8; 32]],
    transport: &T,
) -> Vec<Option<MemberRead>> {
    let mut out = Vec::with_capacity(members.len());
    for (ix, member) in members.iter().enumerate() {
        let r = transport.read_binding(ix, keys).await;
        out.push(Some(attribute_read(member, r)));
    }
    out
}

/// The binding transport for a committed storage set. Live speaks HTTP; tests
/// drive the deterministic in-process fleet.
///
/// One factory, so the driver, the restart resume and the observer all reach
/// the same fleet. They previously each built their own, which left restart
/// resume pinned to HTTP and therefore untestable under the double.
pub(crate) fn binding_transport(
    set: &crate::sdk::storage_set::StorageSet,
) -> Box<dyn BindingTransport + Send + Sync> {
    let eps: Vec<crate::sdk::binding_http_transport::MemberEndpoint> = set
        .members()
        .iter()
        .map(|m| crate::sdk::binding_http_transport::MemberEndpoint {
            endpoint: m.endpoint.clone(),
            #[cfg(not(any(test, feature = "test-utils")))]
            auth: crate::sdk::storage_io::resolve_storage_auth(&m.endpoint),
            #[cfg(any(test, feature = "test-utils"))]
            auth: None,
        })
        .collect();
    #[cfg(any(test, feature = "test-utils"))]
    {
        // Attribute this set's members so a path that never touches the fleet
        // directly still reaches quorum. Additive: held records and injected
        // member failures are preserved.
        let tuples: Vec<(String, Vec<u8>, [u8; 32])> = set
            .members()
            .iter()
            .map(|m| {
                (
                    m.endpoint.clone(),
                    m.member_id.as_bytes().to_vec(),
                    m.register_incarnation_id,
                )
            })
            .collect();
        crate::sdk::binding_fleet_double::ensure_registered(&tuples);
        Box::new(crate::sdk::binding_fleet_double::FakeBindingTransport::new(
            eps,
        ))
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        Box::new(crate::sdk::binding_http_transport::HttpBindingTransport::new(eps))
    }
}

/// Why the runner stopped without a terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The recovery-ballot budget was exhausted before a terminal outcome. The
    /// transaction is INDETERMINATE if it mutated; the caller keeps the
    /// trader-parent fence and may resume recovery later.
    Unresolved { mutated: bool },
    /// The trader-parent fence could not be durably persisted, so the
    /// transaction never began (Req 6.23 (1)). Nothing mutated.
    FenceNotPersisted,
}

/// The identity of the initiating-trader parent fence for a transaction
/// (Req 6.23): the trader's own chain and parent state, plus which DLV
/// transaction fenced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceKey {
    pub trader_chain_id: [u8; 32],
    pub trader_parent_state_commitment: [u8; 32],
    pub tx_id: [u8; 32],
}

/// Drive a transaction UNDER its trader-parent fence (Req 6.23).
///
/// 1. The fence is placed durably BEFORE the first mutating op — if it cannot
///    be persisted the transaction does not begin ((1)).
/// 2. The transaction is driven to a terminal outcome (or a lost one).
/// 3. The outcome is recorded against the fence: `COMMITTED` fixes the exact
///    permitted `trader_successor` ((4)); `ABORTED`/`CONFLICT_FINAL` release
///    without advancing ((3)); an unresolved run keeps the parent fenced as
///    INDETERMINATE (Req 16.4) with the ballot persisted so restart never
///    reuses one.
///
/// This records the DLV outcome only. Releasing a committed fence requires the
/// exact successor to be accepted through ordinary DSM bilateral advancement
/// ((4)); the caller does that with
/// [`crate::storage::client_db::trader_parent_fence::record_event`] and a
/// [`dsm::dlv::trader_fence::FenceEvent::SuccessorAccepted`] afterwards.
#[allow(clippy::too_many_arguments)]
pub async fn run_fenced<T: BindingTransport + ?Sized>(
    engine: &mut QuorumBind,
    members: &[CommittedMember],
    keys: &[[u8; 32]],
    transport: &T,
    backoff: Backoff,
    max_ballots: u32,
    fence: FenceKey,
    trader_successor: [u8; 32],
    storage_set_id: [u8; 32],
    value_addr: [u8; 32],
) -> Result<Outcome, RunError> {
    use crate::storage::client_db::trader_parent_fence as fdb;
    use dsm::dlv::trader_fence::{FenceEvent, FenceState};

    // (1) Place the fence before any mutating op. If it can't persist, refuse
    // to begin.
    let placed = fdb::TraderFence {
        trader_chain_id: fence.trader_chain_id,
        trader_parent_state_commitment: fence.trader_parent_state_commitment,
        tx_id: fence.tx_id,
        ballot: engine.ballot(),
        storage_set_id,
        value_addr,
        state: FenceState::Fenced,
        insertion_ordinal: 0,
    };
    if fdb::place_fence(&placed).is_err() {
        return Err(RunError::FenceNotPersisted);
    }

    // (2) Drive.
    let result = run(engine, members, keys, transport, backoff, max_ballots).await;

    // (3) Record the outcome against the fence, persisting the final ballot.
    let event = match &result {
        Ok(Outcome::Committed) => FenceEvent::Committed {
            successor: trader_successor,
        },
        // Neither ABORTED nor a storage-INVALID proposal chose a value; both
        // release the parent without advancing.
        Ok(Outcome::Aborted) | Ok(Outcome::Invalid) => FenceEvent::Aborted,
        Ok(Outcome::ConflictFinal { .. }) => FenceEvent::ConflictFinal,
        Err(_) => FenceEvent::Indeterminate,
    };
    let _ = fdb::record_event(
        &fence.trader_chain_id,
        &fence.trader_parent_state_commitment,
        &fence.tx_id,
        &event,
        Some(engine.ballot()),
    );
    result
}

/// The result of trying to resume one fence on restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceRecovery {
    pub trader_chain_id: [u8; 32],
    pub trader_parent_state_commitment: [u8; 32],
    pub tx_id: [u8; 32],
    /// Whether this pass drove the fence to a terminal outcome. A fence whose
    /// bundle could not be retrieved yet stays unresolved (`false`) and the
    /// parent stays fenced for a later pass.
    pub resolved: bool,
}

/// Restore every unresolved trader-parent fence to a terminal outcome before
/// the recovered trader chain may advance (Req 16.5, §22 #14).
///
/// On restart this is the canonical entry point: it loads every locally frozen
/// transaction whose fence is not terminal and hands each to `resume_one`,
/// which reconstructs the transaction from the fence's stored storage set and
/// immutable bundle address (catalog resolution + `GetImmutable` + `run_fenced`,
/// supplied by the settle path in PR 5) and returns whether it reached a
/// terminal outcome. A fence whose bundle is not yet retrievable is left fenced
/// and surfaced as unresolved, so the parent cannot advance until a later pass
/// resolves it. One worker per fence, in insertion order.
pub async fn recover_unresolved_fences<F, Fut>(resume_one: F) -> anyhow::Result<Vec<FenceRecovery>>
where
    F: Fn(crate::storage::client_db::trader_parent_fence::TraderFence) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    use crate::storage::client_db::trader_parent_fence as fdb;
    let fences = fdb::list_unresolved_fences()?;
    let mut out = Vec::with_capacity(fences.len());
    for fence in fences {
        let key = (
            fence.trader_chain_id,
            fence.trader_parent_state_commitment,
            fence.tx_id,
        );
        let resolved = resume_one(fence).await;
        out.push(FenceRecovery {
            trader_chain_id: key.0,
            trader_parent_state_commitment: key.1,
            tx_id: key.2,
            resolved,
        });
    }
    Ok(out)
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
                            let answer = attribute_read(&members[member_ix], r);
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
    use dsm::dlv::quorum_bind::{strict_majority, BindingTransaction, BINDING_STATUS_ACCEPTED};
    use dsm::dlv::trader_fence::{FenceEvent, FenceVerdict};
    use crate::storage::client_db::trader_parent_fence as fdb;
    use serial_test::serial;
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
        /// When set, an ACCEPT still lands in the cells but its response is
        /// lost, and every later op goes dark — modelling a COMMIT response
        /// lost after the value was already chosen.
        hide_accepts: Mutex<bool>,
        dark: Mutex<bool>,
    }

    impl MockTransport {
        fn new(n: usize) -> Self {
            MockTransport {
                cells: Mutex::new(vec![BTreeMap::new(); n]),
                members: members(n as u8),
                wrong_incarnation_for: Vec::new(),
                hide_accepts: Mutex::new(false),
                dark: Mutex::new(false),
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
            let (id, inc) = self.echo(ix);
            if *self.dark.lock().unwrap() {
                return TransportRead {
                    echoed_member_id: id,
                    echoed_incarnation: inc,
                    records: None,
                };
            }
            let cells = self.cells.lock().unwrap();
            let recs = keys
                .iter()
                .map(|k| {
                    cells[ix]
                        .get(k)
                        .map(|(b, _)| BindingRecord::decode_canonical(b).unwrap())
                })
                .collect();
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
            let (id, inc) = self.echo(ix);
            let mut cells = self.cells.lock().unwrap();
            let held: Vec<Option<(Vec<u8>, Round)>> =
                keys.iter().map(|k| cells[ix].get(k).cloned()).collect();
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
            // A landed ACCEPT whose response is hidden: the value is chosen on
            // the member, but the client never hears it, and everything goes
            // dark from here.
            if repl_rec.status == BINDING_STATUS_ACCEPTED
                && outcome == CasOutcome::Applied
                && *self.hide_accepts.lock().unwrap()
            {
                *self.dark.lock().unwrap() = true;
                return TransportCas {
                    echoed_member_id: id,
                    echoed_incarnation: inc,
                    outcome: None,
                };
            }
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

    fn fence_key() -> FenceKey {
        FenceKey {
            trader_chain_id: [0x11; 32],
            trader_parent_state_commitment: [0x22; 32],
            tx_id: [9; 32],
        }
    }

    fn init_db() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    #[tokio::test]
    #[serial]
    async fn run_fenced_commits_and_the_fence_permits_only_that_successor() {
        init_db();
        let t = MockTransport::new(3);
        let mut engine = QuorumBind::begin(tx(3)).unwrap();
        let succ = [0xAA; 32];
        let out = run_fenced(
            &mut engine,
            &members(3),
            &[key(1)],
            &t,
            Backoff::default(),
            10,
            fence_key(),
            succ,
            [0x6B; 32],
            [10; 32],
        )
        .await;
        assert_eq!(out, Ok(Outcome::Committed));
        // The committed fence permits ONLY the exact successor, until it is
        // accepted through ordinary DSM bilateral advancement.
        assert_eq!(
            fdb::active_verdict(&[0x11; 32], &[0x22; 32]).unwrap(),
            FenceVerdict::PermitsOnly(succ)
        );
        fdb::record_event(
            &[0x11; 32],
            &[0x22; 32],
            &[9; 32],
            &FenceEvent::SuccessorAccepted { successor: succ },
            None,
        )
        .unwrap();
        assert_eq!(
            fdb::active_verdict(&[0x11; 32], &[0x22; 32]).unwrap(),
            FenceVerdict::Clear
        );
    }

    #[tokio::test]
    #[serial]
    async fn bind_indeterminate_a_lost_commit_stays_fenced_and_recovery_discovers_the_value() {
        init_db();
        // Run 1: the accepts land on a quorum, but their responses are lost and
        // the transport goes dark. The runner cannot confirm, so it reports the
        // transaction unresolved and the fence stays FENCED (Req 16.4).
        let t = MockTransport::new(3);
        *t.hide_accepts.lock().unwrap() = true;
        let mut engine = QuorumBind::begin(tx(3)).unwrap();
        let succ = [0xAA; 32];
        let out = run_fenced(
            &mut engine,
            &members(3),
            &[key(1)],
            &t,
            Backoff::default(),
            3,
            fence_key(),
            succ,
            [0x6B; 32],
            [10; 32],
        )
        .await;
        assert_eq!(out, Err(RunError::Unresolved { mutated: true }));
        assert_eq!(
            fdb::active_verdict(&[0x11; 32], &[0x22; 32]).unwrap(),
            FenceVerdict::BlocksAllSuccessors,
            "a lost commit keeps the parent fenced; a fresh intent cannot pass"
        );
        // The value IS chosen on the members even though the client never heard.
        let unresolved = fdb::list_unresolved_fences().unwrap();
        assert_eq!(unresolved.len(), 1);

        // Restart recovery: a fresh Class K instance for the SAME transaction,
        // resuming above the persisted ballot, discovers the chosen value and
        // reaches COMMITTED — completion, not a second value.
        *t.dark.lock().unwrap() = false;
        *t.hide_accepts.lock().unwrap() = false;
        let mut resumed = QuorumBind::begin(BindingTransaction {
            base_ballot: unresolved[0].ballot,
            ..tx(3)
        })
        .unwrap();
        let out2 = run_fenced(
            &mut resumed,
            &members(3),
            &[key(1)],
            &t,
            Backoff::default(),
            10,
            fence_key(),
            succ,
            [0x6B; 32],
            [10; 32],
        )
        .await;
        assert_eq!(out2, Ok(Outcome::Committed));
        assert_eq!(
            fdb::active_verdict(&[0x11; 32], &[0x22; 32]).unwrap(),
            FenceVerdict::PermitsOnly(succ)
        );
    }

    #[tokio::test]
    #[serial]
    async fn restart_recovery_resumes_each_fence_and_leaves_the_unretrievable_ones_fenced() {
        init_db();
        // Two unresolved fences on DIFFERENT parents (both can be unresolved at
        // once). One bundle is retrievable on restart; the other is not.
        let f1 = fdb::TraderFence {
            trader_chain_id: [0x11; 32],
            trader_parent_state_commitment: [0xA1; 32],
            tx_id: [1; 32],
            ballot: 1,
            storage_set_id: [0x6B; 32],
            value_addr: [0x01; 32],
            state: dsm::dlv::trader_fence::FenceState::Fenced,
            insertion_ordinal: 0,
        };
        let mut f2 = f1.clone();
        f2.trader_parent_state_commitment = [0xA2; 32];
        f2.tx_id = [2; 32];
        f2.value_addr = [0x02; 32];
        fdb::place_fence(&f1).unwrap();
        fdb::place_fence(&f2).unwrap();

        // resume_one: the first fence's bundle is retrievable, so it resolves to
        // a terminal outcome; the second's is not, so it is left fenced.
        let recoveries = recover_unresolved_fences(|f| async move {
            if f.tx_id == [1; 32] {
                fdb::record_event(
                    &f.trader_chain_id,
                    &f.trader_parent_state_commitment,
                    &f.tx_id,
                    &FenceEvent::Aborted,
                    None,
                )
                .unwrap();
                true
            } else {
                false
            }
        })
        .await
        .unwrap();

        assert_eq!(recoveries.len(), 2);
        assert!(recoveries.iter().any(|r| r.tx_id == [1; 32] && r.resolved));
        assert!(recoveries.iter().any(|r| r.tx_id == [2; 32] && !r.resolved));
        // After the pass, only the un-retrievable fence remains — its parent
        // stays fenced until a later pass.
        let remaining = fdb::list_unresolved_fences().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].tx_id, [2; 32]);
        assert_eq!(
            fdb::active_verdict(&[0x11; 32], &[0xA2; 32]).unwrap(),
            FenceVerdict::BlocksAllSuccessors
        );
    }
}
