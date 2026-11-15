// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the host establishes on its own once a wallet has answered.
//!
//! A wallet's answer is a notification. The fact is what this account
//! establishes itself, by the SDK's own `connect.app.status` route: the
//! transfer taken up, the stake read, the signature checked. Until now that
//! route ran only when the application called it, so an application waiting
//! on a request had to keep calling. Here the host calls it for the answered
//! request, again until the route settles it, and records what it came to.
//! The record's new entry wakes the application's held read
//! (`GET /activity/{after}/wait`).
//!
//! The host still decides nothing: every rule is the route's, and the
//! application reads the fact from that same route.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dsm_sdk::generated as pb;
use prost::Message;

use crate::activity::{Record, Snapshot};
use crate::dispatch::{arg_pack, connect_reply, Call, Label, Sdk};

/// One request of one connection.
type Request = ([u8; 32], u64);

/// How often the host asks the route about an answered request, and how many
/// times: transport bounds, never validity rules. Together they are the four
/// minutes the clients' own `wait` gives a request.
#[derive(Clone, Copy)]
pub struct Pace {
    pub pause: Duration,
    pub rounds: usize,
}

impl Pace {
    pub const DEPLOYED: Self = Self {
        pause: Duration::from_millis(500),
        rounds: 480,
    };
}

/// Whether the route has said all it will about a request.
enum Settled {
    Yes,
    NotYet,
}

pub struct Establishing {
    sdk: Sdk,
    record: Arc<Record>,
    pace: Pace,
    /// The requests the host is asking about now: a wallet that posts its
    /// answer again starts no second run.
    under_way: Mutex<HashSet<Request>>,
}

impl Establishing {
    pub fn new(sdk: Sdk, record: Arc<Record>, pace: Pace) -> Arc<Self> {
        Arc::new(Self {
            sdk,
            record,
            pace,
            under_way: Mutex::new(HashSet::new()),
        })
    }

    /// A wallet's answer the account accepted: when it says the wallet
    /// carried the request out, start establishing what DSM holds for it.
    /// A declined or failed answer has no fact to come, and one held for the
    /// player is answered again once the player decides.
    pub fn after_answer(self: &Arc<Self>, answer: &pb::AppResponseBodyV1) {
        if pb::ConnectOutcome::try_from(answer.outcome) != Ok(pb::ConnectOutcome::CarriedOut) {
            return;
        }
        let session = match <[u8; 32]>::try_from(answer.session_id.as_slice()) {
            Ok(session) => session,
            Err(e) => {
                log::error!("[host] an accepted answer names no connection: {e}");
                return;
            }
        };
        let request = (session, answer.seq);
        match self.under_way.lock() {
            Ok(mut under_way) => {
                if !under_way.insert(request) {
                    return;
                }
            }
            Err(poisoned) => {
                log::error!("[host] the requests being established: {poisoned}");
                return;
            }
        }
        let establishing = self.clone();
        tokio::spawn(async move {
            establishing.establish(request).await;
            match establishing.under_way.lock() {
                Ok(mut under_way) => {
                    under_way.remove(&request);
                }
                Err(poisoned) => log::error!("[host] the requests being established: {poisoned}"),
            }
        });
    }

    /// Ask the route about `request` until it settles or the rounds run out,
    /// and record the answer it ends on.
    async fn establish(&self, (session, seq): Request) {
        const ROUTE: &str = "connect.app.status";
        let args = arg_pack(
            pb::ConnectRequestRefV1 {
                session_id: session.to_vec(),
                seq,
            }
            .encode_to_vec(),
        );
        let label = Label {
            kind: pb::AppHostActivityKind::Route,
            name: ROUTE.to_string(),
        };
        // Why the last round's call never reached the route, when it did not.
        let mut unasked = None;
        for round in 1..=self.pace.rounds {
            let before = Snapshot::take();
            let call = Call::invoke(ROUTE, args.clone());
            let asked = call.request.clone();
            match self.sdk.call(call).await {
                Ok(done) => {
                    unasked = None;
                    if let Settled::NotYet = settled(&done.response) {
                        if round < self.pace.rounds {
                            tokio::time::sleep(self.pace.pause).await;
                            continue;
                        }
                    }
                    self.record
                        .add(&label, &asked, &done.response, &before, &Snapshot::take());
                    return;
                }
                // The workers are busy: the next round asks again, and the
                // record says so if no round is left.
                Err(busy) => unasked = Some(busy),
            }
            tokio::time::sleep(self.pace.pause).await;
        }
        if let Some(why) = unasked {
            self.record.relay(
                ROUTE,
                format!("check what DSM established for request #{seq}"),
                Err(why),
            );
        }
    }
}

/// Whether `response` is the route's last word on a request: a fact, a
/// price (information, never a fact), an answer with no fact to come, or a
/// refusal.
fn settled(response: &pb::IngressResponse) -> Settled {
    match connect_reply(response.clone()) {
        Ok(pb::connect_reply_v1::Reply::Status(status)) => {
            let fact = pb::ConnectFact::try_from(status.fact);
            let outcome = pb::ConnectOutcome::try_from(status.outcome);
            match (fact, outcome, status.quote) {
                (
                    Ok(pb::ConnectFact::None),
                    Ok(pb::ConnectOutcome::CarriedOut | pb::ConnectOutcome::AwaitingApproval),
                    None,
                ) => Settled::NotYet,
                _ => Settled::Yes,
            }
        }
        _ => Settled::Yes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    /// A `connect.app.status` answer naming `fact`.
    fn status(fact: pb::ConnectFact) -> pb::IngressResponse {
        let envelope = pb::Envelope {
            version: 3,
            payload: Some(pb::envelope::Payload::ConnectReply(pb::ConnectReplyV1 {
                reply: Some(pb::connect_reply_v1::Reply::Status(
                    pb::ConnectAppStatusV1 {
                        outcome: pb::ConnectOutcome::CarriedOut as i32,
                        fact: fact as i32,
                        fact_detail: "as the route read it".into(),
                        ..Default::default()
                    },
                )),
            })),
            ..Default::default()
        };
        let mut bytes = vec![0x03];
        bytes.extend(envelope.encode_to_vec());
        pb::IngressResponse {
            result: Some(pb::ingress_response::Result::OkBytes(bytes)),
        }
    }

    /// Stand in a worker's place for one call: check it is the status route
    /// for request `seq`, and answer it with `response`.
    fn answer(
        queue: &Receiver<crate::dispatch::Job>,
        seq: u64,
        response: pb::IngressResponse,
    ) -> Result<(), String> {
        let job = queue
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("the host never asked the route: {e}"))?;
        match &job.call.request.operation {
            Some(pb::ingress_request::Operation::RouterInvoke(op)) => {
                assert_eq!(op.method, "connect.app.status");
                let pack = pb::ArgPack::decode(op.args.as_slice()).map_err(|e| e.to_string())?;
                let asked = pb::ConnectRequestRefV1::decode(pack.body.as_slice())
                    .map_err(|e| e.to_string())?;
                assert_eq!((asked.session_id, asked.seq), (vec![7; 32], seq));
            }
            other => return Err(format!("the host asked {other:?}")),
        }
        job.reply
            .send(crate::dispatch::Done { response })
            .map_err(|_unsent| "the host left before its answer".to_string())
    }

    fn carried_out(seq: u64) -> pb::AppResponseBodyV1 {
        pb::AppResponseBodyV1 {
            session_id: vec![7; 32],
            seq,
            outcome: pb::ConnectOutcome::CarriedOut as i32,
            ..Default::default()
        }
    }

    /// Once a wallet's answer says carried out, the host asks the status
    /// route itself, again while it establishes nothing, and records the one
    /// answer that names a fact: the entry a held read of the record wakes
    /// on. The same answer posted again while that runs starts no second run,
    /// and a declined answer starts none.
    #[test]
    fn the_host_asks_until_there_is_a_fact_and_records_it_once() -> Result<(), String> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                crate::activity::test_store()?;
                let (sdk, queue) = Sdk::with_queue(4);
                let record = Arc::new(Record::new(crate::identity::Account {
                    device_id: [0x11; 32],
                }));
                let pace = Pace {
                    pause: Duration::from_millis(20),
                    rounds: 50,
                };
                let establishing = Establishing::new(sdk, record.clone(), pace);

                let declined = pb::AppResponseBodyV1 {
                    outcome: pb::ConnectOutcome::Declined as i32,
                    ..carried_out(3)
                };
                establishing.after_answer(&declined);
                establishing.after_answer(&carried_out(4));
                establishing.after_answer(&carried_out(4));

                let held = {
                    let record = record.clone();
                    tokio::spawn(async move { record.newer_than(0, Duration::from_secs(10)).await })
                };
                let worker = tokio::task::spawn_blocking(move || {
                    answer(&queue, 4, status(pb::ConnectFact::None))?;
                    answer(&queue, 4, status(pb::ConnectFact::None))?;
                    answer(&queue, 4, status(pb::ConnectFact::Paid))?;
                    // Nothing more is asked: not for the declined answer, not
                    // by a second run, not after the fact.
                    match queue.recv_timeout(Duration::from_millis(300)) {
                        Ok(..) => Err("the host asked again".to_string()),
                        Err(quiet) => {
                            assert_eq!(quiet, std::sync::mpsc::RecvTimeoutError::Timeout);
                            Ok(())
                        }
                    }
                });
                tokio::time::timeout(Duration::from_secs(10), held)
                    .await
                    .map_err(|e| format!("the held read never woke: {e}"))?
                    .map_err(|e| format!("the held read: {e}"))??;
                worker.await.map_err(|e| format!("the worker: {e}"))??;

                let feed = record.since(0)?;
                let entries: Vec<_> = feed
                    .entries
                    .iter()
                    .map(|e| (e.name.as_str(), e.result.as_str()))
                    .collect();
                assert_eq!(
                    entries,
                    [("connect.app.status", "RECEIVED: as the route read it")]
                );
                Ok(())
            })
    }

    /// A request the route never settles is asked about for the rounds the
    /// pace gives and no more, and the last answer is recorded.
    #[test]
    fn a_request_never_settled_is_given_up_after_its_rounds() -> Result<(), String> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                crate::activity::test_store()?;
                let (sdk, queue) = Sdk::with_queue(4);
                let record = Arc::new(Record::new(crate::identity::Account {
                    device_id: [0x11; 32],
                }));
                let pace = Pace {
                    pause: Duration::from_millis(10),
                    rounds: 3,
                };
                let establishing = Establishing::new(sdk, record.clone(), pace);
                establishing.after_answer(&carried_out(9));
                tokio::task::spawn_blocking(move || {
                    for _round in 0..3 {
                        answer(&queue, 9, status(pb::ConnectFact::None))?;
                    }
                    match queue.recv_timeout(Duration::from_millis(300)) {
                        Ok(..) => Err("the host asked past its rounds".to_string()),
                        Err(quiet) => {
                            assert_eq!(quiet, std::sync::mpsc::RecvTimeoutError::Timeout);
                            Ok(())
                        }
                    }
                })
                .await
                .map_err(|e| format!("the worker: {e}"))??;
                let feed = record.since(0)?;
                let results: Vec<_> = feed.entries.iter().map(|e| e.result.as_str()).collect();
                assert_eq!(results, ["nothing established: as the route read it"]);
                Ok(())
            })
    }
}
