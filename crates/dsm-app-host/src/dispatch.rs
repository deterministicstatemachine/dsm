// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SDK's ingress, called from worker threads.
//!
//! `dsm_sdk::ingress::dispatch_ingress` blocks on the SDK's own runtime, so
//! it never runs on the host's async threads. Each call is taken by one of a
//! few worker threads, which also read this account's state before and after
//! it and record the call when it is one the application should see. Calls
//! wait for a worker in a queue of bounded length: one more is refused at
//! once, so callers that outrun the workers cannot grow it without end.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use dsm_sdk::generated as pb;
use prost::Message;

use crate::activity::{Record, Snapshot};

/// One call through the ingress.
pub struct Call {
    pub request: pb::IngressRequest,
    /// The name to record it under, when it is recorded.
    pub label: Option<Label>,
}

/// How a recorded call is named in the record.
#[derive(Clone)]
pub struct Label {
    pub kind: pb::AppHostActivityKind,
    pub name: String,
}

impl Call {
    fn router(method: &str, args: Vec<u8>, invoke: Invoke) -> Self {
        let operation = match invoke {
            Invoke::Yes => pb::ingress_request::Operation::RouterInvoke(pb::RouterInvokeOp {
                method: method.to_string(),
                args,
            }),
            Invoke::No => pb::ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: method.to_string(),
                args,
            }),
        };
        Self {
            request: pb::IngressRequest {
                operation: Some(operation),
            },
            label: None,
        }
    }

    pub fn invoke(method: &str, args: Vec<u8>) -> Self {
        Self::router(method, args, Invoke::Yes)
    }

    pub fn query(method: &str, args: Vec<u8>) -> Self {
        Self::router(method, args, Invoke::No)
    }
}

enum Invoke {
    Yes,
    No,
}

/// What one call returned.
pub struct Done {
    pub response: pb::IngressResponse,
}

pub(crate) struct Job {
    call: Call,
    reply: tokio::sync::oneshot::Sender<Done>,
}

/// The worker pool in front of the SDK.
#[derive(Clone)]
pub struct Sdk {
    jobs: mpsc::SyncSender<Job>,
    record: Arc<Mutex<Option<Arc<Record>>>>,
}

impl Sdk {
    /// The pool's front, whose calls wait in a queue that holds at most
    /// `queued` of them, and the queue's receiving end, where workers take
    /// them.
    pub(crate) fn with_queue(queued: usize) -> (Self, mpsc::Receiver<Job>) {
        let (jobs, queue) = mpsc::sync_channel::<Job>(queued);
        let record: Arc<Mutex<Option<Arc<Record>>>> = Arc::new(Mutex::new(None));
        (Self { jobs, record }, queue)
    }

    /// `workers` threads taking calls from a queue that holds at most
    /// `queued` calls waiting for one.
    pub fn start(workers: usize, queued: usize) -> Result<Self, String> {
        let (sdk, queue) = Self::with_queue(queued);
        let queue = Arc::new(Mutex::new(queue));
        for i in 0..workers {
            let queue = queue.clone();
            let record = sdk.record.clone();
            std::thread::Builder::new()
                .name(format!("dsm-sdk-{i}"))
                .spawn(move || work(&queue, &record))
                .map_err(|e| format!("starting SDK worker {i}: {e}"))?;
        }
        Ok(sdk)
    }

    /// Record recorded calls into `record` from now on.
    pub fn record_into(&self, record: Arc<Record>) -> Result<(), String> {
        let mut slot = self
            .record
            .lock()
            .map_err(|e| format!("the record slot: {e}"))?;
        *slot = Some(record);
        Ok(())
    }

    /// Run `call` on a worker, or refuse it at once when the queue is full.
    pub async fn call(&self, call: Call) -> Result<Done, String> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        match self.jobs.try_send(Job { call, reply }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(job)) => {
                return Err(format!(
                    "the SDK workers are busy ({} bytes not queued); try again",
                    job.call.request.encoded_len()
                ))
            }
            Err(mpsc::TrySendError::Disconnected(job)) => {
                return Err(format!(
                    "the SDK workers are gone ({} bytes not run)",
                    job.call.request.encoded_len()
                ))
            }
        }
        answer
            .await
            .map_err(|e| format!("an SDK worker dropped the call: {e}"))
    }
}

fn work(queue: &Mutex<mpsc::Receiver<Job>>, record: &Mutex<Option<Arc<Record>>>) {
    loop {
        let job = match queue.lock() {
            Ok(guard) => match guard.recv() {
                Ok(job) => job,
                Err(closed) => {
                    log::info!("[host] an SDK worker stops: {closed}");
                    return;
                }
            },
            Err(poisoned) => {
                log::error!("[host] an SDK worker stops: the queue is poisoned: {poisoned}");
                return;
            }
        };
        let before = Snapshot::take();
        let label = job.call.label.clone();
        let response = dsm_sdk::ingress::dispatch_ingress(job.call.request.clone());
        if let Some(label) = label {
            let after = Snapshot::take();
            match record.lock() {
                Ok(slot) => {
                    if let Some(record) = slot.as_ref() {
                        record.add(&label, &job.call.request, &response, &before, &after);
                    }
                }
                Err(poisoned) => log::error!("[host] the record slot is poisoned: {poisoned}"),
            }
        }
        // A caller that left (its connection dropped) is owed nothing more:
        // what the call did is in the record above.
        if let Err(undelivered) = job.reply.send(Done { response }) {
            log::info!(
                "[host] a caller left before its answer ({} bytes)",
                undelivered.response.encoded_len()
            );
        }
    }
}

/// What a successful ingress answer carries.
pub fn ok_bytes(response: pb::IngressResponse) -> Result<Vec<u8>, String> {
    match response.result {
        Some(pb::ingress_response::Result::OkBytes(bytes)) => Ok(bytes),
        Some(pb::ingress_response::Result::Error(e)) => Err(e.message),
        None => Err("the ingress answered nothing".into()),
    }
}

/// The envelope a successful router answer carries (`0x03`-framed).
pub fn envelope(response: pb::IngressResponse) -> Result<pb::Envelope, String> {
    let bytes = ok_bytes(response)?;
    let body = bytes
        .strip_prefix(&[0x03])
        .ok_or_else(|| "a router answer is framed 0x03".to_string())?;
    let envelope = pb::Envelope::decode(body).map_err(|e| format!("the router's envelope: {e}"))?;
    match envelope.payload {
        Some(pb::envelope::Payload::Error(e)) => Err(e.message),
        _ => Ok(envelope),
    }
}

/// The `ConnectReplyV1` a successful connect route answers with.
pub fn connect_reply(response: pb::IngressResponse) -> Result<pb::connect_reply_v1::Reply, String> {
    match envelope(response)?.payload {
        Some(pb::envelope::Payload::ConnectReply(pb::ConnectReplyV1 { reply: Some(reply) })) => {
            Ok(reply)
        }
        other => Err(format!("the route answered {other:?}, not a connect reply")),
    }
}

/// `body` as a PROTO `ArgPack`, the shape every route's arguments take.
pub fn arg_pack(body: Vec<u8>) -> Vec<u8> {
    pb::ArgPack {
        codec: pb::Codec::Proto as i32,
        body,
        ..Default::default()
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no worker taking calls, the queue takes as many as it holds and
    /// refuses the next one at once, instead of holding it too.
    #[test]
    fn a_full_queue_refuses_the_next_call_at_once() -> Result<(), String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                // The queue's receiving end is held and never read: no worker
                // takes a call.
                let (sdk, _untaken) = Sdk::with_queue(3);
                let queued: Vec<_> = (0..3)
                    .map(|_| {
                        let sdk = sdk.clone();
                        tokio::spawn(async move {
                            sdk.call(Call::query("balance.list", Vec::new())).await
                        })
                    })
                    .collect();
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let refused = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    sdk.call(Call::query("balance.list", Vec::new())),
                )
                .await
                .map_err(|e| format!("a call over the queue's bound was held: {e}"))?;
                match refused {
                    Ok(..) => return Err("a call over the queue's bound was run".into()),
                    Err(why) => assert!(why.contains("busy"), "{why}"),
                }
                for call in queued {
                    assert!(!call.is_finished(), "a queued call is waiting for a worker");
                    call.abort();
                }
                Ok(())
            })
    }
}
