//! # SDK Event Bus
//!
//! Typed protobuf event queue shared by Android JNI, iOS FFI, and tests.
//! Producers enqueue encoded [`crate::generated::SdkEvent`] messages; platform
//! adapters drain them through the shared ingress using `DrainEventsOp`.

use std::collections::VecDeque;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use prost::Message;
use tokio::sync::broadcast::{self, Receiver, Sender};

use crate::generated as pb;

const EVENT_QUEUE_CAPACITY: usize = 256;
const DEFAULT_DRAIN_MAX_EVENTS: usize = 64;

static EVENT_QUEUE: Lazy<Mutex<VecDeque<Vec<u8>>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(EVENT_QUEUE_CAPACITY)));
static EVENT_BROADCAST: Lazy<Sender<Vec<u8>>> =
    Lazy::new(|| broadcast::channel(EVENT_QUEUE_CAPACITY).0);

fn normalize_max_events(max_events: usize) -> usize {
    if max_events == 0 {
        DEFAULT_DRAIN_MAX_EVENTS
    } else {
        max_events.min(EVENT_QUEUE_CAPACITY)
    }
}

fn encode_event(event: &pb::SdkEvent) -> Vec<u8> {
    event.encode_to_vec()
}

/// Queue an already-encoded `SdkEvent` payload.
pub fn push_event_bytes(bytes: Vec<u8>) {
    {
        let mut queue = EVENT_QUEUE.lock().expect("event queue poisoned");
        if queue.len() >= EVENT_QUEUE_CAPACITY {
            let _ = queue.pop_front();
        }
        queue.push_back(bytes.clone());
    }
    let _ = EVENT_BROADCAST.send(bytes);
}

/// Queue a typed SDK event.
pub fn push_sdk_event(kind: i32, payload: Vec<u8>) {
    let event = pb::SdkEvent { kind, payload };
    push_event_bytes(encode_event(&event));
}

/// Queue a typed SDK event from a protobuf message payload.
pub fn push_sdk_message<M: Message>(kind: i32, payload: &M) {
    push_sdk_event(kind, payload.encode_to_vec());
}

/// Drain up to `max_events` queued SDK events in FIFO order.
pub fn drain_events(max_events: usize) -> pb::SdkEventBatch {
    let take = normalize_max_events(max_events);
    let mut drained = Vec::with_capacity(take);
    let has_more = {
        let mut queue = EVENT_QUEUE.lock().expect("event queue poisoned");
        for _ in 0..take {
            let Some(bytes) = queue.pop_front() else {
                break;
            };
            match pb::SdkEvent::decode(bytes.as_slice()) {
                Ok(event) => drained.push(event),
                Err(e) => {
                    log::warn!("dropping malformed sdk event from queue: {e}");
                }
            }
        }
        !queue.is_empty()
    };

    pb::SdkEventBatch {
        events: drained,
        has_more,
    }
}

/// Subscribe to encoded `SdkEvent` bytes. Primarily used by tests.
pub fn subscribe() -> Receiver<Vec<u8>> {
    EVENT_BROADCAST.subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KIND: i32 = 123;
    static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn drain_all_test_events() {
        loop {
            let batch = drain_events(EVENT_QUEUE_CAPACITY);
            if batch.events.is_empty() && !batch.has_more {
                break;
            }
        }
    }

    #[test]
    fn drain_events_preserves_fifo_order() {
        let _guard = TEST_MUTEX.lock().expect("test mutex poisoned");
        drain_all_test_events();
        push_sdk_event(TEST_KIND, vec![1]);
        push_sdk_event(TEST_KIND, vec![2]);
        push_sdk_event(TEST_KIND, vec![3]);

        let batch = drain_events(8);
        let has_more = batch.has_more;
        let payloads: Vec<Vec<u8>> = batch.events.into_iter().map(|event| event.payload).collect();

        assert_eq!(payloads, vec![vec![1], vec![2], vec![3]]);
        assert!(!has_more);
    }

    #[test]
    fn drain_events_reports_has_more() {
        let _guard = TEST_MUTEX.lock().expect("test mutex poisoned");
        drain_all_test_events();
        for value in 0..3u8 {
            push_sdk_event(TEST_KIND, vec![value]);
        }

        let batch = drain_events(2);
        assert_eq!(batch.events.len(), 2);
        assert!(batch.has_more);

        let second = drain_events(2);
        assert_eq!(second.events.len(), 1);
        assert!(!second.has_more);
    }

    #[test]
    fn subscribers_receive_encoded_sdk_events() {
        let _guard = TEST_MUTEX.lock().expect("test mutex poisoned");
        drain_all_test_events();
        let mut rx = subscribe();

        push_sdk_event(TEST_KIND, vec![0xAA, 0xBB]);
        let bytes = rx.try_recv().expect("missing broadcast event");
        let decoded = pb::SdkEvent::decode(bytes.as_slice()).expect("event should decode");

        assert_eq!(decoded.kind, TEST_KIND);
        assert_eq!(decoded.payload, vec![0xAA, 0xBB]);
    }
}
