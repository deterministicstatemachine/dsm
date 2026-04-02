//! # SDK Event Bus
//!
//! Global protobuf-encoded broadcast channel for asynchronous event delivery.
//! SDK components push pre-encoded protobuf bytes into the stream; UI or
//! bridge subscribers receive them without coupling to any specific generated
//! message type. The channel capacity is 256 messages; lagging receivers
//! silently drop older events.

use once_cell::sync::Lazy;
use tokio::sync::broadcast::{self, Sender, Receiver};

static EVENTS: Lazy<Sender<Vec<u8>>> = Lazy::new(|| broadcast::channel(256).0);

/// Push a pre-encoded event notification (protobuf bytes) into the stream.
/// This avoids coupling to any specific generated message type.
pub fn push_event_bytes(bytes: Vec<u8>) {
    let _ = EVENTS.send(bytes); // ignore lagging receivers
}

/// Subscribe to the event stream
pub fn subscribe() -> Receiver<Vec<u8>> {
    EVENTS.subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: subscribe, push a unique tagged payload, then drain until we
    /// find it. This avoids interference from the global broadcast channel
    /// when tests run in parallel.
    async fn push_and_drain(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut rx = subscribe();
        let mut payload = vec![tag];
        payload.extend_from_slice(body);
        push_event_bytes(payload.clone());
        loop {
            let msg = rx.recv().await.unwrap();
            if msg.first() == Some(&tag) {
                return msg;
            }
        }
    }

    #[tokio::test]
    async fn push_and_receive_single_event() {
        let received = push_and_drain(0xA1, &[1, 2, 3, 4]).await;
        assert_eq!(received, vec![0xA1, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_event() {
        let mut rx1 = subscribe();
        let mut rx2 = subscribe();
        let payload = vec![0xA2, 10, 20];
        push_event_bytes(payload.clone());

        let find = |rx: &mut Receiver<Vec<u8>>| loop {
            match rx.try_recv() {
                Ok(msg) if msg.first() == Some(&0xA2) => return msg,
                Ok(_) => continue,
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(e) => panic!("unexpected recv error: {e:?}"),
            }
        };
        assert_eq!(find(&mut rx1), payload);
        assert_eq!(find(&mut rx2), payload);
    }

    #[tokio::test]
    async fn events_arrive_in_order() {
        let mut rx = subscribe();
        push_event_bytes(vec![0xA3, 1]);
        push_event_bytes(vec![0xA3, 2]);
        push_event_bytes(vec![0xA3, 3]);

        let mut collected = Vec::new();
        loop {
            let msg = rx.recv().await.unwrap();
            if msg.first() == Some(&0xA3) {
                collected.push(msg);
                if collected.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(collected[0], vec![0xA3, 1]);
        assert_eq!(collected[1], vec![0xA3, 2]);
        assert_eq!(collected[2], vec![0xA3, 3]);
    }

    #[test]
    fn push_without_subscriber_does_not_panic() {
        push_event_bytes(vec![0xFF; 100]);
    }

    #[tokio::test]
    async fn empty_tagged_payload_roundtrips() {
        let received = push_and_drain(0xA4, &[]).await;
        assert_eq!(received, vec![0xA4]);
    }
}
