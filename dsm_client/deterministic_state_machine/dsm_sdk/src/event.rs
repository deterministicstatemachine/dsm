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
