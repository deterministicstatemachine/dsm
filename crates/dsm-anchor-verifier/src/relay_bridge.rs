// SPDX-License-Identifier: MIT OR Apache-2.0
//! The sync↔async relay bridge: adapts a SYNC [`SpiRelayChannel`] (what a libtropic-rs stack
//! drives) to an ASYNC pump that a network transport (BLE) fills one transaction at a time.
//!
//! The receiver runs a SYNC libtropic stack over a `RemoteSpiDevice`, but each SPI transaction must
//! cross the network as a relayed packet (async). This bridge runs the sync stack on a blocking task
//! whose [`RelayChannel`] turns each `transceive` into one [`RelayExchange`] the async [`RelayPump`]
//! services. libtropic issues transactions strictly one at a time, so the bridge carries exactly one
//! outstanding exchange (bounded channel of 1). Every failure — pump gone, response dropped, or a
//! transport error — surfaces as a [`RelayError`], so the counter read fails CLOSED.
//!
//! This is transport-agnostic and tropic01-free; the actual libtropic driver that consumes it lives
//! in the excluded hardware crate.

use tokio::sync::{mpsc, oneshot};

use crate::remote_spi::{RelayError, SpiRelayChannel};

/// One relayed SPI transaction handed from the (blocking) libtropic task to the (async) pump: the
/// MOSI bytes to clock out, plus the reply channel for the chip's MISO bytes.
pub struct RelayExchange {
    /// The raw SPI transaction bytes to send to the sender's chip.
    pub mosi: Vec<u8>,
    respond: oneshot::Sender<Result<Vec<u8>, RelayError>>,
}

impl RelayExchange {
    /// Deliver the chip's MISO response.
    pub fn respond(self, miso: Vec<u8>) {
        let _ = self.respond.send(Ok(miso));
    }

    /// Fail this exchange closed (relay error / no response); the waiting `transceive` returns `Err`.
    pub fn fail(self, why: impl Into<String>) {
        let _ = self.respond.send(Err(RelayError::Transport(why.into())));
    }
}

/// The SYNC side, handed to the blocking libtropic task as its `SpiRelayChannel`. Each `transceive`
/// blocks until the async pump returns the chip's response.
pub struct RelayChannel {
    tx: mpsc::Sender<RelayExchange>,
}

impl SpiRelayChannel for RelayChannel {
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
        let (respond, rx) = oneshot::channel();
        self.tx
            .blocking_send(RelayExchange {
                mosi: mosi.to_vec(),
                respond,
            })
            .map_err(|_| RelayError::Transport("relay pump closed".into()))?;
        rx.blocking_recv()
            .map_err(|_| RelayError::Transport("relay response channel dropped".into()))?
    }
}

/// The ASYNC side, driven by the network transport: pull the next relayed transaction, send it, and
/// complete it when the reply arrives.
pub struct RelayPump {
    rx: mpsc::Receiver<RelayExchange>,
}

impl RelayPump {
    /// The next relayed transaction, or `None` once the libtropic task finished (channel dropped).
    pub async fn next(&mut self) -> Option<RelayExchange> {
        self.rx.recv().await
    }
}

/// Create a bridge: the sync [`RelayChannel`] for the blocking libtropic task and the async
/// [`RelayPump`] the transport drives.
#[must_use]
pub fn relay_bridge() -> (RelayChannel, RelayPump) {
    let (tx, rx) = mpsc::channel(1);
    (RelayChannel { tx }, RelayPump { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sync channel relays each transceive to the async pump and returns its response verbatim,
    /// preserving order (one outstanding at a time).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_relays_transactions_in_order() {
        let (mut channel, mut pump) = relay_bridge();
        let task = tokio::task::spawn_blocking(move || {
            let a = channel.transceive(&[1, 2, 3]);
            let b = channel.transceive(&[4, 5]);
            (a, b)
        });

        let ex = pump.next().await.expect("first exchange");
        assert_eq!(ex.mosi, vec![1, 2, 3]);
        let miso: Vec<u8> = ex.mosi.iter().map(|b| !b).collect();
        ex.respond(miso);

        let ex = pump.next().await.expect("second exchange");
        assert_eq!(ex.mosi, vec![4, 5]);
        let miso = ex.mosi.clone();
        ex.respond(miso);

        assert!(pump.next().await.is_none());
        let (a, b) = task.await.expect("join");
        assert_eq!(a.expect("a"), vec![!1, !2, !3]);
        assert_eq!(b.expect("b"), vec![4, 5]);
    }

    /// A failed relay round-trip surfaces as a transceive error -> fail-closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_relay_failure_fails_closed() {
        let (mut channel, mut pump) = relay_bridge();
        let task = tokio::task::spawn_blocking(move || channel.transceive(&[9, 9]));
        let ex = pump.next().await.expect("exchange");
        ex.fail("BLE link dropped");
        let r = task.await.expect("join");
        assert!(matches!(r, Err(RelayError::Transport(_))), "got {r:?}");
    }

    /// If the pump is dropped before responding, the blocking transceive fails closed, not hang.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_pump_fails_closed() {
        let (mut channel, pump) = relay_bridge();
        drop(pump);
        let r = tokio::task::spawn_blocking(move || channel.transceive(&[1]))
            .await
            .expect("join");
        assert!(matches!(r, Err(RelayError::Transport(_))), "got {r:?}");
    }
}
