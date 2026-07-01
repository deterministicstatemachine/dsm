// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLE frame routing for the Path-B raw-SPI counter relay (D2).
//!
//! This is the `tropic01`-free half of the relay that lives in the CI-built SDK. It routes
//! `TropicSpiRelayPacket` frames on both ends of one relayed SPI transaction:
//! - **Sender A** forwards the raw bytes to its local Pico (via [`LocalPicoTransport`]) and replies;
//! - **Receiver B** resolves the pending round-trip so its (out-of-crate) libtropic session gets the
//!   MISO.
//!
//! The actual libtropic session driver (`read_counter_over_relay`, which depends on `tropic01`)
//! lives in the excluded `dsm-anchor-hw-verifier` crate; the on-device layer wires this router's
//! [`TropicRelayRouter::round_trip`] into that reader as its async transport round-trip.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dsm::types::error::DsmError;
use dsm_anchor_verifier::RelayError;
use prost::Message as _;
use tokio::sync::oneshot;

use crate::generated::TropicSpiRelayPacket;

/// A boxed async result, mirroring the transport-delegate style (object-safe async). `'static`:
/// implementations clone/Arc what they need rather than borrowing `self` across the future.
pub type PicoFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// The SENDER's link to its OWN local Pico (Phone A -> Pico A), used to service a relayed
/// `TropicSpiRelayPacket`: forward one raw SPI transaction to the Pico's `OP_SPI_PASSTHROUGH` and
/// return the MISO bytes. The real implementation bridges to the Android phone-to-Pico transport
/// (USB-CDC / BLE); tests use an in-process stand-in. Present only on a device that holds an anchor.
pub trait LocalPicoTransport: Send + Sync {
    fn spi_passthrough(&self, spi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>>;
}

/// Routes `TropicSpiRelayPacket` frames for the Path-B counter read, on BOTH ends of one relayed
/// SPI transaction:
///
/// - **Sender A** (`from_receiver == true`): forward `spi_payload` to the local Pico
///   ([`LocalPicoTransport`]) and hand back a reply packet (`from_receiver = false`) to send to B.
/// - **Receiver B** (`from_receiver == false`): resolve the pending round-trip awaiting this
///   transaction's response, so the (out-of-crate) libtropic session gets its MISO.
///
/// Correlation is by `commitment_hash` (the in-flight transfer); libtropic issues transactions
/// strictly one at a time, so at most one round-trip is outstanding per transfer.
pub struct TropicRelayRouter {
    /// Sender side: the link to the local Pico. `None` on a device with no anchor (it never
    /// services a relay request).
    local_pico: Mutex<Option<Arc<dyn LocalPicoTransport>>>,
    /// Receiver side: round-trips awaiting a response, keyed by `commitment_hash`.
    pending: Mutex<HashMap<[u8; 32], oneshot::Sender<Result<Vec<u8>, RelayError>>>>,
}

impl Default for TropicRelayRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl TropicRelayRouter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            local_pico: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Install the sender-side local Pico link (called on a device that holds an anchor).
    pub fn set_local_pico(&self, pico: Arc<dyn LocalPicoTransport>) {
        if let Ok(mut g) = self.local_pico.lock() {
            *g = Some(pico);
        }
    }

    /// Handle an inbound `TropicSpiRelayPacket`. Returns:
    /// - `Ok(Some(bytes))` — a reply packet to send back to the peer (sender A serviced a request),
    /// - `Ok(None)` — nothing to send (receiver B resolved a pending round-trip),
    /// - `Err(_)` — malformed frame or no local Pico to service a request (fail-closed upstream).
    pub async fn handle_inbound(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, DsmError> {
        let pkt = TropicSpiRelayPacket::decode(payload).map_err(|e| {
            DsmError::invalid_operation(format!("decode TropicSpiRelayPacket: {e}"))
        })?;
        let commitment: [u8; 32] =
            pkt.commitment_hash.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("relay commitment_hash must be 32 bytes")
            })?;

        if pkt.from_receiver {
            // Sender A: forward the raw SPI transaction to the local Pico and reply.
            let pico = self
                .local_pico
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .ok_or_else(|| {
                    DsmError::invalid_operation("no local Pico transport to relay to")
                })?;
            let miso = pico.spi_passthrough(pkt.spi_payload).await?;
            let reply = TropicSpiRelayPacket {
                spi_payload: miso,
                from_receiver: false,
                commitment_hash: commitment.to_vec(),
            };
            Ok(Some(reply.encode_to_vec()))
        } else {
            // Receiver B: hand the MISO to the waiting round-trip (if any).
            if let Ok(mut pend) = self.pending.lock() {
                if let Some(tx) = pend.remove(&commitment) {
                    let _ = tx.send(Ok(pkt.spi_payload));
                }
            }
            Ok(None)
        }
    }

    /// Receiver-side: perform ONE relay round-trip — register a pending response, send the request
    /// packet via `send`, and await the reply (bounded timeout). `send(frame_bytes)` performs the
    /// proactive BLE send to Phone A (`queue_follow_up_chunks` in production; an in-process loop in
    /// tests). Any failure is a fail-closed [`RelayError`].
    pub async fn round_trip<F, Fut>(
        &self,
        commitment: [u8; 32],
        mosi: Vec<u8>,
        send: F,
    ) -> Result<Vec<u8>, RelayError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<(), DsmError>>,
    {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut pend) = self.pending.lock() {
            pend.insert(commitment, tx);
        }
        let req = TropicSpiRelayPacket {
            spi_payload: mosi,
            from_receiver: true,
            commitment_hash: commitment.to_vec(),
        };
        if let Err(e) = send(req.encode_to_vec()).await {
            if let Ok(mut pend) = self.pending.lock() {
                pend.remove(&commitment);
            }
            return Err(RelayError::Transport(format!("relay send failed: {e}")));
        }
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(r)) => r,
            _ => {
                if let Ok(mut pend) = self.pending.lock() {
                    pend.remove(&commitment);
                }
                Err(RelayError::Transport("relay response timeout".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-process stand-in for Pico A: returns the bitwise-NOT of the MOSI bytes as MISO.
    struct EchoPico;
    impl LocalPicoTransport for EchoPico {
        fn spi_passthrough(&self, spi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>> {
            Box::pin(async move { Ok(spi.iter().map(|b| !b).collect()) })
        }
    }

    #[tokio::test]
    async fn sender_forwards_relay_request_to_local_pico() {
        let a = TropicRelayRouter::new();
        a.set_local_pico(Arc::new(EchoPico));
        let req = TropicSpiRelayPacket {
            spi_payload: vec![0xAA, 0xBB],
            from_receiver: true, // a request from B to read A's chip
            commitment_hash: vec![7u8; 32],
        };
        let reply_bytes = a
            .handle_inbound(&req.encode_to_vec())
            .await
            .expect("ok")
            .expect("A returns a reply frame");
        let reply = TropicSpiRelayPacket::decode(&reply_bytes[..]).expect("decode reply");
        assert!(!reply.from_receiver, "reply is chip->receiver");
        assert_eq!(reply.spi_payload, vec![!0xAAu8, !0xBBu8]);
        assert_eq!(reply.commitment_hash, vec![7u8; 32]);
    }

    #[tokio::test]
    async fn sender_with_no_pico_fails_closed() {
        let a = TropicRelayRouter::new(); // no local Pico installed
        let req = TropicSpiRelayPacket {
            spi_payload: vec![1],
            from_receiver: true,
            commitment_hash: vec![0u8; 32],
        };
        assert!(a.handle_inbound(&req.encode_to_vec()).await.is_err());
    }

    /// Full loop: B's round-trip sends a request that A services against its local Pico, and A's
    /// reply routes back to resolve B's pending round-trip — proving the BLE frame routing end to
    /// end (with an in-process transport standing in for phone-to-phone BLE).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_relay_loop_receiver_reads_through_sender() {
        let a = Arc::new(TropicRelayRouter::new());
        a.set_local_pico(Arc::new(EchoPico));
        let b = Arc::new(TropicRelayRouter::new());
        let commitment = [0x42u8; 32];

        let a2 = a.clone();
        let b2 = b.clone();
        let miso = b
            .round_trip(commitment, vec![1, 2, 3, 4], move |frame| async move {
                // A services the relayed request and produces a reply frame...
                let reply = a2.handle_inbound(&frame).await?.expect("A returns a reply");
                // ...which is delivered back to B, resolving the pending round-trip.
                b2.handle_inbound(&reply).await?;
                Ok(())
            })
            .await
            .expect("round trip completes");
        assert_eq!(miso, vec![!1u8, !2, !3, !4]);
    }

    /// A relay send failure removes the pending entry and fails closed (no leak, no hang).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trip_send_failure_fails_closed() {
        let b = TropicRelayRouter::new();
        let r = b
            .round_trip([9u8; 32], vec![1], |_frame| async {
                Err(DsmError::invalid_operation("ble down"))
            })
            .await;
        assert!(matches!(r, Err(RelayError::Transport(_))), "got {r:?}");
    }
}
