// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`RemoteSpiDevice`]: an `embedded_hal::spi::SpiDevice` whose transactions are tunnelled to a
//! remote TROPIC01 over the DSM bilateral relay, so the receiver can run libtropic-rs against the
//! sender's chip as if it were local.
//!
//! # Why this is faithful to libtropic-rs
//!
//! libtropic-rs's L1 (`lt_1.rs`) drives the chip with exactly two shapes of SPI transaction:
//! - a single [`Operation::TransferInPlace`] — one full-duplex transfer of the L2 buffer (MOSI out,
//!   MISO written back in place). This is the ONLY data operation.
//! - a single [`Operation::DelayNs`] — a data-less retry backoff (~25 ms) between `GET_RESPONSE`
//!   polls, with CS toggled empty.
//!
//! So each data transaction maps to exactly ONE relay round-trip ([`SpiRelayChannel::transceive`]),
//! and the delay is a local wait on the receiver (the chip state persists across transactions, so a
//! local sleep is equivalent to the empty CS pulse). Pico A executes each relayed transaction
//! atomically (assert CS, clock the bytes, deassert CS) and returns the MISO bytes verbatim. The
//! other `Operation` variants are handled for completeness/generality even though libtropic does not
//! currently emit them.

use embedded_hal::spi::{Error as SpiError, ErrorKind, ErrorType, Operation, SpiDevice};

/// A pluggable byte tunnel that carries ONE full-duplex SPI transaction to the remote TROPIC01
/// (through Phone B -> Phone A -> Pico A) and returns the chip's response bytes.
///
/// The implementor MUST preserve the SPI transaction boundary: the remote asserts CS, clocks out
/// exactly `mosi`, captures the simultaneous MISO, deasserts CS, and returns a MISO buffer of the
/// SAME length as `mosi`. It must return the chip's exact bytes — no inspection, no mutation.
pub trait SpiRelayChannel {
    /// Execute one full-duplex SPI transaction: clock out `mosi`, return the captured MISO bytes
    /// (same length as `mosi`). Blocking. Errors map to a fail-closed verifier result upstream.
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError>;

    /// Optional inter-poll backoff, in nanoseconds, requested by libtropic's L1 (`Operation::DelayNs`).
    /// CS is empty during this wait, so the default is a no-op (the next `transceive` re-polls the
    /// chip); a real relay MAY sleep to avoid hammering the transport. Never relayed as a transfer.
    fn delay_ns(&mut self, _ns: u32) {}
}

/// A failure in the raw-SPI relay tunnel. Any error here fails the counter read CLOSED (the
/// offline-bearer transfer recovers online) — never treated as a passing counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The underlying transport (BLE relay / phone-to-phone / Pico link) failed to carry the
    /// transaction. Carries a human-readable reason.
    Transport(String),
    /// The remote returned a MISO buffer whose length does not match the clocked-out `mosi`
    /// length — a transaction-boundary violation. Fail-closed.
    LengthMismatch { expected: usize, got: usize },
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RelayError::Transport(why) => write!(f, "SPI relay transport error: {why}"),
            RelayError::LengthMismatch { expected, got } => write!(
                f,
                "SPI relay response length mismatch: expected {expected} bytes, got {got}"
            ),
        }
    }
}

impl std::error::Error for RelayError {}

// `embedded_hal::spi::Error` lets libtropic-rs surface our relay failures through its own error type.
impl SpiError for RelayError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

/// An `embedded_hal::spi::SpiDevice` backed by a [`SpiRelayChannel`]. `Tropic01::new(RemoteSpiDevice)`
/// then runs the full libtropic-rs stack against the remote chip.
pub struct RemoteSpiDevice<C: SpiRelayChannel> {
    channel: C,
}

impl<C: SpiRelayChannel> RemoteSpiDevice<C> {
    /// Wrap a relay channel as a remote SPI device.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    /// Borrow the underlying channel (e.g. to inspect relay stats or close the tunnel).
    pub fn channel_mut(&mut self) -> &mut C {
        &mut self.channel
    }

    /// Consume the device and return the channel.
    pub fn into_channel(self) -> C {
        self.channel
    }
}

impl<C: SpiRelayChannel> ErrorType for RemoteSpiDevice<C> {
    type Error = RelayError;
}

impl<C: SpiRelayChannel> SpiDevice<u8> for RemoteSpiDevice<C> {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), RelayError> {
        // A SpiDevice transaction runs with CS asserted for the whole slice. libtropic issues
        // single-op transactions (one TransferInPlace, or one DelayNs); we execute each op in
        // order and relay every data op as one atomic remote transaction.
        for op in operations.iter_mut() {
            match op {
                // The libtropic hot path: full-duplex transfer, MISO written back in place.
                Operation::TransferInPlace(buf) => {
                    let miso = self.channel.transceive(buf)?;
                    if miso.len() != buf.len() {
                        return Err(RelayError::LengthMismatch {
                            expected: buf.len(),
                            got: miso.len(),
                        });
                    }
                    buf.copy_from_slice(&miso);
                }
                // Retry backoff between GET_RESPONSE polls — CS empty, no data on the wire.
                Operation::DelayNs(ns) => {
                    self.channel.delay_ns(*ns);
                }
                // Half-duplex write: clock out `buf`, discard MISO.
                Operation::Write(buf) => {
                    let _ = self.channel.transceive(buf)?;
                }
                // Half-duplex read: clock out zeros, capture MISO.
                Operation::Read(buf) => {
                    let zeros = vec![0u8; buf.len()];
                    let miso = self.channel.transceive(&zeros)?;
                    if miso.len() != buf.len() {
                        return Err(RelayError::LengthMismatch {
                            expected: buf.len(),
                            got: miso.len(),
                        });
                    }
                    buf.copy_from_slice(&miso);
                }
                // Full-duplex transfer into a separate read buffer.
                Operation::Transfer(read, write) => {
                    let miso = self.channel.transceive(write)?;
                    let n = read.len().min(miso.len());
                    read[..n].copy_from_slice(&miso[..n]);
                    // Zero-fill any tail the write side didn't cover (mirrors a real bus).
                    for b in read[n..].iter_mut() {
                        *b = 0;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A software stand-in for Pico A + TROPIC01 A: it records each relayed transaction and returns
    /// a deterministic transform of the MOSI bytes (bitwise-NOT) as the MISO response, preserving
    /// length. Enough to prove `RemoteSpiDevice` faithfully relays and scatters bytes.
    struct EchoNotChannel {
        txns: Vec<Vec<u8>>,
        delays_ns: Vec<u32>,
    }
    impl EchoNotChannel {
        fn new() -> Self {
            Self {
                txns: Vec::new(),
                delays_ns: Vec::new(),
            }
        }
    }
    impl SpiRelayChannel for EchoNotChannel {
        fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
            self.txns.push(mosi.to_vec());
            Ok(mosi.iter().map(|b| !b).collect())
        }
        fn delay_ns(&mut self, ns: u32) {
            self.delays_ns.push(ns);
        }
    }

    #[test]
    fn transfer_in_place_relays_one_txn_and_writes_miso_back() {
        let mut dev = RemoteSpiDevice::new(EchoNotChannel::new());
        let mut buf = [0xAAu8, 0x00, 0xFF, 0x55];
        dev.transaction(&mut [Operation::TransferInPlace(&mut buf)])
            .expect("relay ok");
        // MISO = !MOSI, written back in place.
        assert_eq!(buf, [0x55, 0xFF, 0x00, 0xAA]);
        // Exactly one relay round-trip carrying the original MOSI bytes.
        assert_eq!(dev.channel_mut().txns, vec![vec![0xAA, 0x00, 0xFF, 0x55]]);
    }

    #[test]
    fn delay_ns_is_local_no_transfer() {
        let mut dev = RemoteSpiDevice::new(EchoNotChannel::new());
        dev.transaction(&mut [Operation::DelayNs(25_000_000)])
            .expect("delay ok");
        assert!(
            dev.channel_mut().txns.is_empty(),
            "delay must not relay a transfer"
        );
        assert_eq!(dev.channel_mut().delays_ns, vec![25_000_000]);
    }

    #[test]
    fn read_clocks_zeros_and_captures_miso() {
        let mut dev = RemoteSpiDevice::new(EchoNotChannel::new());
        let mut buf = [0u8; 3];
        dev.transaction(&mut [Operation::Read(&mut buf)])
            .expect("read ok");
        // MOSI was zeros -> MISO = !0 = 0xFF.
        assert_eq!(buf, [0xFF, 0xFF, 0xFF]);
        assert_eq!(dev.channel_mut().txns, vec![vec![0u8; 3]]);
    }

    #[test]
    fn write_relays_mosi_and_discards_miso() {
        let mut dev = RemoteSpiDevice::new(EchoNotChannel::new());
        dev.transaction(&mut [Operation::Write(&[1, 2, 3])])
            .expect("write ok");
        assert_eq!(dev.channel_mut().txns, vec![vec![1, 2, 3]]);
    }

    /// A channel that violates the transaction boundary (returns a short MISO) must fail CLOSED.
    struct ShortChannel;
    impl SpiRelayChannel for ShortChannel {
        fn transceive(&mut self, _mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
            Ok(vec![0u8]) // wrong length
        }
    }

    #[test]
    fn length_mismatch_fails_closed() {
        let mut dev = RemoteSpiDevice::new(ShortChannel);
        let mut buf = [0u8; 4];
        let err = dev
            .transaction(&mut [Operation::TransferInPlace(&mut buf)])
            .unwrap_err();
        assert_eq!(
            err,
            RelayError::LengthMismatch {
                expected: 4,
                got: 1
            }
        );
    }

    /// A transport failure must propagate as an error (fail-closed upstream), never a silent pass.
    struct DeadChannel;
    impl SpiRelayChannel for DeadChannel {
        fn transceive(&mut self, _mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
            Err(RelayError::Transport("link down".into()))
        }
    }

    #[test]
    fn transport_error_propagates() {
        let mut dev = RemoteSpiDevice::new(DeadChannel);
        let mut buf = [0u8; 2];
        let err = dev
            .transaction(&mut [Operation::TransferInPlace(&mut buf)])
            .unwrap_err();
        assert_eq!(err, RelayError::Transport("link down".into()));
    }
}
