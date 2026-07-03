// SPDX-License-Identifier: MIT OR Apache-2.0
//! The device-layer composition of the Path-B counter read: [`RelayCounterReader`] fills the DSM
//! SDK's [`AnchorCounterReader`] seam by joining the pinned enrollment
//! ([`FusedAnchorPin`]) to the real libtropic verifier session
//! ([`read_counter_over_relay`]) over a caller-supplied relay transport, and
//! [`DsmVerifierPairingDeriver`] fills the [`VerifierPairingDeriver`] seam with the fixed DSM
//! verifier pubkey — so the pubkey B offers in the first-transfer enroll request is, by
//! construction, the key its future counter reads authenticate with.
//!
//! Key handling: the verifier pairing keypair is a FIXED, well-known DSM constant
//! (`dsm_verifier_pairing_secret_bytes` — see the SMT-root-counter rationale there), the same on
//! every device, so a SINGLE caged read-only slot serves every counterparty. Nothing is persisted;
//! the handshake ephemeral is fresh CSPRNG per session.
//!
//! Fail-closed: an INCOMPLETE pin (no verifier slot, no pinned chip static key, or a compromised
//! anchor) returns `None` WITHOUT touching the transport — mirroring the SDK-side
//! `pin_ready_for_counter_read` rail, so the invariant holds independently on both sides of the
//! crate boundary. Every transport/session/identity/counter failure also returns `None`; the
//! acceptance predicate then recovers online.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dsm::crypto::anchor_enrollment::FusedAnchorPin;
use dsm_anchor_verifier::RelayError;
use dsm_sdk::bluetooth::tropic_relay::{AnchorCounterReader, PicoFuture};
use dsm_sdk::bridge::VerifierPairingDeriver;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::relay_driver::read_counter_over_relay;
use crate::session::VerifierSessionCredential;

/// One relay round-trip owned by the device layer: `(peer_device_id, commitment, mosi) -> miso`.
/// The on-device implementation forwards through `TropicRelayRouter::round_trip` + the BLE send;
/// tests use an in-process closure.
pub type RelayRoundTrip = Arc<
    dyn Fn(
            [u8; 32],
            [u8; 32],
            Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RelayError>> + Send>>
        + Send
        + Sync,
>;

/// The raw 32-byte secret of the FIXED, well-known DSM verifier pairing keypair, before the X25519
/// clamp. Single source of truth (the reader, the deriver, and hardware provisioning tooling all go
/// through here). `#[doc(hidden)]`: device-layer/bring-up use only.
///
/// Rationale — the SMT-root counter path: the verifier slot exposes the physical monotonic counter
/// that advances along the device's SMT-root state-transition path — the compressed correctness
/// point for ALL relationships — so a SINGLE caged read-only slot serves every counterparty. There
/// is no per-relationship pairing key; the per-receiver binding is the pinned chip identity (stpub)
/// + the SMT proof under the committed root + the DSM transition predicate (`H == H0 − (u_i+1)`),
/// none of which use this session key. The session may only READ the counter (the slot is caged to
/// MCOUNTER_GET), so the secret being well-known grants nothing more. This also sidesteps the hard
/// 3-slot pairing budget (`PAIRING_KEY_SLOT_MAX = 3`) that per-relationship keying would exhaust.
/// Derived by domain separation so it is fixed, documented, and reproducible on every device.
#[doc(hidden)]
pub fn dsm_verifier_pairing_secret_bytes() -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes("DSM/anchor/verifier-pairing/well-known/v1", &[])
}

/// The fixed DSM verifier pairing SECRET (X25519-clamped). Same on every device.
fn dsm_verifier_pairing_secret() -> StaticSecret {
    StaticSecret::from(dsm_verifier_pairing_secret_bytes())
}

/// The public half of the fixed DSM verifier keypair — provisioned once into the caged verifier slot
/// and offered (redundantly, since it is well-known) in the first-transfer enroll request.
pub fn dsm_verifier_pairing_pubkey() -> [u8; 32] {
    PublicKey::from(&dsm_verifier_pairing_secret()).to_bytes()
}

/// Fills `dsm_sdk`'s [`AnchorCounterReader`] seam: B's real Path-B counter read over the relay.
/// Install on-device via `dsm_sdk::bridge::install_anchor_counter_reader`.
pub struct RelayCounterReader {
    transport: RelayRoundTrip,
}

impl RelayCounterReader {
    /// `transport` performs one relay round-trip to the sender's Pico (B -> A -> Pico A -> A -> B).
    /// The verifier pairing key is the fixed DSM keypair (see [`dsm_verifier_pairing_secret_bytes`]),
    /// so no per-relationship seed is needed.
    pub fn new(transport: RelayRoundTrip) -> Self {
        Self { transport }
    }
}

impl AnchorCounterReader for RelayCounterReader {
    fn read_counter(
        &self,
        peer_device_id: [u8; 32],
        commitment: [u8; 32],
        pin: FusedAnchorPin,
    ) -> PicoFuture<Option<u32>> {
        // Fail-closed gate BEFORE any transport traffic: an incomplete or compromised pin is never
        // counter-read (independent twin of the SDK-side `pin_ready_for_counter_read` rail).
        let (slot, stpub) = match (pin.verifier_slot, pin.chip_static_pubkey, pin.uncompromised) {
            (Some(slot), Some(stpub), true) => (slot, stpub),
            _ => {
                log::warn!(
                    "[hw-verifier] counter read refused: pin incomplete or compromised (fail-closed)"
                );
                return Box::pin(async { None });
            }
        };

        let sh_priv = dsm_verifier_pairing_secret();
        let cred = VerifierSessionCredential {
            slot,
            sh_pub: PublicKey::from(&sh_priv).to_bytes(),
            sh_priv: sh_priv.to_bytes(),
            pinned_static_pubkey: stpub,
        };
        let ephemeral: Option<[u8; 32]> = dsm::crypto::rng::random_bytes(32).try_into().ok();
        let transport = self.transport.clone();

        Box::pin(async move {
            let Some(ephemeral) = ephemeral else {
                log::warn!("[hw-verifier] counter read refused: CSPRNG ephemeral unavailable");
                return None;
            };
            match read_counter_over_relay(cred, ephemeral, move |mosi| {
                (transport)(peer_device_id, commitment, mosi)
            })
            .await
            {
                Ok(h) => Some(h),
                Err(e) => {
                    log::warn!("[hw-verifier] Path-B counter read failed (fail-closed): {e}");
                    None
                }
            }
        })
    }
}

/// Fills `dsm_sdk`'s [`VerifierPairingDeriver`] seam with the fixed DSM verifier pubkey the reader
/// authenticates with, so the enroll-request pubkey and the read-time keypair can never diverge.
/// Peer-independent (one caged slot serves all relationships). Install on-device via
/// `dsm_sdk::bridge::install_verifier_pairing_deriver`.
#[derive(Default)]
pub struct DsmVerifierPairingDeriver;

impl DsmVerifierPairingDeriver {
    pub fn new() -> Self {
        Self
    }
}

impl VerifierPairingDeriver for DsmVerifierPairingDeriver {
    fn verifier_pairing_pubkey(&self, _peer_device_id: [u8; 32]) -> Option<[u8; 32]> {
        Some(dsm_verifier_pairing_pubkey())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pin(slot: Option<u8>, stpub: Option<[u8; 32]>, uncompromised: bool) -> FusedAnchorPin {
        FusedAnchorPin {
            bundle: [0xB1; 32],
            anchor_id: [0xA1; 32],
            enrolled_counter: 1_000_000,
            partition_pk: vec![0x07; 64],
            uncompromised,
            verifier_slot: slot,
            chip_static_pubkey: stpub,
        }
    }

    /// A transport that counts invocations and always fails (dead relay).
    fn counting_dead_transport() -> (RelayRoundTrip, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let t: RelayRoundTrip = Arc::new(move |_peer, _commitment, _mosi| {
            c.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(RelayError::Transport("dead relay".into())) })
        });
        (t, calls)
    }

    #[tokio::test]
    async fn incomplete_or_compromised_pin_returns_none_without_touching_the_transport() {
        let (transport, calls) = counting_dead_transport();
        let reader = RelayCounterReader::new(transport);
        for p in [
            pin(None, None, true),                 // pre-HW admit shape
            pin(Some(2), None, true),              // slot without pinned chip identity
            pin(None, Some([0xCC; 32]), true),     // chip identity without slot
            pin(Some(2), Some([0xCC; 32]), false), // compromised anchor
        ] {
            let h = reader.read_counter([0x11; 32], [0x22; 32], p).await;
            assert_eq!(h, None);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "incomplete pins must never generate relay traffic"
        );
    }

    #[tokio::test]
    async fn complete_pin_reaches_the_transport_and_a_dead_relay_fails_closed() {
        let (transport, calls) = counting_dead_transport();
        let reader = RelayCounterReader::new(transport);
        let h = reader
            .read_counter([0x11; 32], [0x22; 32], pin(Some(2), Some([0xCC; 32]), true))
            .await;
        assert_eq!(h, None, "dead relay must fail closed");
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "a complete pin must pass the gate and drive the chip driver into the relay"
        );
    }

    #[test]
    fn enroll_request_pubkey_and_read_time_keypair_are_the_fixed_verifier_key() {
        // The pubkey B offers in the enroll request is the fixed verifier pubkey, and it is the
        // public half of the exact secret the reader opens the session with — they cannot diverge.
        let offered = DsmVerifierPairingDeriver::new()
            .verifier_pairing_pubkey([0x11; 32])
            .expect("pubkey");
        let session_pub = PublicKey::from(&dsm_verifier_pairing_secret()).to_bytes();
        assert_eq!(offered, session_pub);
        assert_eq!(offered, dsm_verifier_pairing_pubkey());
    }

    #[test]
    fn verifier_pairing_key_is_fixed_across_peers() {
        // One caged slot serves all relationships: the offered pubkey is identical regardless of the
        // counterparty (the per-receiver binding is the pin/SMT/predicate, not this key).
        let d = DsmVerifierPairingDeriver::new();
        assert_eq!(
            d.verifier_pairing_pubkey([0x11; 32]),
            d.verifier_pairing_pubkey([0x12; 32]),
            "the verifier pairing key must not depend on the counterparty"
        );
        // And it is stable across calls (a well-known protocol constant).
        assert_eq!(dsm_verifier_pairing_pubkey(), dsm_verifier_pairing_pubkey());
    }
}
