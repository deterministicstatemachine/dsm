// SPDX-License-Identifier: MIT OR Apache-2.0
//! The device-layer composition of the Path-B counter read: [`RelayCounterReader`] fills the DSM
//! SDK's [`AnchorCounterReader`] seam by joining the pinned enrollment
//! ([`FusedAnchorPin`]) to the real libtropic verifier session
//! ([`read_counter_over_relay`]) over a caller-supplied relay transport, and
//! [`SeedPairingDeriver`] fills the [`VerifierPairingDeriver`] seam with the SAME per-counterparty
//! pairing key derivation — so the pubkey B offers in the first-transfer enroll request is, by
//! construction, the key its future counter reads authenticate with.
//!
//! Key handling follows the DSM idiom: nothing is persisted. B's X25519 verifier pairing keypair
//! is re-derived at use time from B's identity seed + the counterparty device id
//! (`BLAKE3("DSM/anchor/verifier-pairing/v1" ‖ seed ‖ peer)`), and the handshake ephemeral is
//! fresh CSPRNG per session.
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

/// The raw 32-byte seed for B's per-counterparty verifier pairing key, before the X25519 clamp.
/// Single source of truth for the derivation (the reader, the deriver, and hardware provisioning
/// tooling all go through here). `#[doc(hidden)]`: device-layer/bring-up use only.
#[doc(hidden)]
pub fn derive_pairing_secret_bytes(seed: &[u8; 32], peer_device_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(peer_device_id);
    dsm::crypto::blake3::domain_hash_bytes("DSM/anchor/verifier-pairing/v1", &buf)
}

/// Derive B's per-counterparty X25519 verifier pairing SECRET from B's identity seed. Deterministic
/// (re-derivable after restore, nothing persisted) and per-peer (a compromise of one pairing key
/// never crosses relationships). `StaticSecret::from` applies the X25519 clamp.
fn derive_pairing_secret(seed: &[u8; 32], peer_device_id: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(derive_pairing_secret_bytes(seed, peer_device_id))
}

/// The pairing PUBLIC key for `derive_pairing_secret` — what B offers in the enroll request and
/// what A provisions into the read-only verifier slot.
pub fn derive_pairing_pubkey(seed: &[u8; 32], peer_device_id: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&derive_pairing_secret(seed, peer_device_id)).to_bytes()
}

/// Fills `dsm_sdk`'s [`AnchorCounterReader`] seam: B's real Path-B counter read over the relay.
/// Install on-device via `dsm_sdk::bridge::install_anchor_counter_reader`.
pub struct RelayCounterReader {
    seed: [u8; 32],
    transport: RelayRoundTrip,
}

impl RelayCounterReader {
    /// `seed` is B's identity seed root for pairing-key derivation; `transport` performs one relay
    /// round-trip to the sender's Pico (B -> A -> Pico A -> A -> B).
    pub fn new(seed: [u8; 32], transport: RelayRoundTrip) -> Self {
        Self { seed, transport }
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

        let sh_priv = derive_pairing_secret(&self.seed, &peer_device_id);
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

/// Fills `dsm_sdk`'s [`VerifierPairingDeriver`] seam with the SAME derivation the reader uses, so
/// the enroll-request pubkey and the read-time keypair can never diverge. Install on-device via
/// `dsm_sdk::bridge::install_verifier_pairing_deriver`.
pub struct SeedPairingDeriver {
    seed: [u8; 32],
}

impl SeedPairingDeriver {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl VerifierPairingDeriver for SeedPairingDeriver {
    fn verifier_pairing_pubkey(&self, peer_device_id: [u8; 32]) -> Option<[u8; 32]> {
        Some(derive_pairing_pubkey(&self.seed, &peer_device_id))
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
        let reader = RelayCounterReader::new([0x42; 32], transport);
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
        let reader = RelayCounterReader::new([0x42; 32], transport);
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
    fn enroll_request_pubkey_and_read_time_keypair_are_the_same_derivation() {
        let seed = [0x42; 32];
        let peer = [0x11; 32];
        let deriver = SeedPairingDeriver::new(seed);
        let offered = deriver.verifier_pairing_pubkey(peer).expect("pubkey");
        // The reader derives its session keypair from the same seed+peer: the pubkeys must match.
        let session_pub = PublicKey::from(&derive_pairing_secret(&seed, &peer)).to_bytes();
        assert_eq!(offered, session_pub);
        assert_eq!(offered, derive_pairing_pubkey(&seed, &peer));
    }

    #[test]
    fn pairing_keys_are_per_peer_and_per_seed() {
        let a = derive_pairing_pubkey(&[0x42; 32], &[0x11; 32]);
        let b = derive_pairing_pubkey(&[0x42; 32], &[0x12; 32]);
        let c = derive_pairing_pubkey(&[0x43; 32], &[0x11; 32]);
        assert_ne!(a, b, "different peers must get different pairing keys");
        assert_ne!(a, c, "different seeds must get different pairing keys");
    }
}
