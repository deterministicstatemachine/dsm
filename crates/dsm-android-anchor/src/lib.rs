// SPDX-License-Identifier: MIT OR Apache-2.0
//! On-device glue for the DSM Boot Fenced Fused Anchor: installs the libtropic-backed anchor impls
//! (Phase F/G, from `dsm-anchor-hw-verifier`) into the `dsm_sdk` bridge seams, so an offline-bearer
//! receiver can authenticate the sender's TROPIC01 counter over the BLE relay and accept.
//!
//! Dependency direction is ONE-WAY (`dsm-android-anchor` -> `dsm_sdk` + `dsm-anchor-hw-verifier`);
//! `dsm_sdk` never depends back on this crate, so there is no cycle. This crate transitively pulls
//! `tropic01`, so it is EXCLUDED from the workspace and built only in the Android cargo-ndk
//! pipeline. The default CI workspace stays `tropic01`-free.
//!
//! Phasing: H1 (this) establishes the crate + the install entry points and proves it cross-compiles
//! for Android. H2 supplies the concrete transports (the Phone->Pico USB `LocalPicoTransport` and
//! the SE slot-writer that drives it). H3 adds the JNI shell that calls these installers from
//! `initDsmSdk`, wiring `round_trip` to `TropicRelayRouter::round_trip` + the BLE send, and
//! `set_local_pico` on the bilateral adapter's relay router. Until every piece is installed, the
//! SDK stays fail-closed (absent reader / incomplete pin -> online recovery).

// Tests use `.unwrap()`/`.expect()` freely; production code in this crate does not (the workspace
// `.clippy.toml` disallows them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

use std::sync::Arc;

use dsm_anchor_hw_verifier::{DsmVerifierPairingDeriver, RelayCounterReader, RelayRoundTrip};
use dsm_sdk::bridge::{
    install_anchor_counter_reader, install_se_slot_writer, install_verifier_pairing_deriver,
    SeSlotWriter,
};

pub mod install;
pub mod se_slot;
pub mod self_test;
pub mod usb_appliance;
pub mod usb_pico;
pub use usb_pico::{UsbPicoTransport, UsbTransceive};

/// Install the RECEIVER-side anchor impls (nothing persisted; the verifier pairing key is the fixed
/// DSM constant, so no seed is needed):
/// - [`RelayCounterReader`] — B opens its own authenticated libtropic session to the sender's
///   TROPIC01 over the relay and reads the live counter `H`. `round_trip` is the device-layer BLE
///   bridge carrying one raw-SPI transaction B -> A -> Pico A -> A -> B (H3 supplies it, wrapping
///   `TropicRelayRouter::round_trip` + `queue_relay_frame`).
/// - [`DsmVerifierPairingDeriver`] — the fixed DSM verifier pubkey B offers in the first-transfer
///   enroll request; the SAME key the reader authenticates with (one caged slot serves all peers).
///
/// Until this runs, `dsm_sdk`'s counter reader is absent and every offline-bearer transfer recovers
/// online. The reader itself still fail-closes on an incomplete pin (no verifier slot / chip key).
pub fn install_receiver_anchor(round_trip: RelayRoundTrip) {
    install_anchor_counter_reader(Arc::new(RelayCounterReader::new(round_trip)));
    install_verifier_pairing_deriver(Arc::new(DsmVerifierPairingDeriver::new()));
}

/// Install the SENDER-side SE verifier-slot provisioner: on a first-transfer enroll request, A
/// writes the requester's pairing pubkey into a READ-ONLY verifier slot on A's TROPIC01 and returns
/// `(slot, stpub)` for the disclosure. `writer` drives A's local Pico (H2 supplies the concrete
/// impl over the Phone->Pico link).
///
/// NOTE: to also SERVICE a receiver's relay reads, A must install its `LocalPicoTransport` on the
/// bilateral adapter's `TropicRelayRouter` via `set_local_pico` — that is router-instance-scoped
/// (not a global bridge seam), so it is wired at the adapter in H3. Until both are present, the
/// disclosure rides with empty slot/stpub and the receiver's pin stays incomplete -> fail-closed.
pub fn install_sender_slot_writer(writer: Arc<dyn SeSlotWriter>) {
    install_se_slot_writer(writer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    use dsm_anchor_verifier::RelayError;

    /// A round-trip that never actually reaches a chip — enough to construct the reader for the
    /// install-wiring assertion (the deep behavior is proven in dsm_sdk's Phase H0 test).
    fn dead_round_trip() -> RelayRoundTrip {
        Arc::new(
            |_peer: [u8; 32],
             _commitment: [u8; 32],
             _mosi: Vec<u8>|
             -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RelayError>> + Send>> {
                Box::pin(async { Err(RelayError::Transport("no chip in test".into())) })
            },
        )
    }

    struct NoopSlotWriter;
    impl SeSlotWriter for NoopSlotWriter {
        fn provision_verifier_slot(
            &self,
            _requester_device_id: [u8; 32],
            _pairing_pubkey: [u8; 32],
        ) -> Option<(u8, [u8; 32])> {
            None
        }
    }

    /// The installers register the impls into the bridge seams the confirm flow reads.
    #[test]
    fn installs_register_into_the_bridge_seams() {
        assert!(dsm_sdk::bridge::anchor_counter_reader().is_none());
        assert!(dsm_sdk::bridge::verifier_pairing_deriver().is_none());
        assert!(dsm_sdk::bridge::se_slot_writer().is_none());

        install_receiver_anchor(dead_round_trip());
        install_sender_slot_writer(Arc::new(NoopSlotWriter));

        assert!(dsm_sdk::bridge::anchor_counter_reader().is_some());
        assert!(dsm_sdk::bridge::verifier_pairing_deriver().is_some());
        assert!(dsm_sdk::bridge::se_slot_writer().is_some());
    }
}
