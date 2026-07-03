// SPDX-License-Identifier: MIT OR Apache-2.0
//! H3 sender-side SE seam: disclose the DSM SMT-root verifier slot on A's OWN TROPIC01.
//!
//! [`SeVerifierSlotWriter`] fills `dsm_sdk`'s `SeSlotWriter` seam and is **strictly read-only**: on a
//! first-transfer enroll it SCANS the candidate pairing-key indices to LOCATE the one already holding
//! the fixed DSM verifier key + correct cage, and discloses `(that index, stpub)`. It NEVER writes —
//! a transfer or app boot can never touch hardware state. Empty / occupied / wrong-key / any error
//! -> `None` -> disclosure empty -> receiver pin incomplete -> fail-closed.
//!
//! The IRREVERSIBLE provisioning burn is NOT an on-device operation: it is done deliberately at the
//! bench via the `usb_verifier_slot` CLI (see BENCH_BURN_RUNBOOK.md), against a chosen slot index.
//! There is intentionally no on-device burn entry point.
//!
//! The read drives A's local Pico over the same opaque JNI USB up-call the relay uses, wrapped as a
//! sync `SpiRelayChannel` so the proven `provisioner` read runs unchanged on-device.

// Host-testable decision types (hw-verifier is a normal dep, so these resolve on host too).
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_hw_verifier::find_provisioned_slot;
use dsm_anchor_hw_verifier::{dsm_verifier_pairing_pubkey, ProvisionError};
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_verifier::{RelayError, SpiRelayChannel};
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_sdk::bridge::SeSlotWriter;

/// The fail-closed disclosure decision, pulled out of the on-device path so it is host-testable: the
/// receiver's offered key must be the fixed DSM verifier key, and the scan must have LOCATED the role
/// at some candidate index. Anything else -> `None` (disclosure empty -> receiver pin incomplete).
/// The located index (1..=3) is downcast to the wire `u8`.
fn map_disclosure(
    offered_pubkey: [u8; 32],
    found: Result<Option<(u16, [u8; 32])>, ProvisionError>,
) -> Option<(u8, [u8; 32])> {
    if offered_pubkey != dsm_verifier_pairing_pubkey() {
        return None;
    }
    match found {
        Ok(Some((slot, stpub))) => u8::try_from(slot).ok().map(|s| (s, stpub)),
        _ => None,
    }
}

/// A sync `SpiRelayChannel` to A's LOCAL Pico over the JNI USB up-call: each `transceive` frames one
/// raw SPI transaction as `OP_SPI_PASSTHROUGH` (in Rust) and returns the MISO. Zero-size — a fresh
/// one is minted per probed slot (the scanner's factory).
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub struct JniLocalSpiChannel;

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
impl SpiRelayChannel for JniLocalSpiChannel {
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
        let frame = crate::usb_pico::frame_passthrough(mosi.to_vec());
        let body = crate::usb_pico::jni_usb_transceive(frame)
            .map_err(|e| RelayError::Transport(format!("local pico up-call: {e}")))?;
        crate::usb_pico::decode_passthrough(&body)
            .map_err(|e| RelayError::Transport(format!("local pico decode: {e}")))
    }
}

/// Read-only `SeSlotWriter`: discloses the verifier slot iff it is already provisioned + caged
/// (located by scanning). Never writes.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub struct SeVerifierSlotWriter;

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
impl SeSlotWriter for SeVerifierSlotWriter {
    fn provision_verifier_slot(
        &self,
        _requester_device_id: [u8; 32],
        pairing_pubkey: [u8; 32],
    ) -> Option<(u8, [u8; 32])> {
        let found = find_provisioned_slot(|| JniLocalSpiChannel);
        if let Err(ref e) = found {
            log::warn!("[se-slot] verifier-slot scan failed (fail-closed): {e:?}");
        }
        let disclosure = map_disclosure(pairing_pubkey, found);
        if disclosure.is_none() {
            log::warn!(
                "[se-slot] no disclosure (unprovisioned / not caged / wrong key); fail-closed"
            );
        }
        disclosure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STPUB: [u8; 32] = [0xAB; 32];

    #[test]
    fn located_fixed_key_slot_discloses_that_index_and_stpub() {
        // The scan located the role at index 2 (this dev chip): disclose (2, stpub).
        let ok = map_disclosure(dsm_verifier_pairing_pubkey(), Ok(Some((2u16, STPUB))));
        assert_eq!(ok, Some((2u8, STPUB)));
    }

    #[test]
    fn wrong_offered_key_never_discloses_even_when_located() {
        let mut wrong = dsm_verifier_pairing_pubkey();
        wrong[0] ^= 0xFF;
        assert_eq!(map_disclosure(wrong, Ok(Some((2u16, STPUB)))), None);
    }

    #[test]
    fn not_found_and_errors_all_fail_closed() {
        let fixed = dsm_verifier_pairing_pubkey();
        assert_eq!(
            map_disclosure(fixed, Ok(None)),
            None,
            "no provisioned slot -> no disclosure",
        );
        assert_eq!(
            map_disclosure(fixed, Err(ProvisionError::Chip("boom".into()))),
            None,
            "a scan error must fail closed",
        );
    }
}
