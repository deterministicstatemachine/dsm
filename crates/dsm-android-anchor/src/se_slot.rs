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
use dsm_anchor_hw_verifier::{dsm_verifier_pairing_pubkey, ProvisionError};
// The read-only transport + status probes are NOT accept-enabling, so they live under plain
// `target_os = "android"` (shipped in the default .so). Only the accept-enabling `SeSlotWriter` is
// behind the `on_device_installs` feature.
#[cfg(target_os = "android")]
use dsm_anchor_hw_verifier::{
    find_provisioned_slot, preflight_verifier_slot, read_counter, read_verifier_slot,
    VerifierSlotState, MCOUNTER_MAX, VERIFIER_SLOT_CANDIDATES,
};
#[cfg(target_os = "android")]
use dsm_anchor_verifier::{RelayError, SpiRelayChannel};
// The counter-init WRITE is a gated setup op (like the burn) — feature-gated, absent from default .so.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_hw_verifier::init_counter_max;
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
#[cfg(target_os = "android")]
pub struct JniLocalSpiChannel;

#[cfg(target_os = "android")]
impl SpiRelayChannel for JniLocalSpiChannel {
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
        let frame = crate::usb_pico::frame_passthrough(mosi.to_vec());
        let body = crate::usb_pico::jni_usb_transceive(frame)
            .map_err(|e| RelayError::Transport(format!("local pico up-call: {e}")))?;
        crate::usb_pico::decode_passthrough(&body)
            .map_err(|e| RelayError::Transport(format!("local pico decode: {e}")))
    }
}

/// READ-ONLY diagnostic (no writes, no burn): scan every candidate index + run the slot-2 preflight
/// on A's local chip, logging chip identity + per-slot state so an operator (via `adb logcat`) can
/// confirm which chip this is and whether it is safe to burn — through the phone, without moving the
/// chip to a bench. Returns 0 always; results are in logcat under "se-slot". Present in the default
/// .so (read-only); it can never write hardware.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_verifierSlotStatus(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jint {
    log::info!("[se-slot] === verifier-slot STATUS (read-only) ===");
    for &slot in VERIFIER_SLOT_CANDIDATES {
        match read_verifier_slot(slot, JniLocalSpiChannel) {
            Ok(VerifierSlotState::Provisioned { stpub }) => {
                log::info!(
                    "[se-slot] slot {slot}: PROVISIONED (fixed DSM key, caged); stpub={stpub:02x?}"
                )
            }
            Ok(VerifierSlotState::Empty { stpub }) => {
                log::info!("[se-slot] slot {slot}: EMPTY; stpub={stpub:02x?}")
            }
            Ok(VerifierSlotState::Occupied) => {
                log::info!("[se-slot] slot {slot}: OCCUPIED (non-fixed key or not caged)")
            }
            Err(e) => log::warn!("[se-slot] slot {slot}: read error {e:?}"),
        }
    }
    match find_provisioned_slot(|| JniLocalSpiChannel) {
        Ok(Some((slot, stpub))) => {
            log::info!(
                "[se-slot] provisioned verifier role located at slot {slot}; stpub={stpub:02x?}"
            )
        }
        Ok(None) => log::info!("[se-slot] no verifier role provisioned on any candidate index"),
        Err(e) => log::warn!("[se-slot] scan error {e:?}"),
    }
    // Read-only counter status: current mcounter[0] vs the intended device budget (max).
    match read_counter(JniLocalSpiChannel) {
        Ok(v) => {
            let note = if v == MCOUNTER_MAX {
                "at max"
            } else {
                "NOT at max (placeholder/partial)"
            };
            log::info!(
                "[se-slot] mcounter[0] current={v} intended-max(H0)={MCOUNTER_MAX} -> {note}"
            )
        }
        Err(e) => log::warn!("[se-slot] counter read error {e:?}"),
    }
    // Read-only preflight of the intended dev-chip slot (2). Writes nothing.
    match preflight_verifier_slot(2, JniLocalSpiChannel) {
        Ok(r) => log::info!(
            "[se-slot] preflight slot 2: WOULD PROCEED; stpub={:02x?} mcounter[0]={}",
            r.stpub,
            r.mcounter
        ),
        Err(e) => log::warn!("[se-slot] preflight slot 2: NOT eligible: {e:?}"),
    }
    log::info!("[se-slot] === verifier-slot STATUS done ===");
    0
}

/// GATED device-setup WRITE (absent from the default .so): initialize mcounter[0] to the max device
/// budget (`MCOUNTER_MAX`) on A's local chip, via slot 0, and confirm the read-back. SEPARATE from the
/// verifier-slot burn and run BEFORE it. Returns the read-back counter on success, or -1 fail. Invoked
/// deliberately by the operator over ADB; never from app boot or a transfer.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_counterInitMax(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jlong {
    log::info!("[se-slot] counter-init: setting mcounter[0] to MCOUNTER_MAX={MCOUNTER_MAX} ...");
    match init_counter_max(JniLocalSpiChannel) {
        Ok(v) => {
            log::info!("[se-slot] counter-init OK: mcounter[0] read-back = {v} (== max)");
            i64::from(v)
        }
        Err(e) => {
            log::error!("[se-slot] counter-init FAILED: {e:?}");
            -1
        }
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
