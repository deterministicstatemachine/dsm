// SPDX-License-Identifier: MIT OR Apache-2.0
//! H3 sender-side SE op: the DSM SMT-root verifier slot on A's OWN TROPIC01.
//!
//! Two entry points, matching the owner's read/burn split:
//!   - [`SeVerifierSlotWriter`] fills `dsm_sdk`'s `SeSlotWriter` seam. It is **read-only**: on a
//!     first-transfer enroll it confirms slot 1 already holds the fixed DSM verifier key AND is
//!     caged, and discloses `(slot 1, stpub)`. It NEVER writes — a normal transfer (or app boot)
//!     can never burn hardware. Empty / occupied / wrong-key / any error -> `None` -> disclosure
//!     empty -> receiver pin incomplete -> fail-closed.
//!   - [`provision_verifier_slot_commit`] performs the IRREVERSIBLE burn. It runs ONLY from an
//!     explicit setup/commit gate (a dedicated JNI trigger), never as a side effect of anything.
//!
//! Both drive A's local Pico over the same opaque JNI USB up-call the relay uses, wrapped as a sync
//! `SpiRelayChannel` so the proven `provisioner` sequence runs unchanged on-device.

// Host-testable decision types (hw-verifier is a normal dep, so these resolve on host too).
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_hw_verifier::{commit_verifier_slot, read_verifier_slot};
use dsm_anchor_hw_verifier::{
    dsm_verifier_pairing_pubkey, ProvisionError, VerifierSlotState, VERIFIER_SLOT,
};
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_verifier::{RelayError, SpiRelayChannel};
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_sdk::bridge::SeSlotWriter;

/// The fail-closed disclosure decision, pulled out of the on-device path so it is host-testable: the
/// receiver's offered key must be the fixed DSM verifier key, and the slot must read back as fully
/// provisioned + caged. Anything else -> `None` (disclosure empty -> receiver pin incomplete).
fn map_disclosure(
    offered_pubkey: [u8; 32],
    read: Result<VerifierSlotState, ProvisionError>,
) -> Option<(u8, [u8; 32])> {
    if offered_pubkey != dsm_verifier_pairing_pubkey() {
        return None;
    }
    match read {
        Ok(VerifierSlotState::Provisioned { stpub }) => Some((VERIFIER_SLOT as u8, stpub)),
        _ => None,
    }
}

/// A sync `SpiRelayChannel` to A's LOCAL Pico over the JNI USB up-call: each `transceive` frames one
/// raw SPI transaction as `OP_SPI_PASSTHROUGH` (in Rust) and returns the MISO. Zero-size — a fresh
/// one is minted per session (the provisioner's `make_channel`).
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

/// Read-only `SeSlotWriter`: discloses the verifier slot iff it is already provisioned + caged.
/// Never writes.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub struct SeVerifierSlotWriter;

#[cfg(all(target_os = "android", feature = "on_device_installs"))]
impl SeSlotWriter for SeVerifierSlotWriter {
    fn provision_verifier_slot(
        &self,
        _requester_device_id: [u8; 32],
        pairing_pubkey: [u8; 32],
    ) -> Option<(u8, [u8; 32])> {
        let read = read_verifier_slot(JniLocalSpiChannel);
        if let Err(ref e) = read {
            log::warn!("[se-slot] verifier slot read failed (fail-closed): {e:?}");
        }
        let disclosure = map_disclosure(pairing_pubkey, read);
        if disclosure.is_none() {
            log::warn!(
                "[se-slot] no disclosure (unprovisioned / not caged / wrong key); fail-closed"
            );
        }
        disclosure
    }
}

/// EXPLICIT setup/commit action — the IRREVERSIBLE burn. Idempotent when already provisioned; refuses
/// to overwrite a non-empty slot. Returns `(slot, stpub)` on success. NEVER called from a transfer or
/// app boot — only from the dedicated JNI trigger below.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
pub fn provision_verifier_slot_commit() -> Result<(u8, [u8; 32]), String> {
    commit_verifier_slot(|| JniLocalSpiChannel).map_err(|e| format!("{e:?}"))
}

/// JNI trigger for the EXPLICIT setup burn. Returns the slot index (>=0) on success, -1 on failure.
/// Present only in `on_device_installs` builds; a dedicated bench/setup UI action must invoke it. A
/// normal transfer or app boot never reaches this symbol.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_provisionVerifierSlotCommit(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jint {
    match provision_verifier_slot_commit() {
        Ok((slot, stpub)) => {
            log::info!("[se-slot] verifier slot {slot} provisioned; stpub={stpub:02x?}");
            i32::from(slot)
        }
        Err(e) => {
            log::error!("[se-slot] provision failed: {e}");
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STPUB: [u8; 32] = [0xAB; 32];

    #[test]
    fn provisioned_with_the_fixed_key_discloses_slot_and_stpub() {
        let ok = map_disclosure(
            dsm_verifier_pairing_pubkey(),
            Ok(VerifierSlotState::Provisioned { stpub: STPUB }),
        );
        assert_eq!(ok, Some((VERIFIER_SLOT as u8, STPUB)));
    }

    #[test]
    fn wrong_offered_key_never_discloses_even_when_provisioned() {
        let mut wrong = dsm_verifier_pairing_pubkey();
        wrong[0] ^= 0xFF;
        assert_eq!(
            map_disclosure(wrong, Ok(VerifierSlotState::Provisioned { stpub: STPUB })),
            None,
        );
    }

    #[test]
    fn empty_occupied_and_errors_all_fail_closed() {
        let fixed = dsm_verifier_pairing_pubkey();
        assert_eq!(
            map_disclosure(fixed, Ok(VerifierSlotState::Empty { stpub: STPUB })),
            None,
            "an unprovisioned slot must never disclose",
        );
        assert_eq!(
            map_disclosure(fixed, Ok(VerifierSlotState::Occupied)),
            None,
            "an occupied/uncaged slot must never disclose",
        );
        assert_eq!(
            map_disclosure(fixed, Err(ProvisionError::Chip("boom".into()))),
            None,
            "a read error must fail closed",
        );
    }
}
