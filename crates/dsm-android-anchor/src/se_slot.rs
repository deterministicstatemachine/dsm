// SPDX-License-Identifier: MIT OR Apache-2.0
//! Device SETUP + read-only diagnostics for the holder's OWN TROPIC01, driven over the phone's USB
//! link (`OP_SPI_PASSTHROUGH`) — v2 Software-Authority / Hardware-Identity.
//!
//! v2 has NO verifier slot and NO receiver-side hardware. What remains here:
//!   - read-only diagnostics (always shipped in the default .so; can never write hardware):
//!     `anchorChipStatus` logs the live counter vs the intended budget; `anchorCounterSelfTest`
//!     returns ONE authenticated counter read (the H2/H3 bench self-test, now over the local link).
//!   - gated device-setup WRITES (feature `on_device_installs`, absent from the default .so, run
//!     deliberately by the operator over ADB — never from app boot or a transfer):
//!     `counterInitMax` (counter birth: mcounter[0] := MCOUNTER_MAX, spec impl-req #5) and
//!     `birthCageSlot0` (the IRREVERSIBLE slot-0 birth cage: revokes counter-reset/re-key/un-cage).
//!
//! The sync [`SpiRelayChannel`] drives the SAME opaque JNI USB up-call the appliance transport
//! uses, so the proven bench provisioning ops run unchanged on-device.

// Read-only transport + probes are NOT accept-enabling → plain `target_os = "android"` (default
// .so). The setup WRITES are gated `on_device_installs`.
#[cfg(target_os = "android")]
use dsm_anchor_hw_verifier::{read_counter, MCOUNTER_MAX};
#[cfg(target_os = "android")]
use dsm_anchor_verifier::{RelayError, SpiRelayChannel};
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
use dsm_anchor_hw_verifier::{birth_cage_slot0, init_counter_max};

/// A sync `SpiRelayChannel` to the phone's LOCAL Pico over the JNI USB up-call: each `transceive`
/// frames one raw SPI transaction as `OP_SPI_PASSTHROUGH` (in Rust) and returns the MISO.
/// Zero-size — mint a fresh one per operation.
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

/// READ-ONLY diagnostic (no writes): read the local chip's mcounter[0] and log it against the
/// intended device budget. Returns 0 always; results are in logcat under "se-slot". Present in the
/// default .so; it can never write hardware.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_anchorChipStatus(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jint {
    log::info!("[se-slot] === anchor chip STATUS (read-only) ===");
    match read_counter(JniLocalSpiChannel) {
        Ok(v) => {
            let note = if v == MCOUNTER_MAX {
                "at max (full budget)"
            } else {
                "below max (steps consumed, or partial provisioning)"
            };
            log::info!("[se-slot] mcounter[0] current={v} budget-max(H0)={MCOUNTER_MAX} -> {note}");
        }
        Err(e) => log::warn!("[se-slot] counter read error {e:?}"),
    }
    log::info!("[se-slot] === anchor chip STATUS done ===");
    0
}

/// READ-ONLY self-test: ONE authenticated counter read over the local USB link. Returns the live
/// counter `H` (>= 0) or -1 on any failure — the bench proof that the phone can reach a real
/// TROPIC01 through its own Pico. Never writes.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_anchorCounterSelfTest(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jlong {
    match read_counter(JniLocalSpiChannel) {
        Ok(v) => {
            log::info!("[se-slot] counter self-test OK: H={v}");
            i64::from(v)
        }
        Err(e) => {
            log::error!("[se-slot] counter self-test FAILED: {e:?}");
            -1
        }
    }
}

/// GATED device-setup WRITE (absent from the default .so): initialize mcounter[0] to the max device
/// budget (`MCOUNTER_MAX`) on the local chip — counter birth. Returns the read-back counter on
/// success, or -1 fail. Run BEFORE the birth cage (which revokes `mcounter_init` forever). Invoked
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

/// GATED IRREVERSIBLE birth burn (absent from the default .so): permanently revoke slot-0's
/// counter-reset + re-key + un-cage authority (`SLOT0_BIRTH_DENY`), making the down-counter's
/// one-way monotonicity a hardware birth invariant. Run LAST in device setup, AFTER
/// `counterInitMax`. Returns the now-immutable H0 (>= 0) or -1 on failure (nothing partial is
/// trusted). Invoked deliberately by the operator over ADB with explicit confirmation; never from
/// app boot or a transfer.
#[cfg(all(target_os = "android", feature = "on_device_installs"))]
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_Unified_birthCageSlot0(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jlong {
    log::info!("[se-slot] BIRTH CAGE: permanently sealing slot-0 (irreversible) ...");
    match birth_cage_slot0(JniLocalSpiChannel) {
        Ok(h0) => {
            log::info!("[se-slot] BIRTH CAGE OK: sealed; immutable H0={h0}");
            i64::from(h0)
        }
        Err(e) => {
            log::error!("[se-slot] BIRTH CAGE FAILED (nothing partial trusted): {e:?}");
            -1
        }
    }
}
