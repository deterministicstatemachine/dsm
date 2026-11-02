// SPDX-License-Identifier: MIT OR Apache-2.0

//! The radio's C ABI: the twins of `bleLinkOpened`, `bleLinkClosed`,
//! `processIncomingBleData`, the bilateral accept/reject/cancel exports and
//! `initializeBilateralSdk`, each terminating in `crate::bluetooth::radio_link`.
//! The host moves the bytes these answer and interprets none of them.

use std::os::raw::c_char;

use crate::bluetooth::link_session::GattRole;
use crate::bluetooth::radio_link::{self, RadioWriteError};
use crate::ffi::bridge::{error_envelope, ErrorCode};
use crate::ffi::host_bridge::frame_records;
use crate::ffi::{bytes_from, d32_from, str_from, DsmBytes};

/// What a radio event came to: records to write back on the link (each
/// behind its big-endian u32 length, back to back), or why the bytes were
/// refused, in which case the host closes the link. Exactly one of the two
/// carries bytes, unless the event called for nothing.
#[repr(C)]
pub struct DsmRadioAnswer {
    pub reply: DsmBytes,
    pub refusal: DsmBytes,
}

impl DsmRadioAnswer {
    fn reply(records: Vec<Vec<u8>>) -> Self {
        Self {
            reply: if records.is_empty() {
                DsmBytes::none()
            } else {
                DsmBytes::from_vec(frame_records(&records))
            },
            refusal: DsmBytes::none(),
        }
    }

    fn refused(why: &str) -> Self {
        Self {
            reply: DsmBytes::none(),
            refusal: DsmBytes::text(why),
        }
    }
}

fn role_from(role: i32) -> Result<GattRole, String> {
    GattRole::from_wire(role).map_err(|e| e.to_string())
}

/// `bleLinkOpened`: a GATT link came up at `address`, this device on it as
/// `role` (1 client, 2 server); `target` is the 32-byte contact the client
/// reached for, or null for any DSM device. The reply is the client's first
/// Hello, nothing for the server. A refusal means the link is not opened.
///
/// # Safety
/// `address` must be a NUL-terminated string; `target` null or 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_link_opened(
    address: *const c_char,
    role: i32,
    target: *const u8,
) -> DsmRadioAnswer {
    let opened = (|| -> Result<Vec<Vec<u8>>, String> {
        let address = str_from(address, "the link's address")?;
        let role = role_from(role)?;
        let target = if target.is_null() {
            None
        } else {
            Some(d32_from(target, "the link's target")?)
        };
        radio_link::link_opened(address, role, target)
    })();
    match opened {
        Ok(records) => DsmRadioAnswer::reply(records),
        Err(why) => DsmRadioAnswer::refused(&format!("BLE link: {why}")),
    }
}

/// `bleLinkClosed`: the GATT link at `address`, this device on it as `role`,
/// closed. Answers nothing, or why the close was not taken (a bad address or
/// role).
///
/// # Safety
/// `address` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_link_closed(address: *const c_char, role: i32) -> DsmBytes {
    DsmBytes::outcome((|| -> Result<(), String> {
        let address = str_from(address, "the closed link's address")?;
        let role = role_from(role)?;
        radio_link::link_closed(address, role);
        Ok(())
    })())
}

/// `processIncomingBleData`: bytes a peer wrote over BLE on the link at
/// `address`, this device on it as `role`. The reply is written back on the
/// same link; a refusal closes it.
///
/// # Safety
/// `address` must be a NUL-terminated string; `bytes` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_inbound(
    address: *const c_char,
    role: i32,
    bytes: *const u8,
    len: usize,
) -> DsmRadioAnswer {
    let address = match str_from(address, "the link's address") {
        Ok(address) => address,
        Err(why) => return DsmRadioAnswer::refused(&why),
    };
    let role = match role_from(role) {
        Ok(role) => role,
        Err(why) => return DsmRadioAnswer::refused(&why),
    };
    match radio_link::radio_write(address, role, bytes_from(bytes, len)) {
        Ok(records) => DsmRadioAnswer::reply(records),
        Err(e) => {
            log::error!("processIncomingBleData: refused bytes from {address}: {e}");
            DsmRadioAnswer::refused(&format!("processIncomingBleData: {e}"))
        }
    }
}

fn radio_error_envelope(e: RadioWriteError) -> DsmBytes {
    let code = match e {
        RadioWriteError::Refused(_) => ErrorCode::InvalidInput,
        RadioWriteError::NotReady(_) => ErrorCode::NotReady,
        RadioWriteError::Failed(_) => ErrorCode::ProcessingFailed,
    };
    DsmBytes::from_vec(error_envelope(code, e.message()))
}

/// `acceptBilateralByCommitment`: the framed accept envelope, or an error envelope.
///
/// # Safety
/// `commitment` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_accept(commitment: *const u8) -> DsmBytes {
    let commitment = match d32_from(commitment, "commitment_hash") {
        Ok(commitment) => commitment,
        Err(why) => return DsmBytes::from_vec(error_envelope(ErrorCode::InvalidInput, &why)),
    };
    match radio_link::accept_proposal(commitment) {
        Ok(framed) => DsmBytes::from_vec(framed),
        Err(e) => radio_error_envelope(e),
    }
}

/// `rejectBilateralByCommitment`: the framed reject envelope, or an error envelope.
///
/// # Safety
/// `commitment` must point to 32 readable bytes; `reason` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_reject(
    commitment: *const u8,
    reason: *const c_char,
) -> DsmBytes {
    bilateral_with_reason(commitment, reason, radio_link::reject_proposal)
}

/// `cancelBilateralByCommitment`: the framed cancellation, or an error envelope.
///
/// # Safety
/// `commitment` must point to 32 readable bytes; `reason` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ble_cancel(
    commitment: *const u8,
    reason: *const c_char,
) -> DsmBytes {
    bilateral_with_reason(commitment, reason, radio_link::cancel_proposal)
}

unsafe fn bilateral_with_reason(
    commitment: *const u8,
    reason: *const c_char,
    run: fn([u8; 32], String) -> Result<Vec<u8>, RadioWriteError>,
) -> DsmBytes {
    let inputs = (|| -> Result<([u8; 32], String), String> {
        Ok((
            d32_from(commitment, "commitment_hash")?,
            str_from(reason, "the reason")?.to_string(),
        ))
    })();
    let (commitment, reason) = match inputs {
        Ok(inputs) => inputs,
        Err(why) => return DsmBytes::from_vec(error_envelope(ErrorCode::InvalidInput, &why)),
    };
    match run(commitment, reason) {
        Ok(framed) => DsmBytes::from_vec(framed),
        Err(e) => radio_error_envelope(e),
    }
}

/// `initializeBilateralSdk`: mark the bilateral runtime ready once the SDK
/// context is initialized and the BLE stack is live. Answers nothing, or why
/// it is not ready yet; the host calls again when its preconditions can have
/// changed (the identity restored, a wallet created).
#[no_mangle]
pub extern "C" fn dsm_ffi_initialize_bilateral_sdk() -> DsmBytes {
    DsmBytes::outcome(
        crate::runtime::get_runtime()
            .block_on(crate::initialize_bilateral_sdk())
            .map_err(|e| e.to_string()),
    )
}

/// `isBleCoordinatorReady`: 1 when the BLE frame coordinator is injected, else 0.
#[no_mangle]
pub extern "C" fn dsm_ffi_ble_stack_ready() -> i32 {
    match crate::runtime::get_runtime().block_on(crate::bridge::get_ble_coordinator()) {
        Ok(_) => 1,
        Err(_not_yet) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A role that is neither client nor server opens nothing and says so;
    /// the answer carries a refusal and no reply.
    #[test]
    fn a_link_with_no_role_is_refused() {
        let address = c"6B2C7F1E-9A3D-4E08-B5C1-2D7A9F0E4C61";
        let answer = unsafe { dsm_ffi_ble_link_opened(address.as_ptr(), 7, std::ptr::null()) };
        assert!(answer.reply.ptr.is_null());
        let why = unsafe { bytes_from(answer.refusal.ptr, answer.refusal.len) }.to_vec();
        unsafe {
            crate::ffi::dsm_bytes_free(answer.reply);
            crate::ffi::dsm_bytes_free(answer.refusal);
        }
        let why = String::from_utf8(why).expect("utf-8");
        assert!(why.contains("GATT role 7"), "{why}");
    }

    /// Bytes on a link that was never opened are refused: the host closes it.
    #[test]
    fn bytes_on_a_link_never_opened_are_refused() {
        let address = c"0F2A9C44-1D6B-4B2E-8E3F-5A7C1B9D2E60";
        let fragment = [0x05u8, 1, 0, 1, 0xAA];
        let answer =
            unsafe { dsm_ffi_ble_inbound(address.as_ptr(), 2, fragment.as_ptr(), fragment.len()) };
        assert!(answer.reply.ptr.is_null());
        let why = unsafe { bytes_from(answer.refusal.ptr, answer.refusal.len) }.to_vec();
        unsafe {
            crate::ffi::dsm_bytes_free(answer.reply);
            crate::ffi::dsm_bytes_free(answer.refusal);
        }
        assert!(String::from_utf8(why)
            .expect("utf-8")
            .contains("not opened"));
    }
}
