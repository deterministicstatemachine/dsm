// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host's link to its anchor board, as the C ABI sees it. The host supplies one round-trip:
//! a request frame in, the answer frame's body out. On iOS it is the Swift Bluetooth link to the
//! board's service (`DsmWallet/Ble/AnchorLink.swift`); the host moves the bytes and interprets
//! none of them. Installing it gives this process its appliance: the SDK's `FramedAnchorAppliance`
//! over that round-trip, the same client Android runs over its USB round-trip.

use std::sync::Arc;

use dsm::types::error::DsmError;

use crate::anchor::{AnchorAppliance, FramedAnchorAppliance, Transceive};
use crate::ffi::DsmBytes;

/// One round-trip to the board: `request` is the LE32-length-prefixed request frame, whole; the
/// host writes it to the board and reads the answer frame, and fills `out` with the answer's body
/// (the bytes after its LE32 length) in a buffer from `dsm_bytes_alloc`, which Rust then owns.
/// Answers 0 when it did; any other code is a failure to reach the board or to get an answer, and
/// `out` may then carry the reason as UTF-8. The call may take as long as the board does.
pub type DsmAnchorTransceive =
    extern "C" fn(request: *const u8, len: usize, out: *mut DsmBytes) -> i32;

/// Install the host's board link as this process's anchor appliance. From here, every offline
/// release is produced by the board the link reaches; a link that cannot reach one fails every
/// such send closed. Answers nothing.
#[no_mangle]
pub extern "C" fn dsm_ffi_install_anchor_link(transceive: DsmAnchorTransceive) -> DsmBytes {
    let link: Transceive = Arc::new(move |frame: Vec<u8>| exchange(transceive, &frame));
    crate::bridge::install_anchor_appliance_factory(Arc::new(move || {
        let appliance = FramedAnchorAppliance::connect(link.clone())?;
        Ok(Box::new(appliance) as Box<dyn AnchorAppliance + Send>)
    }));
    log::info!("[anchor-link] the host's board link is installed: releases come from the board");
    DsmBytes::none()
}

/// Run the host's round-trip once and take the bytes it filled in. Whatever the code, the buffer
/// is Rust's after the call.
fn exchange(transceive: DsmAnchorTransceive, frame: &[u8]) -> Result<Vec<u8>, DsmError> {
    let mut out = DsmBytes::none();
    let code = transceive(frame.as_ptr(), frame.len(), &mut out);
    let bytes = if out.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) }
    };
    if code != 0 {
        let why = String::from_utf8_lossy(&bytes);
        return Err(DsmError::invalid_operation(if why.is_empty() {
            format!("anchor link: the host's round-trip answered code {code}")
        } else {
            format!("anchor link: {why}")
        }));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn answers_the_frame_back(
        request: *const u8,
        len: usize,
        out: *mut DsmBytes,
    ) -> i32 {
        let frame = unsafe { crate::ffi::bytes_from(request, len) };
        // The body of the frame, as a board answering the request's own bytes would.
        let answer = frame[4..].to_vec();
        unsafe { *out = DsmBytes::from_vec(answer) };
        0
    }

    extern "C" fn cannot_reach_the_board(
        _request: *const u8,
        _len: usize,
        out: *mut DsmBytes,
    ) -> i32 {
        unsafe { *out = DsmBytes::text("no DSM Anchor in range") };
        1
    }

    /// The host's answer bytes are the round-trip's answer, the LE32 header being the host's to read.
    #[test]
    fn the_hosts_answer_is_the_round_trips_answer() {
        let frame = [3u8, 0, 0, 0, 0xA, 0xB, 0xC];
        let answer = exchange(answers_the_frame_back, &frame).expect("an answer");
        assert_eq!(answer, vec![0xA, 0xB, 0xC]);
    }

    /// A failure code with a reason reaches the wallet as that reason, and the buffer is taken.
    #[test]
    fn a_failure_keeps_the_hosts_reason() {
        let refused = exchange(cannot_reach_the_board, &[0, 0, 0, 0]).expect_err("a failure");
        assert!(
            refused.to_string().contains("no DSM Anchor in range"),
            "{refused}"
        );
    }
}
