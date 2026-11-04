// SPDX-License-Identifier: MIT OR Apache-2.0

//! # The C ABI (feature `ffi`): the iOS host's way into the SDK
//!
//! Swift reaches Rust through these `extern "C"` functions, the one surface
//! `dsm_client/ios` links against; `include/dsm_sdk.h` is their header
//! (cbindgen). They mirror the JNI exports Kotlin calls, one for one, and
//! terminate in the same platform-neutral code (`crate::ingress`,
//! `crate::sdk::session_manager`, `crate::bluetooth`): the platform shims
//! marshal bytes and nothing else.
//!
//! ## Bytes
//!
//! Every payload crosses as protobuf bytes, as on Android. Rust answers with a
//! [`DsmBytes`] it allocated; the host frees it with [`dsm_bytes_free`] once,
//! and never reads it after. A `DsmBytes` with a null pointer carries nothing.
//! Strings the host passes are NUL-terminated UTF-8; a null or non-UTF-8
//! string is refused, never read as empty.
//!
//! ## Failures
//!
//! A function whose Android twin answers an error envelope answers the same
//! framed error envelope here (`0x03 ‖ Envelope(Error)`), which the host tells
//! apart with [`bridge::dsm_ffi_error_code_of`]. A function whose twin is
//! `void` answers the UTF-8 reason it did not do its work, or no bytes when
//! it did. A Rust panic is not caught at this boundary: it is logged by the
//! panic hook and ends the process, visibly.

pub mod ble;
pub mod bridge;
pub mod codec;
pub mod host_bridge;

use std::ffi::CStr;
use std::os::raw::c_char;

/// Bytes Rust allocated for the host. Freed once with [`dsm_bytes_free`].
#[repr(C)]
pub struct DsmBytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl DsmBytes {
    /// Hand `bytes` to the host; Rust forgets them until `dsm_bytes_free`.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = std::mem::ManuallyDrop::new(bytes);
        Self {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            cap: bytes.capacity(),
        }
    }

    /// No bytes at all.
    pub fn none() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// The UTF-8 of `text`, for the void-twin functions' answers.
    pub fn text(text: &str) -> Self {
        Self::from_vec(text.as_bytes().to_vec())
    }

    /// Nothing when `outcome` is `Ok`, else the reason as UTF-8.
    pub fn outcome(outcome: Result<(), String>) -> Self {
        match outcome {
            Ok(()) => Self::none(),
            Err(why) => Self::text(&why),
        }
    }
}

/// Free bytes a `dsm_ffi_*` function answered. Freeing a `DsmBytes` with a
/// null pointer does nothing.
///
/// # Safety
/// `bytes` must be exactly what a `dsm_ffi_*` function answered, freed once.
#[no_mangle]
pub unsafe extern "C" fn dsm_bytes_free(bytes: DsmBytes) {
    if bytes.ptr.is_null() {
        return;
    }
    drop(Vec::from_raw_parts(bytes.ptr, bytes.len, bytes.cap));
}

/// Allocate `len` zeroed bytes for the host to fill and hand back to Rust
/// through a callback's out-parameter (`host_bridge`): Rust owns them.
#[no_mangle]
pub extern "C" fn dsm_bytes_alloc(len: usize) -> DsmBytes {
    DsmBytes::from_vec(vec![0u8; len])
}

/// The host's `(ptr, len)` as a slice; a null pointer is no bytes.
///
/// # Safety
/// `ptr` must point to `len` readable bytes that outlive the call.
pub(crate) unsafe fn bytes_from<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        return &[];
    }
    std::slice::from_raw_parts(ptr, len)
}

/// The host's NUL-terminated UTF-8 string, or why it is not one.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string that outlives the call.
pub(crate) unsafe fn str_from<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| format!("{what} is not UTF-8: {e}"))
}

/// Exactly 32 bytes from the host, or why they are not.
///
/// # Safety
/// `ptr` must be null or point to 32 readable bytes that outlive the call.
pub(crate) unsafe fn d32_from(ptr: *const u8, what: &str) -> Result<[u8; 32], String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    <[u8; 32]>::try_from(std::slice::from_raw_parts(ptr, 32))
        .map_err(|e| format!("{what} is not 32 bytes: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_free() {
        let out = DsmBytes::from_vec(vec![3, 1, 4, 1, 5]);
        let seen = unsafe { bytes_from(out.ptr, out.len) }.to_vec();
        assert_eq!(seen, [3, 1, 4, 1, 5]);
        unsafe { dsm_bytes_free(out) };
        unsafe { dsm_bytes_free(DsmBytes::none()) };
    }

    #[test]
    fn a_null_string_is_refused_not_read_as_empty() {
        let refused =
            unsafe { str_from(std::ptr::null(), "the path") }.expect_err("null is refused");
        assert!(refused.contains("the path is null"), "{refused}");
    }

    #[test]
    fn an_outcome_is_nothing_or_the_reason() {
        let fine = DsmBytes::outcome(Ok(()));
        assert!(fine.ptr.is_null() && fine.len == 0);
        let why = DsmBytes::outcome(Err("the config is unreadable".to_string()));
        assert_eq!(
            unsafe { bytes_from(why.ptr, why.len) },
            b"the config is unreadable"
        );
        unsafe { dsm_bytes_free(why) };
    }
}
