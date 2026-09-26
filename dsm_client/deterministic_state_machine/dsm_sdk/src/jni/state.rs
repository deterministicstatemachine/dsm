// SPDX-License-Identifier: MIT OR Apache-2.0

//! # JNI Global State
//!
//! Process-global flags shared across JNI entry points: whether the bilateral
//! poll has started. Where a contact's phone is over BLE is
//! `crate::bluetooth::peer_address`; `SDK_READY` is `sdk::session_manager`.

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use std::sync::atomic::AtomicBool;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub static BILATERAL_INIT_POLL_STARTED: AtomicBool = AtomicBool::new(false);
