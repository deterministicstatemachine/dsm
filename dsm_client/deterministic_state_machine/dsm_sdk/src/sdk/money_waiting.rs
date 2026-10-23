// SPDX-License-Identifier: MIT OR Apache-2.0
//! The count on the app icon and on the b0x button: the transfers this device
//! received and verified that the user has not opened the b0x inbox on yet
//! (owner, 2026-10-23; [`crate::storage::client_db::money_received`]).
//!
//! Rust decides the number; the host draws it. [`publish`] runs whenever the
//! number can have changed — a received transfer stored, the inbox looked at,
//! the poller started in a new process — and hands the host the count for the
//! icon and tells the page to read the list again (`money.waiting`).

use crate::storage::client_db::money_received;

/// Hand the host the number of received transfers waiting. An unreadable
/// store is logged and leaves the icon as it was: no number is drawn that
/// Rust did not read.
pub fn publish() {
    match money_received::money_waiting() {
        Ok(waiting) => match i32::try_from(waiting.received.len()) {
            Ok(count) => show(count),
            Err(e) => log::error!(
                "[money_waiting] {} waiting is past a count the host takes: {e}",
                waiting.received.len()
            ),
        },
        Err(e) => log::error!("[money_waiting] the received notices are unreadable: {e}"),
    }
}

#[cfg(all(target_os = "android", feature = "jni"))]
fn show(count: i32) {
    if let Err(e) = crate::jni::event_dispatch::show_money_received(count) {
        log::warn!("[money_waiting] the icon count was not handed to the host: {e}");
    }
    if let Err(e) = crate::jni::event_dispatch::post_event_to_webview("money.waiting", &[]) {
        log::warn!("[money_waiting] money.waiting was not posted to the page: {e}");
    }
}

/// Builds with no Android host have no icon to draw on.
#[cfg(not(all(target_os = "android", feature = "jni")))]
fn show(count: i32) {
    log::debug!("[money_waiting] {count} waiting; no host icon in this build");
}
