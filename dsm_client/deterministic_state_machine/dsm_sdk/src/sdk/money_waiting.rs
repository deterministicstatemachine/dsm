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

fn show(count: i32) {
    if let Err(e) = crate::host::host().and_then(|host| host.show_money_received(count)) {
        log::warn!("[money_waiting] the icon count was not handed to the host: {e}");
    }
    crate::host::post_event("money.waiting", &[]);
}
