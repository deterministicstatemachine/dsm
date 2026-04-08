// SPDX-License-Identifier: MIT OR Apache-2.0
//! Legacy Android event shim.
//!
//! Older Rust producers still emit topic-parameterized events. The public
//! native boundary is now typed `SdkEvent` bytes drained through ingress, so
//! this module maps those legacy topics into `SdkEventKind` values and queues
//! them on the shared event bus.

use dsm::types::error::DsmError;

use crate::generated as pb;

fn map_legacy_topic(topic: &str) -> Option<i32> {
    match topic {
        "bilateral.event" => Some(pb::SdkEventKind::BilateralEvent as i32),
        "inbox.updated" => Some(pb::SdkEventKind::InboxUpdated as i32),
        "dsm-wallet-refresh" => Some(pb::SdkEventKind::WalletRefresh as i32),
        _ => None,
    }
}

/// Queue a binary event for delivery through the shared ingress event drain.
pub fn post_event_to_webview(topic: &str, payload: &[u8]) -> Result<(), DsmError> {
    let Some(kind) = map_legacy_topic(topic) else {
        let message = format!("unsupported legacy sdk event topic: {topic}");
        log::warn!("{message}");
        return Err(DsmError::invalid_operation(message));
    };

    crate::event::push_sdk_event(kind, payload.to_vec());
    Ok(())
}
