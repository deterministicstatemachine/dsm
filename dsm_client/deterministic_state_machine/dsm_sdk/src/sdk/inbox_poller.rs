// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Inbox Poller — Rust-Driven Inbox Sync
//!
//! Background tokio task that periodically runs `storage.sync` and pushes
//! `inbox.updated` events to the WebView via the canonical reverse-spine
//! (Invariant #7: `Rust → JNI → Kotlin → MessagePort → WebView`).
//!
//! Replaces the frontend `setTimeout` polling loop that violated Invariant #7
//! by making the frontend the authority over inbox discovery timing.

use prost::Message;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

use dsm::types::proto as generated;

/// Default poll interval (ticks between sync attempts).
const DEFAULT_POLL_INTERVAL_MS: u64 = 60_000;

/// Eager poll interval used temporarily after items are found,
/// so follow-up messages (e.g. ACKs or rapid exchanges) are picked up faster.
const EAGER_POLL_INTERVAL_MS: u64 = 8_000;

/// Number of consecutive eager-interval polls before reverting to default.
const EAGER_POLL_CYCLES: u32 = 5;

/// Global poller state.
static POLLER_RUNNING: AtomicBool = AtomicBool::new(false);
static POLLER_STOP: AtomicBool = AtomicBool::new(false);

/// Shared notify for immediate wake-up (app foreground, bilateral commit).
static POLLER_WAKE: once_cell::sync::Lazy<Arc<Notify>> =
    once_cell::sync::Lazy::new(|| Arc::new(Notify::new()));

/// Start the inbox poller background task on the SDK runtime.
///
/// Idempotent: if already running, returns immediately.
pub fn start_poller() {
    if POLLER_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        log::info!("[inbox_poller] Already running, ignoring start_poller()");
        return;
    }
    POLLER_STOP.store(false, Ordering::SeqCst);

    let wake = POLLER_WAKE.clone();

    crate::runtime::get_runtime().spawn(async move {
        log::info!("[inbox_poller] Background poller started");

        // Initial delay before first poll (let bootstrap settle).
        tokio::time::sleep(std::time::Duration::from_millis(5_000)).await;

        let mut eager_remaining: u32 = 0;

        loop {
            if POLLER_STOP.load(Ordering::SeqCst) {
                break;
            }

            let (processed, _pulled) = run_inbox_sync_cycle_counted("poll").await;

            // Enter eager mode when items are processed, so follow-up
            // messages (ACKs, rapid exchanges) are discovered faster.
            if processed > 0 {
                eager_remaining = EAGER_POLL_CYCLES;
                log::info!(
                    "[inbox_poller] Entering eager mode ({} cycles at {}ms)",
                    EAGER_POLL_CYCLES,
                    EAGER_POLL_INTERVAL_MS
                );
            } else {
                eager_remaining = eager_remaining.saturating_sub(1);
            }

            let interval_ms = if eager_remaining > 0 {
                EAGER_POLL_INTERVAL_MS
            } else {
                DEFAULT_POLL_INTERVAL_MS
            };

            // Wait for either the poll interval or a wake-up signal.
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(interval_ms)) => {},
                _ = wake.notified() => {
                    log::info!("[inbox_poller] Woken up early (foreground/bilateral)");
                },
            }
        }

        POLLER_RUNNING.store(false, Ordering::SeqCst);
        log::info!("[inbox_poller] Background poller stopped");
    });
}

/// Stop the inbox poller. The task will exit on its next iteration.
pub fn stop_poller() {
    POLLER_STOP.store(true, Ordering::SeqCst);
    POLLER_WAKE.notify_one();
}

/// Wake the poller immediately (e.g. app foreground, bilateral commit).
pub fn resume_poller() {
    if POLLER_RUNNING.load(Ordering::SeqCst) {
        POLLER_WAKE.notify_one();
    } else {
        // If poller isn't running, start it.
        start_poller();
    }
}

/// Run one sync cycle: call `storage.sync` through the app router,
/// then push `inbox.updated` to the WebView if items were processed.
/// Returns (processed, pulled) counts for adaptive polling.
async fn run_inbox_sync_cycle_counted(source: &str) -> (u32, u32) {
    let router = match crate::bridge::app_router() {
        Some(r) => r,
        None => {
            log::debug!("[inbox_poller] AppRouter not installed yet, skipping cycle");
            return (0, 0);
        }
    };

    // Build a storage.sync request: pull inbox, push pending, limit 50.
    let sync_req = generated::StorageSyncRequest {
        pull_inbox: true,
        push_pending: true,
        limit: 50,
    };
    let arg_pack = generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body: sync_req.encode_to_vec(),
        schema_hash: None,
    };
    let query = crate::bridge::AppQuery {
        path: "storage.sync".to_string(),
        params: arg_pack.encode_to_vec(),
    };

    let result = router.query(query).await;

    if !result.success {
        let msg = result.error_message.as_deref().unwrap_or("unknown");
        log::warn!("[inbox_poller] storage.sync failed: {msg}");
        return (0, 0);
    }

    // Decode the Envelope response to get StorageSyncResponse.
    let (processed, pulled) = match decode_sync_response(&result.data) {
        Some((p, pu)) => (p, pu),
        None => {
            log::debug!("[inbox_poller] Could not decode storage.sync response");
            return (0, 0);
        }
    };

    log::info!(
        "[inbox_poller] sync cycle complete: pulled={pulled}, processed={processed}, source={source}"
    );

    // Push `inbox.updated` event to WebView via the canonical reverse-spine.
    push_inbox_event_to_webview(pulled, processed);

    (processed, pulled)
}

/// Push inbox.updated + optional wallet refresh to WebView.
#[cfg(all(target_os = "android", feature = "jni"))]
fn push_inbox_event_to_webview(pulled: u32, processed: u32) {
    let event_payload = generated::StorageSyncResponse {
        success: true,
        pulled,
        processed,
        pushed: 0,
        errors: vec![],
    };
    let payload_bytes = event_payload.encode_to_vec();

    if let Err(e) =
        crate::jni::event_dispatch::post_event_to_webview("inbox.updated", &payload_bytes)
    {
        log::warn!("[inbox_poller] Failed to push inbox.updated to WebView: {e}");
    }

    if processed > 0 {
        let _ = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]);
    }
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn push_inbox_event_to_webview(_pulled: u32, _processed: u32) {
    // No-op on non-Android / non-JNI builds.
}

/// Decode the framed Envelope response from storage.sync to extract
/// the processed/pulled counts from StorageSyncResponse.
fn decode_sync_response(data: &[u8]) -> Option<(u32, u32)> {
    // Data is framed Envelope v3: [0x03][Envelope proto]
    let envelope_bytes = if !data.is_empty() && data[0] == 0x03 {
        &data[1..]
    } else {
        data
    };

    let envelope = generated::Envelope::decode(envelope_bytes).ok()?;
    match envelope.payload {
        Some(generated::envelope::Payload::StorageSyncResponse(resp)) => {
            Some((resp.processed, resp.pulled))
        }
        _ => None,
    }
}
