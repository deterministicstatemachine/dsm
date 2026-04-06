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

/// Poll interval while sender-side pending online catch-up gates exist.
///
/// This keeps ACK/finalization hot until the relationship actually converges,
/// instead of falling back to the idle 60s cadence after one early wake-up.
const PENDING_GATE_POLL_INTERVAL_MS: u64 = 5_000;

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
            let pending_gate_active = has_pending_online_catchup();

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

            let interval_ms = if pending_gate_active {
                PENDING_GATE_POLL_INTERVAL_MS
            } else if eager_remaining > 0 {
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

fn has_pending_online_catchup() -> bool {
    crate::storage::client_db::get_all_pending_online_outbox()
        .map(|entries| !entries.is_empty())
        .unwrap_or(false)
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
            if !resp.errors.is_empty() {
                log::warn!(
                    "[inbox_poller] storage.sync reported {} error(s): {:?}",
                    resp.errors.len(),
                    resp.errors
                );
            }
            Some((resp.processed, resp.pulled))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ──

    #[test]
    fn default_poll_interval_is_60s() {
        assert_eq!(DEFAULT_POLL_INTERVAL_MS, 60_000);
    }

    #[test]
    fn eager_poll_interval_shorter_than_default() {
        assert_eq!(DEFAULT_POLL_INTERVAL_MS - EAGER_POLL_INTERVAL_MS, 52_000);
    }

    #[test]
    fn eager_poll_cycles_nonzero() {
        assert_eq!(EAGER_POLL_CYCLES, 5);
    }

    #[test]
    fn eager_interval_is_8s() {
        assert_eq!(EAGER_POLL_INTERVAL_MS, 8_000);
    }

    #[test]
    fn eager_cycles_is_5() {
        assert_eq!(EAGER_POLL_CYCLES, 5);
    }

    // ── decode_sync_response ──

    #[test]
    fn decode_empty_returns_none() {
        assert!(decode_sync_response(&[]).is_none());
    }

    #[test]
    fn decode_garbage_returns_none() {
        assert!(decode_sync_response(&[0xFF, 0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn decode_valid_envelope_with_sync_response() {
        let sync_resp = generated::StorageSyncResponse {
            success: true,
            pulled: 7,
            processed: 3,
            pushed: 0,
            errors: vec![],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::StorageSyncResponse(sync_resp)),
        };
        let envelope_bytes = envelope.encode_to_vec();

        // Without v3 frame prefix
        let result = decode_sync_response(&envelope_bytes);
        assert!(result.is_some());
        let (processed, pulled) = result.unwrap();
        assert_eq!(processed, 3);
        assert_eq!(pulled, 7);
    }

    #[test]
    fn decode_valid_envelope_with_v3_frame_prefix() {
        let sync_resp = generated::StorageSyncResponse {
            success: true,
            pulled: 10,
            processed: 5,
            pushed: 2,
            errors: vec![],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::StorageSyncResponse(sync_resp)),
        };
        let envelope_bytes = envelope.encode_to_vec();

        // With 0x03 frame prefix
        let mut framed = vec![0x03];
        framed.extend_from_slice(&envelope_bytes);

        let result = decode_sync_response(&framed);
        assert!(result.is_some());
        let (processed, pulled) = result.unwrap();
        assert_eq!(processed, 5);
        assert_eq!(pulled, 10);
    }

    #[test]
    fn decode_envelope_without_sync_payload_returns_none() {
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: None,
        };
        let data = envelope.encode_to_vec();
        assert!(decode_sync_response(&data).is_none());
    }

    #[test]
    fn decode_envelope_with_different_payload_returns_none() {
        let app_state_resp = generated::AppStateResponse {
            key: "test".to_string(),
            value: Some("val".to_string()),
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::AppStateResponse(
                app_state_resp,
            )),
        };
        let data = envelope.encode_to_vec();
        assert!(decode_sync_response(&data).is_none());
    }

    #[test]
    fn decode_sync_response_zero_counts() {
        let sync_resp = generated::StorageSyncResponse {
            success: true,
            pulled: 0,
            processed: 0,
            pushed: 0,
            errors: vec![],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::StorageSyncResponse(sync_resp)),
        };
        let data = envelope.encode_to_vec();
        let result = decode_sync_response(&data).unwrap();
        assert_eq!(result, (0, 0));
    }

    // ── Poller state flags ──

    #[test]
    fn stop_poller_sets_flag() {
        POLLER_STOP.store(false, Ordering::SeqCst);
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        stop_poller();
        assert!(POLLER_STOP.load(Ordering::SeqCst));
    }

    // ── resume_poller when not running calls start_poller ──

    #[test]
    fn resume_when_running_does_not_restart() {
        POLLER_RUNNING.store(true, Ordering::SeqCst);
        POLLER_STOP.store(false, Ordering::SeqCst);
        resume_poller();
        assert!(POLLER_RUNNING.load(Ordering::SeqCst));
        // Reset for other tests
        POLLER_RUNNING.store(false, Ordering::SeqCst);
    }

    // ── decode_sync_response: additional edge cases ──

    #[test]
    fn decode_single_byte_zero_returns_none() {
        assert!(decode_sync_response(&[0x00]).is_none());
    }

    #[test]
    fn decode_single_byte_v3_prefix_returns_none() {
        assert!(decode_sync_response(&[0x03]).is_none());
    }

    #[test]
    fn decode_v3_prefix_with_garbage_returns_none() {
        let data = vec![0x03, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(decode_sync_response(&data).is_none());
    }

    #[test]
    fn decode_valid_response_large_counts() {
        let sync_resp = generated::StorageSyncResponse {
            success: true,
            pulled: u32::MAX,
            processed: u32::MAX - 1,
            pushed: 100,
            errors: vec!["err1".to_string()],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::StorageSyncResponse(sync_resp)),
        };
        let data = envelope.encode_to_vec();
        let (processed, pulled) = decode_sync_response(&data).unwrap();
        assert_eq!(processed, u32::MAX - 1);
        assert_eq!(pulled, u32::MAX);
    }

    #[test]
    fn decode_ignores_success_flag() {
        let sync_resp = generated::StorageSyncResponse {
            success: false,
            pulled: 1,
            processed: 2,
            pushed: 0,
            errors: vec![],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![],
            payload: Some(generated::envelope::Payload::StorageSyncResponse(sync_resp)),
        };
        let data = envelope.encode_to_vec();
        let result = decode_sync_response(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), (2, 1));
    }

    // ── Constants: relationships ──

    #[test]
    fn eager_total_time_less_than_default_interval() {
        let total_eager_ms = EAGER_POLL_INTERVAL_MS * (EAGER_POLL_CYCLES as u64);
        assert!(
            total_eager_ms < DEFAULT_POLL_INTERVAL_MS * 2,
            "eager burst should not be excessively long"
        );
    }

    // ── Poller flags: independent checks ──

    #[test]
    fn poller_stop_flag_initially_false() {
        POLLER_STOP.store(false, Ordering::SeqCst);
        assert!(!POLLER_STOP.load(Ordering::SeqCst));
    }

    #[test]
    fn poller_running_flag_initially_false() {
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        assert!(!POLLER_RUNNING.load(Ordering::SeqCst));
    }

    #[test]
    fn stop_then_stop_is_idempotent() {
        POLLER_STOP.store(false, Ordering::SeqCst);
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        stop_poller();
        stop_poller();
        assert!(POLLER_STOP.load(Ordering::SeqCst));
    }

    // ── push_inbox_event_to_webview is no-op on non-android ──

    #[test]
    fn push_inbox_event_noop_on_test_platform() {
        // Should not panic on non-Android
        push_inbox_event_to_webview(5, 3);
    }
}
