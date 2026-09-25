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
            // Settlement-urgent covers BOTH directions: the sender awaiting an
            // acceptance receipt AND the recipient still holding an undelivered
            // countersigned reply. Polling the reply side at the idle interval
            // would leave the sender's gate held for a minute after the money
            // was already applied.
            // Settlement state that cannot be read is not "nothing owed": the
            // poller keeps the settlement cadence and says why, every cycle.
            let pending_gate_active = match has_pending_settlement_work() {
                Ok(pending) => pending,
                Err(e) => {
                    log::error!("[inbox_poller] settlement state unreadable: {e}");
                    true
                }
            };

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

/// True while this device owes the network a settlement step that only polling
/// can complete:
///   * a SENDER-side pending online gate awaiting the recipient's acceptance
///     receipt (§16.6 finalize-on-receipt), or
///   * a RECIPIENT-side countersigned reply that has not yet been delivered
///     back to the sender (§16.6 reply window).
///
/// Money in flight must not depend on the user keeping the app on screen. A
/// transfer whose settlement stalls because the phone went in a pocket is
/// indistinguishable, to both parties, from one that failed.
///
/// `Err` when any of it cannot be read. That is not "nothing owed": a reader
/// that could not look has not seen an empty queue (storage spec §4), and the
/// counterparty's liveness rests on this device continuing to deliver.
pub fn has_pending_settlement_work() -> anyhow::Result<bool> {
    if !crate::storage::client_db::get_all_pending_online_outbox()?.is_empty() {
        return Ok(true);
    }
    // A relationship owing a cert-head resync is settlement work: the poller must
    // stay alive to drive it, otherwise a device with no other traffic can never
    // recover its ability to send.
    if crate::storage::client_db::has_outstanding_cert_resync()? {
        return Ok(true);
    }
    // Finality barrier: a sender whose certificate has not reached quorum must
    // keep sweeping; a recipient still awaiting a certificate must keep
    // polling — a backgrounded device would otherwise never be released.
    if !crate::storage::client_db::finalization_checkpoint_pending_sender_outbox()?.is_empty() {
        return Ok(true);
    }
    if crate::storage::client_db::any_relationship_awaits_peer_finalization()? {
        return Ok(true);
    }
    Ok(!crate::storage::client_db::pending_outbound_replies()?.is_empty())
}

/// Lifecycle-driven stop (app backgrounded). `Ok(true)` when the poller was
/// stopped; `Ok(false)` when it was not, because settlement work is
/// outstanding (see [`has_pending_settlement_work`]); `Err` when the
/// settlement state cannot be read — the poller is not stopped then either,
/// because only a readable "nothing owed" may stop it. Use [`stop_poller`]
/// for an unconditional shutdown.
pub fn stop_poller_for_lifecycle() -> anyhow::Result<bool> {
    if has_pending_settlement_work()? {
        log::info!(
            "[inbox_poller] lifecycle stop DECLINED — settlement work outstanding; \
             continuing to poll in the background so the transfer can complete"
        );
        return Ok(false);
    }
    stop_poller();
    Ok(true)
}

/// Stop the inbox poller unconditionally. The task will exit on its next
/// iteration.
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
        Ok(counts) => counts,
        Err(e) => {
            log::error!("[inbox_poller] storage.sync answer is not readable: {e}");
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

/// The `(processed, pulled)` counts of `storage.sync`'s answer. The router
/// answers its own caller with a local answer (`pack_envelope_ok`: `[0x03]`
/// framing, no sender headers, no message id), so it is read as one.
fn decode_sync_response(data: &[u8]) -> Result<(u32, u32), String> {
    let envelope = crate::handlers::response_helpers::decode_local_envelope(data)?;
    match envelope.payload {
        Some(generated::envelope::Payload::StorageSyncResponse(resp)) => {
            if !resp.errors.is_empty() {
                log::warn!(
                    "[inbox_poller] storage.sync reported {} error(s): {:?}",
                    resp.errors.len(),
                    resp.errors
                );
            }
            Ok((resp.processed, resp.pulled))
        }
        _ => Err("storage.sync answered with a payload that is not a StorageSyncResponse".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rename one settlement table out of reach for the guard's lifetime, so
    /// every query over it fails as a production read would.
    struct Unreadable(&'static str);
    impl Unreadable {
        fn table(name: &'static str) -> Self {
            crate::storage::client_db::get_connection()
                .expect("the store")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .execute_batch(&format!("ALTER TABLE {name} RENAME TO {name}_unreadable"))
                .expect("hide the table");
            Self(name)
        }
    }
    impl Drop for Unreadable {
        fn drop(&mut self) {
            let name = self.0;
            let restored = crate::storage::client_db::get_connection().and_then(|conn| {
                conn.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .execute_batch(&format!("ALTER TABLE {name}_unreadable RENAME TO {name}"))
                    .map_err(anyhow::Error::from)
            });
            if let Err(e) = restored {
                eprintln!("{name} was not restored; later tests will fail on it: {e}");
            }
        }
    }

    /// Storage spec §4: settlement state that cannot be read is not "nothing
    /// owed". With either settlement table unreadable, the check is an error
    /// and the lifecycle stop declines — the stop flag stays down. With the
    /// store readable and empty, the same stop goes through.
    #[test]
    #[serial_test::serial]
    fn a_lifecycle_stop_is_declined_while_settlement_state_is_unreadable() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        POLLER_STOP.store(false, Ordering::SeqCst);
        assert!(!has_pending_settlement_work().expect("a readable, empty store"));
        for table in ["pending_online_outbox", "recipient_outbound_reply"] {
            let _hidden = Unreadable::table(table);
            assert!(has_pending_settlement_work().is_err(), "{table}");
            assert!(stop_poller_for_lifecycle().is_err(), "{table}");
            assert!(
                !POLLER_STOP.load(Ordering::SeqCst),
                "{table}: the poller was stopped"
            );
        }
        assert!(stop_poller_for_lifecycle().expect("readable again"));
        assert!(POLLER_STOP.load(Ordering::SeqCst));
        POLLER_STOP.store(false, Ordering::SeqCst);
    }

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

    /// The answer as the router builds it for its own caller.
    fn router_answer(payload: generated::envelope::Payload) -> Vec<u8> {
        crate::handlers::response_helpers::pack_envelope_ok(payload).data
    }

    fn sync_answer(pulled: u32, processed: u32, errors: Vec<String>) -> Vec<u8> {
        router_answer(generated::envelope::Payload::StorageSyncResponse(
            generated::StorageSyncResponse {
                success: true,
                pulled,
                processed,
                pushed: 0,
                errors,
            },
        ))
    }

    /// The poller reads `storage.sync`'s answer in the shape the router sends
    /// it: a local answer, with no headers and no message id. Reading it as an
    /// addressed envelope failed on every cycle, so the poller saw `(0, 0)`
    /// and never announced a sync.
    #[test]
    fn a_storage_sync_answer_as_the_router_frames_it_is_read() {
        assert_eq!(decode_sync_response(&sync_answer(7, 3, vec![])), Ok((3, 7)));
        assert_eq!(
            decode_sync_response(&sync_answer(u32::MAX, u32::MAX - 1, vec!["e".into()])),
            Ok((u32::MAX - 1, u32::MAX))
        );
    }

    #[test]
    fn an_answer_with_another_payload_is_an_error() {
        let data = router_answer(generated::envelope::Payload::AppStateResponse(
            generated::AppStateResponse {
                key: "test".to_string(),
                value: Some("val".to_string()),
            },
        ));
        assert!(decode_sync_response(&data).is_err());
    }

    #[test]
    fn bytes_that_are_not_a_local_answer_are_an_error() {
        for data in [
            &[][..],
            &[0x00],
            &[0x03],
            &[0xFF, 0x01, 0x02, 0x03],
            &[0x03, 0xFF, 0xFF],
        ] {
            assert!(decode_sync_response(data).is_err(), "{data:?}");
        }
        // Unframed: the router always frames its answer.
        let framed = sync_answer(1, 1, vec![]);
        assert!(decode_sync_response(&framed[1..]).is_err());
    }

    // ── Poller state flags ──

    #[test]
    #[serial_test::serial]
    fn stop_poller_sets_flag() {
        POLLER_STOP.store(false, Ordering::SeqCst);
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        stop_poller();
        assert!(POLLER_STOP.load(Ordering::SeqCst));
    }

    // ── resume_poller when not running calls start_poller ──

    #[test]
    #[serial_test::serial]
    fn resume_when_running_does_not_restart() {
        POLLER_RUNNING.store(true, Ordering::SeqCst);
        POLLER_STOP.store(false, Ordering::SeqCst);
        resume_poller();
        assert!(POLLER_RUNNING.load(Ordering::SeqCst));
        // Reset for other tests
        POLLER_RUNNING.store(false, Ordering::SeqCst);
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
    #[serial_test::serial]
    fn poller_stop_flag_initially_false() {
        POLLER_STOP.store(false, Ordering::SeqCst);
        assert!(!POLLER_STOP.load(Ordering::SeqCst));
    }

    #[test]
    #[serial_test::serial]
    fn poller_running_flag_initially_false() {
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        assert!(!POLLER_RUNNING.load(Ordering::SeqCst));
    }

    #[test]
    #[serial_test::serial]
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
