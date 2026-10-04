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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

use dsm::types::proto as generated;

/// Default poll interval (ticks between sync attempts).
const DEFAULT_POLL_INTERVAL_MS: u64 = 60_000;

/// Eager poll interval used temporarily after items are found,
/// so follow-up messages (e.g. ACKs or rapid exchanges) are picked up faster.
const EAGER_POLL_INTERVAL_MS: u64 = 8_000;

/// Poll interval while settlement work is outstanding (see
/// [`has_pending_settlement_work`]): a sender awaiting the acceptance, a
/// recipient owing its reply or awaiting the sender's certificate, a
/// certificate not yet at quorum.
///
/// A transfer settles in three syncs — the recipient takes it and replies,
/// the sender finalizes and posts its certificate, the recipient takes the
/// certificate — and each side waits this long at most for the other's step.
/// At 5 s a two-phone round trip took up to half a minute after the money had
/// already moved, with both phones open.
const PENDING_GATE_POLL_INTERVAL_MS: u64 = 2_000;

/// Poll interval while the app is on screen and nothing is settling: an
/// incoming transfer shows within this, instead of within the idle minute.
const FOREGROUND_POLL_INTERVAL_MS: u64 = 5_000;

/// Number of consecutive eager-interval polls before reverting to default.
const EAGER_POLL_CYCLES: u32 = 5;

/// Poll interval while settlement work is outstanding and the inbox waiter's
/// waits cover the fleet ([`crate::sdk::inbox_waiter::covers_fleet`]): a
/// reply or a certificate wakes a sync the moment it lands, and this poll
/// only retries what an arrival does not drive — a release object not yet
/// fetchable, a delivery that failed.
const COVERED_SETTLEMENT_POLL_INTERVAL_MS: u64 = 5_000;

/// Poll interval while the app is on screen, nothing is settling, and the
/// waits cover the fleet: a safety net only, an arrival wakes a sync at once.
const COVERED_FOREGROUND_POLL_INTERVAL_MS: u64 = 30_000;

/// Poller cycles completed in this process, and the signal each one gives.
static CYCLES_COMPLETED: AtomicU64 = AtomicU64::new(0);
static CYCLE_DONE: once_cell::sync::Lazy<Notify> = once_cell::sync::Lazy::new(Notify::new);

/// Global poller state.
static POLLER_RUNNING: AtomicBool = AtomicBool::new(false);
static POLLER_STOP: AtomicBool = AtomicBool::new(false);

/// Shared notify for immediate wake-up (app foreground, bilateral commit).
static POLLER_WAKE: once_cell::sync::Lazy<Arc<Notify>> =
    once_cell::sync::Lazy::new(|| Arc::new(Notify::new()));

/// Holds the two-device test harness has on the background poller (see
/// [`hold_off_for_two_device_harness`]).
#[cfg(test)]
static POLLER_HOLDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A start the harness's hold deferred, or a poller the hold stopped: the
/// poller starts again when the last hold is released.
#[cfg(test)]
static POLLER_START_DEFERRED: AtomicBool = AtomicBool::new(false);

/// Signalled after every poller cycle, for tests that wait on one.
#[cfg(test)]
pub(crate) static POLLER_CYCLE_DONE: once_cell::sync::Lazy<Notify> =
    once_cell::sync::Lazy::new(Notify::new);

/// The two-device test harness stands in for two devices' processes in one
/// and drives each device's `storage.sync` itself. A background poller in that
/// process syncs whichever device the harness has entered, at times of its
/// own: a second actor the harness's serialization excludes, and one that
/// races every assertion about a state a sync moves on from. The harness
/// holds it off for a pair's life: a running poller is stopped and waited out
/// before the pair is set up, a start while the hold stands is deferred, and
/// the poller starts again once the hold is dropped — on teardown, a failing
/// test's included.
#[cfg(test)]
#[must_use]
pub(crate) struct PollerHold(());

#[cfg(test)]
pub(crate) async fn hold_off_for_two_device_harness() -> PollerHold {
    POLLER_HOLDS.fetch_add(1, Ordering::SeqCst);
    if POLLER_RUNNING.load(Ordering::SeqCst) {
        POLLER_START_DEFERRED.store(true, Ordering::SeqCst);
    }
    stop_poller();
    while POLLER_RUNNING.load(Ordering::SeqCst) {
        POLLER_WAKE.notify_one();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    PollerHold(())
}

/// Whether the two-device harness holds the background tasks off: the
/// connect listener defers to the same hold as the poller.
#[cfg(test)]
pub(crate) fn background_held() -> bool {
    POLLER_HOLDS.load(Ordering::SeqCst) > 0
}

#[cfg(test)]
impl Drop for PollerHold {
    fn drop(&mut self) {
        if POLLER_HOLDS.fetch_sub(1, Ordering::SeqCst) == 1
            && POLLER_START_DEFERRED.swap(false, Ordering::SeqCst)
        {
            start_poller();
        }
    }
}

/// Whether the background poller task is running.
#[cfg(test)]
pub(crate) fn poller_running() -> bool {
    POLLER_RUNNING.load(Ordering::SeqCst)
}

/// Whether a start is deferred until the harness's hold is released.
#[cfg(test)]
pub(crate) fn poller_start_deferred() -> bool {
    POLLER_START_DEFERRED.load(Ordering::SeqCst)
}

/// Held by the poller task for as long as it runs, and clears the running
/// flag when it ends, however it ends. A sync cycle that panics unwinds
/// through it, so a later start is not refused as "already running" by a
/// poller that no longer runs.
struct RunningFlag;

impl Drop for RunningFlag {
    fn drop(&mut self) {
        POLLER_RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Start the inbox poller background task on the SDK runtime.
///
/// Idempotent: if already running, returns immediately.
pub fn start_poller() {
    #[cfg(test)]
    if POLLER_HOLDS.load(Ordering::SeqCst) > 0 {
        POLLER_START_DEFERRED.store(true, Ordering::SeqCst);
        return;
    }
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
        let _running = RunningFlag;
        log::info!("[inbox_poller] Background poller started");

        // Initial delay before first poll (let bootstrap settle).
        tokio::time::sleep(std::time::Duration::from_millis(5_000)).await;

        let mut eager_remaining: u32 = 0;

        loop {
            if POLLER_STOP.load(Ordering::SeqCst) {
                break;
            }

            let (processed, pulled, more_pending) = run_inbox_sync_cycle_counted("poll").await;
            CYCLES_COMPLETED.fetch_add(1, Ordering::SeqCst);
            CYCLE_DONE.notify_waiters();
            #[cfg(test)]
            POLLER_CYCLE_DONE.notify_waiters();
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

            if enters_eager_mode(processed, pulled, more_pending) {
                eager_remaining = EAGER_POLL_CYCLES;
                log::info!(
                    "[inbox_poller] Entering eager mode ({} cycles at {}ms)",
                    EAGER_POLL_CYCLES,
                    EAGER_POLL_INTERVAL_MS
                );
            } else {
                eager_remaining = eager_remaining.saturating_sub(1);
            }

            let activity = if pending_gate_active {
                Activity::Settling
            } else if crate::sdk::session_manager::app_in_foreground() {
                Activity::OnScreen
            } else if eager_remaining > 0 {
                Activity::Eager
            } else {
                Activity::Idle
            };
            let waits = if crate::sdk::inbox_waiter::covers_fleet() {
                Waits::CoverFleet
            } else {
                Waits::DoNotCover
            };
            let interval_ms = poll_interval_ms(activity, waits);

            // Wait for either the poll interval or a wake-up signal.
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(interval_ms)) => {},
                _ = wake.notified() => {
                    log::info!("[inbox_poller] Woken up early (foreground/bilateral)");
                },
            }
        }

        log::info!("[inbox_poller] Background poller stopped");
    });
    crate::sdk::inbox_waiter::start();
}

/// What the device is doing, as the poller's cadence reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Activity {
    /// Settlement work is outstanding ([`has_pending_settlement_work`]).
    Settling,
    /// The app is on screen and nothing is settling.
    OnScreen,
    /// A recent cycle took something: follow-ups come soon.
    Eager,
    /// None of these.
    Idle,
}

/// Whether the inbox waiter's waits cover the fleet
/// ([`crate::sdk::inbox_waiter::covers_fleet`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waits {
    CoverFleet,
    DoNotCover,
}

/// The time to the next poll: the settlement cadence while a transfer is
/// settling, the on-screen cadence while the app is shown, the eager one
/// after an exchange, else the idle minute. While the waits cover the fleet
/// an arrival wakes a sync at once, so the settlement and on-screen cadences
/// slow to a safety net.
pub(crate) fn poll_interval_ms(activity: Activity, waits: Waits) -> u64 {
    match (activity, waits) {
        (Activity::Settling, Waits::CoverFleet) => COVERED_SETTLEMENT_POLL_INTERVAL_MS,
        (Activity::Settling, Waits::DoNotCover) => PENDING_GATE_POLL_INTERVAL_MS,
        (Activity::OnScreen, Waits::CoverFleet) => COVERED_FOREGROUND_POLL_INTERVAL_MS,
        (Activity::OnScreen, Waits::DoNotCover) => FOREGROUND_POLL_INTERVAL_MS,
        (Activity::Eager, _) => EAGER_POLL_INTERVAL_MS,
        (Activity::Idle, _) => DEFAULT_POLL_INTERVAL_MS,
    }
}

/// Poller cycles completed in this process.
pub(crate) fn cycles_completed() -> u64 {
    CYCLES_COMPLETED.load(Ordering::SeqCst)
}

/// Resolves when the next poller cycle completes.
pub(crate) fn cycle_done() -> tokio::sync::futures::Notified<'static> {
    CYCLE_DONE.notified()
}

/// Whether the poller has been told to stop.
pub(crate) fn poller_stopping() -> bool {
    POLLER_STOP.load(Ordering::SeqCst)
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

/// What the poller does when the app leaves the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backgrounded {
    /// Settlement work is outstanding ([`has_pending_settlement_work`]): the
    /// poller keeps going so the transfer completes.
    Settling,
    /// This device has contacts, and any of them can send to it at any time:
    /// the poller and its waits keep going, so what they send lands without
    /// the recipient opening the app. Nothing tells a device a transfer is
    /// coming; listening is the only way it arrives on its own.
    Listening,
    /// Nothing owed and nobody to hear from: the poller was stopped.
    Stopped,
}

/// Lifecycle-driven stop (app backgrounded): the poller stops only when
/// nothing is settling and no contact can send to this device. `Err` when
/// either cannot be read — the poller is not stopped then, because only a
/// readable "nothing owed, nobody to hear from" may stop it. Use
/// [`stop_poller`] for an unconditional shutdown.
pub fn stop_poller_for_lifecycle() -> anyhow::Result<Backgrounded> {
    if has_pending_settlement_work()? {
        log::info!(
            "[inbox_poller] lifecycle stop DECLINED — settlement work outstanding; \
             continuing to poll in the background so the transfer can complete"
        );
        return Ok(Backgrounded::Settling);
    }
    let contacts = crate::storage::client_db::count_contacts()?;
    if contacts > 0 {
        log::info!(
            "[inbox_poller] lifecycle stop DECLINED — {contacts} contact(s) can send to this \
             device; listening in the background"
        );
        return Ok(Backgrounded::Listening);
    }
    stop_poller();
    Ok(Backgrounded::Stopped)
}

/// Stop the inbox poller unconditionally. The task will exit on its next
/// iteration.
pub fn stop_poller() {
    POLLER_STOP.store(true, Ordering::SeqCst);
    POLLER_WAKE.notify_one();
    crate::sdk::inbox_waiter::wake_to_stop();
}

/// Wake the poller immediately (e.g. app foreground, bilateral commit).
pub fn resume_poller() {
    if POLLER_RUNNING.load(Ordering::SeqCst) {
        POLLER_WAKE.notify_one();
        crate::sdk::inbox_waiter::start();
    } else {
        // If poller isn't running, start it.
        start_poller();
    }
}

/// Whether a cycle sends the poller into eager mode. It processed something,
/// so follow-up messages (ACKs, rapid exchanges) are found faster; or a route
/// holds more than the sync took and the sync took entries, so a backlog
/// drains soon (pre-audit item 11). A route still pending when nothing was
/// taken (a read that went over copies already passed over, behind one that
/// waits) is left to the normal cadence: junk cannot hold the poller at the
/// eager rate.
pub(crate) fn enters_eager_mode(processed: u32, pulled: u32, routes_pending: usize) -> bool {
    processed > 0 || (routes_pending > 0 && pulled > 0)
}

/// The `storage.sync` request every poll makes: pull the inbox, push what is
/// owed, at most 50 entries from each route.
pub(crate) fn poll_sync_request() -> generated::StorageSyncRequest {
    generated::StorageSyncRequest {
        pull_inbox: true,
        push_pending: true,
        limit: 50,
    }
}

/// Run one sync cycle: call `storage.sync` through the app router,
/// then push `inbox.updated` to the WebView if items were processed.
/// Returns the processed and pulled counts and how many routes are
/// `more_pending`, for adaptive polling.
async fn run_inbox_sync_cycle_counted(source: &str) -> (u32, u32, usize) {
    let router = match crate::bridge::app_router() {
        Some(r) => r,
        None => {
            log::debug!("[inbox_poller] AppRouter not installed yet, skipping cycle");
            return (0, 0, 0);
        }
    };

    let sync_req = poll_sync_request();
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
        return (0, 0, 0);
    }

    // Decode the Envelope response to get StorageSyncResponse.
    let (processed, pulled, more_pending) = match decode_sync_response(&result.data) {
        Ok(counts) => counts,
        Err(e) => {
            log::error!("[inbox_poller] storage.sync answer is not readable: {e}");
            return (0, 0, 0);
        }
    };

    log::info!(
        "[inbox_poller] sync cycle complete: pulled={pulled}, processed={processed}, \
         more_pending={}, source={source}",
        more_pending.len()
    );

    let routes_pending = more_pending.len();
    // Push `inbox.updated` event to WebView via the canonical reverse-spine.
    push_inbox_event_to_webview(pulled, processed, more_pending);

    (processed, pulled, routes_pending)
}

/// Push inbox.updated + optional wallet refresh to WebView.
#[cfg(all(target_os = "android", feature = "jni"))]
fn push_inbox_event_to_webview(pulled: u32, processed: u32, more_pending: Vec<String>) {
    let event_payload = generated::StorageSyncResponse {
        success: true,
        pulled,
        processed,
        pushed: 0,
        errors: vec![],
        more_pending,
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
fn push_inbox_event_to_webview(_pulled: u32, _processed: u32, _more_pending: Vec<String>) {
    // No-op on non-Android / non-JNI builds.
}

/// The `(processed, pulled)` counts of `storage.sync`'s answer. The router
/// answers its own caller with a local answer (`pack_envelope_ok`: `[0x03]`
/// framing, no sender headers, no message id), so it is read as one.
fn decode_sync_response(data: &[u8]) -> Result<(u32, u32, Vec<String>), String> {
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
            Ok((resp.processed, resp.pulled, resp.more_pending))
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
        assert_eq!(
            stop_poller_for_lifecycle().expect("readable again"),
            Backgrounded::Stopped
        );
        assert!(POLLER_STOP.load(Ordering::SeqCst));
        POLLER_STOP.store(false, Ordering::SeqCst);
    }

    /// Nothing tells a device a transfer is on its way. A device with a
    /// contact keeps listening when the app leaves the screen, so what the
    /// contact sends lands without the recipient opening the app; the stop
    /// flag stays down. Without a contact there is nobody to hear from.
    #[test]
    #[serial_test::serial]
    fn a_device_with_contacts_keeps_listening_in_the_background() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        let stopping_before = POLLER_STOP.load(Ordering::SeqCst);
        crate::storage::client_db::store_contact_record_for_tests([0x5E; 32], "listener");
        assert_eq!(
            stop_poller_for_lifecycle().expect("a readable store"),
            Backgrounded::Listening
        );
        assert_eq!(
            POLLER_STOP.load(Ordering::SeqCst),
            stopping_before,
            "the poller was told to stop"
        );
        assert_eq!(
            crate::storage::client_db::count_contacts().expect("count"),
            1
        );
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
                more_pending: Vec::new(),
            },
        ))
    }

    /// The poller reads `storage.sync`'s answer in the shape the router sends
    /// it: a local answer, with no headers and no message id. Reading it as an
    /// addressed envelope failed on every cycle, so the poller saw `(0, 0)`
    /// and never announced a sync.
    #[test]
    fn a_storage_sync_answer_as_the_router_frames_it_is_read() {
        assert_eq!(
            decode_sync_response(&sync_answer(7, 3, vec![])),
            Ok((3, 7, Vec::new()))
        );
        assert_eq!(
            decode_sync_response(&sync_answer(u32::MAX, u32::MAX - 1, vec!["e".into()])),
            Ok((u32::MAX - 1, u32::MAX, Vec::new()))
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

    /// A test that fails while it holds the poller off still releases the
    /// hold as it unwinds, and a start deferred under it runs then.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_hold_is_released_when_its_test_fails() {
        stop_poller();
        POLLER_RUNNING.store(false, Ordering::SeqCst);
        POLLER_START_DEFERRED.store(false, Ordering::SeqCst);
        let hold = hold_off_for_two_device_harness().await;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _hold = hold;
            start_poller();
            assert!(!poller_running() && poller_start_deferred());
            panic!("the test fails while it holds the poller off");
        }));
        assert!(failed.is_err());
        assert!(
            poller_running() && !poller_start_deferred(),
            "the hold was not released as the failing test unwound"
        );
        stop_poller();
    }

    /// A poller task that ends by panicking clears the running flag as it
    /// unwinds: the flag says a poller runs only while one does.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_poller_that_panics_is_no_longer_running() {
        // The real start marks a poller running; its task is stopped before
        // it polls anything.
        start_poller();
        stop_poller();
        assert!(poller_running(), "the poller was started");
        let ended = tokio::spawn(async {
            let _running = RunningFlag;
            panic!("a sync cycle panics");
        })
        .await;
        assert!(ended.unwrap_err().is_panic());
        assert!(
            !poller_running(),
            "a poller that panicked is still reported running, so it can never start again"
        );
    }

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

    /// While a transfer settles the poller checks every 2 s, and every 5 s
    /// while the app is on screen; with the waits covering the fleet an
    /// arrival syncs at once, so those slow to 5 s and 30 s. An eager burst
    /// and the idle minute are the same either way.
    #[test]
    fn the_waits_covering_the_fleet_slow_the_settling_and_on_screen_polls() {
        use Activity::{Eager, Idle, OnScreen, Settling};
        use Waits::{CoverFleet, DoNotCover};
        assert_eq!(poll_interval_ms(Settling, DoNotCover), 2_000);
        assert_eq!(poll_interval_ms(Settling, CoverFleet), 5_000);
        assert_eq!(poll_interval_ms(OnScreen, DoNotCover), 5_000);
        assert_eq!(poll_interval_ms(OnScreen, CoverFleet), 30_000);
        assert_eq!(poll_interval_ms(Eager, DoNotCover), 8_000);
        assert_eq!(poll_interval_ms(Eager, CoverFleet), 8_000);
        assert_eq!(poll_interval_ms(Idle, DoNotCover), 60_000);
        assert_eq!(poll_interval_ms(Idle, CoverFleet), 60_000);
    }

    #[test]
    fn a_pending_route_hurries_the_poller_only_while_entries_are_taken() {
        assert!(enters_eager_mode(1, 0, 0), "something processed");
        assert!(enters_eager_mode(0, 3, 1), "a backlog being taken");
        assert!(
            !enters_eager_mode(0, 0, 1),
            "a pending route from which nothing was taken"
        );
        assert!(!enters_eager_mode(0, 3, 0), "junk taken, nothing left");
    }

    #[test]
    fn push_inbox_event_noop_on_test_platform() {
        // Should not panic on non-Android
        push_inbox_event_to_webview(5, 3, Vec::new());
    }
}
