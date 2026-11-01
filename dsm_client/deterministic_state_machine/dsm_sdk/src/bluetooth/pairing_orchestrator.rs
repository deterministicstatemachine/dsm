// SPDX-License-Identifier: MIT OR Apache-2.0

//! # BLE Pairing Orchestrator
//!
//! Takes a contact's device id, starts the radio's scan or advertising for it,
//! and completes pairing when the link handshake (DSM Amendment A27,
//! `bluetooth::link_session`) pairs a link with that contact: the contact's
//! address is stored only then. Transport policy: wall-clock time is allowed
//! here for disconnect recovery, retry windows and wake-up timeouts. Those
//! timers never participate in chain ordering, receipt commits or acceptance
//! predicates.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{Notify, RwLock};

/// Pairing session state for a specific contact.
///
/// The link handshake is the pairing (DSM Amendment A27): each side proves it
/// holds the session keys its pinned ML-KEM keys give, and takes the other's
/// last handshake message, before it stores the contact's address. Neither
/// side stores it earlier, and a link that drops before then leaves the
/// session to be paired on the next link.
#[derive(Debug, Clone, PartialEq)]
pub enum PairingState {
    /// Waiting for a BLE connection.
    WaitingForConnection,
    /// A link to the contact is up and its handshake is under way.
    Handshaking,
    /// The handshake paired the link and the contact's address is stored.
    Complete,
    /// Pairing failed; the next pass starts it again.
    Failed(String),
}

/// A pairing attempt still waiting for its first connection this long has
/// found nothing: its scan was refused or ended. It is started again then,
/// not after the handshake window.
const WAITING_FOR_CONNECTION_STALE_SECS: u64 = 20;

/// A handshake under way that has not moved for this long is cleared and
/// started again.
const HANDSHAKE_STALE_SECS: u64 = 90;

/// How long the pairing loop waits for a state change before looking at its
/// sessions again, so an attempt that went stale without an event is still
/// restarted promptly.
const PAIRING_LOOP_WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// After a scan the radio refused, how long before the attempt is retried:
/// past the coordinator's 6 s gap between scans (`BleCoordinator.MIN_SCAN_GAP_MS`).
#[cfg(any(all(target_os = "android", feature = "jni"), test))]
const DISCOVERY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(7);

/// How many seconds a session may sit in `state` before the pairing loop
/// clears it and starts again; `None` for a state the loop never clears by
/// age (finished, or already failed and retried on the next pass).
pub(crate) fn stale_after_secs(state: &PairingState) -> Option<u64> {
    match state {
        PairingState::Complete | PairingState::Failed(_) => None,
        PairingState::WaitingForConnection => Some(WAITING_FOR_CONNECTION_STALE_SECS),
        PairingState::Handshaking => Some(HANDSHAKE_STALE_SECS),
    }
}

/// Active pairing session for a contact
#[derive(Debug, Clone)]
pub struct PairingSession {
    pub contact_device_id: [u8; 32],
    pub state: PairingState,
    pub ble_address: Option<String>,
    /// Wall-clock timestamp of the last state transition.
    ///
    /// This is transport-runtime state only: used for BLE session staleness,
    /// handshake timeout windows, and retry scheduling. It never enters protocol
    /// commitments or acceptance logic.
    pub last_activity: Instant,
}

/// Orchestrates BLE pairing for contacts
pub struct PairingOrchestrator {
    /// Active pairing sessions by contact device_id
    sessions: Arc<RwLock<HashMap<[u8; 32], PairingSession>>>,
    /// Stop flag for the pairing loop — set by stop_pairing_loop()
    loop_stop: Arc<AtomicBool>,
    /// Whether the loop is currently running
    loop_running: Arc<AtomicBool>,
    /// Event-driven wake-up for pairing state changes.
    state_change: Arc<Notify>,
}

impl PairingOrchestrator {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            loop_stop: Arc::new(AtomicBool::new(false)),
            loop_running: Arc::new(AtomicBool::new(false)),
            state_change: Arc::new(Notify::new()),
        }
    }

    fn signal_state_change(&self) {
        self.state_change.notify_waiters();
    }

    /// Initiate pairing for a specific contact
    ///
    /// Frontend may call this, but pairing can also start implicitly when identity is observed.
    /// We do not gate on any prior online state; we simply spin up a session and begin discovery.
    ///
    /// Returns the deterministic role:
    /// - `Ok(true)` = should advertise (be peripheral)
    /// - `Ok(false)` = should scan (be central)
    /// - `Err(_)` = failed to initiate
    pub async fn initiate_pairing(&self, contact_device_id: [u8; 32]) -> Result<bool, String> {
        // Gate: verify contact exists in SQLite before proceeding with BLE pairing.
        // If the contact hasn't been persisted yet (e.g., QR scan still processing),
        // return an error which maps to role=0 (not ready) at the JNI layer.
        match crate::storage::client_db::has_contact_for_device_id(&contact_device_id) {
            Ok(true) => {
                log::info!(
                    "[PairingOrchestrator] Contact verified in SQLite for {:02x}{:02x}...",
                    contact_device_id[0],
                    contact_device_id[1]
                );
            }
            Ok(false) => {
                log::warn!(
                    "[PairingOrchestrator] No contact in SQLite for {:02x}{:02x}...; returning not-ready",
                    contact_device_id[0], contact_device_id[1]
                );
                return Err("Contact not yet persisted in SQLite".to_string());
            }
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] SQLite query failed for {:02x}{:02x}...: {}; returning not-ready",
                    contact_device_id[0], contact_device_id[1], e
                );
                return Err(format!("SQLite query error: {}", e));
            }
        }

        // Create pairing session (idempotent overwrite).
        // Cap active sessions to prevent unbounded JNI thread attachment.
        // BLE can only realistically sustain ~7 concurrent GATT connections;
        // 16 provides headroom without risking thread exhaustion.
        const MAX_PAIRING_SESSIONS: usize = 16;

        let session = PairingSession {
            contact_device_id,
            state: PairingState::WaitingForConnection,
            ble_address: None,
            last_activity: Instant::now(),
        };

        {
            let mut sessions = self.sessions.write().await;
            if !sessions.contains_key(&contact_device_id) && sessions.len() >= MAX_PAIRING_SESSIONS
            {
                return Err(format!(
                    "Max pairing sessions ({MAX_PAIRING_SESSIONS}) reached; retry after existing sessions complete"
                ));
            }
            sessions.insert(contact_device_id, session);
        }

        self.signal_state_change();

        // Get self device ID to determine role
        let self_device_id = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| "Self device ID not available".to_string())?;
        let self_device_id_array: [u8; 32] = self_device_id
            .try_into()
            .map_err(|_| "Self device ID is not 32 bytes".to_string())?;

        // Determine role: if self < contact, advertise (be peripheral); else scan (be central)
        let should_advertise = self_device_id_array < contact_device_id;

        log::info!(
            "[PairingOrchestrator] Initiated pairing for contact: {:02x}{:02x}{:02x}{:02x}... self={:02x}{:02x}... role={}",
            contact_device_id[0],
            contact_device_id[1],
            contact_device_id[2],
            contact_device_id[3],
            self_device_id_array[0],
            self_device_id_array[1],
            if should_advertise { "advertiser" } else { "scanner" }
        );

        // Fire-and-forget: also request BLE discovery start from Rust via JNI as a safety net.
        // This complements the Kotlin WebView bridge which also starts the role-specific op.
        // Duplicate starts are harmless due to idempotent guards in DsmBluetoothService
        // (they will log "already scanning/advertising").
        #[cfg(all(target_os = "android", feature = "jni"))]
        {
            let contact = contact_device_id;
            // Spawn without awaiting to avoid blocking the JNI caller path
            crate::runtime::get_runtime().spawn(async move {
                let orchestrator = crate::bluetooth::get_pairing_orchestrator();
                let started = orchestrator.start_ble_discovery(contact).await;
                orchestrator
                    .after_discovery_start(contact, started, DISCOVERY_RETRY_DELAY)
                    .await;
            });
        }

        // Return the role - Kotlin will start the appropriate BLE operation
        Ok(should_advertise)
    }

    /// What follows the radio's answer to looking for `contact`: nothing when
    /// it started; when it was refused, after `retry_after` (past the radio's
    /// gap between scans) the attempt waiting on it is freed for the next pass
    /// ([`Self::discovery_refused`]).
    #[cfg(any(all(target_os = "android", feature = "jni"), test))]
    pub(crate) async fn after_discovery_start(
        &self,
        contact: [u8; 32],
        started: Result<(), String>,
        retry_after: std::time::Duration,
    ) {
        match started {
            Ok(()) => log::info!(
                "[PairingOrchestrator] BLE discovery started for {:02x}{:02x}...",
                contact[0],
                contact[1]
            ),
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] BLE discovery for {:02x}{:02x}... was refused: {e}; \
                     retrying in {retry_after:?}",
                    contact[0],
                    contact[1]
                );
                tokio::time::sleep(retry_after).await;
                self.discovery_refused(contact).await;
            }
        }
    }

    /// The radio refused to look for `contact` (a scan refused by the
    /// platform's rate limit or the coordinator's gap between scans): an
    /// attempt still waiting for its first connection is marked failed and the
    /// loop woken, so the next pass starts it again instead of leaving it
    /// waiting on a scan that never ran. An attempt already past that is left
    /// alone.
    #[cfg(any(all(target_os = "android", feature = "jni"), test))]
    pub(crate) async fn discovery_refused(&self, contact: [u8; 32]) {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(&contact) else {
            return;
        };
        if session.state != PairingState::WaitingForConnection {
            return;
        }
        session.state = PairingState::Failed("the scan for the peer was refused".to_string());
        session.last_activity = Instant::now();
        drop(sessions);
        self.signal_state_change();
    }

    /// A link to `contact` came up at `ble_address`, and its handshake is
    /// under way (DSM Amendment A27). A session waiting for a connection, or
    /// failed, moves to `Handshaking`; any other is left as it is.
    pub async fn link_opened(&self, contact: [u8; 32], ble_address: &str) {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(&contact) else {
            return;
        };
        match session.state {
            PairingState::WaitingForConnection | PairingState::Failed(_) => {
                session.state = PairingState::Handshaking;
                session.ble_address = Some(ble_address.to_string());
                session.last_activity = Instant::now();
            }
            PairingState::Handshaking | PairingState::Complete => return,
        }
        drop(sessions);
        self.signal_state_change();
    }

    /// The link handshake paired this device with `peer` on the link at
    /// `ble_address` (DSM Amendment A27): each side proved it holds the
    /// session keys and took the other's last handshake message. The address
    /// is stored on the contact, and only then is pairing complete and
    /// reported; a store that fails leaves the session failed, to be paired
    /// on the next link.
    pub async fn link_paired(
        &self,
        paired: &dsm::crypto::ble_link::LinkIdentity,
        ble_address: &str,
    ) -> Result<(), String> {
        let peer = paired.device_id;
        let stored =
            crate::storage::client_db::update_contact_ble_status(&peer, None, Some(ble_address))
                .map_err(|e| format!("the paired address was not stored: {e}"));
        {
            let mut sessions = self.sessions.write().await;
            let session = sessions.entry(peer).or_insert_with(|| PairingSession {
                contact_device_id: peer,
                state: PairingState::WaitingForConnection,
                ble_address: None,
                last_activity: Instant::now(),
            });
            session.state = match &stored {
                Ok(()) => PairingState::Complete,
                Err(reason) => PairingState::Failed(reason.clone()),
            };
            session.ble_address = Some(ble_address.to_string());
            session.last_activity = Instant::now();
        }
        self.signal_state_change();
        match &stored {
            Ok(()) => {
                log::info!(
                    "[PairingOrchestrator] paired with {:02x}{:02x}... on {ble_address}",
                    peer[0],
                    peer[1]
                );
                #[cfg(all(target_os = "android", feature = "jni"))]
                {
                    // The frontend maps the contact to the link's address, as
                    // it did on an identity read, now from an authenticated
                    // handshake.
                    self.emit_ble_event(crate::generated::BleEvent {
                        ev: Some(crate::generated::ble_event::Ev::IdentityObserved(
                            crate::generated::BleIdentityObserved {
                                address: ble_address.to_string(),
                                genesis_hash: paired.genesis.to_vec(),
                                device_id: peer.to_vec(),
                            },
                        )),
                    });
                    if let Err(e) = self.notify_pairing_complete(&peer).await {
                        log::warn!(
                            "[PairingOrchestrator] notify_pairing_complete (link) failed for {:02x}{:02x}...: {}",
                            peer[0],
                            peer[1],
                            e
                        );
                    }
                }
            }
            Err(reason) => {
                self.emit_pairing_status(&peer, "failed", reason, Some(ble_address))
                    .await
            }
        }
        stored
    }

    /// Reset any in-progress pairing session for a peer that just disconnected.
    ///
    /// When the BLE link drops during a pairing handshake the transport retry window
    /// would otherwise wait up to 90 s (`STALE_SECS`) before retrying. Calling this
    /// method resets the session to `Failed` immediately so the next loop iteration
    /// re-initiates pairing without delay.
    ///
    /// Completed (`Complete`) sessions are never reset — an already-paired contact
    /// does not need to be re-paired just because the transport layer disconnected.
    pub async fn handle_peer_disconnected(&self, ble_address: &str) {
        let mut sessions = self.sessions.write().await;
        let mut reset = Vec::new();
        for session in sessions.values_mut() {
            if session.ble_address.as_deref() == Some(ble_address) {
                match &session.state {
                    PairingState::Complete => {
                        // Already paired — no action needed.
                    }
                    PairingState::Failed(_) => {
                        // Already in a terminal retry-eligible state.
                    }
                    _ => {
                        let old_state = format!("{:?}", session.state);
                        session.state = PairingState::Failed("BLE link dropped".to_string());
                        session.last_activity = Instant::now();
                        log::info!(
                            "[PairingOrchestrator] Peer {} disconnected — reset pairing session {:02x}{:02x}... ({} → Failed)",
                            ble_address,
                            session.contact_device_id[0],
                            session.contact_device_id[1],
                            old_state,
                        );
                        reset.push(session.contact_device_id);
                    }
                }
            }
        }
        drop(sessions);
        if !reset.is_empty() {
            // Wake the pairing loop so it retries immediately instead of waiting
            // for the next organic state-change notification.
            self.signal_state_change();
        }
        for device_id in &reset {
            self.emit_pairing_status(device_id, "failed", "BLE link dropped", Some(ble_address))
                .await;
        }
    }

    /// Stop the pairing loop. Safe to call even if no loop is running.
    pub fn stop_pairing_loop(&self) {
        self.loop_stop.store(true, Ordering::SeqCst);
        self.signal_state_change();
        log::info!("[PairingOrchestrator] stop_pairing_loop: stop signal sent");
    }

    /// Start the continuous pairing loop for all unpaired contacts.
    ///
    /// This method:
    /// 1. Queries all contacts from SQLite
    /// 2. Filters to unpaired (no ble_address)
    /// 3. For each, calls initiate_pairing() which determines role and starts BLE
    /// 4. Emits PairingStatusUpdate envelopes for each state change
    /// 5. Waits for actual pairing state changes or a transport retry timeout
    /// 6. Loops until all contacts are paired or stop_pairing_loop() is called
    ///
    /// Spawned on the tokio runtime when the session lets pairing run
    /// (`bluetooth::pairing_follows`, `bluetooth::contact_added`).
    pub async fn start_pairing_all_unpaired(self: Arc<Self>) {
        // Reset stop flag first, then atomically claim the loop
        self.loop_stop.store(false, Ordering::SeqCst);
        if self.loop_running.swap(true, Ordering::SeqCst) {
            self.signal_state_change();
            log::info!(
                "[PairingOrchestrator] start_pairing_all_unpaired: loop already running, skipping"
            );
            return;
        }

        log::info!("[PairingOrchestrator] start_pairing_all_unpaired: loop started");

        loop {
            let state_changed = self.state_change.notified();

            // Check stop flag
            if self.loop_stop.load(Ordering::SeqCst) {
                log::info!(
                    "[PairingOrchestrator] start_pairing_all_unpaired: stop signal received"
                );
                break;
            }

            // Query all contacts from SQLite.
            // A transient SQLite failure is non-fatal: wait for the next state change
            // or the periodic retry timeout and try again rather than exiting the loop.
            let contacts = match crate::storage::client_db::get_all_contacts() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!(
                        "[PairingOrchestrator] start_pairing_all_unpaired: get_all_contacts failed (will retry): {}",
                        e
                    );
                    // Wait with a bounded timeout so we retry automatically instead of
                    // blocking forever if no state-change notification arrives.
                    let _ = tokio::time::timeout(PAIRING_LOOP_WAKE_TIMEOUT, state_changed).await;
                    continue;
                }
            };

            // Filter to unpaired contacts (no ble_address, valid device_id)
            let unpaired: Vec<_> = contacts
                .iter()
                .filter(|c| c.ble_address.is_none() && c.device_id.len() == 32)
                .collect();

            if unpaired.is_empty() {
                // SQLite says all contacts have ble_address, but check if any sessions
                // are still in-flight (e.g., peer is mid-handshake). Don't kill radios
                // until all sessions are Complete or Failed.
                let has_inflight = {
                    let sessions = self.sessions.read().await;
                    sessions.values().any(|s| {
                        matches!(
                            s.state,
                            PairingState::WaitingForConnection | PairingState::Handshaking
                        )
                    })
                };
                if has_inflight {
                    log::info!(
                        "[PairingOrchestrator] All contacts paired in SQLite but sessions still in-flight — waiting for state change"
                    );
                    // Use a bounded timeout: if the BLE link drops silently the
                    // in-flight check will still time out and re-evaluate.
                    let _ = tokio::time::timeout(PAIRING_LOOP_WAKE_TIMEOUT, state_changed).await;
                    continue;
                }
                log::info!("[PairingOrchestrator] start_pairing_all_unpaired: no unpaired contacts and no in-flight sessions, loop ending");
                break;
            }

            log::info!(
                "[PairingOrchestrator] start_pairing_all_unpaired: {} unpaired contacts",
                unpaired.len()
            );

            for contact in &unpaired {
                if self.loop_stop.load(Ordering::SeqCst) {
                    break;
                }

                let mut device_id = [0u8; 32];
                device_id.copy_from_slice(&contact.device_id);

                // Determine whether to skip or clear this contact's pairing session:
                // a finished one is skipped, an in-progress one while it is fresh
                // ([`stale_after_secs`]), a failed one never.
                let should_skip = {
                    let sessions = self.sessions.read().await;
                    sessions.get(&device_id).is_some_and(|session| {
                        session.state == PairingState::Complete
                            || stale_after_secs(&session.state).is_some_and(|stale| {
                                session.last_activity.elapsed().as_secs() < stale
                            })
                    })
                };

                if should_skip {
                    continue;
                }

                // Clear any Failed or stale session so initiate_pairing() inserts a
                // fresh one.  A Failed session for a contact that is still unpaired
                // (ble_address absent in SQLite) is retried on this pass. A
                // stale in-progress session means the GATT
                // connection dropped mid-handshake without transitioning to Failed.
                {
                    let mut sessions = self.sessions.write().await;
                    let should_clear = sessions.get(&device_id).is_some_and(|s| {
                        matches!(&s.state, PairingState::Failed(_))
                            || stale_after_secs(&s.state)
                                .is_some_and(|stale| s.last_activity.elapsed().as_secs() >= stale)
                    });
                    if should_clear {
                        sessions.remove(&device_id);
                        log::info!(
                            "[PairingOrchestrator] Cleared stale/failed session for {:02x}{:02x}... — will re-initiate",
                            device_id[0], device_id[1]
                        );
                    }
                }

                // Initiate pairing for this contact
                match self.initiate_pairing(device_id).await {
                    Ok(should_advertise) => {
                        let role_str = if should_advertise {
                            "advertise"
                        } else {
                            "scan"
                        };
                        log::info!(
                            "[PairingOrchestrator] start_pairing_all_unpaired: initiated for {:02x}{:02x}... role={}",
                            device_id[0], device_id[1], role_str
                        );
                        // Emit scanning status event
                        self.emit_pairing_status(&device_id, "scanning", role_str, None)
                            .await;
                    }
                    Err(e) => {
                        log::warn!(
                            "[PairingOrchestrator] start_pairing_all_unpaired: initiate failed for {:02x}{:02x}...: {}",
                            device_id[0], device_id[1], e
                        );
                    }
                }
            }

            // Wait for the next state-change event or a periodic transport timeout,
            // whichever arrives first. The timeout ensures that stale sessions that
            // were not detected via a disconnect notification are still re-evaluated
            // within a reasonable window rather than waiting indefinitely.
            let _ = tokio::time::timeout(PAIRING_LOOP_WAKE_TIMEOUT, state_changed).await;
        }

        // Stop the pairing scan on loop exit so it does not linger ("stuck
        // scanning") once the peer has completed pairing. Advertising follows
        // the identity and is not the loop's.
        if let Err(e) = self.stop_ble_discovery().await {
            log::warn!("[PairingOrchestrator] loop ended with the scan not stopped: {e}");
        }

        self.loop_running.store(false, Ordering::SeqCst);
        log::info!("[PairingOrchestrator] start_pairing_all_unpaired: loop ended");
    }

    /// Emit a PairingStatusUpdate event to the frontend via BleEvent envelope.
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn emit_pairing_status(
        &self,
        device_id: &[u8; 32],
        status: &str,
        message: &str,
        ble_address: Option<&str>,
    ) {
        use crate::generated as pb;
        use pb::BleEvent;

        let status_update = pb::PairingStatusUpdate {
            device_id: device_id.to_vec(),
            status: status.to_string(),
            message: message.to_string(),
            ble_address: ble_address.unwrap_or("").to_string(),
        };

        let ble_event = BleEvent {
            ev: Some(pb::ble_event::Ev::PairingStatus(status_update)),
        };
        self.emit_ble_event(ble_event);
    }

    /// Hand `ble_event` to the frontend through the BleEvent envelope.
    #[cfg(all(target_os = "android", feature = "jni"))]
    fn emit_ble_event(&self, ble_event: crate::generated::BleEvent) {
        match crate::jni::ble_events::build_ble_event_envelope(ble_event) {
            Ok(envelope_bytes) => {
                // Dispatch via existing BleEventRelay path
                use crate::jni::jni_common::{get_java_vm_borrowed, find_class_with_app_loader};
                use jni::objects::JValue;

                if let Some(vm) = get_java_vm_borrowed() {
                    if let Ok(mut env) = vm.attach_current_thread() {
                        let res = (|| -> Result<(), String> {
                            let cls = find_class_with_app_loader(
                                &mut env,
                                "com/dsm/wallet/bridge/Unified",
                            )?;
                            let j_bytes = env
                                .byte_array_from_slice(&envelope_bytes)
                                .map_err(|e| format!("byte_array_from_slice: {e}"))?;
                            env.call_static_method(
                                cls,
                                "dispatchToWebView",
                                "([B)V",
                                &[JValue::Object(&j_bytes)],
                            )
                            .map_err(|e| format!("dispatchToWebView: {e}"))?;
                            Ok(())
                        })();
                        if let Err(e) = res {
                            log::warn!(
                                "[PairingOrchestrator] BleEvent dispatch to the frontend failed: {}",
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] BleEvent envelope build failed: {}",
                    e
                );
            }
        }
    }

    #[cfg(not(all(target_os = "android", feature = "jni")))]
    async fn emit_pairing_status(
        &self,
        _device_id: &[u8; 32],
        _status: &str,
        _message: &str,
        _ble_address: Option<&str>,
    ) {
        // No-op on non-Android
    }

    /// Get pairing session status
    pub async fn get_session_status(&self, contact_device_id: &[u8; 32]) -> Option<PairingState> {
        let sessions = self.sessions.read().await;
        sessions.get(contact_device_id).map(|s| s.state.clone())
    }

    /// Cancel pairing session
    pub async fn cancel_pairing(&self, contact_device_id: &[u8; 32]) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(contact_device_id);
        drop(sessions);
        self.signal_state_change();
        log::info!(
            "[PairingOrchestrator] Cancelled pairing for {:02x}{:02x}...",
            contact_device_id[0],
            contact_device_id[1]
        );
    }

    /// Start BLE discovery using the deterministic role assignment.
    ///
    /// Role is determined by lexicographic comparison of device IDs:
    ///   self_device_id < contact_device_id → this device ADVERTISES (peripheral)
    ///   self_device_id > contact_device_id → this device SCANS (central)
    ///
    /// Both devices ALWAYS start the GATT server (advertise) so the scanning
    /// device can connect and run the link handshake. Only ONE device scans.
    /// This prevents the race condition where both devices discover each other
    /// simultaneously, both call connectGatt(), and the crossing GATT connections
    /// cause error 133 or timeout on Samsung/Qualcomm stacks.
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn start_ble_discovery(&self, contact_device_id: [u8; 32]) -> Result<(), String> {
        let self_device_id = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| "Self device ID not available".to_string())?;
        let self_device_id_array: [u8; 32] = self_device_id
            .try_into()
            .map_err(|_| "Self device ID is not 32 bytes".to_string())?;

        let should_advertise = self_device_id_array < contact_device_id;

        log::info!(
            "[PairingOrchestrator] Starting BLE discovery for contact {:02x}{:02x}... role={}",
            contact_device_id[0],
            contact_device_id[1],
            if should_advertise {
                "advertiser"
            } else {
                "scanner"
            },
        );

        use crate::jni::jni_common::{get_java_vm_borrowed, find_class_with_app_loader};

        let vm = get_java_vm_borrowed().ok_or_else(|| "JavaVM not initialized".to_string())?;

        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("Failed to attach JNI thread: {e}"))?;

        let class_name = "com/dsm/wallet/bridge/Unified";
        let class = find_class_with_app_loader(&mut env, class_name)
            .map_err(|e| format!("Failed to find class {}: {:?}", class_name, e))?;

        // GATT server must always be up so the scanner can read our identity
        let adv_result = env.call_static_method(&class, "startBlePairingAdvertise", "()Z", &[]);
        let adv_ok = adv_result.map(|r| r.z().unwrap_or(false)).unwrap_or(false);

        if should_advertise {
            // Advertiser role: GATT server only, no scanning. The peer will scan and connect.
            log::info!(
                "[PairingOrchestrator] BLE discovery started (advertiser-only): advertise={}",
                adv_ok,
            );
            if !adv_ok {
                return Err("startBlePairingAdvertise failed".to_string());
            }
        } else {
            // Scanner role: also start scanning to discover the peer's advertisement.
            let scan_result = env.call_static_method(&class, "startBlePairingScan", "()Z", &[]);
            let scan_ok = scan_result.map(|r| r.z().unwrap_or(false)).unwrap_or(false);

            log::info!(
                "[PairingOrchestrator] BLE discovery started (scanner): advertise={} scan={}",
                adv_ok,
                scan_ok,
            );
            // The scanner finds the peer: without its scan the attempt would
            // wait on a scan that never ran.
            if !scan_ok {
                return Err(format!(
                    "startBlePairingScan was refused (advertise={adv_ok})"
                ));
            }
        }

        Ok(())
    }

    /// Stop the scan pairing started, via JNI.
    /// Called when the pairing loop exits to prevent lingering radio activity
    /// that causes "stuck scanning" after pairing completes. Advertising is not
    /// pairing's to stop: it follows the appliance's identity (the Android BLE
    /// service owns it), and an appliance that stopped advertising here could not
    /// be found for an offline transfer by the contact it had just paired with.
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn stop_ble_discovery(&self) -> Result<(), String> {
        use crate::jni::jni_common::{find_class_with_app_loader, get_java_vm_borrowed};

        let vm = get_java_vm_borrowed().ok_or_else(|| "JavaVM not initialized".to_string())?;

        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("Failed to attach JNI thread: {e}"))?;

        let class = find_class_with_app_loader(&mut env, "com/dsm/wallet/bridge/Unified")
            .map_err(|e| format!("Failed to find Unified class: {e:?}"))?;

        let stopped = env
            .call_static_method(&class, "stopBlePairingScan", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| format!("Unified.stopBlePairingScan failed: {e:?}"))?;
        if !stopped {
            return Err(
                "Unified.stopBlePairingScan answered false: the scan was not stopped".to_string(),
            );
        }

        log::info!("[PairingOrchestrator] stop_ble_discovery: scan stopped");
        Ok(())
    }

    #[cfg(not(all(target_os = "android", feature = "jni")))]
    async fn stop_ble_discovery(&self) -> Result<(), String> {
        Ok(())
    }

    /// Notify frontend that pairing completed
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn notify_pairing_complete(&self, device_id: &[u8; 32]) -> Result<(), String> {
        // Log for debugging
        log::info!(
            "[PairingOrchestrator] PAIRING_COMPLETE: device_id={:02x}{:02x}{:02x}{:02x}...",
            device_id[0],
            device_id[1],
            device_id[2],
            device_id[3]
        );

        // Emit event to frontend to refresh contact status
        use crate::jni::jni_common::{get_java_vm_borrowed, find_class_with_app_loader};
        use jni::objects::JValue;

        const TOPIC: &str = "dsm-contact-ble-updated";

        let vm = get_java_vm_borrowed().ok_or_else(|| "JavaVM not initialized".to_string())?;

        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("Failed to attach JNI thread: {e}"))?;

        let res = (|| -> Result<(), String> {
            // Call BleEventRelay.dispatchEvent(topic, payloadBytes)
            let cls = find_class_with_app_loader(&mut env, "com/dsm/wallet/bridge/BleEventRelay")?;
            let j_topic = env
                .new_string(TOPIC)
                .map_err(|e| format!("new_string(topic) failed: {e}"))?;

            // Create byte array for device_id
            let j_payload = env
                .byte_array_from_slice(device_id)
                .map_err(|e| format!("byte_array_from_slice failed: {e}"))?;

            // Signature: (Ljava/lang/String;[B)V
            env.call_static_method(
                cls,
                "dispatchEvent",
                "(Ljava/lang/String;[B)V",
                &[JValue::Object(&j_topic), JValue::Object(&j_payload)],
            )
            .map_err(|e| format!("call_static_method dispatchEvent failed: {e}"))?;

            Ok(())
        })();

        if let Err(err) = res {
            log::warn!("Failed to emit pairing completion event: {err}");
            // Don't fail the pairing just because event emission failed
        }

        Ok(())
    }
}

impl Default for PairingOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export for JNI access
impl PairingOrchestrator {
    /// Check if the pairing loop is currently running
    pub fn is_loop_running(&self) -> bool {
        self.loop_running.load(Ordering::SeqCst)
    }
}

/// Where BLE pairing with a contact stands, for the contact list: paired once
/// the contact holds the address pairing confirmed, `held_address` (a session
/// completes only once that address is stored); otherwise the phase of its
/// pairing session, or idle when there is none.
pub fn contact_pairing_phase(
    held_address: Option<&str>,
    session: Option<&PairingState>,
) -> dsm::types::proto::ContactPairingPhase {
    use dsm::types::proto::ContactPairingPhase as Phase;
    if held_address.is_some() {
        return Phase::Paired;
    }
    match session {
        None => Phase::Idle,
        Some(PairingState::WaitingForConnection) => Phase::Searching,
        Some(PairingState::Handshaking) => Phase::Connected,
        Some(PairingState::Complete) => Phase::Paired,
        Some(PairingState::Failed(_)) => Phase::Retrying,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::storage::client_db;
    use crate::storage::client_db::ContactRecord;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_pairing_session_lifecycle() {
        let orchestrator = PairingOrchestrator::new();
        let device_id = [0x42u8; 32];

        // Check no session initially
        assert!(orchestrator.get_session_status(&device_id).await.is_none());

        // Cancel on non-existent session should be safe
        orchestrator.cancel_pairing(&device_id).await;
    }

    /// An attempt still waiting for its first connection is started again
    /// after 20 s: its scan was refused or ended, and the handshake window of
    /// 90 s would leave the user waiting for two minutes. A handshake under
    /// way keeps the 90 s; a finished or failed session is never cleared by
    /// age.
    #[test]
    fn an_attempt_waiting_for_its_first_connection_goes_stale_before_a_handshake() {
        assert_eq!(
            stale_after_secs(&PairingState::WaitingForConnection),
            Some(20)
        );
        assert_eq!(stale_after_secs(&PairingState::Handshaking), Some(90));
        assert_eq!(stale_after_secs(&PairingState::Complete), None);
        assert_eq!(stale_after_secs(&PairingState::Failed("x".into())), None);
        assert_eq!(
            PAIRING_LOOP_WAKE_TIMEOUT,
            std::time::Duration::from_secs(10)
        );
    }

    /// A refused scan frees the attempt that waited on it: it is marked failed
    /// and the loop is woken, so the next pass starts it again. An attempt
    /// whose handshake is under way is left alone, and a contact with no
    /// session gets none.
    #[tokio::test]
    async fn a_refused_scan_frees_the_attempt_waiting_on_it() {
        let orchestrator = PairingOrchestrator::new();
        let waiting = [0x51u8; 32];
        let reading = [0x52u8; 32];
        {
            let mut sessions = orchestrator.sessions.write().await;
            for (id, state) in [
                (waiting, PairingState::WaitingForConnection),
                (reading, PairingState::Handshaking),
            ] {
                sessions.insert(
                    id,
                    PairingSession {
                        contact_device_id: id,
                        state,
                        ble_address: None,
                        last_activity: Instant::now(),
                    },
                );
            }
        }
        let woken = orchestrator.state_change.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();

        orchestrator.discovery_refused(waiting).await;
        orchestrator.discovery_refused(reading).await;
        orchestrator.discovery_refused([0x53u8; 32]).await;

        assert!(matches!(
            orchestrator.get_session_status(&waiting).await,
            Some(PairingState::Failed(_))
        ));
        assert_eq!(
            orchestrator.get_session_status(&reading).await,
            Some(PairingState::Handshaking)
        );
        assert_eq!(orchestrator.get_session_status(&[0x53u8; 32]).await, None);
        tokio::time::timeout(std::time::Duration::from_secs(1), woken)
            .await
            .expect("the pairing loop was not woken");
    }

    /// A discovery the radio started leaves the attempt waiting for its
    /// connection; one it refused frees the attempt once the retry delay has
    /// passed. The delay the device waits is past the radio's 6 s gap between
    /// scans.
    #[tokio::test]
    async fn a_refused_discovery_is_retried_after_the_scan_gap() {
        assert_eq!(DISCOVERY_RETRY_DELAY, std::time::Duration::from_secs(7));
        let orchestrator = PairingOrchestrator::new();
        let started = [0x61u8; 32];
        let refused = [0x62u8; 32];
        {
            let mut sessions = orchestrator.sessions.write().await;
            for id in [started, refused] {
                sessions.insert(
                    id,
                    PairingSession {
                        contact_device_id: id,
                        state: PairingState::WaitingForConnection,
                        ble_address: None,
                        last_activity: Instant::now(),
                    },
                );
            }
        }
        let retry = std::time::Duration::from_millis(20);
        orchestrator
            .after_discovery_start(started, Ok(()), retry)
            .await;
        orchestrator
            .after_discovery_start(refused, Err("scan refused".to_string()), retry)
            .await;
        assert_eq!(
            orchestrator.get_session_status(&started).await,
            Some(PairingState::WaitingForConnection)
        );
        assert!(matches!(
            orchestrator.get_session_status(&refused).await,
            Some(PairingState::Failed(_))
        ));
    }

    #[tokio::test]
    async fn test_session_state_transitions() {
        let orchestrator = PairingOrchestrator::new();
        let device_id = [0x43u8; 32];
        let _ble_address = "AA:BB:CC:DD:EE:FF".to_string();
        let _genesis_hash = [0x44u8; 32];

        // Create session manually for testing
        {
            let mut sessions = orchestrator.sessions.write().await;
            sessions.insert(
                device_id,
                PairingSession {
                    contact_device_id: device_id,
                    state: PairingState::WaitingForConnection,
                    ble_address: None,
                    last_activity: Instant::now(),
                },
            );
        }

        // Verify session exists
        let status = orchestrator.get_session_status(&device_id).await;
        assert_eq!(status, Some(PairingState::WaitingForConnection));

        // Cancel should remove session
        orchestrator.cancel_pairing(&device_id).await;
        assert!(orchestrator.get_session_status(&device_id).await.is_none());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_initiate_pairing_creates_session() {
        // Initialize fresh in-memory DB (serialized to avoid OnceCell races),
        // in this test's own storage directory.
        crate::economic_fixtures::use_test_storage_dir();
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");

        // Ensure device ID is available using idempotent bootstrap
        crate::sdk::app_state::AppState::set_identity_info_if_empty(
            vec![0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 32],
            vec![0x00; 32],
        )
        .expect("AppState identity");

        // Create a contact record so initiate_pairing's SQLite gate passes
        let device_id = [0x11u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-test-initiate".to_string(),
            device_id: device_id.to_vec(),
            alias: "test-peer".to_string(),
            genesis_hash: vec![0x33; 32],
            current_chain_tip: Some(vec![0x70; 32]),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            public_key: vec![0u8; 32],
            kyber_public_key: vec![0x4B; 1184],
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        let orchestrator = PairingOrchestrator::new();
        orchestrator
            .initiate_pairing(device_id)
            .await
            .expect("initiate");
        let status = orchestrator.get_session_status(&device_id).await;
        assert_eq!(status, Some(PairingState::WaitingForConnection));
    }

    fn store_peer(device_id: [u8; 32]) {
        client_db::store_contact(&ContactRecord {
            contact_id: format!("ct-{:02x}", device_id[0]),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: vec![0x55; 32],
            current_chain_tip: Some(vec![0x70; 32]),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            public_key: vec![0u8; 32],
            kyber_public_key: vec![0x4B; 1184],
            previous_chain_tip: None,
        })
        .expect("store contact");
    }

    async fn session_in(
        orchestrator: &PairingOrchestrator,
        device_id: [u8; 32],
        state: PairingState,
        ble_address: &str,
    ) {
        orchestrator.sessions.write().await.insert(
            device_id,
            PairingSession {
                contact_device_id: device_id,
                state,
                ble_address: Some(ble_address.to_string()),
                last_activity: Instant::now(),
            },
        );
    }

    /// DSM Amendment A27: a paired link completes pairing only once the
    /// contact's address is stored, the stored address being what makes the
    /// contact paired. With no contact to store it on, the session fails and
    /// nothing is reported paired; with the contact, it completes and the
    /// contact holds the link's address. A session waiting for its
    /// connection moves to `Handshaking` when its link comes up.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_paired_link_completes_only_once_the_address_is_stored() {
        crate::economic_fixtures::use_test_storage_dir();
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        let orchestrator = PairingOrchestrator::new();
        let peer = [0x71u8; 32];
        let address = "AA:00:00:00:00:71";

        session_in(
            &orchestrator,
            peer,
            PairingState::WaitingForConnection,
            address,
        )
        .await;
        orchestrator.link_opened(peer, address).await;
        assert_eq!(
            orchestrator.get_session_status(&peer).await,
            Some(PairingState::Handshaking)
        );
        let paired = dsm::crypto::ble_link::LinkIdentity {
            device_id: peer,
            genesis: [0x55; 32],
        };
        let refused = orchestrator
            .link_paired(&paired, address)
            .await
            .expect_err("the address was not stored");
        assert!(refused.contains("not stored"), "{refused}");
        assert!(matches!(
            orchestrator.get_session_status(&peer).await,
            Some(PairingState::Failed(_))
        ));

        store_peer(peer);
        orchestrator
            .link_paired(&paired, address)
            .await
            .expect("completes");
        assert_eq!(
            orchestrator.get_session_status(&peer).await,
            Some(PairingState::Complete)
        );
        let contact = client_db::get_contact_by_device_id(&peer)
            .expect("read")
            .expect("contact");
        assert_eq!(contact.ble_address.as_deref(), Some(address));
    }

    /// The phase the contact list states: paired once the address is stored,
    /// else the session's phase, else idle.
    #[test]
    fn a_contacts_pairing_phase_is_the_sdks_own() {
        use dsm::types::proto::ContactPairingPhase as Phase;
        assert_eq!(
            contact_pairing_phase(Some("AA:00:00:00:00:01"), None),
            Phase::Paired
        );
        assert_eq!(contact_pairing_phase(None, None), Phase::Idle);
        assert_eq!(
            contact_pairing_phase(None, Some(&PairingState::WaitingForConnection)),
            Phase::Searching
        );
        assert_eq!(
            contact_pairing_phase(None, Some(&PairingState::Handshaking)),
            Phase::Connected
        );
        assert_eq!(
            contact_pairing_phase(None, Some(&PairingState::Failed("link".into()))),
            Phase::Retrying
        );
        assert_eq!(
            contact_pairing_phase(None, Some(&PairingState::Complete)),
            Phase::Paired
        );
    }
}
