//! # BLE Pairing Orchestrator
//!
//! Deterministic state machine for bilateral identity exchange over BLE.
//! Takes a contact's device_id as input, coordinates the Kotlin BLE radio
//! (scan/advertise), and drives the bilateral handshake when peer connects.
//! Transport policy: wall-clock time is allowed here for BLE handshake freshness,
//! disconnect recovery, retry windows, and wake-up timeouts. Those timers never
//! participate in chain ordering, receipt commits, or acceptance predicates.
// 4. Validates identity + chain tip
// 5. Updates contact status to BleCapable when complete
// 6. Holds GATT session stable until handshake done

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{Notify, RwLock};

/// Pairing session state for a specific contact.
///
/// 3-phase atomic pairing protocol:
///   Phase 1: Identity exchange (both sides observe each other)
///   Phase 2: Advertiser sends BlePairingAccept → AwaitingConfirm
///   Phase 3: Scanner sends BlePairingConfirm → both sides persist ble_address
///
/// Neither side writes ble_address until Phase 3 completes. If any phase fails,
/// the session stays failed until an explicit restart re-initiates pairing.
#[derive(Debug, Clone, PartialEq)]
pub enum PairingState {
    /// Waiting for BLE connection
    WaitingForConnection,
    /// Connected, reading peer identity
    ReadingIdentity,
    /// Identity validated, exchanging chain tips
    ExchangingChainTips,
    /// Advertiser sent BlePairingAccept, waiting for scanner's BlePairingConfirm.
    /// ble_address is NOT persisted yet — only stored in-memory on the session.
    AwaitingConfirm,
    /// Scanner sent BlePairingConfirm; waiting for GATT write-with-response ACK.
    /// ble_address is stored in-memory on the session but NOT yet persisted to SQLite.
    /// Finalization is deferred to finalize_scanner_pairing_by_address(), which is
    /// called from JNI after the PairingConfirmWritten (onCharacteristicWrite) callback.
    ConfirmSent,
    /// Handshake complete, updating contact status
    UpdatingStatus,
    /// Pairing complete successfully
    Complete,
    /// Pairing failed
    Failed(String),
}

/// Active pairing session for a contact
#[derive(Debug, Clone)]
pub struct PairingSession {
    pub contact_device_id: [u8; 32],
    pub state: PairingState,
    pub ble_address: Option<String>,
    pub peer_genesis_hash: Option<[u8; 32]>,
    pub peer_chain_tip: Option<Vec<u8>>,
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
            peer_genesis_hash: None,
            peer_chain_tip: None,
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
                if let Err(e) = orchestrator.start_ble_discovery(contact).await {
                    log::warn!(
                        "[PairingOrchestrator] start_ble_discovery secondary path failed: {}",
                        e
                    );
                } else {
                    log::info!(
                        "[PairingOrchestrator] start_ble_discovery secondary path issued successfully"
                    );
                }
            });
        }

        // Return the role - Kotlin will start the appropriate BLE operation
        Ok(should_advertise)
    }

    /// Handle BLE identity observed event from AndroidBleBridge
    ///
    /// Called when peer's identity is read from GATT characteristic.
    pub async fn handle_identity_observed(
        &self,
        ble_address: String,
        peer_genesis_hash: [u8; 32],
        peer_device_id: [u8; 32],
    ) -> Result<(), String> {
        // Find matching pairing session, or create one implicitly for auto-pairing
        let mut sessions = self.sessions.write().await;
        match sessions.entry(peer_device_id) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(PairingSession {
                    contact_device_id: peer_device_id,
                    state: PairingState::WaitingForConnection,
                    ble_address: None,
                    peer_genesis_hash: None,
                    peer_chain_tip: None,
                    last_activity: Instant::now(),
                });
                log::info!(
                    "[PairingOrchestrator] Auto-created pairing session for {:02x}{:02x}... (identity_observed)",
                    peer_device_id[0],
                    peer_device_id[1]
                );
            }
            std::collections::hash_map::Entry::Occupied(_e) => {}
        }
        let session = sessions
            .get_mut(&peer_device_id)
            .ok_or_else(|| "Pairing session missing after insertion".to_string())?;

        log::info!(
            "[PairingOrchestrator] (identity_observed) Current state for {:02x}{:02x}...: {:?}",
            peer_device_id[0],
            peer_device_id[1],
            session.state
        );

        // If already complete, just return success (idempotent)
        if session.state == PairingState::Complete {
            log::info!(
                "[PairingOrchestrator] Identity observed for {:02x}{:02x}... but session already complete (idempotent)",
                peer_device_id[0], peer_device_id[1]
            );
            return Ok(());
        }

        // Allow identity observation in early states. When both devices scan AND
        // advertise simultaneously, both may call handle_identity_observed for the
        // same peer — the second call should be a harmless no-op, not an error.
        match session.state {
            PairingState::WaitingForConnection => {} // expected
            PairingState::ReadingIdentity | PairingState::ExchangingChainTips => {
                log::info!(
                    "[PairingOrchestrator] Identity re-observed for {:02x}{:02x}... in state {:?} (idempotent, updating ble_address)",
                    peer_device_id[0], peer_device_id[1], session.state
                );
                // Update BLE address in case it changed (e.g., different GATT connection)
                session.ble_address = Some(ble_address.clone());
                return Ok(());
            }
            PairingState::AwaitingConfirm
            | PairingState::ConfirmSent
            | PairingState::UpdatingStatus => {
                log::info!(
                    "[PairingOrchestrator] Identity observed for {:02x}{:02x}... but pairing already in progress ({:?}), skipping",
                    peer_device_id[0], peer_device_id[1], session.state
                );
                return Ok(());
            }
            _ => {
                log::warn!(
                    "[PairingOrchestrator] Identity observed but session in unexpected state: {:?}",
                    session.state
                );
                return Err(format!("Session in unexpected state: {:?}", session.state));
            }
        }

        // Update session
        session.state = PairingState::ReadingIdentity;
        session.last_activity = Instant::now();
        session.ble_address = Some(ble_address.clone());
        session.peer_genesis_hash = Some(peer_genesis_hash);

        log::info!(
            "[PairingOrchestrator] Identity observed for {:02x}{:02x}...: address={}",
            peer_device_id[0],
            peer_device_id[1],
            ble_address
        );

        // Validate identity against existing contact if present. If contact record
        // is not present yet, do not fail – pairing should still proceed based on
        // the observed identity. Online status is intentionally ignored.
        if let Ok(maybe_contact) =
            crate::storage::client_db::get_contact_by_device_id(&peer_device_id)
        {
            if let Some(contact) = maybe_contact {
                if contact.genesis_hash != peer_genesis_hash {
                    session.state = PairingState::Failed("Genesis hash mismatch".to_string());
                    session.last_activity = Instant::now();
                    drop(sessions);
                    self.signal_state_change();
                    log::warn!(
                        "[PairingOrchestrator] Genesis hash mismatch for {:02x}{:02x}... (identity_observed)",
                        peer_device_id[0], peer_device_id[1]
                    );
                    return Err("Genesis hash mismatch".to_string());
                }
            } else {
                log::warn!("[PairingOrchestrator] Contact record not found for device; proceeding on identity only");
            }
        } else {
            log::warn!(
                "[PairingOrchestrator] Unable to query contact record; proceeding on identity only"
            );
        }

        // Move to chain tip exchange. We must NOT complete pairing immediately here;
        // instead we perform a mutual confirmation via protobuf BlePairingAccept sent
        // as a GATT INDICATE on the PAIRING_ACK characteristic to guarantee both sides
        // observed each other before committing the contact update.
        session.state = PairingState::ExchangingChainTips;
        session.last_activity = Instant::now();

        log::info!(
            "[PairingOrchestrator] Identity validated, ready for pairing exchange for {:02x}{:02x}... (state now ExchangingChainTips)",
            peer_device_id[0],
            peer_device_id[1]
        );

        // Update contact status to BleCapable (identity validated). This unconditionally
        // promotes to BleCapable regardless of prior online state.
        // IMPORTANT: We do NOT set ble_address here. The ble_address column is the
        // sentinel used by start_pairing_all_unpaired to decide whether a contact is
        // "unpaired". Writing it here would cause the pairing loop to exit on Device A
        // before Device B has had a chance to complete the bilateral PAIR1/PAIR2
        // handshake — the classic race condition. ble_address is committed only after
        // the bilateral exchange is confirmed (handle_pairing_ack for the initiator,
        // handle_pairing_propose for the responder).
        match crate::storage::client_db::update_contact_ble_status(
            &peer_device_id,
            None, // no chain tip yet
            None, // ble_address written only on ACK, not on identity observation
        ) {
            Ok(()) => {
                log::info!(
                    "[PairingOrchestrator] Contact BLE status updated for {:02x}{:02x}...",
                    peer_device_id[0],
                    peer_device_id[1]
                );
            }
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] update_contact_ble_status failed for {:02x}{:02x}... (non-fatal, continuing): {}",
                    peer_device_id[0], peer_device_id[1], e
                );
            }
        }

        drop(sessions);
        self.signal_state_change();

        Ok(())
    }

    /// Handle a pairing propose: advertiser has sent BlePairingAccept to scanner.
    /// Called on the ADVERTISER side after building and dispatching the ACK envelope.
    ///
    /// ATOMIC PAIRING: Does NOT write ble_address to SQLite. Only stores the address
    /// in-memory on the session and moves to AwaitingConfirm. The ble_address is
    /// persisted only when the scanner's BlePairingConfirm arrives (handle_pairing_confirm).
    pub async fn handle_pairing_propose(
        &self,
        peer_device_id: [u8; 32],
        peer_ble_address: String,
        peer_chain_tip: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .entry(peer_device_id)
            .or_insert_with(|| PairingSession {
                contact_device_id: peer_device_id,
                state: PairingState::WaitingForConnection,
                ble_address: None,
                peer_genesis_hash: None,
                peer_chain_tip: None,
                last_activity: Instant::now(),
            });

        log::info!(
            "[PairingOrchestrator] Received PAIR_PROPOSE for {:02x}{:02x}... addr={} (state before: {:?})",
            peer_device_id[0],
            peer_device_id[1],
            peer_ble_address,
            session.state
        );

        // Store address and chain tip in-memory ONLY — no SQLite write yet.
        // ble_address is the sentinel that controls the pairing loop exit condition.
        // Writing it now would let this side exit the loop before the scanner confirms.
        session.ble_address = Some(peer_ble_address);
        session.peer_chain_tip = peer_chain_tip.map(|t| t.to_vec());
        session.state = PairingState::AwaitingConfirm;
        session.last_activity = Instant::now();

        log::info!(
            "[PairingOrchestrator] Advertiser waiting for scanner confirm for {:02x}{:02x}... (state now AwaitingConfirm)",
            peer_device_id[0],
            peer_device_id[1]
        );

        drop(sessions);
        self.signal_state_change();

        Ok(())
    }

    /// Handle Phase 3: scanner's BlePairingConfirm received by the advertiser.
    /// NOW it is safe to persist ble_address and mark Complete on the advertiser side,
    /// because the scanner has confirmed it received our BlePairingAccept and has
    /// already persisted its own ble_address.
    pub async fn handle_pairing_confirm(&self, peer_device_id: [u8; 32]) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&peer_device_id)
            .ok_or_else(|| "No active pairing session for confirm".to_string())?;

        log::info!(
            "[PairingOrchestrator] Received PAIRING_CONFIRM for {:02x}{:02x}... (state before: {:?})",
            peer_device_id[0],
            peer_device_id[1],
            session.state
        );

        // Only process if we're actually awaiting confirm (idempotent for duplicates)
        if session.state != PairingState::AwaitingConfirm
            && session.state != PairingState::ExchangingChainTips
        {
            if session.state == PairingState::Complete {
                log::info!(
                    "[PairingOrchestrator] Already Complete for {:02x}{:02x}... (idempotent confirm)",
                    peer_device_id[0], peer_device_id[1]
                );
                return Ok(());
            }
            return Err(format!("Unexpected state for confirm: {:?}", session.state));
        }

        let ble_address = session.ble_address.clone();
        let chain_tip = session.peer_chain_tip.clone();

        // NOW persist ble_address to SQLite — the scanner has confirmed receipt.
        match crate::storage::client_db::update_contact_ble_status(
            &peer_device_id,
            chain_tip.as_deref(),
            ble_address.as_deref(),
        ) {
            Ok(()) => {
                log::info!(
                    "[PairingOrchestrator] Contact BLE status persisted on confirm for {:02x}{:02x}...",
                    peer_device_id[0], peer_device_id[1]
                );
            }
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] update_contact_ble_status failed on confirm for {:02x}{:02x}...: {}",
                    peer_device_id[0], peer_device_id[1], e
                );
            }
        }

        session.state = PairingState::Complete;
        session.last_activity = Instant::now();

        log::info!(
            "[PairingOrchestrator] Pairing complete (advertiser, confirmed) for {:02x}{:02x}...",
            peer_device_id[0],
            peer_device_id[1]
        );

        drop(sessions);
        self.signal_state_change();

        // Emit frontend notification; best-effort
        #[cfg(all(target_os = "android", feature = "jni"))]
        {
            let id = peer_device_id;
            let orch = crate::bluetooth::get_pairing_orchestrator();
            crate::runtime::get_runtime().spawn(async move {
                if let Err(e) = orch.notify_pairing_complete(&id).await {
                    log::warn!(
                        "[PairingOrchestrator] notify_pairing_complete (confirm path) failed: {}",
                        e
                    );
                }
            });
        }

        Ok(())
    }

    /// Handle a pairing ACK (received BlePairingAccept) from the advertiser.
    ///
    /// ATOMIC PAIRING — Phase 3a (scanner side):
    /// This method is called when the scanner receives `BlePairingAccept` from the
    /// advertiser. It stores the peer chain tip in-memory and transitions the session
    /// to `ConfirmSent`, but does NOT persist `ble_address` to SQLite yet.
    ///
    /// Finalization (SQLite persist + Complete + frontend notification) is deferred
    /// to [`finalize_scanner_pairing_by_address`], which is called only after the
    /// `BlePairingConfirm` GATT write is acknowledged by the BLE stack
    /// (`onCharacteristicWrite` → `PairingConfirmWritten` event → JNI call).
    ///
    /// This prevents the scanner from marking itself `Complete` when the confirm
    /// may have been dropped before the advertiser received it — which was the root
    /// cause of the one-sided pairing asymmetry bug.
    ///
    /// `ble_address_hint` is the BLE MAC address of the advertiser, supplied by the
    /// JNI caller at the moment the PairingAccept is received. When the session does
    /// not yet have a `ble_address` (because `handle_identity_observed` ran through the
    /// deferred-retry path and did not set the address yet), the hint is used to
    /// populate it so that `finalize_scanner_pairing_by_address` can locate the session.
    pub async fn handle_pairing_ack(
        &self,
        peer_device_id: [u8; 32],
        peer_chain_tip: Option<[u8; 32]>,
        ble_address_hint: &str,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&peer_device_id)
            .ok_or_else(|| "No active pairing session for ack".to_string())?;

        // Ensure we at least have a ble_address for this session. If none, populate
        // from the caller-supplied hint (the advertiser's BLE MAC, available at JNI
        // call time). Without ble_address, finalize_scanner_pairing_by_address()
        // cannot locate the session and scanner-side finalization silently fails.
        if session.ble_address.is_none() {
            if !ble_address_hint.is_empty() {
                log::info!(
                    "[PairingOrchestrator] ble_address was None for {:02x}{:02x}... — \
                     populating from ACK sender hint: {}",
                    peer_device_id[0],
                    peer_device_id[1],
                    ble_address_hint
                );
                session.ble_address = Some(ble_address_hint.to_string());
            } else {
                log::warn!(
                    "[PairingOrchestrator] ACK received but no ble_address and no hint \
                     for {:02x}{:02x}... (state: {:?}) — finalize_scanner_pairing may fail",
                    peer_device_id[0],
                    peer_device_id[1],
                    session.state
                );
                // Continue: finalizeScannerPairing is called by Kotlin with the address
                // directly; if ble_address is still None the finalize step logs an error.
            }
        }

        // Store chain tip in-memory but do NOT persist ble_address to SQLite yet.
        // Persistence is deferred to finalize_scanner_pairing_by_address() so that
        // both sides only commit after the other side has confirmed receipt.
        if let Some(tip) = peer_chain_tip {
            session.peer_chain_tip = Some(tip.to_vec());
        }

        session.state = PairingState::ConfirmSent;
        session.last_activity = Instant::now();

        log::info!(
            "[PairingOrchestrator] Pairing ConfirmSent for {:02x}{:02x}... — deferred finalization until BlePairingConfirm delivered",
            peer_device_id[0],
            peer_device_id[1]
        );

        drop(sessions);
        self.signal_state_change();

        Ok(())
    }

    /// Finalize scanner-side pairing after `BlePairingConfirm` is confirmed delivered.
    ///
    /// ATOMIC PAIRING — Phase 3b (scanner side):
    /// Called from JNI `finalizeScannerPairing` which is invoked by Kotlin in the
    /// `PairingConfirmWritten` handler (i.e., `onCharacteristicWrite` callback for
    /// the PAIRING characteristic confirm write). At this point the GATT stack has
    /// confirmed the confirm bytes were delivered to the advertiser, so it is safe
    /// to persist `ble_address` and mark the session `Complete`.
    ///
    /// This is the scanner's symmetric counterpart of `handle_pairing_confirm` on
    /// the advertiser side — both sides now persist `ble_address` only after the
    /// other side's receipt is confirmed, completing a 4-phase atomic commit:
    ///   1. Advertiser: `handle_pairing_propose`  → `AwaitingConfirm` (no persist)
    ///   2. Scanner:    `handle_pairing_ack`       → `ConfirmSent`     (no persist)
    ///   3. Advertiser: `handle_pairing_confirm`   → `Complete`        (persist)
    ///   4. Scanner:    `finalize_scanner_pairing_by_address` → `Complete` (persist)
    pub async fn finalize_scanner_pairing_by_address(
        &self,
        ble_address: &str,
    ) -> Result<(), String> {
        // Locate the peer_device_id for the ConfirmSent session, then drop the lock
        // before calling notify_pairing_complete to avoid a potential deadlock.
        let (peer_device_id, chain_tip) = {
            let mut sessions = self.sessions.write().await;

            let (&peer_device_id, session) = sessions
                .iter_mut()
                .find(|(_, s)| {
                    s.state == PairingState::ConfirmSent
                        && s.ble_address.as_deref() == Some(ble_address)
                })
                .ok_or_else(|| {
                    format!(
                        "finalize_scanner_pairing_by_address: no ConfirmSent session for {} (already finalized or timed out)",
                        ble_address
                    )
                })?;

            let chain_tip = session.peer_chain_tip.clone();

            // Persist ble_address — BlePairingConfirm was delivered to the advertiser.
            match crate::storage::client_db::update_contact_ble_status(
                &peer_device_id,
                chain_tip.as_deref(),
                Some(ble_address),
            ) {
                Ok(()) => {
                    log::info!(
                        "[PairingOrchestrator] ble_address persisted on scanner finalize for {:02x}{:02x}...",
                        peer_device_id[0],
                        peer_device_id[1]
                    );
                }
                Err(e) => {
                    log::warn!(
                        "[PairingOrchestrator] update_contact_ble_status failed on scanner finalize for {:02x}{:02x}...: {}",
                        peer_device_id[0],
                        peer_device_id[1],
                        e
                    );
                }
            }

            session.state = PairingState::Complete;
            session.last_activity = Instant::now();

            log::info!(
                "[PairingOrchestrator] Pairing complete (scanner, finalized) for {:02x}{:02x}...",
                peer_device_id[0],
                peer_device_id[1]
            );

            (peer_device_id, chain_tip)
        }; // sessions write-lock released here

        self.signal_state_change();

        let _ = chain_tip; // suppress unused warning if notify path not compiled in
        let _ = peer_device_id; // suppress unused warning on non-android/non-jni targets

        // Emit frontend notification; best-effort
        #[cfg(all(target_os = "android", feature = "jni"))]
        {
            if let Err(e) = self.notify_pairing_complete(&peer_device_id).await {
                log::warn!(
                    "[PairingOrchestrator] notify_pairing_complete (scanner finalize) failed for {:02x}{:02x}...: {}",
                    peer_device_id[0],
                    peer_device_id[1],
                    e
                );
            }
        }

        Ok(())
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
        let mut reset_count = 0usize;
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
                        session.state = PairingState::Failed("BLE link dropped".to_string());
                        session.last_activity = Instant::now();
                        log::info!(
                            "[PairingOrchestrator] Peer {} disconnected — reset pairing session {:02x}{:02x}... ({} → Failed)",
                            ble_address,
                            session.contact_device_id[0],
                            session.contact_device_id[1],
                            old_state,
                        );
                        reset_count += 1;
                    }
                }
            }
        }
        drop(sessions);
        if reset_count > 0 {
            // Wake the pairing loop so it retries immediately instead of waiting
            // for the next organic state-change notification.
            self.signal_state_change();
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
    /// Designed to be spawned on the tokio runtime (fire-and-forget from JNI).
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

        /// Maximum wall-clock interval the pairing loop waits for a state-change
        /// notification before re-evaluating sessions regardless. This is transport
        /// runtime control only and ensures stale or silently-dropped BLE sessions
        /// are recovered even when no explicit disconnect event fires.
        const PAIRING_LOOP_WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
                            PairingState::WaitingForConnection
                                | PairingState::ReadingIdentity
                                | PairingState::ExchangingChainTips
                                | PairingState::AwaitingConfirm
                                | PairingState::ConfirmSent
                                | PairingState::UpdatingStatus
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

                // BLE sessions stale after 90s. This transport timer bounds
                // handshake freshness and reconnect retry windows only.
                const STALE_SECS: u64 = 90;

                // Determine whether to skip or clear this contact's pairing session.
                let should_skip = {
                    let sessions = self.sessions.read().await;
                    if let Some(session) = sessions.get(&device_id) {
                        match &session.state {
                            // Pairing done — skip unconditionally.
                            PairingState::Complete => true,
                            // In-progress states: skip while fresh, clear when stale.
                            PairingState::ReadingIdentity
                            | PairingState::ExchangingChainTips
                            | PairingState::AwaitingConfirm
                            | PairingState::ConfirmSent
                            | PairingState::UpdatingStatus
                            | PairingState::WaitingForConnection => {
                                session.last_activity.elapsed().as_secs() < STALE_SECS
                            }
                            // Failed or stale: do not skip — clear below and retry.
                            PairingState::Failed(_) => false,
                        }
                    } else {
                        false // no session yet — proceed to initiate
                    }
                };

                if should_skip {
                    continue;
                }

                // Clear any Failed or stale session so initiate_pairing() inserts a
                // fresh one.  A Failed session for a contact that is still unpaired
                // (ble_address absent in SQLite) must be retried on the next
                // startPairingAll call.  A stale in-progress session means the GATT
                // connection dropped mid-handshake without transitioning to Failed.
                {
                    let mut sessions = self.sessions.write().await;
                    let should_clear = sessions.get(&device_id).is_some_and(|s| {
                        matches!(&s.state, PairingState::Failed(_))
                            || (!matches!(&s.state, PairingState::Complete)
                                && s.last_activity.elapsed().as_secs() >= STALE_SECS)
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

        // Stop BLE radios on loop exit to prevent lingering scan/advertise that
        // causes "stuck scanning" when the peer has already completed pairing.
        let _ = self.stop_ble_discovery().await;

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
                                "[PairingOrchestrator] emit_pairing_status dispatch failed: {}",
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[PairingOrchestrator] emit_pairing_status envelope build failed: {}",
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
    /// device can read the identity characteristic. Only ONE device scans.
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
            if !adv_ok && !scan_ok {
                return Err(
                    "Both startBlePairingAdvertise and startBlePairingScan failed".to_string(),
                );
            }
        }

        Ok(())
    }

    #[cfg(not(all(target_os = "android", feature = "jni")))]
    async fn start_ble_discovery(&self, _contact_device_id: [u8; 32]) -> Result<(), String> {
        log::warn!("[PairingOrchestrator] BLE discovery not available on this platform");
        Ok(())
    }

    /// Stop BLE scan and advertise via JNI.
    /// Called when the pairing loop exits to prevent lingering radio activity
    /// that causes "stuck scanning" after pairing completes.
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn stop_ble_discovery(&self) -> Result<(), String> {
        use crate::jni::jni_common::{find_class_with_app_loader, get_java_vm_borrowed};

        let vm = get_java_vm_borrowed().ok_or_else(|| "JavaVM not initialized".to_string())?;

        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("Failed to attach JNI thread: {e}"))?;

        let class = find_class_with_app_loader(&mut env, "com/dsm/wallet/bridge/Unified")
            .map_err(|e| format!("Failed to find Unified class: {e:?}"))?;

        // Stop both scan and advertise — we don't know which role we were playing
        let _ = env.call_static_method(&class, "stopBlePairingScan", "()Z", &[]);
        let _ = env.call_static_method(&class, "stopBlePairingAdvertise", "()Z", &[]);

        log::info!("[PairingOrchestrator] stop_ble_discovery: stopped scan and advertise");
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

    #[cfg(not(all(target_os = "android", feature = "jni")))]
    async fn notify_pairing_complete(&self, _device_id: &[u8; 32]) -> Result<(), String> {
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
                    peer_genesis_hash: None,
                    peer_chain_tip: None,
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
        // Initialize fresh in-memory DB (serialized to avoid OnceCell races)
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");

        // Initialize environment for AppState
        let temp_dir = tempfile::Builder::new()
            .prefix("dsm_test_pair")
            .tempdir()
            .expect("tempdir");
        let _ = crate::storage_utils::set_storage_base_dir(temp_dir.keep());

        // Ensure device ID is available using idempotent bootstrap
        crate::sdk::app_state::AppState::set_identity_info_if_empty(
            vec![0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 32],
            vec![0x00; 32],
        );

        // Create a contact record so initiate_pairing's SQLite gate passes
        let device_id = [0x11u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-test-initiate".to_string(),
            device_id: device_id.to_vec(),
            alias: "test-peer".to_string(),
            genesis_hash: vec![0x33; 32],
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: vec![0u8; 32],
            kyber_public_key: Vec::new(),
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

    #[tokio::test]
    #[serial_test::serial]
    async fn test_identity_observed_success_updates_status() {
        // Initialize fresh in-memory DB (serialized to avoid OnceCell races)
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");

        // Create a contact record matching the observed identity
        let device_id = [0x22u8; 32];
        let genesis = [0x33u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-1".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: genesis.to_vec(),
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: vec![0u8; 32],
            kyber_public_key: Vec::new(),
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        let orchestrator = PairingOrchestrator::new();
        // No explicit initiate; observe identity directly
        orchestrator
            .handle_identity_observed("AA:BB:CC".to_string(), genesis, device_id)
            .await
            .expect("identity observed ok");

        // Session should NOT be complete yet; mutual confirmation (PAIR1/PAIR2)
        // is required before finalization.
        let status = orchestrator.get_session_status(&device_id).await;
        assert_eq!(status, Some(PairingState::ExchangingChainTips));

        // Contact status should be promoted to BleCapable but ble_address must NOT
        // be written yet — we defer that to the ACK so the pairing loop on the
        // initiator side stays alive until PAIR2 arrives.
        let contact = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "BleCapable");
        assert_eq!(
            contact.ble_address, None,
            "ble_address must not be set until bilateral ACK"
        );

        // Now simulate the mutual handshake completion by receiving PAIR2.
        orchestrator
            .handle_pairing_ack(device_id, None, "")
            .await
            .expect("ack transitions to ConfirmSent");
        // Scanner is ConfirmSent — ble_address not persisted until confirm delivered.
        let status2 = orchestrator.get_session_status(&device_id).await;
        assert_eq!(status2, Some(PairingState::ConfirmSent));

        // Simulate BlePairingConfirm GATT write ACK (onCharacteristicWrite → finalize).
        orchestrator
            .finalize_scanner_pairing_by_address("AA:BB:CC")
            .await
            .expect("finalize after confirm delivery");
        let status3 = orchestrator.get_session_status(&device_id).await;
        assert_eq!(status3, Some(PairingState::Complete));

        // ble_address must be committed to SQLite now that bilateral ACK is done.
        let contact2 = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact post-ack")
            .expect("exists post-ack");
        assert_eq!(
            contact2.ble_address.as_deref(),
            Some("AA:BB:CC"),
            "ble_address must be set after scanner finalization"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_identity_observed_genesis_mismatch_fails() {
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");

        let device_id = [0x44u8; 32];
        let genesis_stored = [0x55u8; 32];
        let genesis_observed = [0x66u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-2".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer2".to_string(),
            genesis_hash: genesis_stored.to_vec(),
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: vec![0u8; 32],
            kyber_public_key: Vec::new(),
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        let orchestrator = PairingOrchestrator::new();
        let err = orchestrator
            .handle_identity_observed("11:22".to_string(), genesis_observed, device_id)
            .await
            .expect_err("expected mismatch error");
        assert!(err.contains("Genesis hash mismatch"));

        // Session should be marked Failed
        let state = orchestrator
            .get_session_status(&device_id)
            .await
            .expect("session exists");
        match state {
            PairingState::Failed(msg) => assert!(msg.contains("Genesis hash mismatch")),
            other => panic!("expected Failed state, got {:?}", other),
        }

        // Status should remain unchanged (not promoted to BleCapable)
        let contact = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "Created");
        assert_eq!(contact.ble_address, None);
    }
}
