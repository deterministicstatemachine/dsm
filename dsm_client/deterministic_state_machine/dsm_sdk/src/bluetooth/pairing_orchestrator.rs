// SPDX-License-Identifier: MIT OR Apache-2.0

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

    /// Open a pairing session for a contact. The pairing loop opens one per
    /// unpaired contact and then asks the radio for what its sessions need
    /// (`follow_pairing_radio`); opening a session requests nothing of the radio.
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

        let self_device_id_array = self_device_id()?;
        let should_advertise = !scans_for(&self_device_id_array, &contact_device_id);

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
                    #[cfg(all(target_os = "android", feature = "jni"))]
                    self.emit_pairing_status(
                        &peer_device_id,
                        "failed",
                        "Genesis hash mismatch",
                        Some(&ble_address),
                    )
                    .await;
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
        #[cfg(all(target_os = "android", feature = "jni"))]
        self.emit_pairing_status(&peer_device_id, "connected", "", Some(&ble_address))
            .await;

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

        let chain_tip = session.peer_chain_tip.clone();

        // NOW persist ble_address to SQLite — the scanner has confirmed receipt.
        // The session completes only once the address is stored: the stored
        // address is what makes the contact paired, and a complete session is
        // not retried.
        let stored = match session.ble_address.clone() {
            Some(address) => crate::storage::client_db::update_contact_ble_status(
                &peer_device_id,
                chain_tip.as_deref(),
                Some(&address),
            )
            .map(|()| address)
            .map_err(|e| format!("the paired address was not stored: {e}")),
            None => Err("no address was seen for the peer".to_string()),
        };
        let ble_address = match stored {
            Ok(address) => address,
            Err(reason) => {
                session.state = PairingState::Failed(reason.clone());
                session.last_activity = Instant::now();
                drop(sessions);
                self.signal_state_change();
                log::warn!(
                    "[PairingOrchestrator] confirm for {:02x}{:02x}... does not complete: {}",
                    peer_device_id[0],
                    peer_device_id[1],
                    reason
                );
                #[cfg(all(target_os = "android", feature = "jni"))]
                self.emit_pairing_status(&peer_device_id, "failed", &reason, None)
                    .await;
                return Err(reason);
            }
        };
        log::info!(
            "[PairingOrchestrator] Contact BLE status persisted on confirm for {:02x}{:02x}... ({})",
            peer_device_id[0],
            peer_device_id[1],
            ble_address
        );

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
        let (peer_device_id, outcome) = {
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

            // Persist ble_address — BlePairingConfirm was delivered to the advertiser.
            // The session completes only once the address is stored: the stored
            // address is what makes the contact paired, and a complete session is
            // not retried.
            let outcome = crate::storage::client_db::update_contact_ble_status(
                &peer_device_id,
                session.peer_chain_tip.as_deref(),
                Some(ble_address),
            )
            .map_err(|e| format!("the paired address was not stored: {e}"));
            match &outcome {
                Ok(()) => {
                    session.state = PairingState::Complete;
                    log::info!(
                        "[PairingOrchestrator] Pairing complete (scanner, finalized) for {:02x}{:02x}...",
                        peer_device_id[0],
                        peer_device_id[1]
                    );
                }
                Err(reason) => {
                    session.state = PairingState::Failed(reason.clone());
                    log::warn!(
                        "[PairingOrchestrator] scanner finalize for {:02x}{:02x}... does not complete: {}",
                        peer_device_id[0],
                        peer_device_id[1],
                        reason
                    );
                }
            }
            session.last_activity = Instant::now();

            (peer_device_id, outcome)
        }; // sessions write-lock released here

        self.signal_state_change();

        #[cfg(all(target_os = "android", feature = "jni"))]
        self.report_scanner_finalize(peer_device_id, &outcome, ble_address)
            .await;
        // Host builds have no frontend to tell.
        #[cfg(not(all(target_os = "android", feature = "jni")))]
        let _ = peer_device_id;

        outcome
    }

    /// Tell the frontend how the scanner's finalize ended: the failure, or the
    /// completed pairing.
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn report_scanner_finalize(
        &self,
        peer_device_id: [u8; 32],
        outcome: &Result<(), String>,
        ble_address: &str,
    ) {
        match outcome {
            Err(reason) => {
                self.emit_pairing_status(&peer_device_id, "failed", reason, Some(ble_address))
                    .await
            }
            Ok(()) => {
                if let Err(e) = self.notify_pairing_complete(&peer_device_id).await {
                    log::warn!(
                        "[PairingOrchestrator] notify_pairing_complete (scanner finalize) failed for {:02x}{:02x}...: {}",
                        peer_device_id[0],
                        peer_device_id[1],
                        e
                    );
                }
            }
        }
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
        #[cfg(all(target_os = "android", feature = "jni"))]
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
    #[cfg(all(target_os = "android", feature = "jni"))]
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

        // The scan this loop has asked the radio for; withdrawn by this loop only.
        let mut scan = ScanRequest::default();

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
            let unpaired: Vec<[u8; 32]> = contacts
                .iter()
                .filter(|c| c.ble_address.is_none())
                .filter_map(|c| <[u8; 32]>::try_from(c.device_id.as_slice()).ok())
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
                    self.follow_pairing_radio(&mut scan, Initiated::default())
                        .await;
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

            let mut initiated = Initiated::default();
            for &device_id in &unpaired {
                if self.loop_stop.load(Ordering::SeqCst) {
                    break;
                }

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
                // (ble_address absent in SQLite) is retried on this pass. A
                // stale in-progress session means the GATT
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
                        initiated.any = true;
                        initiated.scanner |= !should_advertise;
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

            if self.loop_stop.load(Ordering::SeqCst) {
                break;
            }
            self.follow_pairing_radio(&mut scan, initiated).await;

            // Wait for the next state-change event or a periodic transport timeout,
            // whichever arrives first. The timeout ensures that stale sessions that
            // were not detected via a disconnect notification are still re-evaluated
            // within a reasonable window rather than waiting indefinitely.
            let _ = tokio::time::timeout(PAIRING_LOOP_WAKE_TIMEOUT, state_changed).await;
        }

        // Withdraw the loop's scan so it does not linger ("stuck scanning") once
        // the peer has completed pairing. A scan the loop did not request (the
        // transfer scan) is not the loop's to end, and advertising follows the
        // identity.
        withdraw_pairing_scan(&mut scan);

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

    /// Bring the radio in line with the sessions after a pass of the pairing
    /// loop, in order: nothing is spawned, so no request lands after the loop's
    /// last word. Advertising is requested when the pass opened a session (the
    /// peer reads this appliance's identity from its GATT server whichever side
    /// scans); it is the appliance's and is never withdrawn here. The scan
    /// follows [`ScanRequest::step`].
    #[cfg(all(target_os = "android", feature = "jni"))]
    async fn follow_pairing_radio(&self, scan: &mut ScanRequest, initiated: Initiated) {
        if initiated.any {
            match request_radio("startBlePairingAdvertise") {
                Ok(true) => {}
                Ok(false) => {
                    log::warn!("[PairingOrchestrator] The radio refused pairing advertising")
                }
                Err(e) => {
                    log::warn!("[PairingOrchestrator] Pairing advertising not requested: {e}")
                }
            }
        }
        let wanted = match self_device_id() {
            Ok(self_id) => wants_pairing_scan(&self_id, self.sessions.read().await.values()),
            Err(_) => false,
        };
        match scan.step(wanted, initiated.scanner) {
            ScanStep::Start => match request_radio("startBlePairingScan") {
                Ok(accepted) => {
                    *scan = ScanRequest {
                        issued: true,
                        accepted,
                    };
                    log::info!("[PairingOrchestrator] Pairing scan requested: accepted={accepted}");
                }
                Err(e) => {
                    scan.accepted = false;
                    log::warn!("[PairingOrchestrator] Pairing scan not requested: {e}");
                }
            },
            ScanStep::Stop => withdraw_pairing_scan(scan),
            ScanStep::Hold => {}
        }
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

/// Whether this appliance scans for the contact in pairing (the central)
/// rather than advertising to it (the peripheral): the higher device id scans.
/// Exactly one side of a pair scans, so the two never both call connectGatt()
/// on each other, whose crossing connections fail with error 133 or time out
/// on Samsung/Qualcomm stacks.
fn scans_for(self_device_id: &[u8; 32], contact_device_id: &[u8; 32]) -> bool {
    self_device_id > contact_device_id
}

fn self_device_id() -> Result<[u8; 32], String> {
    crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "Self device ID not available".to_string())?
        .try_into()
        .map_err(|_| "Self device ID is not 32 bytes".to_string())
}

/// Whether any session this appliance scans for is still outstanding (neither
/// complete nor failed).
#[cfg(any(test, all(target_os = "android", feature = "jni")))]
fn wants_pairing_scan<'a>(
    self_device_id: &[u8; 32],
    sessions: impl IntoIterator<Item = &'a PairingSession>,
) -> bool {
    sessions.into_iter().any(|s| {
        scans_for(self_device_id, &s.contact_device_id)
            && !matches!(s.state, PairingState::Complete | PairingState::Failed(_))
    })
}

/// What one pass of the pairing loop opened.
#[cfg(all(target_os = "android", feature = "jni"))]
#[derive(Debug, Default, Clone, Copy)]
struct Initiated {
    /// A session, of either role.
    any: bool,
    /// A session this appliance scans for.
    scanner: bool,
}

/// The pairing loop's scan request as the radio holds it
/// (`BleCoordinator.pairingScanRequested`): it stands from the loop's start
/// until the loop's stop, whatever the radio answered.
#[cfg(any(test, all(target_os = "android", feature = "jni")))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ScanRequest {
    /// The radio holds a request from this loop.
    issued: bool,
    /// The radio's answer to the last start: a scan runs (or already ran).
    accepted: bool,
}

#[cfg(any(test, all(target_os = "android", feature = "jni")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStep {
    Start,
    Stop,
    Hold,
}

#[cfg(any(test, all(target_os = "android", feature = "jni")))]
impl ScanRequest {
    /// What the loop asks of the radio, given whether a session it scans for
    /// is outstanding. Between requests the scan is the radio's: it stops the
    /// scan to connect and resumes it after its own failures, so a standing,
    /// accepted request is issued again only for a session the pass opened (a
    /// new contact, or one reopened after it went stale or failed), and a
    /// refused start is retried. A scan the loop did not request is never
    /// stopped.
    fn step(self, wanted: bool, initiated_scanner: bool) -> ScanStep {
        if wanted {
            if !self.issued || !self.accepted || initiated_scanner {
                ScanStep::Start
            } else {
                ScanStep::Hold
            }
        } else if self.issued {
            ScanStep::Stop
        } else {
            ScanStep::Hold
        }
    }
}

/// Withdraw the loop's scan request, if it made one. An undelivered withdrawal
/// leaves the request standing, to be withdrawn again.
#[cfg(all(target_os = "android", feature = "jni"))]
fn withdraw_pairing_scan(scan: &mut ScanRequest) {
    if !scan.issued {
        return;
    }
    match request_radio("stopBlePairingScan") {
        Ok(stopped) => {
            *scan = ScanRequest::default();
            log::info!("[PairingOrchestrator] Pairing scan withdrawn: a scan stopped={stopped}");
        }
        Err(e) => log::warn!("[PairingOrchestrator] Pairing scan withdrawal not delivered: {e}"),
    }
}

/// One pairing request to the Android BLE layer (`Unified.<method>`, `()Z`),
/// and the radio's answer.
#[cfg(all(target_os = "android", feature = "jni"))]
fn request_radio(method: &'static str) -> Result<bool, String> {
    use crate::jni::jni_common::{find_class_with_app_loader, get_java_vm_borrowed};

    let vm = get_java_vm_borrowed().ok_or_else(|| "JavaVM not initialized".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("Failed to attach JNI thread: {e}"))?;
    let class = find_class_with_app_loader(&mut env, "com/dsm/wallet/bridge/Unified")
        .map_err(|e| format!("Failed to find Unified class: {e:?}"))?;
    env.call_static_method(&class, method, "()Z", &[])
        .and_then(|r| r.z())
        .map_err(|e| format!("{method} failed: {e:?}"))
}

/// Where BLE pairing with a contact stands, for the contact list: paired once
/// the contact holds the address pairing confirmed (a session completes only
/// once that address is stored); otherwise the phase of its pairing session,
/// or idle when there is none.
pub fn contact_pairing_phase(
    holds_address: bool,
    session: Option<&PairingState>,
) -> dsm::types::proto::ContactPairingPhase {
    use dsm::types::proto::ContactPairingPhase as Phase;
    if holds_address {
        return Phase::Paired;
    }
    match session {
        None => Phase::Idle,
        Some(PairingState::WaitingForConnection) => Phase::Searching,
        Some(
            PairingState::ReadingIdentity
            | PairingState::ExchangingChainTips
            | PairingState::AwaitingConfirm
            | PairingState::ConfirmSent
            | PairingState::UpdatingStatus,
        ) => Phase::Connected,
        Some(PairingState::Complete) => Phase::Paired,
        Some(PairingState::Failed(_)) => Phase::Retrying,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::storage::client_db;
    use crate::test_support::two_device::Pair;

    /// A device id as a wallet derives its own: the test mnemonic's BIP-39
    /// seed through the Genesis v3 chain on the beta network.
    fn device_id_of(entropy: u8) -> [u8; 32] {
        let seed = bip39::Mnemonic::parse(crate::economic_fixtures::test_mnemonic(entropy))
            .expect("a mnemonic")
            .to_seed("");
        crate::sdk::identity_presentation::derive_own_authority_context(
            &seed,
            crate::sdk::identity_presentation::OwnerIdentityInputs::beta(
                dsm::economic::register::BETA_NETWORK_ID,
            ),
        )
        .expect("an identity")
        .devid
    }

    /// `n` derived device ids, in ascending order.
    fn ascending_device_ids(n: u8) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = (1..=n).map(device_id_of).collect();
        ids.sort();
        ids
    }

    fn session_with(contact: [u8; 32], state: PairingState) -> PairingSession {
        PairingSession {
            contact_device_id: contact,
            state,
            ble_address: None,
            peer_genesis_hash: None,
            peer_chain_tip: None,
            last_activity: Instant::now(),
        }
    }

    const STANDING: ScanRequest = ScanRequest {
        issued: true,
        accepted: true,
    };

    #[test]
    fn the_higher_device_id_scans_and_the_lower_advertises() {
        let ids = ascending_device_ids(2);
        let (low, high) = (ids[0], ids[1]);
        assert!(scans_for(&high, &low));
        assert!(!scans_for(&low, &high));
    }

    #[test]
    fn the_scan_is_wanted_while_a_session_this_appliance_scans_for_is_outstanding() {
        let ids = ascending_device_ids(4);
        let me = ids[2];
        let (scanned, also_scanned, advertised_to) = (ids[0], ids[1], ids[3]);
        assert!(!wants_pairing_scan(&me, &[]));
        assert!(!wants_pairing_scan(
            &me,
            &[session_with(
                advertised_to,
                PairingState::WaitingForConnection
            )]
        ));
        for state in [
            PairingState::WaitingForConnection,
            PairingState::ReadingIdentity,
            PairingState::ExchangingChainTips,
            PairingState::AwaitingConfirm,
            PairingState::ConfirmSent,
            PairingState::UpdatingStatus,
        ] {
            assert!(
                wants_pairing_scan(&me, &[session_with(scanned, state.clone())]),
                "{state:?}"
            );
        }
        assert!(!wants_pairing_scan(
            &me,
            &[session_with(scanned, PairingState::Complete)]
        ));
        assert!(!wants_pairing_scan(
            &me,
            &[session_with(scanned, PairingState::Failed("link".into()))]
        ));
        assert!(wants_pairing_scan(
            &me,
            &[
                session_with(scanned, PairingState::Complete),
                session_with(also_scanned, PairingState::WaitingForConnection),
            ]
        ));
    }

    /// Bluetooth back on: the new loop holds no request, and its sessions are
    /// still fresh, so no pass reopens them. The scan is requested anyway.
    #[test]
    fn a_loop_holding_no_request_requests_the_scan_its_sessions_want() {
        assert_eq!(ScanRequest::default().step(true, false), ScanStep::Start);
    }

    #[test]
    fn the_loop_never_stops_a_scan_it_did_not_request() {
        assert_eq!(ScanRequest::default().step(false, false), ScanStep::Hold);
    }

    /// The radio stopped the scan to connect; asking again would scan over the
    /// handshake it is making.
    #[test]
    fn a_standing_accepted_request_leaves_the_scan_to_the_radio() {
        assert_eq!(STANDING.step(true, false), ScanStep::Hold);
    }

    /// A contact whose session went stale while the radio's scan was stopped
    /// for another contact's connect is reopened, and must be discovered.
    #[test]
    fn a_session_the_pass_opened_is_asked_for_again() {
        assert_eq!(STANDING.step(true, true), ScanStep::Start);
    }

    #[test]
    fn a_refused_start_is_asked_for_again() {
        let refused = ScanRequest {
            issued: true,
            accepted: false,
        };
        assert_eq!(refused.step(true, false), ScanStep::Start);
    }

    #[test]
    fn the_loop_withdraws_its_request_once_no_session_wants_it() {
        for accepted in [true, false] {
            let request = ScanRequest {
                issued: true,
                accepted,
            };
            assert_eq!(request.step(false, false), ScanStep::Stop);
        }
    }

    #[tokio::test]
    async fn test_pairing_session_lifecycle() {
        let orchestrator = PairingOrchestrator::new();
        let device_id = device_id_of(1);

        // Check no session initially
        assert!(orchestrator.get_session_status(&device_id).await.is_none());

        // Cancel on non-existent session should be safe
        orchestrator.cancel_pairing(&device_id).await;
    }

    #[tokio::test]
    async fn test_session_state_transitions() {
        let orchestrator = PairingOrchestrator::new();
        let device_id = device_id_of(1);

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

    /// A session opens for a contact on a device with an identity: A's
    /// contact B, both created, booted and added to each other as production
    /// does it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn test_initiate_pairing_creates_session() {
        let pair = Pair::boot(0, 0).await;
        pair.a.enter();
        let orchestrator = PairingOrchestrator::new();
        orchestrator
            .initiate_pairing(pair.b.device_id)
            .await
            .expect("initiate");
        assert_eq!(
            orchestrator.get_session_status(&pair.b.device_id).await,
            Some(PairingState::WaitingForConnection)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn test_identity_observed_success_updates_status() {
        let pair = Pair::boot(0, 0).await;
        let (a, b) = (&pair.a, &pair.b);
        a.enter();
        let address = "AA:BB:CC:00:00:0B";

        let orchestrator = PairingOrchestrator::new();
        // No explicit initiate; observe B's identity directly.
        orchestrator
            .handle_identity_observed(address.to_string(), b.genesis, b.device_id)
            .await
            .expect("identity observed ok");

        // Session should NOT be complete yet; mutual confirmation (PAIR1/PAIR2)
        // is required before finalization.
        let status = orchestrator.get_session_status(&b.device_id).await;
        assert_eq!(status, Some(PairingState::ExchangingChainTips));

        // Contact status should be promoted to BleCapable but ble_address must NOT
        // be written yet — we defer that to the ACK so the pairing loop on the
        // initiator side stays alive until PAIR2 arrives.
        let contact = client_db::get_contact_by_device_id(&b.device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "BleCapable");
        assert_eq!(
            contact.ble_address, None,
            "ble_address must not be set until bilateral ACK"
        );

        // Now the mutual handshake completes by receiving PAIR2.
        orchestrator
            .handle_pairing_ack(b.device_id, None, "")
            .await
            .expect("ack transitions to ConfirmSent");
        // Scanner is ConfirmSent — ble_address not persisted until confirm delivered.
        let status2 = orchestrator.get_session_status(&b.device_id).await;
        assert_eq!(status2, Some(PairingState::ConfirmSent));

        // The BlePairingConfirm GATT write ACK (onCharacteristicWrite → finalize).
        orchestrator
            .finalize_scanner_pairing_by_address(address)
            .await
            .expect("finalize after confirm delivery");
        let status3 = orchestrator.get_session_status(&b.device_id).await;
        assert_eq!(status3, Some(PairingState::Complete));

        // ble_address must be committed to SQLite now that bilateral ACK is done.
        let contact2 = client_db::get_contact_by_device_id(&b.device_id)
            .expect("get contact post-ack")
            .expect("exists post-ack");
        assert_eq!(
            contact2.ble_address.as_deref(),
            Some(address),
            "ble_address must be set after scanner finalization"
        );
    }

    /// An identity read that names B's device id with a genesis that is not
    /// B's (here A's own, a real genesis of another device) pairs nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn test_identity_observed_genesis_mismatch_fails() {
        let pair = Pair::boot(0, 0).await;
        let (a, b) = (&pair.a, &pair.b);
        a.enter();
        let before = client_db::get_contact_by_device_id(&b.device_id)
            .expect("get contact")
            .expect("exists");

        let orchestrator = PairingOrchestrator::new();
        let err = orchestrator
            .handle_identity_observed("AA:BB:CC:00:00:0B".to_string(), a.genesis, b.device_id)
            .await
            .expect_err("expected mismatch error");
        assert!(err.contains("Genesis hash mismatch"));

        let state = orchestrator
            .get_session_status(&b.device_id)
            .await
            .expect("session exists");
        match state {
            PairingState::Failed(msg) => assert!(msg.contains("Genesis hash mismatch")),
            other => panic!("expected Failed state, got {:?}", other),
        }

        // The contact is left exactly as it was (not promoted to BleCapable).
        let after = client_db::get_contact_by_device_id(&b.device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(after.status, before.status);
        assert_eq!(after.ble_address, None);
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
                peer_genesis_hash: None,
                peer_chain_tip: None,
                last_activity: Instant::now(),
            },
        );
    }

    /// A pairing completes only once the contact's address is stored: the
    /// stored address is what makes the contact paired, and a complete session
    /// is never retried. The advertiser's confirm used to complete, and report
    /// the contact paired, when the store failed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_confirm_that_cannot_store_the_address_does_not_complete() {
        let pair = Pair::boot(0, 0).await;
        pair.a.enter();
        let orchestrator = PairingOrchestrator::new();
        let address = "AA:00:00:00:00:71";

        // A derived device that is no contact of A: no row to store the address on.
        let stranger = device_id_of(1);
        session_in(
            &orchestrator,
            stranger,
            PairingState::AwaitingConfirm,
            address,
        )
        .await;
        let refused = orchestrator
            .handle_pairing_confirm(stranger)
            .await
            .expect_err("the address was not stored");
        assert!(refused.contains("not stored"), "{refused}");
        assert!(matches!(
            orchestrator.get_session_status(&stranger).await,
            Some(PairingState::Failed(_))
        ));

        let peer = pair.b.device_id;
        session_in(&orchestrator, peer, PairingState::AwaitingConfirm, address).await;
        orchestrator
            .handle_pairing_confirm(peer)
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

    /// As the advertiser's confirm: the scanner's finalize completes only once
    /// the address is stored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_scanner_finalize_that_cannot_store_the_address_does_not_complete() {
        let pair = Pair::boot(0, 0).await;
        pair.a.enter();
        let orchestrator = PairingOrchestrator::new();
        let address = "AA:00:00:00:00:72";

        let stranger = device_id_of(1);
        session_in(&orchestrator, stranger, PairingState::ConfirmSent, address).await;
        let refused = orchestrator
            .finalize_scanner_pairing_by_address(address)
            .await
            .expect_err("the address was not stored");
        assert!(refused.contains("not stored"), "{refused}");
        assert!(matches!(
            orchestrator.get_session_status(&stranger).await,
            Some(PairingState::Failed(_))
        ));

        let peer = pair.b.device_id;
        session_in(&orchestrator, peer, PairingState::ConfirmSent, address).await;
        orchestrator
            .finalize_scanner_pairing_by_address(address)
            .await
            .expect("completes");
        assert_eq!(
            orchestrator.get_session_status(&peer).await,
            Some(PairingState::Complete)
        );
    }

    /// The phase the contact list states: paired once the address is stored,
    /// else the session's phase, else idle.
    #[test]
    fn a_contacts_pairing_phase_is_the_sdks_own() {
        use dsm::types::proto::ContactPairingPhase as Phase;
        assert_eq!(contact_pairing_phase(true, None), Phase::Paired);
        assert_eq!(contact_pairing_phase(false, None), Phase::Idle);
        assert_eq!(
            contact_pairing_phase(false, Some(&PairingState::WaitingForConnection)),
            Phase::Searching
        );
        for state in [
            PairingState::ReadingIdentity,
            PairingState::ExchangingChainTips,
            PairingState::AwaitingConfirm,
            PairingState::ConfirmSent,
            PairingState::UpdatingStatus,
        ] {
            assert_eq!(contact_pairing_phase(false, Some(&state)), Phase::Connected);
        }
        assert_eq!(
            contact_pairing_phase(false, Some(&PairingState::Failed("link".into()))),
            Phase::Retrying
        );
        assert_eq!(
            contact_pairing_phase(false, Some(&PairingState::Complete)),
            Phase::Paired
        );
    }
}
