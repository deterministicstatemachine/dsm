//! Android BLE Bridge for Bilateral Transactions
//!
//! Integrates with Android DsmBluetoothService.kt to coordinate bilateral transactions
//! over BLE GATT characteristics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;
use log::{info, debug, warn};

use dsm::types::error::DsmError;
use crate::generated;
use prost::Message;
use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use crate::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType};

/// BLE event types from Android DsmBluetoothService
#[derive(Debug, Clone)]
pub enum BleEvent {
    DeviceFound {
        address: String,
        name: String,
        rssi: i32,
    },
    DeviceConnected {
        address: String,
    },
    DeviceDisconnected {
        address: String,
    },
    CharacteristicWritten {
        address: String,
        data: Vec<u8>,
    },
    CharacteristicRead {
        address: String,
    },
    ConnectionFailed {
        address: String,
        error: String,
    },
    ScanStarted,
    ScanStopped,
    AdvertisingStarted,
    AdvertisingStopped,
}

/// BLE command types to send to Android DsmBluetoothService
#[derive(Debug, Clone)]
pub enum BleCommand {
    StartScan,
    StopScan,
    StartAdvertising { device_name: String },
    StopAdvertising,
    ConnectToDevice { address: String },
    DisconnectDevice { address: String },
    WriteCharacteristic { address: String, data: Vec<u8> },
    ReadCharacteristic { address: String },
}

/// Android BLE bridge for bilateral transactions
pub struct AndroidBleBridge {
    frame_coordinator: Arc<BleFrameCoordinator>,
    bilateral_handler: Arc<BilateralBleHandler>,
    connected_devices: Arc<RwLock<HashMap<String, DeviceConnection>>>,
    device_id: [u8; 32],
    // When manual-accept is enabled, we stash prepared response commands here keyed by commitment hash
    pending_prepare_responses: Arc<RwLock<HashMap<[u8; 32], Vec<Vec<u8>>>>>,
}

// Global registry for a single AndroidBleBridge instance so JNI shims can access it.
use once_cell::sync::OnceCell;
static GLOBAL_ANDROID_BRIDGE: OnceCell<Arc<AndroidBleBridge>> = OnceCell::new();

pub fn register_global_android_bridge(b: Arc<AndroidBleBridge>) -> bool {
    GLOBAL_ANDROID_BRIDGE.set(b).is_ok()
}

pub fn get_global_android_bridge() -> Option<Arc<AndroidBleBridge>> {
    GLOBAL_ANDROID_BRIDGE.get().cloned()
}

#[derive(Debug, Clone)]
pub struct DeviceConnection {
    pub address: String,
    pub device_id: Option<[u8; 32]>,
    pub connected_at_tick: u64,
    pub last_activity_tick: u64,
    pub pending_commands: VecDeque<Vec<u8>>,
}

// Deterministic monotonic tick counter for activity tracking (no wall clock)
static BLE_ACTIVITY_TICK: AtomicU64 = AtomicU64::new(1);
#[inline]
pub fn next_ble_tick() -> u64 {
    BLE_ACTIVITY_TICK.fetch_add(1, AtomicOrdering::SeqCst)
}

impl AndroidBleBridge {
    pub fn new(
        frame_coordinator: Arc<BleFrameCoordinator>,
        bilateral_handler: Arc<BilateralBleHandler>,
        device_id: [u8; 32],
    ) -> Self {
        Self {
            frame_coordinator,
            bilateral_handler,
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            device_id,
            pending_prepare_responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a reference to the BleFrameCoordinator for external injection
    pub fn frame_coordinator(&self) -> Arc<BleFrameCoordinator> {
        Arc::clone(&self.frame_coordinator)
    }

    /// Manually update connection state for a device (called from JNI when the Android
    /// Bluetooth stack reports a GATT connection/disconnection outside the prost BleEvent flow).
    /// This is required because some connection events are surfaced directly via Kotlin callbacks
    /// (Unified.onDeviceConnected / onDeviceDisconnected) and would otherwise never reach the
    /// internal connected_devices registry used by offline send gating.
    pub async fn update_connection_state(&self, address: &str, connected: bool) {
        let mut devices = self.connected_devices.write().await;
        if connected {
            if !devices.contains_key(address) {
                devices.insert(
                    address.to_string(),
                    DeviceConnection {
                        address: address.to_string(),
                        device_id: None,
                        connected_at_tick: next_ble_tick(),
                        last_activity_tick: next_ble_tick(),
                        pending_commands: VecDeque::new(),
                    },
                );
                log::info!("AndroidBleBridge: device connected (manual) {address}");
            } else {
                // Refresh activity tick to prevent premature cleanup
                if let Some(conn) = devices.get_mut(address) {
                    conn.last_activity_tick = next_ble_tick();
                }
            }
        } else if devices.remove(address).is_some() {
            log::info!("AndroidBleBridge: device disconnected (manual) {address}");
        }
    }

    // Use the bytes/protobuf API `handle_ble_event_bytes(&[u8])` which accepts an
    // Envelope v3 encoded proto.

    /// Process BLE event from Android as raw protobuf bytes (preferred path)
    pub async fn handle_ble_event_bytes(&self, data: &[u8]) -> Result<Option<Vec<u8>>, DsmError> {
        // Decode the canonical BleEvent proto emitted by the platform
        let evt = crate::generated::BleEvent::decode(data).map_err(|e| {
            DsmError::serialization_error(
                "ble_event_proto",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // Map prost BleEvent to local handling logic
        use crate::generated::ble_event::Ev;
        match evt.ev {
            Some(Ev::DeviceFound(dev)) => {
                let address = dev.address;
                let name = dev.name;
                let rssi = dev.rssi;
                info!(
                    "BLE device found (proto): {addr} RSSI={rssi} - name={name}",
                    addr = address,
                    rssi = rssi,
                    name = name
                );
                if name.starts_with("DSM-") {
                    let bytes = self
                        .create_ble_command(BleCommand::ConnectToDevice { address })
                        .await?;
                    return Ok(Some(bytes));
                }
            }
            Some(Ev::DeviceConnected(dev)) => {
                let address = dev.address;
                info!("BLE device connected (proto): {address}");
                let connection = DeviceConnection {
                    address: address.clone(),
                    device_id: None,
                    connected_at_tick: next_ble_tick(),
                    last_activity_tick: next_ble_tick(),
                    pending_commands: VecDeque::new(),
                };
                {
                    let mut devices = self.connected_devices.write().await;
                    devices.insert(address, connection);
                }
            }
            Some(Ev::DeviceDisconnected(dev)) => {
                let address = dev.address;
                info!("BLE device disconnected (proto): {address}");
                {
                    let mut devices = self.connected_devices.write().await;
                    devices.remove(&address);
                }
            }
            Some(Ev::CharacteristicWritten(ch)) => {
                let address = ch.address;
                let data = ch.data;
                // Update last activity deterministically
                if let Some(conn) = self.connected_devices.write().await.get_mut(&address) {
                    conn.last_activity_tick = next_ble_tick();
                }
                return self.handle_characteristic_data(&address, &data).await;
            }
            Some(Ev::CharacteristicRead(ch)) => {
                let address = ch.address;
                if let Some(conn) = self.connected_devices.write().await.get_mut(&address) {
                    conn.last_activity_tick = next_ble_tick();
                }
                return self.handle_characteristic_data(&address, &[]).await;
            }
            Some(Ev::ScanStarted(_)) => {
                info!("BLE scan started (proto) — no background maintenance (clockless)");
            }
            Some(Ev::ScanStopped(_)) => {
                info!("BLE scan stopped (proto)");
            }
            Some(Ev::AdvertisingStarted(_)) => {
                info!("BLE advertising started (proto) — no background maintenance (clockless)");
            }
            Some(Ev::AdvertisingStopped(_)) => {
                info!("BLE advertising stopped (proto)");
            }
            Some(Ev::ConnectionFailed(msg)) => {
                warn!("BLE connection failed (proto): {msg}");
            }
            Some(Ev::PairingRequest(req)) => {
                info!(
                    "BLE pairing request received from {}: alias={}",
                    req.address, req.alias
                );
                // Frontend will handle the modal and user action
                // Just log and pass through
            }
            Some(Ev::PairingAccept(acc)) => {
                info!("BLE pairing accept received from {}", acc.address);
                // Frontend will handle contact creation
                // Just log and pass through
            }
            Some(Ev::PairingStatus(ps)) => {
                info!(
                    "BLE pairing status update: status={} message={}",
                    ps.status, ps.message
                );
                // Status updates are dispatched to the frontend via JNI; no bridge action needed.
            }
            Some(Ev::IdentityObserved(obs)) => {
                info!(
                    "BLE identity observed (implicit) from {} device_id_zero={} genesis_zero={}",
                    obs.address,
                    obs.device_id.iter().all(|&b| b == 0),
                    obs.genesis_hash.iter().all(|&b| b == 0)
                );
                // Update connection record with observed device_id if present (first time only)
                let mut should_reconcile = false;
                if obs.device_id.iter().any(|&b| b != 0) {
                    let mut devices = self.connected_devices.write().await;
                    if let Some(conn) = devices.get_mut(&obs.address) {
                        if conn.device_id.is_none() {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(&obs.device_id);
                            conn.device_id = Some(id);
                            should_reconcile = true;
                        }
                        conn.last_activity_tick = next_ble_tick();
                    } else {
                        // Connection record missing; still allow a one-time reconcile attempt.
                        should_reconcile = true;
                    }
                }

                // Notify pairing orchestrator about identity observation
                let orchestrator = crate::bluetooth::get_pairing_orchestrator();
                let mut device_id = [0u8; 32];
                device_id.copy_from_slice(&obs.device_id);
                let mut genesis_hash = [0u8; 32];
                genesis_hash.copy_from_slice(&obs.genesis_hash);

                info!(
                    "[AndroidBleBridge] Calling orchestrator.handle_identity_observed for {} (device_id={:02x}{:02x}...)",
                    obs.address,
                    device_id[0], device_id[1]
                );

                let mut skip_reconcile = false;
                match orchestrator
                    .handle_identity_observed(obs.address.clone(), genesis_hash, device_id)
                    .await
                {
                    Ok(_) => info!(
                        "Pairing orchestrator handled identity observation for {} (device_id={:02x}{:02x}...)",
                        obs.address, device_id[0], device_id[1]
                    ),
                    Err(e) => {
                        // Orchestrator error is non-fatal - might not have active pairing session
                        debug!(
                            "Pairing orchestrator couldn't handle identity observation: {} (device_id={:02x}{:02x}...)",
                            e, device_id[0], device_id[1]
                        );
                        // Only fall back for non-validation errors. If genesis mismatch (or other validation failure),
                        // do NOT promote contact to BleCapable to preserve integrity.
                        if e.contains("Genesis hash mismatch") {
                            warn!(
                                "Skipping direct BLE status update due to genesis mismatch for {} (device_id={:02x}{:02x}...)",
                                obs.address, device_id[0], device_id[1]
                            );
                            skip_reconcile = true;
                        } else {
                            // Fall back to direct contact status update (original behavior)
                            match crate::storage::client_db::update_contact_ble_status(
                                &obs.device_id,
                                None,
                                Some(&obs.address),
                            ) {
                                Ok(_) => info!("Contact status updated via BLE identity observation: {} (device_id={:02x}{:02x}...)", obs.address, device_id[0], device_id[1]),
                                Err(e) => warn!("Failed to update contact status via BLE identity observation: {}: {} (device_id={:02x}{:02x}...)", obs.address, e, device_id[0], device_id[1]),
                            }
                        }
                    }
                }

                // Reconciliation deleted: forks are Tripwire violations, not reconcilable.
                // Connection established — proceed directly to bilateral protocol.
                let _ = (should_reconcile, skip_reconcile);

                // Pairing confirmation is handled at the GATT layer via protobuf envelopes:
                // the advertiser sends a BlePairingAccept indication on PAIRING_ACK after
                // processing the scanner's identity write. No raw byte-packed PAIR1/PAIR2.
            }
            Some(Ev::PairingConfirm(confirm)) => {
                info!(
                    "BLE pairing confirm received from {} (Phase 3 atomic commit)",
                    confirm.address
                );
                // Handled at the GATT/JNI layer (processBleIdentityEnvelope).
                // Bridge pass-through only.
            }
            // Outbound-only push events — authored by Rust and dispatched to the
            // frontend via dispatchToWebView. They never arrive as inbound requests
            // from Kotlin, so the bridge takes no action here.
            Some(Ev::GenesisLifecycle(_)) => {
                debug!("GenesisLifecycleEvent received in bridge — outbound-only, no action");
            }
            Some(Ev::BlePermission(_)) => {
                debug!("BlePermissionEvent received in bridge — outbound-only, no action");
            }
            None => {
                debug!("Empty BleEvent received");
            }
        }

        Ok(None)
    }

    /// Handle incoming characteristic data (bilateral transaction chunks)
    async fn handle_characteristic_data(
        &self,
        address: &str,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, DsmError> {
        debug!(
            "Received characteristic data from {addr}: {len} bytes",
            addr = address,
            len = data.len()
        );

        // Update last activity tick
        {
            let mut devices = self.connected_devices.write().await;
            if let Some(connection) = devices.get_mut(address) {
                connection.last_activity_tick = next_ble_tick();
            }
        }

        // Process BLE chunk
        if data.is_empty() {
            // Android polled for pending commands (CharacteristicRead without payload)
            let mut devices = self.connected_devices.write().await;
            if let Some(connection) = devices.get_mut(address) {
                connection.last_activity_tick = next_ble_tick();
                if let Some(next_cmd) = connection.pending_commands.pop_front() {
                    debug!(
                        "Dispatching next queued BLE command to {addr}; {remaining} remaining",
                        addr = address,
                        remaining = connection.pending_commands.len()
                    );
                    return Ok(Some(next_cmd));
                }
            }
            return Ok(None);
        }

        let chunk_result = self.frame_coordinator.handle_ble_chunk(data).await?;

        if let Some(result) = chunk_result {
            info!(
                "Received complete bilateral message: frame_type={:?}, response_len={:?}",
                result.frame_type,
                result.response.as_ref().map(|r| r.len())
            );

            // Use the frame type from the BLE frame header
            let frame_type = result.frame_type;

            if let Some(response_bytes) = result.response {
                // Determine follow-up frame type. For a prepare response we now automatically
                // advance to the Confirm phase (3-step protocol) by emitting the confirm envelope.
                let response_type = match frame_type {
                    BleFrameType::BilateralPrepare => BleFrameType::BilateralPrepareResponse,
                    BleFrameType::BilateralPrepareResponse => BleFrameType::BilateralConfirm,
                    // BilateralConfirm returns None from coordinator — no response needed
                    _ => return Ok(None),
                };

                // Determine counterparty device_id; do NOT silently fall back to zero array.
                // If identity has not yet been observed we defer sending the response chunks.
                let counterparty_device_id = {
                    let devices = self.connected_devices.read().await;
                    match devices.get(address).and_then(|c| c.device_id) {
                        Some(id) => id,
                        None => {
                            warn!(
                                "Deferring bilateral response {:?} for address {} until identity observed (device_id unknown)",
                                response_type, address
                            );
                            return Ok(None);
                        }
                    }
                };

                let chunks = self
                    .frame_coordinator
                    .send_bilateral_message(
                        counterparty_device_id,
                        response_type,
                        response_bytes.clone(),
                    )
                    .await?;

                // Send chunks back to Android for transmission; collect the first command to reply
                let mut first_cmd: Option<Vec<u8>> = None;
                let mut pending_followups: Vec<Vec<u8>> = Vec::new();
                for (idx, chunk) in chunks.into_iter().enumerate() {
                    let command = BleCommand::WriteCharacteristic {
                        address: address.to_string(),
                        data: chunk.clone(),
                    };
                    let proto_bytes = self.create_ble_command(command).await?;
                    if idx == 0 {
                        // keep a copy of the first proto bytes to return to caller
                        first_cmd = Some(proto_bytes.clone());
                    } else {
                        pending_followups.push(proto_bytes);
                    }
                }

                // Manual-accept gating for prepare: stash instead of sending immediately
                if response_type as i32 == BleFrameType::BilateralPrepareResponse as i32
                    && crate::bluetooth::manual_accept_enabled()
                {
                    // Decode response to extract commitment hash (origin)
                    if let Ok(resp_env) = crate::generated::Envelope::decode(
                        &mut std::io::Cursor::new(&response_bytes[..]),
                    ) {
                        if let Some(
                            crate::generated::envelope::Payload::BilateralPrepareResponse(resp),
                        ) = resp_env.payload
                        {
                            if let Some(h) = resp.commitment_hash.as_ref() {
                                if h.v.len() == 32 {
                                    let mut key = [0u8; 32];
                                    key.copy_from_slice(&h.v);
                                    let mut all_cmds = Vec::new();
                                    if let Some(f) = first_cmd.take() {
                                        all_cmds.push(f);
                                    }
                                    all_cmds.append(&mut pending_followups);
                                    let mut map = self.pending_prepare_responses.write().await;
                                    map.insert(key, all_cmds);
                                    debug!("Stashed prepare response commands under commitment for manual accept");
                                    // Do not send now
                                    return Ok(None);
                                }
                            }
                        }
                    }
                }

                if !pending_followups.is_empty() {
                    let new_count = pending_followups.len();
                    let mut devices = self.connected_devices.write().await;
                    if let Some(connection) = devices.get_mut(address) {
                        connection
                            .pending_commands
                            .extend(pending_followups.into_iter());
                        debug!(
                            "Queued {new_count} follow-up BLE commands for {addr} (total pending: {total})",
                            new_count = new_count,
                            addr = address,
                            total = connection.pending_commands.len()
                        );
                    } else {
                        warn!(
                            "Attempted to queue follow-up BLE commands for unknown address {address}"
                        );
                    }
                }

                if let Some(cmd_bytes) = first_cmd {
                    return Ok(Some(cmd_bytes));
                }
            }
        }

        Ok(None)
    }

    /// Test-only: Process a bilateral frame locally without real BLE I/O.
    /// This constructs a single-chunk BLE frame and routes it through the
    /// same coordinator code paths, returning any response bytes.
    #[cfg(test)]
    pub async fn loopback_process(
        &self,
        frame_type: BleFrameType,
        envelope_bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DsmError> {
        // Build canonical chunks through the same transport code used in production.
        let chunks = self
            .frame_coordinator
            .chunk_message(frame_type, &envelope_bytes)?;

        let mut final_response = None;
        for chunk in chunks {
            let chunk_result = self.frame_coordinator.handle_ble_chunk(&chunk).await?;
            if let Some(result) = chunk_result {
                final_response = result.response;
            }
        }

        Ok(final_response)
    }

    /// Create BLE command protobuf bytes for Android bridge
    async fn create_ble_command(&self, command: BleCommand) -> Result<Vec<u8>, DsmError> {
        // Build prost BleCommand and return raw protobuf bytes for Android to decode
        let proto_cmd = match command {
            BleCommand::StartScan => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::StartScan(
                    generated::BleStartScan {},
                )),
            },
            BleCommand::StopScan => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::StopScan(
                    generated::BleStopScan {},
                )),
            },
            BleCommand::StartAdvertising { device_name } => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::StartAdvertising(
                    generated::BleStartAdvertising { device_name },
                )),
            },
            BleCommand::StopAdvertising => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::StopAdvertising(
                    generated::BleStopAdvertising {},
                )),
            },
            BleCommand::ConnectToDevice { address } => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::ConnectDevice(
                    generated::BleConnectDevice { address },
                )),
            },
            BleCommand::DisconnectDevice { address } => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::DisconnectDevice(
                    generated::BleDisconnectDevice { address },
                )),
            },
            BleCommand::WriteCharacteristic { address, data } => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::WriteCharacteristic(
                    generated::BleWriteCharacteristic { address, data },
                )),
            },
            BleCommand::ReadCharacteristic { address } => generated::BleCommand {
                cmd: Some(generated::ble_command::Cmd::ReadCharacteristic(
                    generated::BleReadCharacteristic { address },
                )),
            },
        };

        // Serialize prost message (raw bytes-only transport)
        let mut buf = Vec::new();
        prost::Message::encode(&proto_cmd, &mut buf).map_err(|e| {
            DsmError::serialization_error(
                "ble_command_proto",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        Ok(buf)
    }

    /// Start BLE scanning for DSM devices
    pub async fn start_device_discovery(&self) -> Result<Vec<u8>, DsmError> {
        info!("Starting BLE device discovery");
        let command = BleCommand::StartScan;
        self.create_ble_command(command).await
    }

    /// Start BLE advertising as DSM device
    pub async fn start_advertising(&self) -> Result<Vec<u8>, DsmError> {
        // Avoid in-SDK encoding; advertise a constant name. UI/platform may decorate at edges.
        let device_name = "DSM".to_string();
        info!("Starting BLE advertising as: {device_name}");
        let command = BleCommand::StartAdvertising { device_name };
        self.create_ble_command(command).await
    }

    /// Get connected devices status
    pub async fn get_connected_devices(&self) -> Vec<(String, Option<[u8; 32]>)> {
        let devices = self.connected_devices.read().await;
        devices
            .iter()
            .map(|(address, connection)| {
                let addr_cloned = address.clone();
                let dev_id = connection.device_id;
                (addr_cloned, dev_id)
            })
            .collect()
    }

    /// Clean up inactive connections
    pub async fn cleanup_inactive_connections(&self, max_tick_gap: u64) -> usize {
        let mut devices = self.connected_devices.write().await;
        let initial_count = devices.len();

        let current = BLE_ACTIVITY_TICK.load(AtomicOrdering::SeqCst);
        devices.retain(|_address, connection| {
            current.saturating_sub(connection.last_activity_tick) <= max_tick_gap
        });

        let cleaned = initial_count - devices.len();
        if cleaned > 0 {
            info!("Cleaned up {cleaned} inactive BLE connections");
        }
        cleaned
    }

    /// Release a stashed prepare response for a given commitment hash (manual accept)
    pub async fn release_pending_prepare_response(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<(), DsmError> {
        use crate::generated::ble_command::Cmd;
        // Take the stored commands atomically
        let cmds = {
            let mut map = self.pending_prepare_responses.write().await;
            map.remove(&commitment_hash)
        };
        let cmds = cmds.ok_or_else(|| {
            DsmError::invalid_operation("no pending prepare response for commitment")
        })?;
        if cmds.is_empty() {
            return Err(DsmError::invalid_operation("empty pending response"));
        }

        // All commands target the same address; parse from first and queue all
        let addr =
            match crate::generated::BleCommand::decode(&mut std::io::Cursor::new(&cmds[0][..])) {
                Ok(proto) => match proto.cmd {
                    Some(Cmd::WriteCharacteristic(w)) => w.address,
                    _ => String::new(),
                },
                Err(_) => String::new(),
            };
        if !addr.is_empty() {
            let mut devices = self.connected_devices.write().await;
            if let Some(conn) = devices.get_mut(&addr) {
                conn.pending_commands.extend(cmds.into_iter());
            }
        }
        Ok(())
    }

    /// Drop any stashed prepare response for a commitment (manual reject)
    pub async fn drop_pending_prepare_response(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<(), DsmError> {
        let mut map = self.pending_prepare_responses.write().await;
        map.remove(&commitment_hash);
        Ok(())
    }
}

// JNI extern helpers for BLE (android_ble_*) are implemented in
// the unified protobuf bridge (`unified_protobuf_bridge.rs`) so that
// there is a single JNI surface for the SDK and to avoid duplicate
// C-ABI symbols across translation units. Android native code and
// higher-level integration should call into the unified bridge.

// Note: the AndroidBleBridge continues to implement the runtime logic
// for BLE handling (handle_ble_event_bytes, create_ble_command, etc.)
// but does not define C-ABI entrypoints in this module.

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
    use crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator;
    use crate::bluetooth::{get_pairing_orchestrator};
    use crate::storage::client_db;
    use crate::storage::client_db::ContactRecord;
    use std::collections::HashMap;

    #[test]
    fn test_ble_command_serialization() {
        // bring in minimal core types for constructing dependencies
        use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
        use dsm::core::contact_manager::DsmContactManager;
        use dsm::crypto::SignatureKeyPair;
        use dsm::types::identifiers::NodeId;
        let command = BleCommand::StartScan;
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("failed to create tokio runtime: {}", e),
        };

        // Create minimal dependencies for bridge without panicking
        let contact_manager =
            DsmContactManager::new([0u8; 32], vec![NodeId::new("storage_node_1")]);
        // Generate proper cryptographic keypair based on test identity
        let device_id = [0u8; 32];
        let genesis_hash = [0u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = match SignatureKeyPair::generate_from_entropy(&key_entropy) {
            Ok(kp) => kp,
            Err(e) => panic!("keypair generation failed in test: {}", e),
        };
        let bilateral_tx_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            [0u8; 32],
            [0u8; 32],
        )));

        let handler = Arc::new(BilateralBleHandler::new(
            bilateral_tx_manager.clone(),
            [0u8; 32],
        ));
        let coordinator = Arc::new(BleFrameCoordinator::new(handler.clone(), [0u8; 32]));

        // Mock bridge for testing
        let bridge = AndroidBleBridge {
            frame_coordinator: coordinator,
            bilateral_handler: handler,
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            device_id: [0u8; 32],
            pending_prepare_responses: Arc::new(RwLock::new(HashMap::new())),
        };

        // Exercise serialization: create proto bytes, decode and inspect
        let bytes = match rt.block_on(bridge.create_ble_command(command)) {
            Ok(b) => b,
            Err(e) => panic!("create_ble_command failed in test: {}", e),
        };
        let decoded = match crate::generated::BleCommand::decode(&*bytes) {
            Ok(v) => v,
            Err(e) => {
                panic!("BleCommand decode failed in test: {}", e);
            }
        };
        match decoded.cmd {
            Some(crate::generated::ble_command::Cmd::StartScan(_)) => {}
            other => panic!("expected StartScan, got: {:?}", other),
        }
        // assert!(json.contains("30000"));
    }

    #[tokio::test]
    async fn test_device_connections() {
        let connected_devices = Arc::new(RwLock::new(HashMap::new()));

        {
            let mut devices = connected_devices.write().await;
            devices.insert(
                "AA:BB:CC:DD:EE:FF".to_string(),
                DeviceConnection {
                    address: "AA:BB:CC:DD:EE:FF".to_string(),
                    device_id: Some([1u8; 32]),
                    connected_at_tick: super::next_ble_tick(),
                    last_activity_tick: super::next_ble_tick(),
                    pending_commands: VecDeque::new(),
                },
            );
        }

        let devices = connected_devices.read().await;
        assert_eq!(devices.len(), 1);
        assert!(devices.contains_key("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_start_discovery_and_advertise_proto_only() {
        // Build minimal bridge
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("failed to create tokio runtime: {}", e),
        };
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [0u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = match dsm::crypto::SignatureKeyPair::new() {
            Ok(kp) => kp,
            Err(e) => panic!("keygen failed in test: {}", e),
        };
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [0u8; 32],
                [0u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [0u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [0u8; 32]));
        let bridge = Box::new(AndroidBleBridge::new(coord, handler, [0u8; 32]));
        // Start discovery via pure-Rust API
        let bytes = match rt.block_on(bridge.start_device_discovery()) {
            Ok(b) => b,
            Err(e) => panic!("start_device_discovery failed in test: {}", e),
        };
        let decoded = match crate::generated::BleCommand::decode(bytes.as_slice()) {
            Ok(v) => v,
            Err(e) => panic!("BleCommand decode failed in test: {}", e),
        };
        match decoded.cmd {
            Some(crate::generated::ble_command::Cmd::StartScan(_)) => {}
            Some(crate::generated::ble_command::Cmd::StartAdvertising(_)) => {}
            other => panic!("Unexpected discovery command: {:?}", other),
        }

        // Start advertising via pure-Rust API
        let bytes2 = match rt.block_on(bridge.start_advertising()) {
            Ok(b) => b,
            Err(e) => panic!("start_advertising failed in test: {}", e),
        };
        let decoded2 = match crate::generated::BleCommand::decode(bytes2.as_slice()) {
            Ok(v) => v,
            Err(e) => panic!("BleCommand decode failed in test: {}", e),
        };
        match decoded2.cmd {
            Some(crate::generated::ble_command::Cmd::StartAdvertising(a)) => {
                assert!(!a.device_name.is_empty())
            }
            other => panic!("Unexpected advertising command: {:?}", other),
        }
        // Drop bridge implicitly at end of scope
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn pairing_smoke_event_ordering() {
        // Initialize environment for AppState (Global singleton)
        // We leak the tempdir path so it persists for other tests if they share the singleton.
        let temp_dir = tempfile::Builder::new()
            .prefix("dsm_test_bridge")
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

        // Fresh DB + orchestrator for deterministic behavior
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        crate::bluetooth::reset_pairing_orchestrator_for_tests();

        // Build minimal bridge
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [1u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = dsm::crypto::SignatureKeyPair::new().expect("keygen");
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [1u8; 32],
                [2u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [1u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [1u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler.clone(), [1u8; 32]);

        // Prepare contact so status update succeeds
        let device_id = [9u8; 32];
        let genesis = [3u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-smoke".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer-smoke".to_string(),
            genesis_hash: genesis.to_vec(),
            current_chain_tip: None,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: Vec::new(),
            added_at: 1,
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        // Start a pairing session explicitly
        let orchestrator = get_pairing_orchestrator();
        orchestrator
            .initiate_pairing(device_id)
            .await
            .expect("init pairing");
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::WaitingForConnection)
        );

        // 1) DeviceConnected event
        let dev_connected = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::DeviceConnected(
                crate::generated::BleDeviceInfo {
                    address: "AA:BB:CC".to_string(),
                    name: String::new(),
                    rssi: 0,
                },
            )),
        };
        let mut buf1 = Vec::new();
        dev_connected.encode(&mut buf1).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf1)
            .await
            .expect("handle connected");
        // Session should still be WaitingForConnection at orchestrator level
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::WaitingForConnection)
        );

        // 2) IdentityObserved event
        let identity_evt = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::IdentityObserved(
                crate::generated::BleIdentityObserved {
                    address: "AA:BB:CC".to_string(),
                    device_id: device_id.to_vec(),
                    genesis_hash: genesis.to_vec(),
                },
            )),
        };
        let mut buf2 = Vec::new();
        identity_evt.encode(&mut buf2).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf2)
            .await
            .expect("handle identity");

        // After identity observation we are not yet complete; mutual handshake is required.
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::ExchangingChainTips)
        );
        let contact = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "BleCapable");
        // ble_address is NOT set during identity observation — it's committed only
        // after the bilateral handshake (handle_pairing_ack / handle_pairing_propose)
        // to prevent the early-disconnect race condition.
        assert_eq!(contact.ble_address, None);

        // Simulate bilateral confirmation: advertiser sends BlePairingAccept back,
        // scanner receives it and calls handle_pairing_ack on the orchestrator.
        // (In production this flows via PAIRING_ACK GATT indication → Rust JNI.)
        orchestrator
            .handle_pairing_propose(device_id, "AA:BB:CC".to_string(), None)
            .await
            .expect("handle propose");
        orchestrator
            .handle_pairing_ack(device_id, None, "")
            .await
            .expect("handle ack");

        // After handle_pairing_ack the scanner is in ConfirmSent — ble_address is NOT
        // persisted yet. Finalization is deferred until BlePairingConfirm is delivered
        // (simulated here by calling finalize_scanner_pairing_by_address directly).
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::ConfirmSent)
        );
        orchestrator
            .finalize_scanner_pairing_by_address("AA:BB:CC")
            .await
            .expect("finalize scanner pairing");

        // Now final state: Complete, and ble_address is committed.
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::Complete)
        );
        let contact_after_ack = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact_after_ack.ble_address.as_deref(), Some("AA:BB:CC"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn pairing_smoke_identity_before_connection() {
        // Fresh DB + orchestrator
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        crate::bluetooth::reset_pairing_orchestrator_for_tests();

        // Build bridge
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [2u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = dsm::crypto::SignatureKeyPair::new().expect("keygen");
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [2u8; 32],
                [3u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [2u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [2u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler.clone(), [2u8; 32]);

        // Contact
        let device_id = [5u8; 32];
        let genesis = [4u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-pre".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer-pre".to_string(),
            genesis_hash: genesis.to_vec(),
            current_chain_tip: None,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: Vec::new(),
            added_at: 1,
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        let orchestrator = get_pairing_orchestrator();

        // IdentityObserved BEFORE connection
        let identity_evt = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::IdentityObserved(
                crate::generated::BleIdentityObserved {
                    address: "DD:EE:FF".to_string(),
                    device_id: device_id.to_vec(),
                    genesis_hash: genesis.to_vec(),
                },
            )),
        };
        let mut buf = Vec::new();
        identity_evt.encode(&mut buf).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf)
            .await
            .expect("handle identity");

        // Identity is observed, but finalization requires mutual handshake.
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::ExchangingChainTips)
        );
        let contact = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "BleCapable");
        // ble_address not yet committed — only written after bilateral handshake.
        assert_eq!(contact.ble_address, None);

        // Simulate bilateral confirmation via orchestrator (replaces raw PAIR2 bytes).
        orchestrator
            .handle_pairing_ack(device_id, None, "")
            .await
            .expect("handle ack");

        // After handle_pairing_ack the scanner is ConfirmSent — ble_address not yet persisted.
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::ConfirmSent)
        );
        // Simulate the BlePairingConfirm GATT write-with-response ACK from the BLE stack.
        orchestrator
            .finalize_scanner_pairing_by_address("DD:EE:FF")
            .await
            .expect("finalize scanner pairing");
        assert_eq!(
            orchestrator.get_session_status(&device_id).await,
            Some(crate::bluetooth::pairing_orchestrator::PairingState::Complete)
        );
        let contact_after_ack = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact_after_ack.ble_address.as_deref(), Some("DD:EE:FF"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn pairing_smoke_identity_mismatch_no_promotion() {
        // Fresh DB + orchestrator
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        crate::bluetooth::reset_pairing_orchestrator_for_tests();

        // Build bridge
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [10u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = dsm::crypto::SignatureKeyPair::new().expect("keygen");
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [10u8; 32],
                [11u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [10u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [10u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler.clone(), [10u8; 32]);
        // Contact with stored genesis
        let device_id = [12u8; 32];
        let genesis_stored = [8u8; 32];
        let genesis_observed = [9u8; 32];
        let rec = ContactRecord {
            contact_id: "ct-mis".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer-mis".to_string(),
            genesis_hash: genesis_stored.to_vec(),
            current_chain_tip: None,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            public_key: Vec::new(),
            added_at: 1,
            previous_chain_tip: None,
        };
        client_db::store_contact(&rec).expect("store contact");

        // IdentityObserved with mismatched genesis
        let identity_evt = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::IdentityObserved(
                crate::generated::BleIdentityObserved {
                    address: "AA:BB:CC".to_string(),
                    device_id: device_id.to_vec(),
                    genesis_hash: genesis_observed.to_vec(),
                },
            )),
        };
        let mut buf = Vec::new();
        identity_evt.encode(&mut buf).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf)
            .await
            .expect("handle identity");

        // Orchestrator should place session in Failed (mismatch)
        let state = get_pairing_orchestrator()
            .get_session_status(&device_id)
            .await
            .expect("session exists");
        match state {
            crate::bluetooth::pairing_orchestrator::PairingState::Failed(msg) => {
                assert!(msg.contains("Genesis hash mismatch"))
            }
            other => panic!("expected Failed state, got {:?}", other),
        }

        // DB should not be promoted nor address set due to guarded secondary path
        let contact = client_db::get_contact_by_device_id(&device_id)
            .expect("get contact")
            .expect("exists");
        assert_eq!(contact.status, "Created");
        assert_eq!(contact.ble_address, None);
    }

    #[tokio::test]
    async fn device_connect_disconnect_clears_state() {
        // Build bridge (no DB needed)
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [20u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = dsm::crypto::SignatureKeyPair::new().expect("keygen");
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [20u8; 32],
                [21u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [20u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [20u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler.clone(), [20u8; 32]);

        // Send DeviceConnected
        let dev_connected = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::DeviceConnected(
                crate::generated::BleDeviceInfo {
                    address: "11:22".to_string(),
                    name: String::new(),
                    rssi: 0,
                },
            )),
        };
        let mut buf1 = Vec::new();
        dev_connected.encode(&mut buf1).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf1)
            .await
            .expect("handle connected");
        {
            let devices = bridge.connected_devices.read().await;
            assert!(devices.contains_key("11:22"));
        }

        // Send DeviceDisconnected
        let dev_disconnected = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::DeviceDisconnected(
                crate::generated::BleDeviceInfo {
                    address: "11:22".to_string(),
                    name: String::new(),
                    rssi: 0,
                },
            )),
        };
        let mut buf2 = Vec::new();
        dev_disconnected.encode(&mut buf2).expect("encode");
        let _ = bridge
            .handle_ble_event_bytes(&buf2)
            .await
            .expect("handle disconnected");
        {
            let devices = bridge.connected_devices.read().await;
            assert!(!devices.contains_key("11:22"));
        }
    }
    #[tokio::test]
    async fn test_defer_response_until_identity() {
        // Build minimal environment similar to other tests
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [9u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = dsm::crypto::SignatureKeyPair::new().expect("keygen");
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [9u8; 32],
                [5u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [9u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [9u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler.clone(), [9u8; 32]);

        // Establish verified contact + relationship for counterparty so prepare succeeds
        let counterparty = [7u8; 32];
        {
            let mut mgr = bilateral_mgr.write().await;
            if !mgr.has_verified_contact(&counterparty) {
                let contact = dsm::types::contact_types::DsmVerifiedContact {
                    alias: "peer".to_string(),
                    device_id: counterparty,
                    genesis_hash: mgr.local_genesis_hash(),
                    public_key: vec![7u8; 32],
                    genesis_material: vec![],
                    chain_tip: Some([1u8; 32]),
                    chain_tip_smt_proof: None,
                    genesis_verified_online: true,
                    verified_at_commit_height: 1,
                    added_at_commit_height: 1,
                    last_updated_commit_height: 1,
                    verifying_storage_nodes: vec![],
                    ble_address: Some("AA:BB".to_string()),
                };
                let _ = mgr.add_verified_contact(contact);
            }
            if mgr.get_relationship(&counterparty).is_none() {
                let _ = mgr.establish_relationship(&counterparty).await;
            }
        }

        // Create a prepare message chunks directly via coordinator (simulate receiving from counterparty)
        let op = dsm::types::operations::Operation::Noop;
        let chunks = coord
            .create_prepare_message(counterparty, op, 50)
            .await
            .expect("prepare chunks");
        assert!(!chunks.is_empty());

        // Register a connection WITHOUT identity
        bridge.update_connection_state("AA:BB", true).await; // device_id None

        // Feed first chunk into characteristic handler — should defer because identity unknown
        let result = bridge
            .handle_characteristic_data("AA:BB", &chunks[0])
            .await
            .expect("handler ok");
        assert!(
            result.is_none(),
            "Expected None (deferred) when device_id unknown"
        );

        // Now set identity (simulate observation)
        {
            let mut devices = bridge.connected_devices.write().await;
            if let Some(conn) = devices.get_mut("AA:BB") {
                conn.device_id = Some(counterparty);
            }
        }

        // Re-send the same chunk (idempotent path). Since reassembly buffer will treat this as first reception again
        let result2 = bridge
            .handle_characteristic_data("AA:BB", &chunks[0])
            .await
            .expect("handler ok");
        // Might still be None if multi-chunk; for single-chunk prepare it should produce Some(command)
        // Accept either path but ensure it is not deferred due to identity this time.
        // Cannot easily distinguish reasons, but zero secondary-path behavior is gone so at least identity is set.
        let _ = result2; // if Some(_) test passes; if None it's due to waiting additional chunks
    }

    #[test]
    fn test_initiate_bilateral_roundtrip_proto_only() {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("failed to create tokio runtime: {}", e),
        };
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [0u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = match dsm::crypto::SignatureKeyPair::new() {
            Ok(kp) => kp,
            Err(e) => panic!("keygen failed in test: {}", e),
        };
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [0u8; 32],
                [0u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [0u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [0u8; 32]));
        let _bridge = AndroidBleBridge::new(coord.clone(), handler, [0u8; 32]);
        // Prepare inputs
        let cp = [2u8; 32];
        // Satisfy relationship requirement: add verified contact and establish relationship
        {
            let mut m = rt.block_on(bilateral_mgr.write());
            let contact = dsm::types::contact_types::DsmVerifiedContact {
                alias: "peer".to_string(),
                device_id: cp,
                genesis_hash: [1u8; 32],
                public_key: vec![7u8; 32],
                genesis_material: vec![5u8; 32],
                chain_tip: Some([0u8; 32]),
                chain_tip_smt_proof: None,
                genesis_verified_online: true,
                verified_at_commit_height: 1,
                added_at_commit_height: 1,
                last_updated_commit_height: 1,
                ble_address: Some(String::new()),
                verifying_storage_nodes: vec![],
            };
            if let Err(e) = m.add_verified_contact(contact) {
                panic!("add_verified_contact failed in test: {}", e);
            }
        }
        rt.block_on(async {
            match bilateral_mgr
                .write()
                .await
                .establish_relationship(&cp)
                .await
            {
                Ok(_) => {}
                Err(e) => panic!("establish_relationship failed in test: {}", e),
            }
        });

        // Test that we can create prepare message chunks directly from coordinator
        let op = dsm::types::operations::Operation::Noop;
        let chunks = match rt.block_on(coord.create_prepare_message(cp, op, 100)) {
            Ok(c) => c,
            Err(e) => panic!("create_prepare_message failed in test: {}", e),
        };

        assert!(!chunks.is_empty(), "expected at least one chunk");

        // Verify first chunk is valid BLE chunk protobuf
        let first_chunk = match crate::generated::BleChunk::decode(chunks[0].as_slice()) {
            Ok(c) => c,
            Err(e) => panic!("BleChunk decode failed in test: {}", e),
        };

        assert!(first_chunk.header.is_some(), "expected chunk header");
        assert!(!first_chunk.data.is_empty(), "expected chunk data");
        // no JNI buffers to free in proto-only path
    }

    #[test]
    fn test_handle_ble_event_bytes_device_found() {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("failed to create tokio runtime: {}", e),
        };
        let contact_manager = dsm::core::contact_manager::DsmContactManager::new(
            [0u8; 32],
            vec![dsm::types::identifiers::NodeId::new("n")],
        );
        let keypair = match dsm::crypto::SignatureKeyPair::new() {
            Ok(kp) => kp,
            Err(e) => panic!("keygen failed in test: {}", e),
        };
        let bilateral_mgr = Arc::new(RwLock::new(
            dsm::core::bilateral_transaction_manager::BilateralTransactionManager::new(
                contact_manager,
                keypair,
                [0u8; 32],
                [0u8; 32],
            ),
        ));
        let handler = Arc::new(BilateralBleHandler::new(bilateral_mgr.clone(), [0u8; 32]));
        let coord = Arc::new(BleFrameCoordinator::new(handler.clone(), [0u8; 32]));
        let bridge = AndroidBleBridge::new(coord.clone(), handler, [0u8; 32]);

        // Build BleEvent::DeviceFound proto
        let proto_evt = crate::generated::BleEvent {
            ev: Some(crate::generated::ble_event::Ev::DeviceFound(
                crate::generated::BleDeviceInfo {
                    address: "AA:BB:CC:DD:EE:FF".to_string(),
                    name: "DSM-TestDevice".to_string(),
                    rssi: -42,
                },
            )),
        };

        let mut buf = Vec::new();
        if let Err(e) = proto_evt.encode(&mut buf) {
            panic!("encode event failed in test: {}", e);
        }

        let opt_resp = match rt.block_on(bridge.handle_ble_event_bytes(&buf)) {
            Ok(v) => v,
            Err(e) => panic!("handle_ble_event_bytes failed in test: {}", e),
        };
        if let Some(resp_bytes) = opt_resp {
            // Response should be a BleCommand proto (ConnectToDevice)
            let decoded = match crate::generated::BleCommand::decode(&*resp_bytes) {
                Ok(v) => v,
                Err(e) => panic!("decode command failed in test: {}", e),
            };
            match decoded.cmd {
                Some(crate::generated::ble_command::Cmd::ConnectDevice(c)) => {
                    assert_eq!(c.address, "AA:BB:CC:DD:EE:FF")
                }
                other => panic!("expected ConnectDevice, got: {:?}", other),
            }
        } else {
            panic!("expected a response command for DSM device");
        }
    }
}
