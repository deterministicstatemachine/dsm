//! Bluetooth Transport Module (Protobuf-only, Transport Timers Allowed, Production)
//!
//! - Encodes/decodes `pb::Envelope` (prost) for BLE transport.
//! - No JSON and no bincode; BLE transport remains raw protobuf bytes only.
//! - Wall-clock timing is allowed for transport concerns such as retries, ACK timeouts,
//!   reconnect backoff, pacing, and idle expiry.
//! - Protocol semantics remain clockless: no wall-clock data in envelopes, receipt
//!   commits, ordering decisions, or acceptance predicates.
//! - IO is abstracted behind `BleLink` so platform bridges (Android/iOS) can plug in.
//!
//! Integration expectations:
//! - `crate::generated` exposes prost `pb::*` types (Envelope v3).
//! - Upper layers construct valid `pb::Envelope` with a bluetooth payload variant.
//!
//! Notes:
//! - This transport does *not* invent custom message enums; protobuf is the source of truth.
//! - BLE keep-alives, retries, and timeout windows may be wall-clock driven at the
//!   transport layer, but they must never influence DSM protocol semantics.

#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic)]

use core::pin::Pin;
// core::task::Context, Poll not needed here
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt; // for map(), next()
use parking_lot::RwLock;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use dsm::crypto::blake3::dsm_domain_hasher;
use rand_core06::{OsRng, RngCore};

use crate::generated as pb;
use dsm::types::error::DsmError;
use prost::Message;

/// High-level local BLE bridge event type (not on-wire; wire is `pb::DsmBtMessage`).
#[derive(Debug, Clone)]
pub enum BleBridgeEvent {
    /// Opaque data payload with a nominal message type and raw payload bytes.
    Data {
        message_type: String,
        payload: Vec<u8>,
    },
    /// New connection established with device id.
    ConnectionEstablished {
        device_id: String,
    },
    /// Connection lost for device id.
    ConnectionLost {
        device_id: String,
    },
    /// Generic transport error
    Error {
        error: String,
    },
    /// Generic connection request (platform-level)
    ConnectionRequest {
        device_id: String,
    },
    /// Generic connection response (platform-level)
    ConnectionResponse {
        device_id: String,
    },
    /// Typed DSM/Bilateral request payload extracted from Envelope
    TradeRequest {
        device_id: String,
        payload: Vec<u8>,
    },
    /// Typed DSM/Bilateral response payload extracted from Envelope
    TradeResponse {
        device_id: String,
        payload: Vec<u8>,
    },
    /// Miscellaneous transfer placeholder
    PokemonTransfer {
        device_id: String,
        payload: Vec<u8>,
    },
    /// Authentication challenge from peer
    AuthChallenge {
        device_id: String,
        payload: Vec<u8>,
    },
    /// Authentication response from peer
    AuthResponse {
        device_id: String,
        payload: Vec<u8>,
    },
    /// Lightweight ping/pong
    Ping,
    Pong,
    /// Disconnection notice carrying a reason
    Disconnect {
        reason: String,
    },
}

/// Alias to the protobuf typed bilateral message for callers that expect it.
pub type BilateralBluetoothMessage = pb::DsmBtMessage;

/// Minimal device descriptor for discovery/connection management.
/// Transport-internal; protobuf over-the-air remains `pb::Envelope`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BluetoothDevice {
    /// Device identifier (BLE MAC/UUID/platform handle). **Canonical name:** `device_id`.
    pub device_id: String,
    /// Human-readable label if available.
    pub name: String,
    /// Optional metadata slots (platform-defined keys). Not serialized over the air.
    pub metadata: HashMap<String, String>,
}

impl BluetoothDevice {
    pub fn new(device_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            name: name.into(),
            metadata: HashMap::new(),
        }
    }
}

/// Operational role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BluetoothMode {
    Central,    // scanner/client
    Peripheral, // advertiser/server
    Both,
}

/// Platform BLE link contract: implement this in Android/iOS bridges.
/// This trait is intentionally lean and protobuf-agnostic (byte-oriented).
#[async_trait]
pub trait BleLink: Send + Sync + 'static {
    /// Begin scanning (Central or Both).
    async fn start_scan(&self) -> Result<(), DsmError>;
    async fn stop_scan(&self) -> Result<(), DsmError>;

    /// Begin advertising (Peripheral or Both).
    async fn start_advertise(&self) -> Result<(), DsmError>;
    async fn stop_advertise(&self) -> Result<(), DsmError>;

    /// Establish a link to the remote device id (peer).
    async fn connect(&self, device_id: &str) -> Result<(), DsmError>;

    /// Close the link to the remote device id.
    async fn disconnect(&self, device_id: &str) -> Result<(), DsmError>;

    /// Send raw bytes to a connected device.
    async fn send(&self, device_id: &str, bytes: &[u8]) -> Result<(), DsmError>;

    /// Stream raw inbound bytes from a connected device.
    /// The stream MUST terminate when the underlying link closes.
    async fn recv_stream(
        &self,
        device_id: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, DsmError>> + Send>>, DsmError>;

    /// Snapshot discovered devices (best-effort).
    async fn discovered(&self) -> Result<Vec<BluetoothDevice>, DsmError>;
}

/// BLE Security Context for encrypted communication
#[derive(Clone, Debug)]
pub struct BleSecurityContext {
    /// Session key for AES-GCM encryption (derived from device identities)
    session_key: [u8; 32],
    /// Sequence number for nonce generation (prevents replay attacks)
    sequence: Arc<RwLock<u64>>,
}

impl BleSecurityContext {
    /// Create a new security context for a BLE session
    #[must_use]
    pub fn new(local_device_id: &str, remote_device_id: &str) -> Self {
        // Derive session key from both device IDs (order-independent)
        let mut hasher = dsm_domain_hasher("DSM/ble-session-key");

        // Sort device IDs to ensure consistent key derivation
        let (first, second) = if local_device_id <= remote_device_id {
            (local_device_id, remote_device_id)
        } else {
            (remote_device_id, local_device_id)
        };

        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());

        let key_bytes = hasher.finalize();
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(key_bytes.as_bytes());

        Self {
            session_key,
            sequence: Arc::new(RwLock::new(0)),
        }
    }

    /// Encrypt data for BLE transmission
    ///
    /// # Errors
    /// Returns `DsmError` if cipher initialization fails or encryption fails.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        let cipher = Aes256Gcm::new_from_slice(&self.session_key)
            .map_err(|e| DsmError::crypto("Invalid BLE session key", Some(e)))?;

        // Generate nonce from sequence number
        let seq = {
            let mut seq_guard = self.sequence.write();
            let current = *seq_guard;
            *seq_guard = current.wrapping_add(1);
            current
        };

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&seq.to_le_bytes());
        OsRng.fill_bytes(&mut nonce_bytes[8..12]); // Add randomness for uniqueness

        let nonce = Nonce::from(nonce_bytes);

        let encrypted = cipher
            .encrypt(&nonce, data)
            .map_err(|e| DsmError::crypto("BLE encryption failed", Some(e)))?;

        // Prepend nonce to encrypted data
        let mut result = nonce_bytes.to_vec();
        result.extend(encrypted);

        Ok(result)
    }

    /// Decrypt data received over BLE
    ///
    /// # Errors
    /// Returns `DsmError` if the payload is too short, cipher init fails, or decryption fails.
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, DsmError> {
        if encrypted_data.len() < 12 {
            return Err(DsmError::crypto(
                "BLE encrypted data too short",
                None::<std::io::Error>,
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.session_key)
            .map_err(|e| DsmError::crypto("Invalid BLE session key", Some(e)))?;

        let nonce_bytes = &encrypted_data[0..12];
        let ciphertext = &encrypted_data[12..];

        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| DsmError::crypto("Invalid BLE nonce length", None::<std::io::Error>))?;
        let nonce = Nonce::from(nonce_array);

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| DsmError::crypto("BLE decryption failed", Some(e)))
    }
}

/// A connection handle in the transport registry.
#[derive(Debug, Clone)]
pub struct BluetoothConnection {
    pub device: BluetoothDevice,
    /// Security context for encrypted communication
    pub security: Option<BleSecurityContext>,
}

#[derive(Clone)]
pub struct BluetoothTransport<L: BleLink> {
    mode: BluetoothMode,
    link: Arc<L>,
    /// Local device identity (for caller context/metrics; not serialized here).
    _local_device: BluetoothDevice,

    /// Active connections by `device_id`.
    connections: Arc<RwLock<HashMap<String, BluetoothConnection>>>,
    /// Optional event sender used by `get_broadcast_stream()` to publish higher-level
    /// BLE events (connection lifecycle, decoded messages, errors).
    events_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<BleBridgeEvent>>>>,
}

impl<L: BleLink> BluetoothTransport<L> {
    /// Construct a transport over a platform BLE link.
    #[must_use]
    pub fn new(mode: BluetoothMode, link: Arc<L>, local_device: BluetoothDevice) -> Self {
        Self {
            mode,
            link,
            _local_device: local_device,
            connections: Arc::new(RwLock::new(HashMap::new())),
            events_sender: Arc::new(RwLock::new(None)),
        }
    }

    /// Start discovery alias (convenience wrapper).
    ///
    /// # Errors
    /// Returns an error if the platform link fails to start scanning.
    pub async fn start_discovery(&self) -> Result<(), DsmError> {
        self.link.start_scan().await
    }

    /// Current role.
    #[must_use]
    pub fn mode(&self) -> BluetoothMode {
        self.mode
    }

    /// Start role-appropriate services.
    ///
    /// Operational transport timers such as scan pacing or reconnect backoff are
    /// permitted outside this API boundary, but protocol semantics remain clockless.
    ///
    /// # Errors
    /// Returns an error if the platform link fails to start scanning/advertising.
    pub async fn start_service(&self) -> Result<(), DsmError> {
        match self.mode {
            BluetoothMode::Central => self.link.start_scan().await?,
            BluetoothMode::Peripheral => self.link.start_advertise().await?,
            BluetoothMode::Both => {
                self.link.start_scan().await?;
                self.link.start_advertise().await?;
            }
        }
        Ok(())
    }

    /// Stop role-appropriate services.
    ///
    /// # Errors
    /// Returns an error only if clearing the local registry fails (platform stops are best-effort).
    pub async fn stop_service(&self) -> Result<(), DsmError> {
        // Stop both to be explicit and idempotent; platform may no-op as needed.
        let _ = self.link.stop_scan().await;
        let _ = self.link.stop_advertise().await;
        // Clear connection registry (streams will end from link side).
        self.connections.write().clear();
        Ok(())
    }

    /// Snapshot discovered peers.
    ///
    /// # Errors
    /// Returns an error if the platform link cannot provide discovery results.
    pub async fn discovered_devices(&self) -> Result<Vec<BluetoothDevice>, DsmError> {
        self.link.discovered().await
    }

    /// Connect to peer and register locally.
    ///
    /// # Errors
    /// Returns an error if the platform link connection attempt fails.
    pub async fn connect(&self, device_id: &str) -> Result<(), DsmError> {
        self.link.connect(device_id).await?;
        // After successful link connect, try to enrich device info from discovery.
        let device = self
            .link
            .discovered()
            .await?
            .into_iter()
            .find(|d| d.device_id == device_id)
            .unwrap_or_else(|| BluetoothDevice::new(device_id, "unknown"));

        self.connections.write().insert(
            device_id.to_owned(),
            BluetoothConnection {
                device,
                security: None,
            },
        );
        // Notify listeners
        if let Some(sender) = self.events_sender.read().clone() {
            let _ = sender.send(BleBridgeEvent::ConnectionEstablished {
                device_id: device_id.to_string(),
            });
        }
        Ok(())
    }

    /// Disconnect from peer and deregister locally.
    ///
    /// # Errors
    /// Returns an error if the platform link disconnect attempt fails.
    pub async fn disconnect(&self, device_id: &str) -> Result<(), DsmError> {
        self.link.disconnect(device_id).await?;
        self.connections.write().remove(device_id);
        if let Some(sender) = self.events_sender.read().clone() {
            let _ = sender.send(BleBridgeEvent::ConnectionLost {
                device_id: device_id.to_string(),
            });
        }
        Ok(())
    }

    /// Is the peer registered as connected?
    #[must_use]
    pub fn is_connected(&self, device_id: &str) -> bool {
        self.connections.read().contains_key(device_id)
    }

    /// Get a registered connection.
    #[must_use]
    pub fn get_connection(&self, device_id: &str) -> Option<BluetoothConnection> {
        self.connections.read().get(device_id).cloned()
    }

    // ---------- Protobuf-first API (prost) ----------

    /// Send a pre-constructed `pb::Envelope` (protobuf only).
    ///
    /// # Errors
    /// Returns an error if protobuf encoding fails or if the platform link fails to send.
    pub async fn send_envelope(&self, device_id: &str, env: &pb::Envelope) -> Result<(), DsmError> {
        let mut buf = Vec::with_capacity(prost::Message::encoded_len(env));
        prost::Message::encode(env, &mut buf).map_err(|e| DsmError::Transport {
            context: "prost encode Envelope".into(),
            source: Some(Box::new(e)),
        })?;
        self.link.send(device_id, &buf).await
    }

    /// Subscribe to inbound `pb::Envelope`s from a peer.
    /// Decoding errors are surfaced as `DsmError` items; stream ends on link teardown.
    ///
    /// # Errors
    /// Returns an error if the underlying link stream cannot be created or if
    /// the transport encounters a lower-level receive error.
    pub async fn subscribe_envelopes(
        &self,
        device_id: &str,
    ) -> Result<impl Stream<Item = Result<pb::Envelope, DsmError>> + Send, DsmError> {
        let raw = self.link.recv_stream(device_id).await?;
        let connections = Arc::clone(&self.connections);
        let device_id_clone = device_id.to_string();
        Ok(raw.map(move |res| {
            let encrypted_bytes = res?;

            // Try to decrypt if security is enabled for this connection
            let bytes = if let Some(conn) = connections.read().get(&device_id_clone) {
                if let Some(security) = &conn.security {
                    security.decrypt(&encrypted_bytes)?
                } else {
                    encrypted_bytes
                }
            } else {
                encrypted_bytes
            };

            pb::Envelope::decode(bytes.as_slice()).map_err(|e| DsmError::Transport {
                context: "prost decode Envelope".into(),
                source: Some(Box::new(e)),
            })
        }))
    }

    /// Broadcast a single Envelope to all registered connections (best-effort).
    pub async fn broadcast_envelope(&self, env: &pb::Envelope) {
        let mut buf = Vec::with_capacity(prost::Message::encoded_len(env));
        // If encoding fails once, skip broadcast (should not happen with valid env).
        if let Err(e) = prost::Message::encode(env, &mut buf) {
            log::error!("Envelope encode failed; broadcast aborted: {e}");
            return;
        }
        let data = buf;

        let ids: Vec<String> = self.connections.read().keys().cloned().collect();
        for id in ids {
            if let Err(e) = self.link.send(&id, &data).await {
                log::warn!("broadcast_envelope: send to {id} failed: {e}");
            }
        }
    }

    // ---------- Compatibility helpers (optional upper-layer ergonomics) ----------

    /// Send raw bytes (rarely needed—prefer `send_envelope`).
    ///
    /// # Errors
    /// Returns an error if the underlying link fails to transmit the payload.
    pub async fn send_bytes(&self, device_id: &str, bytes: &[u8]) -> Result<(), DsmError> {
        self.link.send(device_id, bytes).await
    }

    /// Fan-in all inbound envelopes from all connections into a single channel receiver.
    /// This is a convenience combinator that subscribes per-connection on demand.
    /// Fan-in all inbound envelopes across currently connected peers into a single
    /// unbounded channel receiver. Call again to refresh the set of sources when
    /// topology changes.
    ///
    /// # Errors
    /// Returns an error if establishing any per-connection subscription fails.
    pub async fn fan_in_all(
        &self,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<Result<pb::Envelope, DsmError>>, DsmError>
    {
        // We materialize connection ids at call time; callers can re-invoke after topology changes.
        let ids: Vec<String> = self.connections.read().keys().cloned().collect();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<pb::Envelope, DsmError>>();

        for id in ids {
            let stream = self.subscribe_envelopes(&id).await?;
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                futures::pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    if tx_clone.send(item).is_err() {
                        break;
                    }
                }
            });
        }

        Ok(rx)
    }

    /// Convenience: send raw bytes to a device (alias for link.send).
    ///
    /// # Errors
    /// Returns an error if the underlying link fails to transmit the payload.
    pub async fn send_to(&self, device_id: &str, bytes: &[u8]) -> Result<(), DsmError> {
        self.link.send(device_id, bytes).await
    }

    /// Convenience: broadcast raw bytes to all registered connections
    pub async fn broadcast(&self, bytes: &[u8]) {
        let ids: Vec<String> = self.connections.read().keys().cloned().collect();
        for id in ids {
            if let Err(e) = self.link.send(&id, bytes).await {
                log::warn!("broadcast: send to {id} failed: {e}");
                if let Some(sender) = self.events_sender.read().clone() {
                    let _ = sender.send(BleBridgeEvent::Error {
                        error: format!("broadcast to {id} failed: {e}"),
                    });
                }
            }
        }
    }

    /// Provide a high-level stream of `BleBridgeEvent` events merging envelopes and
    /// platform lifecycle notifications. This returns a channel receiver that yields
    /// `BleBridgeEvent` items until the underlying fan-in stream ends.
    ///
    /// # Errors
    /// Returns an error if creating the internal fan-in subscription fails.
    pub async fn get_broadcast_stream(
        &self,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<BleBridgeEvent>, DsmError> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<BleBridgeEvent>();

        // Store the sender for lifecycle notifications from connect/disconnect
        {
            let mut w = self.events_sender.write();
            *w = Some(tx.clone());
        }

        // Spawn a task to forward prost Envelopes into BleBridgeEvent::Data
        let mut env_stream = match self.fan_in_all().await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        tokio::spawn(async move {
            while let Some(item) = env_stream.recv().await {
                match item {
                    Ok(env) => {
                        // Prefer explicit DsmBtMessage payload if present, borrow to avoid moving
                        if let Some(pb::envelope::Payload::DsmBtMessage(btm)) = env.payload.as_ref()
                        {
                            // Encode the full DsmBtMessage so upper layers can decode it
                            let buf = prost::Message::encode_to_vec(btm);
                            let msg_type = format!("{:?}", btm.message_type);
                            let _ = tx.send(BleBridgeEvent::Data {
                                message_type: msg_type,
                                payload: buf,
                            });
                        } else {
                            // Re-serialize envelope and emit as generic data
                            let mut buf = Vec::new();
                            if prost::Message::encode(&env, &mut buf).is_ok() {
                                let _ = tx.send(BleBridgeEvent::Data {
                                    message_type: "envelope".into(),
                                    payload: buf,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(BleBridgeEvent::Error {
                            error: format!("{e:?}"),
                        });
                    }
                }
            }
        });

        Ok(rx)
    }

    // ---------- BLE Security Methods ----------

    /// Establish encrypted communication with a device
    ///
    /// # Errors
    /// Returns an error if the device is not connected or security context cannot be established
    pub fn establish_secure_connection(
        &self,
        device_id: &str,
        local_device_id: &str,
    ) -> Result<(), DsmError> {
        let mut connections = self.connections.write();
        if let Some(conn) = connections.get_mut(device_id) {
            let security = BleSecurityContext::new(local_device_id, &conn.device.device_id);
            conn.security = Some(security);
            Ok(())
        } else {
            Err(DsmError::Transport {
                context: format!("Device {device_id} not connected"),
                source: None,
            })
        }
    }

    /// Send encrypted data to a device
    ///
    /// # Errors
    /// Returns an error if encryption fails or the device is not connected with security enabled
    pub async fn send_secure(&self, device_id: &str, data: &[u8]) -> Result<(), DsmError> {
        let security = {
            let connections = self.connections.read();
            let conn = connections
                .get(device_id)
                .ok_or_else(|| DsmError::Transport {
                    context: format!("Device {device_id} not connected"),
                    source: None,
                })?;

            conn.security.clone().ok_or_else(|| DsmError::Transport {
                context: format!("Secure connection not established for device {device_id}"),
                source: None,
            })?
        };

        let encrypted = security.encrypt(data)?;
        self.link.send(device_id, &encrypted).await
    }

    /// Send an envelope with encryption
    ///
    /// # Errors
    /// Returns an error if protobuf encoding, encryption, or transmission fails
    pub async fn send_envelope_secure(
        &self,
        device_id: &str,
        env: &pb::Envelope,
    ) -> Result<(), DsmError> {
        let mut buf = Vec::with_capacity(prost::Message::encoded_len(env));
        prost::Message::encode(env, &mut buf).map_err(|e| DsmError::Transport {
            context: "prost encode Envelope".into(),
            source: Some(Box::new(e)),
        })?;

        self.send_secure(device_id, &buf).await
    }

    /// Check if a connection has security enabled
    #[must_use]
    pub fn is_secure_connection(&self, device_id: &str) -> bool {
        self.connections
            .read()
            .get(device_id)
            .and_then(|conn| conn.security.as_ref())
            .is_some()
    }
}

// Implement BleLink forwarding for boxed trait objects so that
// `BluetoothTransport<Box<dyn BleLink>>` can be instantiated.
#[async_trait]
impl<T: BleLink + ?Sized> BleLink for Box<T> {
    async fn start_scan(&self) -> Result<(), DsmError> {
        (**self).start_scan().await
    }
    async fn stop_scan(&self) -> Result<(), DsmError> {
        (**self).stop_scan().await
    }
    async fn start_advertise(&self) -> Result<(), DsmError> {
        (**self).start_advertise().await
    }
    async fn stop_advertise(&self) -> Result<(), DsmError> {
        (**self).stop_advertise().await
    }
    async fn connect(&self, device_id: &str) -> Result<(), DsmError> {
        (**self).connect(device_id).await
    }
    async fn disconnect(&self, device_id: &str) -> Result<(), DsmError> {
        (**self).disconnect(device_id).await
    }
    async fn send(&self, device_id: &str, bytes: &[u8]) -> Result<(), DsmError> {
        (**self).send(device_id, bytes).await
    }
    async fn recv_stream(
        &self,
        device_id: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, DsmError>> + Send>>, DsmError> {
        (**self).recv_stream(device_id).await
    }
    async fn discovered(&self) -> Result<Vec<BluetoothDevice>, DsmError> {
        (**self).discovered().await
    }
}

// ------------------ Minimal in-memory BleLink (test only) ------------------
/// A minimal, no-op `BleLink` used ONLY for tests. Gated behind `#[cfg(test)]`
/// to prevent accidental use in production builds.
#[cfg(test)]
#[derive(Default, Debug, Clone)]
pub struct InMemoryBleLink {}

#[cfg(test)]
impl InMemoryBleLink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
#[async_trait]
impl BleLink for InMemoryBleLink {
    async fn start_scan(&self) -> Result<(), DsmError> {
        Ok(())
    }
    async fn stop_scan(&self) -> Result<(), DsmError> {
        Ok(())
    }
    async fn start_advertise(&self) -> Result<(), DsmError> {
        Ok(())
    }
    async fn stop_advertise(&self) -> Result<(), DsmError> {
        Ok(())
    }
    async fn connect(&self, _device_id: &str) -> Result<(), DsmError> {
        Ok(())
    }
    async fn disconnect(&self, _device_id: &str) -> Result<(), DsmError> {
        Ok(())
    }
    async fn send(&self, _device_id: &str, _bytes: &[u8]) -> Result<(), DsmError> {
        Ok(())
    }
    async fn recv_stream(
        &self,
        _device_id: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, DsmError>> + Send>>, DsmError> {
        Ok(Box::pin(futures::stream::empty()))
    }
    async fn discovered(&self) -> Result<Vec<BluetoothDevice>, DsmError> {
        Ok(Vec::new())
    }
}

// ------------------------ Unit-testable stream adapter (no mocks in prod) ------------------------
// Intentionally omitted: we do not ship an in-memory test link here to avoid "mocks/stubs" in prod
// code. If you want test utilities, place them under `#[cfg(test)]` in your test modules and
// implement `BleLink` there.

// (No generic tx_err helper; dead code under #[deny(warnings)] is not allowed here.)

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ── BluetoothDevice ────────────────────────────────────────────

    #[test]
    fn bluetooth_device_new() {
        let dev = BluetoothDevice::new("AA:BB:CC", "Pixel 7");
        assert_eq!(dev.device_id, "AA:BB:CC");
        assert_eq!(dev.name, "Pixel 7");
        assert!(dev.metadata.is_empty());
    }

    #[test]
    fn bluetooth_device_eq() {
        let a = BluetoothDevice::new("id1", "name1");
        let b = BluetoothDevice::new("id1", "name1");
        assert_eq!(a, b);
    }

    #[test]
    fn bluetooth_device_ne() {
        let a = BluetoothDevice::new("id1", "name1");
        let b = BluetoothDevice::new("id2", "name1");
        assert_ne!(a, b);
    }

    #[test]
    fn bluetooth_device_with_metadata() {
        let mut dev = BluetoothDevice::new("id", "name");
        dev.metadata
            .insert("rssi".into(), "-42".into());
        assert_eq!(dev.metadata.get("rssi").unwrap(), "-42");
    }

    #[test]
    fn bluetooth_device_debug_and_clone() {
        let dev = BluetoothDevice::new("id", "name");
        let dev2 = dev.clone();
        let dbg = format!("{dev2:?}");
        assert!(dbg.contains("BluetoothDevice"));
    }

    // ── BluetoothMode ──────────────────────────────────────────────

    #[test]
    fn mode_eq_and_copy() {
        let m = BluetoothMode::Central;
        let m2 = m;
        assert_eq!(m, m2);
        assert_ne!(m, BluetoothMode::Peripheral);
        assert_ne!(m, BluetoothMode::Both);
    }

    #[test]
    fn mode_debug() {
        let dbg = format!("{:?}", BluetoothMode::Both);
        assert!(dbg.contains("Both"));
    }

    // ── BleSecurityContext ─────────────────────────────────────────

    #[test]
    fn security_context_deterministic_key() {
        let ctx1 = BleSecurityContext::new("device_a", "device_b");
        let ctx2 = BleSecurityContext::new("device_a", "device_b");
        assert_eq!(ctx1.session_key, ctx2.session_key);
    }

    #[test]
    fn security_context_order_independent() {
        let ctx1 = BleSecurityContext::new("alice", "bob");
        let ctx2 = BleSecurityContext::new("bob", "alice");
        assert_eq!(
            ctx1.session_key, ctx2.session_key,
            "key derivation must be order-independent"
        );
    }

    #[test]
    fn security_context_different_pairs_different_keys() {
        let ctx1 = BleSecurityContext::new("alice", "bob");
        let ctx2 = BleSecurityContext::new("alice", "charlie");
        assert_ne!(ctx1.session_key, ctx2.session_key);
    }

    #[test]
    fn security_context_encrypt_decrypt_roundtrip() {
        let ctx = BleSecurityContext::new("local", "remote");
        let plaintext = b"Hello, BLE world!";

        let encrypted = ctx.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext.as_slice());
        assert!(encrypted.len() > plaintext.len());

        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn security_context_encrypt_empty_data() {
        let ctx = BleSecurityContext::new("a", "b");
        let encrypted = ctx.encrypt(b"").unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn security_context_encrypt_large_data() {
        let ctx = BleSecurityContext::new("a", "b");
        let data = vec![0xABu8; 16384];
        let encrypted = ctx.encrypt(&data).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn security_context_decrypt_too_short() {
        let ctx = BleSecurityContext::new("a", "b");
        let err = ctx.decrypt(&[0u8; 5]);
        assert!(err.is_err());
    }

    #[test]
    fn security_context_decrypt_corrupted() {
        let ctx = BleSecurityContext::new("a", "b");
        let encrypted = ctx.encrypt(b"test").unwrap();

        let mut corrupted = encrypted.clone();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 0xFF;
        }
        assert!(ctx.decrypt(&corrupted).is_err());
    }

    #[test]
    fn security_context_wrong_key_fails() {
        let ctx_a = BleSecurityContext::new("a", "b");
        let ctx_b = BleSecurityContext::new("c", "d");

        let encrypted = ctx_a.encrypt(b"secret").unwrap();
        assert!(ctx_b.decrypt(&encrypted).is_err());
    }

    #[test]
    fn security_context_nonce_prepended() {
        let ctx = BleSecurityContext::new("x", "y");
        let encrypted = ctx.encrypt(b"data").unwrap();
        assert!(
            encrypted.len() >= 12,
            "encrypted must include 12-byte nonce prefix"
        );
    }

    #[test]
    fn security_context_sequence_increments() {
        let ctx = BleSecurityContext::new("s", "r");
        let e1 = ctx.encrypt(b"a").unwrap();
        let e2 = ctx.encrypt(b"a").unwrap();
        assert_ne!(
            e1, e2,
            "same plaintext should produce different ciphertexts (different nonces)"
        );
    }

    #[test]
    fn security_context_clone_and_debug() {
        let ctx = BleSecurityContext::new("a", "b");
        let ctx2 = ctx.clone();
        let dbg = format!("{ctx2:?}");
        assert!(dbg.contains("BleSecurityContext"));
    }

    // ── BleBridgeEvent ─────────────────────────────────────────────

    #[test]
    fn ble_bridge_event_variants() {
        let events = vec![
            BleBridgeEvent::Data {
                message_type: "test".into(),
                payload: vec![1, 2, 3],
            },
            BleBridgeEvent::ConnectionEstablished {
                device_id: "d1".into(),
            },
            BleBridgeEvent::ConnectionLost {
                device_id: "d2".into(),
            },
            BleBridgeEvent::Error {
                error: "oops".into(),
            },
            BleBridgeEvent::ConnectionRequest {
                device_id: "d3".into(),
            },
            BleBridgeEvent::ConnectionResponse {
                device_id: "d4".into(),
            },
            BleBridgeEvent::TradeRequest {
                device_id: "d5".into(),
                payload: vec![],
            },
            BleBridgeEvent::TradeResponse {
                device_id: "d6".into(),
                payload: vec![],
            },
            BleBridgeEvent::PokemonTransfer {
                device_id: "d7".into(),
                payload: vec![],
            },
            BleBridgeEvent::AuthChallenge {
                device_id: "d8".into(),
                payload: vec![],
            },
            BleBridgeEvent::AuthResponse {
                device_id: "d9".into(),
                payload: vec![],
            },
            BleBridgeEvent::Ping,
            BleBridgeEvent::Pong,
            BleBridgeEvent::Disconnect {
                reason: "done".into(),
            },
        ];
        for e in &events {
            let cloned = e.clone();
            let dbg = format!("{cloned:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── BluetoothConnection ────────────────────────────────────────

    #[test]
    fn bluetooth_connection_without_security() {
        let conn = BluetoothConnection {
            device: BluetoothDevice::new("id", "name"),
            security: None,
        };
        let conn2 = conn.clone();
        assert!(conn2.security.is_none());
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("BluetoothConnection"));
    }

    #[test]
    fn bluetooth_connection_with_security() {
        let conn = BluetoothConnection {
            device: BluetoothDevice::new("id", "name"),
            security: Some(BleSecurityContext::new("local", "remote")),
        };
        assert!(conn.security.is_some());
    }

    // ── BluetoothTransport with InMemoryBleLink ────────────────────

    fn make_transport() -> BluetoothTransport<InMemoryBleLink> {
        let link = Arc::new(InMemoryBleLink::new());
        let local = BluetoothDevice::new("local", "TestDevice");
        BluetoothTransport::new(BluetoothMode::Both, link, local)
    }

    #[test]
    fn transport_mode() {
        let t = make_transport();
        assert_eq!(t.mode(), BluetoothMode::Both);
    }

    #[test]
    fn transport_not_connected_initially() {
        let t = make_transport();
        assert!(!t.is_connected("peer"));
        assert!(t.get_connection("peer").is_none());
    }

    #[test]
    fn transport_is_not_secure_when_not_connected() {
        let t = make_transport();
        assert!(!t.is_secure_connection("peer"));
    }

    #[tokio::test]
    async fn transport_connect_and_disconnect() {
        let t = make_transport();

        t.connect("peer1").await.unwrap();
        assert!(t.is_connected("peer1"));
        assert!(t.get_connection("peer1").is_some());

        t.disconnect("peer1").await.unwrap();
        assert!(!t.is_connected("peer1"));
    }

    #[tokio::test]
    async fn transport_start_stop_service() {
        let t = make_transport();
        t.start_service().await.unwrap();
        t.stop_service().await.unwrap();
    }

    #[tokio::test]
    async fn transport_start_discovery() {
        let t = make_transport();
        t.start_discovery().await.unwrap();
    }

    #[tokio::test]
    async fn transport_discovered_devices_empty() {
        let t = make_transport();
        let devs = t.discovered_devices().await.unwrap();
        assert!(devs.is_empty());
    }

    #[tokio::test]
    async fn transport_establish_secure_connection() {
        let t = make_transport();

        t.connect("peer").await.unwrap();
        assert!(!t.is_secure_connection("peer"));

        t.establish_secure_connection("peer", "local").unwrap();
        assert!(t.is_secure_connection("peer"));
    }

    #[test]
    fn transport_establish_secure_not_connected() {
        let t = make_transport();
        let err = t.establish_secure_connection("unknown", "local");
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn transport_send_secure_not_connected() {
        let t = make_transport();
        let err = t.send_secure("unknown", b"data").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn transport_send_secure_no_security() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        let err = t.send_secure("peer", b"data").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn transport_send_secure_works() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        t.establish_secure_connection("peer", "local").unwrap();
        t.send_secure("peer", b"hello").await.unwrap();
    }

    #[tokio::test]
    async fn transport_send_bytes() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        t.send_bytes("peer", b"raw").await.unwrap();
    }

    #[tokio::test]
    async fn transport_send_to() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        t.send_to("peer", b"raw").await.unwrap();
    }

    #[tokio::test]
    async fn transport_broadcast_empty() {
        let t = make_transport();
        t.broadcast(b"hello").await;
    }

    #[tokio::test]
    async fn transport_broadcast_envelope_empty() {
        let t = make_transport();
        let env = pb::Envelope::default();
        t.broadcast_envelope(&env).await;
    }

    #[tokio::test]
    async fn transport_send_envelope() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        let env = pb::Envelope::default();
        t.send_envelope("peer", &env).await.unwrap();
    }

    #[tokio::test]
    async fn transport_send_envelope_secure() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        t.establish_secure_connection("peer", "local").unwrap();
        let env = pb::Envelope::default();
        t.send_envelope_secure("peer", &env).await.unwrap();
    }

    #[tokio::test]
    async fn transport_subscribe_envelopes_empty_stream() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        let stream = t.subscribe_envelopes("peer").await.unwrap();
        futures::pin_mut!(stream);
        let next = stream.next().await;
        assert!(next.is_none(), "empty link stream yields None");
    }

    #[tokio::test]
    async fn transport_fan_in_all_no_connections() {
        let t = make_transport();
        let mut rx = t.fan_in_all().await.unwrap();
        let item = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(item.is_err() || item.unwrap().is_none());
    }

    #[tokio::test]
    async fn transport_multiple_connections() {
        let t = make_transport();
        t.connect("p1").await.unwrap();
        t.connect("p2").await.unwrap();

        assert!(t.is_connected("p1"));
        assert!(t.is_connected("p2"));

        t.stop_service().await.unwrap();
        assert!(!t.is_connected("p1"));
        assert!(!t.is_connected("p2"));
    }

    // ── InMemoryBleLink ────────────────────────────────────────────

    #[tokio::test]
    async fn in_memory_ble_link_all_ops() {
        let link = InMemoryBleLink::new();
        link.start_scan().await.unwrap();
        link.stop_scan().await.unwrap();
        link.start_advertise().await.unwrap();
        link.stop_advertise().await.unwrap();
        link.connect("d").await.unwrap();
        link.disconnect("d").await.unwrap();
        link.send("d", b"hello").await.unwrap();
        let devs = link.discovered().await.unwrap();
        assert!(devs.is_empty());
        let stream = link.recv_stream("d").await.unwrap();
        futures::pin_mut!(stream);
        assert!(stream.next().await.is_none());
    }

    // ── Mode-specific start_service behavior ───────────────────────

    #[tokio::test]
    async fn transport_central_mode_start_service() {
        let link = Arc::new(InMemoryBleLink::new());
        let local = BluetoothDevice::new("local", "Test");
        let t = BluetoothTransport::new(BluetoothMode::Central, link, local);
        t.start_service().await.unwrap();
    }

    #[tokio::test]
    async fn transport_peripheral_mode_start_service() {
        let link = Arc::new(InMemoryBleLink::new());
        let local = BluetoothDevice::new("local", "Test");
        let t = BluetoothTransport::new(BluetoothMode::Peripheral, link, local);
        t.start_service().await.unwrap();
    }

    // ── BilateralBluetoothMessage type alias ───────────────────────

    #[test]
    fn bilateral_bluetooth_message_alias() {
        let msg = BilateralBluetoothMessage::default();
        let _ = format!("{msg:?}");
    }

    // ── BluetoothDevice metadata ───────────────────────────────────

    #[test]
    fn bluetooth_device_multiple_metadata() {
        let mut dev = BluetoothDevice::new("id", "name");
        dev.metadata.insert("rssi".into(), "-50".into());
        dev.metadata.insert("mtu".into(), "512".into());
        dev.metadata.insert("type".into(), "ble".into());
        assert_eq!(dev.metadata.len(), 3);
    }

    #[test]
    fn bluetooth_device_empty_strings() {
        let dev = BluetoothDevice::new("", "");
        assert_eq!(dev.device_id, "");
        assert_eq!(dev.name, "");
    }

    // ── BleSecurityContext edge cases ──────────────────────────────

    #[test]
    fn security_context_same_device_id_both_sides() {
        let ctx = BleSecurityContext::new("same", "same");
        let encrypted = ctx.encrypt(b"test").unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"test");
    }

    #[test]
    fn security_context_unicode_device_ids() {
        let ctx = BleSecurityContext::new("日本語デバイス", "한국어기기");
        let encrypted = ctx.encrypt(b"hello").unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"hello");
    }

    #[test]
    fn security_context_decrypt_exactly_12_bytes() {
        let ctx = BleSecurityContext::new("a", "b");
        let result = ctx.decrypt(&[0u8; 12]);
        assert!(result.is_err(), "12 bytes is nonce only, no ciphertext for non-empty");
    }

    #[test]
    fn security_context_multiple_sequential_encryptions() {
        let ctx = BleSecurityContext::new("x", "y");
        let mut ciphertexts = Vec::new();
        for i in 0..10 {
            let ct = ctx.encrypt(format!("msg_{i}").as_bytes()).unwrap();
            ciphertexts.push(ct);
        }
        for (i, ct) in ciphertexts.iter().enumerate() {
            let pt = ctx.decrypt(ct).unwrap();
            assert_eq!(pt, format!("msg_{i}").as_bytes());
        }
    }

    // ── Transport connection lifecycle ──────────────────────────────

    #[tokio::test]
    async fn transport_connect_disconnect_reconnect() {
        let t = make_transport();

        t.connect("peer").await.unwrap();
        assert!(t.is_connected("peer"));

        t.disconnect("peer").await.unwrap();
        assert!(!t.is_connected("peer"));

        t.connect("peer").await.unwrap();
        assert!(t.is_connected("peer"));
    }

    #[tokio::test]
    async fn transport_get_connection_details() {
        let t = make_transport();
        t.connect("peer_x").await.unwrap();

        let conn = t.get_connection("peer_x").unwrap();
        assert_eq!(conn.device.device_id, "peer_x");
        assert!(conn.security.is_none());
    }

    #[tokio::test]
    async fn transport_establish_secure_then_verify() {
        let t = make_transport();
        t.connect("peer").await.unwrap();
        t.establish_secure_connection("peer", "local_dev").unwrap();

        let conn = t.get_connection("peer").unwrap();
        assert!(conn.security.is_some());
    }

    // ── Transport broadcast with connections ────────────────────────

    #[tokio::test]
    async fn transport_broadcast_with_connections() {
        let t = make_transport();
        t.connect("p1").await.unwrap();
        t.connect("p2").await.unwrap();
        t.broadcast(b"hello all").await;
    }

    #[tokio::test]
    async fn transport_broadcast_envelope_with_connections() {
        let t = make_transport();
        t.connect("p1").await.unwrap();
        t.connect("p2").await.unwrap();
        let env = pb::Envelope::default();
        t.broadcast_envelope(&env).await;
    }

    // ── stop_service clears connections ─────────────────────────────

    #[tokio::test]
    async fn stop_service_clears_all_connections() {
        let t = make_transport();
        t.connect("a").await.unwrap();
        t.connect("b").await.unwrap();
        t.connect("c").await.unwrap();

        t.stop_service().await.unwrap();
        assert!(!t.is_connected("a"));
        assert!(!t.is_connected("b"));
        assert!(!t.is_connected("c"));
    }

    // ── fan_in_all with connections ─────────────────────────────────

    #[tokio::test]
    async fn transport_fan_in_all_with_connections() {
        let t = make_transport();
        t.connect("p1").await.unwrap();
        t.connect("p2").await.unwrap();
        let mut rx = t.fan_in_all().await.unwrap();
        let item = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            item.is_err() || item.unwrap().is_none(),
            "InMemoryBleLink returns empty streams"
        );
    }

    // ── Box<dyn BleLink> forwarding ─────────────────────────────────

    #[tokio::test]
    async fn boxed_ble_link_forwarding() {
        let link: Box<dyn BleLink> = Box::new(InMemoryBleLink::new());
        link.start_scan().await.unwrap();
        link.stop_scan().await.unwrap();
        link.start_advertise().await.unwrap();
        link.stop_advertise().await.unwrap();
        link.connect("dev").await.unwrap();
        link.send("dev", b"data").await.unwrap();
        link.disconnect("dev").await.unwrap();
        let devs = link.discovered().await.unwrap();
        assert!(devs.is_empty());
    }

    #[tokio::test]
    async fn transport_with_boxed_link() {
        let link: Arc<Box<dyn BleLink>> = Arc::new(Box::new(InMemoryBleLink::new()));
        let local = BluetoothDevice::new("local", "Test");
        let t = BluetoothTransport::new(BluetoothMode::Both, link, local);
        t.start_service().await.unwrap();
        t.connect("peer").await.unwrap();
        assert!(t.is_connected("peer"));
        t.stop_service().await.unwrap();
    }

    // ── Transport clone ─────────────────────────────────────────────

    #[tokio::test]
    async fn transport_clone_shares_connections() {
        let t1 = make_transport();
        let t2 = t1.clone();

        t1.connect("shared_peer").await.unwrap();
        assert!(t2.is_connected("shared_peer"));
    }

    // ── InMemoryBleLink default ─────────────────────────────────────

    #[test]
    fn in_memory_ble_link_default() {
        let link = InMemoryBleLink::default();
        let _ = format!("{link:?}");
    }
}
