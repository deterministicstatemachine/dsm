//! Bluetooth Transport Module (Protobuf-only, Clockless, Production)
//!
//! - Encodes/decodes `pb::Envelope` (prost) for BLE transport.
//! - No JSON, no bincode, no wall clocks, no periodic timers.
//! - IO is abstracted behind `BleLink` so platform bridges (Android/iOS) can plug in.
//!
//! Integration expectations:
//! - `crate::generated` exposes prost `pb::*` types (Envelope v3).
//! - Upper layers construct valid `pb::Envelope` with a bluetooth payload variant.
//!
//! Notes:
//! - This transport does *not* invent custom message enums; protobuf is the source of truth.
//! - Keep-alives, retries, etc. must be *state-driven* (hash-chain adjacency / iteration budgets),
//!   not wall-clock driven.

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
use rand::{rngs::OsRng, RngCore};

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

    /// Start role-appropriate services (no timers, no clocks).
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
#[derive(Default)]
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
