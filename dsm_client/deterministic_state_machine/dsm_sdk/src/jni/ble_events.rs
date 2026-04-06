//! # BLE Event Envelope Builders
//!
//! Constructs protobuf-encoded BLE event envelopes for the JNI bridge.
//! Uses `Payload::BleEvent` from the updated proto schema to wrap BLE
//! scan results, connection events, and data payloads for delivery to
//! the Kotlin layer.

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::generated as pb;
use jni::objects::{JByteArray, JObject, JString};
use jni::JNIEnv;
use pb::{BleDeviceInfo, BleEvent};
use prost::Message;

use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

fn pb_send_status_from_router_status(
    status: dsm::types::proto::RelationshipSendStatus,
) -> pb::RelationshipSendStatus {
    pb::RelationshipSendStatus {
        send_ready: status.send_ready,
        send_check_state: status.send_check_state,
        send_block_reason: status.send_block_reason,
        send_block_message: status.send_block_message,
    }
}

/// Convert raw JNIEnv pointer to safe wrapper.
/// Returns None on failure instead of aborting the process.
#[inline]
unsafe fn env_from(raw: jni::sys::JNIEnv) -> Option<JNIEnv<'static>> {
    match JNIEnv::from_raw(raw as *mut _) {
        Ok(env) => Some(env),
        Err(e) => {
            log::error!("env_from failed: {e} (FFI contract violation)");
            None
        }
    }
}

/// Convert raw jstring to safe JString wrapper.
#[inline]
unsafe fn jstr_from(raw: jni::sys::jstring) -> JString<'static> {
    JString::from(JObject::from_raw(raw))
}

/// Convert raw jbyteArray to safe JByteArray wrapper.
#[inline]
unsafe fn jbytes_from(raw: jni::sys::jbyteArray) -> JByteArray<'static> {
    JByteArray::from(JObject::from_raw(raw))
}

/// Return an empty byte array to the JVM when envelope
/// construction fails — the Kotlin caller treats empty results as "no envelope".
fn empty(env: &mut JNIEnv<'_>) -> jni::sys::jbyteArray {
    match env.new_byte_array(0) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn build_app_state_envelope(resp: pb::AppStateResponse) -> Result<Vec<u8>, String> {
    let envelope = pb::Envelope {
        version: 3,
        headers: None,
        message_id: vec![0u8; 16],
        payload: Some(pb::envelope::Payload::AppStateResponse(resp)),
    };
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03);
    envelope
        .encode(&mut buf)
        .map_err(|e| format!("app state envelope encode failed: {e}"))?;
    Ok(buf)
}

/// Create a BleEvent envelope for device_found (scanner discovered a DSM peer).
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleDeviceFoundEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    address_jstr: jni::sys::jstring,
    name_jstr: jni::sys::jstring,
    rssi: jni::sys::jint,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleDeviceFoundEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(address_jstr) };
            let name_jstring = unsafe { jstr_from(name_jstr) };

            let address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("createBleDeviceFoundEnvelope: JNI address extraction failed: {e}");
                    return empty(&mut env);
                }
            };

            let name: String = match env.get_string(&name_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("createBleDeviceFoundEnvelope: JNI name extraction failed: {e}");
                    return empty(&mut env);
                }
            };

            let device_info = BleDeviceInfo {
                address,
                name,
                rssi,
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::DeviceFound(device_info)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => {
                    match env.byte_array_from_slice(&bytes) {
                        Ok(arr) => arr.into_raw(),
                        Err(e) => {
                            log::error!("createBleDeviceFoundEnvelope: JNI byte_array_from_slice failed: {e}");
                            empty(&mut env)
                        }
                    }
                }
                Err(e) => {
                    log::error!("createBleDeviceFoundEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for scan_started.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleScanStartedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleScanStartedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::ScanStarted(true)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => {
                    match env.byte_array_from_slice(&bytes) {
                        Ok(arr) => arr.into_raw(),
                        Err(e) => {
                            log::error!("createBleScanStartedEnvelope: JNI byte_array_from_slice failed: {e}");
                            empty(&mut env)
                        }
                    }
                }
                Err(e) => {
                    log::error!("createBleScanStartedEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for scan_stopped.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleScanStoppedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleScanStoppedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::ScanStopped(true)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => {
                    match env.byte_array_from_slice(&bytes) {
                        Ok(arr) => arr.into_raw(),
                        Err(e) => {
                            log::error!("createBleScanStoppedEnvelope: JNI byte_array_from_slice failed: {e}");
                            empty(&mut env)
                        }
                    }
                }
                Err(e) => {
                    log::error!("createBleScanStoppedEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for advertising_started.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleAdvertisingStartedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleAdvertisingStartedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::AdvertisingStarted(true)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!(
                    "createBleAdvertisingStartedEnvelope: JNI byte_array_from_slice failed: {e}"
                );
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createBleAdvertisingStartedEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for advertising_stopped.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleAdvertisingStoppedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleAdvertisingStoppedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::AdvertisingStopped(true)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!(
                    "createBleAdvertisingStoppedEnvelope: JNI byte_array_from_slice failed: {e}"
                );
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createBleAdvertisingStoppedEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for connection_established.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleConnectionEstablishedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    address_jstr: jni::sys::jstring,
    name_jstr: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleConnectionEstablishedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(address_jstr) };
            let name_jstring = unsafe { jstr_from(name_jstr) };

            let address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!(
                "createBleConnectionEstablishedEnvelope: JNI address extraction failed: {e}"
            );
                    return empty(&mut env);
                }
            };

            let name: String = match env.get_string(&name_jstring) {
                Ok(s) => s.into(),
                Err(_) => String::new(),
            };

            let device_info = BleDeviceInfo {
                address,
                name,
                rssi: 0,
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::DeviceConnected(device_info)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!(
                    "createBleConnectionEstablishedEnvelope: JNI byte_array_from_slice failed: {e}"
                );
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!(
                        "createBleConnectionEstablishedEnvelope: envelope build failed: {e}"
                    );
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Create a BleEvent envelope for connection_lost.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBleConnectionLostEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    address_jstr: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBleConnectionLostEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(address_jstr) };

            let address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!(
                        "createBleConnectionLostEnvelope: JNI address extraction failed: {e}"
                    );
                    return empty(&mut env);
                }
            };

            let device_info = BleDeviceInfo {
                address,
                name: String::new(),
                rssi: 0,
            };

            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::DeviceDisconnected(device_info)),
            };

            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!(
                    "createBleConnectionLostEnvelope: JNI byte_array_from_slice failed: {e}"
                );
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createBleConnectionLostEnvelope: envelope build failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Internal helper to create BleIdentityObserved envelope (Protocol V3).
/// Returns raw bytes of the Framed Envelope.
pub fn create_identity_observed_envelope_inner(
    address: String,
    genesis_hash: Vec<u8>,
    device_id: Vec<u8>,
) -> Vec<u8> {
    let identity_observed = pb::BleIdentityObserved {
        address,
        genesis_hash,
        device_id,
    };
    let ble_event = BleEvent {
        ev: Some(pb::ble_event::Ev::IdentityObserved(identity_observed)),
    };

    build_ble_event_envelope(ble_event).unwrap_or_default()
}

/// Buffered identity data for async retry when contact is not yet in SQLite.
struct PendingIdentity {
    sender_address: String,
    genesis_hash: [u8; 32],
    device_id: [u8; 32],
    buffered_at: std::time::Instant,
}

/// Pending identities awaiting contact insertion. Keyed by device_id.
static PENDING_IDENTITIES: Lazy<Mutex<HashMap<[u8; 32], PendingIdentity>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Process a BLE identity envelope received on the PAIRING characteristic.
///
/// The advertiser receives a protobuf Envelope containing BleEvent.identity_observed
/// from the scanner. This function:
/// 1. Decodes the envelope and extracts genesis_hash + device_id
/// 2. Uses `sender_ble_address` (from the GATT connection, NOT from the envelope) to
///    update the contact's BLE address in SQLite
/// 3. Notifies the PairingOrchestrator to advance the state machine
/// 4. Returns a success ack (empty bytes) or error envelope
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processBleIdentityEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    envelope_jbytes: jni::sys::jbyteArray,
    sender_address_jstr: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "processBleIdentityEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(sender_address_jstr) };

            let sender_address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("processBleIdentityEnvelope: JNI address extraction failed: {e}");
                    return empty(&mut env);
                }
            };

            let envelope_bytes: Vec<u8> =
                match env.convert_byte_array(unsafe { jbytes_from(envelope_jbytes) }) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            "processBleIdentityEnvelope: JNI byte array conversion failed: {e}"
                        );
                        return empty(&mut env);
                    }
                };

            // Strip 0x03 framing byte if present
            let raw = if envelope_bytes.first() == Some(&0x03) {
                &envelope_bytes[1..]
            } else {
                &envelope_bytes[..]
            };

            // Decode protobuf Envelope
            let envelope = match pb::Envelope::decode(raw) {
                Ok(env) => env,
                Err(e) => {
                    log::error!("processBleIdentityEnvelope: envelope decode failed: {e}");
                    return empty(&mut env);
                }
            };

            // Extract BleEvent — either IdentityObserved (advertiser receives scanner's identity)
            // or PairingAccept (scanner receives advertiser's bilateral confirmation).
            let ble_event = match envelope.payload {
                Some(pb::envelope::Payload::BleEvent(ref evt)) => evt.clone(),
                _ => {
                    log::error!("processBleIdentityEnvelope: envelope payload is not BleEvent");
                    return empty(&mut env);
                }
            };

            // Handle PairingAccept (scanner side): the advertiser sent its bilateral ACK.
            // Phase 2 → Phase 3: scanner persists its ble_address, marks Complete, and
            // returns a BlePairingConfirm envelope for Kotlin to write back to the
            // advertiser's PAIRING characteristic (completing the 3-phase atomic commit).
            if let Some(pb::ble_event::Ev::PairingAccept(ref accept)) = ble_event.ev {
                log::info!(
                    "processBleIdentityEnvelope: received BlePairingAccept from {} (device={:02x}{:02x}...)",
                    accept.address,
                    accept.device_id.get(0).copied().unwrap_or(0),
                    accept.device_id.get(1).copied().unwrap_or(0)
                );
                if accept.device_id.len() == 32 {
                    let mut peer_device_id = [0u8; 32];
                    peer_device_id.copy_from_slice(&accept.device_id);
                    let peer_chain_tip: Option<[u8; 32]> = None;
                    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
                    let rt = crate::runtime::get_runtime();
                    // Scanner side: transition to ConfirmSent. Pass sender_address as hint
                    // so handle_pairing_ack can populate session.ble_address if it is None
                    // (guards against the race where initiate_pairing ran before identity
                    // observation completed and the session has no address yet).
                    match rt.block_on(orchestrator.handle_pairing_ack(
                        peer_device_id,
                        peer_chain_tip,
                        &sender_address,
                    )) {
                        Ok(()) => {
                            log::info!("processBleIdentityEnvelope: scanner pairing ACK → Complete")
                        }
                        Err(e) => log::warn!(
                            "processBleIdentityEnvelope: handle_pairing_ack failed: {}",
                            e
                        ),
                    }

                    // Build BlePairingConfirm to send back to the advertiser (Phase 3).
                    // This tells the advertiser "I got your ACK, you can persist now".
                    let local_device_id = crate::sdk::app_state::AppState::get_device_id();
                    if let Some(did) = local_device_id {
                        if did.len() == 32 {
                            let confirm = pb::BlePairingConfirm {
                                address: sender_address.clone(),
                                device_id: did.to_vec(),
                            };
                            let confirm_event = BleEvent {
                                ev: Some(pb::ble_event::Ev::PairingConfirm(confirm)),
                            };
                            match build_ble_event_envelope(confirm_event) {
                                Ok(confirm_bytes) => {
                                    log::info!(
                                        "processBleIdentityEnvelope: built BlePairingConfirm ({} bytes) for {}",
                                        confirm_bytes.len(), sender_address
                                    );
                                    // Return the confirm envelope to Kotlin — it will write
                                    // it to the advertiser's PAIRING characteristic.
                                    match env.byte_array_from_slice(&confirm_bytes) {
                                        Ok(arr) => return arr.into_raw(),
                                        Err(e) => {
                                            log::error!("processBleIdentityEnvelope: failed to create confirm byte array: {e}");
                                            return empty(&mut env);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!(
                                        "processBleIdentityEnvelope: failed to build confirm envelope: {}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                return empty(&mut env);
            }

            // Handle PairingConfirm (advertiser side): the scanner confirmed receipt of
            // our BlePairingAccept. NOW it is safe to persist ble_address on the advertiser.
            if let Some(pb::ble_event::Ev::PairingConfirm(ref confirm)) = ble_event.ev {
                log::info!(
                    "processBleIdentityEnvelope: received BlePairingConfirm from {} (device={:02x}{:02x}...)",
                    confirm.address,
                    confirm.device_id.get(0).copied().unwrap_or(0),
                    confirm.device_id.get(1).copied().unwrap_or(0)
                );
                if confirm.device_id.len() == 32 {
                    let mut peer_device_id = [0u8; 32];
                    peer_device_id.copy_from_slice(&confirm.device_id);
                    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
                    let rt = crate::runtime::get_runtime();
                    match rt.block_on(orchestrator.handle_pairing_confirm(peer_device_id)) {
                        Ok(()) => {
                            log::info!(
                                "processBleIdentityEnvelope: advertiser pairing CONFIRM → Complete"
                            )
                        }
                        Err(e) => log::warn!(
                            "processBleIdentityEnvelope: handle_pairing_confirm failed: {}",
                            e
                        ),
                    }
                }
                return empty(&mut env);
            }

            let obs = match ble_event.ev {
                Some(pb::ble_event::Ev::IdentityObserved(obs)) => obs,
                _ => {
                    log::error!(
                "processBleIdentityEnvelope: envelope does not contain identity_observed or pairing_accept"
            );
                    return empty(&mut env);
                }
            };

            // Validate genesis_hash and device_id lengths
            if obs.genesis_hash.len() != 32 {
                log::error!(
                    "processBleIdentityEnvelope: invalid genesis_hash length: {}",
                    obs.genesis_hash.len()
                );
                return empty(&mut env);
            }
            if obs.device_id.len() != 32 {
                log::error!(
                    "processBleIdentityEnvelope: invalid device_id length: {}",
                    obs.device_id.len()
                );
                return empty(&mut env);
            }

            let mut genesis_hash = [0u8; 32];
            genesis_hash.copy_from_slice(&obs.genesis_hash);
            let mut device_id = [0u8; 32];
            device_id.copy_from_slice(&obs.device_id);

            log::info!(
        "processBleIdentityEnvelope: sender={}, genesis={:02x}{:02x}..., device_id={:02x}{:02x}...",
        sender_address,
        genesis_hash[0],
        genesis_hash[1],
        device_id[0],
        device_id[1]
    );

            // ═══════════════════════════════════════════════════════════════════════════════
            // Contact lookup — immediate, non-blocking.
            // Both paths (found / not-found) use process_deferred_identity for the full
            // pipeline. ACK delivery always goes through the JNI callback so there is
            // exactly ONE code path for identity processing.
            // ═══════════════════════════════════════════════════════════════════════════════
            let pending = PendingIdentity {
                sender_address: sender_address.clone(),
                genesis_hash,
                device_id,
                buffered_at: std::time::Instant::now(),
            };

            match crate::storage::client_db::get_contact_by_device_id(&device_id) {
                Ok(Some(contact)) => {
                    // Contact exists — process immediately (still via the shared helper)
                    process_deferred_identity(pending, contact);
                }
                Ok(None) => {
                    log::warn!(
                "processBleIdentityEnvelope: contact not in SQLite for {:02x}{:02x}... — buffering for async retry",
                device_id[0], device_id[1]
            );
                    match PENDING_IDENTITIES.lock() {
                        Ok(mut map) => {
                            map.insert(device_id, pending);
                        }
                        Err(e) => {
                            log::error!("processBleIdentityEnvelope: PENDING_IDENTITIES mutex poisoned: {e}");
                            return empty(&mut env);
                        }
                    }
                    spawn_pending_identity_retry(device_id);
                }
                Err(e) => {
                    log::error!(
                "processBleIdentityEnvelope: SQLite error for {:02x}{:02x}...: {} (hard-fail)",
                device_id[0], device_id[1], e
            );
                }
            }

            // Always return empty — ACK is delivered asynchronously via deliverDeferredPairingAck JNI callback
            empty(&mut env)
        }),
    )
}

/// Finalize scanner-side pairing after `BlePairingConfirm` GATT write is acknowledged.
///
/// ATOMIC PAIRING — Phase 3b (scanner side):
/// Kotlin calls this from the `PairingConfirmWritten` event handler, which fires when
/// `onCharacteristicWrite` confirms the `BlePairingConfirm` bytes were delivered to the
/// advertiser's GATT server. Only at this point is it safe to persist `ble_address` and
/// mark the scanner session `Complete`.
///
/// Returns `1` (true) on success, `0` (false) if no matching `ConfirmSent` session was
/// found (e.g., already finalized or timed out — both are benign for the caller).
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_finalizeScannerPairing(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    ble_address_jstr: jni::sys::jstring,
) -> jni::sys::jboolean {
    let mut env = match unsafe { jni::JNIEnv::from_raw(env as *mut _) } {
        Ok(e) => e,
        Err(err) => {
            log::error!("finalizeScannerPairing: JNIEnv::from_raw failed: {err}");
            return 0u8;
        }
    };
    let ble_address_ref =
        unsafe { jni::objects::JString::from(jni::objects::JObject::from_raw(ble_address_jstr)) };
    let ble_address: String = match env.get_string(&ble_address_ref) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("finalizeScannerPairing: failed to read ble_address JString: {e}");
            return 0u8;
        }
    };

    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
    let rt = crate::runtime::get_runtime();
    match rt.block_on(orchestrator.finalize_scanner_pairing_by_address(&ble_address)) {
        Ok(()) => {
            log::info!(
                "finalizeScannerPairing: pairing finalized for {}",
                ble_address
            );
            1u8
        }
        Err(e) => {
            // Warn-level: "already finalized" is the expected benign case on retry.
            log::warn!("finalizeScannerPairing: {}", e);
            0u8
        }
    }
}

/// Build a framed Envelope with BleEvent as the direct payload.
/// Uses the dedicated Payload::BleEvent field (proto schema v2.4+).
pub(crate) fn build_ble_event_envelope(ble_event: BleEvent) -> Result<Vec<u8>, String> {
    let envelope = pb::Envelope {
        version: 3,
        headers: Some(pb::Headers {
            device_id: vec![0u8; 32],
            chain_tip: vec![0u8; 32],
            genesis_hash: vec![],
            seq: 0,
        }),
        message_id: vec![],
        payload: Some(pb::envelope::Payload::BleEvent(ble_event)),
    };

    let mut buf = Vec::new();
    buf.push(0x03); // Canonical framing byte for FramedEnvelopeV3
    envelope
        .encode(&mut buf)
        .map_err(|e| format!("Failed to encode Envelope: {e}"))?;
    Ok(buf)
}

/// Spawn an async tokio task that polls SQLite every 500ms for up to 15s,
/// waiting for the contact to appear. When found, runs the full identity
/// processing pipeline and delivers the ACK via JNI callback.
fn spawn_pending_identity_retry(device_id: [u8; 32]) {
    let rt = crate::runtime::get_runtime();
    rt.spawn(async move {
        let max_wait = std::time::Duration::from_secs(15);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            tokio::time::sleep(poll_interval).await;

            if start.elapsed() > max_wait {
                log::error!(
                    "spawn_pending_identity_retry: timeout ({:.1}s) waiting for contact {:02x}{:02x}...",
                    max_wait.as_secs_f64(),
                    device_id[0], device_id[1]
                );
                if let Ok(mut map) = PENDING_IDENTITIES.lock() {
                    map.remove(&device_id);
                } else {
                    log::error!("spawn_pending_identity_retry: PENDING_IDENTITIES mutex poisoned during timeout cleanup");
                }
                return;
            }

            match crate::storage::client_db::get_contact_by_device_id(&device_id) {
                Ok(Some(contact)) => {
                    let pending = match PENDING_IDENTITIES.lock() {
                        Ok(mut map) => map.remove(&device_id),
                        Err(e) => {
                            log::error!("spawn_pending_identity_retry: PENDING_IDENTITIES mutex poisoned: {e}");
                            return;
                        }
                    };
                    if let Some(p) = pending {
                        log::info!(
                            "spawn_pending_identity_retry: contact found for {:02x}{:02x}... after {:.1}s",
                            device_id[0], device_id[1], p.buffered_at.elapsed().as_secs_f64()
                        );
                        process_deferred_identity(p, contact);
                    }
                    return;
                }
                Ok(None) => continue,
                Err(e) => {
                    log::error!(
                        "spawn_pending_identity_retry: SQLite error for {:02x}{:02x}...: {}",
                        device_id[0], device_id[1], e
                    );
                    if let Ok(mut map) = PENDING_IDENTITIES.lock() {
                        map.remove(&device_id);
                    } else {
                        log::error!("spawn_pending_identity_retry: PENDING_IDENTITIES mutex poisoned during error cleanup");
                    }
                    return;
                }
            }
        }
    });
}

/// Process a buffered identity after the contact has been found in SQLite.
/// Runs the same pipeline as the synchronous path in `processBleIdentityEnvelope`:
/// update BLE address, register mapping, dispatch to WebView, notify orchestrator,
/// build ACK, deliver ACK via JNI.
fn process_deferred_identity(
    pending: PendingIdentity,
    contact: crate::storage::client_db::ContactRecord,
) {
    let device_id = pending.device_id;
    let genesis_hash = pending.genesis_hash;
    let sender_address = pending.sender_address;

    // 1. Validate genesis hash
    if contact.genesis_hash != genesis_hash {
        log::warn!(
            "process_deferred_identity: genesis hash mismatch for {:02x}{:02x}...",
            device_id[0],
            device_id[1]
        );
        return;
    }

    // 2. Register in-memory BLE address mapping (for routing), but do NOT persist
    // ble_address to SQLite yet. The ble_address column is the sentinel that controls
    // the pairing loop's exit condition — writing it before the scanner confirms
    // receipt of our ACK breaks atomicity (advertiser exits loop, scanner never paired).
    // Persistence happens in handle_pairing_confirm after the scanner's round-trip.
    super::state::register_ble_address_mapping(&device_id, &sender_address);

    // 3. Dispatch identity event to WebView via JNI callback (background thread)
    dispatch_identity_to_webview(&sender_address, &genesis_hash, &device_id);

    // 4. Notify PairingOrchestrator of identity observation
    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
    let rt = crate::runtime::get_runtime();
    if let Err(e) = rt.block_on(orchestrator.handle_identity_observed(
        sender_address.clone(),
        genesis_hash,
        device_id,
    )) {
        log::warn!("process_deferred_identity: orchestrator error: {}", e);
    }

    // 5. Build BlePairingAccept and deliver via JNI — Phase 2 of 3-phase commit.
    // After sending, move orchestrator to AwaitingConfirm (NOT Complete).
    let local_device_id = crate::sdk::app_state::AppState::get_device_id();
    let local_genesis = crate::sdk::app_state::AppState::get_genesis_hash();

    if let (Some(did), Some(gen)) = (local_device_id, local_genesis) {
        if did.len() == 32 && gen.len() == 32 {
            let accept = pb::BlePairingAccept {
                address: sender_address.clone(),
                genesis_hash: gen.to_vec(),
                device_id: did.to_vec(),
            };
            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::PairingAccept(accept)),
            };
            match build_ble_event_envelope(ble_event) {
                Ok(ack_bytes) => {
                    log::info!(
                        "process_deferred_identity: built ACK ({} bytes), delivering to Kotlin for {}",
                        ack_bytes.len(), sender_address
                    );
                    // Move advertiser to AwaitingConfirm — NOT Complete.
                    // ble_address is stored in-memory on the session but NOT in SQLite.
                    // The scanner must confirm receipt before we persist.
                    let _ = rt.block_on(orchestrator.handle_pairing_propose(
                        device_id,
                        sender_address.clone(),
                        None,
                    ));
                    // Deliver ACK to Kotlin GATT server via JNI callback
                    send_deferred_pairing_ack(&sender_address, &ack_bytes);
                }
                Err(e) => {
                    log::error!("process_deferred_identity: failed to build ACK: {}", e);
                }
            }
        }
    }
}

/// Dispatch a framed identity_observed envelope to the WebView via JNI.
/// Uses `jni_common::with_env` to safely attach to the JVM from background threads.
fn dispatch_identity_to_webview(
    sender_address: &str,
    genesis_hash: &[u8; 32],
    device_id: &[u8; 32],
) {
    use jni::objects::JValue;
    let addr = sender_address.to_string();
    let gh = genesis_hash.to_vec();
    let did = device_id.to_vec();

    let result = crate::jni::jni_common::with_env(|env| {
        let mut env =
            unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/bridge/Unified",
        )?;
        let envelope_bytes = create_identity_observed_envelope_inner(addr, gh, did);
        if !envelope_bytes.is_empty() {
            let jbytes = env
                .byte_array_from_slice(&envelope_bytes)
                .map_err(|e| e.to_string())?;
            let _ = env.call_static_method(
                class,
                "dispatchToWebView",
                "([B)V",
                &[JValue::Object(&jbytes.into())],
            );
        }
        Ok(())
    });
    if let Err(e) = result {
        log::warn!("dispatch_identity_to_webview: JNI callback failed: {}", e);
    }
}

/// Deliver a deferred BlePairingAccept envelope to Kotlin via JNI callback.
/// Kotlin will route it through: Unified → UnifiedBleBridge → BleCoordinator → GattServerHost,
/// which sends it as a PAIRING_ACK INDICATE to the scanner.
fn send_deferred_pairing_ack(device_address: &str, ack_bytes: &[u8]) {
    use jni::objects::JValue;
    let addr = device_address.to_string();
    let ack = ack_bytes.to_vec();

    let result = crate::jni::jni_common::with_env(|env| {
        let mut env =
            unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/bridge/Unified",
        )?;
        let j_addr = env.new_string(&addr).map_err(|e| e.to_string())?;
        let j_ack = env.byte_array_from_slice(&ack).map_err(|e| e.to_string())?;
        env.call_static_method(
            class,
            "deliverDeferredPairingAck",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&j_addr), JValue::Object(&j_ack.into())],
        )
        .map_err(|e| e.to_string())?;
        log::info!(
            "send_deferred_pairing_ack: delivered {} bytes to Kotlin for {}",
            ack.len(),
            addr
        );
        Ok(())
    });
    if let Err(e) = result {
        log::error!("send_deferred_pairing_ack: JNI callback failed: {}", e);
    }
}

/// Encode identity (genesis_hash + device_id) as a protobuf BleIdentityCharValue.
/// Returns the proto bytes to set on the GATT identity characteristic.
/// Kotlin MUST NOT concatenate raw bytes — this is the only canonical encoder.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_encodeIdentityCharValue(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    genesis_hash_jbytes: jni::sys::jbyteArray,
    device_id_jbytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "encodeIdentityCharValue",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };

            let genesis_hash: Vec<u8> =
                match env.convert_byte_array(unsafe { jbytes_from(genesis_hash_jbytes) }) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("encodeIdentityCharValue: genesis_hash extraction failed: {e}");
                        return empty(&mut env);
                    }
                };
            let device_id: Vec<u8> =
                match env.convert_byte_array(unsafe { jbytes_from(device_id_jbytes) }) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("encodeIdentityCharValue: device_id extraction failed: {e}");
                        return empty(&mut env);
                    }
                };

            if genesis_hash.len() != 32 || device_id.len() != 32 {
                log::error!(
                    "encodeIdentityCharValue: invalid lengths genesis={} device_id={}",
                    genesis_hash.len(),
                    device_id.len()
                );
                return empty(&mut env);
            }

            let char_value = pb::BleIdentityCharValue {
                genesis_hash,
                device_id,
            };

            let encoded = char_value.encode_to_vec();
            log::info!("encodeIdentityCharValue: encoded {} bytes", encoded.len());

            match env.byte_array_from_slice(&encoded) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!("encodeIdentityCharValue: JNI byte_array_from_slice failed: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Encode the local relationship send-status as a protobuf GATT characteristic value.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_getRelationshipStatusCharValue(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    ble_address_jstr: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "getRelationshipStatusCharValue",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(ble_address_jstr) };
            let ble_address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!(
                        "getRelationshipStatusCharValue: JNI address extraction failed: {e}"
                    );
                    return empty(&mut env);
                }
            };

            let contact = match crate::storage::client_db::get_contact_by_ble_address(&ble_address)
            {
                Ok(Some(contact)) => contact,
                Ok(None) => {
                    log::warn!(
                        "getRelationshipStatusCharValue: no contact mapped to BLE address {}",
                        ble_address
                    );
                    return empty(&mut env);
                }
                Err(e) => {
                    log::error!(
                        "getRelationshipStatusCharValue: failed to load contact for {}: {}",
                        ble_address,
                        e
                    );
                    return empty(&mut env);
                }
            };

            if contact.device_id.len() != 32 {
                log::error!(
                    "getRelationshipStatusCharValue: contact device_id has invalid length {}",
                    contact.device_id.len()
                );
                return empty(&mut env);
            }

            let send_status =
                crate::handlers::relationship_status::derive_local_send_status_for_contact(
                    &contact,
                );
            let char_value = pb::BleRelationshipStatusCharValue {
                counterparty_device_id: contact.device_id.clone(),
                send_status: Some(pb_send_status_from_router_status(send_status)),
            };

            let encoded = char_value.encode_to_vec();
            match env.byte_array_from_slice(&encoded) {
                Ok(arr) => arr.into_raw(),
                Err(e) => {
                    log::error!(
                        "getRelationshipStatusCharValue: JNI byte_array_from_slice failed: {e}"
                    );
                    empty(&mut env)
                }
            }
        }),
    )
}

/// Process raw protobuf bytes read from the GATT identity characteristic.
///
/// This is the canonical path for handling identity reads on the client (scanner) side.
/// Kotlin passes the raw GATT bytes + BLE address to Rust. Rust:
/// 1. Decodes BleIdentityCharValue protobuf
/// 2. Dispatches identity_observed events (SQLite update, orchestrator notification)
/// 3. Builds a write-back envelope (our local identity as a BleEvent.identity_observed)
/// 4. Returns BleGattIdentityReadResult containing the write-back envelope
///
/// Kotlin MUST NOT parse or split identity bytes — this function does everything.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_processGattIdentityRead(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    ble_address_jstr: jni::sys::jstring,
    raw_proto_jbytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "processGattIdentityRead",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let address_jstring = unsafe { jstr_from(ble_address_jstr) };

            let ble_address: String = match env.get_string(&address_jstring) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!("processGattIdentityRead: JNI address extraction failed: {e}");
                    return emit_identity_read_result(
                        &mut env,
                        false,
                        &[],
                        "JNI address extraction failed",
                    );
                }
            };

            let raw_proto: Vec<u8> = match env
                .convert_byte_array(unsafe { jbytes_from(raw_proto_jbytes) })
            {
                Ok(v) => v,
                Err(e) => {
                    log::error!("processGattIdentityRead: JNI byte array extraction failed: {e}");
                    return emit_identity_read_result(
                        &mut env,
                        false,
                        &[],
                        "JNI byte array extraction failed",
                    );
                }
            };

            // Decode BleIdentityCharValue from GATT bytes
            let char_value = match pb::BleIdentityCharValue::decode(raw_proto.as_slice()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("processGattIdentityRead: proto decode failed: {e}");
                    return emit_identity_read_result(
                        &mut env,
                        false,
                        &[],
                        &format!("proto decode failed: {e}"),
                    );
                }
            };

            if char_value.genesis_hash.len() != 32 || char_value.device_id.len() != 32 {
                log::error!(
                    "processGattIdentityRead: invalid field lengths genesis={} device_id={}",
                    char_value.genesis_hash.len(),
                    char_value.device_id.len()
                );
                return emit_identity_read_result(
                    &mut env,
                    false,
                    &[],
                    "invalid identity field lengths",
                );
            }

            log::info!(
                "processGattIdentityRead: addr={}, genesis={:02x}{:02x}..., device={:02x}{:02x}...",
                ble_address,
                char_value.genesis_hash[0],
                char_value.genesis_hash[1],
                char_value.device_id[0],
                char_value.device_id[1]
            );

            // Strict gate: contact must exist in SQLite before dispatching identity and building write-back.
            match crate::storage::client_db::has_contact_for_device_id(&char_value.device_id) {
                Ok(true) => {
                    log::info!(
                        "processGattIdentityRead: contact EXISTS in SQLite for {:02x}{:02x}...",
                        char_value.device_id[0],
                        char_value.device_id[1]
                    );
                }
                Ok(false) => {
                    // Contact not yet in SQLite — poll up to 15 seconds to handle the
                    // QR-scan-vs-BLE-connect race (e.g. QR code accepted while BLE
                    // connection is already in progress). Symmetric with the advertiser's
                    // send_deferred_pairing_ack retry in processBleIdentityEnvelope.
                    let rt = crate::runtime::get_runtime();
                    let device_id_poll = char_value.device_id.clone();
                    let found = rt.block_on(async {
                        for _ in 0..30u32 {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            match crate::storage::client_db::has_contact_for_device_id(
                                &device_id_poll,
                            ) {
                                Ok(true) => return true,
                                Ok(false) => continue,
                                Err(_) => return false,
                            }
                        }
                        false
                    });
                    if !found {
                        log::error!(
                            "processGattIdentityRead: NO contact in SQLite for {:02x}{:02x}... after 15s — hard-fail",
                            char_value.device_id[0], char_value.device_id[1]
                        );
                        return emit_identity_read_result(
                            &mut env,
                            false,
                            &[],
                            "contact missing in SQLite",
                        );
                    }
                    log::info!(
                        "processGattIdentityRead: contact appeared in SQLite during retry window for {:02x}{:02x}...",
                        char_value.device_id[0], char_value.device_id[1]
                    );
                    // Fall through to dispatch and write-back below
                }
                Err(e) => {
                    log::error!(
                "processGattIdentityRead: SQLite query error for {:02x}{:02x}...: {} — hard-fail",
                char_value.device_id[0], char_value.device_id[1], e
            );
                    return emit_identity_read_result(&mut env, false, &[], "SQLite query error");
                }
            }

            // Dispatch identity observed via the existing handler (updates SQLite, notifies orchestrator)
            let obs = pb::BleIdentityObserved {
                address: ble_address.clone(),
                genesis_hash: char_value.genesis_hash.clone(),
                device_id: char_value.device_id.clone(),
            };
            if let Err(e) =
                super::unified_protobuf_bridge::handle_ble_identity_observed_from_envelope(&obs)
            {
                log::error!("processGattIdentityRead: identity dispatch failed: {e}");
                return emit_identity_read_result(
                    &mut env,
                    false,
                    &[],
                    &format!("identity dispatch failed: {e}"),
                );
            }

            // Dispatch identity_observed to frontend so contact.bleMapped fires
            #[cfg(target_os = "android")]
            {
                use jni::objects::JValue;
                if let Ok(class) = env.find_class("com/dsm/wallet/bridge/Unified") {
                    let obs_envelope = create_identity_observed_envelope_inner(
                        ble_address.clone(),
                        char_value.genesis_hash.clone(),
                        char_value.device_id.clone(),
                    );
                    if !obs_envelope.is_empty() {
                        if let Ok(jbytes) = env.byte_array_from_slice(&obs_envelope) {
                            match env.call_static_method(
                                class,
                                "dispatchToWebView",
                                "([B)V",
                                &[JValue::Object(&jbytes.into())],
                            ) {
                                Ok(_) => log::info!(
                            "processGattIdentityRead: dispatched identity_observed to WebView"
                        ),
                                Err(e) => {
                                    log::warn!(
                                        "processGattIdentityRead: dispatchToWebView failed: {e}"
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Build write-back envelope using LOCAL identity (Rust knows our own identity)
            let local_device_id = crate::sdk::app_state::AppState::get_device_id();
            let local_genesis = crate::sdk::app_state::AppState::get_genesis_hash();

            let write_back = match (local_device_id, local_genesis) {
                (Some(did), Some(genesis)) if did.len() == 32 && genesis.len() == 32 => {
                    let local_obs = pb::BleIdentityObserved {
                        address: ble_address.clone(),
                        genesis_hash: genesis.to_vec(),
                        device_id: did.to_vec(),
                    };
                    let ble_event = BleEvent {
                        ev: Some(pb::ble_event::Ev::IdentityObserved(local_obs)),
                    };
                    match build_ble_event_envelope(ble_event) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            log::warn!(
                                "processGattIdentityRead: write-back envelope build failed: {e}"
                            );
                            Vec::new()
                        }
                    }
                }
                _ => {
                    log::warn!(
                        "processGattIdentityRead: local identity not available for write-back"
                    );
                    Vec::new()
                }
            };

            emit_identity_read_result_with_identity(
                &mut env,
                true,
                &write_back,
                "",
                &char_value.device_id,
                &char_value.genesis_hash,
            )
        }),
    )
}

/// Encode and return a BleGattIdentityReadResult as a JNI byte array.
fn emit_identity_read_result(
    env: &mut JNIEnv<'_>,
    success: bool,
    write_back_envelope: &[u8],
    error_message: &str,
) -> jni::sys::jbyteArray {
    emit_identity_read_result_with_identity(
        env,
        success,
        write_back_envelope,
        error_message,
        &[],
        &[],
    )
}

/// Full version that includes the peer's identity for Kotlin-side anchoring.
fn emit_identity_read_result_with_identity(
    env: &mut JNIEnv<'_>,
    success: bool,
    write_back_envelope: &[u8],
    error_message: &str,
    peer_device_id: &[u8],
    peer_genesis_hash: &[u8],
) -> jni::sys::jbyteArray {
    let result = pb::BleGattIdentityReadResult {
        success,
        write_back_envelope: write_back_envelope.to_vec(),
        error_message: error_message.to_string(),
        peer_device_id: peer_device_id.to_vec(),
        peer_genesis_hash: peer_genesis_hash.to_vec(),
    };
    let encoded = result.encode_to_vec();
    match env.byte_array_from_slice(&encoded) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            log::error!("emit_identity_read_result: JNI byte_array_from_slice failed: {e}");
            empty(env)
        }
    }
}

// ============================================================
// Genesis lifecycle event envelope builders
// All authored here in Rust; Kotlin calls these then relays the
// framed bytes verbatim via BleEventRelay.dispatchEnvelope().
// ============================================================

/// Build a BleEvent envelope wrapping a GenesisLifecycleEvent.
fn build_genesis_lifecycle_envelope(
    kind: pb::genesis_lifecycle_event::Kind,
    progress: u32,
) -> Result<Vec<u8>, String> {
    let ev = pb::GenesisLifecycleEvent {
        kind: kind as i32,
        progress,
    };
    let ble_event = BleEvent {
        ev: Some(pb::ble_event::Ev::GenesisLifecycle(ev)),
    };
    build_ble_event_envelope(ble_event)
}

/// genesis.started
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisStartedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisStartedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindStarted,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisStartedEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisStartedEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.ok
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisOkEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisOkEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindOk,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisOkEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisOkEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.error
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisErrorEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisErrorEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindError,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisErrorEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisErrorEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.securing-device
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisSecuringDeviceEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisSecuringDeviceEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringDevice,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisSecuringDeviceEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisSecuringDeviceEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.securing-device-progress (progress 0–100)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisSecuringProgressEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    progress: jni::sys::jint,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisSecuringProgressEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let pct = (progress.clamp(0, 100)) as u32;
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringProgress,
                pct,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisSecuringProgressEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisSecuringProgressEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.securing-device-complete
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisSecuringCompleteEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisSecuringCompleteEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringComplete,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisSecuringCompleteEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisSecuringCompleteEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// genesis.securing-device-aborted
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createGenesisSecuringAbortedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createGenesisSecuringAbortedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            match build_genesis_lifecycle_envelope(
                pb::genesis_lifecycle_event::Kind::GenesisKindSecuringAborted,
                0,
            ) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createGenesisSecuringAbortedEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createGenesisSecuringAbortedEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// ble.permission.error — BLE permission denied (scan or advertise)
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createBlePermissionDeniedEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    operation_jstr: jni::sys::jstring,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createBlePermissionDeniedEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let operation = {
                let js = unsafe { jstr_from(operation_jstr) };
                let x = match env.get_string(&js) {
                    Ok(s) => s.into(),
                    Err(_) => "unknown".to_string(),
                };
                x
            };
            let ev = pb::BlePermissionEvent { operation };
            let ble_event = BleEvent {
                ev: Some(pb::ble_event::Ev::BlePermission(ev)),
            };
            match build_ble_event_envelope(ble_event) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(a) => a.into_raw(),
                    Err(e) => {
                        log::error!("createBlePermissionDeniedEnvelope: {e}");
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createBlePermissionDeniedEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// NFC recovery capsule — wraps raw NdefRecord bytes in a framed Envelope v3.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createNfcRecoveryCapsuleEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    payload_jbytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createNfcRecoveryCapsuleEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let payload = {
                let jb = unsafe { jbytes_from(payload_jbytes) };
                match env.convert_byte_array(jb) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("createNfcRecoveryCapsuleEnvelope: convert_byte_array: {e}");
                        return empty(&mut env);
                    }
                }
            };
            let capsule = pb::NfcRecoveryCapsule { payload };
            let envelope = pb::Envelope {
                version: 3,
                headers: None,
                message_id: vec![0u8; 16],
                payload: Some(pb::envelope::Payload::NfcRecoveryCapsule(capsule)),
            };
            let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
            buf.push(0x03); // Canonical framing byte for FramedEnvelopeV3
            if let Err(e) = envelope.encode(&mut buf) {
                log::error!("createNfcRecoveryCapsuleEnvelope: encode failed: {e}");
                return empty(&mut env);
            }
            match env.byte_array_from_slice(&buf) {
                Ok(a) => a.into_raw(),
                Err(e) => {
                    log::error!("createNfcRecoveryCapsuleEnvelope: byte_array_from_slice: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}

/// NFC write committed — Rust-authored envelope for the frontend event bridge.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_createNfcBackupWrittenEnvelope(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "createNfcBackupWrittenEnvelope",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let resp = pb::AppStateResponse {
                key: "nfc.backup_written".to_string(),
                value: Some("committed=true".to_string()),
            };
            match build_app_state_envelope(resp) {
                Ok(bytes) => match env.byte_array_from_slice(&bytes) {
                    Ok(arr) => arr.into_raw(),
                    Err(e) => {
                        log::error!(
                            "createNfcBackupWrittenEnvelope: byte_array_from_slice failed: {e}"
                        );
                        empty(&mut env)
                    }
                },
                Err(e) => {
                    log::error!("createNfcBackupWrittenEnvelope: {e}");
                    empty(&mut env)
                }
            }
        }),
    )
}
