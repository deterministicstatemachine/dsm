// path: dsm_client/deterministic_state_machine/dsm_sdk/src/jni/helpers.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! JNI helpers (prost-only transport; NO JSON/base64/hex)

#![allow(dead_code)]
#![allow(clippy::needless_pass_by_value)]

use crate::generated as pb;

use prost::Message;

/// Encode a deterministic transport-level error as an Envelope v3.
/// Uses `Default` to remain schema-stable across minor proto changes.
pub fn encode_error_transport(code: u32, msg: &str) -> pb::Envelope {
    // Build the error without the debug field first to compute canonical bytes
    let mut err = pb::Error {
        code,
        message: msg.to_string(),
        ..Default::default()
    };

    // Encode canonical error bytes (without debug field) and compute Base32-Crockford debug string
    let mut tmp = Vec::new();
    if err.encode(&mut tmp).is_ok() {
        let dbg = base32::encode(base32::Alphabet::Crockford, &tmp);
        err.debug_b32 = dbg;
    } else {
        // Alternate path: compute base32 over UTF-8 textual representation
        let textual = format!("{}:{}", code, msg);
        err.debug_b32 = base32::encode(base32::Alphabet::Crockford, textual.as_bytes());
    }

    pb::Envelope {
        version: 3,
        payload: Some(pb::envelope::Payload::Error(err)),
        ..Default::default()
    }
}

/// Optional success shim if you later wrap raw bytes under a universal channel.
/// Currently returns an empty `UniversalRx`.
pub fn encode_universal_ok() -> pb::Envelope {
    pb::Envelope {
        version: 3,
        payload: Some(pb::envelope::Payload::UniversalRx(pb::UniversalRx {
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[cfg(target_os = "android")]
#[derive(Debug, Clone)]
pub struct JniResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    /// Deterministic tick (no wall clock)
    pub tick: u64,
}

#[cfg(target_os = "android")]
impl<T> JniResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            tick: crate::util::deterministic_time::tick(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            tick: crate::util::deterministic_time::tick(),
        }
    }
}

/// Minimal JNI error taxonomy for upstream mapping (no std/time/alloc bloat)
#[derive(Debug, Clone, Copy)]
pub enum JniErrorCode {
    InvalidInput = 1,
    ProcessingFailed = 2,
    EncodingFailed = 3,
    RuntimeError = 4,
    NotReady = 5,
    BridgeCallFailed = 6,
    DeserializeError = 7,
}

impl JniErrorCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_error_transport_round_trip() {
        let env = encode_error_transport(JniErrorCode::ProcessingFailed as u32, "unit test failed");
        assert_eq!(env.version, 3);
        match env.payload {
            Some(pb::envelope::Payload::Error(e)) => {
                assert_eq!(e.code, JniErrorCode::ProcessingFailed as u32);
                assert_eq!(e.message, "unit test failed");
                // debug_b32 should be present and decode to some bytes
                assert!(e.debug_b32.is_some());
                let dbg = e.debug_b32.unwrap();
                let decoded = match base32::decode(base32::Alphabet::Crockford, &dbg) {
                    Ok(d) => d,
                    Err(e) => panic!("debug_b32 should decode: {:?}", e),
                };
                assert!(decoded.len() > 0);
            }
            other => panic!("Unexpected payload: {:?}", other),
        }
    }
}

/// JNI external: Check if a contact exists for the given device_id.
/// Used by BLE layer to prevent binding to unknown devices.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_hasContactForDeviceId(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    device_id: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "hasContactForDeviceId",
        std::panic::AssertUnwindSafe(|| {
            use jni::objects::JByteArray;
            use jni::sys::{JNI_FALSE, JNI_TRUE};

            let device_id_obj = unsafe { JByteArray::from_raw(device_id) };
            let device_id_bytes = match _env.convert_byte_array(device_id_obj) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::warn!(
                        "[JNI] hasContactForDeviceId: failed to convert device_id: {}",
                        e
                    );
                    return JNI_FALSE;
                }
            };

            if device_id_bytes.len() != 32 {
                log::warn!(
                    "[JNI] hasContactForDeviceId: invalid device_id length: {}",
                    device_id_bytes.len()
                );
                return JNI_FALSE;
            }

            match crate::storage::client_db::has_contact_for_device_id(&device_id_bytes) {
                Ok(exists) => {
                    if exists {
                        JNI_TRUE
                    } else {
                        JNI_FALSE
                    }
                }
                Err(e) => {
                    log::warn!("[JNI] hasContactForDeviceId: storage query failed: {}", e);
                    JNI_FALSE
                }
            }
        }),
    )
}

/// JNI external: Check if a BLE address is fully paired (has ble_address in contact database).
/// Returns true if the address has a completed pairing, false otherwise.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isBleAddressPaired(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    address_jstring: jni::sys::jstring,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "isBleAddressPaired",
        std::panic::AssertUnwindSafe(|| {
            use jni::objects::JString;
            use jni::sys::{JNI_FALSE, JNI_TRUE};

            let address_obj = unsafe { JString::from_raw(address_jstring) };
            let address: String = match env.get_string(&address_obj) {
                Ok(js) => js.into(),
                Err(e) => {
                    log::warn!("[JNI] isBleAddressPaired: failed to convert address: {}", e);
                    return JNI_FALSE;
                }
            };

            // Check if any contact has this BLE address
            match crate::storage::client_db::is_ble_address_paired(&address) {
                Ok(is_paired) => {
                    if is_paired {
                        JNI_TRUE
                    } else {
                        JNI_FALSE
                    }
                }
                Err(e) => {
                    log::warn!("[JNI] isBleAddressPaired: storage query failed: {}", e);
                    JNI_FALSE
                }
            }
        }),
    )
}

/// JNI external: Check if an envelope contains a BilateralCommit operation.
/// Used by DsmBluetoothService to detect commit envelopes and trigger retransmission.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isCommitEnvelope(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "isCommitEnvelope",
        std::panic::AssertUnwindSafe(|| {
            use jni::objects::JByteArray;
            use jni::sys::{JNI_FALSE, JNI_TRUE};
            use prost::Message;

            let envelope_obj = unsafe { JByteArray::from_raw(envelope_bytes) };
            let bytes = match env.convert_byte_array(envelope_obj) {
                Ok(b) => b,
                Err(e) => {
                    log::error!(
                        "[JNI] isCommitEnvelope: failed to convert envelope bytes: {}",
                        e
                    );
                    return JNI_FALSE;
                }
            };

            // Decode envelope
            let envelope = match crate::generated::Envelope::decode(&bytes[..]) {
                Ok(e) => e,
                Err(e) => {
                    log::debug!("[JNI] isCommitEnvelope: failed to decode envelope: {}", e);
                    return JNI_FALSE;
                }
            };

            // Check if payload is UniversalTx with Invoke("bilateral.commit") operation (canonical path)
            if let Some(crate::generated::envelope::Payload::UniversalTx(tx)) = envelope.payload {
                if let Some(first_op) = tx.ops.first() {
                    if let Some(crate::generated::universal_op::Kind::Invoke(inv)) =
                        first_op.kind.as_ref()
                    {
                        if inv.method == "bilateral.commit" {
                            log::info!("[JNI] isCommitEnvelope: detected bilateral.commit invoke");
                            return JNI_TRUE;
                        }
                    }
                }
            }

            JNI_FALSE
        }),
    )
}

/// JNI external: Check if an envelope is a BilateralPrepareReject and return reason bytes.
/// Returns empty byte array if not a reject envelope or on error.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_isRejectEnvelope(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    envelope_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "isRejectEnvelope",
        std::panic::AssertUnwindSafe(|| {
            use jni::objects::JByteArray;
            use prost::Message;

            let envelope_obj = unsafe { JByteArray::from_raw(envelope_bytes) };
            let bytes = match env.convert_byte_array(envelope_obj) {
                Ok(b) => b,
                Err(e) => {
                    log::error!(
                        "[JNI] isRejectEnvelope: failed to convert envelope bytes: {}",
                        e
                    );
                    return env
                        .byte_array_from_slice(&[])
                        .map(|a| a.into_raw())
                        .unwrap_or(std::ptr::null_mut());
                }
            };

            let envelope = match crate::generated::Envelope::decode(&bytes[..]) {
                Ok(e) => e,
                Err(e) => {
                    log::debug!("[JNI] isRejectEnvelope: failed to decode envelope: {}", e);
                    return env
                        .byte_array_from_slice(&[])
                        .map(|a| a.into_raw())
                        .unwrap_or(std::ptr::null_mut());
                }
            };

            if let Some(crate::generated::envelope::Payload::BilateralPrepareReject(rej)) =
                envelope.payload
            {
                let reason = rej.reason;
                return env
                    .byte_array_from_slice(reason.as_bytes())
                    .map(|a| a.into_raw())
                    .unwrap_or(std::ptr::null_mut());
            }

            env.byte_array_from_slice(&[])
                .map(|a| a.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }),
    )
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_notifyBleIdentityObserved(
    mut _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ble_address: jni::objects::JString,
    genesis_hash_bytes: jni::sys::jbyteArray,
    device_id_bytes: jni::sys::jbyteArray,
) {
    crate::jni::bridge_utils::jni_catch_unwind_void(
        "notifyBleIdentityObserved",
        std::panic::AssertUnwindSafe(|| {
            use jni::objects::JByteArray;

            // Convert BLE address
            let address: String = match _env.get_string(&ble_address) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::error!(
                        "[JNI] notifyBleIdentityObserved: failed to convert address: {}",
                        e
                    );
                    return;
                }
            };

            // Convert genesis_hash bytes (32 bytes)
            let genesis_hash_obj = unsafe { JByteArray::from_raw(genesis_hash_bytes) };
            let genesis_hash_vec = match _env.convert_byte_array(genesis_hash_obj) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "[JNI] notifyBleIdentityObserved: failed to convert genesis_hash: {}",
                        e
                    );
                    return;
                }
            };

            if genesis_hash_vec.len() != 32 {
                log::error!(
                    "[JNI] notifyBleIdentityObserved: invalid genesis_hash length: {}",
                    genesis_hash_vec.len()
                );
                return;
            }

            let mut genesis_hash_array = [0u8; 32];
            genesis_hash_array.copy_from_slice(&genesis_hash_vec);

            // Convert device_id bytes (32 bytes)
            let device_id_obj = unsafe { JByteArray::from_raw(device_id_bytes) };
            let device_id_vec = match _env.convert_byte_array(device_id_obj) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "[JNI] notifyBleIdentityObserved: failed to convert device_id: {}",
                        e
                    );
                    return;
                }
            };

            if device_id_vec.len() != 32 {
                log::error!(
                    "[JNI] notifyBleIdentityObserved: invalid device_id length: {}",
                    device_id_vec.len()
                );
                return;
            }

            let mut device_id_array = [0u8; 32];
            device_id_array.copy_from_slice(&device_id_vec);

            log::info!("[JNI] notifyBleIdentityObserved: address={}, genesis_hash={:02x}{:02x}..., device_id={:02x}{:02x}...",
            address, genesis_hash_array[0], genesis_hash_array[1], device_id_array[0], device_id_array[1]);

            // ═══════════════════════════════════════════════════════════════════════════════
            // CRITICAL: Always update contact's BLE address when we observe their identity.
            // This handles BLE MAC address rotation - the stored address may be stale.
            // ═══════════════════════════════════════════════════════════════════════════════
            if let Ok(Some(contact)) =
                crate::storage::client_db::get_contact_by_device_id(&device_id_array)
            {
                // Verify genesis hash matches before updating
                if contact.genesis_hash == genesis_hash_array {
                    let needs_update = contact.ble_address.as_ref() != Some(&address);
                    if needs_update {
                        log::info!(
                        "[JNI] notifyBleIdentityObserved: 🔄 Updating BLE address for contact {:02x}{:02x}...: {} → {}",
                        device_id_array[0], device_id_array[1],
                        contact.ble_address.as_deref().unwrap_or("(none)"),
                        address
                    );
                        match crate::storage::client_db::update_contact_ble_status(
                            &device_id_array,
                            None, // Don't change chain tip
                            Some(&address),
                        ) {
                            Ok(()) => {
                                log::info!(
                                "[JNI] notifyBleIdentityObserved: ✅ BLE address updated in SQLite for {:02x}{:02x}...",
                                device_id_array[0], device_id_array[1]
                            );
                                // Note: In-memory contact caches will pick up the change on next storage read.
                                // No separate in-memory update needed since SQLite is the source of truth.

                                // ═══════════════════════════════════════════════════════════════════════════════
                                // NEW: Dispatch BLE identity mapped event to frontend immediately
                                // ═══════════════════════════════════════════════════════════════════════════════
                                #[cfg(target_os = "android")]
                                {
                                    use jni::objects::JValue;

                                    if let Some(vm) = crate::jni::jni_common::get_java_vm_borrowed()
                                    {
                                        if let Ok(mut jenv) = vm.attach_current_thread() {
                                            let class_name = "com/dsm/wallet/bridge/Unified";
                                            if let Ok(class) = jenv.find_class(class_name) {
                                                // Generate strictly framed V3 envelope
                                                let envelope_bytes = crate::jni::ble_events::create_identity_observed_envelope_inner(
                                                address.clone(),
                                                genesis_hash_array.to_vec(),
                                                device_id_array.to_vec(),
                                            );

                                                // Send raw bytes via dispatchToWebView
                                                if !envelope_bytes.is_empty() {
                                                    if let Ok(jbytes) =
                                                        jenv.byte_array_from_slice(&envelope_bytes)
                                                    {
                                                        let method_result = jenv
                                                            .call_static_method(
                                                                class,
                                                                "dispatchToWebView",
                                                                "([B)V",
                                                                &[JValue::Object(&jbytes.into())],
                                                            );
                                                        if let Err(e) = method_result {
                                                            log::warn!("[JNI] notifyBleIdentityObserved: Failed to call dispatchToWebView: {}", e);
                                                        } else {
                                                            log::info!("[JNI] notifyBleIdentityObserved: ✅ Dispatched framed identity_observed envelope");
                                                        }
                                                    }
                                                }
                                            } else {
                                                log::warn!("[JNI] notifyBleIdentityObserved: Could not find Unified class");
                                            }
                                        } else {
                                            log::warn!("[JNI] notifyBleIdentityObserved: Could not attach to JVM thread");
                                        }
                                    } else {
                                        log::warn!(
                                            "[JNI] notifyBleIdentityObserved: JavaVM not available"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!(
                                "[JNI] notifyBleIdentityObserved: ❌ Failed to update BLE address: {}",
                                e
                            );
                            }
                        }
                    } else {
                        log::debug!(
                        "[JNI] notifyBleIdentityObserved: BLE address unchanged for {:02x}{:02x}...",
                        device_id_array[0],
                        device_id_array[1]
                    );
                    }
                } else {
                    log::warn!(
                    "[JNI] notifyBleIdentityObserved: genesis hash mismatch for {:02x}{:02x}... - NOT updating",
                    device_id_array[0], device_id_array[1]
                );
                }
            }

            // Notify pairing orchestrator
            let orchestrator = crate::bluetooth::get_pairing_orchestrator();

            // Use global runtime to avoid runtime drop panics in async context
            let rt = crate::runtime::get_runtime();

            match rt.block_on(orchestrator.handle_identity_observed(
                address.clone(),
                genesis_hash_array,
                device_id_array,
            )) {
                Ok(()) => {
                    log::info!(
                        "[JNI] notifyBleIdentityObserved: successfully notified orchestrator"
                    );

                    // Check if pairing completed and trigger contact refresh
                    if let Some(status) =
                        rt.block_on(orchestrator.get_session_status(&device_id_array))
                    {
                        if matches!(
                            status,
                            crate::bluetooth::pairing_orchestrator::PairingState::Complete
                        ) {
                            log::info!("[JNI] PAIRING_STATUS_CHANGED");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("[JNI] notifyBleIdentityObserved: orchestrator error (may not have active session): {}", e);
                }
            }
        }),
    );
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_hasUnpairedContacts(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "hasUnpairedContacts",
        std::panic::AssertUnwindSafe(|| {
            use jni::sys::{JNI_FALSE, JNI_TRUE};

            let has_unpaired = crate::storage::client_db::has_unpaired_contacts();

            if has_unpaired {
                log::debug!(
                    "[JNI] hasUnpairedContacts: true - persistent scanning should be active"
                );
                JNI_TRUE
            } else {
                log::debug!("[JNI] hasUnpairedContacts: false - can stop persistent scanning");
                JNI_FALSE
            }
        }),
    )
}

/// Start the pairing loop for all unpaired contacts.
/// Spawns on the tokio runtime (fire-and-forget). The loop runs until all contacts are
/// paired or stopPairingAll() is called.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_startPairingAll(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) {
    log::info!("[JNI] startPairingAll invoked");
    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
    if orchestrator.is_loop_running() {
        log::info!("[JNI] startPairingAll: loop already running, ignoring");
        return;
    }
    crate::runtime::get_runtime().spawn(async move {
        orchestrator.start_pairing_all_unpaired().await;
    });
}

/// Stop the pairing loop. Safe to call even if no loop is running.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_stopPairingAll(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) {
    log::info!("[JNI] stopPairingAll invoked");
    let orchestrator = crate::bluetooth::get_pairing_orchestrator();
    orchestrator.stop_pairing_loop();
}
