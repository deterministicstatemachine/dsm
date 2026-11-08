// path: dsm_client/deterministic_state_machine/dsm_sdk/src/jni/helpers.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! JNI helpers (prost-only transport; NO JSON/base64/hex)

#![allow(clippy::needless_pass_by_value)]

use crate::generated as pb;

use prost::Message;

/// Wrap `payload` for this device's own app: a local answer, with no sender
/// headers and no message id.
pub fn encode_payload_transport(payload: pb::envelope::Payload) -> pb::Envelope {
    crate::envelope::local_answer(payload)
}

/// Encode a deterministic transport-level error as an Envelope v3.
pub fn encode_error_transport(code: u32, msg: &str) -> pb::Envelope {
    let mut err = pb::Error {
        code,
        message: msg.to_string(),
        ..Default::default()
    };

    let mut tmp = Vec::new();
    if err.encode(&mut tmp).is_ok() {
        let dbg = base32::encode(base32::Alphabet::Crockford, &tmp);
        err.debug_b32 = dbg;
    } else {
        let textual = format!("{}:{}", code, msg);
        err.debug_b32 = base32::encode(base32::Alphabet::Crockford, textual.as_bytes());
    }

    encode_payload_transport(pb::envelope::Payload::Error(err))
}

pub fn encode_universal_ok() -> pb::Envelope {
    encode_payload_transport(pb::envelope::Payload::UniversalRx(pb::UniversalRx {
        ..Default::default()
    }))
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
        assert!(
            env.headers.is_none() && env.message_id.is_empty(),
            "a local answer"
        );
        match env.payload {
            Some(pb::envelope::Payload::Error(e)) => {
                assert_eq!(e.code, JniErrorCode::ProcessingFailed as u32);
                assert_eq!(e.message, "unit test failed");
                // debug_b32 is present and decodes to some bytes
                assert!(!e.debug_b32.is_empty());
                let decoded = base32::decode(base32::Alphabet::Crockford, &e.debug_b32)
                    .expect("debug_b32 decodes");
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
            let envelope = match crate::envelope::from_canonical_bytes(&bytes[..]) {
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

            let envelope = match crate::envelope::from_canonical_bytes(&bytes[..]) {
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
