// SPDX-License-Identifier: MIT OR Apache-2.0

//! # BLE Event Envelope Builders
//!
//! Constructs protobuf-encoded BLE event envelopes for the JNI bridge.
//! Uses `Payload::BleEvent` from the updated proto schema to wrap BLE
//! scan results, connection events, and data payloads for delivery to
//! the Kotlin layer.

use crate::generated as pb;
use jni::objects::{JByteArray, JObject, JString};
use jni::JNIEnv;
use pb::{BleDeviceInfo, BleEvent};
use prost::Message;

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

/// Build a framed Envelope with BleEvent as the direct payload, for the
/// WebView (a local answer: no headers, no message id). Never a frame sent to
/// a peer: every radio byte is a link handshake fragment or a sealed record
/// (`bluetooth::link_session`).
/// Uses the dedicated Payload::BleEvent field (proto schema v2.4+).
pub(crate) fn build_ble_event_envelope(ble_event: BleEvent) -> Result<Vec<u8>, String> {
    Ok(crate::host::ble_event_envelope(ble_event))
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
