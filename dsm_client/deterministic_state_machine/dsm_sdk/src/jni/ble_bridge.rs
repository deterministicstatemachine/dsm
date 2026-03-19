// SPDX-License-Identifier: MIT OR Apache-2.0
//! JNI entrypoints for routing Android BLE events into the canonical Rust BLE bridge.
//!
//! This provides a raw-bytes interface: Kotlin encodes BleEvent (prost) → byte[] and calls
//! into these methods. We decode minimally and forward to AndroidBleBridge which can return
//! outgoing BleCommand (prost) bytes as a response for immediate write.
#![cfg(all(target_os = "android", feature = "bluetooth"))]

use jni::objects::{JByteArray, JClass};
use jni::JNIEnv;
use prost::Message;

use crate::bluetooth::android_ble_bridge::{get_global_android_bridge};
use crate::generated as pb;

// Helper removed; we now use higher-level JNIEnv/JByteArray directly.

/// Handle a BLE event from Android service and optionally return a BLE command to write.
/// Signature in Kotlin: `native byte[] handleBleEvent(byte[] eventProto)`
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_DsmBluetoothService_handleBleEvent<'a>(
    env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    event: JByteArray<'a>,
) -> JByteArray<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let data = match env.convert_byte_array(&event) {
            Ok(v) => v,
            Err(e) => {
                log::error!("[JNI][BLE] convert_byte_array failed: {e}");
                return env
                    .new_byte_array(0)
                    .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) });
            }
        };

        let bridge = match get_global_android_bridge() {
            Some(b) => b,
            None => {
                log::warn!("[JNI][BLE] Global AndroidBleBridge not registered; dropping event");
                return env
                    .new_byte_array(0)
                    .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) });
            }
        };

        // Forward to bridge; if it returns Some(bytes), send back to Java for immediate write
        let result = crate::runtime::get_runtime()
            .block_on(async move { bridge.handle_ble_event_bytes(&data).await });
        match result {
            Ok(Some(bytes)) => {
                // Return prost-encoded BleCommand to Kotlin
                env.byte_array_from_slice(&bytes)
                    .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) })
            }
            Ok(None) | Err(_) => env
                .new_byte_array(0)
                .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) }),
        }
    }));
    match result {
        Ok(value) => value,
        Err(panic) => {
            let msg = crate::jni::bridge_utils::panic_message(&panic);
            log::error!("handleBleEvent: panic captured: {}", msg);
            env.new_byte_array(0)
                .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) })
        }
    }
}

/// Convenience JNI: construct a BleCommand from fields and return prost bytes for writing.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_DsmBluetoothService_encodeBleCommand<'a>(
    env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    command_type: i32,
    payload: JByteArray<'a>,
) -> JByteArray<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let payload_bytes = env.convert_byte_array(&payload).unwrap_or_default();

        let ev = match command_type as i32 {
            // 1: StartScan, 2: StopScan, 3: StartAdvertising, 4: StopAdvertising, 5: Connect, 6: Disconnect, 7: Write, 8: Read
            7 => pb::BleCommand {
                cmd: Some(pb::ble_command::Cmd::WriteCharacteristic(
                    pb::BleWriteCharacteristic {
                        address: String::new(),
                        data: payload_bytes,
                    },
                )),
            },
            _ => pb::BleCommand { cmd: None },
        };
        let mut out = Vec::new();
        if ev.encode(&mut out).is_err() {
            out.clear();
        }
        env.byte_array_from_slice(&out)
            .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) })
    }));
    match result {
        Ok(value) => value,
        Err(panic) => {
            let msg = crate::jni::bridge_utils::panic_message(&panic);
            log::error!("encodeBleCommand: panic captured: {}", msg);
            env.new_byte_array(0)
                .unwrap_or_else(|_| unsafe { JByteArray::from_raw(std::ptr::null_mut()) })
        }
    }
}
