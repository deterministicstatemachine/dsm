// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Phone->Pico USB-OTG byte bridge. The framing/protocol lives entirely in Rust: callers frame
//! an `ApplianceRequest` (LE32 length ++ prost), hand the OPAQUE bytes to an injected USB
//! round-trip (on Android: a JNI up-call to Kotlin, which only moves bytes; in tests: an in-process
//! transceive), and decode the `ApplianceResponse`. Kotlin never decodes a frame; no key material
//! crosses the boundary. Every failure (USB down, timeout, an op the chip refused, a malformed
//! response) is fail-closed to a `DsmError`.
//!
//! Consumer: [`crate::usb_appliance::UsbAnchorAppliance`] (the sender's release producer).

use std::sync::Arc;

use dsm_sdk::types::error::DsmError;

/// The opaque USB round-trip Kotlin performs: write the length-prefixed request frame to the Pico's
/// USB-CDC endpoint, read the `LE32` length + that many bytes, return the `ApplianceResponse` body.
/// Any transport failure is an `Err` (fail-closed). Blocking is fine — it runs on the SDK's blocking
/// relay task, not the BLE/GATT thread.
pub type UsbTransceive = Arc<dyn Fn(Vec<u8>) -> Result<Vec<u8>, DsmError> + Send + Sync>;

/// What came back over USB, taken as an answer only when there is one. Kotlin's transport hands back
/// an empty array whenever no exchange took place: no appliance on USB, Android not yet letting DSM
/// use it, a write or a read that failed, or a frame the appliance refused without an answer. That
/// is a USB failure, never a response to decode: decoded, it reads as the appliance refusing op 0
/// with error 0, which is how the rig showed a phone waiting for Allow (2026-11-11).
#[cfg(any(target_os = "android", test))]
fn answer_over_usb(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err("no answer over USB: the appliance is not plugged in, Android has not let DSM \
                    use it yet (tap Allow when it asks), the link dropped, or the appliance refused \
                    the frame"
            .to_string());
    }
    Ok(bytes)
}

/// The raw opaque USB round-trip: up-call Kotlin's `Unified.picoUsbTransceive([B)[B`, which does the
/// actual USB-OTG round-trip to A's own Pico. Mirrors `queue_follow_up_chunks`' `with_env` +
/// re-derive-mutable-JNIEnv pattern. Any JNI/USB failure -> `Err` (fail-closed): a null return from
/// Kotlin, and the empty array it returns when no exchange took place ([`answer_over_usb`]). The
/// transport of [`crate::usb_appliance::UsbAnchorAppliance`].
#[cfg(target_os = "android")]
pub(crate) fn jni_usb_transceive(frame: Vec<u8>) -> Result<Vec<u8>, DsmError> {
    use jni::objects::{JByteArray, JObject, JValue};
    dsm_sdk::jni::jni_common::with_env(|env| -> Result<Vec<u8>, String> {
        // Re-derive a mutable JNIEnv from the raw handle (same as queue_follow_up_chunks).
        let mut env = unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _) }
            .map_err(|e| format!("clone JNIEnv: {e}"))?;
        let cls = dsm_sdk::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/bridge/Unified",
        )?;
        let arr = env
            .byte_array_from_slice(&frame)
            .map_err(|e| format!("byte_array_from_slice: {e}"))?;
        let arr_obj = JObject::from(arr);
        let res = env
            .call_static_method(
                &cls,
                "picoUsbTransceive",
                "([B)[B",
                &[JValue::Object(&arr_obj)],
            )
            .map_err(|e| format!("call picoUsbTransceive: {e}"))?;
        let obj = res.l().map_err(|e| format!("result not object: {e}"))?;
        if obj.is_null() {
            return Err("picoUsbTransceive returned null (USB failure)".to_string());
        }
        let bytes = env
            .convert_byte_array(JByteArray::from(obj))
            .map_err(|e| format!("convert_byte_array: {e}"))?;
        answer_over_usb(bytes)
    })
    .map_err(|e| DsmError::invalid_operation(format!("usb-pico JNI up-call: {e}")))
}

#[cfg(test)]
mod tests {
    use super::answer_over_usb;
    use anchor_core::proto::{encode_response, pb};

    #[test]
    fn no_bytes_over_usb_is_no_answer() {
        let refused = answer_over_usb(Vec::new()).expect_err("no bytes came back: no answer");
        assert!(refused.contains("no answer over USB"), "{refused}");
    }

    #[test]
    fn bytes_over_usb_are_the_answer_as_sent() {
        let frame = encode_response(&pb::ApplianceResponse {
            op: pb::Op::Status as i32,
            active_anchor_counter: 3,
            ..Default::default()
        });
        assert_eq!(answer_over_usb(frame.clone()).expect("an answer"), frame);
    }
}
