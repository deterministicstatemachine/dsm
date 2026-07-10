// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Phone->Pico USB-OTG byte bridge. The framing/protocol lives entirely in Rust: callers frame
//! an `ApplianceRequest` (LE32 length ++ prost), hand the OPAQUE bytes to an injected USB
//! round-trip (on Android: a JNI up-call to Kotlin, which only moves bytes; in tests: a mock), and
//! decode the `ApplianceResponse`. Kotlin never decodes a TROPIC frame; no key material crosses the
//! boundary. Every failure (USB down, timeout, `ok=false`, malformed response) is fail-closed to a
//! `DsmError`.
//!
//! Consumers: [`crate::usb_appliance::UsbAnchorAppliance`] (the sender's release producer) and
//! [`crate::se_slot`]'s sync SPI channel (`OP_SPI_PASSTHROUGH` for device setup/diagnostics).

use std::sync::Arc;

use anchor_core::proto::{decode_response, encode_request, pb};
use dsm_sdk::types::error::DsmError;

/// The opaque USB round-trip Kotlin performs: write the length-prefixed request frame to the Pico's
/// USB-CDC endpoint, read the `LE32` length + that many bytes, return the `ApplianceResponse` body.
/// Any transport failure is an `Err` (fail-closed). Blocking is fine — it runs on the SDK's blocking
/// relay task, not the BLE/GATT thread.
pub type UsbTransceive = Arc<dyn Fn(Vec<u8>) -> Result<Vec<u8>, DsmError> + Send + Sync>;

/// Build the length-prefixed `OP_SPI_PASSTHROUGH` request frame for a raw SPI MOSI (LE32 body len ++
/// `ApplianceRequest`). Consumed by the sync device-setup SPI channel in [`crate::se_slot`]
/// (Android-only), so host lib builds see it as dead code.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn frame_passthrough(mosi: Vec<u8>) -> Vec<u8> {
    let req = pb::ApplianceRequest {
        op: pb::Op::SpiPassthrough as i32,
        spi_payload: mosi,
        ..Default::default()
    };
    let body = encode_request(&req);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Decode an `ApplianceResponse` body (already length-stripped by Kotlin) and return `spi_response`,
/// or a fail-closed `DsmError` on a malformed frame / `ok=false`.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn decode_passthrough(resp_body: &[u8]) -> Result<Vec<u8>, DsmError> {
    let resp = decode_response(resp_body).map_err(|e| {
        DsmError::invalid_operation(format!("usb-pico: decode ApplianceResponse: {e:?}"))
    })?;
    if !resp.ok {
        return Err(DsmError::invalid_operation(format!(
            "usb-pico: passthrough error code {}",
            resp.error
        )));
    }
    Ok(resp.spi_response)
}

/// The raw opaque USB round-trip: up-call Kotlin's `Unified.picoUsbTransceive([B)[B`, which does the
/// actual USB-OTG round-trip to A's own Pico. Mirrors `queue_follow_up_chunks`' `with_env` +
/// re-derive-mutable-JNIEnv pattern. Any JNI/USB failure -> `Err` (fail-closed); a null return from
/// Kotlin (no device / permission / timeout) is a USB failure. Shared by the
/// [`crate::usb_appliance::UsbAnchorAppliance`] transport and the sync setup SPI channel.
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
        env.convert_byte_array(JByteArray::from(obj))
            .map_err(|e| format!("convert_byte_array: {e}"))
    })
    .map_err(|e| DsmError::invalid_operation(format!("usb-pico JNI up-call: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appliance_ok_response(spi_response: Vec<u8>) -> Vec<u8> {
        anchor_core::proto::encode_response(&pb::ApplianceResponse {
            op: pb::Op::SpiPassthrough as i32,
            ok: true,
            spi_response,
            ..Default::default()
        })
    }

    #[test]
    fn passthrough_frame_round_trips_through_an_echo_pico() {
        // Echo-Pico: decode the request frame the way the real firmware would, echo MOSI as MISO.
        let frame = frame_passthrough(vec![1, 2, 3, 4]);
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        let req = anchor_core::proto::decode_request(&frame[4..4 + len]).unwrap();
        assert_eq!(req.op, pb::Op::SpiPassthrough as i32);
        let miso = decode_passthrough(&appliance_ok_response(req.spi_payload)).expect("decode ok");
        assert_eq!(miso, vec![1, 2, 3, 4]);
    }

    #[test]
    fn pico_error_status_fails_closed() {
        let body = anchor_core::proto::encode_response(&pb::ApplianceResponse {
            op: pb::Op::SpiPassthrough as i32,
            ok: false,
            error: 7,
            ..Default::default()
        });
        assert!(decode_passthrough(&body).is_err());
    }

    #[test]
    fn malformed_response_fails_closed() {
        assert!(decode_passthrough(&[0xFF, 0xFF, 0xFF]).is_err());
    }
}
