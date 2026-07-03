// SPDX-License-Identifier: MIT OR Apache-2.0
//! H2 — the Phone->Pico USB-OTG bridge. `UsbPicoTransport` implements the SDK's
//! [`LocalPicoTransport`](dsm_sdk::bluetooth::tropic_relay::LocalPicoTransport): the sender phone A
//! forwards a relayed raw-SPI MOSI to its own Pico over USB and returns the MISO, using the SAME
//! `OP_SPI_PASSTHROUGH` framing the bench tools proved.
//!
//! The framing/protocol lives entirely in Rust: this wraps the MOSI in an `ApplianceRequest`,
//! length-prefixes it, hands the OPAQUE bytes to an injected USB round-trip (on Android: a JNI
//! up-call to Kotlin, which only moves bytes; in tests: a mock), then decodes the `ApplianceResponse`
//! and returns `spi_response`. Kotlin never decodes a TROPIC frame; no key material crosses the
//! boundary. Every failure (USB down, timeout, `ok=false`, malformed response) is fail-closed to a
//! `DsmError` — the relay read then yields no counter and the transfer recovers online.

use std::sync::Arc;

use anchor_core::proto::{decode_response, encode_request, pb};
use dsm_sdk::bluetooth::tropic_relay::{LocalPicoTransport, PicoFuture};
use dsm_sdk::types::error::DsmError;

/// The opaque USB round-trip Kotlin performs: write the length-prefixed request frame to the Pico's
/// USB-CDC endpoint, read the `LE32` length + that many bytes, return the `ApplianceResponse` body.
/// Any transport failure is an `Err` (fail-closed). Blocking is fine — it runs on the SDK's blocking
/// relay task, not the BLE/GATT thread.
pub type UsbTransceive = Arc<dyn Fn(Vec<u8>) -> Result<Vec<u8>, DsmError> + Send + Sync>;

/// Frames `OP_SPI_PASSTHROUGH` in Rust and delegates the raw byte round-trip to `usb`.
pub struct UsbPicoTransport {
    usb: UsbTransceive,
}

impl UsbPicoTransport {
    /// `usb` performs one opaque USB round-trip (request frame bytes -> response body bytes).
    pub fn new(usb: UsbTransceive) -> Self {
        Self { usb }
    }

    /// Build the length-prefixed `OP_SPI_PASSTHROUGH` request frame for a raw SPI MOSI.
    fn frame_request(mosi: Vec<u8>) -> Vec<u8> {
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
}

impl LocalPicoTransport for UsbPicoTransport {
    fn spi_passthrough(&self, mosi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>> {
        let usb = self.usb.clone();
        Box::pin(async move {
            let frame = Self::frame_request(mosi);
            log::debug!("[usb-pico] passthrough req len={}", frame.len());
            let resp_body = match usb(frame) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("[usb-pico] USB round-trip failed (recover online): {e}");
                    return Err(e);
                }
            };
            log::debug!("[usb-pico] passthrough resp len={}", resp_body.len());
            let resp = decode_response(&resp_body).map_err(|e| {
                log::warn!("[usb-pico] malformed passthrough response (recover online): {e:?}");
                DsmError::invalid_operation(format!("usb-pico: decode ApplianceResponse: {e:?}"))
            })?;
            if !resp.ok {
                log::warn!(
                    "[usb-pico] Pico reported passthrough error code {} (recover online)",
                    resp.error
                );
                return Err(DsmError::invalid_operation(format!(
                    "usb-pico: passthrough error code {}",
                    resp.error
                )));
            }
            Ok(resp.spi_response)
        })
    }
}

/// The on-device constructor: `usb` up-calls Kotlin's opaque `Unified.picoUsbTransceive([B)[B`,
/// which does the actual USB-OTG round-trip to the Pico. Mirrors `queue_follow_up_chunks`'
/// `with_env` + re-derive-mutable-JNIEnv pattern. Any JNI/USB failure -> `Err` (fail-closed). A
/// null return from Kotlin (no device / permission / timeout) is treated as a USB failure. This
/// path is Android-only; host builds/tests use `UsbPicoTransport::new` with a mock.
#[cfg(target_os = "android")]
pub fn android_usb_pico_transport() -> UsbPicoTransport {
    use jni::objects::{JByteArray, JObject, JValue};
    UsbPicoTransport::new(Arc::new(|frame: Vec<u8>| -> Result<Vec<u8>, DsmError> {
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
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    fn appliance_ok_response(spi_response: Vec<u8>) -> Vec<u8> {
        let resp = pb::ApplianceResponse {
            op: pb::Op::SpiPassthrough as i32,
            ok: true,
            spi_response,
            ..Default::default()
        };
        // Response body is the encoded ApplianceResponse (Kotlin already stripped the length prefix).
        anchor_core::proto::encode_response(&resp)
    }

    #[test]
    fn happy_path_frames_request_and_returns_decoded_miso() {
        // Echo-Pico: decode the request frame, return an ok response carrying the MOSI as MISO.
        let usb: UsbTransceive = Arc::new(|frame: Vec<u8>| {
            // Strip the LE32 length prefix and decode the request the way the real Pico would.
            let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
            let req = anchor_core::proto::decode_request(&frame[4..4 + len]).unwrap();
            assert_eq!(req.op, pb::Op::SpiPassthrough as i32);
            Ok(appliance_ok_response(req.spi_payload)) // MISO = MOSI (echo)
        });
        let t = UsbPicoTransport::new(usb);
        let miso = block_on(t.spi_passthrough(vec![1, 2, 3, 4])).expect("passthrough ok");
        assert_eq!(miso, vec![1, 2, 3, 4]);
    }

    #[test]
    fn usb_error_fails_closed() {
        let usb: UsbTransceive =
            Arc::new(|_frame| Err(DsmError::invalid_operation("cable disconnected")));
        let t = UsbPicoTransport::new(usb);
        assert!(block_on(t.spi_passthrough(vec![9])).is_err());
    }

    #[test]
    fn pico_error_status_fails_closed() {
        let usb: UsbTransceive = Arc::new(|_frame| {
            let resp = pb::ApplianceResponse {
                op: pb::Op::SpiPassthrough as i32,
                ok: false,
                error: 7,
                ..Default::default()
            };
            Ok(anchor_core::proto::encode_response(&resp))
        });
        let t = UsbPicoTransport::new(usb);
        assert!(block_on(t.spi_passthrough(vec![9])).is_err());
    }

    #[test]
    fn malformed_response_fails_closed() {
        let usb: UsbTransceive = Arc::new(|_frame| Ok(vec![0xFF, 0xFF, 0xFF]));
        let t = UsbPicoTransport::new(usb);
        assert!(block_on(t.spi_passthrough(vec![9])).is_err());
    }
}
