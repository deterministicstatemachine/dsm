// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bridge's wire shapes, decoded and encoded for the Swift host.
//!
//! Kotlin reads `proto/dsm_app.proto` through generated classes. Swift reads
//! none of it: every protobuf the page and the host exchange is decoded and
//! encoded here, by the same generated Rust types the SDK uses, so the Swift
//! shell holds bytes it does not interpret. The shapes are the ones
//! `BridgeEnvelopeCodec.kt` names: `BridgeRpcRequest` and `BridgeRpcResponse`
//! on the page's port, `NativeHostEvent` and
//! `NativeHostRequest`/`Response` on the private host boundary,
//! `PreferencePayload`, `BilateralPayload`, and the identity in a
//! `GenesisCreatedResponse`.

use std::os::raw::c_char;

use prost::Message;

use crate::ffi::{bytes_from, str_from, DsmBytes};
use crate::generated as pb;

/// The longest method name a `BridgeRpcRequest` may carry.
const METHOD_MAX_BYTES: usize = 128;

/// The decoded request, validated as `BridgeEnvelopeCodec.parseBridgeRequest`
/// validates it: the method present, at most 128 bytes, an identifier.
fn bridge_request(bytes: &[u8]) -> Result<pb::BridgeRpcRequest, String> {
    let request = pb::BridgeRpcRequest::decode(bytes)
        .map_err(|e| format!("BridgeRpcRequest does not decode: {e}"))?;
    if request.method.is_empty() {
        return Err("BridgeRpcRequest.method missing".to_string());
    }
    if request.method.len() > METHOD_MAX_BYTES {
        return Err(format!(
            "BridgeRpcRequest.method too long: {} bytes (max {METHOD_MAX_BYTES})",
            request.method.len()
        ));
    }
    if !request
        .method
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    {
        return Err(format!(
            "BridgeRpcRequest.method invalid characters: '{}'",
            request.method
        ));
    }
    Ok(request)
}

/// The payload of a `BridgeRpcRequest`, as the Kotlin dispatcher reads it:
/// the inner bytes of the bytes, string and BLE payloads, and the message's
/// own bytes for the typed payloads the dispatcher decodes itself.
pub fn bridge_request_payload(request: &pb::BridgeRpcRequest) -> Vec<u8> {
    use pb::bridge_rpc_request::Payload;
    match &request.payload {
        None | Some(Payload::Empty(_)) => Vec::new(),
        Some(Payload::Bytes(bytes)) => bytes.data.clone(),
        Some(Payload::String(text)) => text.value.as_bytes().to_vec(),
        Some(Payload::Preference(preference)) => preference.encode_to_vec(),
        Some(Payload::AppRouter(app_router)) => app_router.encode_to_vec(),
        Some(Payload::BleContact(contact)) => contact.pairing_data.clone(),
        Some(Payload::BleAddress(address)) => address.device_id.clone(),
        Some(Payload::Bilateral(bilateral)) => bilateral.encode_to_vec(),
    }
}

/// The method of a `BridgeRpcRequest`, as UTF-8; no bytes when the request
/// does not decode or its method is not valid (the host answers an error).
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bridge_request_method(request: *const u8, len: usize) -> DsmBytes {
    match bridge_request(bytes_from(request, len)) {
        Ok(request) => DsmBytes::from_vec(request.method.into_bytes()),
        Err(e) => {
            log::warn!("[ffi] a bridge request was refused: {e}");
            DsmBytes::none()
        }
    }
}

/// Why a `BridgeRpcRequest` is refused, as UTF-8; no bytes when it is valid.
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bridge_request_refusal(request: *const u8, len: usize) -> DsmBytes {
    DsmBytes::outcome(bridge_request(bytes_from(request, len)).map(|_| ()))
}

/// The payload of a valid `BridgeRpcRequest` (see [`bridge_request_payload`]).
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bridge_request_payload(request: *const u8, len: usize) -> DsmBytes {
    match bridge_request(bytes_from(request, len)) {
        Ok(request) => DsmBytes::from_vec(bridge_request_payload(&request)),
        Err(_refused) => DsmBytes::none(),
    }
}

/// A `BridgeRpcResponse` carrying `data` as its success.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bridge_success(data: *const u8, len: usize) -> DsmBytes {
    let response = pb::BridgeRpcResponse {
        result: Some(pb::bridge_rpc_response::Result::Success(
            pb::SuccessResponse {
                data: bytes_from(data, len).to_vec(),
            },
        )),
    };
    DsmBytes::from_vec(response.encode_to_vec())
}

/// A `BridgeRpcResponse` carrying an error. The debug string is the Base32
/// Crockford of the error without itself, as Kotlin's `createErrorResponse`.
///
/// # Safety
/// `message` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bridge_error(error_code: u32, message: *const c_char) -> DsmBytes {
    let message = match str_from(message, "the error message") {
        Ok(message) => message.to_string(),
        Err(why) => why,
    };
    let preimage = pb::ErrorResponse {
        error_code,
        message: message.clone(),
        debug_b32: String::new(),
    };
    let response = pb::BridgeRpcResponse {
        result: Some(pb::bridge_rpc_response::Result::Error(pb::ErrorResponse {
            error_code,
            message,
            debug_b32: base32::encode(base32::Alphabet::Crockford, &preimage.encode_to_vec()),
        })),
    };
    DsmBytes::from_vec(response.encode_to_vec())
}

fn native_host_event(kind: pb::NativeHostEventKind, payload: Vec<u8>) -> DsmBytes {
    DsmBytes::from_vec(
        pb::NativeHostEvent {
            kind: kind as i32,
            payload,
        }
        .encode_to_vec(),
    )
}

/// The QR scanner's result for the page: a `NativeHostEvent` of kind
/// QR_SCAN_RESULT carrying `QrScanResultPayload { text }`; an empty text is
/// a cancelled scan.
///
/// # Safety
/// `text` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_qr_scan_result_event(text: *const c_char) -> DsmBytes {
    let text_utf8 = match str_from(text, "the QR text") {
        Ok(text) => text.to_string(),
        Err(why) => {
            log::warn!("[ffi] a QR result was not framed: {why}");
            return DsmBytes::none();
        }
    };
    native_host_event(
        pb::NativeHostEventKind::QrScanResult,
        pb::QrScanResultPayload { text_utf8 }.encode_to_vec(),
    )
}

/// The phone contact the user picked (DSM Amendment A17), for the page: a
/// `NativeHostEvent` of kind PHONE_CONTACT_PICKED carrying a
/// `ContactProfileV1`, or carrying no bytes when `display_name` is null (the
/// user picked none, or did not allow the read).
///
/// # Safety
/// Each string must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_phone_contact_picked_event(
    display_name: *const c_char,
    email: *const c_char,
    phone: *const c_char,
    phone_lookup_key: *const c_char,
) -> DsmBytes {
    let kind = pb::NativeHostEventKind::PhoneContactPicked;
    if display_name.is_null() {
        return native_host_event(kind, Vec::new());
    }
    let field = |ptr: *const c_char, what: &str| -> Result<String, String> {
        if ptr.is_null() {
            Ok(String::new())
        } else {
            str_from(ptr, what).map(str::to_string)
        }
    };
    let profile = (|| -> Result<pb::ContactProfileV1, String> {
        Ok(pb::ContactProfileV1 {
            display_name: field(display_name, "the contact's name")?,
            email: field(email, "the contact's email")?,
            phone: field(phone, "the contact's phone")?,
            phone_lookup_key: field(phone_lookup_key, "the contact's lookup key")?,
            ..Default::default()
        })
    })();
    match profile {
        Ok(profile) => native_host_event(kind, profile.encode_to_vec()),
        Err(why) => {
            log::warn!("[ffi] a picked contact was not framed: {why}");
            DsmBytes::none()
        }
    }
}

/// The kind of a `NativeHostRequest` the page sent on the private host
/// boundary, as its enum number; 0 when the bytes do not decode.
///
/// # Safety
/// `request` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_native_host_request_kind(request: *const u8, len: usize) -> i32 {
    match pb::NativeHostRequest::decode(bytes_from(request, len)) {
        Ok(request) => request.kind,
        Err(e) => {
            log::warn!("[ffi] a native host request does not decode: {e}");
            pb::NativeHostRequestKind::Unspecified as i32
        }
    }
}

/// The `NativeHostResponse` to a host request, from what the host did: with
/// `code` 0 the request was carried out and the response is an acknowledging
/// `NativeHostAck`; with any other code it is the refusal `message` under
/// that code, recoverable, as `NativeHostBridge.errorResponse` answers one.
///
/// # Safety
/// `message` must be null (with code 0) or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_native_host_response(code: u32, message: *const c_char) -> DsmBytes {
    let result = if code == 0 {
        pb::native_host_response::Result::OkBytes(
            pb::NativeHostAck {
                success: code == 0,
                ..Default::default()
            }
            .encode_to_vec(),
        )
    } else {
        let message = match str_from(message, "the refusal") {
            Ok(message) => message.to_string(),
            Err(why) => why,
        };
        pb::native_host_response::Result::Error(pb::Error {
            code,
            message,
            is_recoverable: code != 0,
            ..Default::default()
        })
    };
    DsmBytes::from_vec(
        pb::NativeHostResponse {
            result: Some(result),
        }
        .encode_to_vec(),
    )
}

/// Every preference key the page keeps (`runtime/skinKeys.ts` and the
/// screens that own the others), as `BridgePreferencesHandler.kt` lists
/// them. The page reads and writes these keys and no other: the host's
/// preference store also holds the identity pointers a cold start restores,
/// and a page script must not be able to repoint them.
const PAGE_KEYS: [&str; 14] = [
    "ui_skin",
    "ui_scheme",
    "simple_mode",
    "simple_offline",
    "receipts_email",
    "beta_agreement",
    "ui_theme",
    "sfx_enabled",
    "dev_mode",
    "ui_tour_seen",
    "profile_photo",
    "profile_banner",
    "diagnostics_consent",
    "lock_prompt_dismissed",
];

/// A contact's photo, by the contact's device id (`components/modern/contactPhotos.ts`).
const CONTACT_PHOTO_PREFIX: &str = "contact_photo_";
/// A 32-byte device id in Base32 Crockford: 52 characters of its alphabet.
const DEVICE_ID_B32_LEN: usize = 52;
const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Whether `key` is a preference the page keeps.
pub fn page_keeps(key: &str) -> bool {
    PAGE_KEYS.contains(&key)
        || key
            .strip_prefix(CONTACT_PHOTO_PREFIX)
            .is_some_and(|id| id.len() == DEVICE_ID_B32_LEN && id.chars().all(|c| CROCKFORD.contains(c)))
}

/// The key of a `PreferencePayload` when it is one the page keeps, as UTF-8;
/// no bytes when it does not decode, names no key, or names a key the page
/// does not keep (the host answers that the key is not the page's).
///
/// # Safety
/// `payload` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_preference_key(payload: *const u8, len: usize) -> DsmBytes {
    match pb::PreferencePayload::decode(bytes_from(payload, len)) {
        Ok(preference) if page_keeps(&preference.key) => {
            DsmBytes::from_vec(preference.key.into_bytes())
        }
        Ok(preference) => {
            log::warn!(
                "[ffi] \"{}\" is not a preference the page keeps",
                preference.key
            );
            DsmBytes::none()
        }
        Err(e) => {
            log::warn!("[ffi] a preference payload does not decode: {e}");
            DsmBytes::none()
        }
    }
}

/// Whether a `PreferencePayload` carries a value (a set), 1, or none (a get), 0.
///
/// # Safety
/// `payload` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_preference_has_value(payload: *const u8, len: usize) -> i32 {
    match pb::PreferencePayload::decode(bytes_from(payload, len)) {
        Ok(preference) => i32::from(preference.value.is_some()),
        Err(_undecodable) => 0,
    }
}

/// The value of a `PreferencePayload`, as UTF-8; no bytes when it carries none.
///
/// # Safety
/// `payload` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_preference_value(payload: *const u8, len: usize) -> DsmBytes {
    match pb::PreferencePayload::decode(bytes_from(payload, len)) {
        Ok(pb::PreferencePayload {
            value: Some(value),
            ..
        }) => DsmBytes::from_vec(value.into_bytes()),
        Ok(_) => DsmBytes::none(),
        Err(_undecodable) => DsmBytes::none(),
    }
}

/// The 32-byte commitment of a `BilateralPayload`; no bytes when it does not
/// decode or the commitment is not 32 bytes.
///
/// # Safety
/// `payload` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bilateral_commitment(payload: *const u8, len: usize) -> DsmBytes {
    match pb::BilateralPayload::decode(bytes_from(payload, len)) {
        Ok(bilateral) if bilateral.commitment.len() == 32 => {
            DsmBytes::from_vec(bilateral.commitment)
        }
        Ok(bilateral) => {
            log::warn!(
                "[ffi] a bilateral payload's commitment is {} bytes, not 32",
                bilateral.commitment.len()
            );
            DsmBytes::none()
        }
        Err(e) => {
            log::warn!("[ffi] a bilateral payload does not decode: {e}");
            DsmBytes::none()
        }
    }
}

/// The reason of a `BilateralPayload`, as UTF-8; no bytes when it carries none.
///
/// # Safety
/// `payload` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_bilateral_reason(payload: *const u8, len: usize) -> DsmBytes {
    match pb::BilateralPayload::decode(bytes_from(payload, len)) {
        Ok(pb::BilateralPayload {
            reason: Some(reason),
            ..
        }) => DsmBytes::from_vec(reason.into_bytes()),
        Ok(_) => DsmBytes::none(),
        Err(_undecodable) => DsmBytes::none(),
    }
}

/// The identity a framed `GenesisCreatedResponse` envelope installs: its
/// 32-byte device id then its 32-byte genesis hash, 64 bytes; no bytes when
/// the envelope is not that, or either part is not 32 bytes.
///
/// # Safety
/// `envelope` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_genesis_created_identity(envelope: *const u8, len: usize) -> DsmBytes {
    let bytes = bytes_from(envelope, len);
    let raw = match bytes.first() {
        Some(0x03) if bytes.len() > 1 => &bytes[1..],
        _ => bytes,
    };
    // A local answer, as `Envelope.parseFrom` reads it on Android: no sender
    // headers and no message id to check.
    let envelope = match pb::Envelope::decode(raw) {
        Ok(envelope) => envelope,
        Err(e) => {
            log::warn!("[ffi] a genesis envelope does not decode: {e}");
            return DsmBytes::none();
        }
    };
    let Some(pb::envelope::Payload::GenesisCreatedResponse(created)) = envelope.payload else {
        log::warn!("[ffi] the envelope is not a GenesisCreatedResponse");
        return DsmBytes::none();
    };
    let genesis = created.genesis_hash.map(|hash| hash.v);
    match (created.device_id, genesis) {
        (device_id, Some(genesis)) if device_id.len() == 32 && genesis.len() == 32 => {
            DsmBytes::from_vec([device_id, genesis].concat())
        }
        (device_id, genesis) => {
            log::warn!(
                "[ffi] a genesis envelope with a {}-byte device id and a {:?}-byte genesis",
                device_id.len(),
                genesis.map(|g| g.len())
            );
            DsmBytes::none()
        }
    }
}

/// An `ArchitectureInfoProto`, the diagnostics screen's picture of the device
/// the host measured: its status word, architecture, the ABIs it runs, and
/// the host's message and recommendation.
///
/// # Safety
/// Each string must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_architecture_info(
    status: *const c_char,
    device_arch: *const c_char,
    supported_abis: *const c_char,
    message: *const c_char,
    recommendation: *const c_char,
) -> DsmBytes {
    let info = (|| -> Result<pb::ArchitectureInfoProto, String> {
        Ok(pb::ArchitectureInfoProto {
            status: str_from(status, "the status")?.to_string(),
            device_arch: str_from(device_arch, "the architecture")?.to_string(),
            supported_abis: str_from(supported_abis, "the ABIs")?.to_string(),
            message: str_from(message, "the message")?.to_string(),
            recommendation: str_from(recommendation, "the recommendation")?.to_string(),
        })
    })();
    match info {
        Ok(info) => DsmBytes::from_vec(info.encode_to_vec()),
        Err(why) => {
            log::warn!("[ffi] the architecture info was not framed: {why}");
            DsmBytes::none()
        }
    }
}

/// A `ResultPack`'s body, for a router query's answer (`system.generateMnemonic`
/// answers the mnemonic's UTF-8 there); no bytes when it does not decode.
///
/// # Safety
/// `pack` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_result_pack_body(pack: *const u8, len: usize) -> DsmBytes {
    match pb::ResultPack::decode(bytes_from(pack, len)) {
        Ok(result) => DsmBytes::from_vec(result.body),
        Err(e) => {
            log::warn!("[ffi] a result pack does not decode: {e}");
            DsmBytes::none()
        }
    }
}

/// An `ArgPack` of codec PROTO around `body`, the argument shape router
/// routes take.
///
/// # Safety
/// `body` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_arg_pack(body: *const u8, len: usize) -> DsmBytes {
    DsmBytes::from_vec(
        pb::ArgPack {
            codec: pb::Codec::Proto as i32,
            body: bytes_from(body, len).to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

/// A `WalletCreateGenesisV2Request` around `mnemonic`.
///
/// # Safety
/// `mnemonic` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_create_genesis_v2_request(mnemonic: *const c_char) -> DsmBytes {
    match str_from(mnemonic, "the mnemonic") {
        Ok(mnemonic) if !mnemonic.trim().is_empty() => DsmBytes::from_vec(
            pb::WalletCreateGenesisV2Request {
                mnemonic: mnemonic.to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        Ok(_) => DsmBytes::none(),
        Err(why) => {
            log::warn!("[ffi] a genesis request was not framed: {why}");
            DsmBytes::none()
        }
    }
}

/// An `IngressRequest` for a router invoke of `method` with `args`.
///
/// # Safety
/// `method` must be a NUL-terminated string; `args` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_router_invoke_request(
    method: *const c_char,
    args: *const u8,
    len: usize,
) -> DsmBytes {
    router_request(method, args, len, |method, args| {
        pb::ingress_request::Operation::RouterInvoke(pb::RouterInvokeOp { method, args })
    })
}

/// An `IngressRequest` for a router query of `method` with `args`.
///
/// # Safety
/// `method` must be a NUL-terminated string; `args` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_router_query_request(
    method: *const c_char,
    args: *const u8,
    len: usize,
) -> DsmBytes {
    router_request(method, args, len, |method, args| {
        pb::ingress_request::Operation::RouterQuery(pb::RouterQueryOp { method, args })
    })
}

unsafe fn router_request(
    method: *const c_char,
    args: *const u8,
    len: usize,
    operation: impl FnOnce(String, Vec<u8>) -> pb::ingress_request::Operation,
) -> DsmBytes {
    match str_from(method, "the route") {
        Ok(method) if !method.is_empty() => DsmBytes::from_vec(
            pb::IngressRequest {
                operation: Some(operation(
                    method.to_string(),
                    bytes_from(args, len).to_vec(),
                )),
            }
            .encode_to_vec(),
        ),
        Ok(_) => DsmBytes::none(),
        Err(why) => {
            log::warn!("[ffi] a router request was not framed: {why}");
            DsmBytes::none()
        }
    }
}

/// The ok bytes of an `IngressResponse`; no bytes when it is an error or
/// does not decode (ask [`dsm_ffi_ingress_error_message`] why).
///
/// # Safety
/// `response` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ingress_ok_bytes(response: *const u8, len: usize) -> DsmBytes {
    match pb::IngressResponse::decode(bytes_from(response, len)) {
        Ok(pb::IngressResponse {
            result: Some(pb::ingress_response::Result::OkBytes(bytes)),
        }) => DsmBytes::from_vec(bytes),
        Ok(_) => DsmBytes::none(),
        Err(_undecodable) => DsmBytes::none(),
    }
}

/// Why an `IngressResponse` is not an answer, as UTF-8: its error's message,
/// "returned no result", or why it does not decode. No bytes when it is ok.
///
/// # Safety
/// `response` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_ingress_error_message(response: *const u8, len: usize) -> DsmBytes {
    match pb::IngressResponse::decode(bytes_from(response, len)) {
        Ok(pb::IngressResponse {
            result: Some(pb::ingress_response::Result::OkBytes(_)),
        }) => DsmBytes::none(),
        Ok(pb::IngressResponse {
            result: Some(pb::ingress_response::Result::Error(error)),
        }) => DsmBytes::text(&error.message),
        Ok(pb::IngressResponse { result: None }) => DsmBytes::text("ingress returned no result"),
        Err(e) => DsmBytes::text(&format!("IngressResponse does not decode: {e}")),
    }
}

/// The ok bytes of a `StartupResponse`, as [`dsm_ffi_ingress_ok_bytes`].
///
/// # Safety
/// `response` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_ffi_startup_error_message(response: *const u8, len: usize) -> DsmBytes {
    match pb::StartupResponse::decode(bytes_from(response, len)) {
        Ok(pb::StartupResponse {
            result: Some(pb::startup_response::Result::OkBytes(_)),
        }) => DsmBytes::none(),
        Ok(pb::StartupResponse {
            result: Some(pb::startup_response::Result::Error(error)),
        }) => DsmBytes::text(&error.message),
        Ok(pb::StartupResponse { result: None }) => DsmBytes::text("startup returned no result"),
        Err(e) => DsmBytes::text(&format!("StartupResponse does not decode: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(bytes: DsmBytes) -> Vec<u8> {
        let copy = unsafe { bytes_from(bytes.ptr, bytes.len) }.to_vec();
        unsafe { crate::ffi::dsm_bytes_free(bytes) };
        copy
    }

    fn c(text: &str) -> std::ffi::CString {
        std::ffi::CString::new(text).expect("no NUL")
    }

    /// The request the page's port sends decodes to its method and payload
    /// as Kotlin's codec reads them; a method with a `/` is refused.
    #[test]
    fn a_bridge_request_yields_its_method_and_payload() {
        let request = pb::BridgeRpcRequest {
            method: "nativeBoundaryIngress".to_string(),
            payload: Some(pb::bridge_rpc_request::Payload::Bytes(pb::BytesPayload {
                data: vec![9, 8, 7],
            })),
        }
        .encode_to_vec();
        let method = taken(unsafe { dsm_ffi_bridge_request_method(request.as_ptr(), request.len()) });
        assert_eq!(method, b"nativeBoundaryIngress");
        let payload =
            taken(unsafe { dsm_ffi_bridge_request_payload(request.as_ptr(), request.len()) });
        assert_eq!(payload, [9, 8, 7]);
        assert!(taken(unsafe {
            dsm_ffi_bridge_request_refusal(request.as_ptr(), request.len())
        })
        .is_empty());

        let bad = pb::BridgeRpcRequest {
            method: "../etc".to_string(),
            payload: None,
        }
        .encode_to_vec();
        assert!(taken(unsafe { dsm_ffi_bridge_request_method(bad.as_ptr(), bad.len()) }).is_empty());
        let why = taken(unsafe { dsm_ffi_bridge_request_refusal(bad.as_ptr(), bad.len()) });
        assert!(String::from_utf8(why).expect("utf-8").contains("invalid characters"));
    }

    #[test]
    fn responses_carry_success_or_a_coded_error() {
        let ok = taken(unsafe { dsm_ffi_bridge_success([1u8, 2].as_ptr(), 2) });
        match pb::BridgeRpcResponse::decode(ok.as_slice()).expect("decodes").result {
            Some(pb::bridge_rpc_response::Result::Success(s)) => assert_eq!(s.data, [1, 2]),
            other => panic!("not a success: {other:?}"),
        }
        let msg = c("Unknown binary RPC method: foo");
        let err = taken(unsafe { dsm_ffi_bridge_error(8, msg.as_ptr()) });
        match pb::BridgeRpcResponse::decode(err.as_slice()).expect("decodes").result {
            Some(pb::bridge_rpc_response::Result::Error(e)) => {
                assert_eq!(e.error_code, 8);
                assert_eq!(e.message, "Unknown binary RPC method: foo");
                let preimage = base32::decode(base32::Alphabet::Crockford, &e.debug_b32)
                    .expect("decodes");
                let inner = pb::ErrorResponse::decode(preimage.as_slice()).expect("an ErrorResponse");
                assert_eq!(inner.error_code, 8);
                assert!(inner.debug_b32.is_empty());
            }
            other => panic!("not an error: {other:?}"),
        }
    }

    #[test]
    fn host_events_carry_their_kind_and_payload() {
        let text = c("dsm:contact/v3:ABC");
        let qr = taken(unsafe { dsm_ffi_qr_scan_result_event(text.as_ptr()) });
        let host_event = pb::NativeHostEvent::decode(qr.as_slice()).expect("decodes");
        assert_eq!(host_event.kind, pb::NativeHostEventKind::QrScanResult as i32);
        let payload = pb::QrScanResultPayload::decode(host_event.payload.as_slice()).expect("decodes");
        assert_eq!(payload.text_utf8, "dsm:contact/v3:ABC");

        let none = taken(unsafe {
            dsm_ffi_phone_contact_picked_event(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        });
        let picked = pb::NativeHostEvent::decode(none.as_slice()).expect("decodes");
        assert_eq!(picked.kind, pb::NativeHostEventKind::PhoneContactPicked as i32);
        assert!(picked.payload.is_empty());
    }

    #[test]
    fn preferences_and_bilateral_payloads_decode_to_their_parts() {
        let set = pb::PreferencePayload {
            key: "ui_skin".to_string(),
            value: Some("modern".to_string()),
        }
        .encode_to_vec();
        assert_eq!(taken(unsafe { dsm_ffi_preference_key(set.as_ptr(), set.len()) }), b"ui_skin");
        assert_eq!(unsafe { dsm_ffi_preference_has_value(set.as_ptr(), set.len()) }, 1);
        assert_eq!(taken(unsafe { dsm_ffi_preference_value(set.as_ptr(), set.len()) }), b"modern");
        let get = pb::PreferencePayload {
            key: "ui_skin".to_string(),
            value: None,
        }
        .encode_to_vec();
        assert_eq!(unsafe { dsm_ffi_preference_has_value(get.as_ptr(), get.len()) }, 0);

        // A key the page does not keep names nothing: the identity pointers
        // the host stores beside the page's keys stay out of a page's reach.
        let not_the_pages = pb::PreferencePayload {
            key: "device_id_bytes".to_string(),
            value: Some("ZZZZ".to_string()),
        }
        .encode_to_vec();
        assert!(taken(unsafe {
            dsm_ffi_preference_key(not_the_pages.as_ptr(), not_the_pages.len())
        })
        .is_empty());
        assert!(page_keeps(&format!("contact_photo_{}", "7".repeat(52))));
        assert!(!page_keeps("contact_photo_7"));
        assert!(!page_keeps(""));

        let bilateral = pb::BilateralPayload {
            commitment: vec![0x5a; 32],
            reason: Some("changed my mind".to_string()),
        }
        .encode_to_vec();
        assert_eq!(
            taken(unsafe { dsm_ffi_bilateral_commitment(bilateral.as_ptr(), bilateral.len()) }),
            vec![0x5a; 32]
        );
        assert_eq!(
            taken(unsafe { dsm_ffi_bilateral_reason(bilateral.as_ptr(), bilateral.len()) }),
            b"changed my mind"
        );
        let short = pb::BilateralPayload {
            commitment: vec![0x5a; 31],
            reason: None,
        }
        .encode_to_vec();
        assert!(taken(unsafe { dsm_ffi_bilateral_commitment(short.as_ptr(), short.len()) }).is_empty());
    }

    #[test]
    fn a_genesis_envelope_yields_its_identity_and_nothing_else_does() {
        let created = pb::GenesisCreated {
            device_id: vec![0x11; 32],
            genesis_hash: Some(pb::Hash32 { v: vec![0x22; 32] }),
            ..Default::default()
        };
        let framed = crate::host::framed_local_answer(
            pb::envelope::Payload::GenesisCreatedResponse(created),
        );
        let identity = taken(unsafe { dsm_ffi_genesis_created_identity(framed.as_ptr(), framed.len()) });
        assert_eq!(identity.len(), 64);
        assert!(identity[..32].iter().all(|b| *b == 0x11));
        assert!(identity[32..].iter().all(|b| *b == 0x22));

        let other = crate::host::framed_local_answer(pb::envelope::Payload::UniversalRx(
            pb::UniversalRx::default(),
        ));
        assert!(taken(unsafe { dsm_ffi_genesis_created_identity(other.as_ptr(), other.len()) }).is_empty());
    }

    #[test]
    fn router_requests_and_their_answers_round_trip() {
        let method = c("system.generateMnemonic");
        let request = taken(unsafe { dsm_ffi_router_query_request(method.as_ptr(), std::ptr::null(), 0) });
        match pb::IngressRequest::decode(request.as_slice()).expect("decodes").operation {
            Some(pb::ingress_request::Operation::RouterQuery(op)) => {
                assert_eq!(op.method, "system.generateMnemonic");
                assert!(op.args.is_empty());
            }
            other => panic!("not a query: {other:?}"),
        }

        let ok = pb::IngressResponse {
            result: Some(pb::ingress_response::Result::OkBytes(vec![4, 2])),
        }
        .encode_to_vec();
        assert_eq!(taken(unsafe { dsm_ffi_ingress_ok_bytes(ok.as_ptr(), ok.len()) }), [4, 2]);
        assert!(taken(unsafe { dsm_ffi_ingress_error_message(ok.as_ptr(), ok.len()) }).is_empty());

        let refused = pb::IngressResponse {
            result: Some(pb::ingress_response::Result::Error(pb::Error {
                code: 2,
                message: "the wallet is locked".to_string(),
                ..Default::default()
            })),
        }
        .encode_to_vec();
        assert!(taken(unsafe { dsm_ffi_ingress_ok_bytes(refused.as_ptr(), refused.len()) }).is_empty());
        assert_eq!(
            taken(unsafe { dsm_ffi_ingress_error_message(refused.as_ptr(), refused.len()) }),
            b"the wallet is locked"
        );
    }
}
