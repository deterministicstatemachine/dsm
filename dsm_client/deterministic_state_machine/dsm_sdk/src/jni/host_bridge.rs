// SPDX-License-Identifier: MIT OR Apache-2.0

//! Android as the SDK's host: every [`HostBridge`] call is a JNI up-call into
//! the Kotlin that owns the radio, the page and the Keystore.

use jni::objects::{JByteArray, JObject, JObjectArray, JValue};
use jni::JNIEnv;

use crate::bluetooth::link_session::Link;
use crate::host::{Delivery, HostBridge};
use crate::jni::jni_common::{find_class_with_app_loader, with_env};

const UNIFIED: &str = "com/dsm/wallet/bridge/Unified";
const KEYSTORE_VAULT: &str = "com/dsm/wallet/security/KeystoreVault";

/// The Kotlin side of the host.
pub struct AndroidHost;

/// A `byte[][]` of `chunks`.
pub(crate) fn chunk_array<'a>(
    env: &mut JNIEnv<'a>,
    chunks: &[Vec<u8>],
) -> Result<JObjectArray<'a>, String> {
    let byte_array_class = env
        .find_class("[B")
        .map_err(|e| format!("find_class([B) failed: {e}"))?;
    let array = env
        .new_object_array(chunks.len() as i32, &byte_array_class, JObject::null())
        .map_err(|e| format!("new_object_array failed: {e}"))?;
    for (i, chunk) in chunks.iter().enumerate() {
        let bytes = env
            .byte_array_from_slice(chunk)
            .map_err(|e| format!("byte_array_from_slice failed for chunk {i}: {e}"))?;
        env.set_object_array_element(&array, i as i32, bytes)
            .map_err(|e| format!("set_object_array_element failed for chunk {i}: {e}"))?;
    }
    Ok(array)
}

/// Call a static `()Z` on `Unified`; `Err` when it answered no.
fn unified_answers_yes(method: &'static str) -> Result<(), String> {
    let answered = with_env(|env| {
        let mut env =
            unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = find_class_with_app_loader(&mut env, UNIFIED)?;
        env.call_static_method(&class, method, "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| format!("Unified.{method} failed: {e}"))
    })?;
    if answered {
        Ok(())
    } else {
        Err(format!("Unified.{method} answered no"))
    }
}

/// `KeystoreVault.seal([B)[B` or `.open([B)[B`.
fn keystore(method: &'static str, input: &[u8]) -> Result<Vec<u8>, String> {
    with_env(|env| {
        let mut env =
            unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = find_class_with_app_loader(&mut env, KEYSTORE_VAULT)?;
        let input = env
            .byte_array_from_slice(input)
            .map_err(|e| e.to_string())?;
        let answer = env
            .call_static_method(class, method, "([B)[B", &[JValue::Object(&input.into())])
            .map_err(|e| format!("KeystoreVault.{method} upcall failed: {e}"))?;
        let object = answer.l().map_err(|e| e.to_string())?;
        if object.is_null() {
            return Err(format!("KeystoreVault.{method} returned null"));
        }
        env.convert_byte_array(JByteArray::from(object))
            .map_err(|e| e.to_string())
    })
}

impl HostBridge for AndroidHost {
    fn post_event(&self, topic: &str, payload: &[u8]) -> Result<(), String> {
        crate::jni::event_dispatch::post_event_to_webview(topic, payload).map_err(|e| e.to_string())
    }

    fn show_money_received(&self, count: i32) -> Result<(), String> {
        crate::jni::event_dispatch::show_money_received(count).map_err(|e| e.to_string())
    }

    fn write_on_link(&self, link: &Link, sealed: &[Vec<u8>]) -> Result<Delivery, String> {
        let written = with_env(|env| {
            let mut env =
                unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
            let address = env
                .new_string(&link.address)
                .map_err(|e| format!("new_string failed: {e}"))?;
            let chunks = chunk_array(&mut env, sealed)?;
            let class = find_class_with_app_loader(&mut env, UNIFIED)?;
            let address = JObject::from(address);
            let chunks = JObject::from(chunks);
            env.call_static_method(
                &class,
                "dispatchRustBleFollowUp",
                "(Ljava/lang/String;I[[B)Z",
                &[
                    JValue::Object(&address),
                    JValue::Int(link.role.to_wire()),
                    JValue::Object(&chunks),
                ],
            )
            .and_then(|v| v.z())
            .map_err(|e| format!("Unified.dispatchRustBleFollowUp failed: {e}"))
        })?;
        Ok(if written {
            Delivery::Sent
        } else {
            Delivery::NotNow
        })
    }

    fn request_connect(
        &self,
        device_id: &[u8; 32],
        address_hint: Option<&str>,
    ) -> Result<(), String> {
        with_env(|env| {
            let mut env =
                unsafe { JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
            let device_id = env
                .byte_array_from_slice(device_id)
                .map_err(|e| format!("byte_array_from_slice failed: {e}"))?;
            // Kotlin's requestGattConnect reads an empty hint as "no address to
            // try first" (`hint.isNotEmpty()`): that string is its spelling of
            // the absent hint, not a value standing in for one.
            let hint_text = match address_hint {
                Some(address) => address,
                None => "",
            };
            let hint = env
                .new_string(hint_text)
                .map_err(|e| format!("new_string failed: {e}"))?;
            let class = find_class_with_app_loader(&mut env, UNIFIED)?;
            let device_id = JObject::from(device_id);
            let hint = JObject::from(hint);
            env.call_static_method(
                &class,
                "requestGattConnect",
                "([BLjava/lang/String;)V",
                &[JValue::Object(&device_id), JValue::Object(&hint)],
            )
            .map(|_| ())
            .map_err(|e| format!("Unified.requestGattConnect failed: {e}"))
        })
    }

    fn start_advertising(&self) -> Result<(), String> {
        unified_answers_yes("startBlePairingAdvertise")
    }

    fn start_scan(&self) -> Result<(), String> {
        unified_answers_yes("startBlePairingScan")
    }

    fn stop_scan(&self) -> Result<(), String> {
        unified_answers_yes("stopBlePairingScan")
    }

    fn seal_seed(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        keystore("seal", plaintext)
    }

    fn open_seed(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        keystore("open", blob)
    }
}
