// SPDX-License-Identifier: MIT OR Apache-2.0
//! Android WebView event shim.
//!
//! Rust producers deliver protobuf bytes directly to the existing Android
//! push bridge (`BleEventRelay`) instead of detouring through the deprecated
//! SDK event queue and ingress drain path.

use dsm::types::error::DsmError;
use jni::objects::JValue;

pub fn post_event_to_webview(topic: &str, payload: &[u8]) -> Result<(), DsmError> {
    crate::jni::jni_common::with_env(|env| {
        let mut env = unsafe {
            jni::JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())?
        };
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/bridge/BleEventRelay",
        )?;
        let j_topic = env.new_string(topic).map_err(|e| e.to_string())?;
        let j_payload = env.byte_array_from_slice(payload).map_err(|e| e.to_string())?;
        env.call_static_method(
            class,
            "dispatchEvent",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&j_topic), JValue::Object(&j_payload.into())],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
    .map_err(DsmError::invalid_operation)
}
