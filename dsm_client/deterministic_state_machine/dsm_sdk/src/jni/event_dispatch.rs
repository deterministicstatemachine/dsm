// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generic Rust → WebView event dispatch.
//!
//! Provides `post_event_to_webview()` — a topic-parameterized push function
//! that sends protobuf bytes to the WebView via JNI → Kotlin `SinglePathWebViewBridge.postBinary()`.
//!
//! This is the canonical reverse-spine for Invariant #7:
//! `Rust → JNI → Kotlin → MessagePort → WebView`
//!
//! Bilateral BLE events delegate here. Inbox poller pushes use the same path.

use dsm::types::error::DsmError;

/// Push a binary event to the WebView via the canonical reverse-spine.
///
/// `topic` — event topic string (e.g. `"bilateral.event"`, `"inbox.updated"`)
/// `payload` — protobuf-encoded bytes (topic-specific schema)
///
/// JNI mechanics: `get_java_vm_borrowed()` → attach thread →
/// `SinglePathWebViewBridge.postBinary(topic, payload)` → Kotlin relays to
/// `MainActivity.dispatchDsmEventToWebView()` → MessagePort ArrayBuffer → WebView.
#[cfg(all(target_os = "android", feature = "jni"))]
pub fn post_event_to_webview(topic: &str, payload: &[u8]) -> Result<(), DsmError> {
    use crate::jni::jni_common::{find_class_with_app_loader, get_java_vm_borrowed};
    use jni::objects::JValue;

    let vm = get_java_vm_borrowed()
        .ok_or_else(|| DsmError::invalid_operation("JavaVM not initialized".to_string()))?;

    let mut env = vm
        .attach_current_thread()
        .map_err(|e| DsmError::invalid_operation(format!("Failed to attach JNI thread: {e}")))?;

    let res = (|| -> Result<(), String> {
        let cls =
            find_class_with_app_loader(&mut env, "com/dsm/wallet/bridge/SinglePathWebViewBridge")?;
        let j_topic = env
            .new_string(topic)
            .map_err(|e| format!("new_string(topic) failed: {e}"))?;
        let j_payload = env
            .byte_array_from_slice(payload)
            .map_err(|e| format!("byte_array_from_slice(payload) failed: {e}"))?;

        env.call_static_method(
            cls,
            "postBinary",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&j_topic), JValue::Object(&j_payload)],
        )
        .map_err(|e| format!("call_static_method postBinary failed: {e}"))?;

        Ok(())
    })();

    match res {
        Ok(()) => {
            log::debug!(
                "Posted event to WebView: topic={} ({} bytes)",
                topic,
                payload.len()
            );
            Ok(())
        }
        Err(err) => {
            log::warn!(
                "Failed posting event to WebView: topic={} err={}",
                topic,
                err
            );
            Err(DsmError::invalid_operation(format!(
                "post_event_to_webview({topic}): {err}"
            )))
        }
    }
}

/// Stub when JNI feature is not enabled (desktop builds, non-JNI Android).
#[cfg(not(all(target_os = "android", feature = "jni")))]
pub fn post_event_to_webview(_topic: &str, _payload: &[u8]) -> Result<(), DsmError> {
    Ok(())
}
