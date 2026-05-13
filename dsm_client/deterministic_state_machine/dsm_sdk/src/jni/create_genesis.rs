//! # JNI Genesis Creation (deprecated shim)
//!
//! Canonical genesis creation now lives on the ingress `system.genesis` query path
//! (`handlers/system_routes.rs`) followed by bootstrap finalize.
//! This JNI entrypoint is retained only for ABI compatibility and intentionally
//! rejects direct use.

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::generated as pb;
use jni::objects::{JByteArray, JClass, JString};
use jni::JNIEnv;
use prost::Message;

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_createGenesis<'a>(
    mut env: JNIEnv<'a>,
    _clazz: JClass<'a>,
    _j_locale: JString<'a>,
    _j_network: JString<'a>,
    entropy_bytes: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    let entropy = match env.convert_byte_array(unsafe { JByteArray::from_raw(entropy_bytes) }) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("createGenesis(deprecated): failed to read entropy bytes: {e:?}");
            return encode_env_as_bytes(
                &mut env,
                crate::jni::helpers::encode_error_transport(400, "invalid device entropy"),
            );
        }
    };

    if entropy.len() != 32 {
        return encode_env_as_bytes(
            &mut env,
            crate::jni::helpers::encode_error_transport(422, "device entropy must be 32 bytes"),
        );
    }

    log::warn!(
        "createGenesis(deprecated): direct JNI path disabled; use ingress router query 'system.genesis' + bootstrap finalize"
    );
    encode_env_as_bytes(
        &mut env,
        crate::jni::helpers::encode_error_transport(
            410,
            "deprecated path: use ingress system.genesis canonical route",
        ),
    )
}

fn encode_env_as_bytes(env: &mut JNIEnv<'_>, envl: pb::Envelope) -> jni::sys::jbyteArray {
    let mut out = Vec::new();
    out.push(0x03); // FramedEnvelopeV3 prefix
    if envl.encode(&mut out).is_err() {
        return env
            .new_byte_array(0)
            .map(|arr| arr.into_raw())
            .unwrap_or(std::ptr::null_mut());
    }

    let jarray = match env.new_byte_array(out.len() as i32) {
        Ok(arr) => arr,
        Err(e) => {
            log::error!("createGenesis(deprecated): new_byte_array failed: {e}");
            return std::ptr::null_mut();
        }
    };

    let i8_slice = unsafe { std::slice::from_raw_parts(out.as_ptr() as *const i8, out.len()) };
    if let Err(e) = env.set_byte_array_region(&jarray, 0, i8_slice) {
        log::error!("createGenesis(deprecated): set_byte_array_region failed: {e}");
        return std::ptr::null_mut();
    }

    jarray.into_raw()
}
