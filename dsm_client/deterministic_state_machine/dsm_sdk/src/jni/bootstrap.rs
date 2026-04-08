//! # JNI Bootstrap (Platform Boundary Interface)
//!
//! Android JNI entry point for `sdkBootstrap`. Receives device_id,
//! genesis_hash, and DBRW entropy from Kotlin, initializes the SDK
//! context, sets the `SDK_READY` flag, and triggers handler installation.

// SPDX-License-Identifier: MIT OR Apache-2.0

use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::{jboolean, jbyteArray};
use dsm::pbi::{PlatformContext, RawPlatformInputs};
use std::sync::{Mutex, OnceLock};
// NOTE: Base32 Crockford text <-> bytes helpers live in crate::util::text_id.

// Global Platform Context (The Single Source of Truth)
static PLATFORM_CONTEXT: OnceLock<Mutex<PlatformContext>> = OnceLock::new();

#[no_mangle]
pub extern "system" fn Java_com_dsm_native_DsmNative_sdkBootstrap<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    device_id: jbyteArray,
    genesis_hash: jbyteArray,
    dbrw_hw: jbyteArray,
    dbrw_env: jbyteArray,
    dbrw_salt: jbyteArray,
) -> jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "sdkBootstrap",
        std::panic::AssertUnwindSafe(|| {
            // 1. Ingest Raw Inputs (JNI -> Rust Vec<u8>)
            let device_id_bytes = match env
                .convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(device_id) })
            {
                Ok(b) => b,
                Err(_) => return 0,
            };

            let genesis_bytes = match env
                .convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(genesis_hash) })
            {
                Ok(b) => b,
                Err(_) => return 0,
            };

            let hw_bytes = match env
                .convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(dbrw_hw) })
            {
                Ok(b) => b,
                Err(_) => return 0,
            };

            let env_bytes = match env
                .convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(dbrw_env) })
            {
                Ok(b) => b,
                Err(_) => return 0,
            };

            let salt_bytes = match env
                .convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(dbrw_salt) })
            {
                Ok(b) => b,
                Err(_) => return 0,
            };

            // 2. Construct Raw Inputs
            let raw_inputs = RawPlatformInputs {
                device_id_raw: device_id_bytes,
                genesis_hash_raw: genesis_bytes,
                cdbrw_hw_entropy: hw_bytes,
                cdbrw_env_fingerprint: env_bytes,
                cdbrw_salt: salt_bytes,
            };

            // 3. Call PBI Bootstrap (The Hard Boundary)
            log::info!("sdkBootstrap: calling PlatformContext::bootstrap");
            match PlatformContext::bootstrap(raw_inputs) {
                Ok(ctx) => {
                    log::info!("sdkBootstrap: PlatformContext::bootstrap succeeded");

                    // Extract binding key before moving ctx
                    let binding_key = ctx.cdbrw_binding.clone();
                    let device_id = ctx.device_id;
                    let genesis_hash = ctx.genesis_hash;

                    // 4. Store the Canonical Context
                    match PLATFORM_CONTEXT.get() {
                        Some(mutex) => {
                            let mut guard = mutex.lock().unwrap_or_else(|poisoned| {
                                log::error!("PLATFORM_CONTEXT mutex poisoned, recovering");
                                poisoned.into_inner()
                            });
                            *guard = ctx;
                        }
                        None => {
                            let _ = PLATFORM_CONTEXT.set(Mutex::new(ctx));
                        }
                    }

                    // Initialize C-DBRW binding key from the validated context
                    log::info!("sdkBootstrap: setting C-DBRW binding key");
                    crate::jni::cdbrw::set_cdbrw_binding_key(binding_key.to_vec());

                    match crate::ingress::dispatch_startup(crate::generated::StartupRequest {
                        operation: Some(
                            crate::generated::startup_request::Operation::InitializeIdentityContext(
                                crate::generated::InitializeIdentityContextOp {
                                    device_id: device_id.to_vec(),
                                    genesis_hash: genesis_hash.to_vec(),
                                    binding_key: binding_key.to_vec(),
                                },
                            ),
                        ),
                    })
                    .result
                    {
                        Some(crate::generated::startup_response::Result::OkBytes(_)) => {
                            log::info!("sdkBootstrap: shared startup identity initialization succeeded");
                            1 // true
                        }
                        Some(crate::generated::startup_response::Result::Error(error)) => {
                            log::error!(
                                "sdkBootstrap: shared startup identity initialization failed: {}",
                                error.message
                            );
                            0 // false
                        }
                        None => {
                            log::error!("sdkBootstrap: shared startup returned empty response");
                            0 // false
                        }
                    }
                }
                Err(e) => {
                    log::error!("sdkBootstrap: PlatformContext::bootstrap failed: {:?}", e);
                    0 // false
                }
            }
        }),
    ) // catch_unwind
}
