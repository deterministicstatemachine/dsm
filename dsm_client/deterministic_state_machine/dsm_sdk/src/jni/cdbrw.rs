//! C-DBRW JNI bridge.
//!
//! Provides JNI entry points for the C-DBRW (Challenge-seeded DBRW) anti-cloning
//! protocol. The binding key K_DBRW is stored in a global `OnceLock` and set
//! during PBI bootstrap.

#[cfg(target_os = "android")]
use dsm::crypto::{
    blake3::domain_hash_bytes,
    ephemeral_key::{
        derive_kyber_coins, derive_kyber_step_key, sign_cdbrw_response_with_context,
        verify_cdbrw_response_signature,
    },
    kyber::kyber_encapsulate_deterministic,
};
#[cfg(target_os = "android")]
use jni::{
    objects::{JObject, JObjectArray},
    JNIEnv,
};
#[cfg(target_os = "android")]
use std::sync::OnceLock;

#[cfg(target_os = "android")]
use crate::security::cdbrw_verifier::{
    ensure_verifier_public_key, verify_challenge_response, CdbrwVerificationOutcome,
    CdbrwVerificationRequest,
};

/// Global C-DBRW binding key, set once during bootstrap.
#[cfg(target_os = "android")]
static CDBRW_BINDING_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Store the C-DBRW binding key (called from bootstrap).
#[cfg(target_os = "android")]
pub fn set_cdbrw_binding_key(key: Vec<u8>) {
    let _ = CDBRW_BINDING_KEY.set(key);
}

/// Retrieve the C-DBRW binding key. Returns `None` if not yet bootstrapped.
#[cfg(target_os = "android")]
pub fn get_cdbrw_binding_key() -> Option<Vec<u8>> {
    CDBRW_BINDING_KEY.get().cloned()
}

#[cfg(target_os = "android")]
fn require_exact_32(bytes: &[u8], field: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be exactly 32 bytes"))
}

#[cfg(target_os = "android")]
fn build_byte_array_pair<'a>(
    env: &mut JNIEnv<'a>,
    first: &[u8],
    second: &[u8],
) -> Result<JObjectArray<'a>, String> {
    let byte_array_class = env
        .find_class("[B")
        .map_err(|e| format!("find_class([B) failed: {e}"))?;
    let result = env
        .new_object_array(2, byte_array_class, JObject::null())
        .map_err(|e| format!("new_object_array failed: {e}"))?;

    let first_array = env
        .byte_array_from_slice(first)
        .map_err(|e| format!("byte_array_from_slice(first) failed: {e}"))?;
    let second_array = env
        .byte_array_from_slice(second)
        .map_err(|e| format!("byte_array_from_slice(second) failed: {e}"))?;

    env.set_object_array_element(&result, 0, first_array)
        .map_err(|e| format!("set_object_array_element(first) failed: {e}"))?;
    env.set_object_array_element(&result, 1, second_array)
        .map_err(|e| format!("set_object_array_element(second) failed: {e}"))?;

    Ok(result)
}

#[cfg(target_os = "android")]
fn encode_verification_outcome(outcome: &CdbrwVerificationOutcome) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(9 + outcome.reason.len());
    encoded.push(u8::from(outcome.accepted));
    encoded.extend_from_slice(&outcome.gamma_distance.to_le_bytes());
    encoded.extend_from_slice(&outcome.threshold.to_le_bytes());
    encoded.extend_from_slice(outcome.reason.as_bytes());
    encoded
}

#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwDomainHash(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    tag: jni::sys::jbyteArray,
    data: jni::sys::jbyteArray,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "cdbrwDomainHash",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return std::ptr::null_mut(),
            };
            let tag =
                match env.convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(tag) }) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log::error!("cdbrwDomainHash: tag conversion failed: {e}");
                        return std::ptr::null_mut();
                    }
                };
            let data =
                match env.convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(data) }) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log::error!("cdbrwDomainHash: data conversion failed: {e}");
                        return std::ptr::null_mut();
                    }
                };

            let tag = match std::str::from_utf8(&tag) {
                Ok(tag) => tag.trim_end_matches('\0'),
                Err(e) => {
                    log::error!("cdbrwDomainHash: invalid UTF-8 tag: {e}");
                    return std::ptr::null_mut();
                }
            };
            if !tag.starts_with("DSM/") && !tag.starts_with("DJTE.") {
                log::error!("cdbrwDomainHash: invalid domain tag: {tag}");
                return std::ptr::null_mut();
            }

            let digest = domain_hash_bytes(tag, &data);
            match env.byte_array_from_slice(&digest) {
                Ok(array) => array.into_raw(),
                Err(e) => {
                    log::error!("cdbrwDomainHash: failed to create byte array: {e}");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwEncapsDeterministic(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    public_key: jni::sys::jbyteArray,
    chain_tip: jni::sys::jbyteArray,
    commitment_preimage: jni::sys::jbyteArray,
    device_id: jni::sys::jbyteArray,
    k_dbrw: jni::sys::jbyteArray,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "cdbrwEncapsDeterministic",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return std::ptr::null_mut(),
            };

            let public_key = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(public_key) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: pk conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let chain_tip = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(chain_tip) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: chain_tip conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage = match env.convert_byte_array(unsafe {
                crate::jni::bridge_utils::jba_from(commitment_preimage)
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "cdbrwEncapsDeterministic: commitment_preimage conversion failed: {e}"
                    );
                    return std::ptr::null_mut();
                }
            };
            let device_id = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(device_id) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: device_id conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let k_dbrw = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(k_dbrw) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: k_dbrw conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };

            let chain_tip = match require_exact_32(&chain_tip, "chain_tip") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage =
                match require_exact_32(&commitment_preimage, "commitment_preimage") {
                    Ok(value) => value,
                    Err(e) => {
                        log::error!("cdbrwEncapsDeterministic: {e}");
                        return std::ptr::null_mut();
                    }
                };
            let device_id = match require_exact_32(&device_id, "device_id") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: {e}");
                    return std::ptr::null_mut();
                }
            };
            let k_dbrw = match require_exact_32(&k_dbrw, "k_dbrw") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: {e}");
                    return std::ptr::null_mut();
                }
            };

            let message_seed =
                derive_kyber_coins(&chain_tip, &commitment_preimage, &device_id, &k_dbrw);
            let public_key = if public_key.len() >= 1184 {
                &public_key[..1184]
            } else {
                log::error!("cdbrwEncapsDeterministic: public_key must be at least 1184 bytes");
                return std::ptr::null_mut();
            };

            let (shared_secret, ciphertext) =
                match kyber_encapsulate_deterministic(public_key, &message_seed) {
                    Ok(result) => result,
                    Err(e) => {
                        log::error!("cdbrwEncapsDeterministic: encapsulation failed: {e}");
                        return std::ptr::null_mut();
                    }
                };
            let k_step = derive_kyber_step_key(&shared_secret);

            match build_byte_array_pair(&mut env, &ciphertext, &k_step) {
                Ok(result) => result.into_raw(),
                Err(e) => {
                    log::error!("cdbrwEncapsDeterministic: failed to build result: {e}");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwSignResponse(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    chain_tip: jni::sys::jbyteArray,
    commitment_preimage: jni::sys::jbyteArray,
    k_step: jni::sys::jbyteArray,
    k_dbrw: jni::sys::jbyteArray,
    gamma: jni::sys::jbyteArray,
    ciphertext: jni::sys::jbyteArray,
    challenge: jni::sys::jbyteArray,
) -> jni::sys::jobjectArray {
    crate::jni::bridge_utils::jni_catch_unwind_jobjectarray(
        "cdbrwSignResponse",
        std::panic::AssertUnwindSafe(|| {
            let mut env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return std::ptr::null_mut(),
            };

            let chain_tip = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(chain_tip) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: chain_tip conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage = match env.convert_byte_array(unsafe {
                crate::jni::bridge_utils::jba_from(commitment_preimage)
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: commitment_preimage conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let k_step = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(k_step) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: k_step conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let k_dbrw = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(k_dbrw) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: k_dbrw conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let gamma = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(gamma) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: gamma conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let ciphertext = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(ciphertext) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: ciphertext conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let challenge = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(challenge) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwSignResponse: challenge conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };

            let chain_tip = match require_exact_32(&chain_tip, "chain_tip") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwSignResponse: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage =
                match require_exact_32(&commitment_preimage, "commitment_preimage") {
                    Ok(value) => value,
                    Err(e) => {
                        log::error!("cdbrwSignResponse: {e}");
                        return std::ptr::null_mut();
                    }
                };
            let k_step = match require_exact_32(&k_step, "k_step") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwSignResponse: {e}");
                    return std::ptr::null_mut();
                }
            };
            let k_dbrw = match require_exact_32(&k_dbrw, "k_dbrw") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwSignResponse: {e}");
                    return std::ptr::null_mut();
                }
            };
            let gamma = match require_exact_32(&gamma, "gamma") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwSignResponse: {e}");
                    return std::ptr::null_mut();
                }
            };

            let (signature, ephemeral_pk) = match sign_cdbrw_response_with_context(
                &chain_tip,
                &commitment_preimage,
                &k_step,
                &k_dbrw,
                &gamma,
                &ciphertext,
                &challenge,
            ) {
                Ok(result) => result,
                Err(e) => {
                    log::error!("cdbrwSignResponse: signing failed: {e}");
                    return std::ptr::null_mut();
                }
            };

            match build_byte_array_pair(&mut env, &signature, &ephemeral_pk) {
                Ok(result) => result.into_raw(),
                Err(e) => {
                    log::error!("cdbrwSignResponse: failed to build result: {e}");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwVerifyResponseSignature(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    ephemeral_pk: jni::sys::jbyteArray,
    gamma: jni::sys::jbyteArray,
    ciphertext: jni::sys::jbyteArray,
    challenge: jni::sys::jbyteArray,
    signature: jni::sys::jbyteArray,
) -> jni::sys::jboolean {
    crate::jni::bridge_utils::jni_catch_unwind_jboolean(
        "cdbrwVerifyResponseSignature",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return jni::sys::JNI_FALSE,
            };

            let ephemeral_pk = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(ephemeral_pk) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: pk conversion failed: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };
            let gamma = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(gamma) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: gamma conversion failed: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };
            let ciphertext = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(ciphertext) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: ciphertext conversion failed: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };
            let challenge = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(challenge) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: challenge conversion failed: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };
            let signature = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(signature) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: signature conversion failed: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };

            let gamma = match require_exact_32(&gamma, "gamma") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: {e}");
                    return jni::sys::JNI_FALSE;
                }
            };

            match verify_cdbrw_response_signature(
                &ephemeral_pk,
                &gamma,
                &ciphertext,
                &challenge,
                &signature,
            ) {
                Ok(true) => jni::sys::JNI_TRUE,
                Ok(false) => jni::sys::JNI_FALSE,
                Err(e) => {
                    log::error!("cdbrwVerifyResponseSignature: verify failed: {e}");
                    jni::sys::JNI_FALSE
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwEnsureVerifierPublicKey(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "cdbrwEnsureVerifierPublicKey",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return std::ptr::null_mut(),
            };

            let public_key = match ensure_verifier_public_key() {
                Ok(public_key) => public_key,
                Err(e) => {
                    log::error!("cdbrwEnsureVerifierPublicKey: ensure failed: {e}");
                    return std::ptr::null_mut();
                }
            };

            match env.byte_array_from_slice(&public_key) {
                Ok(array) => array.into_raw(),
                Err(e) => {
                    log::error!("cdbrwEnsureVerifierPublicKey: byte array creation failed: {e}");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

#[no_mangle]
#[cfg(target_os = "android")]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_cdbrwVerifyChallengeResponse(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
    challenge: jni::sys::jbyteArray,
    gamma: jni::sys::jbyteArray,
    ciphertext: jni::sys::jbyteArray,
    signature: jni::sys::jbyteArray,
    ephemeral_pk: jni::sys::jbyteArray,
    chain_tip: jni::sys::jbyteArray,
    commitment_preimage: jni::sys::jbyteArray,
    enrollment_anchor: jni::sys::jbyteArray,
    epsilon_intra: jni::sys::jfloat,
    epsilon_inter: jni::sys::jfloat,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "cdbrwVerifyChallengeResponse",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { crate::jni::bridge_utils::env_from(env) } {
                Some(env) => env,
                None => return std::ptr::null_mut(),
            };

            let challenge = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(challenge) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: challenge conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let gamma = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(gamma) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: gamma conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let ciphertext = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(ciphertext) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: ciphertext conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let signature = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(signature) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: signature conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let ephemeral_pk = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(ephemeral_pk) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "cdbrwVerifyChallengeResponse: ephemeral_pk conversion failed: {e}"
                    );
                    return std::ptr::null_mut();
                }
            };
            let chain_tip = match env
                .convert_byte_array(unsafe { crate::jni::bridge_utils::jba_from(chain_tip) })
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: chain_tip conversion failed: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage = match env.convert_byte_array(unsafe {
                crate::jni::bridge_utils::jba_from(commitment_preimage)
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "cdbrwVerifyChallengeResponse: commitment_preimage conversion failed: {e}"
                    );
                    return std::ptr::null_mut();
                }
            };
            let enrollment_anchor = match env.convert_byte_array(unsafe {
                crate::jni::bridge_utils::jba_from(enrollment_anchor)
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "cdbrwVerifyChallengeResponse: enrollment_anchor conversion failed: {e}"
                    );
                    return std::ptr::null_mut();
                }
            };

            let gamma = match require_exact_32(&gamma, "gamma") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: {e}");
                    return std::ptr::null_mut();
                }
            };
            let chain_tip = match require_exact_32(&chain_tip, "chain_tip") {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: {e}");
                    return std::ptr::null_mut();
                }
            };
            let commitment_preimage =
                match require_exact_32(&commitment_preimage, "commitment_preimage") {
                    Ok(value) => value,
                    Err(e) => {
                        log::error!("cdbrwVerifyChallengeResponse: {e}");
                        return std::ptr::null_mut();
                    }
                };
            let enrollment_anchor = match require_exact_32(&enrollment_anchor, "enrollment_anchor")
            {
                Ok(value) => value,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: {e}");
                    return std::ptr::null_mut();
                }
            };

            let binding_key = match get_cdbrw_binding_key() {
                Some(key) => match require_exact_32(&key, "binding_key") {
                    Ok(value) => value,
                    Err(e) => {
                        log::error!("cdbrwVerifyChallengeResponse: {e}");
                        return std::ptr::null_mut();
                    }
                },
                None => {
                    log::error!("cdbrwVerifyChallengeResponse: binding key unavailable");
                    return std::ptr::null_mut();
                }
            };

            let request = CdbrwVerificationRequest {
                binding_key: &binding_key,
                challenge: &challenge,
                gamma: &gamma,
                ciphertext: &ciphertext,
                signature: &signature,
                supplied_ephemeral_public_key: &ephemeral_pk,
                chain_tip: &chain_tip,
                commitment_preimage: &commitment_preimage,
                enrollment_anchor: &enrollment_anchor,
                epsilon_intra,
                epsilon_inter,
            };

            let outcome = match verify_challenge_response(&request) {
                Ok(outcome) => outcome,
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: verify failed: {e}");
                    return std::ptr::null_mut();
                }
            };

            let encoded = encode_verification_outcome(&outcome);
            match env.byte_array_from_slice(&encoded) {
                Ok(array) => array.into_raw(),
                Err(e) => {
                    log::error!("cdbrwVerifyChallengeResponse: byte array creation failed: {e}");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

// Non-android stubs for compilation on host.
#[cfg(not(target_os = "android"))]
fn host_binding_slot() -> &'static std::sync::Mutex<Option<Vec<u8>>> {
    static HOST_CDBRW_BINDING_KEY: std::sync::OnceLock<std::sync::Mutex<Option<Vec<u8>>>> =
        std::sync::OnceLock::new();
    HOST_CDBRW_BINDING_KEY.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(not(target_os = "android"))]
pub fn set_cdbrw_binding_key(key: Vec<u8>) {
    let mut guard = host_binding_slot().lock().unwrap_or_else(|p| p.into_inner());
    *guard = Some(key);
}

#[cfg(not(target_os = "android"))]
pub fn get_cdbrw_binding_key() -> Option<Vec<u8>> {
    host_binding_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

#[cfg(all(not(target_os = "android"), test))]
pub fn clear_cdbrw_binding_key_for_testing() {
    let mut guard = host_binding_slot().lock().unwrap_or_else(|p| p.into_inner());
    *guard = None;
}
