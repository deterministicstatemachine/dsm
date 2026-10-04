// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phone-local (online-domain) hardware-sealed vault.
//!
//! Persists two secrets at rest so a cold start does **not** require the mnemonic again:
//! the Genesis v2 wallet seed (`mnemonic.to_seed("")`), from which the **online** device
//! signer is rebuilt, and the NFC recovery key `K_R`, from which the recovery capsule is
//! refreshed. Both are one-way derivations from the paper mnemonic, never the mnemonic and
//! never reversible to it. The paper mnemonic stays off-device (disaster recovery only).
//!
//! ## Domain scope (owner directive 2026-07-11)
//!
//! This vault is the **online-domain** vault, sealed by **phone** hardware (Android
//! Keystore) — NOT the RP2350/TROPIC appliance. Online DSM must work on a phone + seed
//! alone; gating online onboarding on the appliance is forbidden. The **offline** bearer
//! domain is appliance-gated *by construction*: an offline release additionally needs
//! `σ^chip` (TROPIC resident key) and `σ^host` (RP2350 partition key) — hardware keys that
//! are never seed-derived and never stored on the phone (spec §6.4, §11). So a phone-only
//! compromise yields online takeover, offline stays safe, regardless of what this vault holds.
//!
//! Reserved seam: a distinct offline seed-factor
//! (`k_offline_seed_factor = HKDF(seed, "DSM/identity/offline-seed-factor/v1")`) belongs in a
//! SEPARATE **appliance-gated** vault, built with the offline-cash phase — it must NOT be
//! added to this phone Keystore vault. Fully replacing the raw seed here with an online-only
//! `k_online = HKDF(seed, "DSM/identity/online/v1")` (spec §6.1) so this vault cannot derive
//! the offline factor is a deliberate genesis-derivation re-root (device identity changes),
//! tracked separately; it is not required for offline gating, which the hardware factors enforce.
//!
//! ## Sealing key
//!
//! An `AndroidKeyStore` AES-256/GCM key held by `com.dsm.wallet.security.KeystoreVault`
//! (hardware-backed on devices with a TEE/StrongBox). Rust hands plaintext across JNI and
//! gets ciphertext back — the sealing key never enters Rust memory.
//!
//! This module exists only on Android with the `jni` feature. Elsewhere the platform holds
//! no key for it, so nothing is sealed at rest: a host unlocks from its mnemonic on every
//! start (owner ruling, 2026-10-04: "No seal off Android").

use dsm::types::error::DsmError;

/// Seal `plaintext` under this device's Keystore key. Output is opaque ciphertext for
/// storage at rest; only this device's key can [`open`] it.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    keystore_upcall("seal", plaintext)
}

/// Open a blob produced by [`seal`] on this device, recovering the plaintext.
pub fn open(blob: &[u8]) -> Result<Vec<u8>, DsmError> {
    keystore_upcall("open", blob)
}

/// Call `KeystoreVault.seal([B):[B` / `.open([B):[B` on the JVM and return the bytes.
fn keystore_upcall(method: &str, input: &[u8]) -> Result<Vec<u8>, DsmError> {
    use jni::objects::{JByteArray, JValue};

    crate::jni::jni_common::with_env(|env| {
        let mut env =
            unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/security/KeystoreVault",
        )?;
        let j_in = env
            .byte_array_from_slice(input)
            .map_err(|e| e.to_string())?;
        let ret = env
            .call_static_method(class, method, "([B)[B", &[JValue::Object(&j_in.into())])
            .map_err(|e| format!("KeystoreVault.{method} upcall failed: {e}"))?;
        let obj = ret.l().map_err(|e| e.to_string())?;
        if obj.is_null() {
            return Err(format!("KeystoreVault.{method} returned null"));
        }
        let arr = JByteArray::from(obj);
        env.convert_byte_array(arr).map_err(|e| e.to_string())
    })
    .map_err(DsmError::invalid_operation)
}
