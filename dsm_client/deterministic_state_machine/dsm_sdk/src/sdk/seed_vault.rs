// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phone-local (online-domain) hardware-sealed seed vault.
//!
//! Persists the Genesis v2 wallet seed at rest so the **online** device signer can be
//! rebuilt on a cold start **without re-entering the mnemonic**. The stored material is
//! the BIP39 wallet seed (`mnemonic.to_seed("")`) — a one-way derivation from the paper
//! mnemonic that is NOT the mnemonic and cannot be reversed back to it. The paper mnemonic
//! stays off-device (disaster recovery only); the usable key material lives here, sealed.
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
//! Sealing key:
//! - **Android** (`target_os = "android"`): an `AndroidKeyStore` AES/GCM key held by
//!   `com.dsm.wallet.security.KeystoreVault` (hardware-backed; a no-auth key for a
//!   no-lock wallet, a biometric/PIN-gated key otherwise). Rust hands plaintext across
//!   JNI and gets ciphertext back — the sealing key never enters Rust memory.
//! - **Host / desktop** (non-Android, tests): a software XChaCha20-Poly1305 fallback so
//!   the persistence logic is exercisable off-device. This path is **not** hardware-backed
//!   and is never the production anti-clone boundary; it exists only where no Keystore does.

use dsm::types::error::DsmError;

/// Seal `plaintext` with the platform sealing key. Output is opaque ciphertext for
/// storage at rest; only this device can [`open`] it.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    platform_seal(plaintext)
}

/// Open a blob produced by [`seal`] on this device, recovering the plaintext.
pub fn open(blob: &[u8]) -> Result<Vec<u8>, DsmError> {
    platform_open(blob)
}

// ---------------------------------------------------------------------------
// Android (with the `jni` feature): seal/open via the AndroidKeyStore-backed
// Kotlin helper through a JNI upcall.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "android", feature = "jni"))]
fn platform_seal(plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    keystore_upcall("seal", plaintext)
}

#[cfg(all(target_os = "android", feature = "jni"))]
fn platform_open(blob: &[u8]) -> Result<Vec<u8>, DsmError> {
    keystore_upcall("open", blob)
}

/// Call `KeystoreVault.seal([B):[B` / `.open([B):[B` on the JVM and return the bytes.
#[cfg(all(target_os = "android", feature = "jni"))]
fn keystore_upcall(method: &str, input: &[u8]) -> Result<Vec<u8>, DsmError> {
    use jni::objects::{JByteArray, JValue};

    crate::jni::jni_common::with_env(|env| {
        let mut env =
            unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _).map_err(|e| e.to_string())? };
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/security/KeystoreVault",
        )?;
        let j_in = env.byte_array_from_slice(input).map_err(|e| e.to_string())?;
        let ret = env
            .call_static_method(
                class,
                method,
                "([B)[B",
                &[JValue::Object(&j_in.into())],
            )
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

// ---------------------------------------------------------------------------
// Host / desktop / tests: software XChaCha20-Poly1305 fallback (NOT hardware-backed).
// ---------------------------------------------------------------------------

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn platform_seal(plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let key = host_software_key();
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| DsmError::InvalidState(format!("seed-vault cipher init: {e}")))?;
    // Nonce derived from the key and plaintext so re-sealing the same seed is stable
    // and distinct seeds never reuse a nonce (matches the recovery-key persist scheme).
    let nonce_hash = {
        let mut h = dsm::crypto::blake3::Hasher::new_derive_key("DSM/seed-vault-host-nonce/v1\0");
        h.update(&key);
        h.update(plaintext);
        h.finalize()
    };
    let nonce = XNonce::from_slice(&nonce_hash.as_bytes()[..24]);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| DsmError::InvalidState(format!("seed-vault seal: {e}")))?;
    let mut blob = Vec::with_capacity(24 + ct.len());
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ct);
    Ok(blob)
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn platform_open(blob: &[u8]) -> Result<Vec<u8>, DsmError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    if blob.len() < 24 {
        return Err(DsmError::InvalidState(format!(
            "seed-vault blob too short: {} bytes",
            blob.len()
        )));
    }
    let nonce = XNonce::from_slice(&blob[..24]);
    let ct = &blob[24..];
    let key = host_software_key();
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| DsmError::InvalidState(format!("seed-vault cipher init: {e}")))?;
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| DsmError::InvalidState(format!("seed-vault open: {e}")))
}

/// Host-only software wrapping key. Deliberately NOT a hardware secret — this path
/// runs only on non-Android builds (desktop/dev/tests), where there is no Keystore and
/// no anti-clone boundary to uphold. A fixed domain-derived key keeps the persistence
/// logic exercisable without depending on app-state/storage initialization.
#[cfg(not(all(target_os = "android", feature = "jni")))]
fn host_software_key() -> [u8; 32] {
    *dsm::crypto::blake3::Hasher::new_derive_key("DSM/seed-vault-host-key/v1\0")
        .update(b"non-android software fallback")
        .finalize()
        .as_bytes()
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_recovers_plaintext() {
        let seed = vec![7u8; 64];
        let sealed = seal(&seed).expect("seal");
        assert_ne!(sealed, seed, "sealed blob must not equal plaintext");
        let opened = open(&sealed).expect("open");
        assert_eq!(opened, seed, "open must recover the exact seed");
    }

    #[test]
    fn open_rejects_truncated_blob() {
        assert!(open(&[0u8; 8]).is_err(), "short blob must fail closed");
    }

    #[test]
    fn open_rejects_corrupted_ciphertext() {
        let seed = vec![3u8; 64];
        let mut sealed = seal(&seed).expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // flip a tag/ciphertext byte
        assert!(open(&sealed).is_err(), "AEAD must reject tampered blob");
    }
}
