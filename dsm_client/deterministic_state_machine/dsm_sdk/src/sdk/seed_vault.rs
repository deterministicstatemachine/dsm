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
//!   `com.dsm.wallet.security.KeystoreVault` (hardware-backed, with no user-authentication
//!   requirement: the app lock is Rust's, `sdk::app_lock`). Rust hands plaintext across
//!   JNI and gets ciphertext back — the sealing key never enters Rust memory.
//! - **iOS** (the `ffi` feature): the key the Swift host holds for Rust, reached through
//!   the same `crate::host::HostBridge` calls; the key never enters Rust.
//!
//! This module exists on those two builds only (owner, 2026-10-04: "No seal off Android").
//! No other build has a platform key to seal under, so it writes the seed nowhere: it keeps
//! the seed in memory and unlocks from its mnemonic on every start.

use dsm::types::error::DsmError;

/// Seal `plaintext` with the platform sealing key, which never enters Rust
/// (`crate::host`). Output is opaque ciphertext for storage at rest; only this device can
/// [`open`] it.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>, DsmError> {
    crate::host::host()
        .and_then(|host| host.seal_seed(plaintext))
        .map_err(DsmError::invalid_operation)
}

/// Open a blob produced by [`seal`] on this device, recovering the plaintext.
pub fn open(blob: &[u8]) -> Result<Vec<u8>, DsmError> {
    crate::host::host()
        .and_then(|host| host.open_seed(blob))
        .map_err(DsmError::invalid_operation)
}
