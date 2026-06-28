// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical SDK device signing authority.
//!
//! The device signing keypair is the Genesis v2 attestation key (AK). It derives
//! deterministically from the BIP39 wallet seed via the single canonical
//! [`crate::init::derive_device_signing_keypair`] (shared with genesis creation and
//! recovery-authority anchoring), so the key re-derived here is byte-identical to the
//! one `create_genesis_v2` registered.
//!
//! There is no persisted device secret and no C-DBRW binding key: the wallet seed lives
//! only in the session cache populated at unlock ([`crate::sdk::recovery_sdk`]). Every
//! consumer therefore fails closed when the wallet is locked.

use dsm::crypto::SignatureKeyPair;
use dsm::types::error::DsmError;

use crate::sdk::app_state::AppState;

fn genesis_from_app_state() -> Result<[u8; 32], DsmError> {
    let genesis_hash = AppState::get_genesis_hash().ok_or_else(|| {
        DsmError::InvalidState(
            "genesis_hash not initialized for canonical signing authority".into(),
        )
    })?;
    if genesis_hash.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "genesis_hash must be 32 bytes, got {}",
            genesis_hash.len()
        )));
    }
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(&genesis_hash);
    Ok(genesis)
}

pub(crate) fn derive_current_signing_keypair() -> Result<SignatureKeyPair, DsmError> {
    let genesis = genesis_from_app_state()?;
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::InvalidState(
                "wallet seed unavailable for canonical signing authority (wallet locked)".into(),
            )
        })?;

    crate::init::derive_device_signing_keypair(&wallet_seed, &genesis)
}

pub(crate) fn current_public_key() -> Result<Vec<u8>, DsmError> {
    Ok(derive_current_signing_keypair()?.public_key().to_vec())
}

pub(crate) fn current_secret_key() -> Result<Vec<u8>, DsmError> {
    Ok(derive_current_signing_keypair()?.secret_key().to_vec())
}

// ---------------------------------------------------------------------------
// Test helpers.
//
// Legacy fixtures passed a deterministic 32-byte "binding key"; under Genesis v2 that
// fixture is simply the wallet seed the derivation re-roots on. `device_id` is no longer
// an input to the derivation and is retained only for call-site compatibility.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn derive_signing_keypair_for_testing(
    _device_id: &[u8],
    genesis_hash: &[u8],
    wallet_seed: &[u8],
) -> Result<SignatureKeyPair, DsmError> {
    if genesis_hash.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "genesis_hash must be 32 bytes, got {}",
            genesis_hash.len()
        )));
    }
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(genesis_hash);
    crate::init::derive_device_signing_keypair(wallet_seed, &genesis)
}

#[cfg(test)]
pub(crate) fn derive_signing_keys_for_testing(
    device_id: &[u8],
    genesis_hash: &[u8],
    wallet_seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let keypair = derive_signing_keypair_for_testing(device_id, genesis_hash, wallet_seed)?;
    Ok((keypair.public_key().to_vec(), keypair.secret_key().to_vec()))
}

#[cfg(any(test, feature = "test-utils"))]
#[cfg(not(all(target_os = "android", feature = "jni")))]
pub(crate) fn set_binding_key_for_testing(wallet_seed: Vec<u8>) {
    crate::sdk::recovery_sdk::RecoverySDK::set_cached_wallet_seed_for_testing(wallet_seed);
}

#[cfg(any(test, feature = "test-utils"))]
#[cfg(not(all(target_os = "android", feature = "jni")))]
pub(crate) fn clear_binding_key_for_testing() {
    crate::sdk::recovery_sdk::RecoverySDK::clear_cached_wallet_seed_for_testing();
}
