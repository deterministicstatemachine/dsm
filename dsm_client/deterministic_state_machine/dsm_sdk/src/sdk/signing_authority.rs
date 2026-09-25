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

/// Sign `payload` with this device's signing key (SPHINCS+).
pub(crate) fn sign_bytes(payload: &[u8]) -> Result<Vec<u8>, DsmError> {
    let sk = current_secret_key()?;
    dsm::crypto::sphincs::sphincs_sign(&sk, payload).map_err(|e| {
        DsmError::crypto(
            format!("SPHINCS+ byte signing failed: {e}"),
            None::<std::io::Error>,
        )
    })
}

/// Both halves of the device signing keypair, for callers that sign and embed
/// the public key in one object.
pub fn current_keypair() -> Result<(Vec<u8>, Vec<u8>), dsm::types::error::DsmError> {
    Ok((current_public_key()?, current_secret_key()?))
}
