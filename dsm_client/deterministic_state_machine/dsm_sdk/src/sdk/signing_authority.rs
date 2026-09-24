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

/// A token creation or burn authorization by this device: the witness record
/// `(u32 pk_len, pk, u32 sig_len, sig)` over `token_authorization_preimage`.
///
/// That preimage is what the policy's `TokenAuthority` condition rebuilds from
/// the operation it gates, and the key is matched against the policy's signer
/// list, so the witness authorizes that operation and nothing else.
/// `authorized_by` MUST equal what the enforcement context carries for the
/// operation; a mismatch is indistinguishable from a forged signature, which is
/// how it should behave.
pub(crate) fn token_authorization_witness(
    policy_commit: &[u8; 32],
    op: &str,
    token_id: &[u8],
    amount: u64,
    authorized_by: &[u8],
) -> Result<Vec<u8>, DsmError> {
    let preimage = dsm::core::token::policy::policy_enforcement::token_authorization_preimage(
        policy_commit,
        op,
        token_id,
        amount,
        authorized_by,
    );
    let keypair = derive_current_signing_keypair()?;
    let pk = keypair.public_key();
    let sig = dsm::crypto::sphincs::sphincs_sign(keypair.secret_key(), &preimage).map_err(|e| {
        DsmError::crypto(
            format!("token {op} authorization signing failed: {e}"),
            None::<std::io::Error>,
        )
    })?;
    let pk_len = u32::try_from(pk.len())
        .map_err(|_| DsmError::invalid_operation("signing key too large for a witness record"))?;
    let sig_len = u32::try_from(sig.len())
        .map_err(|_| DsmError::invalid_operation("signature too large for a witness record"))?;
    let mut witness = Vec::with_capacity(8 + pk.len() + sig.len());
    witness.extend_from_slice(&pk_len.to_le_bytes());
    witness.extend_from_slice(pk);
    witness.extend_from_slice(&sig_len.to_le_bytes());
    witness.extend_from_slice(&sig);
    Ok(witness)
}

/// Both halves of the device signing keypair, for callers that sign and embed
/// the public key in one object.
pub fn current_keypair() -> Result<(Vec<u8>, Vec<u8>), dsm::types::error::DsmError> {
    Ok((current_public_key()?, current_secret_key()?))
}
