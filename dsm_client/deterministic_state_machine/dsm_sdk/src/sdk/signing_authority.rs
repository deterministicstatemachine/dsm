use dsm::crypto::SignatureKeyPair;
use dsm::types::error::DsmError;

use crate::sdk::app_state::AppState;

fn get_binding_key() -> Option<Vec<u8>> {
    crate::binding_key::get_binding_key()
}

fn derive_signing_keypair_from(
    device_id: &[u8],
    genesis_hash: &[u8],
    binding_key: &[u8],
) -> Result<SignatureKeyPair, DsmError> {
    if device_id.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "device_id must be 32 bytes, got {}",
            device_id.len()
        )));
    }
    if genesis_hash.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "genesis_hash must be 32 bytes, got {}",
            genesis_hash.len()
        )));
    }
    if binding_key.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "C-DBRW binding key must be 32 bytes, got {}",
            binding_key.len()
        )));
    }

    let mut entropy = Vec::with_capacity(96);
    entropy.extend_from_slice(genesis_hash);
    entropy.extend_from_slice(device_id);
    entropy.extend_from_slice(binding_key);

    SignatureKeyPair::generate_from_entropy_with_params(
        &entropy,
        dsm::crypto::signatures::ParameterSet::SPX256f,
    )
    .map_err(|e| {
        DsmError::crypto(
            format!("canonical signing key derivation failed: {e}"),
            None::<std::io::Error>,
        )
    })
}

pub(crate) fn derive_current_signing_keypair() -> Result<SignatureKeyPair, DsmError> {
    let device_id = AppState::get_device_id().ok_or_else(|| {
        DsmError::InvalidState("device_id not initialized for canonical signing authority".into())
    })?;
    let genesis_hash = AppState::get_genesis_hash().ok_or_else(|| {
        DsmError::InvalidState(
            "genesis_hash not initialized for canonical signing authority".into(),
        )
    })?;
    let binding_key = get_binding_key().ok_or_else(|| {
        DsmError::InvalidState(
            "C-DBRW binding key unavailable for canonical signing authority".into(),
        )
    })?;

    derive_signing_keypair_from(&device_id, &genesis_hash, &binding_key)
}

pub(crate) fn current_public_key() -> Result<Vec<u8>, DsmError> {
    let keypair = derive_current_signing_keypair()?;
    Ok(keypair.public_key().to_vec())
}

pub(crate) fn current_secret_key() -> Result<Vec<u8>, DsmError> {
    let keypair = derive_current_signing_keypair()?;
    Ok(keypair.secret_key().to_vec())
}

#[cfg(test)]
pub(crate) fn derive_signing_keypair_for_testing(
    device_id: &[u8],
    genesis_hash: &[u8],
    binding_key: &[u8],
) -> Result<SignatureKeyPair, DsmError> {
    derive_signing_keypair_from(device_id, genesis_hash, binding_key)
}

#[cfg(test)]
pub(crate) fn derive_signing_keys_for_testing(
    device_id: &[u8],
    genesis_hash: &[u8],
    binding_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let keypair = derive_signing_keypair_from(device_id, genesis_hash, binding_key)?;
    Ok((keypair.public_key().to_vec(), keypair.secret_key().to_vec()))
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
pub(crate) fn set_binding_key_for_testing(binding_key: Vec<u8>) {
    let _ = crate::binding_key::install_binding_key(binding_key);
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
pub(crate) fn clear_binding_key_for_testing() {
    crate::binding_key::clear_binding_key_for_testing();
}
