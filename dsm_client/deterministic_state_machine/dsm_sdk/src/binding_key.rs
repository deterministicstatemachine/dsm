use std::sync::{Mutex, OnceLock};

use dsm::types::error::DsmError;

fn binding_key_slot() -> &'static Mutex<Option<Vec<u8>>> {
    static CANONICAL_BINDING_KEY: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    CANONICAL_BINDING_KEY.get_or_init(|| Mutex::new(None))
}

pub(crate) fn install_binding_key(binding_key: Vec<u8>) -> Result<(), DsmError> {
    if binding_key.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "C-DBRW binding key must be 32 bytes, got {}",
            binding_key.len()
        )));
    }

    let mut guard = binding_key_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(binding_key);
    Ok(())
}

pub(crate) fn get_binding_key() -> Option<Vec<u8>> {
    binding_key_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Zero the in-memory K_DBRW slot. Called by `cdbrw.reprove` on
/// `CloneDetected` AND by `cdbrw_responder::publish_trust_snapshot`
/// on W1 drift (Phase 13 follow-up: aligns operational behaviour
/// with the documented Layer B claim that drift zeros K_DBRW).
/// Every downstream signer that would use K_DBRW must fail closed
/// (`InvalidState`) until re-enrollment re-derives it.
///
/// TOCTOU bound: a signer that already cloned the bytes via
/// `get_binding_key()` BEFORE this call can still complete; the access
/// gate downgrade (`AccessLevel::PinRequired` / `ReadOnly`) in the
/// router is the strong fence. This function bounds the in-memory
/// residue window — it does not eliminate it.
pub(crate) fn clear_binding_key() {
    let mut guard = binding_key_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Best-effort zeroize the bytes before replacing the slot so the
    // value doesn't linger in heap memory.
    if let Some(prev) = guard.as_mut() {
        for b in prev.iter_mut() {
            *b = 0;
        }
    }
    *guard = None;
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn clear_binding_key_for_testing() {
    let mut guard = binding_key_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}
