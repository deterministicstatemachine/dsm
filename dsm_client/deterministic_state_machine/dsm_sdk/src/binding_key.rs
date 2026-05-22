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

/// Zero the in-memory K_DBRW slot. Used by `cdbrw.reprove` when a clone
/// (or catastrophic substrate drift) is detected — every downstream
/// signer that would use K_DBRW must fail closed until re-enrollment
/// re-derives it.
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
