//! DSM Recovery SDK
//!
//! SDK wrapper for the offline-first, post-quantum recovery system.
//! Provides application-level APIs for creating recovery capsules, managing
//! tombstone/succession receipts, and performing device recovery operations.

use std::collections::HashMap;
use std::sync::Mutex;
use dsm::recovery::{
    create_recovery_capsule, create_recovery_capsule_with_key, decrypt_recovery_capsule,
    create_tombstone_receipt, create_succession_receipt, verify_tombstone_receipt,
    verify_succession_receipt, update_rollup, verify_rollup, init_recovery, EncryptedCapsule,
    RecoveryCapsule, ReceiptRollup, TombstoneReceipt, SuccessionReceipt,
};
use dsm::recovery::capsule::{decrypt_capsule_with_key, derive_recovery_key};
use dsm::types::error::DsmError;

/// In-memory cached recovery key (derived from mnemonic via Argon2id + HKDF-BLAKE3).
/// Never persisted to disk — cleared on disable or app restart.
static RECOVERY_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// SDK for DSM recovery operations
pub struct RecoverySDK;

struct RecoveryCapsuleState {
    smt_root: Vec<u8>,
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: ReceiptRollup,
    next_index: u64,
}

impl RecoverySDK {
    /// Initialize the recovery subsystem
    pub fn init() {
        init_recovery();
    }

    /// Create an encrypted recovery capsule for NFC ring storage
    ///
    /// # Arguments
    /// * `smt_root` - Current SMT root hash
    /// * `counterparty_tips` - Map of counterparty_id -> (height, head_hash) for bilateral chains
    /// * `rollup` - Current receipt rollup accumulator
    /// * `mnemonic` - 24-word BIP39 mnemonic for key derivation
    /// * `counter` - Recovery capsule counter/version
    ///
    /// # Returns
    /// Encrypted capsule ready for NFC storage
    pub fn create_recovery_capsule(
        smt_root: &[u8],
        counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
        rollup: &ReceiptRollup,
        mnemonic: &str,
        counter: u64,
    ) -> Result<EncryptedCapsule, DsmError> {
        create_recovery_capsule(smt_root, counterparty_tips, rollup, mnemonic, counter)
    }

    /// Decrypt and verify a recovery capsule from NFC ring
    ///
    /// # Arguments
    /// * `encrypted_capsule` - Encrypted capsule from NFC ring
    /// * `mnemonic` - 24-word BIP39 mnemonic for key derivation
    ///
    /// # Returns
    /// Decrypted recovery capsule with SMT root and peer tips
    pub fn decrypt_recovery_capsule(
        encrypted_capsule: &EncryptedCapsule,
        mnemonic: &str,
    ) -> Result<RecoveryCapsule, DsmError> {
        decrypt_recovery_capsule(encrypted_capsule, mnemonic)
    }

    /// Create tombstone receipt to invalidate old device binding
    ///
    /// # Arguments
    /// * `old_smt_root` - SMT root from old device state
    /// * `old_counter` - Counter from old device state
    /// * `old_rollup` - Rollup hash from old device state
    /// * `device_id` - Device identifier
    /// * `private_key` - SPHINCS+ private key for signing
    ///
    /// # Returns
    /// Signed tombstone receipt
    pub fn create_tombstone_receipt(
        old_smt_root: &[u8],
        old_counter: u64,
        old_rollup: &[u8],
        device_id: &str,
        private_key: &[u8],
    ) -> Result<TombstoneReceipt, DsmError> {
        create_tombstone_receipt(
            old_smt_root,
            old_counter,
            old_rollup,
            device_id,
            private_key,
        )
    }

    /// Create succession receipt to bind new device
    ///
    /// # Arguments
    /// * `tombstone_hash` - Hash of the tombstone receipt
    /// * `new_device_commitment` - Commitment to new device public key
    /// * `device_id` - Device identifier
    /// * `private_key` - SPHINCS+ private key for signing
    ///
    /// # Returns
    /// Signed succession receipt
    pub fn create_succession_receipt(
        tombstone_hash: &[u8],
        new_device_commitment: &[u8],
        device_id: &str,
        private_key: &[u8],
    ) -> Result<SuccessionReceipt, DsmError> {
        create_succession_receipt(
            tombstone_hash,
            new_device_commitment,
            device_id,
            private_key,
        )
    }

    /// Verify tombstone receipt
    ///
    /// # Arguments
    /// * `tombstone` - Tombstone receipt to verify
    /// * `public_key` - SPHINCS+ public key for verification
    ///
    /// # Returns
    /// True if tombstone is valid
    pub fn verify_tombstone_receipt(
        tombstone: &TombstoneReceipt,
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        verify_tombstone_receipt(tombstone, public_key)
    }

    /// Verify succession receipt
    ///
    /// # Arguments
    /// * `succession` - Succession receipt to verify
    /// * `tombstone_hash` - Expected tombstone hash
    /// * `public_key` - SPHINCS+ public key for verification
    ///
    /// # Returns
    /// True if succession is valid
    pub fn verify_succession_receipt(
        succession: &SuccessionReceipt,
        tombstone_hash: &[u8],
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        verify_succession_receipt(succession, tombstone_hash, public_key)
    }

    /// Update receipt rollup with new receipt
    ///
    /// # Arguments
    /// * `rollup` - Rollup accumulator to update
    /// * `receipt_id` - Unique receipt identifier
    /// * `receipt_hash` - Hash of the receipt
    /// * `counterparty_id` - Counterparty identifier
    /// * `new_height` - New chain height
    pub fn update_rollup(
        rollup: &mut ReceiptRollup,
        receipt_id: &[u8],
        receipt_hash: &[u8],
        counterparty_id: &str,
        new_height: u64,
    ) -> Result<(), DsmError> {
        update_rollup(
            rollup,
            receipt_id,
            receipt_hash,
            counterparty_id,
            new_height,
        )
    }

    /// Verify rollup against expected value
    ///
    /// # Arguments
    /// * `rollup` - Rollup to verify
    /// * `expected` - Expected rollup hash
    ///
    /// # Returns
    /// True if rollup matches expected value
    pub fn verify_rollup(rollup: &ReceiptRollup, expected: &[u8]) -> bool {
        verify_rollup(rollup, expected)
    }

    /// Create an encrypted recovery capsule from the current device state.
    ///
    /// Gathers current SMT root, all bilateral counterparty chain tips,
    /// the receipt rollup accumulator, and the next capsule index from SQLite,
    /// then encrypts everything into a capsule ready for NFC ring storage.
    ///
    /// # Arguments
    /// * `mnemonic` - 24-word BIP39 mnemonic for key derivation
    ///
    /// # Returns
    /// Tuple of (capsule_index, encrypted capsule bytes serialized for NFC)
    pub fn create_capsule_from_current_state(mnemonic: &str) -> Result<(u64, Vec<u8>), DsmError> {
        let key = derive_recovery_key(mnemonic)?;
        Self::create_capsule_from_current_state_with_key(&key)
    }

    /// Get the latest pending recovery capsule bytes for NFC write.
    /// Returns None if no capsule is pending.
    pub fn get_pending_capsule() -> Option<(u64, Vec<u8>)> {
        crate::storage::client_db::recovery::get_pending_recovery_capsule()
            .ok()
            .flatten()
    }

    /// Check if NFC backup is currently enabled.
    pub fn is_nfc_backup_enabled() -> bool {
        crate::storage::client_db::recovery::is_nfc_backup_enabled()
    }

    /// Check if NFC backup was ever configured (mnemonic set up).
    pub fn is_nfc_backup_configured() -> bool {
        crate::storage::client_db::recovery::is_nfc_backup_configured()
    }

    /// Enable NFC backup. Marks the backup as both configured and enabled.
    pub fn enable_nfc_backup() -> Result<(), DsmError> {
        crate::storage::client_db::recovery::set_nfc_backup_configured(true)
            .map_err(|e| DsmError::InvalidState(format!("Failed to set configured: {e}")))?;
        crate::storage::client_db::recovery::set_nfc_backup_enabled(true)
            .map_err(|e| DsmError::InvalidState(format!("Failed to set enabled: {e}")))?;
        Ok(())
    }

    /// Disable NFC backup. Keeps configured=true so the user can re-enable.
    pub fn disable_nfc_backup() -> Result<(), DsmError> {
        crate::storage::client_db::recovery::set_nfc_backup_enabled(false)
            .map_err(|e| DsmError::InvalidState(format!("Failed to set disabled: {e}")))?;
        crate::storage::client_db::recovery::clear_pending_recovery_capsule()
            .map_err(|e| DsmError::InvalidState(format!("Failed to clear pending capsule: {e}")))?;
        Ok(())
    }

    /// Generate a cryptographically secure 24-word BIP-39 mnemonic.
    /// Uses 256 bits of CSPRNG entropy via OsRng. Crypto stays in Rust.
    pub fn generate_mnemonic() -> Result<String, DsmError> {
        use rand::RngCore;
        let mut entropy = [0u8; 32]; // 256 bits → 24 words
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| {
            DsmError::crypto(
                format!("BIP-39 generation failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok(mnemonic.to_string())
    }

    /// Derive recovery key from mnemonic and cache it in memory.
    /// Key derivation: S_mn = Argon2id("DSM/recovery-ring\0", mnemonic)
    ///                 K_R  = BLAKE3 derive-key("DSM/recovery-aead\0", S_mn)
    pub fn derive_and_cache_key(mnemonic: &str) -> Result<(), DsmError> {
        let key = derive_recovery_key(mnemonic)?;
        let mut guard = RECOVERY_KEY
            .lock()
            .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
        *guard = Some(key);
        Ok(())
    }

    /// Clear the cached recovery key from memory (for disable or app shutdown).
    pub fn clear_cached_key() {
        if let Ok(mut guard) = RECOVERY_KEY.lock() {
            if let Some(ref mut k) = *guard {
                // Zeroize before dropping
                k.iter_mut().for_each(|b| *b = 0);
            }
            *guard = None;
        }
    }

    /// Check if a recovery key is currently cached in memory.
    pub fn has_cached_key() -> bool {
        RECOVERY_KEY.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Decrypt an encrypted capsule using the in-memory cached recovery key.
    ///
    /// Used by the ring-import flow so mnemonic handling stays in Rust.
    pub fn decrypt_capsule_with_cached_key_bytes(
        capsule_bytes: &[u8],
    ) -> Result<RecoveryCapsule, DsmError> {
        let key = {
            let guard = RECOVERY_KEY
                .lock()
                .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
            guard.ok_or_else(|| DsmError::InvalidState("No cached recovery key".into()))?
        };

        let encrypted = EncryptedCapsule::from_bytes(capsule_bytes)?;
        decrypt_capsule_with_key(&encrypted, &key)
    }

    /// Silently refresh the pending NFC capsule if backup is enabled and a key is cached.
    ///
    /// Called by the transport layer (Kotlin) after every state-mutating operation.
    /// Rust decides whether to actually create a capsule. If backup is not enabled
    /// or no key is cached, this is a no-op. If capsule creation fails, it logs
    /// and moves on — it's not critical.
    ///
    /// The capsule overwrites any previous pending capsule. It sits there until
    /// the NFC ring comes into range, at which point Kotlin writes it, vibrates,
    /// and clears pending.
    pub fn maybe_refresh_nfc_capsule() {
        if !Self::is_nfc_backup_enabled() {
            return;
        }
        if !Self::has_cached_key() {
            return;
        }

        match Self::create_capsule_from_current_state_with_cached_key() {
            Ok((idx, capsule_bytes)) => {
                log::info!(
                    "[NFC_BACKUP] Auto-refreshed capsule index={} size={}",
                    idx,
                    capsule_bytes.len(),
                );
            }
            Err(e) => {
                log::warn!("[NFC_BACKUP] Auto-refresh failed (non-fatal): {}", e);
            }
        }
    }

    /// Create a capsule using the cached recovery key (no mnemonic needed).
    /// Used by `maybe_refresh_nfc_capsule` for automatic post-transition capsule creation.
    fn create_capsule_from_current_state_with_cached_key() -> Result<(u64, Vec<u8>), DsmError> {
        let key = {
            let guard = RECOVERY_KEY
                .lock()
                .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
            guard.ok_or_else(|| DsmError::InvalidState("No cached recovery key".into()))?
        };
        Self::create_capsule_from_current_state_with_key(&key)
    }

    /// Get recovery status for frontend display.
    pub fn get_recovery_status() -> RecoveryStatus {
        let enabled = crate::storage::client_db::recovery::is_nfc_backup_enabled();
        let configured = crate::storage::client_db::recovery::is_nfc_backup_configured();
        let pending_capsule = crate::storage::client_db::recovery::get_pending_recovery_capsule()
            .ok()
            .flatten()
            .is_some();
        let capsule_count = crate::storage::client_db::recovery::get_capsule_count().unwrap_or(0);
        let last_capsule_index =
            crate::storage::client_db::recovery::get_max_capsule_index().unwrap_or(0);

        RecoveryStatus {
            enabled,
            configured,
            pending_capsule,
            capsule_count,
            last_capsule_index,
        }
    }

    fn create_capsule_from_current_state_with_key(
        key: &[u8; 32],
    ) -> Result<(u64, Vec<u8>), DsmError> {
        let RecoveryCapsuleState {
            smt_root,
            counterparty_tips,
            rollup,
            next_index,
        } = Self::build_capsule_state()?;
        let tip_count = counterparty_tips.len();
        let encrypted = create_recovery_capsule_with_key(
            &smt_root,
            counterparty_tips,
            &rollup,
            key,
            next_index,
        )?;
        let capsule_bytes = encrypted.to_bytes();
        Self::persist_capsule(next_index, &smt_root, &capsule_bytes, tip_count)?;
        log::info!(
            "[RECOVERY_SDK] Created recovery capsule index={} size={} counterparties={}",
            next_index,
            capsule_bytes.len(),
            tip_count,
        );
        Ok((next_index, capsule_bytes))
    }

    fn build_capsule_state() -> Result<RecoveryCapsuleState, DsmError> {
        let smt_root = crate::sdk::app_state::AppState::get_smt_root().ok_or_else(|| {
            DsmError::InvalidState(
                "SMT root not available — run genesis before creating recovery capsule".to_string(),
            )
        })?;

        let device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::InvalidState("Device ID not available".to_string()))?;
        let local_device_id = crate::util::text_id::encode_base32_crockford(&device_id_bytes);
        let rollup = Self::derive_recovery_rollup(&local_device_id)?;

        let mut counterparty_tips = HashMap::new();
        if let Ok(contacts) = crate::storage::client_db::get_all_contacts() {
            for contact in contacts {
                if let Some(ref tip) = contact.current_chain_tip {
                    if tip.len() == 32 && contact.device_id.len() == 32 {
                        let counterparty_id =
                            crate::util::text_id::encode_base32_crockford(&contact.device_id);
                        // The SMT-backed relationship tip is authoritative. Height is a transport
                        // placeholder until a canonical per-relationship counter is persisted.
                        counterparty_tips.insert(counterparty_id, (0, tip.clone()));
                    }
                }
            }
        }

        // If there's already a pending (unconsumed) capsule, reuse its index —
        // we only care about the newest state. Index only advances after the ring
        // actually consumes a capsule and clears pending.
        let next_index = match crate::storage::client_db::recovery::get_pending_recovery_capsule() {
            Ok(Some((idx, _))) => idx,
            _ => crate::storage::client_db::recovery::get_max_capsule_index()
                .map_err(|e| DsmError::InvalidState(format!("Failed to read capsule index: {e}")))?
                .saturating_add(1),
        };

        Ok(RecoveryCapsuleState {
            smt_root,
            counterparty_tips,
            rollup,
            next_index,
        })
    }

    fn derive_recovery_rollup(local_device_id: &str) -> Result<ReceiptRollup, DsmError> {
        let binding = crate::storage::client_db::get_connection().map_err(|e| {
            DsmError::InvalidState(format!("Failed to open transaction history: {e}"))
        })?;
        let conn = binding
            .lock()
            .map_err(|_| DsmError::InvalidState("Database lock poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                // Rebuild the rollup from deterministic transaction ordering only.
                "SELECT tx_id, from_device, to_device, chain_height, proof_data
                 FROM transactions
                 ORDER BY step_index ASC, tx_id ASC",
            )
            .map_err(|e| {
                DsmError::InvalidState(format!("Failed to query transaction history: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(|e| {
                DsmError::InvalidState(format!("Failed to iterate transaction history: {e}"))
            })?;

        let mut rollup = ReceiptRollup::new();

        for row in rows {
            let (tx_id, from_device, to_device, chain_height, proof_data) = row.map_err(|e| {
                DsmError::InvalidState(format!("Failed to decode transaction row: {e}"))
            })?;

            let counterparty_id = if from_device == local_device_id && to_device != local_device_id
            {
                to_device
            } else if to_device == local_device_id && from_device != local_device_id {
                from_device
            } else {
                continue;
            };

            let Some(receipt_bytes) = proof_data.filter(|bytes| !bytes.is_empty()) else {
                continue;
            };

            let mut receipt_hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/receipt");
            receipt_hasher.update(&receipt_bytes);
            let receipt_hash = *receipt_hasher.finalize().as_bytes();
            update_rollup(
                &mut rollup,
                tx_id.as_bytes(),
                &receipt_hash,
                &counterparty_id,
                chain_height,
            )?;
        }

        Ok(rollup)
    }

    fn persist_capsule(
        capsule_index: u64,
        smt_root: &[u8],
        capsule_bytes: &[u8],
        tip_count: usize,
    ) -> Result<(), DsmError> {
        let smt_root_32: [u8; 32] = smt_root
            .try_into()
            .map_err(|_| DsmError::InvalidState("Recovery SMT root must be 32 bytes".into()))?;

        crate::storage::client_db::recovery::store_recovery_capsule(
            capsule_index,
            capsule_bytes,
            &smt_root_32,
        )
        .map_err(|e| DsmError::InvalidState(format!("Failed to persist capsule: {e}")))?;
        crate::storage::client_db::recovery::mark_pending_recovery_capsule(capsule_index)
            .map_err(|e| DsmError::InvalidState(format!("Failed to mark capsule pending: {e}")))?;
        crate::storage::client_db::recovery::set_latest_capsule_counterparty_count(
            tip_count as u64,
        )
        .map_err(|e| DsmError::InvalidState(format!("Failed to persist capsule preview: {e}")))?;
        let _ = crate::storage::client_db::recovery::prune_old_capsules(5);
        Ok(())
    }
}

/// Recovery status for frontend display.
#[derive(Debug, Clone)]
pub struct RecoveryStatus {
    pub enabled: bool,
    pub configured: bool,
    pub pending_capsule: bool,
    pub capsule_count: u64,
    pub last_capsule_index: u64,
}

impl Default for RecoverySDK {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoverySDK {
    /// Create a new RecoverySDK instance
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::recovery::ReceiptRollup;

    #[test]
    fn test_recovery_sdk_creation() {
        let _sdk = RecoverySDK::new();
        // SDK instance created successfully
    }

    #[test]
    fn test_rollup_operations_via_sdk() -> Result<(), DsmError> {
        let mut rollup = ReceiptRollup::new();
        let initial_hash = rollup.current_hash();

        // Update rollup via SDK
        RecoverySDK::update_rollup(&mut rollup, b"receipt1", &[1; 32], "peer1", 1)?;

        // Hash should change
        assert_ne!(rollup.current_hash(), initial_hash);

        // Verify rollup via SDK
        assert!(RecoverySDK::verify_rollup(&rollup, &rollup.current_hash()));

        Ok(())
    }
}
