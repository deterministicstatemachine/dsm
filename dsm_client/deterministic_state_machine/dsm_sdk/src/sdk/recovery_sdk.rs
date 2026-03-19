//! DSM Recovery SDK
//!
//! SDK wrapper for the offline-first, post-quantum recovery system.
//! Provides application-level APIs for creating recovery capsules, managing
//! tombstone/succession receipts, and performing device recovery operations.

use std::collections::HashMap;
use std::sync::Mutex;
use dsm::recovery::{
    create_recovery_capsule, decrypt_recovery_capsule, create_tombstone_receipt,
    create_succession_receipt, verify_tombstone_receipt, verify_succession_receipt, update_rollup,
    verify_rollup, init_recovery, EncryptedCapsule, RecoveryCapsule, ReceiptRollup,
    TombstoneReceipt, SuccessionReceipt,
};
use dsm::types::error::DsmError;

/// In-memory cached recovery key (derived from mnemonic via Argon2id + HKDF-BLAKE3).
/// Never persisted to disk — cleared on disable or app restart.
static RECOVERY_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// SDK for DSM recovery operations
pub struct RecoverySDK;

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
    /// * `device_id` - Unique device identifier
    /// * `counter` - Recovery capsule counter/version
    ///
    /// # Returns
    /// Encrypted capsule ready for NFC storage
    pub fn create_recovery_capsule(
        smt_root: &[u8],
        counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
        rollup: &ReceiptRollup,
        mnemonic: &str,
        device_id: &str,
        counter: u64,
    ) -> Result<EncryptedCapsule, DsmError> {
        create_recovery_capsule(
            smt_root,
            counterparty_tips,
            rollup,
            mnemonic,
            device_id,
            counter,
        )
    }

    /// Decrypt and verify a recovery capsule from NFC ring
    ///
    /// # Arguments
    /// * `encrypted_capsule` - Encrypted capsule from NFC ring
    /// * `mnemonic` - 24-word BIP39 mnemonic for key derivation
    /// * `device_id` - Device identifier for verification
    ///
    /// # Returns
    /// Decrypted recovery capsule with SMT root and peer tips
    pub fn decrypt_recovery_capsule(
        encrypted_capsule: &EncryptedCapsule,
        mnemonic: &str,
        device_id: &str,
    ) -> Result<RecoveryCapsule, DsmError> {
        decrypt_recovery_capsule(encrypted_capsule, mnemonic, device_id)
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
        // 1. Read current SMT root from AppState
        let smt_root = crate::sdk::app_state::AppState::get_smt_root().ok_or_else(|| {
            DsmError::InvalidState(
                "SMT root not available — run genesis before creating recovery capsule".to_string(),
            )
        })?;

        // 2. Read device_id
        let device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::InvalidState("Device ID not available".to_string()))?;
        let device_id_str = crate::util::text_id::encode_base32_crockford(&device_id_bytes);

        // 3. Gather counterparty bilateral chain tips from contacts SQLite
        let mut counterparty_tips: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
        if let Ok(contacts) = crate::storage::client_db::get_all_contacts() {
            for contact in contacts {
                // Only include contacts that have an established bilateral chain tip
                if let Some(ref tip) = contact.current_chain_tip {
                    if tip.len() == 32 && contact.device_id.len() == 32 {
                        let counterparty_id =
                            crate::util::text_id::encode_base32_crockford(&contact.device_id);
                        // Use added_at as height proxy (chain height for this relationship)
                        counterparty_tips.insert(counterparty_id, (contact.added_at, tip.clone()));
                    }
                }
            }
        }

        // 4. Get or create a fresh rollup accumulator
        let rollup = ReceiptRollup::new();

        // 5. Determine next capsule index (monotonic counter, not wall-clock)
        let next_index = crate::storage::client_db::recovery::get_max_capsule_index()
            .map_err(|e| DsmError::InvalidState(format!("Failed to read capsule index: {e}")))?
            .saturating_add(1);

        // 6. Create the encrypted capsule via core
        let tip_count = counterparty_tips.len();
        let encrypted = create_recovery_capsule(
            &smt_root,
            counterparty_tips,
            &rollup,
            mnemonic,
            &device_id_str,
            next_index,
        )?;

        // 7. Serialize the encrypted capsule to bytes for NFC storage
        let capsule_bytes = encrypted.to_bytes();

        // 8. Persist to SQLite for pending NFC write
        let smt_root_32: [u8; 32] = if smt_root.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&smt_root);
            arr
        } else {
            [0u8; 32]
        };

        crate::storage::client_db::recovery::store_recovery_capsule(
            next_index,
            &capsule_bytes,
            &smt_root_32,
        )
        .map_err(|e| DsmError::InvalidState(format!("Failed to persist capsule: {e}")))?;

        // 9. Prune old capsules (keep latest 5)
        let _ = crate::storage::client_db::recovery::prune_old_capsules(5);

        log::info!(
            "[RECOVERY_SDK] Created recovery capsule index={} size={} counterparties={}",
            next_index,
            capsule_bytes.len(),
            tip_count,
        );

        Ok((next_index, capsule_bytes))
    }

    /// Get the latest pending recovery capsule bytes for NFC write.
    /// Returns None if no capsule is pending.
    pub fn get_pending_capsule() -> Option<(u64, Vec<u8>)> {
        crate::storage::client_db::recovery::get_latest_recovery_capsule()
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
    ///                 K_R  = BLAKE3-keyed("DSM/recovery-aead\0", S_mn)
    pub fn derive_and_cache_key(mnemonic: &str) -> Result<(), DsmError> {
        let key = Self::derive_recovery_key(mnemonic)?;
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

    /// Internal: derive the 32-byte recovery key from a mnemonic.
    fn derive_recovery_key(mnemonic: &str) -> Result<[u8; 32], DsmError> {
        use argon2::Argon2;

        // Step 1: S_mn = Argon2id("DSM/recovery-ring\0", mnemonic_bytes)
        let salt_bytes = b"DSM/recovery-ring\0";
        // Use Argon2id with default params (19 MiB, 2 iterations, 1 lane)
        let argon2 = Argon2::default();
        let mut s_mn = [0u8; 32];
        argon2
            .hash_password_into(mnemonic.as_bytes(), salt_bytes, &mut s_mn)
            .map_err(|e| {
                DsmError::crypto(format!("Argon2id failed: {e}"), None::<std::io::Error>)
            })?;

        // Step 2: K_R = BLAKE3-keyed("DSM/recovery-aead\0", S_mn)
        let domain = b"DSM/recovery-aead\0";
        let mut hasher = blake3::Hasher::new_keyed(&s_mn);
        hasher.update(domain);
        let k_r: [u8; 32] = *hasher.finalize().as_bytes();

        // Zeroize intermediate
        s_mn.iter_mut().for_each(|b| *b = 0);

        Ok(k_r)
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
        // Gate 1: is NFC backup enabled?
        if !Self::is_nfc_backup_enabled() {
            return;
        }

        // Gate 2: is a recovery key cached in memory?
        if !Self::has_cached_key() {
            return;
        }

        // Gate 3: extract the cached key and derive mnemonic-equivalent
        // We can't re-derive from mnemonic (not stored), but the capsule creation
        // path uses mnemonic directly. Since we can't recover the mnemonic from
        // the key, we need a different approach: use the cached key directly.
        //
        // For now, use create_capsule_from_current_state_with_key which encrypts
        // using the pre-derived key instead of re-deriving from mnemonic.
        match Self::create_capsule_from_current_state_with_cached_key() {
            Ok((idx, size)) => {
                log::info!(
                    "[NFC_BACKUP] Auto-refreshed capsule index={} size={}",
                    idx, size,
                );
            }
            Err(e) => {
                log::warn!("[NFC_BACKUP] Auto-refresh failed (non-fatal): {}", e);
            }
        }
    }

    /// Create a capsule using the cached recovery key (no mnemonic needed).
    /// Used by `maybe_refresh_nfc_capsule` for automatic post-transition capsule creation.
    fn create_capsule_from_current_state_with_cached_key() -> Result<(u64, usize), DsmError> {
        let key = {
            let guard = RECOVERY_KEY
                .lock()
                .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
            guard.ok_or_else(|| DsmError::InvalidState("No cached recovery key".into()))?
        };

        // Read current state
        let smt_root = crate::sdk::app_state::AppState::get_smt_root().ok_or_else(|| {
            DsmError::InvalidState("SMT root not available".to_string())
        })?;

        // Gather counterparty tips
        let mut counterparty_tips: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
        if let Ok(contacts) = crate::storage::client_db::get_all_contacts() {
            for contact in contacts {
                if let Some(ref tip) = contact.current_chain_tip {
                    if tip.len() == 32 && contact.device_id.len() == 32 {
                        let cid = crate::util::text_id::encode_base32_crockford(&contact.device_id);
                        counterparty_tips.insert(cid, (contact.added_at, tip.clone()));
                    }
                }
            }
        }

        let rollup = dsm::recovery::ReceiptRollup::new();
        let next_index = crate::storage::client_db::recovery::get_max_capsule_index()
            .map_err(|e| DsmError::InvalidState(format!("Failed to read capsule index: {e}")))?
            .saturating_add(1);

        // Build capsule metadata
        let metadata = dsm::recovery::CapsuleMetadata {
            version: 1,
            flags: 0,
            logical_time: next_index,
            counter: next_index,
        };

        let capsule = dsm::recovery::RecoveryCapsule {
            smt_root: smt_root.clone(),
            counterparty_tips,
            rollup_hash: rollup.current_hash().to_vec(),
            metadata,
        };

        // Serialize via canonical RecoveryCapsule::to_bytes (single source of truth in core)
        let plaintext = capsule.to_bytes();

        // Encrypt with cached key using ChaCha20-Poly1305 (or AES-256-GCM)
        use aes_gcm::{Aes256Gcm, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| DsmError::crypto("Invalid cached key", None::<String>))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| DsmError::verification("Failed to encrypt capsule"))?;

        let tag_start = ciphertext.len().saturating_sub(16);
        let tag = ciphertext[tag_start..].to_vec();
        let ct = ciphertext[..tag_start].to_vec();

        // Build EncryptedCapsule and serialize
        let encrypted = dsm::recovery::EncryptedCapsule {
            ciphertext: ct,
            tag,
            nonce: nonce_bytes.to_vec(),
            salt: vec![], // No salt needed — key is pre-derived
            metadata: dsm::recovery::CapsuleMetadata {
                version: 1,
                flags: 0,
                logical_time: next_index,
                counter: next_index,
            },
        };

        let capsule_bytes = encrypted.to_bytes();
        let size = capsule_bytes.len();

        // Persist
        let smt_root_32: [u8; 32] = if smt_root.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&smt_root);
            arr
        } else {
            [0u8; 32]
        };

        crate::storage::client_db::recovery::store_recovery_capsule(
            next_index,
            &capsule_bytes,
            &smt_root_32,
        )
        .map_err(|e| DsmError::InvalidState(format!("Failed to persist capsule: {e}")))?;

        let _ = crate::storage::client_db::recovery::prune_old_capsules(5);

        Ok((next_index, size))
    }

    /// Get recovery status for frontend display.
    pub fn get_recovery_status() -> RecoveryStatus {
        let enabled = crate::storage::client_db::recovery::is_nfc_backup_enabled();
        let configured = crate::storage::client_db::recovery::is_nfc_backup_configured();
        let capsule_count = crate::storage::client_db::recovery::get_capsule_count().unwrap_or(0);
        let last_capsule_index =
            crate::storage::client_db::recovery::get_max_capsule_index().unwrap_or(0);

        RecoveryStatus {
            enabled,
            configured,
            capsule_count,
            last_capsule_index,
        }
    }
}

/// Recovery status for frontend display.
#[derive(Debug, Clone)]
pub struct RecoveryStatus {
    pub enabled: bool,
    pub configured: bool,
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
