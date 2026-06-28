// SPDX-License-Identifier: MIT OR Apache-2.0

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
use dsm::recovery::capsule::{
    decrypt_capsule_with_key, derive_recovery_key, derive_recovery_authority_seed,
};
use dsm::types::error::DsmError;

/// In-memory cached recovery key (derived from mnemonic via Argon2id + HKDF-BLAKE3).
/// Also persisted to SQLite encrypted by a device-bound key so it survives app restarts.
static RECOVERY_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// In-memory cached recovery authority SPHINCS+ keypair (public, secret).
/// Derived from the mnemonic via a separate HKDF domain (`DSM/recovery-authority`).
/// Used to sign tombstone and succession receipts during device recovery.
/// Never persisted to disk — cleared alongside the encryption key.
static RECOVERY_AUTHORITY_KEYPAIR: Mutex<Option<(Vec<u8>, Vec<u8>)>> = Mutex::new(None);

/// In-memory cached BIP39 wallet seed (`mnemonic.to_seed("")`). The canonical Genesis v2
/// root-secret input — `wallet_seed -> s0 -> Smaster -> {device signing key, per-step EK,
/// ML-KEM coins}` are re-derived from it on demand via the wallet/recovery unlock path.
/// NEVER persisted; populated at unlock alongside the recovery key, cleared with it.
static WALLET_SEED_CACHE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// SDK for DSM recovery operations
pub struct RecoverySDK;

struct RecoveryCapsuleState {
    smt_root: Vec<u8>,
    counterparty_tips: HashMap<String, (u64, Vec<u8>)>,
    rollup: ReceiptRollup,
    next_index: u64,
    /// Device ID of this device (for capsule source binding).
    source_device_id: Vec<u8>,
    /// Genesis hash of this device (for capsule genesis binding).
    genesis_hash: Vec<u8>,
}

/// Session inputs for [`RecoverySDK::build_and_activate_recovery`] — the decrypted capsule's
/// floor/frontier plus the recovery intent and the recovered device's final state. The route
/// handler decodes the capsule + AppState identity into this; the orchestrator fetches all
/// online-posted state from storage itself.
#[derive(Clone, Debug)]
pub struct RecoveryActivationContext {
    pub genesis_id: [u8; 32],
    /// The device being recovered (capsule `source_device_id`).
    pub a_old: [u8; 32],
    /// The recovering successor device (this device).
    pub a_new: [u8; 32],
    /// Per-counterparty capsule floor `h_cap` (the sealed `(A_old,C)` tip), keyed by C.
    pub capsule_floor: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    /// A_old's frontier for the tombstone (from the capsule).
    pub old_smt_root: [u8; 32],
    pub old_counter: u64,
    pub old_rollup_hash: [u8; 32],
    /// Recovery-session seal context (bound into the activation seal, not derived here).
    pub recovery_intent_digest: [u8; 32],
    pub tombstone_proposal_digest: [u8; 32],
    pub final_per_device_smt_root: [u8; 32],
    pub final_receipt_roll: [u8; 32],
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
        let mut entropy = [0u8; 32]; // 256 bits → 24 words
        let mut rng = rand::rngs::OsRng;
        rand::TryRngCore::try_fill_bytes(&mut rng, &mut entropy).map_err(|e| {
            DsmError::crypto(
                format!("OsRng entropy failure: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| {
            DsmError::crypto(
                format!("BIP-39 generation failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok(mnemonic.to_string())
    }

    /// The cached BIP39 wallet seed (the Genesis v2 root-secret input), if the mnemonic
    /// has been unlocked this session via [`Self::derive_and_cache_key`]. `None` otherwise —
    /// callers that need it (device-key re-derivation, per-step EK/ML-KEM) MUST fail closed.
    pub fn get_cached_wallet_seed() -> Option<Vec<u8>> {
        WALLET_SEED_CACHE.lock().ok().and_then(|g| g.clone())
    }

    /// Seed the wallet-seed session cache directly (tests only). Replaces the legacy
    /// C-DBRW binding-key fixtures: derivations re-root on this seed exactly as production
    /// re-roots on the mnemonic-derived seed.
    #[cfg(not(target_os = "android"))]
    pub fn set_cached_wallet_seed_for_testing(seed: Vec<u8>) {
        if let Ok(mut guard) = WALLET_SEED_CACHE.lock() {
            *guard = Some(seed);
        }
    }

    /// Clear the wallet-seed session cache (tests only / wallet lock).
    #[cfg(not(target_os = "android"))]
    pub fn clear_cached_wallet_seed_for_testing() {
        if let Ok(mut guard) = WALLET_SEED_CACHE.lock() {
            *guard = None;
        }
    }

    /// Derive recovery key from mnemonic and cache it in memory.
    ///
    /// Key derivation: S_mn = Argon2id("DSM/recovery-ring\0", mnemonic)
    ///                 K_R  = BLAKE3 derive-key("DSM/recovery-aead\0", S_mn)
    ///                 K_A  = BLAKE3 derive-key("DSM/recovery-authority\0", S_mn)
    ///                 (pk, sk) = SPHINCS+.generate_from_seed(K_A)
    ///
    /// Both the encryption key and the authority keypair are cached in memory.
    pub fn derive_and_cache_key(mnemonic: &str) -> Result<(), DsmError> {
        let key = derive_recovery_key(mnemonic)?;
        {
            let mut guard = RECOVERY_KEY
                .lock()
                .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
            *guard = Some(key);
        }

        // Cache the BIP39 wallet seed — the canonical Genesis v2 root-secret input
        // (mnemonic -> wallet_seed -> s0 -> Smaster). NEVER persisted; lives only for the
        // unlocked session so device-key + per-step EK/ML-KEM derivations can re-derive it.
        {
            let seed = bip39::Mnemonic::parse(mnemonic)
                .map_err(|e| DsmError::InvalidState(format!("invalid mnemonic: {e}")))?
                .to_seed("");
            let mut guard = WALLET_SEED_CACHE
                .lock()
                .map_err(|_| DsmError::InvalidState("Wallet seed mutex poisoned".into()))?;
            *guard = Some(seed.to_vec());
        }

        // Persist the key encrypted by a device-bound wrapping key so it
        // survives app restarts without requiring the mnemonic again.
        if let Err(e) = Self::persist_recovery_key(&key) {
            log::warn!("[RECOVERY_SDK] Failed to persist recovery key (non-fatal): {e}");
        }

        // Derive and cache the recovery authority SPHINCS+ keypair.
        let authority_seed = derive_recovery_authority_seed(mnemonic)?;
        let keypair = dsm::crypto::sphincs::generate_keypair_from_seed(
            dsm::crypto::sphincs::SphincsVariant::SPX256f,
            &authority_seed,
        )
        .map_err(|e| DsmError::InvalidState(format!("Recovery authority keygen failed: {e}")))?;
        {
            let mut guard = RECOVERY_AUTHORITY_KEYPAIR.lock().map_err(|_| {
                DsmError::InvalidState("Recovery authority keypair mutex poisoned".into())
            })?;
            *guard = Some((keypair.public_key.clone(), keypair.secret_key.clone()));
        }
        log::info!("[RECOVERY_SDK] Cached recovery encryption key and authority keypair");
        Ok(())
    }

    /// Clear the cached recovery key and authority keypair from memory and storage.
    pub fn clear_cached_key() {
        if let Ok(mut guard) = RECOVERY_KEY.lock() {
            if let Some(ref mut k) = *guard {
                k.iter_mut().for_each(|b| *b = 0);
            }
            *guard = None;
        }
        if let Ok(mut guard) = RECOVERY_AUTHORITY_KEYPAIR.lock() {
            if let Some((ref mut pk, ref mut sk)) = *guard {
                pk.iter_mut().for_each(|b| *b = 0);
                sk.iter_mut().for_each(|b| *b = 0);
            }
            *guard = None;
        }
        // Also wipe the persisted encrypted blob.
        let _ = crate::storage::client_db::recovery::delete_encrypted_recovery_key();
    }

    /// Check if a recovery key is currently cached in memory.
    pub fn has_cached_key() -> bool {
        RECOVERY_KEY.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Get the cached recovery authority keypair (public_key, secret_key).
    /// Returns `None` if no mnemonic has been cached yet.
    pub fn get_cached_authority_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
        RECOVERY_AUTHORITY_KEYPAIR
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    /// Build the genesis-anchored recovery-authority anchor (spec §0.5 step 5) for THIS
    /// device, ready to publish. Re-derives the device's genesis signing keypair
    /// deterministically (it is never persisted — `init::derive_device_signing_keypair`
    /// is the SOLE canonical derivation), uses the cached mnemonic-derived authority
    /// keypair, and produces the doubly-signed declaration committing `H(K_A_pub)`.
    ///
    /// Fail-closed: requires AppState identity (device_id + genesis_hash), K_DBRW, and a
    /// cached authority keypair — i.e. the mnemonic must already be cached (call
    /// `derive_and_cache_key` first, as `recovery.enable` does).
    pub fn build_authority_anchor() -> Result<dsm::recovery::RecoveryAuthorityAnchor, DsmError> {
        let device_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;
        let genesis_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_genesis_hash(),
            "genesis_hash",
        )?;

        let wallet_seed = Self::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::InvalidState(
                "recovery anchor: wallet seed not unlocked (cache the mnemonic via derive_and_cache_key first)"
                    .into(),
            )
        })?;

        // Re-derive the device signing keypair — byte-identical to the one create_genesis_v2
        // registered (the AK keypair rooted in the BIP39 wallet seed; Genesis v2). No DBRW.
        let device_kp = crate::init::derive_device_signing_keypair(&wallet_seed, &genesis_id)?;

        let (authority_pk, authority_sk) =
            Self::get_cached_authority_keypair().ok_or_else(|| {
                DsmError::InvalidState(
                "recovery anchor: no cached recovery-authority keypair (cache the mnemonic first)"
                    .into(),
            )
            })?;

        dsm::recovery::create_recovery_authority_anchor(
            &genesis_id,
            &device_id,
            &authority_pk,
            &device_kp.secret_key,
            &authority_sk,
        )
    }

    /// Fail-closed `Option<Vec<u8>>` → `[u8; 32]` for this device's own identity fields.
    fn require_self_id32(v: Option<Vec<u8>>, what: &str) -> Result<[u8; 32], DsmError> {
        let bytes = v.ok_or_else(|| {
            DsmError::InvalidState(format!("recovery anchor: {what} not set (no identity)"))
        })?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            DsmError::InvalidState(format!("recovery anchor: {what} must be 32 bytes"))
        })
    }

    /// The dedicated, genesis-keyed bind-once endpoint path for a recovery-authority
    /// anchor (matches the storage-node route `/api/v2/recovery/authority-anchor/{genesis}`).
    /// Keyed by genesis ONLY — the device is carried inside the anchor — so the
    /// storage-node single-assignment store binds one authority per genesis. Base32
    /// Crockford (no hex). Returned without a leading slash for the fan-out helpers.
    pub fn authority_anchor_endpoint_path(genesis_id: &[u8; 32]) -> String {
        format!(
            "api/v2/recovery/authority-anchor/{}",
            crate::util::text_id::encode_base32_crockford(genesis_id),
        )
    }

    /// Build THIS device's recovery-authority anchor and publish it to the dedicated
    /// bind-once endpoint on every storage node. Returns the number of nodes that
    /// accepted the write (2xx).
    ///
    /// Bind-once is enforced server-side per genesis: the FIRST anchor wins; an
    /// identical replay is idempotent (2xx); a DIFFERENT anchor for the same genesis
    /// is rejected 409. A 409 here therefore means a conflicting authority is already
    /// bound for this genesis — this call returns an error rather than masking it.
    pub async fn publish_authority_anchor() -> Result<usize, DsmError> {
        let anchor = Self::build_authority_anchor()?;
        let path = Self::authority_anchor_endpoint_path(&anchor.genesis_id);
        let r = crate::sdk::storage_io::put_to_all_nodes_path(&path, &anchor.to_bytes()).await?;
        if r.conflict > 0 {
            return Err(DsmError::InvalidState(format!(
                "recovery anchor publish: {}/{} nodes report a DIFFERENT authority anchor already \
                 bound for this genesis (bind-once conflict); refusing to treat as published",
                r.conflict, r.total
            )));
        }
        if r.ok == 0 {
            return Err(DsmError::storage(
                format!(
                    "recovery anchor publish: no node accepted the write ({} failed of {})",
                    r.failed, r.total
                ),
                None::<std::io::Error>,
            ));
        }
        Ok(r.ok)
    }

    /// Fetch a device's recovery-authority anchor from the dedicated endpoint by genesis.
    ///
    /// Availability-only fetch + protobuf decode; it does NOT authenticate the anchor.
    /// The caller MUST verify it client-side via [`dsm::recovery::RecoveryAuthorityAnchor::verify`]
    /// using the device's genesis-authenticated signing pubkey (device-tree quorum) and
    /// the candidate authority pubkey carried by the recovery bundle (storage = availability;
    /// verification = client-side).
    pub async fn fetch_authority_anchor(
        genesis_id: &[u8; 32],
    ) -> Result<dsm::recovery::RecoveryAuthorityAnchor, DsmError> {
        let path = Self::authority_anchor_endpoint_path(genesis_id);
        let bytes = crate::sdk::storage_io::get_from_any_node_path(&path).await?;
        dsm::recovery::RecoveryAuthorityAnchor::from_bytes(&bytes)
    }

    /// Fetch a device's recovery-authority anchor AND authenticate it end-to-end:
    /// its genesis-binding signature is verified against the device's
    /// genesis-authenticated signing pubkey (device-tree quorum), and
    /// `candidate_authority_pubkey` is bound to the anchored commitment. On success the
    /// caller may treat `candidate_authority_pubkey` as the genesis-anchored recovery
    /// authority for `(genesis_id, device_id)` and use it to verify tombstone/succession.
    ///
    /// `candidate_authority_pubkey` comes from the recovery bundle (which carries
    /// `K_A_pub` alongside the tombstone/succession); this checks `H(it)` equals the
    /// anchored commitment, the device signing key signed the anchor, and `K_A` proved
    /// possession. Fail-closed: any fetch, quorum, genesis-mismatch, or verify failure
    /// returns an error and yields NO authority.
    pub async fn fetch_and_verify_authority_anchor(
        genesis_id: &[u8; 32],
        device_id: &[u8; 32],
        candidate_authority_pubkey: &[u8],
    ) -> Result<dsm::recovery::RecoveryAuthorityAnchor, DsmError> {
        let anchor = Self::fetch_authority_anchor(genesis_id).await?;

        // Genesis-authenticated device signing pubkey via the device-tree quorum.
        let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
            .await
            .map_err(|e| {
                DsmError::storage(
                    format!("load storage node config: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        let qid = crate::handlers::app_router_impl::fetch_quorum_device_identity(
            &config.node_urls,
            *device_id,
        )
        .await
        .map_err(|e| {
            DsmError::verification(format!(
                "authority anchor: device identity quorum failed: {e}"
            ))
        })?;
        if &qid.genesis_hash != genesis_id {
            return Err(DsmError::verification(
                "authority anchor: quorum device identity genesis_hash != genesis under recovery",
            ));
        }

        anchor.verify(
            genesis_id,
            device_id,
            &qid.public_key,
            candidate_authority_pubkey,
        )?;
        Ok(anchor)
    }

    /// Endpoint path for a device's append-only PDSMT head chain (R4 layer 1).
    /// Device-keyed (the PDSMT is device-scoped). Base32 Crockford; no leading slash.
    pub fn pdsmt_head_chain_endpoint_path(device_id: &[u8; 32]) -> String {
        format!(
            "api/v2/tips/{}/head-chain",
            crate::util::text_id::encode_base32_crockford(device_id),
        )
    }

    /// Publish a PDSMT head to the append-only chain on every node. Returns the
    /// accepted-node count. A 409 from any node means the head does not link the current
    /// chain tip (fork/gap/stale) — this errors so the caller re-fetches the tip and
    /// re-chains rather than treating it as published.
    pub async fn publish_pdsmt_head(
        head: &dsm::recovery::PostedPdsmtHead,
    ) -> Result<usize, DsmError> {
        let path = Self::pdsmt_head_chain_endpoint_path(&head.device_id);
        let r = crate::sdk::storage_io::put_to_all_nodes_path(&path, &head.to_bytes()).await?;
        if r.conflict > 0 {
            return Err(DsmError::InvalidState(format!(
                "pdsmt head publish: {}/{} nodes report a chain conflict (head does not link the \
                 current tip); re-fetch the tip and re-chain",
                r.conflict, r.total
            )));
        }
        if r.ok == 0 {
            return Err(DsmError::storage(
                format!(
                    "pdsmt head publish: no node accepted the write ({} failed of {})",
                    r.failed, r.total
                ),
                None::<std::io::Error>,
            ));
        }
        Ok(r.ok)
    }

    /// Fetch the latest PDSMT head for a device (availability-only fetch + decode).
    /// The caller MUST verify it client-side (`PostedPdsmtHead::verify` + authority
    /// chained to G via the anchor + device ∈ genesis device tree).
    pub async fn fetch_pdsmt_head_latest(
        device_id: &[u8; 32],
    ) -> Result<dsm::recovery::PostedPdsmtHead, DsmError> {
        let path = Self::pdsmt_head_chain_endpoint_path(device_id);
        let bytes = crate::sdk::storage_io::get_from_any_node_path(&path).await?;
        dsm::recovery::PostedPdsmtHead::from_bytes(&bytes)
    }

    /// Fetch a specific PDSMT head by chain position (e.g. the head at/before the
    /// recovery snapshot). Availability-only fetch + decode; caller verifies.
    pub async fn fetch_pdsmt_head_at(
        device_id: &[u8; 32],
        head_number: u64,
    ) -> Result<dsm::recovery::PostedPdsmtHead, DsmError> {
        let path = format!(
            "{}/{}",
            Self::pdsmt_head_chain_endpoint_path(device_id),
            head_number
        );
        let bytes = crate::sdk::storage_io::get_from_any_node_path(&path).await?;
        dsm::recovery::PostedPdsmtHead::from_bytes(&bytes)
    }

    /// Storage key for a device's posted PDSMT leaf set at a given head number (generic
    /// content-addressed object store; availability-only — the head's signed
    /// `leaf_index_root` is the authority). Base32 Crockford (no hex).
    pub fn pdsmt_leaves_storage_key(
        genesis_id: &[u8; 32],
        device_id: &[u8; 32],
        head_number: u64,
    ) -> String {
        format!(
            "recovery/pdsmt-leaves/v1/{}/{}/{}",
            crate::util::text_id::encode_base32_crockford(genesis_id),
            crate::util::text_id::encode_base32_crockford(device_id),
            head_number,
        )
    }

    /// Build THIS device's PDSMT snapshot (head + enumerable leaf set) from the live
    /// device head, chain it onto the append-only head chain, and publish both: the leaf
    /// set to the generic object store (availability) and the signed head to the
    /// head-chain endpoint (append-only, R4 layer 1). Returns the accepted-node count for
    /// the head. Fail-closed: requires identity, a cached `K_A`, and a live device head;
    /// a head-chain conflict errors (re-fetch the tip and re-chain).
    pub async fn build_and_publish_pdsmt_head() -> Result<usize, DsmError> {
        let device_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;
        let device_state = crate::storage::client_db::load_bcr_device_head(&device_id)
            .map_err(|e| {
                DsmError::storage(format!("load device head: {e}"), None::<std::io::Error>)
            })?
            .ok_or_else(|| {
                DsmError::InvalidState(
                    "build_and_publish_pdsmt_head: no device head to publish".into(),
                )
            })?;

        let (authority_pk, authority_sk) =
            Self::get_cached_authority_keypair().ok_or_else(|| {
                DsmError::InvalidState(
                "build_and_publish_pdsmt_head: no cached recovery-authority keypair (cache the \
                 mnemonic first)"
                    .into(),
            )
            })?;

        // Chain position: extend the latest valid head, or start the genesis head.
        let (parent_head_hash, head_number) = match Self::fetch_pdsmt_head_latest(&device_id).await
        {
            Ok(prev) => (prev.head_hash(), prev.head_number.saturating_add(1)),
            Err(_) => (dsm::recovery::GENESIS_PARENT_HEAD_HASH, 0),
        };

        let cp_genesis = |cp: &[u8; 32]| -> Option<[u8; 32]> {
            crate::storage::client_db::get_contact_by_device_id(cp)
                .ok()
                .flatten()
                .and_then(|c| <[u8; 32]>::try_from(c.genesis_hash.as_slice()).ok())
        };

        let (head, leaves) = dsm::recovery::build_pdsmt_snapshot(
            &device_state,
            &authority_pk,
            &authority_sk,
            parent_head_hash,
            head_number,
            cp_genesis,
        )?;

        // Publish the enumerable leaf set FIRST (availability), so the head's committed
        // leaf_index_root is backed by fetchable leaves once the head is accepted.
        let leaves_key = Self::pdsmt_leaves_storage_key(&head.genesis_id, &device_id, head_number);
        crate::sdk::storage_io::put_bytes(&leaves_key, &dsm::recovery::encode_leaf_set(&leaves))
            .await?;

        // Publish the signed head onto the append-only chain (errors on chain conflict).
        Self::publish_pdsmt_head(&head).await
    }

    /// Fetch a device's posted PDSMT leaf set at a head number (availability-only fetch +
    /// decode). The caller MUST verify each leaf against the head's signed
    /// `leaf_index_root` via `verify_head_with_leaves` (storage = availability).
    pub async fn fetch_pdsmt_leaves(
        genesis_id: &[u8; 32],
        device_id: &[u8; 32],
        head_number: u64,
    ) -> Result<Vec<dsm::recovery::PostedPdsmtLeafRecord>, DsmError> {
        let key = Self::pdsmt_leaves_storage_key(genesis_id, device_id, head_number);
        let bytes = crate::sdk::storage_io::get_bytes(&key).await?;
        dsm::recovery::decode_leaf_set(&bytes)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Relationship-state evidence postings (spec §0.5 Phase D prerequisite).
    //
    // PDSMT heads/leaves prove "what the current tip IS" + value-capability. These objects
    // prove HOW a relationship reached its tip (old-chain ancestry h_cap ->* T_old_current)
    // and that the successor relationship was BORN binding the carry-forward commitment.
    // Availability-only + content-addressed + SELF-VERIFIED on fetch. Storage attests
    // NOTHING; a missing/invalid/wrong-key object FAILS CLOSED at the verifier — it can only
    // BLOCK recovery, never advance it. The orchestrator (Phase D step 2) additionally binds
    // current_tip to C's genesis-authenticated PDSMT head and floor_tip to the capsule.
    // ─────────────────────────────────────────────────────────────────────────

    /// Storage key for a posted ancestry segment, keyed by the device-pair `rel_key`
    /// (symmetric — both parties derive the same key). Base32 Crockford; no hex.
    pub fn rel_chain_segment_storage_key(rel_key: &[u8; 32]) -> String {
        format!(
            "recovery/rel-segment/v1/{}",
            crate::util::text_id::encode_base32_crockford(rel_key),
        )
    }

    /// Storage key for the new `(A_new,C)` establishment receipt, keyed by `new_rel_key`.
    pub fn establishment_receipt_storage_key(new_rel_key: &[u8; 32]) -> String {
        format!(
            "recovery/establish-receipt/v1/{}",
            crate::util::text_id::encode_base32_crockford(new_rel_key),
        )
    }

    /// Assemble the forward-ancestry segment for `rel_key` from this device's BCR chain-state
    /// archive, covering `floor_tip` (EXCLUSIVE) -> `current_tip` (INCLUSIVE). Walks by
    /// `embedded_parent` adjacency — NOT archive insertion order — and FAILS CLOSED on a gap
    /// (no archived child toward the target) or a fork (multiple distinct children at one
    /// parent → ambiguous path). The returned segment is self-verified before return.
    pub fn build_rel_chain_segment(
        owner_device_id: &[u8; 32],
        rel_key: &[u8; 32],
        floor_tip: &[u8; 32],
        current_tip: &[u8; 32],
    ) -> Result<dsm::recovery::RelationshipChainSegment, DsmError> {
        // No-divergence common case: the floor IS the current tip → empty segment.
        if floor_tip == current_tip {
            let seg = dsm::recovery::RelationshipChainSegment {
                rel_key: *rel_key,
                floor_tip: *floor_tip,
                current_tip: *current_tip,
                states: Vec::new(),
            };
            seg.verify()?;
            return Ok(seg);
        }

        let all = crate::storage::client_db::get_bcr_chain_states_for_rel(owner_device_id, rel_key)
            .map_err(|e| {
                DsmError::storage(
                    format!("build_rel_chain_segment: load archive: {e}"),
                    None::<std::io::Error>,
                )
            })?;

        // Index by embedded_parent so the walk follows hash adjacency, not insertion order.
        let mut by_parent: HashMap<
            [u8; 32],
            Vec<dsm::types::device_state::RelationshipChainState>,
        > = HashMap::new();
        for s in all {
            by_parent.entry(s.embedded_parent).or_default().push(s);
        }
        let archive_len: usize = by_parent.values().map(|v| v.len()).sum();

        let mut states = Vec::new();
        let mut cursor = *floor_tip;
        loop {
            let children = by_parent.get(&cursor).ok_or_else(|| {
                DsmError::verification(
                    "build_rel_chain_segment: gap — no archived child of the current tip toward \
                     current_tip (incomplete history; fail closed)",
                )
            })?;
            // A unique forward path is required; distinct child tips at one parent = fork.
            let mut distinct: Vec<[u8; 32]> =
                children.iter().map(|s| s.compute_chain_tip()).collect();
            distinct.sort_unstable();
            distinct.dedup();
            if distinct.len() != 1 {
                return Err(DsmError::verification(
                    "build_rel_chain_segment: fork in archive — ambiguous ancestry path (fail \
                     closed)",
                ));
            }
            let s = children[0].clone();
            let tip = s.compute_chain_tip();
            states.push(s);
            if &tip == current_tip {
                break;
            }
            cursor = tip;
            // Runaway guard: a valid acyclic path cannot exceed the archive size.
            if states.len() > archive_len {
                return Err(DsmError::verification(
                    "build_rel_chain_segment: path exceeds archive size (cycle?) — fail closed",
                ));
            }
        }

        let seg = dsm::recovery::RelationshipChainSegment {
            rel_key: *rel_key,
            floor_tip: *floor_tip,
            current_tip: *current_tip,
            states,
        };
        seg.verify()?; // canonical re-check (rel_key uniform + adjacency + reaches current_tip)
        Ok(seg)
    }

    /// Publish a relationship-chain ancestry segment (availability-only). Self-verifies
    /// FIRST — an object that won't verify is never posted.
    pub async fn publish_rel_chain_segment(
        seg: &dsm::recovery::RelationshipChainSegment,
    ) -> Result<(), DsmError> {
        seg.verify()?;
        let key = Self::rel_chain_segment_storage_key(&seg.rel_key);
        crate::sdk::storage_io::put_bytes(&key, &seg.to_bytes()).await?;
        Ok(())
    }

    /// Fetch + VERIFY a counterparty's ancestry segment for `rel_key`. Fail-closed: a
    /// missing, undecodable, wrong-key, or non-self-consistent segment errors.
    pub async fn fetch_rel_chain_segment(
        rel_key: &[u8; 32],
    ) -> Result<dsm::recovery::RelationshipChainSegment, DsmError> {
        let key = Self::rel_chain_segment_storage_key(rel_key);
        let bytes = crate::sdk::storage_io::get_bytes(&key).await?;
        let seg = dsm::recovery::RelationshipChainSegment::from_bytes(&bytes)?;
        if &seg.rel_key != rel_key {
            return Err(DsmError::verification(
                "fetch_rel_chain_segment: fetched rel_key != requested",
            ));
        }
        seg.verify()?;
        Ok(seg)
    }

    /// Publish the new `(A_new,C)` establishment receipt (availability-only). Self-verifies
    /// FIRST against `(A_new, C)` — never posts an object that won't verify.
    pub async fn publish_establishment_receipt(
        receipt: &dsm::recovery::RecoveryEstablishmentReceipt,
        a_new: &[u8; 32],
        c: &[u8; 32],
    ) -> Result<(), DsmError> {
        receipt.verify(a_new, c)?;
        let key = Self::establishment_receipt_storage_key(&receipt.rel_key);
        crate::sdk::storage_io::put_bytes(&key, &receipt.to_bytes()).await?;
        Ok(())
    }

    /// Fetch + VERIFY the new `(A_new,C)` establishment receipt for `new_rel_key`.
    /// Fail-closed: a missing, undecodable, wrong-key, or non-first-state receipt errors.
    pub async fn fetch_establishment_receipt(
        new_rel_key: &[u8; 32],
        a_new: &[u8; 32],
        c: &[u8; 32],
    ) -> Result<dsm::recovery::RecoveryEstablishmentReceipt, DsmError> {
        let key = Self::establishment_receipt_storage_key(new_rel_key);
        let bytes = crate::sdk::storage_io::get_bytes(&key).await?;
        let receipt = dsm::recovery::RecoveryEstablishmentReceipt::from_bytes(&bytes)?;
        if &receipt.rel_key != new_rel_key {
            return Err(DsmError::verification(
                "fetch_establishment_receipt: fetched rel_key != requested",
            ));
        }
        receipt.verify(a_new, c)?;
        Ok(receipt)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // dBTC vault index (spec §0.4 P5 — dBTC enumeration). The healthy device posts a
    // K_A-signed list of its dBTC vault ids; a recovering device fetches it as the candidate
    // set for reconcile_dbtc_asset. Availability-only; verified client-side. Enumeration
    // completeness is not a safety property (per-vault Bitcoin backing is the unlock gate).
    // ─────────────────────────────────────────────────────────────────────────

    /// Storage key for a device's posted dBTC vault index (Base32 Crockford; no hex).
    pub fn dbtc_vault_index_storage_key(genesis_id: &[u8; 32], device_id: &[u8; 32]) -> String {
        format!(
            "recovery/dbtc-vault-index/v1/{}/{}",
            crate::util::text_id::encode_base32_crockford(genesis_id),
            crate::util::text_id::encode_base32_crockford(device_id),
        )
    }

    /// Build (from THIS device's local vault store) + sign + publish the dBTC vault index.
    /// Fail-closed: requires identity + a cached `K_A`. Returns the vault-id count posted.
    pub async fn publish_dbtc_vault_index() -> Result<usize, DsmError> {
        let device_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;
        let genesis_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_genesis_hash(),
            "genesis_hash",
        )?;
        let (authority_pk, authority_sk) =
            Self::get_cached_authority_keypair().ok_or_else(|| {
                DsmError::InvalidState(
                    "publish_dbtc_vault_index: no cached recovery-authority keypair".into(),
                )
            })?;
        let vault_ids = crate::storage::client_db::list_all_vault_ids().map_err(|e| {
            DsmError::storage(format!("list vault ids: {e}"), None::<std::io::Error>)
        })?;
        let n = vault_ids.len();
        let index = dsm::recovery::build_dbtc_vault_index(
            genesis_id,
            device_id,
            vault_ids,
            &authority_pk,
            &authority_sk,
        )?;
        let key = Self::dbtc_vault_index_storage_key(&genesis_id, &device_id);
        crate::sdk::storage_io::put_bytes(&key, &index.to_bytes()).await?;
        Ok(n)
    }

    /// Fetch + VERIFY a device's dBTC vault index against the genesis-anchored authority
    /// commit. Fail-closed: missing/undecodable/unverifiable → error (dBTC stays locked).
    pub async fn fetch_dbtc_vault_index(
        genesis_id: &[u8; 32],
        device_id: &[u8; 32],
        anchored_authority_commit: &[u8; 32],
    ) -> Result<dsm::recovery::PostedDbtcVaultIndex, DsmError> {
        let key = Self::dbtc_vault_index_storage_key(genesis_id, device_id);
        let bytes = crate::sdk::storage_io::get_bytes(&key).await?;
        let index = dsm::recovery::PostedDbtcVaultIndex::from_bytes(&bytes)?;
        if &index.genesis_id != genesis_id || &index.device_id != device_id {
            return Err(DsmError::verification(
                "fetch_dbtc_vault_index: fetched index genesis/device != requested",
            ));
        }
        index.verify(anchored_authority_commit)?;
        Ok(index)
    }

    /// Auto-source candidate dBTC vault ids for recovery: fetch + verify the posted vault
    /// index for A_old (the recovered identity's lost device, from the staged capsule), using
    /// this identity's genesis-anchored `K_A`. Fail-closed: any missing/unverifiable piece
    /// errors (the caller then leaves dBTC LockedRecovery / reports awaiting-enumeration).
    pub async fn auto_dbtc_vault_candidates() -> Result<Vec<String>, DsmError> {
        let a_old_v =
            crate::storage::client_db::recovery::get_recovery_pref("capsule_source_device_id")
                .map_err(|e| {
                    DsmError::storage(format!("read capsule source: {e}"), None::<std::io::Error>)
                })?
                .ok_or_else(|| {
                    DsmError::InvalidState(
                        "auto_dbtc_vault_candidates: no staged capsule source".into(),
                    )
                })?;
        let a_old = <[u8; 32]>::try_from(a_old_v.as_slice()).map_err(|_| {
            DsmError::verification("auto_dbtc_vault_candidates: capsule source not 32 bytes")
        })?;
        let genesis = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_genesis_hash(),
            "genesis_hash",
        )?;
        let (ka_pub, _) = Self::get_cached_authority_keypair().ok_or_else(|| {
            DsmError::InvalidState("auto_dbtc_vault_candidates: no cached K_A".into())
        })?;
        // Genesis-anchor A_old's authority (this identity's K_A) before trusting its index.
        Self::fetch_and_verify_authority_anchor(&genesis, &a_old, &ka_pub).await?;
        let anchored = dsm::recovery::compute_authority_pubkey_commit(&ka_pub);
        let index = Self::fetch_dbtc_vault_index(&genesis, &a_old, &anchored).await?;
        Ok(index.vault_ids)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Producer endpoints (spec §0.5 Phase D step 2 — the bilateral re-establish side).
    //
    // These are the deterministic posting endpoints the interactive bilateral re-establish
    // transport calls; the transport (exchanging h_cap + co-signing the new (A_new,C) first
    // state) is the separate bilateral machinery. Both endpoints self-verify before posting.
    // ─────────────────────────────────────────────────────────────────────────

    /// COUNTERPARTY side: build (from THIS device's own BCR archive) and publish the
    /// `(recovering_device, self)` ancestry segment from the recovering device's capsule floor
    /// `h_cap` to this device's current tip. Called by a counterparty C once it learns the
    /// recovering device's per-relationship floor (conveyed by the re-establish handshake).
    /// Returns the segment content id. Fail-closed: no such relationship, or a gap/fork in the
    /// archive between `h_cap` and the current tip, aborts (see [`Self::build_rel_chain_segment`]).
    pub async fn publish_recovery_ancestry_segment(
        recovering_device_id: &[u8; 32],
        h_cap: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        let self_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;
        let old_rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            recovering_device_id,
            &self_id,
        );
        let head = crate::storage::client_db::load_bcr_device_head(&self_id)
            .map_err(|e| {
                DsmError::storage(format!("load device head: {e}"), None::<std::io::Error>)
            })?
            .ok_or_else(|| {
                DsmError::InvalidState(
                    "publish_recovery_ancestry_segment: no device head for this device".into(),
                )
            })?;
        let current_tip = head
            .rel_chain_tip(&old_rel_key)
            .map(|t| t.chain_tip)
            .ok_or_else(|| {
                DsmError::verification(
                    "publish_recovery_ancestry_segment: no relationship with the recovering device",
                )
            })?;
        let seg = Self::build_rel_chain_segment(&self_id, &old_rel_key, h_cap, &current_tip)?;
        Self::publish_rel_chain_segment(&seg).await?;
        Ok(seg.content_id())
    }

    /// RECOVERING (A_new) side: wrap a built `(A_new,C)` first establishment state (its
    /// `CreateRelationship` op binding the carry-forward commitment — produced by the
    /// bilateral establish flow) as a [`dsm::recovery::RecoveryEstablishmentReceipt`] and
    /// publish it. Returns the receipt content id. Self-verifies first (first-state, rel_key,
    /// op shape); the binding to C is enforced downstream by C's own posted leaf, so a
    /// structurally-valid receipt cannot bypass C's agreement.
    pub async fn publish_recovery_establishment(
        establishment_state: dsm::types::device_state::RelationshipChainState,
        counterparty_device_id: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        let a_new = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;
        let new_rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &a_new,
            counterparty_device_id,
        );
        let receipt = dsm::recovery::RecoveryEstablishmentReceipt {
            rel_key: new_rel_key,
            state: establishment_state,
        };
        Self::publish_establishment_receipt(&receipt, &a_new, counterparty_device_id).await?;
        Ok(receipt.content_id())
    }

    /// Derive a device-bound wrapping key from device_id + genesis_hash.
    /// Used to encrypt the recovery key before persisting to SQLite.
    fn device_wrapping_key() -> Result<[u8; 32], DsmError> {
        let device_id = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::InvalidState("Device ID not available".into()))?;
        let genesis_hash = crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();
        let mut hasher = dsm::crypto::blake3::Hasher::new_derive_key("DSM/recovery-persist\0");
        hasher.update(&device_id);
        hasher.update(&genesis_hash);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Encrypt the recovery key with a device-bound wrapping key and store in SQLite.
    /// Format: nonce (24 bytes) || ciphertext+tag.
    fn persist_recovery_key(key: &[u8; 32]) -> Result<(), DsmError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::Aead;

        let wrapping_key = Self::device_wrapping_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|e| DsmError::InvalidState(format!("wrapping cipher init: {e}")))?;

        // Nonce derived from wrapping key AND plaintext — safe even if the
        // mnemonic (and therefore key) changes between persist calls.
        let nonce_hash = {
            let mut h = dsm::crypto::blake3::Hasher::new_derive_key("DSM/recovery-persist-nonce\0");
            h.update(&wrapping_key);
            h.update(key);
            h.finalize()
        };
        let nonce = XNonce::from_slice(&nonce_hash.as_bytes()[..24]);

        let ciphertext = cipher
            .encrypt(nonce, key.as_ref())
            .map_err(|e| DsmError::InvalidState(format!("recovery key encryption: {e}")))?;

        // Store nonce || ciphertext so decrypt doesn't need to re-derive from plaintext.
        let mut blob = Vec::with_capacity(24 + ciphertext.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ciphertext);

        crate::storage::client_db::recovery::store_encrypted_recovery_key(&blob)
            .map_err(|e| DsmError::InvalidState(format!("persist encrypted key: {e}")))?;

        log::info!(
            "[RECOVERY_SDK] Recovery key persisted (encrypted, {} bytes)",
            blob.len()
        );
        Ok(())
    }

    /// Load the persisted encrypted recovery key, decrypt it, and cache in memory.
    /// Returns Ok(true) if loaded, Ok(false) if no persisted key exists.
    fn load_persisted_recovery_key() -> Result<bool, DsmError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::Aead;

        let blob = match crate::storage::client_db::recovery::load_encrypted_recovery_key() {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(false),
            Err(e) => {
                return Err(DsmError::InvalidState(format!(
                    "load encrypted recovery key: {e}"
                )))
            }
        };

        if blob.len() < 24 {
            return Err(DsmError::InvalidState(format!(
                "persisted key blob too short: {} bytes",
                blob.len()
            )));
        }

        let nonce = XNonce::from_slice(&blob[..24]);
        let ciphertext = &blob[24..];

        let wrapping_key = Self::device_wrapping_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|e| DsmError::InvalidState(format!("wrapping cipher init: {e}")))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| DsmError::InvalidState(format!("recovery key decryption: {e}")))?;

        if plaintext.len() != 32 {
            return Err(DsmError::InvalidState(format!(
                "decrypted key wrong length: {} (expected 32)",
                plaintext.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        {
            let mut guard = RECOVERY_KEY
                .lock()
                .map_err(|_| DsmError::InvalidState("Recovery key mutex poisoned".into()))?;
            *guard = Some(key);
        }
        Ok(true)
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

    /// Decode this device's persisted recovery state into a [`RecoveryActivationContext`]
    /// (the integration seam between the recovery pipeline and the activation orchestration).
    ///
    /// Reads the staged capsule prefs (A_old `source_device_id`, SMT root, rollup hash), the
    /// per-counterparty capsule floor (`get_recovered_chain_tips`), the propagated tombstone
    /// hash, and AppState identity (genesis + this device = A_new). The seal-context fields
    /// are derived deterministically: `tombstone_proposal_digest` = the propagated tombstone
    /// hash; `recovery_intent_digest` = a domain-separated commit over
    /// `(A_old, A_new, genesis, tombstone_hash)`; `final_*` from A_new's resumed device head.
    ///
    /// `old_counter` is fixed at 0 to match [`execute_recovery_pipeline`]'s tombstone (so the
    /// tombstone re-created in [`Self::build_and_activate_recovery`] is byte-identical to the
    /// one counterparties already bound their carry-forward against — `create_tombstone` is
    /// deterministic). Fail-closed: missing capsule/identity state errors.
    pub fn build_activation_context_from_persisted() -> Result<RecoveryActivationContext, DsmError>
    {
        use std::collections::BTreeMap;

        fn pref32(key: &str) -> Result<[u8; 32], DsmError> {
            let v = crate::storage::client_db::recovery::get_recovery_pref(key)
                .map_err(|e| DsmError::storage(format!("read {key}: {e}"), None::<std::io::Error>))?
                .ok_or_else(|| {
                    DsmError::InvalidState(format!(
                        "build_activation_context: missing persisted `{key}` (stage a capsule + \
                         run the recovery pipeline first)"
                    ))
                })?;
            <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                DsmError::verification(format!("build_activation_context: `{key}` is not 32 bytes"))
            })
        }

        let a_old = pref32("capsule_source_device_id")?;
        let old_smt_root = pref32("capsule_smt_root")?;
        let old_rollup_hash = pref32("capsule_rollup_hash")?;

        let genesis_id = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_genesis_hash(),
            "genesis_hash",
        )?;
        let a_new = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;

        let tombstone_hash = {
            let v = crate::storage::client_db::recovery::get_tombstone_hash()
                .map_err(|e| {
                    DsmError::storage(format!("read tombstone_hash: {e}"), None::<std::io::Error>)
                })?
                .ok_or_else(|| {
                    DsmError::InvalidState(
                        "build_activation_context: no propagated tombstone (run the recovery \
                         pipeline first)"
                            .into(),
                    )
                })?;
            <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                DsmError::verification("build_activation_context: tombstone_hash is not 32 bytes")
            })?
        };

        // Per-counterparty capsule floor: device_id -> sealed (A_old,C) tip (h_cap).
        let capsule_floor: BTreeMap<[u8; 32], [u8; 32]> =
            crate::storage::client_db::recovery::get_recovered_chain_tips()
                .map_err(|e| {
                    DsmError::storage(
                        format!("read recovered chain tips: {e}"),
                        None::<std::io::Error>,
                    )
                })?
                .into_iter()
                .map(|t| (t.device_id, t.head_hash))
                .collect();

        // A_new's resumed device head fixes the final per-device SMT root; the recovered
        // rollup is the capsule rollup. (These are seal bindings, not validated invariants.)
        let final_per_device_smt_root = crate::storage::client_db::load_bcr_device_head(&a_new)
            .ok()
            .flatten()
            .map(|ds| ds.root())
            .unwrap_or(old_smt_root);

        // Deterministic recovery-intent commitment over the recovery's fixed endpoints.
        let recovery_intent_digest = {
            let mut h = dsm::crypto::blake3::Hasher::new_derive_key("DSM/recovery-intent\0");
            h.update(&a_old);
            h.update(&a_new);
            h.update(&genesis_id);
            h.update(&tombstone_hash);
            *h.finalize().as_bytes()
        };

        Ok(RecoveryActivationContext {
            genesis_id,
            a_old,
            a_new,
            capsule_floor,
            old_smt_root,
            old_counter: 0,
            old_rollup_hash,
            recovery_intent_digest,
            tombstone_proposal_digest: tombstone_hash,
            final_per_device_smt_root,
            final_receipt_roll: old_rollup_hash,
        })
    }

    /// Re-derive A_new's identity-level tombstone/succession (A's `K_A`) proving A_new
    /// succeeds A_old, from the persisted recovery context. SPHINCS+ signing is deterministic,
    /// so the re-derived receipts are byte-identical to the ones the recovery pipeline
    /// propagated (their hashes match the persisted `tombstone_proposal_digest`); reconstructing
    /// avoids depending on partial receipt persistence. The device-id string MUST match dsm's
    /// `encode_crockford` (the verifiers compare `tombstone.device_id == encode_crockford(a_old)`);
    /// the SDK encoder is the documented byte-identical twin. Returns `(K_A_pub, tombstone,
    /// succession)`. Fail-closed: requires a cached recovery-authority keypair.
    fn recreate_identity_succession(
        ctx: &RecoveryActivationContext,
    ) -> Result<
        (
            Vec<u8>,
            dsm::recovery::TombstoneReceipt,
            dsm::recovery::SuccessionReceipt,
        ),
        DsmError,
    > {
        let (ka_pub, ka_sk) = Self::get_cached_authority_keypair().ok_or_else(|| {
            DsmError::InvalidState(
                "recovery: no cached recovery-authority keypair (cache the mnemonic first)".into(),
            )
        })?;
        let a_old_str = crate::util::text_id::encode_base32_crockford(&ctx.a_old);
        let tombstone = create_tombstone_receipt(
            &ctx.old_smt_root,
            ctx.old_counter,
            &ctx.old_rollup_hash,
            &a_old_str,
            &ka_sk,
        )?;
        let succession = create_succession_receipt(
            &tombstone.tombstone_hash,
            ctx.a_new.as_ref(),
            &a_old_str,
            &ka_sk,
        )?;
        Ok((ka_pub, tombstone, succession))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bilateral re-establish (spec §0.5 — the interactive successor-channel transport).
    //
    // After identity recovery, A_new must re-establish each prior `(A_old,C)` relationship as a
    // NEW `(A_new,C)` channel "born as a successor": its first state binds the carry-forward
    // commitment over C's REAL `(A_old,C)` frontier. The transport reuses the ordinary bilateral
    // 3-phase commit (no new BLE message types): the recovery-establish `CreateRelationship` op
    // rides the prepare, its `commitment` is the carry-forward, and `proof` conveys the capsule
    // floor `h_cap`. A_new builds the op (`begin_recovery_reestablish`); C MUST gate co-signing
    // on `verify_incoming_recovery_reestablish`. The pre-co-sign authorization (authority pubkey
    // + tombstone/succession) is posted as a `RecoverySuccessionProof` and fetched by C.
    // ─────────────────────────────────────────────────────────────────────────

    /// Storage key for A_new's posted recovery succession proof (Base32 Crockford; no hex).
    /// Keyed by `(genesis_under_recovery, a_new)` — the recovering identity's genesis (shared
    /// with A_old) and the successor device.
    pub fn recovery_succession_proof_storage_key(
        genesis_id: &[u8; 32],
        a_new: &[u8; 32],
    ) -> String {
        format!(
            "recovery/succession-proof/v1/{}/{}",
            crate::util::text_id::encode_base32_crockford(genesis_id),
            crate::util::text_id::encode_base32_crockford(a_new),
        )
    }

    /// A_new posts its [`dsm::recovery::RecoverySuccessionProof`] (authority pubkey +
    /// tombstone/succession) so a counterparty can run its accept-guard before co-signing.
    /// Availability-only; the receiver genesis-anchors the authority + verifies the receipts.
    pub async fn publish_recovery_succession_proof() -> Result<(), DsmError> {
        let ctx = Self::build_activation_context_from_persisted()?;
        let (ka_pub, tombstone, succession) = Self::recreate_identity_succession(&ctx)?;
        let proof = dsm::recovery::RecoverySuccessionProof {
            authority_pubkey: ka_pub,
            tombstone,
            succession,
        };
        let key = Self::recovery_succession_proof_storage_key(&ctx.genesis_id, &ctx.a_new);
        crate::sdk::storage_io::put_bytes(&key, &proof.to_bytes()).await?;
        Ok(())
    }

    /// Fetch + decode A_new's posted recovery succession proof. Fail-closed decode only; the
    /// CALLER MUST genesis-anchor `authority_pubkey` and run the accept-guard before trusting it.
    pub async fn fetch_recovery_succession_proof(
        genesis_id: &[u8; 32],
        a_new: &[u8; 32],
    ) -> Result<dsm::recovery::RecoverySuccessionProof, DsmError> {
        let key = Self::recovery_succession_proof_storage_key(genesis_id, a_new);
        let bytes = crate::sdk::storage_io::get_bytes(&key).await?;
        dsm::recovery::RecoverySuccessionProof::from_bytes(&bytes)
    }

    /// A_new side: build the recovery-establish `CreateRelationship` operation for counterparty
    /// `c`, to be carried by the ordinary bilateral prepare. Computes the carry-forward
    /// commitment over C's REAL `(A_old,C)` frontier and conveys the capsule floor `h_cap` in
    /// the op's `proof`; also posts the [`dsm::recovery::RecoverySuccessionProof`] C needs.
    ///
    /// `t_old_current` is sourced from C's posted PDSMT leaf for the `(A_old,C)` relationship.
    /// If C has advanced that relationship since it last posted, the leaf is stale and C's
    /// accept-guard will reject the (mismatched) carry-forward — fail-closed; retry once C
    /// re-posts. Fail-closed: A had no sealed relationship with `c` (no capsule floor), or C
    /// has no posted `(A_old,C)` leaf, aborts.
    pub async fn begin_recovery_reestablish(
        c: &[u8; 32],
    ) -> Result<dsm::types::operations::Operation, DsmError> {
        let ctx = Self::build_activation_context_from_persisted()?;
        let h_cap = ctx.capsule_floor.get(c).copied().ok_or_else(|| {
            DsmError::InvalidState(
                "begin_recovery_reestablish: no capsule floor for this counterparty (A had no \
                 sealed (A_old,C) relationship)"
                    .into(),
            )
        })?;

        // Post the pre-co-sign succession proof so C can run its accept-guard.
        Self::publish_recovery_succession_proof().await?;

        let old_rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&ctx.a_old, c);
        let new_rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&ctx.a_new, c);

        // C's current (A_old,C) tip from its posted PDSMT leaf.
        let c_head = Self::fetch_pdsmt_head_latest(c).await?;
        let c_leaves = Self::fetch_pdsmt_leaves(&c_head.genesis_id, c, c_head.head_number).await?;
        let t_old_current = c_leaves
            .iter()
            .find(|l| l.rel_key == old_rel_key && l.counterparty_device_id == ctx.a_old)
            .map(|l| l.current_tip)
            .ok_or_else(|| {
                DsmError::verification(
                    "begin_recovery_reestablish: counterparty has no posted (A_old,C) leaf \
                     (cannot determine its current tip; ensure C has posted its PDSMT)",
                )
            })?;

        let (_ka_pub, tombstone, succession) = Self::recreate_identity_succession(&ctx)?;
        let carry = dsm::recovery::compute_carry_forward_commitment(
            &old_rel_key,
            &new_rel_key,
            &h_cap,
            &t_old_current,
            &tombstone.tombstone_hash,
            &succession.succession_hash,
            &ctx.a_old,
            &ctx.a_new,
            c,
        );
        Ok(dsm::recovery::build_recovery_establishment_op(
            c, &carry, &h_cap,
        ))
    }

    /// C side: the accept-guard the bilateral handler MUST call before co-signing an incoming
    /// recovery-establish proposal from `a_new` (gate 1 of the two-gate model). Returns `Ok(())`
    /// only if C may co-sign; otherwise errors (fail-closed). It blocks a non-authority forger
    /// and blocks re-establishing onto a fabricated/stale frontier; it does NOT distinguish the
    /// owner from a mnemonic thief (gate 2 / P5 handles double-spend safety). See
    /// [`dsm::recovery::verify_recovery_reestablish_request`] for the exact security property.
    ///
    /// Gathers everything from authenticated sources: A_new's genesis + recovery authority from
    /// its posted, genesis-anchored PDSMT head; the [`dsm::recovery::RecoverySuccessionProof`]
    /// (bound to that same anchored authority); A_old from the tombstone; and C's own
    /// `(A_old,C)` frontier (ordered post-floor segment from its BCR archive). Then runs the
    /// pure [`dsm::recovery::verify_recovery_reestablish_request`].
    pub async fn verify_incoming_recovery_reestablish(
        op: &dsm::types::operations::Operation,
        a_new: &[u8; 32],
    ) -> Result<(), DsmError> {
        let h_cap = dsm::recovery::recovery_establishment_floor(op).ok_or_else(|| {
            DsmError::verification(
                "recovery reestablish: op carries no 32-byte capsule floor in its proof",
            )
        })?;
        let c_self = Self::require_self_id32(
            crate::sdk::app_state::AppState::get_device_id(),
            "device_id",
        )?;

        // A_new's genesis + recovery authority, from A_new's posted head (genesis-anchored).
        let a_new_head = Self::fetch_pdsmt_head_latest(a_new).await?;
        let a_new_genesis = a_new_head.genesis_id;
        Self::fetch_and_verify_authority_anchor(
            &a_new_genesis,
            a_new,
            &a_new_head.authority_pubkey,
        )
        .await?;

        // The pre-co-sign succession proof, bound to the SAME anchored authority.
        let proof = Self::fetch_recovery_succession_proof(&a_new_genesis, a_new).await?;
        if proof.authority_pubkey != a_new_head.authority_pubkey {
            return Err(DsmError::verification(
                "recovery reestablish: succession-proof authority != A_new's genesis-anchored \
                 head authority",
            ));
        }

        // A_old is the tombstoned predecessor (authenticated by the receipts under K_A).
        let a_old_v = crate::util::text_id::decode_base32_crockford(&proof.tombstone.device_id)
            .ok_or_else(|| {
                DsmError::verification(
                    "recovery reestablish: tombstone device_id is not Base32 Crockford",
                )
            })?;
        let a_old = <[u8; 32]>::try_from(a_old_v.as_slice()).map_err(|_| {
            DsmError::verification("recovery reestablish: tombstone device_id is not 32 bytes")
        })?;
        let old_rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&a_old, &c_self);

        // C's current (A_old,C) tip from its OWN device head; reject if no such relationship.
        let head = crate::storage::client_db::load_bcr_device_head(&c_self)
            .map_err(|e| {
                DsmError::storage(format!("load device head: {e}"), None::<std::io::Error>)
            })?
            .ok_or_else(|| {
                DsmError::InvalidState("recovery reestablish: no local device head".into())
            })?;
        let current_tip = head
            .rel_chain_tip(&old_rel_key)
            .map(|t| t.chain_tip)
            .ok_or_else(|| {
                DsmError::verification(
                    "recovery reestablish: C has no relationship with A_old (nothing to \
                     re-establish)",
                )
            })?;

        // Ordered post-floor (A_old,C) states from h_cap → current tip (fail-closed on gap/fork).
        let seg = Self::build_rel_chain_segment(&c_self, &old_rel_key, &h_cap, &current_tip)?;

        dsm::recovery::verify_recovery_reestablish_request(
            op,
            &a_old,
            a_new,
            &c_self,
            &proof.tombstone,
            &proof.succession,
            &proof.authority_pubkey,
            &h_cap,
            &seg.states,
        )
    }

    /// End-to-end recovery activation orchestration (spec §0.5 Phase D step 2).
    ///
    /// Fetches A_old's and every candidate counterparty's online-posted, genesis-authenticated
    /// state, assembles + verifies the per-counterparty cross-relationship succession evidence
    /// (via the pure [`dsm::recovery::assemble_recovery_activation`] core), and feeds the
    /// fail-closed [`Self::verify_and_record_activation`] chokepoint. It does NOT unlock
    /// anything — `verify_and_record_activation` still returns the disabled error until go-live.
    ///
    /// Session-specific inputs (the decrypted capsule's floor/frontier + the recovery intent
    /// and the recovered device's final state) are supplied via [`RecoveryActivationContext`];
    /// the route handler decodes the capsule and AppState identity into it. `K_A` must be cached.
    ///
    /// Fail-closed: a missing/unanchored counterparty, a gate member without posted evidence,
    /// or any verification failure aborts. Storage is availability-only; every authority is
    /// genesis-anchored client-side (A's via the chokepoint's anchor check; each C's via
    /// [`Self::fetch_and_verify_authority_anchor`]).
    pub async fn build_and_activate_recovery(
        ctx: &RecoveryActivationContext,
    ) -> Result<(), DsmError> {
        use std::collections::{BTreeMap, BTreeSet};

        // Identity-level tombstone/succession (A's K_A) proving A_new succeeds A_old.
        let (ka_pub, tombstone, succession) = Self::recreate_identity_succession(ctx)?;

        // A_old's posted head + leaves. A_old's recovery authority IS this identity's K_A
        // (per-identity, re-derived from the mnemonic) — the posted head must be signed by it.
        let a_old_head = Self::fetch_pdsmt_head_latest(&ctx.a_old).await?;
        if a_old_head.authority_pubkey != ka_pub {
            return Err(DsmError::verification(
                "build_and_activate_recovery: A_old head authority_pubkey != this identity's K_A",
            ));
        }
        let a_old_authority_commit = dsm::recovery::compute_authority_pubkey_commit(&ka_pub);
        let a_old_leaves =
            Self::fetch_pdsmt_leaves(&ctx.genesis_id, &ctx.a_old, a_old_head.head_number).await?;

        // Candidate counterparties: A_old's posted leaves ∪ the capsule's floor set.
        let mut candidates: BTreeSet<[u8; 32]> = a_old_leaves
            .iter()
            .map(|l| l.counterparty_device_id)
            .collect();
        candidates.extend(ctx.capsule_floor.keys().copied());

        // Per-C: fetch posted state, GENESIS-ANCHOR C's authority (pubkey carried in the head),
        // and bind the floor/segment/receipt. Skip a candidate missing any piece — the
        // assembler then FAILS CLOSED if that candidate is a gate member.
        let mut counterparties: BTreeMap<[u8; 32], dsm::recovery::CounterpartyRecoveryInput> =
            BTreeMap::new();
        for c in &candidates {
            let Some(h_cap) = ctx.capsule_floor.get(c).copied() else {
                log::debug!(
                    "[RECOVERY] candidate {} has no capsule floor; skipping",
                    crate::util::text_id::encode_base32_crockford(c)
                );
                continue;
            };
            let head = match Self::fetch_pdsmt_head_latest(c).await {
                Ok(h) => h,
                Err(e) => {
                    log::debug!("[RECOVERY] no posted head for a candidate: {e}; skipping");
                    continue;
                }
            };
            let c_genesis = head.genesis_id;
            // Genesis-anchor C's authority: binds H(head.authority_pubkey) to C's anchored
            // commit, quorum-verifies C ∈ c_genesis device tree, and checks c_genesis is real.
            if let Err(e) =
                Self::fetch_and_verify_authority_anchor(&c_genesis, c, &head.authority_pubkey).await
            {
                log::debug!(
                    "[RECOVERY] counterparty authority not genesis-anchored: {e}; skipping"
                );
                continue;
            }
            let authority_commit =
                dsm::recovery::compute_authority_pubkey_commit(&head.authority_pubkey);
            let leaves = match Self::fetch_pdsmt_leaves(&c_genesis, c, head.head_number).await {
                Ok(l) => l,
                Err(e) => {
                    log::debug!("[RECOVERY] no posted leaves for a counterparty: {e}; skipping");
                    continue;
                }
            };
            let old_rel_key =
                dsm::core::bilateral_transaction_manager::compute_smt_key(&ctx.a_old, c);
            let new_rel_key =
                dsm::core::bilateral_transaction_manager::compute_smt_key(&ctx.a_new, c);
            let old_segment = match Self::fetch_rel_chain_segment(&old_rel_key).await {
                Ok(s) => s,
                Err(e) => {
                    log::debug!("[RECOVERY] no ancestry segment for a counterparty: {e}; skipping");
                    continue;
                }
            };
            let establishment =
                match Self::fetch_establishment_receipt(&new_rel_key, &ctx.a_new, c).await {
                    Ok(r) => r,
                    Err(e) => {
                        log::debug!(
                            "[RECOVERY] no establishment receipt for a counterparty: {e}; skipping"
                        );
                        continue;
                    }
                };
            counterparties.insert(
                *c,
                dsm::recovery::CounterpartyRecoveryInput {
                    head,
                    authority_commit,
                    leaves,
                    old_segment,
                    establishment,
                    h_cap,
                },
            );
        }

        // Assemble + verify the (seal, gate_set, evidence) triple (pure core; fail-closed).
        let inputs = dsm::recovery::RecoveryAssemblyInputs {
            genesis_id: ctx.genesis_id,
            a_old: ctx.a_old,
            a_new: ctx.a_new,
            a_old_head,
            a_old_authority_commit,
            a_old_leaves,
            counterparties,
            tombstone,
            succession,
            recovery_intent_digest: ctx.recovery_intent_digest,
            tombstone_proposal_digest: ctx.tombstone_proposal_digest,
            final_per_device_smt_root: ctx.final_per_device_smt_root,
            final_receipt_roll: ctx.final_receipt_roll,
        };
        let assembled = dsm::recovery::assemble_recovery_activation(&inputs, &ka_pub)?;

        // Fail-closed chokepoint. Needs A's authority anchor + A_old's genesis-authenticated
        // device signing pubkey (device-tree quorum) to bind K_A to the genesis.
        let a_old_anchor = Self::fetch_authority_anchor(&ctx.genesis_id).await?;
        let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
            .await
            .map_err(|e| {
                DsmError::storage(
                    format!("load storage node config: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        let qid = crate::handlers::app_router_impl::fetch_quorum_device_identity(
            &config.node_urls,
            ctx.a_old,
        )
        .await
        .map_err(|e| {
            DsmError::verification(format!(
                "recovery: A_old device identity quorum failed: {e}"
            ))
        })?;

        Self::verify_and_record_activation(
            &assembled.seal,
            &assembled.gate_set,
            &assembled.evidence,
            &a_old_anchor,
            &qid.public_key,
            &ka_pub,
        )
    }

    /// Verify a recovery activation seal and, on success, RECORD activation so a
    /// recovered successor may egress value. This is the SOLE unlock chokepoint:
    /// `set_recovery_activated(true)` is reached only after the genesis-anchored
    /// authority binding AND the core `validate_recovery_activation` pass (spec §0.5).
    ///
    /// Recovery authority is the counterparties' OWN online-posted, genesis-authenticated
    /// state — NOT the stolen device, the capsule, or the local contacts DB. The
    /// authority pubkey that authenticates each counterparty's tombstone/succession is
    /// itself bound to the genesis via `authority_anchor` (§0.5 step 5); `gate_set`,
    /// `evidence`, and `genesis_signing_pubkey` are produced by the caller from the
    /// online-posted, quorum-verified records (storage = availability; verification =
    /// client-side).
    pub fn verify_and_record_activation(
        seal: &dsm::recovery::RecoveryActivationSeal,
        gate_set: &std::collections::BTreeSet<[u8; 32]>,
        evidence: &std::collections::BTreeMap<
            [u8; 32],
            dsm::recovery::CrossRelationshipSuccessionEvidence,
        >,
        authority_anchor: &dsm::recovery::RecoveryAuthorityAnchor,
        genesis_signing_pubkey: &[u8],
        candidate_authority_pubkey: &[u8],
    ) -> Result<(), DsmError> {
        // §0.5 step 5 — genesis-anchored recovery authority (HARD fail-closed): the
        // pubkey used to verify every counterparty's tombstone/succession is NOT taken
        // raw. It must match the genesis-chained authority anchor, whose genesis-binding
        // signature is verified against the OLD device's genesis-authenticated signing
        // pubkey (caller supplies it from the device-tree quorum path). There is no
        // runtime "provided pubkey" path — an unanchored or mismatched pubkey fails here.
        authority_anchor.verify(
            &seal.genesis_id,
            &seal.old_device_id,
            genesis_signing_pubkey,
            candidate_authority_pubkey,
        )?;

        // §0.5 evidence model: validate that every gate-set counterparty's posted
        // state proves the cross-relationship succession — retire (A_old,C), establish
        // a new bilateral (A_new,C) carrying forward the old frontier (structural
        // validation; unit-tested). Recovery authority is the counterparties' posted
        // state, not a signed ack and not the local contacts DB.
        dsm::recovery::validate_recovery_activation(
            seal,
            gate_set,
            evidence,
            candidate_authority_pubkey,
        )?;

        // FAIL-CLOSED: recording activation (the SOLE spend-unlock for a recovered
        // successor) stays disabled until the inputs are produced by a trusted path:
        //   - each `counterparty_root` must be GENESIS-AUTHENTICATED (DevTreeProof /
        //     signature on the posted root), not taken on faith;
        //   - `gate_set` must be the ONLINE-POSTED value-capable relationship set
        //     under the genesis (fetched + verified), not the local capsule;
        //   - the migration op must reference the specific mnemonic-authorized
        //     tombstone for `A_old`.
        // Until those land, `recovery_activated` is not flipped and
        // `set_recovered_successor(true)` must stay unwired — so no live spend path
        // depends on this unlock (spec §0.5).
        Err(DsmError::InvalidState(
            "recovery activation recording disabled: per-counterparty posted state is \
             not yet genesis-authenticated and the online-posted gate-set is not yet \
             wired (spec §0.5); refusing to unlock a recovered successor"
                .into(),
        ))
    }

    /// Refresh the pending NFC capsule if backup is enabled and a key is available.
    ///
    /// Called by the transport layer (Kotlin) after every state-mutating operation.
    /// If the in-memory key was lost (app restart), this auto-loads the persisted
    /// encrypted key from SQLite before creating the capsule.
    pub fn maybe_refresh_nfc_capsule() {
        if !Self::is_nfc_backup_enabled() {
            return;
        }

        // Auto-load persisted key if the in-memory cache was lost (app restart).
        if !Self::has_cached_key() {
            log::info!("[NFC_BACKUP] No cached key — attempting to load persisted key");
            match Self::load_persisted_recovery_key() {
                Ok(true) => {
                    log::info!("[NFC_BACKUP] Persisted key loaded successfully");
                }
                Ok(false) => {
                    log::warn!(
                        "[NFC_BACKUP] No persisted key found — capsule refresh skipped. \
                         User must re-enter mnemonic via Settings."
                    );
                    return;
                }
                Err(e) => {
                    log::warn!("[NFC_BACKUP] Failed to load persisted key: {e}");
                    return;
                }
            }
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
        let accepted_state_index = crate::storage::client_db::recovery::accepted_state_index();
        let capsule_state_index = crate::storage::client_db::recovery::capsule_state_index();
        let capsule_dirty = crate::storage::client_db::recovery::is_capsule_dirty();

        RecoveryStatus {
            enabled,
            configured,
            pending_capsule,
            capsule_count,
            last_capsule_index,
            capsule_dirty,
            accepted_state_index,
            capsule_state_index,
        }
    }

    fn create_capsule_from_current_state_with_key(
        key: &[u8; 32],
    ) -> Result<(u64, Vec<u8>), DsmError> {
        // Capsule currency (spec §5.2): capture the accepted-state index this
        // seal represents *before* gathering state, so a transition that races
        // the seal leaves the capsule observably dirty (fail-safe) rather than
        // falsely current.
        let captured_index = crate::storage::client_db::recovery::accepted_state_index();
        let RecoveryCapsuleState {
            smt_root,
            counterparty_tips,
            rollup,
            next_index,
            source_device_id,
            genesis_hash,
        } = Self::build_capsule_state()?;
        let tip_count = counterparty_tips.len();
        let encrypted = dsm::recovery::create_recovery_capsule_with_binding(
            &smt_root,
            counterparty_tips,
            &rollup,
            key,
            next_index,
            &source_device_id,
            &genesis_hash,
        )?;
        let capsule_bytes = encrypted.to_bytes();
        Self::persist_capsule(next_index, &smt_root, &capsule_bytes, tip_count)?;
        // Capsule currency (spec §5.2): record the accepted-state index this seal
        // captured so `is_capsule_dirty()` clears.
        if let Err(e) = crate::storage::client_db::recovery::set_capsule_state_index(captured_index)
        {
            log::warn!("[RECOVERY_SDK] failed to record capsule_state_index: {e}");
        }
        log::info!(
            "[RECOVERY_SDK] Created recovery capsule index={} size={} counterparties={} captured_state_index={}",
            next_index,
            capsule_bytes.len(),
            tip_count,
            captured_index,
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
                        // The SMT-backed relationship tip is authoritative. Height is hardcoded
                        // to 0 as it is not used for conflict resolution in this context.
                        counterparty_tips.insert(counterparty_id, (0, tip.clone()));
                    }
                }
            }
        }

        // If there's already a pending (unconsumed) capsule, reuse its index —
        // we only care about the newest state. The pending capsule is continuously
        // overwritten with the latest SMT root until the ring consumes it.
        //
        // When there's NO pending capsule (ring consumed it via clearPending),
        // always advance to max_index + 1. We cannot compare SMT roots here
        // because the consumed capsule was already overwritten with the current
        // state before being written to the ring — the roots would match and
        // the index would never advance.
        let next_index = match crate::storage::client_db::recovery::get_pending_recovery_capsule() {
            Ok(Some((idx, _))) => idx,
            _ => {
                let max_idx = crate::storage::client_db::recovery::get_max_capsule_index()
                    .map_err(|e| {
                        DsmError::InvalidState(format!("Failed to read capsule index: {e}"))
                    })?;
                if max_idx == 0 {
                    // No capsules exist yet — start at 1.
                    1
                } else {
                    // Ring consumed the previous capsule — always advance.
                    max_idx.saturating_add(1)
                }
            }
        };

        let genesis_hash_bytes =
            crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();

        Ok(RecoveryCapsuleState {
            smt_root,
            counterparty_tips,
            rollup,
            next_index,
            source_device_id: device_id_bytes,
            genesis_hash: genesis_hash_bytes,
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

            let mut receipt_hasher =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_RECEIPT);
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
    /// Capsule currency (spec §5.2): true when the latest sealed capsule does
    /// not capture the latest accepted state.
    pub capsule_dirty: bool,
    /// Device-level monotone count of accepted frontier-changing transitions.
    pub accepted_state_index: u64,
    /// Accepted-state index captured by the latest successful capsule seal.
    pub capsule_state_index: u64,
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
    fn dbtc_vault_index_storage_key_is_deterministic_genesis_device_keyed_crockford() {
        let g = [0x6E; 32];
        let d = [0xA0; 32];
        let k = RecoverySDK::dbtc_vault_index_storage_key(&g, &d);
        assert_eq!(k, RecoverySDK::dbtc_vault_index_storage_key(&g, &d));
        assert!(k.starts_with("recovery/dbtc-vault-index/v1/"));
        assert!(!k.starts_with('/'));
        // Keyed by BOTH genesis and device.
        assert_ne!(
            k,
            RecoverySDK::dbtc_vault_index_storage_key(&[0x6F; 32], &d)
        );
        assert_ne!(
            k,
            RecoverySDK::dbtc_vault_index_storage_key(&g, &[0xA1; 32])
        );
        // Base32 Crockford only — no hex (repo invariant).
        assert!(!k.contains("0x"));
    }

    #[test]
    fn recovery_succession_proof_storage_key_is_deterministic_genesis_anew_keyed_crockford() {
        let g = [0x6E; 32];
        let a_new = [0xA1; 32];
        let k = RecoverySDK::recovery_succession_proof_storage_key(&g, &a_new);
        assert_eq!(
            k,
            RecoverySDK::recovery_succession_proof_storage_key(&g, &a_new)
        );
        assert!(k.starts_with("recovery/succession-proof/v1/"));
        assert!(!k.starts_with('/'));
        // Keyed by BOTH genesis and the successor device.
        assert_ne!(
            k,
            RecoverySDK::recovery_succession_proof_storage_key(&[0x6F; 32], &a_new)
        );
        assert_ne!(
            k,
            RecoverySDK::recovery_succession_proof_storage_key(&g, &[0xA2; 32])
        );
        // Base32 Crockford only — no hex (repo invariant).
        assert!(!k.contains("0x"));
    }

    #[test]
    fn authority_anchor_endpoint_path_is_deterministic_genesis_keyed_crockford() {
        let g = [0x6E; 32];
        let p = RecoverySDK::authority_anchor_endpoint_path(&g);
        // Deterministic + stable route prefix, NO leading slash (fan-out helpers join it).
        assert_eq!(p, RecoverySDK::authority_anchor_endpoint_path(&g));
        assert!(p.starts_with("api/v2/recovery/authority-anchor/"));
        assert!(!p.starts_with('/'));
        // Keyed by genesis only (one authority per genesis — matches server bind-once).
        assert_ne!(p, RecoverySDK::authority_anchor_endpoint_path(&[0x6F; 32]));
        // Base32 Crockford only — no '0x' prefix (repo invariant: no hex encoding).
        let suffix = p.trim_start_matches("api/v2/recovery/authority-anchor/");
        assert!(!suffix.contains("0x"));
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn pdsmt_head_chain_endpoint_path_is_device_keyed_crockford() {
        let d = [0xD0; 32];
        let p = RecoverySDK::pdsmt_head_chain_endpoint_path(&d);
        assert_eq!(p, RecoverySDK::pdsmt_head_chain_endpoint_path(&d));
        assert!(p.starts_with("api/v2/tips/"));
        assert!(p.ends_with("/head-chain"));
        assert!(!p.starts_with('/'));
        assert_ne!(p, RecoverySDK::pdsmt_head_chain_endpoint_path(&[0xD1; 32]));
        let mid = p
            .trim_start_matches("api/v2/tips/")
            .trim_end_matches("/head-chain");
        assert!(!mid.contains("0x"));
        assert!(mid.chars().all(|c| c.is_ascii_alphanumeric()));
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
