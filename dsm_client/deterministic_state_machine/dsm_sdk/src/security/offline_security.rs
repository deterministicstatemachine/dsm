// SPDX-License-Identifier: MIT OR Apache-2.0
//! # DSM Local Storage Security (drop-in, no serde/json/base64)
//!
//! Lightweight, **local-only** encryption helpers that complement DSM Core.
//! - Encrypts sensitive app state at rest using a device master key
//! - Encrypts queued offline transactions for later sync
//! - **No serde / JSON / base64** anywhere; uses deterministic protobuf serialization
//! - Uses deterministic logical time via `tick()`
//!
//! Core transaction crypto (signing, verification, PQC, etc.) remains the job of DSM Core.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use blake3;
use dsm::types::error::DsmError;
use dsm::types::proto::SensitiveAppDataProto;
use prost::Message;
use rand_core06::{OsRng, RngCore};
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::util::deterministic_time::tick;

/// Device-specific master key for **local storage encryption only**.
/// DSM Core handles all network/transaction keys with ephemeral rotation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceMasterKey([u8; 32]);

impl DeviceMasterKey {
    /// Generate a master key from OS/hardware entropy.
    /// This key is **never** used for transaction signing.
    pub fn generate_from_hardware() -> Result<Self, DsmError> {
        let mut entropy = [0u8; 32];

        #[cfg(target_os = "android")]
        {
            use std::fs::File;
            use std::io::Read;

            let mut f = File::open("/dev/random")
                .map_err(|e| DsmError::crypto("Failed to access entropy source", Some(e)))?;
            f.read_exact(&mut entropy)
                .map_err(|e| DsmError::crypto("Failed to read entropy", Some(e)))?;

            // Mix with a static domain key to produce a stable-sized key material
            let mut key = [0u8; 32];
            let domain = b"DSM/local_storage";
            key[..domain.len().min(32)].copy_from_slice(&domain[..domain.len().min(32)]);
            entropy = *blake3::keyed_hash(&key, &entropy).as_bytes();

            // Best-effort extra uniqueness (not required for correctness)
            let _ = android_device_id();
        }

        #[cfg(not(target_os = "android"))]
        {
            OsRng.fill_bytes(&mut entropy);
        }

        Ok(DeviceMasterKey(entropy))
    }

    /// Derive a 256-bit AES-GCM key for a particular local purpose/context.
    pub fn derive_storage_key(&self, purpose: &str, context: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(b"DSM/local_storage_key");
        hasher.update(purpose.as_bytes());
        hasher.update(context);
        *hasher.finalize().as_bytes()
    }
}

/// Sensitive data that is **never** stored unencrypted.
pub struct SensitiveAppData {
    pub device_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub genesis_hash: Vec<u8>,
    pub smt_root: Vec<u8>,
}

impl SensitiveAppData {
    /// Serialize to deterministic protobuf format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let proto = SensitiveAppDataProto {
            device_id: self.device_id.clone(),
            public_key: self.public_key.clone(),
            genesis_hash: self.genesis_hash.clone(),
            smt_root: self.smt_root.clone(),
        };
        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(buf)
    }

    /// Deserialize from protobuf format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let proto = SensitiveAppDataProto::decode(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(SensitiveAppData {
            device_id: proto.device_id,
            public_key: proto.public_key,
            genesis_hash: proto.genesis_hash,
            smt_root: proto.smt_root,
        })
    }
}

/// Encrypted container for sensitive app state (local-only).
pub struct EncryptedAppState {
    pub encrypted_data: Vec<u8>, // AES-GCM ciphertext+tag
    pub nonce: [u8; 12],         // AES-GCM nonce
    pub key_context: Vec<u8>,    // derivation context (e.g., device fingerprint/hash)
    pub version: u32,            // for future migrations
}

impl EncryptedAppState {
    /// Encrypt sensitive app state for local storage.
    pub fn encrypt(
        master_key: &DeviceMasterKey,
        device_id: &[u8],
        public_key: &[u8],
        genesis_hash: &[u8],
        smt_root: &[u8],
    ) -> Result<Self, DsmError> {
        // Context binds this encryption to this device
        let key_context = dsm::crypto::blake3::domain_hash("DSM/offline-key-ctx", device_id)
            .as_bytes()
            .to_vec();
        let enc_key = master_key.derive_storage_key("app_state", &key_context);

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        let sensitive = SensitiveAppData {
            device_id: device_id.to_vec(),
            public_key: public_key.to_vec(),
            genesis_hash: genesis_hash.to_vec(),
            smt_root: smt_root.to_vec(),
        };
        let plaintext = sensitive
            .to_bytes()
            .map_err(|e| DsmError::crypto("Failed to serialize sensitive data", Some(e)))?;

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let encrypted_data = cipher
            .encrypt(&Nonce::from(nonce), plaintext.as_ref())
            .map_err(|e| DsmError::crypto("Failed to encrypt app state", Some(e)))?;

        Ok(EncryptedAppState {
            encrypted_data,
            nonce,
            key_context,
            version: 1,
        })
    }

    /// Decrypt sensitive app state.
    pub fn decrypt(&self, master_key: &DeviceMasterKey) -> Result<SensitiveAppData, DsmError> {
        let enc_key = master_key.derive_storage_key("app_state", &self.key_context);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        let plaintext = cipher
            .decrypt(&Nonce::from(self.nonce), self.encrypted_data.as_ref())
            .map_err(|e| DsmError::crypto("Failed to decrypt app state", Some(e)))?;

        SensitiveAppData::from_bytes(&plaintext)
            .map_err(|e| DsmError::crypto("Failed to deserialize sensitive data", Some(e)))
    }

    /// Length-prefixed binary encoding:
    /// `[`u32 version`][`12-byte nonce`][`u32 len ctx`][ctx][`u32 len ct`][ct]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(4 + 12 + 4 + self.key_context.len() + 4 + self.encrypted_data.len());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.key_context.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.key_context);
        out.extend_from_slice(&(self.encrypted_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.encrypted_data);
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, std::io::Error> {
        use std::io::{Error, ErrorKind};

        fn take<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], std::io::Error> {
            if r.len() < N {
                return Err(Error::new(ErrorKind::UnexpectedEof, "take"));
            }
            let mut out = [0u8; N];
            out.copy_from_slice(&r[..N]);
            *r = &r[N..];
            Ok(out)
        }
        fn read_len(r: &mut &[u8]) -> Result<usize, std::io::Error> {
            let le = take::<4>(r)?;
            Ok(u32::from_le_bytes(le) as usize)
        }
        fn read_vec(r: &mut &[u8], len: usize) -> Result<Vec<u8>, std::io::Error> {
            if r.len() < len {
                return Err(Error::new(ErrorKind::UnexpectedEof, "vec"));
            }
            let v = r[..len].to_vec();
            *r = &r[len..];
            Ok(v)
        }

        let ver = u32::from_le_bytes(take::<4>(&mut bytes)?);
        let nonce = take::<12>(&mut bytes)?;
        let ctx_len = read_len(&mut bytes)?;
        let key_context = read_vec(&mut bytes, ctx_len)?;
        let ct_len = read_len(&mut bytes)?;
        let encrypted_data = read_vec(&mut bytes, ct_len)?;

        Ok(Self {
            encrypted_data,
            nonce,
            key_context,
            version: ver,
        })
    }
}

/// Encrypted transaction entry for the offline queue.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedTransaction {
    pub encrypted_data: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_context: Vec<u8>,
    /// Deterministic logical tick index when enqueued (clockless).
    pub tick_index: u64,
}

impl EncryptedTransaction {
    /// `[`u64 tick`][`12-byte nonce`][`u32 len ctx`][ctx][`u32 len ct`][ct]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + 12 + 4 + self.key_context.len() + 4 + self.encrypted_data.len());
        out.extend_from_slice(&self.tick_index.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.key_context.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.key_context);
        out.extend_from_slice(&(self.encrypted_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.encrypted_data);
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, std::io::Error> {
        use std::io::{Error, ErrorKind};

        fn take<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], std::io::Error> {
            if r.len() < N {
                return Err(Error::new(ErrorKind::UnexpectedEof, "take"));
            }
            let mut out = [0u8; N];
            out.copy_from_slice(&r[..N]);
            *r = &r[N..];
            Ok(out)
        }
        fn read_len(r: &mut &[u8]) -> Result<usize, std::io::Error> {
            let mut le = [0u8; 4];
            if r.len() < 4 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "len"));
            }
            le.copy_from_slice(&r[..4]);
            *r = &r[4..];
            Ok(u32::from_le_bytes(le) as usize)
        }
        fn read_vec(r: &mut &[u8], len: usize) -> Result<Vec<u8>, std::io::Error> {
            if r.len() < len {
                return Err(Error::new(ErrorKind::UnexpectedEof, "vec"));
            }
            let v = r[..len].to_vec();
            *r = &r[len..];
            Ok(v)
        }

        if bytes.len() < 8 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "tick"));
        }
        let mut tick_le = [0u8; 8];
        tick_le.copy_from_slice(&bytes[..8]);
        bytes = &bytes[8..];
        let tick_index = u64::from_le_bytes(tick_le);

        let nonce = take::<12>(&mut bytes)?;
        let ctx_len = read_len(&mut bytes)?;
        let key_context = read_vec(&mut bytes, ctx_len)?;
        let ct_len = read_len(&mut bytes)?;
        let encrypted_data = read_vec(&mut bytes, ct_len)?;

        Ok(Self {
            encrypted_data,
            nonce,
            key_context,
            tick_index,
        })
    }
}

/// Offline transaction queue with local encryption only.
/// DSM Core validates/syncs these later.
pub struct OfflineTransactionQueue {
    encrypted_transactions: Mutex<Vec<EncryptedTransaction>>,
    master_key: DeviceMasterKey,
}

impl OfflineTransactionQueue {
    pub fn new(master_key: DeviceMasterKey) -> Self {
        Self {
            encrypted_transactions: Mutex::new(Vec::new()),
            master_key,
        }
    }

    /// Encrypt and enqueue a transaction blob.
    pub fn enqueue_transaction(&self, transaction: &[u8]) -> Result<(), DsmError> {
        let encrypted = self.encrypt_transaction(transaction)?;
        self.encrypted_transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(encrypted);
        Ok(())
    }

    /// Read-only snapshot of pending transactions (still encrypted).
    pub fn get_pending_transactions(&self) -> Vec<EncryptedTransaction> {
        self.encrypted_transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Remove the first `count` transactions after successful sync.
    pub fn clear_synced_transactions(&self, count: usize) {
        let mut v = self
            .encrypted_transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let n = count.min(v.len());
        v.drain(0..n);
    }

    /// Decrypt a previously-encrypted transaction from the queue.
    pub fn decrypt_queued_transaction(
        &self,
        encrypted: &EncryptedTransaction,
    ) -> Result<Vec<u8>, DsmError> {
        self.decrypt_transaction(encrypted)
    }

    fn decrypt_transaction(&self, encrypted: &EncryptedTransaction) -> Result<Vec<u8>, DsmError> {
        let enc_key = self
            .master_key
            .derive_storage_key("transaction", &encrypted.key_context);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        let pt = cipher
            .decrypt(
                &Nonce::from(encrypted.nonce),
                encrypted.encrypted_data.as_ref(),
            )
            .map_err(|e| DsmError::crypto("Failed to decrypt transaction", Some(e)))?;
        Ok(pt)
    }

    fn encrypt_transaction(&self, transaction: &[u8]) -> Result<EncryptedTransaction, DsmError> {
        // Bind encryption to the content itself
        let key_context = dsm::crypto::blake3::domain_hash("DSM/offline-tx-ctx", transaction)
            .as_bytes()
            .to_vec();
        let enc_key = self
            .master_key
            .derive_storage_key("transaction", &key_context);
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| DsmError::crypto("Invalid AES key", Some(e)))?;

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let encrypted_data = cipher
            .encrypt(&Nonce::from(nonce), transaction)
            .map_err(|e| DsmError::crypto("Failed to encrypt transaction", Some(e)))?;

        Ok(EncryptedTransaction {
            encrypted_data,
            nonce,
            key_context,
            tick_index: tick(),
        })
    }
}

/// In-memory secure app state: plaintext flags + encrypted sensitive blob.
pub struct SecureAppState {
    // Non-sensitive state (plaintext)
    pub has_identity: bool,
    pub sdk_initialized: bool,

    // Sensitive state (encrypted)
    pub encrypted_state: Option<EncryptedAppState>,

    // Device-local master key (not persisted)
    master_key: Option<DeviceMasterKey>,

    // Offline transaction queue (encrypted)
    transaction_queue: Option<OfflineTransactionQueue>,
}

impl SecureAppState {
    pub fn new() -> Result<Self, DsmError> {
        let master_key = DeviceMasterKey::generate_from_hardware()?;

        Ok(Self {
            has_identity: false,
            sdk_initialized: false,
            encrypted_state: None,
            master_key: Some(master_key),
            transaction_queue: None,
        })
    }

    /// Set identity info and encrypt sensitive parts for local storage.
    pub fn set_identity_info(
        &mut self,
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        genesis_hash: Vec<u8>,
        smt_root: Vec<u8>,
    ) -> Result<(), DsmError> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| DsmError::crypto("Master key not available", None::<std::io::Error>))?;

        let enc = EncryptedAppState::encrypt(
            master_key,
            &device_id,
            &public_key,
            &genesis_hash,
            &smt_root,
        )?;
        self.encrypted_state = Some(enc);
        self.has_identity = true;

        if self.transaction_queue.is_none() {
            self.transaction_queue = Some(OfflineTransactionQueue::new(master_key.clone()));
        }
        Ok(())
    }

    pub fn get_device_id(&self) -> Result<Option<Vec<u8>>, DsmError> {
        let Some(enc) = &self.encrypted_state else {
            return Ok(None);
        };
        let Some(master) = &self.master_key else {
            return Err(DsmError::crypto(
                "Master key not available",
                None::<std::io::Error>,
            ));
        };
        let s = enc.decrypt(master)?;
        Ok(Some(s.device_id))
    }

    pub fn get_public_key(&self) -> Result<Option<Vec<u8>>, DsmError> {
        let Some(enc) = &self.encrypted_state else {
            return Ok(None);
        };
        let Some(master) = &self.master_key else {
            return Err(DsmError::crypto(
                "Master key not available",
                None::<std::io::Error>,
            ));
        };
        let s = enc.decrypt(master)?;
        Ok(Some(s.public_key))
    }

    /// Queue a transaction blob for later sync (still encrypted at rest).
    pub fn queue_transaction(&self, transaction: &[u8]) -> Result<(), DsmError> {
        self.transaction_queue
            .as_ref()
            .ok_or_else(|| {
                DsmError::crypto("Transaction queue not initialized", None::<std::io::Error>)
            })?
            .enqueue_transaction(transaction)
    }

    /// Return encrypted pending transactions to be shipped to storage nodes.
    pub fn get_pending_transactions(&self) -> Vec<EncryptedTransaction> {
        self.transaction_queue
            .as_ref()
            .map(|q| q.get_pending_transactions())
            .unwrap_or_default()
    }

    /// Remove the first `count` queued transactions after successful sync.
    pub fn clear_synced_transactions(&self, count: usize) {
        if let Some(q) = &self.transaction_queue {
            q.clear_synced_transactions(count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> DeviceMasterKey {
        DeviceMasterKey::generate_from_hardware().expect("key generation should succeed")
    }

    #[test]
    fn derive_storage_key_deterministic() {
        let mk = test_master_key();
        let k1 = mk.derive_storage_key("purpose_a", b"ctx1");
        let k2 = mk.derive_storage_key("purpose_a", b"ctx1");
        assert_eq!(k1, k2, "same inputs must yield same derived key");
    }

    #[test]
    fn derive_storage_key_varies_with_purpose() {
        let mk = test_master_key();
        let k1 = mk.derive_storage_key("purpose_a", b"ctx");
        let k2 = mk.derive_storage_key("purpose_b", b"ctx");
        assert_ne!(k1, k2, "different purposes must yield different keys");
    }

    #[test]
    fn derive_storage_key_varies_with_context() {
        let mk = test_master_key();
        let k1 = mk.derive_storage_key("purpose", b"ctx_1");
        let k2 = mk.derive_storage_key("purpose", b"ctx_2");
        assert_ne!(k1, k2, "different contexts must yield different keys");
    }

    #[test]
    fn sensitive_app_data_roundtrip() {
        let data = SensitiveAppData {
            device_id: vec![1; 32],
            public_key: vec![2; 64],
            genesis_hash: vec![3; 32],
            smt_root: vec![4; 32],
        };
        let bytes = data.to_bytes().unwrap();
        let restored = SensitiveAppData::from_bytes(&bytes).unwrap();
        assert_eq!(data.device_id, restored.device_id);
        assert_eq!(data.public_key, restored.public_key);
        assert_eq!(data.genesis_hash, restored.genesis_hash);
        assert_eq!(data.smt_root, restored.smt_root);
    }

    #[test]
    fn encrypted_app_state_encrypt_decrypt_roundtrip() {
        let mk = test_master_key();
        let device_id = vec![10u8; 32];
        let public_key = vec![20u8; 64];
        let genesis_hash = vec![30u8; 32];
        let smt_root = vec![40u8; 32];

        let enc = EncryptedAppState::encrypt(
            &mk,
            &device_id,
            &public_key,
            &genesis_hash,
            &smt_root,
        )
        .unwrap();

        assert_eq!(enc.version, 1);
        assert!(!enc.encrypted_data.is_empty());

        let dec = enc.decrypt(&mk).unwrap();
        assert_eq!(dec.device_id, device_id);
        assert_eq!(dec.public_key, public_key);
        assert_eq!(dec.genesis_hash, genesis_hash);
        assert_eq!(dec.smt_root, smt_root);
    }

    #[test]
    fn encrypted_app_state_binary_roundtrip() {
        let mk = test_master_key();
        let enc = EncryptedAppState::encrypt(&mk, b"did", b"pk", b"gh", b"sr").unwrap();
        let bytes = enc.to_bytes();
        let restored = EncryptedAppState::from_bytes(&bytes).unwrap();
        assert_eq!(restored.version, enc.version);
        assert_eq!(restored.nonce, enc.nonce);
        assert_eq!(restored.key_context, enc.key_context);
        assert_eq!(restored.encrypted_data, enc.encrypted_data);

        let dec = restored.decrypt(&mk).unwrap();
        assert_eq!(dec.device_id, b"did");
    }

    #[test]
    fn encrypted_app_state_wrong_key_fails() {
        let mk1 = test_master_key();
        let mk2 = test_master_key();
        let enc =
            EncryptedAppState::encrypt(&mk1, b"did", b"pk", b"gh", b"sr").unwrap();
        assert!(enc.decrypt(&mk2).is_err());
    }

    #[test]
    fn encrypted_app_state_from_bytes_truncated() {
        assert!(EncryptedAppState::from_bytes(&[]).is_err());
        assert!(EncryptedAppState::from_bytes(&[0u8; 3]).is_err());
    }

    #[test]
    fn encrypted_transaction_binary_roundtrip() {
        let et = EncryptedTransaction {
            encrypted_data: vec![0xAA; 48],
            nonce: [0xBB; 12],
            key_context: vec![0xCC; 32],
            tick_index: 42,
        };
        let bytes = et.to_bytes();
        let restored = EncryptedTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(restored.tick_index, 42);
        assert_eq!(restored.nonce, [0xBB; 12]);
        assert_eq!(restored.key_context, vec![0xCC; 32]);
        assert_eq!(restored.encrypted_data, vec![0xAA; 48]);
    }

    #[test]
    fn encrypted_transaction_from_bytes_truncated() {
        assert!(EncryptedTransaction::from_bytes(&[]).is_err());
        assert!(EncryptedTransaction::from_bytes(&[0u8; 7]).is_err());
    }

    #[test]
    fn offline_queue_enqueue_decrypt_roundtrip() {
        let mk = test_master_key();
        let queue = OfflineTransactionQueue::new(mk);

        let tx_data = b"test transaction payload";
        queue.enqueue_transaction(tx_data).unwrap();

        let pending = queue.get_pending_transactions();
        assert_eq!(pending.len(), 1);

        let decrypted = queue.decrypt_queued_transaction(&pending[0]).unwrap();
        assert_eq!(decrypted, tx_data);
    }

    #[test]
    fn offline_queue_clear_synced() {
        let mk = test_master_key();
        let queue = OfflineTransactionQueue::new(mk);

        queue.enqueue_transaction(b"tx1").unwrap();
        queue.enqueue_transaction(b"tx2").unwrap();
        queue.enqueue_transaction(b"tx3").unwrap();
        assert_eq!(queue.get_pending_transactions().len(), 3);

        queue.clear_synced_transactions(2);
        let remaining = queue.get_pending_transactions();
        assert_eq!(remaining.len(), 1);

        let dec = queue.decrypt_queued_transaction(&remaining[0]).unwrap();
        assert_eq!(dec, b"tx3");
    }

    #[test]
    fn offline_queue_clear_more_than_available() {
        let mk = test_master_key();
        let queue = OfflineTransactionQueue::new(mk);
        queue.enqueue_transaction(b"only").unwrap();
        queue.clear_synced_transactions(100);
        assert!(queue.get_pending_transactions().is_empty());
    }

    #[test]
    fn secure_app_state_lifecycle() {
        let mut state = SecureAppState::new().unwrap();
        assert!(!state.has_identity);
        assert!(!state.sdk_initialized);
        assert!(state.get_device_id().unwrap().is_none());
        assert!(state.get_public_key().unwrap().is_none());

        state
            .set_identity_info(
                vec![1; 32],
                vec![2; 64],
                vec![3; 32],
                vec![4; 32],
            )
            .unwrap();
        assert!(state.has_identity);
        assert_eq!(state.get_device_id().unwrap().unwrap(), vec![1; 32]);
        assert_eq!(state.get_public_key().unwrap().unwrap(), vec![2; 64]);
    }

    #[test]
    fn secure_app_state_transaction_queue() {
        let mut state = SecureAppState::new().unwrap();
        // Queue not initialized before identity
        assert!(state.queue_transaction(b"tx").is_err());
        assert!(state.get_pending_transactions().is_empty());

        state
            .set_identity_info(vec![1; 32], vec![2; 32], vec![3; 32], vec![4; 32])
            .unwrap();

        state.queue_transaction(b"tx_a").unwrap();
        state.queue_transaction(b"tx_b").unwrap();
        assert_eq!(state.get_pending_transactions().len(), 2);

        state.clear_synced_transactions(1);
        assert_eq!(state.get_pending_transactions().len(), 1);
    }
}

#[cfg(target_os = "android")]
fn android_device_id() -> Result<String, DsmError> {
    // Android-specific device ID retrieval (best-effort; purely for local key mixing).
    if let Some(id) = crate::sdk::app_state::AppState::get_device_id() {
        if id.len() == 32 {
            return Ok(crate::util::text_id::encode_base32_crockford(&id));
        }
    }

    if let Some(k) = crate::jni::cdbrw::get_cdbrw_binding_key() {
        if !k.is_empty() {
            let h = dsm::crypto::blake3::domain_hash("DSM/offline-key-derive", &k);
            return Ok(crate::util::text_id::encode_base32_crockford(h.as_bytes()));
        }
    }

    Err(DsmError::crypto(
        "android_device_id unavailable",
        None::<std::io::Error>,
    ))
}
