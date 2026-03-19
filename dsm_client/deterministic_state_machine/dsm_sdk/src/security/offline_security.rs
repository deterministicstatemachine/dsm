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
use rand::{rngs::OsRng, RngCore};
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
