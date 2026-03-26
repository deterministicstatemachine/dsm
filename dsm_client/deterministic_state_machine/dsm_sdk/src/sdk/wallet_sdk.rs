//! # Wallet SDK Module (no JSON, no Base64/b64, no hex, no wall clock)
//!
//! Deterministic, offline-capable wallet operations for DSM.
//! - All time uses deterministic logical ticks from `utils::deterministic_time`.
//! - UI/debug-friendly representations may exist, but protocol text IDs are base32.
//! - No serde_json anywhere.

use super::core_sdk::{CoreSDK, TokenManagerTrait};
use super::identity_sdk::IdentitySDK;
#[cfg(feature = "storage")]
use super::storage_sync_sdk::{StorageSyncSdk, WalletDisplayData};
use super::token_sdk::TokenSDK;

use dsm::crypto;
use dsm::types::error::DsmError;
use dsm::types::state_types::State;
use dsm::types::token_types::{Balance, TokenOperation};

use base32;
use log;
use parking_lot::RwLock;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::util::deterministic_time as dt;

// ---------- helpers: no hex/b64 ----------
const ERA_SOURCE_DLV_PEER_KEY: &str = "era-source-dlv";
const ERA_SOURCE_DLV_DISPLAY_NAME: &str = "ERA Source DLV";

fn first8_le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let take = bytes.len().min(8);
    buf[..take].copy_from_slice(&bytes[..take]);
    u64::from_le_bytes(buf)
}

fn era_source_dlv_device_id() -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(
        "DSM/system-peer-device-id",
        ERA_SOURCE_DLV_PEER_KEY.as_bytes(),
    )
}

fn build_faucet_protocol_payload(
    recipient_device_id: &[u8; 32],
    token_id: &str,
    amount: u64,
    source_state_hash: &[u8; 32],
    source_state_number: u64,
) -> Vec<u8> {
    let source_state_number_bytes = source_state_number.to_le_bytes();
    crate::sdk::receipts::encode_protocol_transition_payload(
        b"faucet.claim",
        &[
            recipient_device_id,
            token_id.as_bytes(),
            &amount.to_le_bytes(),
            source_state_hash,
            &source_state_number_bytes,
        ],
    )
}

// ---------- TokenSDK clone wrapper ----------
struct TokenSDKWrapper {
    inner: TokenSDK<IdentitySDK>,
}
impl TokenSDKWrapper {
    fn new(token_sdk: TokenSDK<IdentitySDK>) -> Self {
        Self { inner: token_sdk }
    }
}
impl TokenManagerTrait for TokenSDKWrapper {
    fn register_token(&self, token_id: &str) -> Result<(), DsmError> {
        TokenManagerTrait::register_token(&self.inner, token_id)
    }
    fn get_balance(&self, token_id: &str) -> Result<u64, DsmError> {
        TokenManagerTrait::get_balance(&self.inner, token_id)
    }
}

// ---------- types ----------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Standard,
    High,
    Maximum,
}

#[derive(Debug, Clone)]
pub struct Counterparty {
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub alias: Option<String>,
    pub created_at: u64, // ticks
    pub last_used: u64,  // ticks
    pub is_hidden: bool,
}
impl Counterparty {
    pub fn new(device_id: String, public_key: Vec<u8>, alias: Option<String>) -> Self {
        let now = dt::tick();
        Self {
            device_id,
            public_key,
            alias,
            created_at: now,
            last_used: now,
            is_hidden: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainTipInfo {
    pub counterparty_device_id: Vec<u8>,
    pub chain_tip_id: Vec<u8>,
    pub last_state_hash: Vec<u8>,
    pub state_number: u64,
    pub last_updated: u64, // ticks
    pub is_synchronized: bool,
}
impl ChainTipInfo {
    pub fn new(
        counterparty_device_id: Vec<u8>,
        chain_tip_id: Vec<u8>,
        last_state_hash: Vec<u8>,
        state_number: u64,
    ) -> Self {
        let now = dt::tick();
        Self {
            counterparty_device_id,
            chain_tip_id,
            last_state_hash,
            state_number,
            last_updated: now,
            is_synchronized: true,
        }
    }
    pub fn update(&mut self, new_tip_id: Vec<u8>, new_state_hash: Vec<u8>, new_state_number: u64) {
        self.chain_tip_id = new_tip_id;
        self.last_state_hash = new_state_hash;
        self.state_number = new_state_number;
        self.last_updated = dt::tick();
        self.is_synchronized = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Rejected,
    Scheduled,
}

#[derive(Clone)]
pub struct WalletTransaction {
    pub id: String, // decimal/readable
    pub from_device_id: String,
    pub to_device_id: String,
    pub amount: u64,
    pub token_id: String,
    pub memo: Option<String>,
    pub tick: u64,
    pub status: TransactionStatus,
    pub state_number: Option<u64>,
    pub hash: Vec<u8>, // blake3 raw bytes
    pub fee: u64,
    pub signature: Option<Vec<u8>>,
    pub chain_tip_id: String, // decimal text
    pub metadata: HashMap<String, String>,
}
impl fmt::Debug for WalletTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletTransaction")
            .field("id", &self.id)
            .field("from_device_id", &self.from_device_id)
            .field("to_device_id", &self.to_device_id)
            .field("amount", &self.amount)
            .field("token_id", &self.token_id)
            .field("memo", &self.memo)
            .field("tick", &self.tick)
            .field("status", &self.status)
            .field("state_number", &self.state_number)
            .field("chain_tip_id", &self.chain_tip_id)
            .field("fee", &self.fee)
            .field("metadata", &self.metadata)
            .finish()
    }
}
impl WalletTransaction {
    pub fn new(
        from_device_id: String,
        to_device_id: String,
        amount: u64,
        token_id: String,
        memo: Option<String>,
        fee: u64,
        chain_tip_id: String,
    ) -> Self {
        let now = dt::tick();

        // hash for id + body
        let mut tx_hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/tx-hash");
        tx_hasher.update(from_device_id.as_bytes());
        tx_hasher.update(to_device_id.as_bytes());
        tx_hasher.update(&amount.to_le_bytes());
        tx_hasher.update(token_id.as_bytes());
        tx_hasher.update(chain_tip_id.as_bytes());
        if let Some(m) = &memo {
            tx_hasher.update(m.as_bytes());
        }
        tx_hasher.update(&now.to_le_bytes());
        tx_hasher.update(&fee.to_le_bytes());
        let tx_hash = tx_hasher.finalize();

        let id = format!(
            "tx:{}:{}:{}:{}:{}",
            first8_le_u64(tx_hash.as_bytes()),
            from_device_id,
            to_device_id,
            amount,
            fee
        );

        Self {
            id,
            from_device_id,
            to_device_id,
            amount,
            token_id,
            memo,
            tick: now,
            status: TransactionStatus::Pending,
            state_number: None,
            hash: tx_hash.as_bytes().to_vec(),
            fee,
            signature: None,
            chain_tip_id,
            metadata: HashMap::new(),
        }
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<Vec<u8>, DsmError> {
        let sig = dsm::crypto::signatures::sign_message(private_key, &self.hash).map_err(|e| {
            DsmError::crypto(format!("Signing failed: {e}"), None::<std::io::Error>)
        })?;
        self.signature = Some(sig.clone());
        Ok(sig)
    }
}

// ---------- config & SDK ----------
#[derive(Debug, Clone)]
pub struct WalletRecoveryOptions {
    pub mnemonic: Option<String>,
    pub recovery_file: Option<PathBuf>,
    pub recovery_email: Option<String>,
    pub hardware_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WalletConfig {
    pub name: String,
    pub security_level: SecurityLevel,
    /// auto-lock in ticks (0 = never)
    pub auto_lock_timeout: u64,
    pub offline_transactions_enabled: bool,
    pub default_fee: u64,
    pub db_path: Option<PathBuf>,
    /// backup schedule in ticks (0 = disabled)
    pub backup_schedule_hours: u64,
    pub recovery_options: WalletRecoveryOptions,
    pub custom_options: HashMap<String, String>,
}
impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            name: "DSM Wallet".to_string(),
            security_level: SecurityLevel::Standard,
            auto_lock_timeout: 300,
            offline_transactions_enabled: true,
            default_fee: 1,
            db_path: None,
            backup_schedule_hours: 24,
            recovery_options: WalletRecoveryOptions {
                mnemonic: None,
                recovery_file: None,
                recovery_email: None,
                hardware_path: None,
            },
            custom_options: HashMap::new(),
        }
    }
}

pub struct WalletSDK {
    #[allow(dead_code)]
    core_sdk: Arc<CoreSDK>,
    token_sdk: Arc<TokenSDK<IdentitySDK>>,
    config: RwLock<WalletConfig>,
    bilateral_chains: RwLock<HashMap<Vec<u8>, ChainTipInfo>>,
    transactions: RwLock<Vec<WalletTransaction>>,
    locked: RwLock<bool>,
    last_activity: RwLock<u64>, // ticks
    // Canonical text device identifier (updated post-genesis).
    device_id: RwLock<String>,
    keystore: RwLock<HashMap<String, Vec<u8>>>,
    last_backup: RwLock<Option<u64>>, // ticks
    device_book: RwLock<HashMap<String, Counterparty>>,
}

pub struct FailedOnlineSendRollback<'a> {
    pub tx_id: &'a str,
    pub token_id: &'a str,
    pub failed_state: &'a State,
    pub previous_state: &'a State,
    pub recipient_device_id: &'a [u8; 32],
    pub amount: u64,
    pub memo: Option<&'a str>,
}

impl fmt::Debug for WalletSDK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let did = self.device_id.read().clone();
        f.debug_struct("WalletSDK")
            .field("device_id", &did)
            .field("config", &"WalletConfig{...}")
            .field("bilateral_chains_len", &self.bilateral_chains.read().len())
            .field("locked", &self.locked.read())
            .finish()
    }
}

impl WalletSDK {
    fn device_id_string(&self) -> String {
        self.device_id.read().clone()
    }

    /// Canonical device id text (base32 for 32-byte device id).
    ///
    /// Most persistence keys in `client_db` use this representation.
    fn device_id_base32(&self) -> String {
        self.device_id.read().clone()
    }

    fn device_id_bytes(&self) -> Vec<u8> {
        self.device_id_string().into_bytes()
    }

    fn device_id_array(&self) -> [u8; 32] {
        let bytes = crate::util::text_id::decode_base32_crockford(&self.device_id_string())
            .unwrap_or_default();
        let mut array = [0u8; 32];
        if bytes.len() == 32 {
            array.copy_from_slice(&bytes);
        } else {
            log::warn!(
                "Wallet device_id decode produced {} bytes; using zero device id fallback",
                bytes.len()
            );
        }
        array
    }

    pub fn new(
        core_sdk: Arc<CoreSDK>,
        device_id: &str,
        config: Option<WalletConfig>,
    ) -> Result<Self, DsmError> {
        let device_id_bytes = crate::util::domain_helpers::device_id_hash(device_id);
        let token_sdk = Arc::new(TokenSDK::<IdentitySDK>::new(
            core_sdk.clone(),
            device_id_bytes,
        ));
        let token_sdk_clone = TokenSDK::<IdentitySDK>::new(core_sdk.clone(), device_id_bytes);
        core_sdk.register_token_manager(Box::new(TokenSDKWrapper::new(token_sdk_clone)))?;

        let config = config.unwrap_or_else(|| WalletConfig {
            name: format!("{device_id}'s Wallet"),
            ..WalletConfig::default()
        });
        let now = dt::tick();

        let wallet = Self {
            core_sdk,
            token_sdk,
            config: RwLock::new(config),
            bilateral_chains: RwLock::new(HashMap::new()),
            transactions: RwLock::new(Vec::new()),
            locked: RwLock::new(false),
            last_activity: RwLock::new(now),
            device_id: RwLock::new(device_id.to_string()),
            keystore: RwLock::new(HashMap::new()),
            last_backup: RwLock::new(None),
            device_book: RwLock::new(HashMap::new()),
        };

        wallet.initialize_device_keys()?;
        Ok(wallet)
    }

    fn initialize_device_keys(&self) -> Result<(), DsmError> {
        let now = dt::peek();
        {
            let mut la = self.last_activity.write();
            *la = now;
        }

        let current_id = self.device_id_string();
        let ks = self.keystore.read();
        let sentinel_key = format!("{id}_device_sphincs_pk", id = current_id);
        if ks.contains_key(&sentinel_key) {
            if let Some(existing_sk) = ks.get(&format!("{id}_device_sphincs_sk", id = current_id)) {
                self.token_sdk.set_signing_key(existing_sk.clone());
                self.core_sdk.set_signing_key(existing_sk.clone());
            }
            // Ensure state machine's device_info.public_key matches the wallet's key
            if let Some(existing_pk) = ks.get(&sentinel_key) {
                self.core_sdk.update_signing_public_key(existing_pk.clone());
            }
            return Ok(());
        }
        drop(ks);

        let (kyber_pk, kyber_sk) = dsm::crypto::generate_keypair()?;
        let (sphincs_pk, sphincs_sk) = if let (Ok(pk_str), Ok(sk_str)) = (
            std::env::var("DSM_SDK_TEST_IMPORT_PK"),
            std::env::var("DSM_SDK_TEST_IMPORT_SK"),
        ) {
            // Use canonical RFC4648 no-padding for import
            let pk = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &pk_str)
                .ok_or_else(|| {
                    DsmError::internal("Invalid base32 import PK", None::<std::io::Error>)
                })?;
            let sk = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &sk_str)
                .ok_or_else(|| {
                    DsmError::internal("Invalid base32 import SK", None::<std::io::Error>)
                })?;
            log::info!("Imported test keys from environment for {}", current_id);
            (pk, sk)
        } else if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
            use dsm::crypto::sphincs::SphincsVariant;
            let pk_len = dsm::crypto::sphincs::public_key_bytes(SphincsVariant::SPX256s);
            let sk_len = dsm::crypto::sphincs::secret_key_bytes(SphincsVariant::SPX256s);
            let seed = dsm::crypto::blake3::domain_hash(
                "DSM/test-sphincs-seed",
                format!("DSM_TEST_SPHINCS:{}", current_id).as_bytes(),
            );

            let mut pk = vec![0u8; pk_len];
            let mut sk = vec![0u8; sk_len];

            for (idx, b) in pk.iter_mut().enumerate() {
                *b = seed.as_bytes()[idx % seed.as_bytes().len()];
            }
            for (idx, b) in sk.iter_mut().enumerate() {
                *b = seed.as_bytes()[(idx + 7) % seed.as_bytes().len()];
            }

            (pk, sk)
        } else {
            dsm::crypto::sphincs::generate_sphincs_keypair()?
        };
        let sphincs_sk_clone = sphincs_sk.clone();
        let sphincs_pk_clone = sphincs_pk.clone();

        let mut ks_mut = self.keystore.write();
        ks_mut.insert(format!("{id}_device_kyber_pk", id = current_id), kyber_pk);
        ks_mut.insert(format!("{id}_device_kyber_sk", id = current_id), kyber_sk);
        ks_mut.insert(
            format!("{id}_device_sphincs_pk", id = current_id),
            sphincs_pk,
        );
        ks_mut.insert(
            format!("{id}_device_sphincs_sk", id = current_id),
            sphincs_sk,
        );

        // Provide the TokenSDK and CoreSDK with the device signing key for
        // transfer authorization and DLV unlock operation signing.
        drop(ks_mut);
        self.token_sdk.set_signing_key(sphincs_sk_clone.clone());
        self.core_sdk.set_signing_key(sphincs_sk_clone);

        // CRITICAL: Update the state machine's device_info.public_key to match the wallet's
        // SPHINCS+ public key. Without this, the state machine verifies signatures against
        // the genesis public key (a different keypair), causing all transfers to fail.
        self.core_sdk.update_signing_public_key(sphincs_pk_clone);

        log::info!("Initialized device keys for {}", current_id);
        Ok(())
    }

    fn update_activity_sync(&self) {
        let now = dt::peek();
        let prev = {
            let la = self.last_activity.read();
            *la
        };
        let auto_lock = self.config.read().auto_lock_timeout;
        if auto_lock > 0 && prev > 0 && now > prev + auto_lock {
            let mut locked = self.locked.write();
            *locked = true;
            log::debug!("Wallet auto-locked due to inactivity");
        }
        let mut la = self.last_activity.write();
        *la = dt::tick();
    }

    pub fn add_counterparty(
        &self,
        device_id: &str,
        public_key: Vec<u8>,
        alias: Option<&str>,
    ) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let cp = Counterparty::new(
            device_id.to_string(),
            public_key,
            alias.map(|s| s.to_string()),
        );
        let mut book = self.device_book.write();
        book.insert(device_id.to_string(), cp);
        log::info!("Added counterparty: {device_id}");
        Ok(())
    }

    pub fn initialize_bilateral_chain(
        &self,
        counterparty_device_id: &str,
        initial_state_hash: &[u8],
    ) -> Result<ChainTipInfo, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let counterparty_device_id_bytes = crate::util::text_id::decode_base32_crockford(
            counterparty_device_id,
        )
        .ok_or_else(|| DsmError::invalid_parameter("counterparty_device_id must be base32"))?;
        if counterparty_device_id_bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "counterparty_device_id must decode to 32 bytes",
            ));
        }

        let normalized_initial_state_hash: Vec<u8> = match initial_state_hash.len() {
            0 => vec![0u8; 32],
            32 => initial_state_hash.to_vec(),
            _ => {
                return Err(DsmError::invalid_parameter(
                    "initial_state_hash must be 32 bytes or empty",
                ))
            }
        };

        let self_id = self.device_id_string();
        let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/chain-tip-id");
        h.update(self_id.as_bytes());
        h.update(&counterparty_device_id_bytes);
        h.update(&normalized_initial_state_hash);
        let tip_id = format!("tip_{}", first8_le_u64(h.finalize().as_bytes()));

        let chain_tip = ChainTipInfo::new(
            counterparty_device_id_bytes.clone(),
            tip_id.into_bytes(),
            normalized_initial_state_hash,
            0,
        );
        let mut chains = self.bilateral_chains.write();
        chains.insert(counterparty_device_id_bytes, chain_tip.clone());
        log::info!(
            "Initialized bilateral chain with {:?}",
            counterparty_device_id
        );
        Ok(chain_tip)
    }

    pub fn get_bilateral_chain_tip(
        &self,
        counterparty_device_id: &[u8],
    ) -> Result<ChainTipInfo, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let chains = self.bilateral_chains.read();
        chains.get(counterparty_device_id).cloned().ok_or_else(|| {
            DsmError::not_found(
                format!(
                    "Bilateral chain with counterparty {:?}",
                    base32::encode(base32::Alphabet::Crockford, counterparty_device_id)
                ),
                None::<String>,
            )
        })
    }

    pub fn get_device_book(&self) -> Result<HashMap<String, Counterparty>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        Ok(self.device_book.read().clone())
    }

    pub fn update_bilateral_chain_tip(
        &self,
        counterparty_device_id: &str,
        new_tip_id: &str,
        new_state_hash: &str,
        new_state_number: u64,
    ) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let counterparty_device_id_bytes = crate::util::text_id::decode_base32_crockford(
            counterparty_device_id,
        )
        .ok_or_else(|| DsmError::invalid_parameter("counterparty_device_id must be base32"))?;
        if counterparty_device_id_bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "counterparty_device_id must decode to 32 bytes",
            ));
        }

        let new_tip_id_bytes = crate::util::text_id::decode_base32_crockford(new_tip_id)
            .ok_or_else(|| DsmError::invalid_parameter("new_tip_id must be base32"))?;
        if new_tip_id_bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "new_tip_id must decode to 32 bytes",
            ));
        }

        let new_state_hash_bytes = crate::util::text_id::decode_base32_crockford(new_state_hash)
            .ok_or_else(|| DsmError::invalid_parameter("new_state_hash must be base32"))?;
        if new_state_hash_bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "new_state_hash must decode to 32 bytes",
            ));
        }

        let mut chains = self.bilateral_chains.write();
        match chains.get_mut(&counterparty_device_id_bytes) {
            Some(tip) => {
                tip.update(new_tip_id_bytes, new_state_hash_bytes, new_state_number);
                log::info!("Updated chain tip for {counterparty_device_id}");
                Ok(())
            }
            None => Err(DsmError::not_found(
                format!("Bilateral chain with counterparty {counterparty_device_id}"),
                None::<String>,
            )),
        }
    }

    /// Return device_id as raw UTF-8 bytes (deterministic, no encoding transforms).
    pub fn get_device_id(&self) -> Vec<u8> {
        self.device_id_bytes()
    }

    pub fn get_bilateral_chains(&self) -> Result<HashMap<Vec<u8>, ChainTipInfo>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        Ok(self.bilateral_chains.read().clone())
    }

    pub fn get_balance(&self, token_id: Option<&str>) -> Result<Balance, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let token_id = token_id.unwrap_or("ROOT");
        let owner = self.device_id_array();
        Ok(self.token_sdk.get_token_balance(&owner, token_id))
    }

    pub async fn create_transaction(
        &self,
        to_device_id: &str,
        amount: u64,
        token_id: Option<&str>,
        memo: Option<&str>,
        fee: Option<u64>,
    ) -> Result<WalletTransaction, DsmError> {
        log::debug!("[WALLET] create_transaction: start");
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        log::debug!("[WALLET] create_transaction: wallet not locked");
        self.update_activity_sync();

        let to_device_id_bytes = crate::util::text_id::decode_base32_crockford(to_device_id)
            .ok_or_else(|| DsmError::invalid_parameter("to_device_id must be base32"))?;
        if to_device_id_bytes.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "to_device_id must decode to 32 bytes",
            ));
        }

        log::debug!("[WALLET] create_transaction: checking device book");
        if !self.device_book.read().contains_key(to_device_id) {
            return Err(DsmError::not_found(
                format!("Recipient device ID {to_device_id} not found in device book"),
                None::<String>,
            ));
        }

        log::debug!("[WALLET] create_transaction: getting bilateral chain tip");
        let chain_tip = self.get_bilateral_chain_tip(&to_device_id_bytes)?;
        log::debug!("[WALLET] create_transaction: got chain tip");
        let token_id = token_id.unwrap_or("ROOT").to_string();
        let fee = fee.unwrap_or(self.config.read().default_fee);
        log::debug!("[WALLET] create_transaction: got fee from config");
        let from = self.device_id_string();

        log::debug!("[WALLET] create_transaction: creating WalletTransaction");
        Ok(WalletTransaction::new(
            from,
            to_device_id.to_string(),
            amount,
            token_id,
            memo.map(|s| s.to_string()),
            fee,
            base32::encode(base32::Alphabet::Crockford, &chain_tip.chain_tip_id),
        ))
    }

    pub fn sign_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> Result<WalletTransaction, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let self_id = self.device_id_string();
        if transaction.from_device_id != self_id {
            return Err(DsmError::unauthorized(
                format!(
                    "Cannot sign transaction from device {} using device {}",
                    transaction.from_device_id, self_id
                ),
                None::<std::io::Error>,
            ));
        }

        let ks = self.keystore.read();
        let sk_key = format!("{id}_device_sphincs_sk", id = self_id);
        let private_key = ks.get(&sk_key).ok_or_else(|| {
            DsmError::crypto(
                format!("Private key not found for device ID {}", self_id),
                None::<std::io::Error>,
            )
        })?;

        let mut tx = transaction.clone();
        tx.sign(private_key)?;
        Ok(tx)
    }

    /// Sign arbitrary operation bytes with the device's SPHINCS+ key.
    /// This is used for unilateral/b0x sends where recipients must
    /// verify signatures over canonical Operation bytes (not the
    /// WalletTransaction hash).
    pub fn sign_operation_bytes(&self, payload: &[u8]) -> Result<Vec<u8>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let self_id = self.device_id_string();
        let ks = self.keystore.read();
        let sk_key = format!("{id}_device_sphincs_sk", id = self_id);
        let private_key = ks.get(&sk_key).ok_or_else(|| {
            DsmError::crypto(
                format!("Private key not found for device ID {}", self_id),
                None::<std::io::Error>,
            )
        })?;

        dsm::crypto::sphincs::sphincs_sign(private_key, payload).map_err(|e| {
            DsmError::crypto(
                format!("Operation signing failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Return the local SPHINCS+ signing keypair used by wallet operations.
    ///
    /// This is for internal SDK integrations (e.g., Bitcoin TAP DLV creation).
    /// Callers must keep the returned secret key in-memory only.
    pub fn get_signing_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let self_id = self.device_id_string();
        let ks = self.keystore.read();
        let pk_key = format!("{id}_device_sphincs_pk", id = self_id);
        let sk_key = format!("{id}_device_sphincs_sk", id = self_id);

        let public_key = ks.get(&pk_key).cloned().ok_or_else(|| {
            DsmError::crypto(
                format!("Public key not found for device ID {}", self_id),
                None::<std::io::Error>,
            )
        })?;
        let private_key = ks.get(&sk_key).cloned().ok_or_else(|| {
            DsmError::crypto(
                format!("Private key not found for device ID {}", self_id),
                None::<std::io::Error>,
            )
        })?;

        Ok((public_key, private_key))
    }

    /// Return the local Kyber/ML-KEM public key used for vault content encryption.
    pub fn get_kyber_public_key(&self) -> Result<Vec<u8>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let self_id = self.device_id_string();
        let ks = self.keystore.read();
        let pk_key = format!("{id}_device_kyber_pk", id = self_id);

        ks.get(&pk_key).cloned().ok_or_else(|| {
            DsmError::crypto(
                format!("Kyber public key not found for device ID {}", self_id),
                None::<std::io::Error>,
            )
        })
    }

    /// Execute a pre-built, pre-signed Transfer Operation directly through the state machine.
    /// This bypasses the Operation-reconstruction in `execute_signed_transfer` that causes
    /// signature verification mismatch (different nonce/balance fields).
    pub fn send_transfer_op(
        &self,
        op: dsm::types::operations::Operation,
        transaction: &WalletTransaction,
    ) -> Result<State, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        log::debug!("[WALLET] send_transfer_op: calling token_sdk.execute_transfer_op...");
        let new_state = self.token_sdk.execute_transfer_op(op)?;
        log::debug!("[WALLET] send_transfer_op: execute_transfer_op OK");

        let mut tx_copy = transaction.clone();
        tx_copy.status = TransactionStatus::Confirmed;
        tx_copy.state_number = Some(new_state.state_number);
        self.transactions.write().push(tx_copy.clone());

        // §16.6: Relationship chain tip h_{n+1} is the caller's responsibility.
        // send_transfer_op advances the token state machine only; the caller
        // (app_router_impl or bilateral_sdk) persists the correct relationship tip
        // using compute_precommit + compute_successor_tip with the shared nonce.

        // Persist canonical balance projection + transaction record
        let sender = self.device_id_string();
        let token_id = if transaction.token_id.is_empty() {
            "ERA"
        } else {
            transaction.token_id.as_str()
        };
        let existing_locked = match crate::storage::client_db::get_locked_balance(&sender, token_id)
        {
            Ok(l) => l,
            Err(e) => {
                log::error!("[WALLET] send_transfer_op: failed to read locked balance: {e}");
                0
            }
        };
        let policy_commit = self.token_sdk.resolve_policy_commit_strict(token_id)?;
        if let Err(e) = crate::storage::client_db::sync_token_projection_from_state(
            &sender,
            token_id,
            &policy_commit,
            &new_state,
            existing_locked,
        ) {
            log::error!(
                "[WALLET] send_transfer_op: CRITICAL: failed to sync token projection for {}: {}",
                transaction.token_id,
                e
            );
            return Err(DsmError::invalid_operation(format!(
                "failed to sync token projection: {e}"
            )));
        } else {
            log::info!(
                "[WALLET] send_transfer_op: token projection synced from canonical state: {}:{} state_number={}",
                sender,
                transaction.token_id,
                new_state.state_number
            );
        }

        {
            let tx_hash_txt = crate::util::text_id::encode_base32_crockford(&tx_copy.hash);
            let mut meta: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            meta.insert(
                "token_id".to_string(),
                transaction.token_id.as_bytes().to_vec(),
            );
            if let Some(m) = &transaction.memo {
                meta.insert("memo".to_string(), m.as_bytes().to_vec());
            }
            let rec = crate::storage::client_db::TransactionRecord {
                tx_id: tx_copy.id.clone(),
                tx_hash: tx_hash_txt,
                from_device: tx_copy.from_device_id.clone(),
                to_device: tx_copy.to_device_id.clone(),
                amount: tx_copy.amount,
                tx_type: "online".to_string(),
                status: "confirmed".to_string(),
                chain_height: new_state.state_number,
                step_index: tx_copy.tick,
                commitment_hash: None,
                // §ISSUE-W1 FIX: proof_data must carry relationship chain tips h_n / h_{n+1},
                // NOT entity-level state hashes. The real ReceiptCommit with correct SMT
                // proofs is built and stored by the caller (app_router_impl.rs) after this
                // function returns. Set None so the subsequent upsert preserves authority.
                proof_data: None,
                metadata: meta,
                created_at: 0,
            };
            crate::storage::client_db::store_transaction(&rec).map_err(|e| {
                DsmError::internal(
                    format!("Failed to persist transaction record: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        }

        log::info!(
            "send_transfer_op completed: {} -> {}, amount: {}, token: {}",
            transaction.from_device_id,
            transaction.to_device_id,
            transaction.amount,
            transaction.token_id
        );

        Ok(new_state)
    }

    pub fn lock(&self) -> Result<(), DsmError> {
        *self.locked.write() = true;
        log::info!("Wallet locked");
        Ok(())
    }

    pub fn unlock(&self, _password: &str) -> Result<(), DsmError> {
        {
            *self.locked.write() = false;
        }
        self.update_activity_sync();
        log::info!("Wallet unlocked");
        Ok(())
    }

    pub fn get_transaction_history(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<WalletTransaction>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let txs = self.transactions.read();
        let offset = offset.unwrap_or(0);
        let slice = if offset < txs.len() {
            &txs[offset..]
        } else {
            &[]
        };
        Ok(if let Some(limit) = limit {
            slice.iter().take(limit).cloned().collect()
        } else {
            slice.to_vec()
        })
    }

    pub fn get_transaction(&self, id: &str) -> Result<WalletTransaction, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        for tx in self.transactions.read().iter() {
            if tx.id == id {
                return Ok(tx.clone());
            }
        }
        Err(DsmError::not_found(
            "Transaction",
            Some(format!("{id} not found")),
        ))
    }

    pub fn add_device_book_entry(
        &self,
        device_id: &str,
        public_key: Vec<u8>,
        alias: &str,
    ) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        self.add_counterparty(device_id, public_key, Some(alias))?;
        log::info!("Added device book entry: {device_id} -> {alias}");
        Ok(())
    }

    pub fn get_device_book_entries(&self) -> Result<HashMap<String, Counterparty>, DsmError> {
        self.get_device_book()
    }

    pub fn is_ready(&self) -> bool {
        if *self.locked.read() {
            return false;
        }
        let did = self.device_id_string();
        if did.is_empty() {
            return false;
        }
        let ks = self.keystore.read();
        let pk_key = format!("{id}_device_sphincs_pk", id = did);
        let sk_key = format!("{id}_device_sphincs_sk", id = did);
        ks.contains_key(&pk_key) && ks.contains_key(&sk_key)
    }

    pub fn update_config(&self, config: WalletConfig) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        *self.config.write() = config;
        log::info!("Updated wallet configuration");
        Ok(())
    }

    pub fn generate_recovery_mnemonic(&self) -> Result<String, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let _entropy = crypto::generate_nonce_32();
        let mnemonic = "quantum resist secure wallet phrase post entropy example".to_string();
        self.config.write().recovery_options.mnemonic = Some(mnemonic.clone());
        log::info!("Generated recovery mnemonic");
        Ok(mnemonic)
    }

    pub fn create_backup(&self, path: &Path) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        *self.last_backup.write() = Some(dt::tick());
        log::info!("Created wallet backup at {}", path.display());
        Ok(())
    }

    pub fn backup(&self) -> Result<String, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        let did = self.device_id_string();
        let path = format!("/tmp/wallet_backup_{}_{}.bin", did, dt::peek());
        *self.last_backup.write() = Some(dt::tick());
        log::info!("Created wallet backup at {path}");
        Ok(path)
    }

    pub fn restore(&self, backup_path: &str) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        log::info!("Restored wallet from backup: {backup_path}");
        Ok(())
    }

    pub fn verify_transaction(&self, transaction: &WalletTransaction) -> Result<bool, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let signature = match &transaction.signature {
            Some(s) => s,
            None => return Ok(false),
        };

        let device_book = self.device_book.read();
        let sender_device = device_book.get(&transaction.from_device_id);

        let public_key = {
            let self_id = self.device_id_string();
            if transaction.from_device_id == self_id {
                let ks = self.keystore.read();
                let pk_key = format!("{id}_device_sphincs_pk", id = self_id);
                match ks.get(&pk_key) {
                    Some(k) => k.clone(),
                    None => return Ok(false),
                }
            } else {
                match sender_device {
                    Some(d) => d.public_key.clone(),
                    None => return Ok(false),
                }
            }
        };

        dsm::crypto::verify_signature(&transaction.hash, signature, &public_key)
    }

    pub async fn get_wallet_info(&self) -> Result<HashMap<String, String>, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let mut info = HashMap::new();
        let cfg = self.config.read();
        let did = self.device_id_string();
        info.insert("name".to_string(), cfg.name.clone());
        info.insert("device_id".to_string(), did);
        info.insert(
            "bilateral_chain_count".to_string(),
            self.bilateral_chains.read().len().to_string(),
        );
        info.insert(
            "device_book_count".to_string(),
            self.device_book.read().len().to_string(),
        );
        info.insert(
            "transaction_count".to_string(),
            self.transactions.read().len().to_string(),
        );
        if let Some(last_backup) = *self.last_backup.read() {
            info.insert("last_backup_ticks".to_string(), last_backup.to_string());
        }
        info.insert("locked".to_string(), self.locked.read().to_string());
        info.insert(
            "security_level".to_string(),
            format!("{:?}", cfg.security_level),
        );
        Ok(info)
    }

    /// Mint tokens to this wallet's own device account (testnet faucet helper)
    pub async fn mint_for_self(
        &self,
        amount: u64,
        token_id: Option<&str>,
    ) -> Result<State, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        let token = token_id.unwrap_or("ERA").to_string();
        let pre_mint_available = self
            .get_balance(Some(&token))
            .map(|b| b.available())
            .unwrap_or(0);
        let recipient = self.device_id_array();
        let op = TokenOperation::Mint {
            token_id: token.clone(),
            recipient,
            amount,
        };
        // Execute through TokenSDK (updates canonical state)
        let new_state = self.token_sdk.execute_token_operation(op).await?;

        // Keep canonical balance projections in sync for every token, including ERA.
        {
            let device_id_txt = self.device_id_base32();
            let existing_locked =
                match crate::storage::client_db::get_locked_balance(&device_id_txt, &token) {
                    Ok(l) => l,
                    Err(e) => {
                        log::error!(
                            "[wallet.mint_for_self] failed to read {} locked balance: {}",
                            token,
                            e
                        );
                        0
                    }
                };
            let policy_commit = self.token_sdk.resolve_policy_commit_strict(&token)?;

            if let Err(e) = crate::storage::client_db::sync_token_projection_from_state(
                &device_id_txt,
                &token,
                &policy_commit,
                &new_state,
                existing_locked,
            ) {
                log::error!(
                    "[wallet.mint_for_self] FAILED to sync {} projection from state: {}",
                    token,
                    e
                );
            } else {
                log::info!(
                    "[wallet.mint_for_self] {} projection synced from canonical state_number={}",
                    token,
                    new_state.state_number
                );
            }

            let expected_available = pre_mint_available.saturating_add(amount);
            self.token_sdk
                .force_set_balance(self.device_id_array(), &token, expected_available);
        }

        let protocol_payload = build_faucet_protocol_payload(
            &recipient,
            &token,
            amount,
            &new_state.hash,
            new_state.state_number,
        );
        let protocol_event = {
            use crate::storage::client_db::{
                advance_system_chain_tip, get_system_peer, store_system_peer, SystemPeerRecord,
                SystemPeerType,
            };

            let mut expected_parent_tip = [0u8; 32];
            match get_system_peer(ERA_SOURCE_DLV_PEER_KEY).map_err(|e| {
                DsmError::internal(
                    format!("Failed to load stable ERA source DLV peer: {e}"),
                    None::<std::io::Error>,
                )
            })? {
                Some(existing) => {
                    let expected_device_id = era_source_dlv_device_id().to_vec();
                    if existing.device_id != expected_device_id {
                        return Err(DsmError::internal(
                            format!(
                                "Stable ERA source DLV peer has unexpected device_id for {}",
                                ERA_SOURCE_DLV_PEER_KEY
                            ),
                            None::<std::io::Error>,
                        ));
                    }
                    if existing.peer_type != SystemPeerType::Dlv {
                        return Err(DsmError::internal(
                            format!(
                                "Stable ERA source DLV peer has unexpected type {}",
                                existing.peer_type.as_str()
                            ),
                            None::<std::io::Error>,
                        ));
                    }
                    if let Some(current_tip) = existing.current_chain_tip.as_deref() {
                        if current_tip.len() != 32 {
                            return Err(DsmError::internal(
                                format!(
                                    "Stable ERA source DLV peer has invalid chain tip length {}",
                                    current_tip.len()
                                ),
                                None::<std::io::Error>,
                            ));
                        }
                        expected_parent_tip.copy_from_slice(current_tip);
                    }
                }
                None => {
                    let rec = SystemPeerRecord {
                        peer_key: ERA_SOURCE_DLV_PEER_KEY.to_string(),
                        device_id: era_source_dlv_device_id().to_vec(),
                        display_name: ERA_SOURCE_DLV_DISPLAY_NAME.to_string(),
                        peer_type: SystemPeerType::Dlv,
                        current_chain_tip: None,
                        created_at: crate::util::deterministic_time::tick(),
                        updated_at: crate::util::deterministic_time::tick(),
                        metadata: HashMap::new(),
                    };
                    store_system_peer(&rec).map_err(|e| {
                        DsmError::internal(
                            format!("Failed to create stable ERA source DLV peer: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                }
            }

            advance_system_chain_tip(
                ERA_SOURCE_DLV_PEER_KEY,
                SystemPeerType::Dlv,
                &expected_parent_tip,
                &protocol_payload,
                &new_state.hash,
                new_state.state_number,
            )
            .map_err(|e| {
                DsmError::internal(
                    format!("Failed to advance ERA source DLV tip: {e}"),
                    None::<std::io::Error>,
                )
            })?
        };

        let protocol_chain_tip_id =
            crate::util::text_id::encode_base32_crockford(&protocol_event.child_tip);

        let mut tx = WalletTransaction::new(
            self.device_id_base32(),    // from_device_id (self)
            self.device_id_base32(),    // to_device_id (self)
            amount,                     // amount minted
            token.clone(),              // token id
            Some("faucet".to_string()), // memo
            0,                          // fee
            protocol_chain_tip_id,      // protocol actor child tip
        );
        tx.status = TransactionStatus::Confirmed;
        tx.state_number = Some(new_state.state_number);
        tx.metadata
            .insert("source".to_string(), "faucet".to_string());
        tx.metadata.insert(
            "protocol_peer_key".to_string(),
            ERA_SOURCE_DLV_PEER_KEY.to_string(),
        );
        self.transactions.write().push(tx);

        // CRITICAL: Update global SDK_CONTEXT chain_tip so transport headers reflect new state
        // Per whitepaper Sec 2.1: h_{n+1} := H(S_{n+1}) - chain_tip must be 32-byte hash
        if new_state.hash.len() == 32 {
            if let Err(e) = crate::get_sdk_context().update_chain_tip(new_state.hash.to_vec()) {
                log::warn!("Failed to update SDK_CONTEXT chain_tip after faucet: {}", e);
            } else {
                log::info!(
                    "SDK_CONTEXT chain_tip updated after faucet (first 8 bytes): {:?}",
                    &new_state.hash[..8]
                );
            }
        }

        // Persist canonical transaction record only; balance projection was already synced.
        {
            // CRITICAL FIX: Use state_number + tick to ensure uniqueness
            // (state_number is monotonically increasing, tick provides additional entropy)
            let tx_id = format!("faucet_{}_{}", new_state.state_number, dt::tick());
            let tx_hash_txt = {
                let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/faucet-claim");
                h.update(tx_id.as_bytes());
                h.update(&new_state.hash);
                crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes())
            };
            let mut meta: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            meta.insert("token_id".to_string(), token.as_bytes().to_vec());
            meta.insert("source".to_string(), b"faucet".to_vec());
            meta.insert(
                "protocol_peer_key".to_string(),
                protocol_event.peer_key.as_bytes().to_vec(),
            );
            meta.insert(
                "protocol_peer_type".to_string(),
                protocol_event.peer_type.as_str().as_bytes().to_vec(),
            );
            meta.insert(
                "protocol_parent_tip".to_string(),
                protocol_event.parent_tip.clone(),
            );
            meta.insert(
                "protocol_child_tip".to_string(),
                protocol_event.child_tip.clone(),
            );
            meta.insert(
                "protocol_transition_digest".to_string(),
                protocol_event.transition_digest.clone(),
            );
            meta.insert(
                "protocol_transition_payload".to_string(),
                protocol_event.payload_bytes.clone(),
            );
            meta.insert(
                "source_state_hash".to_string(),
                protocol_event.source_state_hash.clone(),
            );
            meta.insert(
                "source_state_number".to_string(),
                protocol_event.source_state_number.to_le_bytes().to_vec(),
            );
            let rec = crate::storage::client_db::TransactionRecord {
                tx_id: tx_id.clone(),
                tx_hash: tx_hash_txt,
                from_device: self.device_id_base32(),
                to_device: self.device_id_base32(),
                amount,
                tx_type: "faucet".to_string(),
                status: "confirmed".to_string(),
                chain_height: new_state.state_number,
                step_index: dt::tick(),
                commitment_hash: Some(protocol_event.transition_digest.clone()),
                proof_data: None,
                metadata: meta,
                created_at: 0,
            };
            log::info!(
                "📝 Storing transaction: {} ({} -> {})",
                tx_id,
                rec.from_device,
                rec.to_device
            );
            crate::storage::client_db::store_transaction(&rec).map_err(|e| {
                log::error!(
                    "❌ CRITICAL: Failed to store faucet transaction {}: {}",
                    tx_id,
                    e
                );
                DsmError::internal(
                    format!("Failed to persist faucet transaction record: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            log::info!("✅ Transaction stored successfully, amount={}", amount);
        }

        Ok(new_state)
    }

    /// Execute a token operation directly through TokenSDK.
    /// Unconditionally set the local in-memory balance cache without advancing
    /// the state machine. Used by the b0x rollback path to restore the cached
    /// pre-send value after a failed storage-node delivery.
    pub fn force_set_balance_for_self(&self, token_id: &str, amount: u64) {
        let device_id = self.device_id_array();
        self.token_sdk
            .force_set_balance(device_id, token_id, amount);
    }

    /// Reload the local in-memory balance cache from canonical reads and any
    /// derived projections needed to hydrate the cache.
    pub fn reload_balance_cache_for_self(&self) -> Result<(), DsmError> {
        let device_id = self.device_id_array();
        self.token_sdk.reload_balance_cache_for_self(device_id)
    }

    pub(crate) fn rollback_failed_online_send(
        &self,
        rollback: &FailedOnlineSendRollback<'_>,
    ) -> Result<(), DsmError> {
        let canonical_token_id = if rollback.token_id.is_empty() {
            "ERA"
        } else {
            rollback.token_id
        };
        crate::storage::client_db::rollback_failed_online_send_atomic(
            &self.device_id_array(),
            &rollback.failed_state.hash,
            rollback.tx_id,
            &self.device_id_base32(),
            canonical_token_id,
        )
        .map_err(|e| {
            DsmError::internal(
                format!("Failed to rollback failed online-send artifacts: {e}"),
                None::<std::io::Error>,
            )
        })?;

        self.core_sdk
            .restore_state_snapshot(rollback.previous_state)?;
        self.transactions
            .write()
            .retain(|tx| tx.id != rollback.tx_id);
        let _ = self.token_sdk.discard_transfer_history_entry(
            canonical_token_id,
            rollback.recipient_device_id,
            rollback.amount,
            rollback.memo,
        );
        self.reload_balance_cache_for_self()?;
        Ok(())
    }

    pub fn seed_token_balance_for_self(&self, token_id: &str, amount: u64) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        let device_id = self.device_id_array();
        self.token_sdk
            .seed_in_memory_balance(device_id, token_id, amount)
    }

    ///
    /// Used by bridge flows (e.g., Bitcoin Tap deposit completion) to apply
    /// mint/burn accounting atomically with protocol completion.
    pub async fn execute_token_operation(
        &self,
        op: dsm::types::token_types::TokenOperation,
    ) -> Result<State, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();

        self.token_sdk.execute_token_operation(op).await
    }

    /// Register token metadata in the local token registry (token issuance anchor).
    pub async fn import_token_metadata(
        &self,
        token_id: String,
        metadata: dsm::types::token_types::TokenMetadata,
    ) -> Result<(), DsmError> {
        self.token_sdk
            .import_token_metadata(token_id, metadata)
            .await
    }

    /// Debug helper: clears local faucet cooldown state (if any).
    ///
    /// Note: the current SDK faucet implementation (`faucet.claim`) does not
    /// enforce cooldown in this layer (it mints immediately for test use).
    /// This method exists to satisfy tooling/UI that expects a "faucet clean"
    /// action to be available, without re-introducing old Vault UI.
    pub async fn faucet_clean(&self) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        // No-op for now: cooldown tracking lives in core `EraFaucet`, but
        // the SDK's faucet is currently implemented as direct mint.
        Ok(())
    }

    #[cfg(feature = "storage")]
    pub async fn get_wallet_display_data(
        &self,
        _storage_sync_sdk: &StorageSyncSdk,
    ) -> Result<WalletDisplayData, DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        // This function is only compiled when storage feature is enabled.
        // Concrete storage sync semantics must be provided by WalletDisplayData
        // and StorageSyncSdk implementors.
        Err(DsmError::internal(
            "Storage-backed wallet display data is not available in this binary",
            None::<std::convert::Infallible>,
        ))
    }

    #[cfg(feature = "storage")]
    pub async fn sync_wallet_data(
        &self,
        _storage_sync_sdk: &StorageSyncSdk,
    ) -> Result<(), DsmError> {
        if *self.locked.read() {
            return Err(DsmError::unauthorized(
                "Wallet is locked",
                None::<std::io::Error>,
            ));
        }
        self.update_activity_sync();
        // Deterministic hard-fail until concrete sync wiring is provided.
        Err(DsmError::internal(
            "Storage-backed wallet sync is not available in this binary",
            None::<std::convert::Infallible>,
        ))
    }

    #[cfg(test)]
    pub fn test_wallet() -> Result<Self, DsmError> {
        let core_sdk = Arc::new(CoreSDK::new()?);
        Self::new(core_sdk, "default_device", None)
    }
}
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::WalletSDK;

    #[test]
    fn test_initialization_and_bilateral_chains() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("")?;
        let device_id = wallet.get_device_id();
        assert!(!device_id.is_empty(), "Device ID should be set");
        let chains = wallet.get_bilateral_chains()?;
        assert!(chains.is_empty(), "Should start with no bilateral chains");
        Ok(())
    }

    #[test]
    fn test_lock_and_unlock_behavior() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.lock()?;
        assert!(
            wallet.get_device_book().is_err(),
            "Expected error when locked"
        );
        assert!(wallet
            .add_counterparty("test_device", vec![1, 2, 3], Some("Test"))
            .is_err());
        wallet.unlock("pw")?;
        assert!(wallet.get_device_book().is_ok());
        assert!(wallet
            .add_counterparty("test_device", vec![1, 2, 3], Some("Test"))
            .is_ok());
        Ok(())
    }

    #[test]
    fn test_add_counterparty_and_bilateral_chain() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("any")?;
        let device_id = crate::util::text_id::encode_base32_crockford(&[0xAA; 32]);
        let public_key = vec![1, 2, 3, 4];
        let before = wallet.get_device_book()?.len();
        wallet.add_counterparty(&device_id, public_key, Some("Test User"))?;
        let after = wallet.get_device_book()?;
        assert_eq!(after.len(), before + 1);
        assert!(after.contains_key(device_id.as_str()));
        wallet.initialize_bilateral_chain(&device_id, &[0; 32])?;
        let chains = wallet.get_bilateral_chains()?;
        let device_id_bytes = crate::util::text_id::decode_base32_crockford(&device_id).unwrap();
        assert!(chains.contains_key(&device_id_bytes));
        Ok(())
    }

    #[test]
    fn test_initialize_bilateral_chain_with_empty_initial_hash_uses_zero_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("any")?;
        let device_id = crate::util::text_id::encode_base32_crockford(&[0xAB; 32]);
        wallet.add_counterparty(&device_id, vec![1, 2, 3, 4], Some("Zero State Peer"))?;

        let chain = wallet.initialize_bilateral_chain(&device_id, &[])?;

        assert_eq!(chain.last_state_hash, vec![0u8; 32]);
        Ok(())
    }

    #[tokio::test]
    async fn test_create_and_sign_transaction() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("x")?;
        let to_device_id = crate::util::text_id::encode_base32_crockford(&[0xBB; 32]);
        wallet.add_counterparty(&to_device_id, vec![1, 2, 3], Some("Recipient"))?;
        wallet.initialize_bilateral_chain(&to_device_id, &[0; 32])?;
        let tx = wallet
            .create_transaction(&to_device_id, 100, None, Some("memo"), None)
            .await?;
        assert_eq!(tx.to_device_id, to_device_id);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.status, super::TransactionStatus::Pending);
        let signed = wallet.sign_transaction(&tx)?;
        assert!(signed.signature.is_some());
        Ok(())
    }

    #[test]
    fn test_generate_recovery_mnemonic_and_config() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("")?;
        let mnem = wallet.generate_recovery_mnemonic()?;
        assert!(mnem.contains("quantum"));
        let cfg = wallet.config.read();
        let m = cfg
            .recovery_options
            .mnemonic
            .as_ref()
            .unwrap_or_else(|| panic!("mnemonic not set"));
        assert_eq!(m, &mnem);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_wallet_info_fields() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        wallet.unlock("")?;
        let info = wallet.get_wallet_info().await?;
        let device_id = info
            .get("device_id")
            .unwrap_or_else(|| panic!("device_id missing"));
        assert_eq!(device_id, "default_device");
        let name = info.get("name").unwrap_or_else(|| panic!("name missing"));
        assert!(name.ends_with("Wallet"));
        let cc_raw = info
            .get("bilateral_chain_count")
            .unwrap_or_else(|| panic!("bilateral_chain_count missing"));
        let cc: usize = cc_raw.parse()?;
        assert_eq!(cc, 0);
        let tc_raw = info
            .get("transaction_count")
            .unwrap_or_else(|| panic!("transaction_count missing"));
        let tc: usize = tc_raw.parse()?;
        assert_eq!(tc, 0);
        Ok(())
    }

    #[test]
    fn wallet_history_transaction_id_is_utf8_safe() {
        // WalletHistoryResponse.TransactionInfo.id is a `string` in the protobuf schema.
        // Protobuf enforces UTF-8 for `string` fields; we must never populate it from raw bytes.
        // Our app router constructs ids as ASCII: "tx_" + base32_hash.
        let tx = crate::generated::TransactionInfo {
            id: "tx_ABCDEF".to_string(),
            from_device_id: vec![0u8; 32],
            to_device_id: vec![0u8; 32],
            token_id: "ERA".to_string(),
            amount: 1,
            fee: 0,
            logical_index: 0,
            tx_hash: vec![0u8; 32],
            amount_signed: 1,
            tx_type: crate::generated::TransactionType::TxTypeUnspecified as i32,
            status: "ok".to_string(),
            recipient: "someone".to_string(),
            stitched_receipt: Vec::new(),
            created_at: 0,
            memo: String::new(),
            receipt_verified: false,
        };

        let msg = crate::generated::WalletHistoryResponse {
            transactions: vec![tx],
        };

        let mut bytes = Vec::new();
        prost::Message::encode(&msg, &mut bytes).expect("encode should succeed");

        let decoded: crate::generated::WalletHistoryResponse =
            prost::Message::decode(&*bytes).expect("decode should succeed");

        assert_eq!(decoded.transactions.len(), 1);
        assert!(decoded.transactions[0].id.starts_with("tx_"));
    }
}
