// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Wallet SDK Module (no JSON, no Base64/b64, no hex, no wall clock)
//!
//! Deterministic, offline-capable wallet operations for DSM.
//! - No clock: nothing here reads or records time.
//! - UI/debug-friendly representations may exist, but protocol text IDs are base32.
//! - No serde_json anywhere.

use super::core_sdk::CoreSDK;
use super::token_sdk::TokenSDK;

use dsm::types::error::DsmError;
use dsm::types::state_types::State;
use dsm::types::token_types::{Balance};

use base32;
use log;
use parking_lot::RwLock;

use std::collections::HashMap;
use std::fmt;
use std::path::{PathBuf};
use std::sync::Arc;

// ---------- helpers: no hex/b64 ----------

fn first8_le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let take = bytes.len().min(8);
    buf[..take].copy_from_slice(&bytes[..take]);
    u64::from_le_bytes(buf)
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
    pub is_hidden: bool,
}
impl Counterparty {
    pub fn new(device_id: String, public_key: Vec<u8>, alias: Option<String>) -> Self {
        Self {
            device_id,
            public_key,
            alias,
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
    pub is_synchronized: bool,
}
impl ChainTipInfo {
    pub fn new(
        counterparty_device_id: Vec<u8>,
        chain_tip_id: Vec<u8>,
        last_state_hash: Vec<u8>,
        state_number: u64,
    ) -> Self {
        Self {
            counterparty_device_id,
            chain_tip_id,
            last_state_hash,
            state_number,
            is_synchronized: true,
        }
    }
    pub fn update(&mut self, new_tip_id: Vec<u8>, new_state_hash: Vec<u8>, new_state_number: u64) {
        self.chain_tip_id = new_tip_id;
        self.last_state_hash = new_state_hash;
        self.state_number = new_state_number;
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
            .field("status", &self.status)
            .field("state_number", &self.state_number)
            .field("chain_tip_id", &self.chain_tip_id)
            .field("fee", &self.fee)
            .field("metadata", &self.metadata)
            .finish()
    }
}
impl WalletTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_device_id: String,
        to_device_id: String,
        amount: u64,
        token_id: String,
        memo: Option<String>,
        fee: u64,
        chain_tip_id: String,
        // `relationship_key` + `operation_nonce` are Some for bilateral transfers
        // and None for faucet / protocol-actor records (see identity v2 below).
        relationship_key: Option<&[u8; 32]>,
        operation_nonce: Option<&[u8]>,
    ) -> Self {
        // hash for id + body
        let mut tx_hasher =
            dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TX_HASH);
        tx_hasher.update(from_device_id.as_bytes());
        tx_hasher.update(to_device_id.as_bytes());
        tx_hasher.update(&amount.to_le_bytes());
        tx_hasher.update(token_id.as_bytes());
        tx_hasher.update(chain_tip_id.as_bytes());
        if let Some(m) = &memo {
            tx_hasher.update(m.as_bytes());
        }
        tx_hasher.update(&fee.to_le_bytes());
        let tx_hash = tx_hasher.finalize();

        // IDENTITY v2 — derived from PROTOCOL identity, not from a clock.
        //
        // v1 was `tx:{first8(hash)}:{from}:{to}:{amount}:{fee}` where the hash folded
        // in `tick()`. `tick()` is a COMMIT HEIGHT, constant within a height, so two
        // same-amount sends to the same recipient in one height produced a
        // byte-identical id. That is not hypothetical: 8XK carries two proposals —
        // one finalized, one rolled back — sharing `tx:8099128616718722169`.
        //
        // v2 binds the id to the transfer's own protocol identity: the relationship
        // and the operation nonce. The nonce is already `H(h_n ‖ seq ‖ amount ‖
        // token ‖ recipient)`, so it separates transfers by relationship STEP and by
        // payload without consulting any clock or in-memory cache.
        //
        // Two attempts at the same step with the same payload still share an id, and
        // that is correct — they are the same logical transfer, and a stable id is
        // what makes a retry idempotent rather than a second debit.
        let id = match (relationship_key, operation_nonce) {
            (Some(rel), Some(nonce)) => {
                let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_ONLINE_TX_ID_V2,
                );
                h.update(rel);
                h.update(nonce);
                format!(
                    "tx2:{}",
                    crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes())
                )
            }
            // Paths with no relationship identity (faucet, protocol actors) keep the
            // legacy shape; they are not bilateral transfers and never rolled back.
            _ => format!(
                "tx:{}:{}:{}:{}:{}",
                first8_le_u64(tx_hash.as_bytes()),
                from_device_id,
                to_device_id,
                amount,
                fee
            ),
        };

        Self {
            id,
            from_device_id,
            to_device_id,
            amount,
            token_id,
            memo,
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
    pub offline_transactions_enabled: bool,
    pub default_fee: u64,
    pub db_path: Option<PathBuf>,
    pub recovery_options: WalletRecoveryOptions,
    pub custom_options: HashMap<String, String>,
}
impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            name: "DSM Wallet".to_string(),
            security_level: SecurityLevel::Standard,
            offline_transactions_enabled: true,
            default_fee: 1,
            db_path: None,
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
    pub(crate) token_sdk: Arc<TokenSDK>,
    config: RwLock<WalletConfig>,
    bilateral_chains: RwLock<HashMap<Vec<u8>, ChainTipInfo>>,
    transactions: RwLock<Vec<WalletTransaction>>,
    // Canonical text device identifier (updated post-genesis).
    device_id: RwLock<String>,
    keystore: RwLock<HashMap<String, Vec<u8>>>,
    device_book: RwLock<HashMap<String, Counterparty>>,
}

impl fmt::Debug for WalletSDK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let did = self.device_id.read().clone();
        f.debug_struct("WalletSDK")
            .field("device_id", &did)
            .field("config", &"WalletConfig{...}")
            .field("bilateral_chains_len", &self.bilateral_chains.read().len())
            .finish()
    }
}

impl WalletSDK {
    fn current_signing_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        Ok((
            crate::sdk::signing_authority::current_public_key()?,
            crate::sdk::signing_authority::current_secret_key()?,
        ))
    }

    /// AK (attestation key) keypair access for cert-chain bootstrapping
    /// (whitepaper §11.1). Used at relationship genesis (step 0) when no
    /// per-step chain head exists yet — `sign_receipt_with_per_step_ek`
    /// falls back to AK_sk to sign cert_1.
    ///
    /// Visibility: `pub(crate)` to limit attack surface — only the SDK's
    /// receipt-signing flow should touch the AK_sk directly.
    pub(crate) fn ak_keypair_for_cert_chain(&self) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        self.current_signing_keypair()
    }

    fn device_id_string(&self) -> String {
        self.device_id.read().clone()
    }

    fn device_id_array(&self) -> Result<[u8; 32], DsmError> {
        let text = self.device_id_string();
        let bytes = crate::util::text_id::decode_base32_crockford(&text).ok_or_else(|| {
            DsmError::invalid_parameter(format!("wallet device id {text:?} is not Base32"))
        })?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            DsmError::invalid_parameter(format!(
                "wallet device id decodes to {} bytes, not 32",
                bytes.len()
            ))
        })
    }

    pub fn new(
        core_sdk: Arc<CoreSDK>,
        device_id: &str,
        config: Option<WalletConfig>,
    ) -> Result<Self, DsmError> {
        let token_sdk = Arc::new(TokenSDK::new(core_sdk));

        let config = config.unwrap_or_else(|| WalletConfig {
            name: format!("{device_id}'s Wallet"),
            ..WalletConfig::default()
        });
        let wallet = Self {
            token_sdk,
            config: RwLock::new(config),
            bilateral_chains: RwLock::new(HashMap::new()),
            transactions: RwLock::new(Vec::new()),
            device_id: RwLock::new(device_id.to_string()),
            keystore: RwLock::new(HashMap::new()),
            device_book: RwLock::new(HashMap::new()),
        };

        wallet.initialize_device_keys()?;
        Ok(wallet)
    }

    fn initialize_device_keys(&self) -> Result<(), DsmError> {
        let current_id = self.device_id_string();

        // Device Kyber keypair: THE SAME deterministic Smaster derivation Genesis
        // v2 uses (`generate_kyber_keypair_from_entropy(smaster, "DSM/kyber\0")`,
        // genesis.rs create_genesis_v2), so the keystore key is byte-identical to
        // the one genesis derived — STABLE across app restarts and
        // reinstalls-from-seed. Without Smaster (wallet locked, or no genesis or
        // device id in the app state) there is no key to install, and the wallet
        // is not built.
        let smaster = crate::init::current_smaster()?;
        let (kyber_pk, kyber_sk) =
            dsm::crypto::kyber::generate_kyber_keypair_from_entropy(&smaster, "DSM/kyber\0")?;

        let mut ks_mut = self.keystore.write();
        ks_mut.insert(format!("{id}_device_kyber_pk", id = current_id), kyber_pk);
        ks_mut.insert(format!("{id}_device_kyber_sk", id = current_id), kyber_sk);

        drop(ks_mut);

        log::info!("Initialized device keys for {}", current_id);
        Ok(())
    }

    pub fn add_counterparty(
        &self,
        device_id: &str,
        public_key: Vec<u8>,
        alias: Option<&str>,
    ) -> Result<(), DsmError> {
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
        let mut h =
            dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_CHAIN_TIP_ID);
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
        Ok(self.device_book.read().clone())
    }

    pub fn update_bilateral_chain_tip(
        &self,
        counterparty_device_id: &str,
        new_tip_id: &str,
        new_state_hash: &str,
        new_state_number: u64,
    ) -> Result<(), DsmError> {
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

    pub fn get_balance(&self, token_id: &str) -> Result<Balance, DsmError> {
        let owner = self.device_id_array()?;
        Ok(self.token_sdk.get_token_balance(&owner, token_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_transaction(
        &self,
        to_device_id: &str,
        amount: u64,
        token_id: Option<&str>,
        memo: Option<&str>,
        fee: Option<u64>,
        // Protocol identity for the transfer id (identity v2). Bilateral transfers
        // pass both; callers with no relationship pass None and keep the legacy id.
        relationship_key: Option<&[u8; 32]>,
        operation_nonce: Option<&[u8]>,
    ) -> Result<WalletTransaction, DsmError> {
        log::debug!("[WALLET] create_transaction: start");

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
            relationship_key,
            operation_nonce,
        ))
    }

    pub fn sign_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> Result<WalletTransaction, DsmError> {
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

        let private_key = crate::sdk::signing_authority::current_secret_key()?;

        let mut tx = transaction.clone();
        tx.sign(&private_key)?;
        Ok(tx)
    }

    /// Sign arbitrary operation bytes with the device's SPHINCS+ key.
    /// This is used for unilateral/b0x sends where recipients must
    /// verify signatures over canonical Operation bytes (not the
    /// WalletTransaction hash).
    pub fn sign_operation_bytes(&self, payload: &[u8]) -> Result<Vec<u8>, DsmError> {
        let private_key = crate::sdk::signing_authority::current_secret_key()?;

        dsm::crypto::sphincs::sphincs_sign(&private_key, payload).map_err(|e| {
            DsmError::crypto(
                format!("Operation signing failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Return the local Kyber/ML-KEM public key used for vault content encryption.
    pub fn get_kyber_public_key(&self) -> Result<Vec<u8>, DsmError> {
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

    /// §16.6 defect zero — STAGED send.
    ///
    /// `build_artifacts` runs after the pure prepare and before the durable
    /// write (the only window where DB-reading work such as per-step EK signing
    /// is legal); `write_extra` persists the result INSIDE the advance
    /// transaction. The canonical advance and every local record justifying the
    /// outgoing message therefore commit atomically — there is no observable
    /// state in which a debit exists without its durable lifecycle record.
    ///
    /// An economic admission rides the same advance (3.5b sender debit).
    pub fn send_transfer_op_staged_with_admission<A>(
        &self,
        op: dsm::types::operations::Operation,
        transaction: &WalletTransaction,
        build_artifacts: impl FnOnce(&dsm::types::device_state::AdvanceOutcome) -> Result<A, DsmError>,
        write_extra: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
        admission: Option<crate::sdk::core_sdk::AdmissionPlan<'_>>,
    ) -> Result<(State, A), DsmError> {
        // Everything fallible that is NOT part of the advance runs BEFORE it, so
        // that an `Err` from the staged call keeps meaning "nothing was committed".
        // `token_sdk` resolves the same policy commit pre-advance already, so this
        // is a pure re-read — failing it here is strictly correct and costs nothing.
        let sender = self.device_id_string();
        if transaction.token_id.is_empty() {
            return Err(DsmError::invalid_operation(
                "a transfer names the token it moves",
            ));
        }
        let token_id_owned = transaction.token_id.clone();
        let policy_commit = self
            .token_sdk
            .resolve_policy_commit_strict(&token_id_owned)?;
        let existing_locked =
            crate::storage::client_db::get_locked_balance(&sender, &token_id_owned).map_err(
                |e| {
                    DsmError::storage(
                        format!("send_transfer_op: the locked balance could not be read: {e}"),
                        None::<std::io::Error>,
                    )
                },
            )?;

        log::debug!("[WALLET] send_transfer_op: calling token_sdk.execute_transfer_op...");
        let (new_state, artifacts) = self.token_sdk.execute_transfer_op_staged_with_admission(
            op,
            build_artifacts,
            write_extra,
            admission,
        )?;
        log::debug!("[WALLET] send_transfer_op: execute_transfer_op OK");

        // ==================================================================
        // PAST THIS POINT THE ADVANCE AND THE DURABLE BUNDLE ARE COMMITTED.
        //
        // Nothing below may return `Err`. Everything below is a PROJECTION or a
        // local history row — derived state, rebuildable from canonical. Failing
        // the send here would tell the caller "this did not happen" about a
        // transfer that is committed and deliverable, and the caller would roll
        // back a durable debit. Log and reconcile forward instead.
        // ==================================================================

        let mut tx_copy = transaction.clone();
        tx_copy.status = TransactionStatus::Confirmed;

        self.transactions.write().push(tx_copy.clone());

        // §16.6: Relationship chain tip h_{n+1} is the caller's responsibility.
        // send_transfer_op advances the token state machine only; the caller
        // (app_router_impl or bilateral_sdk) persists the correct relationship tip
        // using compute_precommit + compute_successor_tip with the shared nonce.

        // Persist canonical balance projection + transaction record
        let token_id = token_id_owned.as_str();
        if let Err(e) = crate::storage::client_db::sync_token_projection_from_state(
            &sender,
            token_id,
            &policy_commit,
            &new_state,
            existing_locked,
        ) {
            log::error!(
                "[WALLET] send_transfer_op: post-commit projection sync FAILED for {} ({}). \
                 The advance and the durable outbox are committed; the transfer stands.",
                transaction.token_id,
                e
            );
            // DURABLE reconcile-forward. A log line dies with the process; this
            // row does not. The startup sweep rebuilds the projection from
            // canonical BCR state.
            if let Err(q) = crate::storage::client_db::enqueue_projection_repair(
                &sender,
                token_id,
                &format!("post-commit projection sync failed: {e}"),
            ) {
                log::error!(
                    "[WALLET] send_transfer_op: could not QUEUE projection repair for {sender}:{token_id}: {q}"
                );
            }
        } else {
            log::info!(
                "[WALLET] send_transfer_op: token projection synced from canonical state: {}:{} state_number={}",
                sender,
                transaction.token_id,
                new_state.hash[0] as u64
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
                commitment_hash: None,
                // §ISSUE-W1 FIX: proof_data must carry relationship chain tips h_n / h_{n+1},
                // NOT entity-level state hashes. The real ReceiptCommit with correct SMT
                // proofs is built and stored by the caller (app_router_impl.rs) after this
                // function returns. Set None so the subsequent upsert preserves authority.
                proof_data: None,
                metadata: meta,
            };
            // Post-commit: local history only. A failure here must NOT fail the
            // send — the advance and the durable outbox are already committed and
            // the transfer is deliverable. The row is rebuildable from canonical
            // BCR state (see the canonical/projection rebuild work item).
            if let Err(e) = crate::storage::client_db::store_transaction(&rec) {
                log::error!(
                    "[WALLET] send_transfer_op: post-commit history row FAILED to persist \
                     ({e}). The transfer stands."
                );
                // Durable intent to rebuild — see the projection-repair queue.
                if let Err(q) = crate::storage::client_db::enqueue_projection_repair(
                    &sender,
                    &token_id_owned,
                    &format!("post-commit history row failed: {e}"),
                ) {
                    log::error!("[WALLET] send_transfer_op: could not QUEUE history repair: {q}");
                }
            }
        }

        log::info!(
            "send_transfer_op completed: {} -> {}, amount: {}, token: {}",
            transaction.from_device_id,
            transaction.to_device_id,
            transaction.amount,
            transaction.token_id
        );

        Ok((new_state, artifacts))
    }

    pub fn add_device_book_entry(
        &self,
        device_id: &str,
        public_key: Vec<u8>,
        alias: &str,
    ) -> Result<(), DsmError> {
        self.add_counterparty(device_id, public_key, Some(alias))?;
        log::info!("Added device book entry: {device_id} -> {alias}");
        Ok(())
    }

    /// Reload the local in-memory balance cache from canonical reads and any
    /// derived projections needed to hydrate the cache.
    pub fn reload_balance_cache_for_self(&self) -> Result<(), DsmError> {
        let device_id = self.device_id_array()?;
        self.token_sdk.reload_balance_cache_for_self(device_id)
    }

    /// Project the local in-memory balance cache from a caller-supplied
    /// canonical state snapshot.
    pub fn project_balance_cache_for_self(
        &self,
        state: &dsm::types::state_types::State,
    ) -> Result<(), DsmError> {
        let device_id = self.device_id_array()?;
        self.token_sdk
            .project_balance_cache_from_state(device_id, state)
    }

    ///
    /// Used by bridge flows (e.g., Bitcoin Tap deposit completion) to apply
    /// mint/burn accounting atomically with protocol completion.
    pub async fn execute_token_operation(
        &self,
        op: dsm::types::token_types::TokenOperation,
    ) -> Result<State, DsmError> {
        self.token_sdk.execute_token_operation(op).await
    }

    /// A wallet on a device with a real identity, over a fresh database.
    #[cfg(test)]
    pub fn test_wallet() -> Result<Self, DsmError> {
        let (identity, core) = crate::economic_fixtures::local_device(0x11);
        let core_sdk = Arc::new(core);
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&identity.device_id);
        let test_config = WalletConfig {
            name: format!("{device_id_b32}'s Wallet"),
            ..WalletConfig::default()
        };
        Self::new(core_sdk, &device_id_b32, Some(test_config))
    }
}
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::WalletSDK;
    use serial_test::serial;
    use super::WalletTransaction;

    /// The 8XK collision, as a test.
    ///
    /// v1 folded `tick()` — a commit HEIGHT, constant within a height — into the
    /// transfer id, so two same-amount sends to the same recipient in one height
    /// produced byte-identical ids. 8XK carries exactly that: two proposals, one
    /// finalized and one rolled back, both `tx:8099128616718722169`. An unscoped
    /// `DELETE ... WHERE tx_id` then destroyed the finalized one.
    #[test]
    fn identity_v2_separates_transfers_that_v1_collided() {
        let rel = [0x11u8; 32];
        let mk = |nonce: &[u8]| {
            WalletTransaction::new(
                "SENDER".into(),
                "RECIPIENT".into(),
                15,
                "ERA".into(),
                None,
                0,
                "TIP".into(),
                Some(&rel),
                Some(nonce),
            )
            .id
        };

        // Same amount, recipient, token and chain-tip string — the exact shape that
        // collided. Different relationship STEPS give different nonces.
        let a = mk(&[0xAAu8; 32]);
        let b = mk(&[0xBBu8; 32]);
        assert_ne!(a, b, "distinct transfers must not share an identity");
        assert!(a.starts_with("tx2:"), "bilateral transfers use identity v2");

        // A retry of the SAME logical transfer keeps its id — that is what makes a
        // resend idempotent instead of a second debit.
        assert_eq!(
            mk(&[0xAAu8; 32]),
            a,
            "same step + payload is the same transfer"
        );
    }

    /// The id must not depend on a clock at all, so it cannot collide because of
    /// commit height.
    #[test]
    fn identity_v2_is_independent_of_the_commit_height() {
        let rel = [0x22u8; 32];
        let nonce = [0x33u8; 32];
        let mk = |tip: &str, amount: u64| {
            WalletTransaction::new(
                "S".into(),
                "R".into(),
                amount,
                "ERA".into(),
                None,
                0,
                tip.into(),
                Some(&rel),
                Some(&nonce),
            )
            .id
        };
        // Neither the chain-tip cache string nor the amount may perturb it: the
        // nonce already binds both, so identity comes from the nonce alone.
        assert_eq!(mk("TIP-A", 15), mk("TIP-B", 15));
        assert_eq!(mk("TIP-A", 15), mk("TIP-A", 99));
    }

    /// Faucet / protocol-actor records are not bilateral transfers and keep the
    /// legacy shape.
    #[test]
    fn non_relationship_records_keep_the_legacy_identity() {
        let id = WalletTransaction::new(
            "S".into(),
            "R".into(),
            100,
            "ERA".into(),
            None,
            0,
            "TIP".into(),
            None,
            None,
        )
        .id;
        assert!(id.starts_with("tx:"), "got {id}");
        assert!(!id.starts_with("tx2:"));
    }

    #[test]
    #[serial]
    fn test_add_counterparty_and_bilateral_chain() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        let device_id = crate::util::text_id::encode_base32_crockford(&[0xAA; 32]);
        let public_key = vec![1, 2, 3, 4];
        let before = wallet.get_device_book()?.len();
        wallet.add_counterparty(&device_id, public_key, Some("Test User"))?;
        let after = wallet.get_device_book()?;
        assert_eq!(after.len(), before + 1);
        assert!(after.contains_key(device_id.as_str()));
        wallet.initialize_bilateral_chain(&device_id, &[0; 32])?;
        let device_id_bytes = crate::util::text_id::decode_base32_crockford(&device_id).unwrap();
        assert!(wallet.get_bilateral_chain_tip(&device_id_bytes).is_ok());
        Ok(())
    }

    #[test]
    #[serial]
    fn test_initialize_bilateral_chain_with_empty_initial_hash_uses_zero_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        let device_id = crate::util::text_id::encode_base32_crockford(&[0xAB; 32]);
        wallet.add_counterparty(&device_id, vec![1, 2, 3, 4], Some("Zero State Peer"))?;

        let chain = wallet.initialize_bilateral_chain(&device_id, &[])?;

        assert_eq!(chain.last_state_hash, vec![0u8; 32]);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_and_sign_transaction() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = WalletSDK::test_wallet()?;
        let to_device_id = crate::util::text_id::encode_base32_crockford(&[0xBB; 32]);
        wallet.add_counterparty(&to_device_id, vec![1, 2, 3], Some("Recipient"))?;
        wallet.initialize_bilateral_chain(&to_device_id, &[0; 32])?;
        let tx = wallet
            .create_transaction(&to_device_id, 100, None, Some("memo"), None, None, None)
            .await?;
        assert_eq!(tx.to_device_id, to_device_id);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.status, super::TransactionStatus::Pending);
        let signed = wallet.sign_transaction(&tx)?;
        assert!(signed.signature.is_some());
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
            tx_hash: vec![0u8; 32],
            amount_signed: 1,
            tx_type: crate::generated::TransactionType::TxTypeUnspecified as i32,
            status: "ok".to_string(),
            recipient: "someone".to_string(),
            stitched_receipt: Vec::new(),
            memo: String::new(),
            receipt_verified: false,
            display_amount: "1".to_string(),
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
